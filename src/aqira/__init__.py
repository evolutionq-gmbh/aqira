import argparse
import contextlib
import selectors
from hashlib import blake2s
from socket import SHUT_WR, create_connection, socket
from time import sleep, time
from types import TracebackType
from typing import Self, cast
from uuid import UUID

from ksnp import CloseDirection, client
from ksnp.client import event
from ksnp.stream import OpenParams
from wgnlpy import (
    PresharedKey,
    PublicKey,
    WireGuard,
)
from wgnlpy.wireguardpeer import (
    WireGuardPeer,
)


class QkdClient:
    KEY_SIZE: int = 32
    REKEY_DELAY = 120.0
    REKEY_TIMEOUT = 5.0

    def __init__(
        self,
        qkd_address: tuple[str, int],
        interface: str,
        peer_key: PublicKey,
        interval: float = 0.0,
    ) -> None:
        if interval < 0.0:
            raise ValueError

        self._qkd_address = qkd_address
        self._read_buf = bytearray()
        self._write_buf = bytearray()
        self._client = client.Client(self._read_buf, self._write_buf)
        self._interval = interval
        self._interface = interface
        self._peer = peer_key
        self._peer_str = str(peer_key)

        self._sock: socket | None = None
        self._selector: selectors.DefaultSelector | None = None
        self._wg: WireGuard | None = None
        self._stream_id: bytes | None = None

    def open(self) -> None:
        try:
            self._sock = create_connection(self._qkd_address)
            self._sock.setblocking(False)
            self._selector = selectors.DefaultSelector()
            self._selector.register(
                self._sock, selectors.EVENT_READ | selectors.EVENT_WRITE
            )
            self._wg = WireGuard()
            wg_iface = self._wg.get_interface(self._interface)
            if self._peer not in wg_iface.peers:
                msg = f"peer {self._peer} not known to {self._interface}"
                raise ValueError(msg)
            self._stream_id = blake2s(
                bytes(
                    a ^ b
                    for a, b in zip(
                        bytes(wg_iface.public_key),
                        bytes(self._peer),
                        strict=True,
                    )
                ),
                digest_size=16,
            ).digest()
        except:
            if self._sock:
                self._sock.close()
            if self._selector:
                self._selector.close()
            if self._wg:
                del self._wg
                self._wg = None

            raise

    def close(self) -> None:
        assert self._sock is not None, "must be connected"
        assert self._wg is not None, "must be connected"
        assert self._selector is not None, "must be connected"

        self._set_psk(PresharedKey.generate())
        self._client.close_connection(CloseDirection.WRITE)
        while self._wait_event() is not None:
            # Drain the connection
            pass

        del self._wg
        self._wg = None

        with contextlib.suppress(Exception):
            self._selector.close()
        self._selector = None

        with contextlib.suppress(Exception):
            self._sock.close()
        self._sock = None

    def run(self) -> None:
        print("Wait for key")
        psk = self._wait_key()
        if psk is None:
            return

        while True:
            key_time = self._ensure_psk(psk)

            if self._interval > (key_age := time() - key_time):
                print(f"Wait {self._interval - key_age} for interval")
                sleep(self._interval - key_age)

            psk = self._wait_key()
            if psk is None:
                return

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> bool | None:
        self.close()

    def _handshake_time(self) -> float:
        assert self._wg is not None, "must be connected"
        peer = cast(
            "WireGuardPeer | None",
            self._wg.get_interface(self._interface).peers.get(self._peer, None),
        )
        if peer is None:
            msg = f"peer {self._peer} is no longer configured for interface {self._interface}"
            raise RuntimeError(msg)
        return cast("float | None", peer.last_handshake_time) or 0.0

    def _set_psk(self, key: PresharedKey) -> None:
        """
        Set the PSK to the given key.
        """
        assert self._wg is not None, "must be connected"
        self._wg.set_peer(
            self._interface,
            public_key=self._peer,
            preshared_key=key,
        )

    def _ensure_psk(self, psk: PresharedKey) -> float:
        """
        Set the PSk to the given key, and wait for the first handshake
        that makes use of it.

        Returns the time at which the last handshake completed.

        There is a small window where the PSK is set, but the handshake
        completes with the previous PSK (if any). This is ignored, as
        either this, or the next, PSK is used on the next handshake.
        """
        # Set the PSK and record when having done so.
        self._set_psk(psk)
        psk_time = time()
        print(f"PSK set at {psk_time}")

        # Wait for the handshake that uses the PSK.
        if (handshake_time := self._handshake_time()) < psk_time:
            handshake_age = time() - handshake_time
            if handshake_age < QkdClient.REKEY_DELAY:
                print(
                    f"Wait {QkdClient.REKEY_DELAY - handshake_age} for next handshake"
                )
                sleep(QkdClient.REKEY_DELAY - handshake_age)
            # If there is a PSK mismatch, or the network is down,
            # recheck the handshake time every REKEY_TIMEOUT seconds.
            # This allows a remote to catch up.
            while (handshake_time := self._handshake_time()) < psk_time:
                print(".", end=None)
                sleep(QkdClient.REKEY_TIMEOUT)

        # At this point a handshake occurred that appeared after setting
        # the PSK. Most likely, the PSK is in use. If both sides set the
        # PSK slightly too late, the previous PSK is being used, the
        # current PSK will be used on the next handshake (or the next
        # PSK, if the PSK rolled).
        print(f"PSK assumed enabled at {handshake_time}")

        return handshake_time

    def _wait_event(
        self,
    ) -> (
        event.Handshake
        | event.StreamAccepted
        | event.StreamRejected
        | event.StreamClose
        | event.StreamSuspend
        | event.KeyData
        | event.KeepAlive
        | event.Error
        | None
    ):
        assert self._selector is not None, "must be connected"

        if self._sock is None:
            return None

        while (next_event := self._client.next_event()) is None:
            if not self._client.want_read() and not self._client.want_write():
                return None

            mask = 0
            if self._client.want_read():
                mask |= selectors.EVENT_READ
            if self._client.want_write():
                self._client.flush_data()
                if len(self._write_buf) > 0:
                    mask |= selectors.EVENT_WRITE
                else:
                    self._sock.shutdown(SHUT_WR)

            self._selector.modify(self._sock, mask)

            events = self._selector.select()
            if len(events) == 0:
                raise TimeoutError

            for _, mask in events:
                if mask & selectors.EVENT_READ:
                    try:
                        data = self._sock.recv(4096)
                    except Exception as e:
                        print(f"Error on QKD connection: {e}")
                        self._sock = None
                        return None
                    if len(data) == 0:
                        self._client.close_connection(CloseDirection.READ)
                    else:
                        self._read_buf.extend(data)

                if mask & selectors.EVENT_WRITE:
                    try:
                        count = self._sock.send(self._write_buf)
                    except Exception as e:
                        print(f"Error on QKD connection: {e}")
                        self._sock = None
                        return None
                    del self._write_buf[:count]

        return next_event

    def _wait_key(self) -> PresharedKey | None:
        while (next_event := self._wait_event()) is not None:
            match next_event:
                case event.Handshake():
                    # Round up to match WG handshake interval
                    delay = self._interval + (120.0 - self._interval % 120.0)
                    self._client.open_stream(
                        OpenParams(
                            destination=str(self._peer),
                            stream_id=UUID(bytes=self._stream_id),
                            min_bps=(QkdClient.KEY_SIZE, int(delay)),
                            capacity=QkdClient.KEY_SIZE,
                        )
                    )
                    continue
                case event.StreamAccepted(parameters=parameters):
                    if parameters.position != 0:
                        msg = "Stream resumption is not supported"
                        raise RuntimeError(msg)
                case event.KeyData(key_data=key_data):
                    assert len(key_data) == QkdClient.KEY_SIZE
                    self._client.add_capacity(QkdClient.KEY_SIZE)
                    return PresharedKey(key_data)
                case _:
                    return None
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--host",
        metavar="HOST",
        required=True,
        help="Host of the QKD interface to retrieve keys from",
    )
    parser.add_argument(
        "--port",
        metavar="PORT",
        required=True,
        type=int,
        help="Port of the QKD interface to retrieve keys from",
    )
    parser.add_argument(
        "--interface",
        metavar="IFACE",
        required=True,
        help="Name of the WireGuard interface to set the PSK of",
    )
    parser.add_argument(
        "--peer_key",
        metavar="PUBKEY",
        required=True,
        type=PublicKey,
        help="Public key of the peer to share the PSK with",
    )
    parser.add_argument(
        "--interval", metavar="SECONDS", required=False, type=float, default=0.0
    )

    args = parser.parse_args()

    if args.interval % QkdClient.REKEY_DELAY != 0:
        print(
            f"WARN: PSK interval is not a multiple of the rekey delay ({QkdClient.REKEY_DELAY} seconds)."
        )

    client = QkdClient(
        (args.host, args.port), args.interface, args.peer_key, args.interval
    )

    with client:
        client.run()


if __name__ == "__main__":
    main()
