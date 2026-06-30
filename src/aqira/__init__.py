import argparse
from hashlib import blake2s
from time import sleep, time
from types import TracebackType
from typing import Self
from uuid import UUID

from wgnlpy import PublicKey, PresharedKey  # pyright: ignore[reportMissingTypeStubs]

from .wg import WgClient
from .qkd import QkdClient


class QkdGuard:
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
        self._interval = interval
        self._key_delay = self._interval + (120.0 - self._interval % 120.0)
        self._wg = WgClient(interface=interface, peer_key=peer_key)
        self._open = False

    def __enter__(self) -> Self:
        self._wg.open()
        self._open = True
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> bool | None:
        self._open = False
        self._wg.close()

    def run(self) -> None:
        assert self._open, "must be running"

        key_delay = self._interval + (120.0 - self._interval % 120.0)
        stream_id = UUID(
            bytes=blake2s(
                bytes(
                    a ^ b
                    for a, b in zip(
                        self._wg.public_key,
                        self._wg.peer_key,
                        strict=True,
                    )
                ),
                digest_size=16,
            ).digest()
        )

        running = True
        delay = 0.0
        while running:
            sleep(delay)
            delay = 5.0

            with QkdClient(
                self._qkd_address,
                stream_id,
                str(self._wg.peer_key),
                WgClient.KEY_SIZE,
                key_delay,
            ) as qkd:
                pass

                print("Wait for key")
                psk = qkd.wait_key()
                if psk is None:
                    continue

                while True:
                    key_time = self._ensure_psk(psk)

                    if self._interval > (key_age := time() - key_time):
                        print(f"Wait {self._interval - key_age} for interval")
                        sleep(self._interval - key_age)

                    psk = qkd.wait_key()
                    if psk is None:
                        return

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
        self._wg.set_psk(psk)
        psk_time = time()
        print(f"PSK set at {psk_time}")

        # Wait for the handshake that uses the PSK.
        if (handshake_time := self._wg.handshake_time) < psk_time:
            handshake_age = time() - handshake_time
            if handshake_age < WgClient.REKEY_DELAY:
                print(f"Wait {WgClient.REKEY_DELAY - handshake_age} for next handshake")
                sleep(WgClient.REKEY_DELAY - handshake_age)
            # If there is a PSK mismatch, or the network is down,
            # recheck the handshake time every REKEY_TIMEOUT seconds.
            # This allows a remote to catch up.
            while (handshake_time := self._wg.handshake_time) < psk_time:
                print(".", end=None)
                sleep(WgClient.REKEY_TIMEOUT)

        # At this point a handshake occurred that appeared after setting
        # the PSK. Most likely, the PSK is in use. If both sides set the
        # PSK slightly too late, the previous PSK is being used, the
        # current PSK will be used on the next handshake (or the next
        # PSK, if the PSK rolled).
        print(f"PSK assumed enabled at {handshake_time}")

        return handshake_time


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

    if args.interval % WgClient.REKEY_DELAY != 0:
        print(
            f"WARN: PSK interval is not a multiple of the rekey delay ({WgClient.REKEY_DELAY} seconds)."
        )

    client = QkdGuard(
        (args.host, args.port), args.interface, args.peer_key, args.interval
    )

    with client:
        client.run()


if __name__ == "__main__":
    main()
