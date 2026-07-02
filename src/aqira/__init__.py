from hashlib import blake2s
from socket import AddressFamily, SocketKind, socket, getaddrinfo, IPPROTO_UDP
from time import sleep, time
from types import TracebackType
from typing import Any, ClassVar, Self
from uuid import UUID
import argparse
import logging

from wgnlpy import PublicKey, PresharedKey  # pyright: ignore[reportMissingTypeStubs]

from .wg import WgClient
from .qkd import QkdClient
from .sync import SyncClient

logger = logging.getLogger(__name__)


class QkdGuard:
    SYNC_TIMEOUT: ClassVar[float | None] = 30.0
    """
    Time to allow for stream synchronization.

    If the key can not be synchronized within this timeout, the key
    stream is restarted.
    """

    def __init__(
        self,
        qkd_address: tuple[str, int],
        sync_socket: socket,
        wg: WgClient,
        peer_address: tuple[Any, ...],
        interval: float = 0.0,
    ) -> None:
        if interval < 0.0:
            raise ValueError

        self._qkd_address = qkd_address
        self._sync_socket = sync_socket
        self._peer_address = peer_address
        self._wg = wg

        self._interval = interval
        self._key_delay = self._interval + (120.0 - self._interval % 120.0)
        self._open = False

    def __enter__(self) -> Self:
        self._open = True
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> bool | None:
        self._open = False
        return None

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

        delay = 0.0
        while True:
            # Restart after delay, delay only after the first iteration.
            sleep(delay)
            delay = 5.0

            logger.debug(f"Connecting to QKD device on {self._qkd_address}")

            with QkdClient(
                self._qkd_address,
                stream_id,
                str(self._wg.peer_key),
                WgClient.KEY_SIZE,
                key_delay,
            ) as qkd:
                logger.info(f"Opened QKD stream {stream_id}")

                if (auth_psk := qkd.wait_key()) is None:
                    logger.warning("QKD stream closed")
                    break
                with SyncClient(
                    self._sync_socket, self._peer_address, auth_psk=auth_psk[0]
                ) as sync:
                    logger.debug("Wait for initial key")
                    if (
                        psk := qkd.wait_key()
                    ) is None or not sync.sync_current_position(
                        psk[1], timeout=self.SYNC_TIMEOUT
                    ):
                        logger.warning("Unable to fetch and sync initial key")
                        continue

                    while True:
                        key_time = self._ensure_psk(psk[0])

                        if self._interval > (key_age := time() - key_time):
                            logger.debug(
                                f"Wait {self._interval - key_age} for interval"
                            )
                            sleep(self._interval - key_age)

                        logger.debug("Wait for key")
                        psk = qkd.wait_key()
                        if psk is None or not sync.sync_current_position(
                            psk[1], timeout=self.SYNC_TIMEOUT
                        ):
                            logger.warning("Unable to fetch and sync key")
                            break  # Restart QKD

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
        logger.info(f"PSK set at {psk_time}")

        # Wait for the handshake that uses the PSK.
        if (handshake_time := self._wg.handshake_time) < psk_time:
            handshake_age = time() - handshake_time
            if handshake_age < WgClient.REKEY_DELAY:
                logger.debug(
                    f"Wait {WgClient.REKEY_DELAY - handshake_age} for next handshake"
                )
                sleep(WgClient.REKEY_DELAY - handshake_age)

            # If there is a PSK mismatch, or the network is down,
            # recheck the handshake time every REKEY_TIMEOUT seconds.
            # This allows a remote to catch up.
            while (handshake_time := self._wg.handshake_time) < psk_time:
                sleep(WgClient.REKEY_TIMEOUT)

        # At this point a handshake occurred that appeared after setting
        # the PSK. Most likely, the PSK is in use. If both sides set the
        # PSK slightly too late, the previous PSK is being used, the
        # current PSK will be used on the next handshake (or the next
        # PSK, if the PSK rolled).
        logger.debug(f"PSK assumed enabled at {handshake_time}")

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
        "--interval",
        metavar="SECONDS",
        required=False,
        type=float,
        default=0.0,
        help="Minimum delay between PSK updates",
    )
    parser.add_argument(
        "--sync_port",
        metavar="PORT",
        required=True,
        type=int,
        help="Port to listen on for synchronization messages",
    )
    parser.add_argument(
        "--peer_port",
        metavar="PORT",
        required=True,
        type=int,
        help="Port to send synchronization messages to",
    )
    parser.add_argument(
        "--sync_address",
        metavar="ADDRESS",
        required=False,
        type=str,
        default=None,
        help="Interface to bind to for synchronization messages",
    )
    parser.add_argument(
        "--peer_address",
        metavar="ADDRESS",
        required=False,
        type=str,
        default=None,
        help="Peer address to send synchronization messages to (derived from the WireGuard link if not specified)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Disable normal log output",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug log output",
    )

    args = parser.parse_args()

    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.ERROR
    else:
        level = logging.INFO

    logging.basicConfig(level=level)
    logging.getLogger("pyroute2.netlink").setLevel(logging.ERROR)

    if args.interval % WgClient.REKEY_DELAY != 0:
        print(
            f"WARN: PSK interval is not a multiple of the rekey delay ({WgClient.REKEY_DELAY} seconds)."
        )

    with WgClient(interface=args.interface, peer_key=args.peer_key) as wg:
        peer_address: tuple[AddressFamily, SocketKind, tuple[Any, ...]]
        if args.peer_address is None:
            addr = wg.peer_address.addr
            peer_address = (
                AddressFamily(wg.peer_address.family),
                SocketKind.SOCK_DGRAM,
                (str(addr), args.peer_port),
            )
        else:
            for gai_addr in getaddrinfo(
                args.peer_address,
                args.peer_port,
                type=SocketKind.SOCK_DGRAM,
                proto=IPPROTO_UDP,
            ):
                peer_address = (gai_addr[0], gai_addr[1], gai_addr[4])
                break
            else:
                raise RuntimeError(
                    f"Unable to resolve peer address {args.peer_address}"
                )

        with socket(family=peer_address[0], type=peer_address[1]) as sync_socket:
            sync_socket.bind((args.sync_address or "", args.sync_port))

            with QkdGuard(
                (args.host, args.port),
                sync_socket,
                wg,
                peer_address[2],
                args.interval,
            ) as client:
                client.run()


if __name__ == "__main__":
    main()
