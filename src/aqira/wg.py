from sys import stderr
from types import TracebackType
from typing import ClassVar, Self, cast
from wgnlpy import (
    PresharedKey,
    PublicKey,
    WireGuard,
)
from wgnlpy.wireguardpeer import (
    WireGuardPeer,
)


class WgClient:
    KEY_SIZE: ClassVar[int] = 32
    REKEY_DELAY: ClassVar[float] = 120.0
    REKEY_TIMEOUT: ClassVar[float] = 5.0

    def __init__(
        self,
        interface: str,
        peer_key: PublicKey,
    ) -> None:
        self._interface = interface
        self._peer = peer_key
        self._wg: WireGuard | None = None

        self.disable_on_close = False

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

    @property
    def public_key(self) -> bytes:
        wg_iface = self._wg.get_interface(self._interface)
        return bytes(wg_iface.public_key)

    @property
    def peer_key(self) -> bytes:
        return bytes(self._peer)

    @property
    def handshake_time(self) -> float:
        assert self._wg is not None, "must be connected"
        peer = cast(
            "WireGuardPeer | None",
            self._wg.get_interface(self._interface).peers.get(self._peer, None),
        )
        if peer is None:
            msg = f"peer {self._peer} is no longer configured for interface {self._interface}"
            raise RuntimeError(msg)
        return cast("float | None", peer.last_handshake_time) or 0.0

    def open(self) -> None:
        wg = WireGuard()
        wg_iface = wg.get_interface(self._interface)
        if self._peer not in wg_iface.peers:
            msg = f"peer {self._peer} not known to {self._interface}"
            raise ValueError(msg)

        self._wg = wg

    def close(self) -> None:
        assert self._wg is not None, "must be connected"

        # Invalidating the PSK will render the link unusable on the next
        # handshake.
        if self.disable_on_close:
            try:
                self.set_psk(PresharedKey.generate())
            except BaseException as e:
                print(f"Failed to invalidate PSK: {e}", file=stderr)

        wg, self._wg = self._wg, None
        # Superfluous, but WireGuard just implements __del__
        del wg

    def set_psk(self, key: PresharedKey) -> None:
        """
        Set the PSK to the given key.
        """
        assert self._wg is not None, "must be connected"
        self._wg.set_peer(
            self._interface,
            public_key=self._peer,
            preshared_key=key,
            update_only=True,
        )
