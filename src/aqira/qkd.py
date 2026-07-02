import contextlib
import selectors
from socket import SHUT_WR, create_connection, socket
from types import TracebackType
from typing import Self
from uuid import UUID

from ksnp import CloseDirection, client  # pyright: ignore[reportMissingModuleSource]
from ksnp.client import event  # pyright: ignore[reportMissingModuleSource]
from ksnp.stream import OpenParams

from wgnlpy import PresharedKey  # pyright: ignore[reportMissingTypeStubs]


class QkdClient:
    def __init__(
        self,
        qkd_address: tuple[str, int],
        stream_id: UUID,
        destination: str,
        key_size: int,
        key_delay: float,
    ) -> None:
        self._qkd_address = qkd_address
        self._stream_id = stream_id
        self._destination = destination
        self._key_size = key_size
        self._key_delay = key_delay

        self.position = 0
        self._read_buf = bytearray()
        self._write_buf = bytearray()
        self._client = client.Client(self._read_buf, self._write_buf)

        self._sock: socket | None = None
        self._selector: selectors.DefaultSelector | None = None

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
        return None

    def open(self) -> None:
        try:
            self._sock = create_connection(self._qkd_address)
            self._sock.setblocking(False)
            self._selector = selectors.DefaultSelector()
            self._selector.register(
                self._sock, selectors.EVENT_READ | selectors.EVENT_WRITE
            )
        except:
            if self._sock:
                self._sock.close()
            if self._selector:
                self._selector.close()

            raise

    def close(self) -> None:
        assert self._sock is not None, "must be connected"
        assert self._selector is not None, "must be connected"

        self._client.close_connection(CloseDirection.WRITE)
        while self._wait_event() is not None:
            # Drain the connection
            pass

        with contextlib.suppress(Exception):
            self._selector.close()
        self._selector = None

        with contextlib.suppress(Exception):
            self._sock.close()
        self._sock = None

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

    def wait_key(self) -> tuple[PresharedKey, int] | None:
        while (next_event := self._wait_event()) is not None:
            match next_event:
                case event.Handshake():
                    # Round up to match WG handshake interval
                    self._client.open_stream(
                        OpenParams(
                            destination=self._destination,
                            stream_id=self._stream_id,
                            min_bps=(self._key_size, int(self._key_delay)),
                            capacity=self._key_size,
                        )
                    )
                    continue
                case event.StreamAccepted(parameters=parameters):
                    if parameters.position != 0:
                        msg = "Stream resumption is not supported"
                        raise RuntimeError(msg)
                    self.position = parameters.position
                case event.KeyData(key_data=key_data):
                    assert len(key_data) == self._key_size
                    self._client.add_capacity(self._key_size)
                    position = self.position
                    self.position += len(key_data)
                    return PresharedKey(key_data), position
                case _:
                    return None
        return None
