from dataclasses import dataclass
from hashlib import blake2s
from socket import SocketIO, socket, socketpair
from threading import Condition, Thread
from types import TracebackType
from typing import Any, ClassVar, Self
from wgnlpy import PresharedKey  # pyright: ignore[reportMissingTypeStubs]
import hmac
import logging
import pickle
import selectors

logger = logging.getLogger(__name__)


@dataclass
class Message:
    MAX_MESSAGE_SIZE: ClassVar[int] = 4 + 1 + blake2s.MAX_DIGEST_SIZE

    position: int
    retry: bool
    mac: bytes

    @classmethod
    def new(cls, position: int, retry: bool, key: PresharedKey) -> Message:
        msg = Message(
            position=position,
            retry=retry,
            mac=bytes(),
        )
        msg.mac = hmac.digest(bytes(key), msg._payload(), digest=blake2s)
        return msg

    @classmethod
    def decode(cls, msg: bytes | bytearray) -> Message:
        position = int.from_bytes(msg[:4], byteorder="little", signed=False)
        retry = bool.from_bytes(msg[4:5])
        mac = bytes(msg[5:])
        return Message(position=position, retry=retry, mac=mac)

    def encode(self) -> bytes:
        msg = self._payload()
        msg.extend(self.mac)
        return bytes(msg)

    def _payload(self) -> bytearray:
        msg = bytearray()
        msg.extend(self.position.to_bytes(4, byteorder="little", signed=False))
        msg.extend(self.retry.to_bytes(1))
        return msg

    def validate(self, key: PresharedKey) -> bool:
        return hmac.digest(bytes(key), self._payload(), digest=blake2s) == self.mac


class SyncClient:
    PEER_RESEND_DELAY: ClassVar[float] = 5.0
    """
    Time to wait for peer messages before resending the current
    position.
    """

    def __init__(
        self,
        sync_socket: socket,
        peer_address: tuple[Any, ...],
        auth_psk: PresharedKey,
    ) -> None:
        self._sync_socket = sync_socket
        self._peer_address = peer_address
        self._auth_psk = auth_psk

        self._sock: socket | None = None
        self._last_peer_position: int | None = None
        self._peer_position_cond = Condition()
        self._thread: Thread | None = None
        self._thread_comm: SocketIO | None = None

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> bool | None:
        self.stop()
        return None

    def start(self) -> None:
        assert self._thread_comm is None, "must be stopped"
        assert self._thread is None, "must be stopped"

        comm_r, comm_w = socketpair()
        thread = Thread(
            target=self._run,
            args=(comm_r.makefile("rb", buffering=0),),
        )
        thread.start()
        self._thread = thread
        self._thread_comm = comm_w.makefile("wb", buffering=0)

    def stop(self) -> None:
        assert self._thread_comm is not None, "must be started"
        assert self._thread is not None, "must be started"

        thread_comm, self._thread_comm = self._thread_comm, None
        thread, self._thread = self._thread, None

        thread_comm.close()
        thread.join()

    def sync_current_position(
        self, position: int, timeout: float | None = None
    ) -> bool | None:
        assert self._thread_comm is not None, "must be started"
        assert self._peer_position_cond, "must be started"

        pickle.dump(obj=position, file=self._thread_comm)
        self._thread_comm.flush()

        def check_pos() -> bool:
            return self._last_peer_position is not None and (
                self._last_peer_position == position or self._last_peer_position == -1
            )

        with self._peer_position_cond:
            result = self._peer_position_cond.wait_for(check_pos, timeout=timeout)

        if self._last_peer_position == -1:
            return None
        else:
            return result

    def _read_message(self) -> bool:
        reply_data, reply_addr = self._sync_socket.recvfrom(Message.MAX_MESSAGE_SIZE)
        logger.debug(f"Received message from {reply_addr[0]}")
        if reply_addr[0] != self._peer_address[0]:
            logger.debug(
                f"Reply address mismatch, {reply_addr[0]} != {self._peer_address[0]}"
            )
            return False

        reply_msg = Message.decode(reply_data)
        if not reply_msg.validate(self._auth_psk):
            logger.debug("Message uses invalid key")
            return False

        if reply_msg.retry:
            return True

        if self._last_peer_position is not None:
            # Ignore stale messages.
            # Ignore resends if the position is the same.
            if reply_msg.position <= self._last_peer_position:
                logger.debug(f"Stale message with position {reply_msg.position}")
                return False

        logger.debug(f"Remote at position {reply_msg.position}")

        with self._peer_position_cond:
            self._last_peer_position = reply_msg.position
            self._peer_position_cond.notify_all()

        return False

    def _send_message(self, position: int, retry: bool) -> None:
        msg = Message.new(position=position, retry=retry, key=self._auth_psk)
        logger.debug(f"Sending message position {position} to {self._peer_address}")
        self._sync_socket.sendto(msg.encode(), self._peer_address)

    def _run(self, input_sock: SocketIO) -> None:
        try:
            self._run_sync(input_sock=input_sock)
        except BaseException:
            logger.exception("Exception in sync thread")
            raise
        finally:
            with self._peer_position_cond:
                self._last_peer_position = -1
                self._peer_position_cond.notify_all()

    def _run_sync(self, input_sock: SocketIO) -> None:
        current_position: int | None = None

        with selectors.DefaultSelector() as selector:
            selector.register(self._sync_socket, selectors.EVENT_READ)
            selector.register(input_sock, selectors.EVENT_READ)

            while True:
                # Resend if the peer is behind
                timeout = (
                    self.PEER_RESEND_DELAY
                    if current_position is not None
                    and (
                        self._last_peer_position is None
                        or current_position > self._last_peer_position
                    )
                    else None
                )
                items = selector.select(timeout=timeout)
                if len(items) == 0:
                    # Timeout. If peer is running behind, resend current
                    # position.
                    if current_position is not None:
                        self._send_message(position=current_position, retry=True)
                    continue
                for key, _ in items:
                    if key.fileobj is input_sock:
                        try:
                            position = pickle.load(input_sock)
                            assert type(position) is int, "position is int"
                        except EOFError:
                            # Connection closed, stop thread
                            return
                        current_position = position
                        assert current_position is not None
                        self._send_message(position=current_position, retry=False)

                    if key.fileobj is self._sync_socket:
                        if self._read_message() and current_position is not None:
                            self._send_message(current_position, False)
