from __future__ import annotations

import abc
import asyncio
import binascii
import dataclasses
import enum
import logging
import time

from zigpy.types import BaseDataclassMixin

import bellows.types as t

_LOGGER = logging.getLogger(__name__)

FLAG = b"\x7E"  # Marks end of frame
ESCAPE = b"\x7D"
XON = b"\x11"  # Resume transmission
XOFF = b"\x13"  # Stop transmission
SUBSTITUTE = b"\x18"
CANCEL = b"\x1A"  # Terminates a frame in progress

RESERVED = frozenset(FLAG + ESCAPE + XON + XOFF + SUBSTITUTE + CANCEL)

# Initial value of t_rx_ack, the maximum time the NCP waits to receive acknowledgement
# of a DATA frame
T_RX_ACK_INIT = 1.6

# Minimum value of t_rx_ack
T_RX_ACK_MIN = 0.4

# Maximum value of t_rx_ack
T_RX_ACK_MAX = 3.2

# Delay before sending a non-piggybacked acknowledgement
T_TX_ACK_DELAY = 0.02

# Time from receiving an ACK or NAK with the nRdy flag set after which the NCP resumes
# sending callback frames to the host without requiring an ACK or NAK with the nRdy
# flag clear
T_REMOTE_NOTRDY = 1.0

# Maximum number of DATA frames the NCP can transmit without having received
# acknowledgements
TX_K = 5

# Maximum number of consecutive timeouts allowed while waiting to receive an ACK before
# going to the FAILED state. The value 0 prevents the NCP from entering the error state
# due to timeouts.
ACK_TIMEOUTS = 4


def generate_random_sequence(length: int) -> bytes:
    output = bytearray()
    rand = 0x42

    for _i in range(length):
        output.append(rand)

        if rand & 0b00000001 == 0:
            rand = rand >> 1
        else:
            rand = (rand >> 1) ^ 0xB8

    return output


# Since the sequence is static for every frame, we only need to generate it once
PSEUDO_RANDOM_DATA_SEQUENCE = generate_random_sequence(256)


class NCPState(enum.Enum):
    CONNECTED = "connected"
    FAILED = "failed"


class AshException(Exception):
    pass


class NotAcked(AshException):
    def __init__(self, frame: NakFrame):
        self.frame = frame

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(" f"frame={self.frame}" f")>"


class OutOfSequenceError(AshException):
    def __init__(self, expected_seq: int, frame: AshFrame):
        self.expected_seq = expected_seq
        self.frame = frame

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__}("
            f"expected_seq={self.expected_seq}"
            f", frame={self.frame}"
            f")>"
        )


class AshFrame(abc.ABC, BaseDataclassMixin):
    MASK: t.uint8_t
    MASK_VALUE: t.uint8_t

    @classmethod
    def from_bytes(cls, data: bytes) -> DataFrame:
        raise NotImplementedError()

    def to_bytes(self) -> bytes:
        raise NotImplementedError()

    @classmethod
    def _unwrap(cls, data: bytes) -> tuple[int, bytes]:
        if len(data) < 3:
            raise ValueError(f"Frame is too short: {data!r}")

        computed_crc = binascii.crc_hqx(data[:-2], 0xFFFF).to_bytes(2, "big")

        if computed_crc != data[-2:]:
            raise ValueError(f"Invalid CRC bytes in frame {data!r}")

        return data[0], data[1:-2]

    @staticmethod
    def append_crc(data: bytes) -> bytes:
        return data + binascii.crc_hqx(data, 0xFFFF).to_bytes(2, "big")


@dataclasses.dataclass(frozen=True)
class DataFrame(AshFrame):
    MASK = 0b10000000
    MASK_VALUE = 0b00000000

    frm_num: int
    re_tx: bool
    ack_num: int
    ezsp_frame: bytes

    @staticmethod
    def _randomize(data: bytes) -> bytes:
        assert len(data) <= len(PSEUDO_RANDOM_DATA_SEQUENCE)
        return bytes([a ^ b for a, b in zip(data, PSEUDO_RANDOM_DATA_SEQUENCE)])

    @classmethod
    def from_bytes(cls, data: bytes) -> DataFrame:
        control, data = cls._unwrap(data)

        return cls(
            frm_num=(control & 0b01110000) >> 4,
            re_tx=(control & 0b00001000) >> 3,
            ack_num=(control & 0b00000111) >> 0,
            ezsp_frame=cls._randomize(data),
        )

    def to_bytes(self, *, randomize: bool = True) -> bytes:
        return self.append_crc(
            bytes(
                [
                    self.MASK_VALUE
                    | (self.frm_num) << 4
                    | (self.re_tx) << 3
                    | (self.ack_num) << 0
                ]
            )
            + self._randomize(self.ezsp_frame)
        )

    def __str__(self) -> str:
        return f"DATA(num={self.frm_num}, ack={self.ack_num}, re_tx={self.re_tx}) = {self.ezsp_frame.hex()}"


@dataclasses.dataclass(frozen=True)
class AckFrame(AshFrame):
    MASK = 0b11100000
    MASK_VALUE = 0b10000000

    res: int
    ncp_ready: bool
    ack_num: int

    @classmethod
    def from_bytes(cls, data: bytes) -> AckFrame:
        control, data = cls._unwrap(data)

        return cls(
            res=(control & 0b00010000) >> 4,
            ncp_ready=(control & 0b00001000) >> 3,
            ack_num=(control & 0b00000111) >> 0,
        )

    def to_bytes(self) -> bytes:
        return self.append_crc(
            bytes(
                [
                    self.MASK_VALUE
                    | (self.res) << 4
                    | (self.ncp_ready) << 3
                    | (self.ack_num) << 0
                ]
            )
        )

    def __str__(self) -> str:
        return f"ACK(ack={self.ack_num}, ready={'+' if self.ncp_ready == 0 else '-'!r})"


@dataclasses.dataclass(frozen=True)
class NakFrame(AshFrame):
    MASK = 0b11100000
    MASK_VALUE = 0b10100000

    res: int
    ncp_ready: bool
    ack_num: int

    @classmethod
    def from_bytes(cls, data: bytes) -> AckFrame:
        control, data = cls._unwrap(data)

        return cls(
            res=(control & 0b00010000) >> 4,
            ncp_ready=(control & 0b00001000) >> 3,
            ack_num=(control & 0b00000111) >> 0,
        )

    def to_bytes(self) -> bytes:
        return self.append_crc(
            bytes(
                [
                    self.MASK_VALUE
                    | (self.res) << 4
                    | (self.ncp_ready) << 3
                    | (self.ack_num) << 0
                ]
            )
        )

    def __str__(self) -> str:
        return f"NAK(ack={self.ack_num}, ready={'+' if self.ncp_ready == 0 else '-'!r})"


@dataclasses.dataclass(frozen=True)
class RstFrame(AshFrame):
    MASK = 0b11111111
    MASK_VALUE = 0b11000000

    @classmethod
    def from_bytes(cls, data: bytes) -> RstFrame:
        control, data = cls._unwrap(data)

        if data:
            raise ValueError(f"Invalid data for RST frame: {data!r}")

        return cls()

    def to_bytes(self) -> bytes:
        return self.append_crc(bytes([self.MASK_VALUE]))

    def __str__(self) -> str:
        return "RST()"


@dataclasses.dataclass(frozen=True)
class RStackFrame(AshFrame):
    MASK = 0b11111111
    MASK_VALUE = 0b11000001

    version: t.uint8_t
    reset_code: t.NcpResetCode

    @classmethod
    def from_bytes(cls, data: bytes) -> RStackFrame:
        control, data = cls._unwrap(data)

        if len(data) != 2:
            raise ValueError(f"Invalid data length for RSTACK frame: {data!r}")

        version = data[0]

        if version != 0x02:
            raise ValueError(f"Invalid version for RSTACK frame: {version}")

        reset_code = t.NcpResetCode(data[1])

        return cls(
            version=version,
            reset_code=reset_code,
        )

    def to_bytes(self) -> bytes:
        return self.append_crc(bytes([self.MASK_VALUE]) + self.data)

    def __str__(self) -> str:
        return f"RSTACK(ver={self.version}, code={self.reset_code})"


@dataclasses.dataclass(frozen=True)
class ErrorFrame(RStackFrame):
    MASK_VALUE = 0b11000010

    def __str__(self) -> str:
        return f"ERROR(ver={self.version}, code={self.reset_code})"


class AshProtocol(asyncio.Protocol):
    def __init__(self, ezsp_protocol) -> None:
        self._ezsp_protocol = ezsp_protocol
        self._transport = None
        self._buffer = bytearray()
        self._discarding_until_flag: bool = False
        self._pending_data_frames: dict[int, asyncio.Future] = {}
        self._ncp_state = NCPState.CONNECTED
        self._send_data_frame_semaphore = asyncio.Semaphore(TX_K)
        self._tx_seq: int = 0
        self._rx_seq: int = 0
        self._t_rx_ack = T_RX_ACK_INIT

    def connection_made(self, transport):
        self._transport = transport
        self._ezsp_protocol.connection_made(self)

    def connection_lost(self, exc):
        self._ezsp_protocol.connection_lost(exc)

    def eof_received(self):
        self._ezsp_protocol.eof_received()

    def _get_tx_seq(self) -> int:
        result = self._tx_seq
        self._tx_seq = (self._tx_seq + 1) % 8

        return result

    def close(self):
        if self._transport is not None:
            self._transport.close()

    def _extract_frame(self, data: bytes) -> AshFrame:
        control_byte = data[0]

        for frame in [
            DataFrame,
            AckFrame,
            NakFrame,
            RstFrame,
            RStackFrame,
            ErrorFrame,
        ]:
            if control_byte & frame.MASK == frame.MASK_VALUE:
                return frame.from_bytes(data)
        else:
            raise ValueError(f"Could not determine frame type: {data!r}")

    @staticmethod
    def _stuff_bytes(data: bytes) -> bytes:
        """Stuff bytes for transmission"""
        out = bytearray()

        for c in data:
            if c in RESERVED:
                out.extend([ESCAPE[0], c ^ 0b00100000])
            else:
                out.append(c)

        return out

    @staticmethod
    def _unstuff_bytes(data: bytes) -> bytes:
        """Unstuff bytes after receipt"""
        out = bytearray()
        escaped = False

        for c in data:
            if escaped:
                byte = c ^ 0b00100000
                assert byte in RESERVED
                out.append(byte)
                escaped = False
            elif c == ESCAPE[0]:
                escaped = True
            else:
                out.append(c)

        return out

    def data_received(self, data: bytes) -> None:
        _LOGGER.debug("Received data: %s", data.hex())
        self._buffer.extend(data)

        while self._buffer:
            if self._discarding_until_flag:
                if FLAG not in self._buffer:
                    self._buffer.clear()
                    return

                self._discarding_until_flag = False
                _, _, self._buffer = self._buffer.partition(FLAG)

            if self._buffer.startswith(FLAG):
                # Consecutive Flag Bytes after the first Flag Byte are ignored
                self._buffer = self._buffer[1:]
            elif self._buffer.startswith(CANCEL):
                # all data received since the previous Flag Byte to be ignored
                _, _, self._buffer = self._buffer.partition(CANCEL)
            elif self._buffer.startswith(XON):
                _LOGGER.debug("Received XON byte, resuming transmission")
                self._buffer = self._buffer[1:]
            elif self._buffer.startswith(XOFF):
                _LOGGER.debug("Received XOFF byte, pausing transmission")
                self._buffer = self._buffer[1:]
            elif self._buffer.startswith(SUBSTITUTE):
                self._discarding_until_flag = True
                self._buffer = self._buffer[1:]
            elif FLAG in self._buffer:
                frame_bytes, _, self._buffer = self._buffer.partition(FLAG)
                data = self._unstuff_bytes(frame_bytes)

                try:
                    frame = self._extract_frame(data)
                except ValueError:
                    _LOGGER.warning(
                        "Failed to parse frame %r", frame_bytes, exc_info=True
                    )
                else:
                    self.frame_received(frame)
            else:
                break

    def _handle_ack(self, frame: DataFrame | AckFrame) -> None:
        # Note that ackNum is the number of the next frame the receiver expects and it
        # is one greater than the last frame received.
        ack_num = (frame.ack_num - 1) % 8

        fut = self._pending_data_frames.get(ack_num)

        if fut is None:
            _LOGGER.warning("Received an unexpected ACK: %r", frame)
            return
        elif fut.done():
            _LOGGER.debug("Received a double ACK, ignoring...")
            return

        _LOGGER.debug("Resolving frame %d", ack_num)
        self._pending_data_frames[ack_num].set_result(True)

    def frame_received(self, frame: AshFrame) -> None:
        _LOGGER.debug("Received frame %r", frame)

        if isinstance(frame, DataFrame):
            # The Host may not piggyback acknowledgments and should promptly send an ACK
            # frame when it receives a DATA frame.

            if frame.frm_num == self._rx_seq:
                self._handle_ack(frame)
                self._rx_seq = (frame.frm_num + 1) % 8
                self._write_frame(AckFrame(res=0, ncp_ready=0, ack_num=self._rx_seq))

                self._ezsp_protocol.data_received(frame.ezsp_frame)
            elif frame.re_tx:
                # Retransmitted frames must be immediately ACKed even if they are out of
                # sequence
                self._write_frame(AckFrame(res=0, ncp_ready=0, ack_num=self._rx_seq))
            else:
                _LOGGER.warning("Received an out of sequence frame: %r", frame)
                self._write_frame(NakFrame(res=0, ncp_ready=0, ack_num=self._rx_seq))
        elif isinstance(frame, ErrorFrame):
            self._ezsp_protocol.error_received(frame.reset_code)
        elif isinstance(frame, RStackFrame):
            self._tx_seq = 0
            self._rx_seq = 0
            self._change_ack_timeout(T_RX_ACK_INIT)
            self._ezsp_protocol.reset_received(frame.reset_code)
        elif isinstance(frame, AckFrame):
            self._handle_ack(frame)
        elif isinstance(frame, NakFrame):
            error = NotAcked(frame=frame)
            self._pending_data_frames[frame.ack_num].set_exception(error)

    def _write_frame(self, frame: AshFrame) -> None:
        _LOGGER.debug("Sending frame %r", frame)
        data = self._stuff_bytes(frame.to_bytes()) + FLAG

        _LOGGER.debug("Sending data %s", data.hex())
        self._transport.write(data)

    def _change_ack_timeout(self, new_value: float) -> None:
        new_value = max(T_RX_ACK_MIN, min(new_value, T_RX_ACK_MAX))

        if abs(new_value - self._t_rx_ack) > 0.01:
            _LOGGER.debug(
                "Changing ACK timeout from %0.2f to %0.2f", self._t_rx_ack, new_value
            )

        self._t_rx_ack = new_value

    async def _send_frame(self, frame: AshFrame) -> None:
        if not isinstance(frame, DataFrame):
            # Non-DATA frames can be sent immediately and do not require an ACK
            self._write_frame(frame)
            return

        if self._send_data_frame_semaphore.locked():
            _LOGGER.debug("Semaphore is locked, waiting")

        async with self._send_data_frame_semaphore:
            frm_num = self._tx_seq
            self._tx_seq = (self._tx_seq + 1) % 8

            ack_future = asyncio.get_running_loop().create_future()
            self._pending_data_frames[frm_num] = ack_future

            try:
                for attempt in range(ACK_TIMEOUTS):
                    # Use a fresh ACK number on every retry
                    frame = frame.replace(
                        frm_num=frm_num,
                        re_tx=(attempt > 0),
                        ack_num=self._rx_seq,
                    )

                    send_time = time.monotonic()
                    self._write_frame(frame)

                    try:
                        await asyncio.wait_for(ack_future, timeout=self._t_rx_ack)
                    except asyncio.TimeoutError:
                        _LOGGER.debug("No ACK received in %0.2fs", self._t_rx_ack)
                        # If a DATA frame acknowledgement is not received within the current
                        # timeout value, then t_rx_ack is doubled.
                        self._change_ack_timeout(2 * self._t_rx_ack)
                    else:
                        # Whenever an acknowledgement is received, t_rx_ack is set to 7/8 of
                        # its current value plus 1/2 of the measured time for the
                        # acknowledgement.
                        delta = time.monotonic() - send_time
                        self._change_ack_timeout((7 / 8) * self._t_rx_ack + 0.5 * delta)

                        break
                else:
                    self._enter_failed_state()
                    raise
            finally:
                self._pending_data_frames.pop(frm_num)

    async def send_data(self, data: bytes) -> None:
        await self._send_frame(
            # All of the other fields will be set during transmission/retries
            DataFrame(frm_num=None, re_tx=None, ack_num=None, ezsp_frame=data)
        )

    def send_reset(self) -> None:
        self._write_frame(RstFrame())


def main():
    import ast
    import pathlib
    import sys
    import unittest.mock

    import coloredlogs

    coloredlogs.install(level="DEBUG")

    class CapturingAshProtocol(AshProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._parsed_frames = []

        def frame_received(self, frame: AshFrame) -> None:
            self._parsed_frames.append(frame)

    with pathlib.Path(sys.argv[1]).open("r") as f:
        for line in f:
            if "bellows.uart" not in line:
                continue

            if "Sending: " in line:
                direction = " --->"
            elif (
                "Data frame:" in line or "ACK frame: " in line or "NAK frame: " in line
            ):
                direction = "<--- "
            else:
                continue

            data = bytes.fromhex(ast.literal_eval(line.split(": b", 1)[1]))

            # Data frames are logged already unstuffed
            if direction == "<--- ":
                data = AshProtocol._stuff_bytes(data[:-1]) + data[-1:]

            protocol = CapturingAshProtocol(ezsp_protocol=unittest.mock.Mock())
            protocol.data_received(data)

            if len(protocol._parsed_frames) != 1:
                raise ValueError(f"Failed to parse frames: {protocol._parsed_frames}")

            frame = protocol._parsed_frames[0]

            _LOGGER.info("%s: %s", direction, frame)


if __name__ == "__main__":
    main()
