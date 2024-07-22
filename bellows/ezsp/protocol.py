from __future__ import annotations

import abc
import asyncio
import binascii
import functools
import logging
import sys
from typing import TYPE_CHECKING, Any, AsyncGenerator, Callable, Iterable

import zigpy.state

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout  # pragma: no cover
else:
    from asyncio import timeout as asyncio_timeout  # pragma: no cover

from bellows.config import CONF_EZSP_POLICIES
from bellows.exception import InvalidCommandError
import bellows.types as t

if TYPE_CHECKING:
    from bellows.uart import Gateway

LOGGER = logging.getLogger(__name__)
EZSP_CMD_TIMEOUT = 6  # Sum of all ASH retry timeouts: 0.4 + 0.8 + 1.6 + 3.2


class ProtocolHandler(abc.ABC):
    """EZSP protocol specific handler."""

    COMMANDS = {}
    VERSION = None

    def __init__(self, cb_handler: Callable, gateway: Gateway) -> None:
        self._handle_callback = cb_handler
        self._awaiting = {}
        self._gw = gateway
        self._seq = 0
        self.COMMANDS_BY_ID = {
            cmd_id: (name, tx_schema, rx_schema)
            for name, (cmd_id, tx_schema, rx_schema) in self.COMMANDS.items()
        }
        self.tc_policy = 0

    def _ezsp_frame(self, name: str, *args: Any, **kwargs: Any) -> bytes:
        """Serialize the named frame and data."""
        c, tx_schema, rx_schema = self.COMMANDS[name]
        frame = self._ezsp_frame_tx(name)

        if isinstance(tx_schema, dict):
            assert not kwargs
            data = t.serialize_dict(args, tx_schema)
        else:
            data = tx_schema(*args, **kwargs).serialize()
        return frame + data

    @abc.abstractmethod
    def _ezsp_frame_rx(self, data: bytes) -> tuple[int, int, bytes]:
        """Handler for received data frame."""

    @abc.abstractmethod
    def _ezsp_frame_tx(self, name: str) -> bytes:
        """Serialize the named frame."""

    async def command(self, name, *args, **kwargs) -> Any:
        """Serialize command and send it."""
        LOGGER.debug("Sending command  %s: %s", name, args)
        data = self._ezsp_frame(name, *args, **kwargs)
        cmd_id, _, rx_schema = self.COMMANDS[name]
        future = asyncio.get_running_loop().create_future()
        self._awaiting[self._seq] = (cmd_id, rx_schema, future)
        self._seq = (self._seq + 1) % 256

        async with asyncio_timeout(EZSP_CMD_TIMEOUT):
            await self._gw.send_data(data)
            return await future

    async def update_policies(self, policy_config: dict) -> None:
        """Set up the policies for what the NCP should do."""

        policies = self.SCHEMAS[CONF_EZSP_POLICIES](policy_config)
        self.tc_policy = policies[t.EzspPolicyId.TRUST_CENTER_POLICY.name]

        for policy, value in policies.items():
            (status,) = await self.setPolicy(t.EzspPolicyId[policy], value)
            assert (
                t.sl_Status.from_ember_status(status) == t.sl_Status.OK
            )  # TODO: Better check

    def __call__(self, data: bytes) -> None:
        """Handler for received data frame."""
        orig_data = data
        sequence, frame_id, data = self._ezsp_frame_rx(data)

        try:
            frame_name, _, rx_schema = self.COMMANDS_BY_ID[frame_id]
        except KeyError:
            LOGGER.warning(
                "Unknown application frame 0x%04X received: %s (%s).  This is a bug!",
                frame_id,
                binascii.hexlify(data),
                binascii.hexlify(orig_data),
            )
            return

        try:
            if isinstance(rx_schema, dict):
                result, data = t.deserialize_dict(data, rx_schema)
                LOGGER.debug("Received command %s: %s", frame_name, result)
                result = list(result.values())
            else:
                result, data = rx_schema.deserialize(data)
                LOGGER.debug("Received command %s: %s", frame_name, result)
        except Exception:
            LOGGER.warning(
                "Failed to parse frame %s: %s",
                frame_name,
                binascii.hexlify(data),
                exc_info=True,
            )
            raise

        if data:
            LOGGER.debug("Frame contains trailing data: %s", data)

        if sequence in self._awaiting:
            expected_id, schema, future = self._awaiting.pop(sequence)
            try:
                if frame_name == "invalidCommand":
                    sent_cmd_name = self.COMMANDS_BY_ID[expected_id][0]
                    future.set_exception(
                        InvalidCommandError(
                            f"{sent_cmd_name} command is an {frame_name}, was sent "
                            f"under {sequence} sequence number: {result[0].name}"
                        )
                    )
                    return

                assert expected_id == frame_id
                future.set_result(result)
            except asyncio.InvalidStateError:
                LOGGER.debug(
                    "Error processing %s response. %s command timed out?",
                    sequence,
                    self.COMMANDS_BY_ID.get(expected_id, [expected_id])[0],
                )
        else:
            self._handle_callback(frame_name, result)

    def __getattr__(self, name: str) -> Callable:
        if name not in self.COMMANDS:
            raise AttributeError(f"{name} not found in COMMANDS")

        return functools.partial(self.command, name)

    async def pre_permit(self, time_s: int) -> None:
        """Schedule task before allowing new joins."""

    async def add_transient_link_key(
        self, ieee: t.EUI64, key: t.KeyData
    ) -> t.sl_Status:
        """Add a transient link key."""

    @abc.abstractmethod
    async def read_child_data(
        self,
    ) -> AsyncGenerator[tuple[t.NWK, t.EUI64, t.EmberNodeType], None]:
        raise NotImplementedError

    @abc.abstractmethod
    async def read_link_keys(self) -> AsyncGenerator[zigpy.state.Key, None]:
        raise NotImplementedError

    @abc.abstractmethod
    async def read_address_table(self) -> AsyncGenerator[tuple[t.NWK, t.EUI64], None]:
        raise NotImplementedError

    @abc.abstractmethod
    async def get_network_key(self) -> zigpy.state.Key:
        raise NotImplementedError

    @abc.abstractmethod
    async def get_tc_link_key(self) -> zigpy.state.Key:
        raise NotImplementedError

    @abc.abstractmethod
    async def write_nwk_frame_counter(self, frame_counter: t.uint32_t) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def write_aps_frame_counter(self, frame_counter: t.uint32_t) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def write_link_keys(self, keys: Iterable[zigpy.state.Key]) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def write_child_data(self, children: dict[t.EUI64, t.NWK]) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def initialize_network(self) -> t.sl_Status:
        raise NotImplementedError

    @abc.abstractmethod
    async def factory_reset(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def send_unicast(
        self,
        nwk: t.NWK,
        aps_frame: t.EmberApsFrame,
        message_tag: t.uint8_t,
        data: bytes,
    ) -> tuple[t.sl_Status, t.uint8_t]:
        raise NotImplementedError

    @abc.abstractmethod
    async def send_multicast(
        self,
        aps_frame: t.EmberApsFrame,
        radius: t.uint8_t,
        non_member_radius: t.uint8_t,
        message_tag: t.uint8_t,
        data: bytes,
    ) -> tuple[t.sl_Status, t.uint8_t]:
        raise NotImplementedError

    @abc.abstractmethod
    async def send_broadcast(
        self,
        address: t.BroadcastAddress,
        aps_frame: t.EmberApsFrame,
        radius: t.uint8_t,
        message_tag: t.uint8_t,
        aps_sequence: t.uint8_t,
        data: bytes,
    ) -> tuple[t.sl_Status, t.uint8_t]:
        raise NotImplementedError
