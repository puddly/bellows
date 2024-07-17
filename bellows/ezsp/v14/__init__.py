""""EZSP Protocol version 14 protocol handler."""
from __future__ import annotations

from typing import AsyncGenerator

import voluptuous as vol
from zigpy.exceptions import NetworkNotFormed
import zigpy.state

import bellows.config
import bellows.types as t

from . import commands, config, types as v14_types
from ..v13 import EZSPv13


class EZSPv14(EZSPv13):
    """EZSP Version 14 Protocol version handler."""

    VERSION = 14
    COMMANDS = commands.COMMANDS
    SCHEMAS = {
        bellows.config.CONF_EZSP_CONFIG: vol.Schema(config.EZSP_SCHEMA),
        bellows.config.CONF_EZSP_POLICIES: vol.Schema(config.EZSP_POLICIES_SCH),
    }
    types = v14_types

    async def read_address_table(self) -> AsyncGenerator[tuple[t.NWK, t.EUI64], None]:
        (status, addr_table_size) = await self.getConfigurationValue(
            self.types.EzspConfigId.CONFIG_ADDRESS_TABLE_SIZE
        )

        for idx in range(addr_table_size):
            (status, nwk, eui64) = await self.getAddressTableInfo(idx)

            if status != t.sl_Status.OK:
                continue

            if eui64 in (
                t.EUI64.convert("00:00:00:00:00:00:00:00"),
                t.EUI64.convert("FF:FF:FF:FF:FF:FF:FF:FF"),
            ):
                continue

            yield nwk, eui64

    async def get_network_key(self) -> zigpy.state.Key:
        status, network_key_data, _ = await self.exportKey(
            self.types.sl_zb_sec_man_context_t(
                core_key_type=self.types.sl_zb_sec_man_key_type_t.NETWORK,
                key_index=0,
                derived_type=self.types.sl_zb_sec_man_derived_key_type_t.NONE,
                eui64=t.EUI64.convert("00:00:00:00:00:00:00:00"),
                multi_network_index=0,
                flags=self.types.sl_zb_sec_man_flags_t.NONE,
                psa_key_alg_permission=0,
            )
        )

        assert t.sl_Status.from_ember_status(status) == t.sl_Status.OK

        (status, network_key_info) = await self.getNetworkKeyInfo()
        assert t.sl_Status.from_ember_status(status) == t.sl_Status.OK

        if not network_key_info.network_key_set:
            raise NetworkNotFormed("Network key is not set")

        return zigpy.state.Key(
            key=network_key_data,
            tx_counter=network_key_info.network_key_frame_counter,
            seq=network_key_info.network_key_sequence_number,
        )

    async def get_tc_link_key(self) -> zigpy.state.Key:
        status, tc_link_key_data, _ = await self.exportKey(
            self.types.sl_zb_sec_man_context_t(
                core_key_type=self.types.sl_zb_sec_man_key_type_t.TC_LINK,
                key_index=0,
                derived_type=self.types.sl_zb_sec_man_derived_key_type_t.NONE,
                eui64=t.EUI64.convert("00:00:00:00:00:00:00:00"),
                multi_network_index=0,
                flags=self.types.sl_zb_sec_man_flags_t.NONE,
                psa_key_alg_permission=0,
            )
        )

        assert t.sl_Status.from_ember_status(status) == t.sl_Status.OK

        return zigpy.state.Key(key=tc_link_key_data)