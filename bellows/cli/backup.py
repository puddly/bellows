import asyncio
import datetime
import json
import logging
import os

import click
import voluptuous as vol
from zigpy.config.validators import cv_hex, cv_key
import zigpy.types
import zigpy.zdo.types

import bellows
import bellows.types as t

from . import util
from .main import main

LOGGER = logging.getLogger(__name__)

ATTR_CHANNELS = "channels"
ATTR_EXT_PAN_ID = "extendedPanId"
ATTR_KEY = "key"
ATTR_KEY_BITMASK = "bitmask"
ATTR_KEY_FRAME_COUNTER_IN = "incomingFrameCounter"
ATTR_KEY_FRAME_COUNTER_OUT = "outgoingFrameCounter"
ATTR_KEY_GLOBAL = "tc_link_key"
ATTR_KEY_NWK = "network_key"
ATTR_KEY_PARTNER = "partnerEUI64"
ATTR_KEY_SEQ = "sequenceNumber"
ATTR_KEY_TABLE = "key_table"
ATTR_KEY_TYPE = "type"
ATTR_NODE_EUI64 = "node_ieee"
ATTR_NODE_ID = "node_id"
ATTR_NODE_TYPE = "node_type"
ATTR_NWK_UPDATE_ID = "nwkUpdateId"
ATTR_PAN_ID = "panId"
ATTR_RADIO_CHANNEL = "radioChannel"
ATTR_RADIO_TX_PWR = "radioTxPower"

SCHEMA_KEY = vol.Schema(
    {
        ATTR_KEY_BITMASK: cv_hex,
        ATTR_KEY_TYPE: cv_hex,
        ATTR_KEY: cv_key,
        ATTR_KEY_FRAME_COUNTER_OUT: cv_hex,
        ATTR_KEY_FRAME_COUNTER_IN: cv_hex,
        ATTR_KEY_SEQ: cv_hex,
        ATTR_KEY_PARTNER: vol.All(str, t.EmberEUI64.convert),
    }
)
SCHEMA_BAK = vol.Schema(
    {
        ATTR_CHANNELS: cv_hex,
        ATTR_NODE_TYPE: cv_hex,
        ATTR_NODE_ID: cv_hex,
        ATTR_NODE_EUI64: vol.All(str, t.EmberEUI64.convert),
        ATTR_NWK_UPDATE_ID: cv_hex,
        ATTR_PAN_ID: cv_hex,
        ATTR_RADIO_CHANNEL: cv_hex,
        ATTR_RADIO_TX_PWR: cv_hex,
        ATTR_EXT_PAN_ID: vol.All(str, t.ExtendedPanId.convert),
        ATTR_KEY_GLOBAL: SCHEMA_KEY,
        ATTR_KEY_NWK: SCHEMA_KEY,
        ATTR_KEY_TABLE: vol.Any([], vol.Schema([SCHEMA_KEY])),
    }
)


def _print_cb(frame_name, response):
    LOGGER.debug("%s callback: %s", frame_name, response)


@main.command()
@click.pass_context
@util.background
async def backup(ctx):
    """Backup NCP config to stdio."""
    ezsp = await util.setup(ctx.obj["device"], ctx.obj["baudrate"], _print_cb)

    try:
        await _backup(ezsp)
    finally:
        ezsp.close()


async def _backup(ezsp):
    (status,) = await ezsp.networkInit()
    LOGGER.debug("Network init status: %s", status)
    assert status == t.EmberStatus.SUCCESS

    (status, node_type, network) = await ezsp.getNetworkParameters()
    assert status == t.EmberStatus.SUCCESS
    assert node_type == ezsp.types.EmberNodeType.COORDINATOR
    LOGGER.debug("Network params: %s", network)

    (ieee,) = await ezsp.getEui64()

    (status, nwk_key) = await ezsp.getKey(ezsp.types.EmberKeyType.CURRENT_NETWORK_KEY)
    assert status == t.EmberStatus.SUCCESS
    LOGGER.debug("Network key: %s", nwk_key)

    (status, tclk) = await ezsp.getKey(ezsp.types.EmberKeyType.TRUST_CENTER_LINK_KEY)
    assert status == t.EmberStatus.SUCCESS
    LOGGER.debug("TCLK: %s", tclk)

    addresses = {}

    for idx in range(0, 255 + 1):
        (entry_is_active,) = await ezsp.addressTableEntryIsActive(idx)

        if not entry_is_active:
            continue

        (nwk,) = await ezsp.getAddressTableRemoteNodeId(idx)
        (eui64,) = await ezsp.getAddressTableRemoteEui64(idx)

        LOGGER.debug("NWK for %s is %s", eui64, nwk)
        addresses[eui64] = nwk

    keys = {}

    for idx in range(0, 192):
        LOGGER.debug("Getting key index %s", idx)
        (status, key_struct) = await ezsp.getKeyTableEntry(idx)
        if status == t.EmberStatus.INDEX_OUT_OF_RANGE:
            break
        elif status == t.EmberStatus.SUCCESS:
            keys[key_struct.partnerEUI64] = key_struct

    now = datetime.datetime.now().astimezone()
    result = {
        "metadata": {
            "version": 1,
            "format": "zigpy/open-coordinator-backup",
            "source": f"bellows@{bellows.__version__}",
            "internal": {
                "creation_time": now.isoformat(timespec="seconds"),
            },
        },
        "coordinator_ieee": ieee.serialize()[::-1].hex(),
        "pan_id": network.panId.serialize()[::-1].hex(),
        "extended_pan_id": network.extendedPanId.serialize()[::-1].hex(),
        "nwk_update_id": network.nwkUpdateId,
        # "security_level": network.security_level,
        "security_level": 5,
        "channel": network.radioChannel,
        "channel_mask": list(network.channels),
        "network_key": {
            "key": nwk_key.key.serialize().hex(),
            "sequence_number": nwk_key.sequenceNumber,
            "frame_counter": nwk_key.outgoingFrameCounter,
        },
        "devices": [
            {
                "ieee_address": key.partnerEUI64.serialize()[::-1].hex(),
                "link_key": {
                    "key": key.key.serialize().hex(),
                    "rx_counter": key.incomingFrameCounter,
                    "tx_counter": key.outgoingFrameCounter,
                },
                "nwk_address": None,
            }
            for key in []
        ],
    }

    click.echo(json.dumps(result))


async def _backup_keys(ezsp):
    """Backup keys."""

    keys = []
    for idx in range(0, 192):
        LOGGER.debug("Getting key index %s", idx)
        (status, key_struct) = await ezsp.getKeyTableEntry(idx)
        if status == t.EmberStatus.SUCCESS:
            keys.append(key_struct)
        elif status == t.EmberStatus.INDEX_OUT_OF_RANGE:
            break
    return keys


@main.command()
@click.option(
    "--i-understand-i-can-update-eui64-only-once-and-i-still-want-to-do-it",
    is_flag=True,
    required=False,
    default=False,
    help=(
        "EUI64 can be overridden using a manufacturer token only once and will not "
        "accept new changes once it is set"
    ),
)
@click.option("-f", "--force", is_flag=True, required=False, default=False)
@click.option("-B", "--backup-file", type=str, required=True)
@click.option(
    "-U", "--upgrade-to-hashed-tc-link-key", is_flag=True, required=False, default=False
)
@click.pass_context
@util.background
async def restore(
    ctx,
    backup_file,
    force,
    i_understand_i_can_update_eui64_only_once_and_i_still_want_to_do_it,
    upgrade_to_hashed_tc_link_key,
):
    """Backup NCP config to stdio."""
    click.echo("Restoring NCP")
    try:
        with open(backup_file, "r") as file:
            backup_data = json.load(file)
            LOGGER.debug("loaded: %s", backup_data)
            backup_data = SCHEMA_BAK(backup_data)
            LOGGER.debug("schema pass: %s", backup_data)
    except OSError as exc:
        LOGGER.error("Couldn't import backup file: %s", exc)
        return
    except vol.Error as exc:
        LOGGER.error("backup file does not pass schema validation: %s", exc)
        return

    LOGGER.info("backup file: %s", backup_data)

    ezsp = await util.setup(ctx.obj["device"], ctx.obj["baudrate"], _print_cb)
    try:
        await _restore(
            ezsp,
            backup_data,
            force,
            i_understand_i_can_update_eui64_only_once_and_i_still_want_to_do_it,
            upgrade_to_hashed_tc_link_key,
        )
    finally:
        ezsp.close()


async def _restore(
    ezsp, backup_data, force, update_eui64_token=False, upg_tc_link_key=False
):
    """Restore backup."""

    (status,) = await ezsp.networkInit()
    LOGGER.debug("Network init status: %s", status)
    assert status in (t.EmberStatus.SUCCESS, t.EmberStatus.NOT_JOINED)

    if status == t.EmberStatus.SUCCESS:
        if not force:
            click.echo("Network is up, not forcing restore")
            return
        try:
            (status,) = await ezsp.leaveNetwork()
            if status != t.EmberStatus.NETWORK_DOWN:
                LOGGER.error("Couldn't leave network")
                return
        except asyncio.TimeoutError:
            LOGGER.error("Didn't not receive stack changed status callback")
            return

    if update_eui64_token:
        ncp_eui64 = t.EmberEUI64(backup_data[ATTR_NODE_EUI64]).serialize()
        (status,) = await ezsp.setMfgToken(
            t.EzspMfgTokenId.MFG_CUSTOM_EUI_64, ncp_eui64
        )

    sec_bitmask = (
        t.EmberInitialSecurityBitmask.HAVE_PRECONFIGURED_KEY
        | t.EmberInitialSecurityBitmask.REQUIRE_ENCRYPTED_KEY
        | t.EmberInitialSecurityBitmask.TRUST_CENTER_GLOBAL_LINK_KEY
        | t.EmberInitialSecurityBitmask.HAVE_NETWORK_KEY
        | t.EmberInitialSecurityBitmask.NO_FRAME_COUNTER_RESET
    )
    if not is_well_known_key(backup_data[ATTR_KEY_GLOBAL][ATTR_KEY]):
        sec_bitmask |= t.EmberInitialSecurityBitmask.TRUST_CENTER_USES_HASHED_LINK_KEY

    init_sec_state = t.EmberInitialSecurityState(
        bitmask=sec_bitmask,
        preconfiguredKey=backup_data[ATTR_KEY_GLOBAL][ATTR_KEY],
        networkKey=backup_data[ATTR_KEY_NWK][ATTR_KEY],
        networkKeySequenceNumber=backup_data[ATTR_KEY_NWK][ATTR_KEY_SEQ],
        preconfiguredTrustCenterEui64=[0x00] * 8,
    )
    if (
        upg_tc_link_key
        and t.EmberInitialSecurityBitmask.TRUST_CENTER_USES_HASHED_LINK_KEY
        not in sec_bitmask
    ):
        init_sec_state.bitmask |= (
            t.EmberInitialSecurityBitmask.TRUST_CENTER_USES_HASHED_LINK_KEY
        )
        init_sec_state.preconfiguredKey = t.EmberKeyData(os.urandom(16))

    (status,) = await ezsp.setInitialSecurityState(init_sec_state)
    LOGGER.debug("Set initial security state: %s", status)
    assert status == t.EmberStatus.SUCCESS

    if backup_data[ATTR_KEY_TABLE]:
        await _restore_keys(ezsp, backup_data[ATTR_KEY_TABLE])

    network_key = backup_data[ATTR_KEY_NWK]
    (status,) = await ezsp.setValue(
        ezsp.types.EzspValueId.VALUE_NWK_FRAME_COUNTER,
        t.uint32_t(network_key[ATTR_KEY_FRAME_COUNTER_OUT]).serialize(),
    )
    LOGGER.debug("Set network frame counter: %s", status)
    assert status == t.EmberStatus.SUCCESS

    tc_key = backup_data[ATTR_KEY_GLOBAL]
    (status,) = await ezsp.setValue(
        ezsp.types.EzspValueId.VALUE_APS_FRAME_COUNTER,
        t.uint32_t(tc_key[ATTR_KEY_FRAME_COUNTER_OUT]).serialize(),
    )
    LOGGER.debug("Set network frame counter: %s", status)
    assert status == t.EmberStatus.SUCCESS

    await _form_network(ezsp, backup_data)
    await asyncio.sleep(2)


async def _restore_keys(ezsp, key_table):
    """Restore keys."""

    (status,) = await ezsp.setConfigurationValue(
        ezsp.types.EzspConfigId.CONFIG_KEY_TABLE_SIZE, len(key_table)
    )
    assert status == t.EmberStatus.SUCCESS

    for key in key_table:
        is_link_key = key[ATTR_KEY_TYPE] in (
            ezsp.types.EmberKeyType.APPLICATION_LINK_KEY,
            ezsp.types.EmberKeyType.TRUST_CENTER_LINK_KEY,
        )
        (status,) = await ezsp.addOrUpdateKeyTableEntry(
            key[ATTR_KEY_PARTNER], is_link_key, key[ATTR_KEY]
        )
        if status != t.EmberStatus.SUCCESS:
            LOGGER.warning("Couldn't add %s key: %s", key, status)
        await asyncio.sleep(0.2)


async def _form_network(ezsp, backup_data):
    """Form network."""
    network = t.EmberNetworkParameters(
        panId=backup_data[ATTR_PAN_ID],
        extendedPanId=backup_data[ATTR_EXT_PAN_ID],
        radioTxPower=backup_data[ATTR_RADIO_TX_PWR],
        radioChannel=backup_data[ATTR_RADIO_CHANNEL],
        joinMethod=t.EmberJoinMethod.USE_MAC_ASSOCIATION,
        nwkManagerId=0x0000,
        nwkUpdateId=backup_data[ATTR_NWK_UPDATE_ID],
        channels=backup_data[ATTR_CHANNELS],
    )
    (status,) = await ezsp.formNetwork(network)
    LOGGER.debug("Form network: %s", status)
    assert status == t.EmberStatus.NETWORK_UP

    await _update_nwk_id(ezsp, backup_data[ATTR_NWK_UPDATE_ID])

    (status,) = await ezsp.setValue(ezsp.types.EzspValueId.VALUE_STACK_TOKEN_WRITING, 1)
    LOGGER.debug("Set token writing: %s", status)
    assert status == t.EmberStatus.SUCCESS


async def _update_nwk_id(ezsp, nwk_update_id):
    """Update NWK id by sending a ZDO broadcast."""

    aps_frame = t.EmberApsFrame(
        profileId=0x0000,
        clusterId=zigpy.zdo.types.ZDOCmd.Mgmt_NWK_Update_req,
        sourceEndpoint=0x00,
        destinationEndpoint=0x00,
        options=t.EmberApsOption.APS_OPTION_NONE,
        groupId=0x0000,
        sequence=0xDE,
    )
    nwk_update_id = t.uint8_t(nwk_update_id).serialize()
    payload = b"\xDE" + zigpy.types.Channels.ALL_CHANNELS.serialize() + b"\xFF"
    payload += nwk_update_id + b"\x00\x00"

    status, _ = await ezsp.sendBroadcast(
        zigpy.types.BroadcastAddress.ALL_DEVICES,
        aps_frame,
        0x00,
        0x01,
        payload,
    )
    assert status == t.EmberStatus.SUCCESS
    await asyncio.sleep(1)


def is_well_known_key(tc_link_key):
    """Return True if this is a well known key."""
    well_known_key = t.EmberKeyData.deserialize(b"ZigBeeAlliance09")[0]
    return tc_link_key == well_known_key
