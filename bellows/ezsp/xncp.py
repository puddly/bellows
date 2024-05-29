"""Custom EZSP commands."""
from __future__ import annotations

import dataclasses
from typing import Callable

import zigpy.types as t

from bellows.types import EmberStatus

COMMANDS: dict[XncpCommandId, type[XncpCommandPayload]] = {}
REV_COMMANDS: dict[type[XncpCommandPayload], XncpCommandId] = {}


def register_command(command_id: XncpCommandId) -> Callable[[type], type]:
    def decorator(cls: type) -> type:
        COMMANDS[command_id] = cls
        REV_COMMANDS[cls] = command_id
        return cls

    return decorator


class Bytes(bytes):
    def serialize(self) -> Bytes:
        return self

    @classmethod
    def deserialize(cls, data: bytes) -> tuple[Bytes, bytes]:
        return cls(data), b""

    def __repr__(self) -> str:
        # Reading byte sequences like \x200\x21 is extremely annoying
        # compared to \x20\x30\x21
        escaped = "".join(f"\\x{b:02X}" for b in self)

        return f"b'{escaped}'"

    __str__ = __repr__


class XncpCommandId(t.enum16):
    GET_SUPPORTED_FEATURES_REQ = 0x0000
    SET_SOURCE_ROUTE_REQ = 0x0001
    GET_BOARD_NAME_REQ = 0x0002
    GET_MANUF_NAME_REQ = 0x0003

    GET_SUPPORTED_FEATURES_RSP = GET_SUPPORTED_FEATURES_REQ | 0x8000
    SET_SOURCE_ROUTE_RSP = SET_SOURCE_ROUTE_REQ | 0x8000
    GET_BOARD_NAME_RSP = GET_BOARD_NAME_REQ | 0x8000
    GET_MANUF_NAME_RSP = GET_MANUF_NAME_REQ | 0x8000

    UNKNOWN = 0xFFFF


@dataclasses.dataclass
class XncpCommand:
    command_id: XncpCommandId
    status: EmberStatus
    payload: XncpCommandPayload

    @classmethod
    def from_payload(cls, payload: XncpCommandPayload) -> XncpCommand:
        return cls(
            command_id=REV_COMMANDS[type(payload)],
            status=EmberStatus.SUCCESS,
            payload=payload,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> XncpCommand:
        command_id, data = XncpCommandId.deserialize(data)
        status, data = EmberStatus.deserialize(data)
        payload = COMMANDS[command_id].deserialize(data)

        return cls(command_id=command_id, status=status, payload=payload)

    def serialize(self) -> Bytes:
        return (
            self.command_id.serialize()
            + self.status.serialize()
            + self.payload.serialize()
        )


class FirmwareFeatures(t.bitmap32):
    NONE = 0

    # The firmware passes through all group traffic, regardless of group membership
    MEMBER_OF_ALL_GROUPS = 1 << 0

    # Source routes can be overridden by the application
    MANUAL_SOURCE_ROUTE = 1 << 1

    # The firmware supports overriding the board name
    BOARD_MANUF = 1 << 2


class XncpCommandPayload(t.Struct):
    pass


@register_command(XncpCommandId.GET_SUPPORTED_FEATURES_REQ)
class GetSupportedFeaturesReq(XncpCommandPayload):
    pass


@register_command(XncpCommandId.GET_SUPPORTED_FEATURES_RSP)
class GetSupportedFeaturesRsp(XncpCommandPayload):
    features: FirmwareFeatures


@register_command(XncpCommandId.SET_SOURCE_ROUTE_REQ)
class SetSourceRouteReq(XncpCommandPayload):
    destination: t.NWK
    source_route: t.List[t.NWK]


@register_command(XncpCommandId.SET_SOURCE_ROUTE_RSP)
class SetSourceRouteRsp(XncpCommandPayload):
    pass


@register_command(XncpCommandId.GET_BOARD_NAME_REQ)
class GetBoardNameReq(XncpCommandPayload):
    pass


@register_command(XncpCommandId.GET_BOARD_NAME_RSP)
class GetBoardNameRsp(XncpCommandPayload):
    board_name: Bytes


@register_command(XncpCommandId.GET_MANUF_NAME_REQ)
class GetManufNameReq(XncpCommandPayload):
    pass


@register_command(XncpCommandId.GET_MANUF_NAME_RSP)
class GetManufNameRsp(XncpCommandPayload):
    manuf_name: Bytes
