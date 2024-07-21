import bellows.types as t

from ..v9.commands import COMMANDS as COMMANDS_v9

COMMANDS = {
    **COMMANDS_v9,
    # Use the correct `EmberChildData` object with the extra field
    "getChildData": (
        0x004A,
        (t.uint8_t,),
        (t.EmberStatus, t.EmberChildDataV10),
    ),
    "setChildData": (
        0x00AC,
        (t.uint8_t, t.EmberChildDataV10),
        (t.EmberStatus,),
    ),
}
