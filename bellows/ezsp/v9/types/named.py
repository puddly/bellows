"""Protocol version 9 named types."""

import bellows.types.basic as basic
from bellows.types.named import (  # noqa: F401, F403
    EUI64,
    Bool,
    Channels,
    EmberApsOption,
    EmberBindingType,
    EmberCertificate283k1Data,
    EmberCertificateData,
    EmberConcentratorType,
    EmberConfigTxPowerMode,
    EmberCurrentSecurityBitmask,
    EmberEventUnits,
    EmberGpKeyType,
    EmberGpSecurityLevel,
    EmberIncomingMessageType,
    EmberInitialSecurityBitmask,
    EmberJoinDecision,
    EmberKeyStatus,
    EmberKeyStructBitmask,
    EmberKeyType,
    EmberLibraryId,
    EmberLibraryStatus,
    EmberMacPassthroughType,
    EmberMessageDigest,
    EmberMulticastId,
    EmberNetworkStatus,
    EmberNodeId,
    EmberNodeType,
    EmberOutgoingMessageType,
    EmberPanId,
    EmberPrivateKey283k1Data,
    EmberPrivateKeyData,
    EmberPublicKey283k1Data,
    EmberPublicKeyData,
    EmberSignature283k1Data,
    EmberSignatureData,
    EmberSmacData,
    EmberStackError,
    EmberStatus,
    EmberZdoConfigurationFlags,
    EmberZllKeyIndex,
    EmberZllState,
    ExtendedPanId,
    EzspConfigId,
    EzspDecisionBitmask,
    EzspEndpointFlags,
    EzspExtendedValueId,
    EzspMfgTokenId,
    EzspNetworkScanType,
    EzspPolicyId,
    EzspSourceRouteOverheadInformation,
    EzspStatus,
    EzspValueId,
    EzspZllNetworkOperation,
    KeyData,
    sl_Status,
)


class EzspDecisionId(basic.enum8):
    # Identifies a policy decision.

    # BINDING_MODIFICATION_POLICY default decision. Do not allow the local
    # binding table to be changed by remote nodes.
    DISALLOW_BINDING_MODIFICATION = 0x10
    # BINDING_MODIFICATION_POLICY decision.  Allow remote nodes to change
    # the local binding table.
    ALLOW_BINDING_MODIFICATION = 0x11
    # BINDING_MODIFICATION_POLICY decision.  Allows remote nodes to set local
    # binding entries only if the entries correspond to endpoints defined on
    # the device, and for output clusters bound to those endpoints.
    CHECK_BINDING_MODIFICATIONS_ARE_VALID_ENDPOINT_CLUSTERS = 0x12
    # UNICAST_REPLIES_POLICY default decision.  The NCP will automatically send
    # an empty reply (containing no payload) for every unicast received.
    HOST_WILL_NOT_SUPPLY_REPLY = 0x20
    # UNICAST_REPLIES_POLICY decision. The NCP will only send a reply if it
    # receives a sendReply command from the Host.
    HOST_WILL_SUPPLY_REPLY = 0x21
    # POLL_HANDLER_POLICY default decision. Do not inform the Host when a child polls.
    POLL_HANDLER_IGNORE = 0x30
    # POLL_HANDLER_POLICY decision. Generate a pollHandler callback when a child polls.
    POLL_HANDLER_CALLBACK = 0x31
    # MESSAGE_CONTENTS_IN_CALLBACK_POLICY default decision. Include only the
    # message tag in the messageSentHandler callback.
    MESSAGE_TAG_ONLY_IN_CALLBACK = 0x40
    # MESSAGE_CONTENTS_IN_CALLBACK_POLICY decision. Include both the message
    # tag and the message contents in the messageSentHandler callback.
    MESSAGE_TAG_AND_CONTENTS_IN_CALLBACK = 0x41
    # TC_KEY_REQUEST_POLICY decision. When the Trust Center receives a request
    # for a Trust Center link key, it will be ignored.
    DENY_TC_KEY_REQUESTS = 0x50
    # TC_KEY_REQUEST_POLICY decision. When the Trust Center receives a request for a
    # Trust Center link key, it will reply to it with the corresponding key.
    ALLOW_TC_KEY_REQUESTS_AND_SEND_CURRENT_KEY = 0x51
    # TC_KEY_REQUEST_POLICY decision. When the Trust Center receives a request
    # for a Trust Center link key, it will generate a key to send to the joiner.
    ALLOW_TC_KEY_REQUEST_AND_GENERATE_NEW_KEY = 0x52
    # APP_KEY_REQUEST_POLICY decision. When the Trust Center receives a request
    # for an application link key, it will be ignored.
    DENY_APP_KEY_REQUESTS = 0x60
    # APP_KEY_REQUEST_POLICY decision. When the Trust Center receives a request
    # for an application link key, it will randomly generate a key and send it
    # to both partners.
    ALLOW_APP_KEY_REQUESTS = 0x61
    # Indicates that packet validate library checks are enabled on the NCP.
    PACKET_VALIDATE_LIBRARY_CHECKS_ENABLED = 0x62
    # Indicates that packet validate library checks are NOT enabled on the NCP.
    PACKET_VALIDATE_LIBRARY_CHECKS_DISABLED = 0x63


class EmberDeviceUpdate(basic.enum8):
    # The status of the device update.

    STANDARD_SECURITY_SECURED_REJOIN = 0x0
    STANDARD_SECURITY_UNSECURED_JOIN = 0x1
    DEVICE_LEFT = 0x2
    STANDARD_SECURITY_UNSECURED_REJOIN = 0x3


class EmberCounterType(basic.enum8):
    # Defines the events reported to the application by the
    # readAndClearCounters command.

    # The MAC received a broadcast.
    COUNTER_MAC_RX_BROADCAST = 0
    # The MAC transmitted a broadcast.
    COUNTER_MAC_TX_BROADCAST = 1
    # The MAC received a unicast.
    COUNTER_MAC_RX_UNICAST = 2
    # The MAC successfully transmitted a unicast.
    COUNTER_MAC_TX_UNICAST_SUCCESS = 3
    # The MAC retried a unicast.
    COUNTER_MAC_TX_UNICAST_RETRY = 4
    # The MAC unsuccessfully transmitted a unicast.
    COUNTER_MAC_TX_UNICAST_FAILED = 5
    # The APS layer received a data broadcast.
    COUNTER_APS_DATA_RX_BROADCAST = 6
    # The APS layer transmitted a data broadcast.
    COUNTER_APS_DATA_TX_BROADCAST = 7
    # The APS layer received a data unicast.
    COUNTER_APS_DATA_RX_UNICAST = 8
    # The APS layer successfully transmitted a data unicast.
    COUNTER_APS_DATA_TX_UNICAST_SUCCESS = 9
    # The APS layer retried a data unicast.
    COUNTER_APS_DATA_TX_UNICAST_RETRY = 10
    # The APS layer unsuccessfully transmitted a data unicast.
    COUNTER_APS_DATA_TX_UNICAST_FAILED = 11
    # The network layer successfully submitted a new route discovery to the MAC.
    COUNTER_ROUTE_DISCOVERY_INITIATED = 12
    # An entry was added to the neighbor table.
    COUNTER_NEIGHBOR_ADDED = 13
    # An entry was removed from the neighbor table.
    COUNTER_NEIGHBOR_REMOVED = 14
    # A neighbor table entry became stale because it had not been heard from.
    COUNTER_NEIGHBOR_STALE = 15
    # A node joined or rejoined to the network via this node.
    COUNTER_JOIN_INDICATION = 16
    # An entry was removed from the child table.
    COUNTER_CHILD_REMOVED = 17
    # EZSP-UART only. An overflow error occurred in the UART.
    COUNTER_ASH_OVERFLOW_ERROR = 18
    # EZSP-UART only. A framing error occurred in the UART.
    COUNTER_ASH_FRAMING_ERROR = 19
    # EZSP-UART only. An overrun error occurred in the UART.
    COUNTER_ASH_OVERRUN_ERROR = 20
    # A message was dropped at the network layer because the NWK frame counter
    # was not higher than the last message seen from that source.
    COUNTER_NWK_FRAME_COUNTER_FAILURE = 21
    # A message was dropped at the APS layer because the APS frame counter was
    # not higher than the last message seen from that source.
    COUNTER_APS_FRAME_COUNTER_FAILURE = 22
    # Utility counter for general debugging use.
    COUNTER_UTILITY = 23
    # A message was dropped at the APS layer because it had APS encryption but
    # the key associated with the sender has not been authenticated, and thus
    # the key is not authorized for use in APS data messages.
    COUNTER_APS_LINK_KEY_NOT_AUTHORIZED = 24
    # A NWK encrypted message was received but dropped because decryption
    # failed.
    COUNTER_NWK_DECRYPTION_FAILURE = 25
    # An APS encrypted message was received but dropped because decryption
    # failed.
    COUNTER_APS_DECRYPTION_FAILURE = 26
    # The number of times we failed to allocate a set of linked packet buffers.
    # This doesn't necessarily mean that the packet buffer count was 0 at the
    # time, but that the number requested was greater than the number free.
    COUNTER_ALLOCATE_PACKET_BUFFER_FAILURE = 27
    # The number of relayed unicast packets.
    COUNTER_RELAYED_UNICAST = 28
    # The number of times we dropped a packet due to reaching
    # the preset PHY to MAC queue limit (emMaxPhyToMacQueueLength).
    COUNTER_PHY_TO_MAC_QUEUE_LIMIT_REACHED = 29
    # The number of times we dropped a packet due to the
    # packet-validate library checking a packet and rejecting it
    # due to length or other formatting problems.
    COUNTER_PACKET_VALIDATE_LIBRARY_DROPPED_COUNT = 30
    # The number of times the NWK retry queue is full and a
    # new message failed to be added.
    COUNTER_TYPE_NWK_RETRY_OVERFLOW = 31
    # The number of times the PHY layer was unable to transmit
    # due to a failed CCA.
    COUNTER_PHY_CCA_FAIL_COUNT = 32
    # The number of times a NWK broadcast was dropped because
    # the broadcast table was full.
    COUNTER_BROADCAST_TABLE_FULL = 33
    # The number of low priority packet traffic arbitration requests.
    COUNTER_PTA_LO_PRI_REQUESTED = 34
    # The number of high priority packet traffic arbitration requests.
    COUNTER_PTA_HI_PRI_REQUESTED = 35
    # The number of low priority packet traffic arbitration requests denied.
    COUNTER_PTA_LO_PRI_DENIED = 36
    # The number of high priority packet traffic arbitration requests denied.
    COUNTER_PTA_HI_PRI_DENIED = 37
    # The number of aborted low priority packet traffic arbitration transmissions.
    COUNTER_PTA_LO_PRI_TX_ABORTED = 38
    # The number of aborted high priority packet traffic arbitration transmissions.
    COUNTER_PTA_HI_PRI_TX_ABORTED = 39
    # The number of times an address conflict has caused node_id change, and an address
    # conflict error is sent
    COUNTER_ADDRESS_CONFLICT_SENT = 40


class EmberJoinMethod(basic.enum8):
    # The type of method used for joining.

    # Normally devices use MAC Association to join a network, which respects
    # the "permit joining" flag in the MAC Beacon. For mobile nodes this value
    # causes the device to use an Ember Mobile Node Join, which is functionally
    # equivalent to a MAC association. This value should be used by default.
    USE_MAC_ASSOCIATION = 0x0
    # For those networks where the "permit joining" flag is never turned on,
    # they will need to use a ZigBee NWK Rejoin. This value causes the rejoin
    # to be sent without NWK security and the Trust Center will be asked to
    # send the NWK key to the device. The NWK key sent to the device can be
    # encrypted with the device's corresponding Trust Center link key. That is
    # determined by the ::EmberJoinDecision on the Trust Center returned by the
    # ::emberTrustCenterJoinHandler(). For a mobile node this value will cause
    # it to use an Ember Mobile node rejoin, which is functionally equivalent.
    USE_NWK_REJOIN = 0x1
    # For those networks where the "permit joining" flag is never turned on,
    # they will need to use a NWK Rejoin. If those devices have been
    # preconfigured with the NWK key (including sequence number) they can use a
    # secured rejoin. This is only necessary for end devices since they need a
    # parent. Routers can simply use the ::USE_NWK_COMMISSIONING join method
    # below.
    USE_NWK_REJOIN_HAVE_NWK_KEY = 0x2
    # For those networks where all network and security information is known
    # ahead of time, a router device may be commissioned such that it does not
    # need to send any messages to begin communicating on the network.
    USE_CONFIGURED_NWK_STATE = 0x3


class EmberNetworkInitBitmask(basic.bitmap16):
    # Bitmask options for emberNetworkInit().

    # No options for Network Init
    NETWORK_INIT_NO_OPTIONS = 0x0000
    # Save parent info (node ID and EUI64) in a token during joining/rejoin,
    # and restore on reboot.
    NETWORK_INIT_PARENT_INFO_IN_TOKEN = 0x0001
    # Send a rejoin request as an end device on reboot if parent information is
    # persisted. ZB3 end devices must rejoin on reboot.
    NETWORK_INIT_END_DEVICE_REJOIN_ON_REBOOT = 0x0002


EmberNetworkInitStruct = EmberNetworkInitBitmask


class EmberMultiPhyNwkConfig(basic.enum8):
    """Network configuration for the desired radio interface for multi phy network."""

    # Enable broadcast support on Routers
    BROADCAST_SUPPORT = 0x01


class EmberDutyCycleState(basic.enum8):
    """Duty cycle states."""

    # No Duty cycle tracking or metrics are taking place
    DUTY_CYCLE_TRACKING_OFF = 0
    # Duty Cycle is tracked and has not exceeded any thresholds.
    DUTY_CYCLE_LBT_NORMAL = 1
    # We have exceeded the limited threshold of our total duty cycle allotment.
    DUTY_CYCLE_LBT_LIMITED_THRESHOLD_REACHED = 2
    # We have exceeded the critical threshold of our total duty cycle allotment.
    DUTY_CYCLE_LBT_CRITICAL_THRESHOLD_REACHED = 3
    # We have reached the suspend limit and are blocking all outbound transmissions.
    DUTY_CYCLE_LBT_SUSPEND_LIMIT_REACHED = 4


class EmberRadioPowerMode(basic.enum8):
    """Radio power mode."""

    # The radio receiver is switched on.
    RADIO_POWER_MODE_RX_ON = 0
    # The radio receiver is switched off.
    RADIO_POWER_MODE_OFF = 1


class EmberEntropySource(basic.enum8):
    """Entropy sources."""

    # Entropy source error
    ENTROPY_SOURCE_ERROR = 0
    # Entropy source is the radio.
    ENTROPY_SOURCE_RADIO = 1
    # Entropy source is the TRNG powered by mbed TLS.
    ENTROPY_SOURCE_MBEDTLS_TRNG = 2
    # Entropy source is powered by mbed TLS, the source is not TRNG.
    ENTROPY_SOURCE_MBEDTLS = 3


class EmberDutyCycleHectoPct(basic.uint16_t):
    """The percent of duty cycle for a limit.

    Duty Cycle, Limits, and Thresholds are reported in units of Percent * 100
    (i.e. 10000 = 100.00%, 1 = 0.01%)
    """


class EmberGpProxyTableEntryStatus(basic.uint8_t):
    """The proxy table entry status."""


class EmberGpSecurityFrameCounter(basic.uint32_t):
    """The security frame counter"""


class EmberGpSinkTableEntryStatus(basic.uint8_t):
    """The sink table entry status."""


class SecureEzspSecurityType(basic.uint32_t):
    """Security type of the Secure EZSP Protocol."""


class SecureEzspSecurityLevel(basic.uint8_t):
    """Security level of the Secure EZSP Protocol."""


class SecureEzspRandomNumber(basic.FixedList[basic.uint8_t, 16]):
    """Randomly generated 64-bit number.

    Both NCP and Host contribute this number to create the Session ID,
    which is used in the nonce.
    """


class SecureEzspSessionId(basic.FixedList[basic.uint8_t, 8]):
    """Generated 64-bit Session ID, using random numbers from Host and NCP.

    It is generated at each reboot (during negotiation phase). Having both sides
    contribute to the value prevents one side from choosing a number that might have
    been previously used (either because of a bug or by malicious intent).
    """
