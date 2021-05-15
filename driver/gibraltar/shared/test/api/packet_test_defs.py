#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

#!/usr/bin/env python3

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *
from scapy.layers.l2 import *
from enum import Enum
from io import StringIO
from leaba import sdk
import decor

load_contrib('mpls')

# Scapy extension
# Scapy is extended with the following parts:
# 1. Ethertype enum .
# 2. Additional binding of ethertype to protocols.
# 3. Propritery protocol definitions - Punt/Inject headers.

RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'


class Ethertype(Enum):
    IPv4 = 0x0800                                 # IPv4
    IPv6 = 0x86dd                                 # IPv6
    Dot1Q = 0x8100                                # VLAN-tagged frame (802.1q) and Shortest Path Bridging (802.1aq)
    SVLAN = 0x88a8                                # Provider Bridging (802.1ad) and Shortest Path Bridging (802.1aq)
    QinQ = 0x9100                                 # Legacy QinQ/802.ad
    Unknown = 0xbead                              # Dummy unknown Ethertype value
    MPLS = 0x8847                                 # MPLS
    Inject = 0x7103                               # Inject
    Punt = 0x7102                                 # Punt
    PortExtender = 0x7101                         # PortExtender TPID
    LLDP = 0x88cc                                 # LLDP
    LACP = 0x8809                                 # LACP
    FlowControl = 0x8808                          # Ethernet flow control
    SVL = 0x7104                                  # SVL


# Adding vlan header type to Ether protocol
bind_layers(Ether, Dot1Q, type=Ethertype.QinQ.value)

# Adding MPLS label decoding until bottom-of-stack is reached
bind_layers(MPLS, MPLS, s=0)

# If after MPLS comes IPv4/6 then need to manually code that.
# This is the decoding function.


def mpls_guess_payload_class(self, payload):
    if not self.s:
        return MPLS
    if len(payload) >= 1:
        ip_version = (payload[0] >> 4) & 0xF
        if ip_version == 4:
            return IP
        elif ip_version == 6:
            return IPv6
    return Padding


def parse_ip_after_mpls():
    MPLS.guess_payload_class = mpls_guess_payload_class

# Helper that abstracts IPv4 and IPv6 as a single IP header


def IPvX(**kwargs):
    # Sanity
    assert('ipvx' in kwargs), "no 'ipvx' parameter defined."

    ipvx = kwargs['ipvx']
    assert(ipvx in ['v4', 'v6']), "unsupported value for 'ipvx'=%s parameter" % ipvx

    # Remove the IP type indication
    kwargs.pop('ipvx')

    # Add support for providing a DSCP field, which resides in tos[7:2]
    tos = None

    if 'dscp' in kwargs:
        assert('tc' not in kwargs), "IPvX with ipvx=%s doesn't support setting both 'dscp' and 'tc' " % ipvx
        assert('tos' not in kwargs), "IPvX with ipvx=%s doesn't support setting both 'dscp' and 'tos' " % ipvx

        dscp = kwargs.pop('dscp')
        tos = dscp << 2

    if 'ecn' in kwargs:
        assert('tc' not in kwargs), "IPvX with ipvx=%s doesn't support setting both 'ecn' and 'tc' " % ipvx
        assert('tos' not in kwargs), "IPvX with ipvx=%s doesn't support setting both 'ecn' and 'tos' " % ipvx

        ecn = kwargs.pop('ecn')
        if tos is not None:
            # If tos was set by DSCP, preserve its value
            tos |= ecn
        else:
            tos = ecn

    if tos is not None:
        kwargs['tos'] = tos

    # Return the requested IP type
    if ipvx == 'v4':
        return IP(**kwargs)
    else:   # v6
        # Rename the field from their IPv4 names to the IPv6 names
        if 'tos' in kwargs:
            assert('tc' not in kwargs), "IPvX with ipvx=%s doesn't support setting both 'tos' and 'tc' " % ipvx
            kwargs['tc'] = kwargs.pop('tos')
        if 'ttl' in kwargs:
            assert('hlim' not in kwargs), "IPvX with ipvx=%s doesn't support setting both 'ttl' and 'hlim' " % ipvx
            kwargs['hlim'] = kwargs.pop('ttl')
        if 'proto' in kwargs:
            assert('nh' not in kwargs), "IPvX with ipvx=%s doesn't support setting both 'proto' and 'nh' " % ipvx
            kwargs['nh'] = kwargs.pop('proto')

        return IPv6(**kwargs)

# Helper that provides a single PCPDEI field for Dot1Q


def Dot1QPrio(**kwargs):
    if 'pcpdei' in kwargs:
        assert('prio' not in kwargs), "Dot1QPrio doesn't support setting both 'pcpdei' and 'prio' "
        assert('id' not in kwargs), "Dot1QPrio doesn't support setting both 'pcpdei' and 'id' "

        pcpdei = kwargs.pop('pcpdei')
        pcp = pcpdei // 2
        dei = pcpdei % 2
        kwargs['prio'] = pcp
        kwargs['id'] = dei

    return Dot1Q(**kwargs)


class ERSPAN(Packet):
    name = "ERSPAN"
    fields_desc = [
        BitField("version", 1, 4),
        BitField("vlan", 0, 12),
        BitField("cos", 0, 3),
        BitField("en", 0, 2),
        BitField("t", 0, 1),
        BitField("session_id", 0, 10),
        BitField("reserved", 0, 12),
        BitField("index", 0, 20)]

    def mysummary(self):
        return self.sprintf("ERSPAN (session_id=%ERSPAN.session_id%)")


bind_layers(GRE, ERSPAN, proto=0x88be)


class PFC(Packet):
    name = "PFC"
    fields_desc = [
        XBitField("opcode", 0x101, 16),
        XBitField("class_enable_vector", 0x0, 16),
        XBitField("time_class0", 0x0, 16),
        XBitField("time_class1", 0x0, 16),
        XBitField("time_class2", 0x0, 16),
        XBitField("time_class3", 0x0, 16),
        XBitField("time_class4", 0x0, 16),
        XBitField("time_class5", 0x0, 16),
        XBitField("time_class6", 0x0, 16),
        XBitField("time_class7", 0x0, 16),
        BitField("padding", 0x0, 32),
        BitField("padding", 0x0, 32),
        BitField("padding", 0x0, 32),
        BitField("padding", 0x0, 32),
        BitField("padding", 0x0, 32),
        BitField("padding", 0x0, 32),
        BitField("padding", 0x0, 16)]

    def mysummary(self):
        return self.sprintf("PFC (class_enable_vector=%PFC.class_enable_vector%)")


bind_layers(Ether, PFC, type=Ethertype.FlowControl.value)

# BFD definition


class BFD(Packet):
    name = "BFD"
    fields_desc = [
        BitField("version", 1, 3),
        BitField("diag", 0, 5),
        BitField("state", 0, 2),
        FlagsField("flags", 0x00, 6, ['M', 'D', 'A', 'C', 'F', 'P']),
        XByteField("detect_mult", 0x03),
        ByteField("len", 24),
        XBitField("my_discriminator", 0x11111111, 32),
        XBitField("your_discriminator", 0x22222222, 32),
        BitField("min_tx_interval", 1000000000, 32),
        BitField("min_rx_interval", 1000000000, 32),
        BitField("echo_rx_interval", 0, 32)]

    def mysummary(self):
        return self.sprintf("BFD (my_disc=%BFD.my_discriminator%, your_disc=%BFD.my_discriminator%)")


class BFD_ECHO(Packet):
    name = "BFD_ECHO"
    fields_desc = [
        BitField("version", 1, 3),
        BitField("padding", 0, 21),
        ByteField("len", 24),
        BitField("padding", 0x0, 32),
        XBitField("local_discriminator", 0x11111111, 32),
        BitField("padding", 0x0, 32),
        BitField("padding", 0x0, 32),
        BitField("padding", 0x0, 32)]

    def mysummary(self):
        return self.sprintf("BFD_ECHO (local_disc=%BFD_ECHO.local_discriminator%)")


bind_layers(UDP, BFD, dport=3784)
bind_layers(UDP, BFD, dport=4784)
bind_layers(UDP, BFD, dport=6784)
bind_layers(UDP, BFD_ECHO, dport=3785)


class PseudowireControlWord(Packet):

    name = "PseudowireControlWord"
    fields_desc = [
        BitField("channel", 0x0, 4),
        BitField("version", 0x0, 4),
        BitField("reserved", 0x0, 8),
        BitField("seqnumber", 0x0, 16)]

    def mysummary(self):
        return self.sprintf("PseudowireControlWord(channel=%PseudowireControlWord.channel%)")

# Inject Down header


class InjectDown(Packet):
    name = "InjectDown"
    fields_desc = [
        BitField("type", 0, 8),         # Inject type
        BitField("encap", 0, 3),        # Encapsulation type
        BitField("phb_tc", 0, 3),       # Traffic Class of the packet. According to 802.1q, 7 is high.
        BitField("phb_dp", 0, 2),       # Drop Precedence of the packet. 0 means green.
        BitField("dest", 0, 20),        # Destination ID - DSP or BVN.
        BitField("padding1", 0, 8),     # padding.
        BitField("counter_ptr", 0, 20),  # Counter pointer (TBD)
        BitField("l3_dlp", 0, 16),      # L3 DLP
        BitField("down_nh", 0, 12),     # NH

        BitField("padding2", 0, 4),     # padding
        BitField("ts_opcode", 0, 4),    # Time stamp - opcode
        BitField("ts_res2", 0, 1),      #
        BitField("ts_offset", 0, 7),    # Time stamp - offset

        BitField("lm_opcode", 0, 4),    # Counter stamp - opcode
        BitField("lm_res2", 0, 1),      #
        BitField("lm_offset", 0, 7),    # Counter stamp - offset

        BitField("internal", 0, 8),     # Internal use. Must be 0
        BitField("ext_type", 0, 8)     # Type of Inject extension header
    ]

# Inject Up header


class InjectUp(Packet):
    name = "InjectUp"
    fields_desc = [
        BitField("type", 34, 8),         # Inject type (INJECT_HEADER_TYPE_UP_ETH)

        BitField("padding1", 0, 5),     # padding
        BitField("phb_tc", 0, 3),       # Traffic Class of the packet. According to 802.1q, 7 is high.
        BitField("phb_dp", 0, 2),       # Drop Precedence of the packet. 0 means green.
        BitField("qos_group", 0, 7),    # QOS group.
        BitField("fwd_qos_tag", 0, 7),  # QOS tag (DSCP).
        BitField("ssp_gid", 0, 12),     # Source system port GID.
        BitField("counter_ptr", 0, 20),  # Counter pointer (TBD)

        BitField("padding2", 0, 32),    # Padding
        BitField("ts_opcode", 0, 4),    # Time stamp - opcode
        BitField("ts_res2", 0, 1),      #
        BitField("ts_offset", 0, 7),    # Time stamp - offset

        BitField("lm_opcode", 0, 4),    # Counter stamp - opcode
        BitField("lm_res2", 0, 1),      #
        BitField("lm_offset", 0, 7),    # Counter stamp - offset

        BitField("internal", 0, 8),     # Internal
        BitField("ext_type", 0, 8),     # Type of Inject extension header
    ]


class InjectUpStd(Packet):
    name = "InjectUpStd"
    pif_field_len = 7 if decor.is_akpg() else 5
    fields_desc = [
        BitField("type", 38, 8),                     # Inject type (INJECT_HEADER_TYPE_UP_STD_PROCESS)

        BitField("padding1", 0, 5),                  # padding
        BitField("phb_tc", 0, 3),                    # Traffic Class of the packet. According to 802.1q, 7 is high.
        BitField("phb_dp", 0, 2),                    # Drop Precedence of the packet. 0 means green.
        BitField("qos_group", 0, 7),                 # QOS group.
        BitField("fwd_qos_tag", 0, 7),               # QOS tag (DSCP).

        BitField("ifg_id", 0, 1),                    # Source IFG ID.
        BitField("pif_id", 0, pif_field_len),        # Source PIF ID.
        BitField("padding2", 0, 11 - pif_field_len),  # padding
        BitField("counter_ptr", 0, 20),              # Counter pointer (TBD)

        BitField("padding3", 0, 32),                 # Padding
        BitField("ts_opcode", 0, 4),                 # Time stamp - opcode
        BitField("ts_res2", 0, 1),                   #
        BitField("ts_offset", 0, 7),                 # Time stamp - offset

        BitField("lm_opcode", 0, 4),                 # Counter stamp - opcode
        BitField("lm_res2", 0, 1),                   #
        BitField("lm_offset", 0, 7),                 # Counter stamp - offset

        BitField("internal", 0, 8),                  # Internal
        BitField("trailer_size", 0, 8),              # Reserved for internal use. Must be 0. PACKET-DMA-WA
    ]


class InjectUpDestOverride(Packet):
    name = "InjectUpDestOverride"
    fields_desc = [
        BitField("type", 46, 8),          # Inject type (INJECT_TYPE_UP_DESTINATION_OVERRIDE)

        BitField("padding1", 0, 4),       # padding
        BitField("destination", 0, 20),   # Destination
        BitField("ssp_gid", 0, 12),       # Source system port GID.
        BitField("counter_ptr", 0, 20),   # Counter pointer (TBD)

        BitField("padding2", 0, 32),      # Padding
        BitField("ts_opcode", 0, 4),      # Time stamp - opcode
        BitField("ts_res2", 0, 1),        #
        BitField("ts_offset", 0, 7),      # Time stamp - offset

        BitField("lm_opcode", 0, 4),      # Counter stamp - opcode
        BitField("lm_res2", 0, 1),        #
        BitField("lm_offset", 0, 7),      # Counter stamp - offset

        BitField("internal", 0, 8),       # Internal
        BitField("ext_type", 0, 8),       # Type of Inject extension header
    ]


class Trailer8Bytes(Packet):
    name = "Trailer8Bytes"
    fields_desc = [
        BitField("trailer", 0, 64)      # Trailer
    ]


class InjectUpDirectWithTrailer(Packet):  # PACKET-DMA-WA : this header should not be used by users, only for NSIM testing
    name = "InjectUpDirectWithTrailer"
    fields_desc = [
        BitField("type", 34, 8),         # Inject type (INJECT_HEADER_TYPE_ETH_UP)

        BitField("padding1", 0, 5),     # padding
        BitField("phb_tc", 0, 3),       # Traffic Class of the packet. According to 802.1q, 7 is high.
        BitField("phb_dp", 0, 2),       # Drop Precedence of the packet. 0 means green.
        BitField("qos_group", 0, 7),    # QOS group.
        BitField("fwd_qos_tag", 0, 7),  # QOS tag (DSCP).
        BitField("ssp_gid", 0, 12),     # Source system port GID.
        BitField("counter_ptr", 0, 20),  # Counter pointer (TBD)

        BitField("padding2", 0, 32),    # Padding
        BitField("ts_opcode", 0, 4),    # Time stamp - opcode
        BitField("ts_res2", 0, 1),      #
        BitField("ts_offset", 0, 7),    # Time stamp - offset

        BitField("lm_opcode", 0, 4),    # Counter stamp - opcode
        BitField("lm_res2", 0, 1),      #
        BitField("lm_offset", 0, 7),    # Counter stamp - offset

        BitField("internal", 0, 8),     # Internal
        BitField("trailer_size", 8, 8),  # Reserved for internal use. Must be 0. PACKET-DMA-WA
        BitField("trailer", 0, 64)      # Trailer
    ]


class PacketDmaWaHeader8(Packet):  # PACKET-DMA-WA : this header should not be used by users, only for NSIM testing
    name = "PacketDmaWaHeader8"
    pif_field_len = 7 if decor.is_akpg() else 5
    fields_desc = [
        BitField("size", 8, 8),                      # Header size in bytes
        BitField("padding1", 0, 5),                  # Padding
        BitField("slice_id", 0, 3),                  # Source SLICE ID
        BitField("ifg_id", 0, 1),                    # Source IFG ID
        BitField("pif_id", 0, pif_field_len),        # Source PIF GID
        BitField("padding2", 0, 47 - pif_field_len),  # Padding
    ]


class PacketDmaWaHeader16(Packet):  # PACKET-DMA-WA : this header should not be used by users, only for NSIM testing
    name = "PacketDmaWaHeader16"
    pif_field_len = 7 if decor.is_akpg() else 5
    fields_desc = [
        BitField("size", 16, 8),                      # Header size in bytes
        BitField("padding1", 0, 5),                   # Padding
        BitField("slice_id", 0, 3),                   # Source SLICE ID
        BitField("ifg_id", 0, 1),                     # Source IFG ID
        BitField("pif_id", 0, pif_field_len),         # Source PIF GID
        BitField("padding2", 0, 111 - pif_field_len),  # Padding
    ]


class KernelHeader(Packet):         # PACKET-DMA-WA : this header should not be used by users, only for NSIM testing
    name = "KernelHeader"
    pif_field_len = 7 if decor.is_akpg() else 5
    fields_desc = [
        XBitField("dummy_mac", 0, 112),       # Header size in bytes
        BitField("pad1", 0, 5),
        BitField("slice_id", 0, 3),
        BitField("ifg", 0, 1),                # IFG
        BitField("pif", 0, pif_field_len),    # PIF
        BitField("pad2", 0, 7 - pif_field_len),
    ]

# Punt header


class Punt(Packet):
    name = "Punt"
    fields_desc = [
        BitField("next_header", 0, 5),         # Next header protocol.
        BitField("fwd_header_type", 0, 4),     # Forward header type.
        BitField("reserved1", 0, 3),           #
        BitField("next_header_offset", 0, 8),  # Offset to L3 header.
        BitField("source", 0, 4),              # Punt source.
        BitField("code", 0, 8),                # Punt code.
        BitField("lpts_flow_type", 0, 8),      # LPTS flow type.
        BitField("source_sp", 0, 16),          # Source system port GID.
        BitField("destination_sp", 0, 16),     # Destination system port GID.
        BitField("source_lp", 0, 20),          # Source logical port GID.
        BitField("destination_lp", 0, 20),     # Destination logical port GID.
        BitField("reserved2", 0, 2),           #
        BitField("relay_id", 0, 14),           # Punt relay ID.
        XBitField("time_stamp", 0, 64),        # Time stamp value.
        XBitField("receive_time", 0, 32),      # Receive time stamp ns value.
    ]

    def guess_payload_class(self, payload):
        if self.source != 0:
            if self.next_header == 4:
                return IP
            elif self.next_header == 6:
                return IPv6
            elif self.next_header == 7:
                return MPLS
        return Ether


class sflow_tunnel_metadata(Packet):
    name = "sflow_tunnel_metadata"
    fields_desc = [
        BitField("source_sp", 0, 16),          # Source system port GID.
        BitField("reserved", 0, 16),           # Reserved.
        BitField("source_lp", 0, 20),          # Source logical port GID.
        BitField("destination_sp", 0, 20),     # Destination system port GID.
    ]


# Bind the following to support sflow Tunnel
bind_layers(UDP, sflow_tunnel_metadata, dport=6343)


class PFC_modified_input_ether(Packet):
    name = "PFC_modified_input_ether"
    fields_desc = [
        XBitField("dst", 0, 48),
        XBitField("device_time", 0, 64),        # Time stamp value.
        XBitField("vlan", 0, 16),
        XBitField("ether_type", 0, 16),
    ]

    def guess_payload_class(self, payload):
        if self.ether_type == 0x800:
            return IP
        if self.ether_type == 0x86dd:
            return IPv6
        if self.ether_type == 0x8847:
            return MPLS
        return Ether


class NPU_host_ext(Packet):
    name = "OAM Punt"
    fields_desc = [
        BitField("first_npe_macro_id", 0, 8),
        BitField("first_fi_macro_id", 0, 8),
        XBitField("ether_type", 0, 16),
    ]


bind_layers(NPU_host_ext, Punt)


class InjectTimeExt(Packet):
    name = "InjectTimeExt"
    fields_desc = [
        XBitField("cpu_time", 0, 32),
    ]


class PTPv2(Packet):
    name = "Precision Time Protocol v2"
    fields_desc = [
        BitField("transport_specific", 0, 4),
        BitField("message_type", 0, 4),
        BitField("reserved", 0, 4),
        BitField("ptp_version", 2, 4),
        BitField("message_length", 54, 16),
        BitField("domain_number", 0, 8),
        BitField("reserved2", 0, 8),
        BitField("flags", 0, 16),
        XBitField("correction_field", 0, 64),
        BitField("reserved3", 0, 32),
        BitField("source_port_id", 0, 80),
        BitField("sequence_id", 0, 16),
        BitField("control", 0, 8),
        BitField("log_message_period", 0, 8)]


class PTPSync(Packet):
    name = "PTP sync"
    fields_desc = [
        XBitField("origin_time_stamp", 0, 80)]


class PTPDelayReq(Packet):
    name = "PTP delay request"
    fields_desc = [
        XBitField("origin_time_stamp", 0, 80)]


class PTPDelayResp(Packet):
    name = "PTP delay response"
    fields_desc = [
        XBitField("receive_time_stamp", 0, 80),
        BitField("requesting_port_id", 0, 80)]


class LearnRecordField(Field):
    name = "MAC learning record"
    fields_desc = [
        BitField("command", 0, 2),
        XBitField("slp", 0x0, 20),
        XBitField("relay_id", 0x0, 14),
        XBitField("mac_sa", 0x0, 48),
        BitField("mact_ldb", 0, 4)]
    LearnRecordLen = 11

    def __init__(self, name):
        Field.__init__(self, name, None, "11s")

    def i2m(self, pkt, x):
        if x is None:
            return b"\0\0\0\0\0\0\0\0\0\0\0"
        if not isinstance(x, str):
            x = x.decode('ascii')
        return b''.join([bytes([int(i, 16)]) for i in x.split(":")])

    def m2i(self, pkt, x):
        return ("%02x:" * 11)[:-1] % tuple(x)

    def any2i(self, pkt, x):
        if isinstance(x, bytes) and len(x) is self.LearnRecordLen:
            x = self.m2i(pkt, x)
        return x


class LearnRecord(Packet):
    name = "MAC learning record"
    fields_desc = [
        BitField("command", 0, 2),
        XBitField("slp", 0x0, 20),
        XBitField("relay_id", 0x0, 14),
        XBitField("mac_sa", 0x0, 48),
        BitField("mact_ldb", 0, 4)]


class LearnRecordHeader(Packet):
    name = "MAC learning record header"
    fields_desc = [
        XBitField("LR header", 0, 32),
        BitField("num_lr_records", 0, 8)]


class LearnRecordTrailer(Packet):
    name = "MAC learning record trailer"
    fields_desc = [
        ShortField("trailer", 0)]


# Inject and Punt headers binding to Ethertype.
bind_layers(Ether, InjectDown, type=Ethertype.Inject.value)
bind_layers(Ether, InjectUp, type=Ethertype.Inject.value)
bind_layers(Ether, InjectUpStd, type=Ethertype.Inject.value)
bind_layers(Ether, InjectUpDirectWithTrailer, type=Ethertype.Inject.value)
bind_layers(Ether, Punt, type=Ethertype.Punt.value)
bind_layers(InjectDown, InjectTimeExt, ext_type=sdk.la_packet_types.LA_INJECT_HEADER_EXT_TYPE_TIME)
bind_layers(InjectUp, InjectTimeExt, ext_type=sdk.la_packet_types.LA_INJECT_HEADER_EXT_TYPE_TIME)
bind_layers(InjectUp, LearnRecordHeader, type=sdk.la_packet_types.LA_PACKET_INJECT_TYPE_UP_LEARN_RECORD)
bind_layers(InjectUpStd, LearnRecordHeader, type=sdk.la_packet_types.LA_PACKET_INJECT_TYPE_UP_LEARN_RECORD)
bind_layers(LearnRecordHeader, LearnRecord)
bind_layers(LearnRecord, LearnRecord)
bind_layers(LearnRecord, LearnRecordTrailer)
bind_layers(Ether, PTPv2, type=0x88f7)
bind_layers(UDP, PTPv2, dport=319)
bind_layers(PTPv2, PTPSync, message_type=0)
bind_layers(PTPv2, PTPDelayReq, message_type=1)
bind_layers(PTPv2, PTPDelayResp, message_type=9)
bind_layers(InjectUpStd, Trailer8Bytes, trailer_size=8)
bind_layers(InjectUpStd, Ether)
bind_layers(Trailer8Bytes, Ether)
bind_layers(KernelHeader, Ether)
bind_layers(PacketDmaWaHeader8, Ether)
bind_layers(PacketDmaWaHeader16, Ether)
bind_layers(Dot1Q, InjectUpStd, type=Ethertype.Inject.value)
bind_layers(Dot1Q, InjectUp, type=Ethertype.Inject.value)

_GP_FLAGS = ["R", "R", "R", "A", "R", "R", "D", "R"]


class ThreeBytesField(X3BytesField, ByteField):
    def i2repr(self, pkt, x):
        return ByteField.i2repr(self, pkt, x)


class VXLAN(Packet):
    name = "VXLAN"

    fields_desc = [
        FlagsField("flags", 0x8, 8,
                   ['OAM', 'R', 'NextProtocol', 'Instance',
                    'V1', 'V2', 'R', 'G']),
        # ConditionalField(
        #    ShortField("reserved0", 0),
        #    lambda pkt: pkt.flags.NextProtocol,
        #),
        # ConditionalField(
        #    ByteEnumField('NextProtocol', 0,
        #                  {0: 'NotDefined',
        #                   1: 'IPv4',
        #                   2: 'IPv6',
        #                   3: 'Ethernet',
        #                   4: 'NSH'}),
        #    lambda pkt: pkt.flags.NextProtocol,
        #),
        # ConditionalField(
        #    ThreeBytesField("reserved1", 0),
        #    lambda pkt: (not pkt.flags.G) and (not pkt.flags.NextProtocol),
        #),
        # ConditionalField(
        #    FlagsField("gpflags", 0, 8, _GP_FLAGS),
        #    lambda pkt: pkt.flags.G,
        #),
        # ConditionalField(
        #    ShortField("gpid", 0),
        #    lambda pkt: pkt.flags.G,
        #),
        X3BytesField("reserved", 0),
        X3BytesField("vni", 0),
        XByteField("reserved2", 0),
    ]

    # Use default linux implementation port
    overload_fields = {
        UDP: {'dport': 8472},
    }

    def mysummary(self):
        if self.flags.G:
            return self.sprintf("VXLAN (vni=%VXLAN.vni% gpid=%VXLAN.gpid%)")
        else:
            return self.sprintf("VXLAN (vni=%VXLAN.vni%)")


bind_layers(UDP, VXLAN, dport=4789)  # RFC standard vxlan port
bind_layers(UDP, VXLAN, dport=4790)  # RFC standard vxlan-gpe port
bind_layers(UDP, VXLAN, dport=6633)  # New IANA assigned port for use with NSH
bind_layers(UDP, VXLAN, dport=8472)  # Linux implementation port
bind_layers(UDP, VXLAN, dport=48879)  # Cisco ACI
bind_layers(UDP, VXLAN, sport=4789)
bind_layers(UDP, VXLAN, sport=4790)
bind_layers(UDP, VXLAN, sport=6633)
bind_layers(UDP, VXLAN, sport=8472)
# By default, set both ports to the RFC standard
bind_layers(UDP, VXLAN, sport=4789, dport=4789)

bind_layers(VXLAN, Ether)
bind_layers(VXLAN, IP, NextProtocol=1)
bind_layers(VXLAN, IPv6, NextProtocol=2)
bind_layers(VXLAN, Ether, flags=4, NextProtocol=0)
bind_layers(VXLAN, IP, flags=4, NextProtocol=1)
bind_layers(VXLAN, IPv6, flags=4, NextProtocol=2)
bind_layers(VXLAN, Ether, flags=4, NextProtocol=3)

LLC = scapy.layers.l2.LLC


class ISO(Packet):
    name = "ISO"
    fields_desc = [ByteField("disc", 0),
                   ByteField("lenIndic", 0),
                   ByteField("idExt", 0),
                   ByteField("idLen", 0),
                   BitField("reserv", 0, 3),
                   BitField("pduType", 0, 5),
                   ByteField("pduVer", 0),
                   ByteField("reserv", 0),
                   ByteField("minArea", 0)
                   ]


bind_layers(LLC, ISO, dsap=0xfe)
