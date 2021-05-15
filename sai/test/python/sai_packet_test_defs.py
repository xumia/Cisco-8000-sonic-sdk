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
from enum import Enum
from io import StringIO
from leaba import sdk

load_contrib('mpls')

# File contains Scapy extensions for more protocols. Copied from SDK Python tests


class Ethertype(Enum):
    IPv4 = 0x0800                                 # IPv4
    IPv6 = 0x86dd                                 # IPv6
    Dot1Q = 0x8100                                # VLAN-tagged frame (802.1q) and Shortest Path Bridging (802.1aq)
    SVLAN = 0x88a8                                # Provider Bridging (802.1ad) and Shortest Path Bridging (802.1aq)
    QinQ = 0x9100                                 # Legacy QinQ/802.ad
    Unknown = 0xbead                              # Dummy unknown Ethertype value
    MPLS = 0x8847                                 # MPLS
    PortExtender = 0x7101                         # PortExtender TPID
    LLDP = 0x88cc                                 # LLDP
    FlowControl = 0x8808                          # Ethernet flow control


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


bind_layers(Ether, PTPv2, type=0x88f7)
bind_layers(UDP, PTPv2, dport=319)
bind_layers(PTPv2, PTPSync, message_type=0)
bind_layers(PTPv2, PTPDelayReq, message_type=1)
bind_layers(PTPv2, PTPDelayResp, message_type=9)

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
