# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# This directive is read by leaba_format.py script
# pep8_extra_args = "--ignore=E2 --max-line-length 200"
# pep8_extra_args = "--ignore=E2,E5,W2"
# pep8_extra_args "--ignore=E721"

from fi_configurator_src import *


def config_tables():
    STAGE = PFI_STAGE_6
    IS_RXPP = True
    macro = {NETWORK_CONTEXT:[], HOST_CONTEXT:[], FABRIC_CONTEXT:[], FABRIC_ELEMENT_CONTEXT:[]}
    macro_config = {NETWORK_CONTEXT:[], HOST_CONTEXT:[], FABRIC_CONTEXT:[], FABRIC_ELEMENT_CONTEXT:[]}
    PACIFIC_COMPATIBLE_TM_HEADERS_MODE = True

    # macro config
    ETH = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_ETH,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_ETHERNET) \
        .Key('ether_type_or_tpid', EthernetHeader().ether_type_or_tpid) \
        .Hardwired(FI_HARDWIRED_LOGIC_ETHERNET, mask_hw_logic_header_format_flags=flag_da_is_bc | flag_sa_is_mc | flag_sa_eq_da) \
        .AddMacro(macro_config)

    VLAN_0 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_VLAN_0,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_VLAN_0) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hw_logic_header_format_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    VLAN_1 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_VLAN_1,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_VLAN_1) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hw_logic_header_format_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    ETHERTYPE = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_ETHERTYPE,
        start_new_header=False,
        start_new_layer=False) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    ARP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_ARP,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_ARP) \
        .AddMacro(macro_config)

    ICMP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_ICMP,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_ICMP) \
        .AddMacro(macro_config)

    IGMP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IGMP,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_IGMP) \
        .AddMacro(macro_config)

    # (header-error can be: TTL==0, Version, HLN, SIP multicast)
    IPV4 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IPV4,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV4) \
        .Hardwired(FI_HARDWIRED_LOGIC_IPV4, mask_hw_logic_header_format_flags=flag_header_error | flag_is_fragmented | flag_checksum_error) \
        .Key('sip_24_msb', IPv4Header().sip.Slice(31, 8)) \
        .Key('protocol', IPv4Header().protocol) \
        .Shifter(IPv4Header().hln, 2) \
        .AddMacro(macro_config)

    IPV6_FIRST = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IPV6_FIRST,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV6) \
        .Key('sip_16_msb', IPv6Header().sip.Slice(127, 112)) \
        .Key('hop_limit', IPv6Header().hop_limit) \
        .Key('version', IPv6Header().version) \
        .AddMacro(macro_config)

    IPV6_SECOND = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IPV6_SECOND,
        start_new_header=False,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_IPV6,
        offset_from_header_start=6) \
        .Key('dip_16_msbs', IPv6Header().dip.Slice(127, 112)) \
        .Key('next_header', IPv6Header().next_header) \
        .AddMacro(macro_config)

    IPV6_EH = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IPV6_EH,
        start_new_header=False,
        start_new_layer=False) \
        .Key('next_protocol', IPv6EHHeader().next_header) \
        .Shifter(IPv6EHHeader().hdr_len, 3) \
        .AddMacro(macro_config)

    IPV6_FRAG_EH = \
        FiMacro(
            contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
            macro_id=FI_MACRO_ID_IPV6_FRAG_EH,
            start_new_header=False,
            start_new_layer=False) \
        .Key('HOP_hdr_fields', IPv6EHHeader().HOP_hdr_fields.Slice(111, 96)) \
        .AddMacro(macro_config)

    # TODO replace hw logic when nsim is ready
    GRE = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_GRE,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_GRE) \
        .Hardwired(FI_HARDWIRED_LOGIC_NONE, mask_hw_logic_header_format_flags=flag_header_error | flag_is_fragmented | flag_checksum_error, mask_hw_logic_calc_header_size=True) \
        .Key('protocol', GREHeader().protocol) \
        .AddMacro(macro_config)

    SYSTEM_INJECT = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_SYSTEM_INJECT,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_INJECT) \
        .Key('inject_header_type', InjectHeader().inject_header_type) \
        .AddMacro(macro_config)

    ETHERNET_OVER_SYSTEM_INJECT = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_ETHERNET_OVER_SYSTEM_INJECT,
        start_new_header=False,
        start_new_layer=False,
        offset_from_header_start=16) \
        .Shifter(InjectHeader().inject_header_trailer_type) \
        .AddMacro(macro_config)

    IPV4_OVER_SYSTEM_INJECT = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IPV4_OVER_SYSTEM_INJECT,
        start_new_header=False,
        start_new_layer=False,
        offset_from_header_start=16) \
        .Shifter(InjectHeader().inject_header_trailer_type) \
        .AddMacro(macro_config)

    IPV6_OVER_SYSTEM_INJECT = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IPV6_OVER_SYSTEM_INJECT,
        start_new_header=False,
        start_new_layer=False,
        offset_from_header_start=16) \
        .Shifter(InjectHeader().inject_header_trailer_type) \
        .AddMacro(macro_config)

    SYSTEM_PUNT_PHASE1 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_SYSTEM_PUNT_PHASE1,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_PUNT) \
        .Key('punt_code', PuntHeader().punt_code) \
        .AddMacro(macro_config)

    SYSTEM_PUNT_PHASE2 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_SYSTEM_PUNT_PHASE2,
        start_new_header=False,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_PUNT) \
        .Key('punt_code_4_msb', PuntHeader().punt_code.Slice(7, 4)) \
        .AddMacro(macro_config)

    # classify the type of mpls processing based on the first label
    MPLS_0 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_MPLS_0,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_MPLS) \
        .Hardwired(FI_HARDWIRED_LOGIC_MPLS) \
        .Key('label', MPLSHeader().label) \
        .Key('exp', MPLSHeader().exp) \
        .Key('bos', MPLSHeader().bos) \
        .Key('speculative_next_nibble', MPLSHeader().speculative_next_nibble) \
        .AddMacro(macro_config)

    # this macro iterates over all null labels it will start a new mpls header on
    # the first non null label otherwise if bos encountered will perform speculative
    MPLS_1 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_MPLS_1,
        start_new_header=False,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_MPLS) \
        .Key('label', MPLSHeader().label) \
        .Key('exp', MPLSHeader().exp) \
        .Key('bos', MPLSHeader().bos) \
        .Key('speculative_next_nibble', MPLSHeader().speculative_next_nibble) \
        .AddMacro(macro_config)

    MPLS_2 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_MPLS_2,
        start_new_header=False,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_MPLS) \
        .Hardwired(FI_HARDWIRED_LOGIC_MPLS) \
        .Key('prev_bos', PreviousHeaderFormat().prev_flags.Slice(0, 0)) \
        .Key('prev_type', PreviousHeaderFormat().prev_type) \
        .Key('speculative_first_nibble', MPLSHeader().speculative_first_nibble) \
        .AddMacro(macro_config)

    MPLS_EL = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_MPLS_EL,
        start_new_header=False,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_MPLS) \
        .Key('label', MPLSHeader().label) \
        .Key('exp', MPLSHeader().exp) \
        .Key('bos', MPLSHeader().bos) \
        .Key('speculative_next_nibble', MPLSHeader().speculative_next_nibble) \
        .AddMacro(macro_config)

    UDP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_UDP,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_UDP) \
        .Key('dst_port', UDPHeader().dst_port) \
        .Key('ip_version', UDPHeader().ip_version) \
        .AddMacro(macro_config)

    IP_OVER_UDP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IP_OVER_UDP,
        start_new_header=False,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_UDP) \
        .Key('ip_version', IPv4Header().version) \
        .AddMacro(macro_config)

    TCP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_TCP,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_TCP) \
        .Key('dst_port', TCPHeader().dst_port) \
        .AddMacro(macro_config)

    ABOVE_TCP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_ABOVE_TCP,
        start_new_header=False,
        start_new_layer=False,
        offset_from_header_start=2) \
        .Shifter(TCPHeader().header_length, 2) \
        .AddMacro(macro_config)

    VXLAN = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_VXLAN,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_VXLAN) \
        .AddMacro(macro_config)

    FABRIC = FiMacro(
        contexts=[FABRIC_CONTEXT, FABRIC_ELEMENT_CONTEXT],
        macro_id=FI_MACRO_ID_FABRIC,
        start_new_header=True,
        start_new_layer=True) \
        .Key('fabric_header_type', FabricHeader().fabric_header_type) \
        .AddMacro(macro_config)

    TM = \
        FiMacro(
            contexts=[FABRIC_CONTEXT, FABRIC_ELEMENT_CONTEXT],
            macro_id=FI_MACRO_ID_TM,
            start_new_header=True,
            start_new_layer=False) \
        .Key('tm_header_type', TMHeader().hdr_type) \
        .Key('fabric_header_type', TMHeader().vce.Union(TMHeader().tc).Slice(3, 2)) \
        .AddMacro(macro_config)

    OAMP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_OAMP,
        start_new_header=False,
        start_new_layer=False) \
        .AddMacro(macro_config)

    OAMP_SECOND = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_OAMP_SECOND,
        start_new_header=False,
        start_new_layer=False,
        offset_from_header_start=4) \
        .Key('fwd_header_type', OAMPPuntHeader().punt_fwd_header_type) \
        .Key('reserved', OAMPPuntHeader().reserved) \
        .Key('pl_header_offset_first_nibble', OAMPPuntHeader().pl_header_offset.Slice(7, 4)) \
        .Shifter(OAMPPuntHeader().pl_header_offset) \
        .AddMacro(macro_config)

    CFM = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_CFM,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_CFM) \
        .AddMacro(macro_config)

    PTP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_PTP,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_PTP) \
        .AddMacro(macro_config)

    MACSEC = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_MACSEC,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_MACSEC) \
        .AddMacro(macro_config)

    PFC = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_PFC,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_PFC) \
        .AddMacro(macro_config)

    GTP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_GTP,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_GTP) \
        .AddMacro(macro_config)

    UNDEF = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT, FABRIC_CONTEXT, FABRIC_ELEMENT_CONTEXT],
        macro_id=FI_MACRO_ID_UNDEF,
        start_new_header=True,
        start_new_layer=True,
        last_macro=True) \
        .AddMacro(macro_config)

    FiMacro.populate_macro_config(macro_config=macro_config, stage=STAGE, is_rxpp=IS_RXPP)

    # FI config - tcam entries
    # network context
    ETH \
        .Conditions(ether_type_or_tpid=0x8100) \
        .Action(macro,
                header_format_type=PROTOCOL_TYPE_ETHERNET_VLAN,
                next_macro=VLAN_0,
                header_size=14)

    # /* (Ethernet QinQ) */
    ETH \
        .Conditions(ether_type_or_tpid=0x9100) \
        .Action(macro,
                header_format_type=PROTOCOL_TYPE_ETHERNET_VLAN,
                next_macro=VLAN_1,
                header_size=14)

    # /* (Ethernet QinQ) */
    ETH \
        .Conditions(ether_type_or_tpid=0x88a8) \
        .Action(macro,
                header_format_type=PROTOCOL_TYPE_ETHERNET_VLAN,
                next_macro=VLAN_1,
                header_size=14)

    ETH \
        .Conditions(ether_type_or_tpid=0x0800) \
        .Action(macro,
                next_macro=IPV4,
                header_size=14)

    ETH \
        .Conditions(ether_type_or_tpid=0x86dd) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_size=14)

    ETH \
        .Conditions(ether_type_or_tpid=0x8847) \
        .Action(macro,
                next_macro=MPLS_0,
                header_size=14)

    # /* (IPv4 o ETh) */
    ETH \
        .Conditions() \
        .Action(macro,
                next_macro=ETHERTYPE,
                header_size=10)

    # /* (IPv6 o ETh) */
    # 16, 0x7103 ethertype/tpid for inject
    VLAN_0 \
        .Conditions(tpid=ETHER_TYPE_INJECT_MAC) \
        .Action(macro,
                next_macro=SYSTEM_INJECT,
                header_size=4)

    # VLAN-0 tcam entries
    # 0x7102 ethertype/tpid for punt header
    VLAN_0 \
        .Conditions(tpid=ETHER_TYPE_PUNT_MAC) \
        .Action(macro,
                next_macro=SYSTEM_PUNT_PHASE1,
                header_size=4)

    VLAN_0 \
        .Conditions(tpid=0x0800) \
        .Action(macro,
                next_macro=IPV4,
                header_size=4)

    VLAN_0 \
        .Conditions(tpid=0x86dd) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_size=4)

    VLAN_0 \
        .Conditions(tpid=0x8847) \
        .Action(macro,
                next_macro=MPLS_0,
                header_size=4)

    VLAN_0 \
        .Conditions() \
        .Action(macro,
                next_macro=ETHERTYPE,
                advance_data=False)

    # VLAN-1 tcam entries
    VLAN_1 \
        .Conditions(tpid=0x8100) \
        .Action(macro,
                next_macro=VLAN_0,
                header_size=4)

    VLAN_1 \
        .Conditions() \
        .Action(macro,
                next_macro=ETHERTYPE,
                advance_data=False)

    ETHERTYPE \
        .Conditions(tpid=0x806) \
        .Action(macro,
                next_macro=ARP,
                header_size=4)

    # PTP over Vlan over Eth
    ETHERTYPE \
        .Conditions(tpid=0x88f7) \
        .Action(macro,
                next_macro=PTP,
                header_size=4)

    # L2CP CFM
    ETHERTYPE \
        .Conditions(tpid=0x8902) \
        .Action(macro,
                next_macro=CFM,
                header_size=4)

    # PFC pause frames
    ETHERTYPE \
        .Conditions(tpid=0x8808) \
        .Action(macro,
                next_macro=PFC,
                header_size=4)

    # MACSEC over EthoVLANoVLAN - RFC MACSEC
    ETHERTYPE \
        .Conditions(tpid=0x888e) \
        .Action(macro,
                next_macro=MACSEC,
                header_size=4)

    # MACSEC over EthoVLANoVLAN - Propriety MACSEC
    ETHERTYPE \
        .Conditions(tpid=0x876f) \
        .Action(macro,
                next_macro=MACSEC,
                header_size=4)

    # MACSEC over EthoVLANoVLAN - Propriety MACSEC
    ETHERTYPE \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_size=4)

    # ARP tcam entries
    ARP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_size=28)

    # ICMP tcam entries
    ICMP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_size=8)

    # IGMP tcam entries
    IGMP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_size=8)

    # L2CP CFM tcam entries
    CFM \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF)

    # PFC tcam entries
    PFC \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF)

    # PTP tcam entries
    PTP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF)

    MACSEC \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF)

    GTP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF)

    LOCAL_HOST = 0x7f0000  # localhost (127.x.x.x)
    IPV4 \
        .Conditions(sip_24_msb={"key": LOCAL_HOST, "mask": 0xff0000}) \
        .Action(macro,
                next_macro=UNDEF,
                header_format_flags=flag_sip_multicast)

    # sip is broadcast. Always catch error packet and stop parsing
    IPV4 \
        .Conditions(sip_24_msb=0xffffff) \
        .Action(macro,
                next_macro=UNDEF,
                header_format_flags=flag_sip_multicast)

    # ip-in-ip, don't check sip
    IPV4 \
        .Conditions(protocol=0x4) \
        .Action(macro,
                next_macro=IPV4)

    # ipv6-in-ipv4
    IPV4 \
        .Conditions(protocol=0x29) \
        .Action(macro,
                next_macro=IPV6_FIRST)

    # GRE
    IPV4 \
        .Conditions(protocol=0x2f) \
        .Action(macro,
                next_macro=GRE)

    # UDP
    IPV4 \
        .Conditions(protocol=0x11) \
        .Action(macro,
                header_format_type=PROTOCOL_TYPE_IPV4_L4,
                next_macro=UDP)

    # TCP
    IPV4 \
        .Conditions(protocol=0x6) \
        .Action(macro,
                header_format_type=PROTOCOL_TYPE_IPV4_L4,
                next_macro=TCP)

    # IPV4-IGMP
    IPV4 \
        .Conditions(protocol=0x2) \
        .Action(macro,
                header_format_type=PROTOCOL_TYPE_IPV4_L4,
                next_macro=IGMP)

    IPV4 \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF)

    # IPv6 tcam entries
    # IPv6 SIP-is-MC -> header_error=1, advance 6B
    #.Conditions(hop_limit_sip_16_msb={"key": 0x00ff00, "mask": 0x00ff00}) \
    IPV6_FIRST \
        .Conditions(sip_16_msb={"key": 0xff00, "mask": 0xff00}) \
        .Action(macro,
                next_macro=IPV6_SECOND,
                header_format_flags=flag_header_error,
                header_size=6)

    # IPv6 Hop-limit == 0 -> header_error=1, advance 6B
    #.Conditions(hop_limit_sip_16_msb={"key": 0x000000, "mask": 0xff0000}) \
    IPV6_FIRST \
        .Conditions(hop_limit=0) \
        .Action(macro,
                next_macro=IPV6_SECOND,
                header_format_flags=flag_header_error,
                header_size=6)

    # IPv6 SIP[127:112] == 0 -> sip_msbs_are_0=1, advance 6B
    #.Conditions(hop_limit_sip_16_msb={"key": 0x000000, "mask": 0x00ffff}, version=0x6) \
    # IPV6_FIRST \
    #     .Conditions(sip_16_msb=0, version=0x6) \
    #     .Action(macro,
    #             next_macro=IPV6_SECOND,
    #             header_format_flags=flag_sip_msbs_eq_0,
    #             header_size=6)
    # NOTES: Above should be a full 128 bit all_zeros.  Checking only 16 bit msbs conflicts
    #        with some valid cases such as ipv4 over ipv6.  This same flag bit is set by hardware
    #        for certain header options

    # IPv6 version==6 and no other error -> go to next nacro IPV6_SECOND, advance 6B
    IPV6_FIRST \
        .Conditions(version=0x6) \
        .Action(macro,
                next_macro=IPV6_SECOND,
                header_size=6)

    # IPv6 version!=6 and no other error -> Stop processing, advance 40B
    IPV6_FIRST \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_format_flags=flag_header_error,
                header_size=40)

    # IPv6 NxtHdr==UDP
    IPV6_SECOND \
        .Conditions(next_header=0x11) \
        .Action(macro,
                header_format_type=PROTOCOL_TYPE_IPV6_L4,
                next_macro=UDP,
                header_size=34)

    # IPv6 NxtHdr==TCP
    IPV6_SECOND \
        .Conditions(next_header=0x6) \
        .Action(macro,
                header_format_type=PROTOCOL_TYPE_IPV6_L4,
                next_macro=TCP,
                header_size=34)

    # IPv6 NxtHdr == GRE
    IPV6_SECOND \
        .Conditions(next_header=0x2f) \
        .Action(macro,
                next_macro=GRE,
                header_size=34)

    # IPv6 NxtHdr==ICMP
    IPV6_SECOND \
        .Conditions(next_header=0x3a) \
        .Action(macro,
                next_macro=ICMP,
                header_size=34)

    # IPv6 in IPv6
    IPV6_SECOND \
        .Conditions(next_header=0x29) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_size=34)

    # IPv4 in IPv6
    IPV6_SECOND \
        .Conditions(next_header=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_size=34)

    # IPv6 NxtHdr==Frag EH
    IPV6_SECOND \
        .Conditions(next_header=0x2c) \
        .Action(macro,
                next_macro=IPV6_FRAG_EH,
                header_size=34)

    # IPv6 NxtHdr==Destination EH
    IPV6_SECOND \
        .Conditions(next_header=0x3c) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=34)

    # IPv6 NxtHdr==Routing EH
    IPV6_SECOND \
        .Conditions(next_header=0x2b) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=34)

    # IPv6 NxtHdr==Authentication EH
    IPV6_SECOND \
        .Conditions(next_header=0x33) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=34)

    # IPv6 NxtHdr==Mobility EH
    IPV6_SECOND \
        .Conditions(next_header=0x87) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=34)

    # IPv6 NxtHdr==HIP EH
    IPV6_SECOND \
        .Conditions(next_header=0x8b) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=34)

    # IPv6 NxtHdr==SHIM6 EH
    IPV6_SECOND \
        .Conditions(next_header=0x8c) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=34)

    # IPv6 EH NxtHdr==UDP
    IPV6_EH \
        .Conditions(next_protocol=0x11) \
        .Action(macro,
                next_macro=UDP,
                header_size=8)

    # IPv6 EH NxtHdr==TCP
    IPV6_EH \
        .Conditions(next_protocol=0x6) \
        .Action(macro,
                next_macro=TCP,
                header_size=8)

    # IPv6 EH NxtHdr==ICMP
    IPV6_EH \
        .Conditions(next_protocol=0x3a) \
        .Action(macro,
                next_macro=ICMP,
                header_size=8)

    # IPv6 EH NxtHdr== inner IPV6
    IPV6_EH \
        .Conditions(next_protocol=0x29) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_size=8)

    # IPv6 EH NxtHdr== inner IPV4
    IPV6_EH \
        .Conditions(next_protocol=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_size=8)

    # IPv6 EH NxtHdr== inner GRE
    IPV6_EH \
        .Conditions(next_protocol=0x2f) \
        .Action(macro,
                next_macro=GRE,
                header_size=8)

    # IPv6 EH NxtHdr==Frag EH
    IPV6_EH \
        .Conditions(next_protocol=0x2c) \
        .Action(macro,
                next_macro=IPV6_FRAG_EH,
                header_size=8)

    # IPv6 EH NxtHdr==Destination EH
    IPV6_EH \
        .Conditions(next_protocol=0x3c) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=8)

    # IPv6 EH NxtHdr==Routing EH
    IPV6_EH \
        .Conditions(next_protocol=0x2b) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=8)

    # IPv6 EH NxtHdr==Authentication EH
    IPV6_EH \
        .Conditions(next_protocol=0x33) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=8)

    # IPv6 EH NxtHdr==Mobility EH
    IPV6_EH \
        .Conditions(next_protocol=0x87) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=8)

    # IPv6 EH NxtHdr==HIP EH
    IPV6_EH \
        .Conditions(next_protocol=0x8b) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=8)

    # IPv6 EH NxtHdr==SHIM6 EH
    IPV6_EH \
        .Conditions(next_protocol=0x8c) \
        .Action(macro,
                next_macro=IPV6_EH,
                header_size=8)

    # IPv6 Fragmentation EH macro - check whether FragOffset is 0 - do nothing
    IPV6_FRAG_EH \
        .Conditions(HOP_hdr_fields={"key": 0x0, "mask": 0xff8}) \
        .Action(macro,
                next_macro=IPV6_EH)

    # IPv6 Fragmentation EH macro - If we got here than FragOffset is not 0
    IPV6_FRAG_EH \
        .Conditions() \
        .Action(macro,
                next_macro=IPV6_EH,
                header_format_flags=flag_is_fragmented)

    # GRE
    # size calculation is done by hw logic

    # IPv4 over GRE
    # checksum flag = 0
    GRE \
        .Conditions(protocol=0x800) \
        .Action(macro,
                next_macro=IPV4,
                header_size=4)

    # IPv6 over GRE
    # checksum flag = 0
    GRE \
        .Conditions(protocol=0x86dd) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_size=4)

    # MPLS over GRE
    # checksum flag = 0
    GRE \
        .Conditions(protocol=0x8847) \
        .Action(macro,
                next_macro=MPLS_0,
                header_size=4)

    # Ethernet over GRE
    # checksum flag = 0
    GRE \
        .Conditions(protocol=0x6558) \
        .Action(macro,
                next_macro=ETH,
                header_size=4)

    # not supported protocol with checksum flag = 0
    GRE \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_size=4)

    # UDP tcam entries - VXLAN AFTER UDP
    UDP \
        .Conditions(dst_port=0x12b5) \
        .Action(macro,
                next_macro=VXLAN,
                header_size=8)

    # UDP tcam entries - GTP-U
    UDP \
        .Conditions(dst_port=0x868) \
        .Action(macro,
                next_macro=GTP,
                header_size=8)

    # user defined/PVC tunnel
    UDP \
        .Conditions(dst_port=0xfa) \
        .Action(macro,
                next_macro=IP_OVER_UDP,
                header_size=16)

    # UDP tcam entries - IPv4/6 AFTER UDP-GUE
    UDP \
        .Conditions(dst_port=0x17c0, ip_version=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_size=8)

    # UDP tcam entries - IPv4/6 AFTER UDP-GUE
    UDP \
        .Conditions(dst_port=0x17c0, ip_version=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_size=8)

    # UDP tcam entries - MPLS AFTER UDP
    UDP \
        .Conditions(dst_port=0x19eb) \
        .Action(macro,
                next_macro=MPLS_0,
                header_size=8)

    # UDP tcam entries - Default UDP
    UDP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_size=8)

    IP_OVER_UDP \
        .Conditions(ip_version=0x4) \
        .Action(macro,
                next_macro=IPV4)

    IP_OVER_UDP \
        .Conditions(ip_version=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST)

    # TCP tcam entries

    # GTP over TCP
    TCP \
        .Conditions(dst_port=0x868) \
        .Action(macro,
                next_macro=ABOVE_TCP,
                header_size=2)

    # default TCP
    TCP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF)

    # currently only support GTP above TCP
    ABOVE_TCP \
        .Conditions() \
        .Action(macro,
                next_macro=GTP)
    VXLAN \
        .Conditions() \
        .Action(macro,
                next_macro=ETH,
                header_size=8)

    # inject down - Header size is 17 + trailer size calculated using ALU
    # On inject down we do not process the packet contrents so no need to continue parsing
    SYSTEM_INJECT \
        .Conditions(inject_header_type={"key": INJECT_HEADER_TYPE_DOWN, "mask": 0x7e}) \
        .Action(macro,
                next_macro=UNDEF,
                header_size=17)

    # # inject up - Header size is 17 + trailer size calculated using ALU
    # #  Inject up next protocol is encoded in the 2 lsb of the header type:
    # #    Ethernet - 10
    # #    IPv4     - 01
    # #    IPv6     - 00
    # #    Other    - 11
    SYSTEM_INJECT \
        .Conditions(inject_header_type={"key": 0b10, "mask": 0x3}) \
        .Action(macro,
                next_macro=ETHERNET_OVER_SYSTEM_INJECT,
                header_size=16)

    SYSTEM_INJECT \
        .Conditions(inject_header_type={"key": 0b01, "mask": 0x3}) \
        .Action(macro,
                next_macro=IPV4_OVER_SYSTEM_INJECT,
                header_size=16)

    SYSTEM_INJECT \
        .Conditions(inject_header_type={"key": 0b00, "mask": 0x3}) \
        .Action(macro,
                next_macro=IPV6_OVER_SYSTEM_INJECT,
                header_size=16)

    SYSTEM_INJECT \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_size=17)

    ETHERNET_OVER_SYSTEM_INJECT \
        .Conditions() \
        .Action(macro,
                next_macro=ETH,
                header_size=1)

    IPV4_OVER_SYSTEM_INJECT \
        .Conditions() \
        .Action(macro,
                next_macro=IPV4,
                header_size=1)

    IPV6_OVER_SYSTEM_INJECT \
        .Conditions() \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_size=1)

    # Recycle punt header tcam entries
    #   first phase - advance data with max databus size
    # 0xCE is MC_LPTS punt code.  Continue parsing beyond punt header as needed by LPTS processing.
    # all other cases, punt header is terminal-- no need to parse beyond.
    SYSTEM_PUNT_PHASE1 \
        .Conditions(punt_code=0xCE) \
        .Action(macro,
                next_macro=ETH,
                header_size=28)

    SYSTEM_PUNT_PHASE1 \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_size=28)

   # These are not really used? May alias with MAC header if speculating
   # v4/v6
   #
   # # Recycle punt header tcam entries
   # # punt_code_4_msb - next header first nibble (speculative ipv4)
   # SYSTEM_PUNT_PHASE2 \
   #     .Conditions(punt_code_4_msb=0x4) \
   #     .Action(macro,
   #             next_macro=IPV4,
   #             header_size=3)
   #
   # # Recycle punt header tcam entries
   # SYSTEM_PUNT_PHASE2 \
   #     .Conditions(punt_code_4_msb=0x6) \
   #     .Action(macro,
   #             next_macro=IPV6_FIRST,
   #             header_size=3)

    # MPLS tcam entries
    # IPV6 Explicit null + BOS, next protocol is IPv4, mark flags as illegal ipv4
    # tcam_mask_hw_logic_advance_data        : 1; #used for mpls. for
    # speculative, use '0' (becuase if '1', advance-data = !bos-found) NOTE:
    # not used because of null headers search
    # tcam_mask_hw_logic_last_macro          : 1; #used for mpls. for
    # speculative, use '0' (because if '1', last-macro   = bos-found)  NOTE:
    # not used because of null headers search
    # tcam_mask_hw_logic_header_format.flags : 3; //Used for {padd, is-null, is_bos} #Used for {padd, is-null, is_bos}
    MPLS_0 \
        .Conditions(label=0x2, bos=1, speculative_next_nibble=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_format_flags=flag_illegal_ipv4 | flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries
    # null+bos, next-spculative-is-v4
    MPLS_0 \
        .Conditions(label=0, bos=1, speculative_next_nibble=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_format_flags=flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries
    # null+bos, next-spculative-is-v6
    MPLS_0 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=1, speculative_next_nibble=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_format_flags=flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries
    # null+bos
    MPLS_0 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=1) \
        .Action(macro,
                next_macro=ETH,
                header_format_flags=flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries
    # null+not-bos
    MPLS_0 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=0) \
        .Action(macro,
                next_macro=MPLS_1,
                header_format_flags=flag_is_null,
                header_size=4)

    # MPLS tcam entries
    # ELI Label
    MPLS_0 \
        .Conditions(label=0x7, bos=0) \
        .Action(macro,
                next_macro=MPLS_EL,
                header_format_flags=flag_is_null,
                header_size=4)

    # not null -> do mpls-stack logic
    MPLS_0 \
        .Conditions() \
        .Action(macro,
                next_macro=MPLS_2,
                mask_hw_logic_header_format_flags=flag_is_bos,
                mask_hw_logic_calc_header_size=True)

    # MPLS tcam entries
    # Explicit IPv6 null + bos, next protocol is IPv4, mark flags as illegal IPv4
    # tcam_mask_hw_logic_advance_data        : 1; #used for mpls. for speculative, use '0' (becuase if '1', advance-data = !bos-found) NOTE: not used because of null headers search
    # tcam_mask_hw_logic_last_macro          : 1; #used for mpls. for
    # speculative, use '0' (because if '1', last-macro   = bos-found)  NOTE:
    # not used because of null headers search
    MPLS_1 \
        .Conditions(label=0x2, bos=1, speculative_next_nibble=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_format_flags=flag_illegal_ipv4 | flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries
    # null+bos, next-spculative-is-v4
    MPLS_1 \
        .Conditions(label=0, bos=1, speculative_next_nibble=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_format_flags=flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries
    # null+bos, next-spculative-is-v6
    MPLS_1 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=1, speculative_next_nibble=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_format_flags=flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries
    # null+bos where not IPv4/IPv6 -> assuming Ethernet
    MPLS_1 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=1) \
        .Action(macro,
                next_macro=ETH,
                header_format_flags=flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries
    # null+not-bos
    MPLS_1 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=0) \
        .Action(macro,
                next_macro=MPLS_1,
                header_format_flags=flag_is_null,
                header_size=4)

    # ELI
    MPLS_1 \
        .Conditions(label=0x7, bos=0) \
        .Action(macro,
                next_macro=MPLS_EL,
                header_format_flags=flag_is_null,
                header_size=4)

    # not null -> close null and start mpls-stack header on NEXT macro
    MPLS_1 \
        .Conditions() \
        .Action(macro,
                next_macro=MPLS_2,
                start_new_header=True)

    # prev macro is not bos -> do mpls-stack logic
    MPLS_2 \
        .Conditions(prev_bos=0) \
        .Action(macro,
                next_macro=MPLS_2,
                mask_hw_logic_header_format_flags=flag_is_bos,
                mask_hw_logic_calc_header_size=True)

    # prev bos, next-spculative-is-v4
    MPLS_2 \
        .Conditions(speculative_first_nibble=0x4) \
        .Action(macro,
                next_macro=IPV4)

    # prev bos, next-spculative-is-v6
    MPLS_2 \
        .Conditions(speculative_first_nibble=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST)

    # prev bos
    MPLS_2 \
        .Conditions() \
        .Action(macro,
                next_macro=ETH)

    # MPLS tcam entries
    # EL + bos, next-spculative-is-v4
    # tcam_mask_hw_logic_advance_data        : 1; //used for mpls. for
    # speculative, use '0' (becuase if '1', advance-data = !bos-found) NOTE:
    # not used because of null headers search
    # tcam_mask_hw_logic_last_macro          : 1; //used for mpls. for
    # speculative, use '0' (because if '1', last-macro   = bos-found)  NOTE:
    # not used because of null headers search
    MPLS_EL \
        .Conditions(bos=1, speculative_next_nibble=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_format_flags=flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries */
    # EL + bos, next-spculative-is-v6
    MPLS_EL \
        .Conditions(bos=1, speculative_next_nibble=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_format_flags=flag_is_null | flag_is_bos,
                header_size=4)

    # MPLS tcam entries
    # EL + bos
    MPLS_EL \
        .Conditions(bos=1) \
        .Action(macro,
                next_macro=ETH,
                header_format_flags=flag_is_null | flag_is_bos,
                header_size=4)

    # EL not BOS -> check if next label closes the null stack
    MPLS_EL \
        .Conditions() \
        .Action(macro,
                next_macro=MPLS_1,
                header_format_flags=flag_is_null,
                header_size=4)

    OAMP \
        .Conditions() \
        .Action(macro,
                next_macro=OAMP_SECOND,
                header_size=4)

    OAMP_SECOND \
        .Conditions(fwd_header_type=FWD_HEADER_TYPE_IPV4) \
        .Action(macro,
                next_macro=IPV4,
                header_size=32-4)

    OAMP_SECOND \
        .Conditions(fwd_header_type=FWD_HEADER_TYPE_IPV6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_size=32-4)

    OAMP_SECOND \
        .Conditions() \
        .Action(macro,
                next_macro=ETH,
                mask_hw_logic_header_size_in=False,
                header_size=32-4)

    # fabric context
    # fbric/tm headers part
    # first header is fabric, followed by TM, followed by NPU(aka SMS)  header.
    # first we configure the first-macro-table, then the tcam entris that will lead us to the next macro. since there are 4 TM headers type - we have 4 entries in the "fabric TCAM"(it's the same TCAM for all),
    # but logically it's adiffrenet one.
    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET) \
        .Action(macro,
                next_macro=TM,
                header_format_type=FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET,
                header_size=6)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS) \
        .Action(macro,
                next_macro=TM,
                header_format_type=FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS,
                header_size=7)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET) \
        .Action(macro,
                next_macro=TM,
                header_format_type=FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET,
                header_size=12)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS) \
        .Action(macro,
                next_macro=TM,
                header_format_type=FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS,
                header_size=13)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_SN_TS_PLB_KEEPALIVE) \
        .Action(macro,
                next_macro=TM,
                header_format_type=FABRIC_HEADER_TYPE_SN_TS_PLB_KEEPALIVE,
                header_size=10)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_FLB) \
        .Action(macro,
                next_macro=TM,
                header_format_type=FABRIC_HEADER_TYPE_FLB,
                header_size=3)

    # now we configure the macro of the TM header, then the tcam entris that
    # will lead us to the next macro, since there is 1 SMS/NPU  heade type -
    # we have 1 entries in the TM TCAM( this the same tcam of the fabric-
    # starts with offset..)
    if PACIFIC_COMPATIBLE_TM_HEADERS_MODE:
        uc_or_muu_plb_tm_header_size = 4
    else: # GB
        uc_or_muu_plb_tm_header_size = 5
    TM.Conditions(tm_header_type=TM_HEADER_TYPE_UNICAST_OR_MUU_PLB) \
        .Action(macro,
                next_macro=UNDEF,
                header_format_type=TM_HEADER_TYPE_UNICAST_OR_MUU_PLB << 2,
                header_size=uc_or_muu_plb_tm_header_size)

    TM \
        .Conditions(tm_header_type=TM_HEADER_TYPE_UNICAST_FLB) \
        .Action(macro,
                next_macro=UNDEF,
                header_format_type=TM_HEADER_TYPE_UNICAST_FLB << 2,  # type is 2 bits, padding with 0 in msb and 2'b0 in lsb
                header_size=3)

    TM \
        .Conditions(tm_header_type=TM_HEADER_TYPE_MMM_PLB_OR_FLB) \
        .Action(macro,
                next_macro=UNDEF,
                header_format_type=TM_HEADER_TYPE_MMM_PLB_OR_FLB << 2,  # type is 2 bits, padding with 0 in msb and 2'b0 in lsb
                header_size=3)

    TM \
        .Conditions(tm_header_type=TM_HEADER_TYPE_MUM_PLB) \
        .Action(macro,
                next_macro=UNDEF,
                header_format_type=TM_HEADER_TYPE_MUM_PLB << 2,  # type is 2 bits, padding with 0 in msb and 2'b0 in lsb
                header_size=5)

    FABRIC \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_format_type=FABRIC_HEADER_TYPE_FLB,
                header_size=3)

    UNDEF \
        .Conditions(mask_macro_id=0) \
        .Action(macro,
                next_macro=UNDEF)

    FiMacro.populate_macro(macro=macro, stage=STAGE, is_rxpp=IS_RXPP)
