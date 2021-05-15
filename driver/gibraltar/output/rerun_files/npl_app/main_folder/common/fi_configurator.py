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
    macro = {NETWORK_CONTEXT:[], HOST_CONTEXT:[], FABRIC_CONTEXT:[], FABRIC_ELEMENT_CONTEXT:[]}
    macro_config = {NETWORK_CONTEXT:[], HOST_CONTEXT:[], FABRIC_CONTEXT:[], FABRIC_ELEMENT_CONTEXT:[]}
    PACIFIC_COMPATIBLE_TM_HEADERS_MODE = True

    #########################################################################
    # packet header - 20B # PreviousHeaderFormat - 1B # packet header - 20B #
    #########################################################################

    # headers
    class PreviousHeaderFormat():
        prev_flags = Field(WINDOW_SIZE * 8 - 8, 3)
        prev_type = Field(WINDOW_SIZE * 8 - 5, 5)

    class InjectHeader():
        inject_header_type = Field(0, 8)
        inject_header_specific_data = Field(8, 88)
        time_and_cntr_stamp_cmd = Field(96, 24)
        npl_internal_info = Field(120, 8)
        inject_header_trailer_type = Field(128, 8)

    class PuntHeader():
        punt_next_header = Field(0, 5)
        punt_fwd_header_type = Field(5, 4)
        reserved = Field(9, 3)
        pl_header_offset = Field(12, 8)
        punt_source = Field(20, 4)
        punt_code = Field(24, 8)
        punt_sub_code = Field(32, 8)
        ssp = Field(40, 16)
        dsp = Field(56, 16)
        slp = Field(72, 20)
        dlp = Field(92, 20)
        padding = Field(112, 2)
        punt_relay_id = Field(114, 14)
        time_stamp_val = Field(128, 64)
        receive_time = Field(192, 32)

    class OAMPPuntHeader():
        first_fi_macro_id = Field(0, 8)
        first_npe_macro_id = Field(8, 8)
        ether_type = Field(16, 16)
        punt_next_header = Field(32, 5)
        punt_fwd_header_type = Field(37, 4)
        reserved = Field(41, 3)
        pl_header_offset = Field(44, 8)

    class FabricHeader():
        fabric_header_type = Field(0, 4)
        ctrl = Field(4, 4)

    class TMHeader():
        hdr_type = Field(0, 2)
        vce = Field(2, 1)
        tc = Field(3, 3)
        dp = Field(6, 2)

    class EthernetHeader():
        da = Field(offset=0, width=48)
        sa = Field(offset=48, width=48)
        ether_type_or_tpid = Field(offset=96, width=16)

    class VlanHeader():
        pcp = Field(0, 3)
        dei = Field(3, 1)
        vid = Field(4, 12)
        tpid = Field(16, 16)

    class IPv4Header():
        version = Field(0, 4)
        hln = Field(4, 4)
        dscp = Field(8, 6)
        ecn = Field(14, 2)
        total_length = Field(16, 16)
        identification = Field(32, 16)
        reserved = Field(48, 1)
        dont_fragment = Field(49, 1)
        more_fragments = Field(50, 1)
        fragment_offset = Field(51, 13)
        ttl = Field(64, 8)
        protocol = Field(72, 8)
        header_checksum = Field(80, 16)
        sip = Field(96, 32)
        dip = Field(128, 32)

    class IPv6Header():
        version = Field(0, 4)
        dscp = Field(4, 6)
        ecn = Field(10, 2)
        flow_label = Field(12, 20)
        payload_length = Field(32, 16)
        next_header = Field(48, 8)
        hop_limit = Field(56, 8)
        sip = Field(64, 128)
        dip = Field(192, 128)

    class IPv6EHHeader():
        next_header = Field(0, 8)
        hdr_len = Field(8, 8)
        HOP_hdr_fields = Field(16, 112)
        routing_hdr_fields = Field(128, 112)
        dest_hdr_fields = Field(240, 112)
        frag_hdr_fields = Field(352, 48)
        Auth_hdr_fields = Field(400, 112)

    class UDPHeader():
        src_port = Field(0, 16)
        dst_port = Field(16, 16)
        length = Field(32, 16)
        checksum = Field(48, 16)
        ip_version = Field(64, 4)

    class TCPHeader():
        src_port = Field(0, 16)
        dst_port = Field(16, 16)
        sequence_number = Field(32, 32)
        acknowledgement_number = Field(64, 32)
        header_length = Field(96, 4)
        flags = Field(100, 12)
        window = Field(112, 16)
        checksum = Field(128, 16)
        urgent = Field(144, 16)

    class GREHeader():
        C = Field(0, 1)
        na = Field(1, 1)
        k = Field(2, 1)
        s = Field(3, 1)
        reserved0 = Field(4, 9)
        version = Field(13, 3)
        protocol = Field(16, 16)
        vsid = Field(32, 24)
        flowid = Field(56, 8)

    class MPLSHeader():
        speculative_first_nibble = Field(0, 4)
        label = Field(0, 20)
        exp = Field(20, 3)
        bos = Field(23, 1)
        ttl = Field(24, 8)
        speculative_next_nibble = Field(32, 4)

    # flags
    flag_da_is_bc = 0b100
    flag_sa_is_mc = 0b010
    flag_sa_eq_da = 0b001
    flag_is_priority = 0b001
    flag_header_error = 0b100
    flag_is_fragmented = 0b010
    flag_checksum_error = 0b001
    flag_sip_multicast = 0b100
    # flag_sip_msbs_eq_0 = 0b001 not used
    flag_illegal_ipv4 = 0b100
    flag_is_null = 0b010
    flag_is_bos = 0b001

    # macro config
    ETH = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_ETH,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_ETHERNET) \
        .Key('ether_type_or_tpid', EthernetHeader().ether_type_or_tpid) \
        .Hardwired(FI_HARDWIRED_LOGIC_ETHERNET, mask_hardwired_flags=flag_da_is_bc | flag_sa_is_mc | flag_sa_eq_da) \
        .AddMacro(macro_config)

    VLAN_0 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_VLAN_0,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_VLAN_0) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hardwired_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    VLAN_1 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_VLAN_1,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_VLAN_1) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hardwired_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    ETHERTYPE = \
        FiMacro(
            contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
            macro_id=FI_MACRO_ID_ETHERTYPE,
            start_header=False, start_layer=False) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    ARP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_ARP,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_ARP) \
        .AddMacro(macro_config)

    ICMP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_ICMP,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_ICMP) \
        .AddMacro(macro_config)

    IGMP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IGMP,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_IGMP) \
        .AddMacro(macro_config)

    # (header-error can be: TTL==0, Version, HLN, SIP multicast)
    IPV4 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IPV4,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_IPV4) \
        .Hardwired(FI_HARDWIRED_LOGIC_IPV4,
                   mask_hardwired_flags=flag_header_error | flag_is_fragmented | flag_checksum_error) \
        .Key('sip_24_msb', IPv4Header().sip.Slice(31, 8)) \
        .Key('protocol', IPv4Header().protocol) \
        .ALU(IPv4Header().hln, 2, 0, 8, mask_alu_size=0x3f) \
        .AddMacro(macro_config)

    IPV6_FIRST = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IPV6_FIRST,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_IPV6) \
        .Key('sip_16_msb', IPv6Header().sip.Slice(127, 112)) \
        .Key('hop_limit', IPv6Header().hop_limit) \
        .Key('version', IPv6Header().version) \
        .AddMacro(macro_config)

    IPV6_SECOND = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IPV6_SECOND,
        start_header=False,
        start_layer=False,
        header_type=PROTOCOL_TYPE_IPV6,
        offset_from_header_start=6) \
        .Key('dip_16_msbs', IPv6Header().dip.Slice(127, 112)) \
        .Key('next_header', IPv6Header().next_header) \
        .AddMacro(macro_config)

    IPV6_EH = \
        FiMacro(
            contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
            macro_id=FI_MACRO_ID_IPV6_EH,
            start_header=False,
            start_layer=False) \
        .Key('next_protocol', IPv6EHHeader().next_header) \
        .ALU(IPv6EHHeader().hdr_len, 3, 8, 8, mask_alu_size=0x3f) \
        .AddMacro(macro_config)

    IPV6_FRAG_EH = \
        FiMacro(
            contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
            macro_id=FI_MACRO_ID_IPV6_FRAG_EH,
            start_header=False,
            start_layer=False) \
        .Key('HOP_hdr_fields', IPv6EHHeader().HOP_hdr_fields.Slice(111, 96)) \
        .AddMacro(macro_config)

    # for calculating GRE header size (sequence number & key influence only) ALU is computing:
    # (s||0000 << 1) + (k||s||0000) << 5 & 0x3c (tcam mask)
    GRE = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_GRE,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_GRE) \
        .Key('cs', GREHeader().C) \
        .Key('pad', GREHeader().na) \
        .Key('key', GREHeader().k) \
        .Key('sn', GREHeader().s) \
        .Key('protocol', GREHeader().protocol) \
        .ALU(GREHeader().s.Union(GREHeader().reserved0.Slice(8, 5)), 1, GREHeader().k.Union(GREHeader().reserved0.Slice(8, 5)), 5, mask_alu_size=0x3c) \
        .AddMacro(macro_config)

    SYSTEM_INJECT = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_SYSTEM_INJECT,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_INJECT) \
        .Key('inject_header_type', InjectHeader().inject_header_type) \
        .ALU(InjectHeader().inject_header_trailer_type, 0, 0, 8, mask_alu_size=0x3f) \
        .AddMacro(macro_config)

    SYSTEM_PUNT_PHASE1 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_SYSTEM_PUNT_PHASE1,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_PUNT) \
        .Key('punt_code', PuntHeader().punt_code) \
        .AddMacro(macro_config)

    SYSTEM_PUNT_PHASE2 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_SYSTEM_PUNT_PHASE2,
        start_header=False,
        start_layer=False,
        header_type=PROTOCOL_TYPE_PUNT) \
        .Key('punt_code_4_msb', PuntHeader().punt_code.Slice(7, 4)) \
        .AddMacro(macro_config)

    # classify the type of mpls processing based on the first label
    MPLS_0 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_MPLS_0,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_MPLS) \
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
        start_header=False,
        start_layer=False,
        header_type=PROTOCOL_TYPE_MPLS) \
        .Key('label', MPLSHeader().label) \
        .Key('exp', MPLSHeader().exp) \
        .Key('bos', MPLSHeader().bos) \
        .Key('speculative_next_nibble', MPLSHeader().speculative_next_nibble) \
        .AddMacro(macro_config)

    MPLS_2 = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_MPLS_2,
        start_header=False,
        start_layer=False,
        header_type=PROTOCOL_TYPE_MPLS) \
        .Hardwired(FI_HARDWIRED_LOGIC_MPLS) \
        .Key('prev_bos', PreviousHeaderFormat().prev_flags.Slice(0, 0)) \
        .Key('prev_type', PreviousHeaderFormat().prev_type) \
        .Key('speculative_first_nibble', MPLSHeader().speculative_first_nibble) \
        .AddMacro(macro_config)

    MPLS_EL = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_MPLS_EL,
        start_header=False,
        start_layer=False,
        header_type=PROTOCOL_TYPE_MPLS) \
        .Key('label', MPLSHeader().label) \
        .Key('exp', MPLSHeader().exp) \
        .Key('bos', MPLSHeader().bos) \
        .Key('speculative_next_nibble', MPLSHeader().speculative_next_nibble) \
        .AddMacro(macro_config)

    # TODO not supported
    # EXTENDED_VLAN = \
    #     FiMacro(contexts=[NETWORK_CONTEXT, HOST_CONTEXT], macro_id=FI_MACRO_ID_EXTENDED_VLAN, start_header=False, start_layer=False) \
    #     .Key('tpid', VlanHeader().tpid) \
    #     .Key('first_byte', VlanHeader().pcp.Union(VlanHeader().vid).Slice(15, 8)) \
    #     .AddMacro(macro_config)

    UDP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_UDP,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_UDP) \
        .Key('dst_port', UDPHeader().dst_port) \
        .Key('ip_version', UDPHeader().ip_version) \
        .AddMacro(macro_config)

    IP_OVER_UDP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_IP_OVER_UDP,
        start_header=False,
        start_layer=False,
        header_type=PROTOCOL_TYPE_UDP) \
        .Key('ip_version', IPv4Header().version) \
        .AddMacro(macro_config)

    TCP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_TCP,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_TCP) \
        .Key('dst_port', TCPHeader().dst_port) \
        .ALU(TCPHeader().header_length, 2, 0, 8, mask_alu_size=0x3f) \
        .AddMacro(macro_config)

    VXLAN = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_VXLAN,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_VXLAN) \
        .AddMacro(macro_config)

    SVL_TM_HEADER = FiMacro(
        contexts=[NETWORK_CONTEXT],
        macro_id=FI_MACRO_ID_SVL_TM,
        start_header=True,
        start_layer=False,
        header_type=PROTOCOL_TYPE_SVL) \
        .AddMacro(macro_config)

    FABRIC = \
        FiMacro(
            contexts=[FABRIC_CONTEXT, FABRIC_ELEMENT_CONTEXT],
            macro_id=FI_MACRO_ID_FABRIC,
            start_header=True,
            start_layer=True) \
        .Key('fabric_header_type', FabricHeader().fabric_header_type) \
        .AddMacro(macro_config)

    TM = \
        FiMacro(
            contexts=[FABRIC_CONTEXT, FABRIC_ELEMENT_CONTEXT],
            macro_id=FI_MACRO_ID_TM,
            start_header=True,
            start_layer=False) \
        .Key('tm_header_type', TMHeader().hdr_type) \
        .Key('fabric_header_type', TMHeader().vce.Union(TMHeader().tc).Slice(3, 2)) \
        .AddMacro(macro_config)

    OAMP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_OAMP,
        start_header=False,
        start_layer=False) \
        .Key('fwd_header_type', OAMPPuntHeader().punt_fwd_header_type) \
        .Key('reserved', OAMPPuntHeader().reserved) \
        .Key('pl_header_offset_first_nibble', OAMPPuntHeader().pl_header_offset.Slice(7, 4)) \
        .ALU(OAMPPuntHeader().pl_header_offset, 0, 0, 8, mask_alu_size=0x3f) \
        .AddMacro(macro_config)

    CFM = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_CFM,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_CFM) \
        .AddMacro(macro_config)

    PTP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_PTP,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_PTP) \
        .AddMacro(macro_config)

    MACSEC = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_MACSEC,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_MACSEC) \
        .AddMacro(macro_config)

    PFC = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_PFC,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_PFC) \
        .AddMacro(macro_config)

    GTP = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT],
        macro_id=FI_MACRO_ID_GTP,
        start_header=True,
        start_layer=True,
        header_type=PROTOCOL_TYPE_GTP) \
        .AddMacro(macro_config)

    UNDEF = FiMacro(
        contexts=[NETWORK_CONTEXT, HOST_CONTEXT, FABRIC_CONTEXT, FABRIC_ELEMENT_CONTEXT],
        macro_id=FI_MACRO_ID_UNDEF,
        start_header=True,
        start_layer=True,
        last_macro=True) \
        .AddMacro(macro_config)

    FiMacro.populate_macro_config(macro_config)

    # FI config - tcam entries
    # network context
    ETH \
        .Conditions(ether_type_or_tpid=0x8100) \
        .Action(macro,
                header_type=PROTOCOL_TYPE_ETHERNET_VLAN,
                next_macro=VLAN_0,
                size=14)

    # /* (Ethernet QinQ) */
    ETH \
        .Conditions(ether_type_or_tpid=0x9100) \
        .Action(macro,
                header_type=PROTOCOL_TYPE_ETHERNET_VLAN,
                next_macro=VLAN_1,
                size=14)

    # /* (Ethernet QinQ) */
    ETH \
        .Conditions(ether_type_or_tpid=0x88a8) \
        .Action(macro,
                header_type=PROTOCOL_TYPE_ETHERNET_VLAN,
                next_macro=VLAN_1,
                size=14)

    ETH \
        .Conditions(ether_type_or_tpid=0x0800) \
        .Action(macro,
                next_macro=IPV4,
                size=14)

    ETH \
        .Conditions(ether_type_or_tpid=0x86dd) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                size=14)

    ETH \
        .Conditions(ether_type_or_tpid=0x8847) \
        .Action(macro,
                next_macro=MPLS_0,
                size=14)

    # /* (IPv4 o ETh) */
    ETH \
        .Conditions() \
        .Action(macro,
                next_macro=ETHERTYPE,
                size=10)

    # /* (SVL TM Header) */
    SVL_TM_HEADER \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                size=6)

    # /* (IPv6 o ETh) */
    # 16, 0x7103 ethertype/tpid for inject
    VLAN_0 \
        .Conditions(tpid=ETHER_TYPE_INJECT_MAC) \
        .Action(macro,
                next_macro=SYSTEM_INJECT,
                size=4)

    # VLAN-0 tcam entries
    # 0x7102 ethertype/tpid for punt header
    VLAN_0 \
        .Conditions(tpid=ETHER_TYPE_PUNT_MAC) \
        .Action(macro,
                next_macro=SYSTEM_PUNT_PHASE1,
                size=4)

    # /* (SVL Ethernet) */
    VLAN_0 \
        .Conditions(tpid=ETHER_TYPE_SVL) \
        .Action(macro,
                next_macro=SVL_TM_HEADER,
                size=4)
    VLAN_0 \
        .Conditions(tpid=0x0800) \
        .Action(macro,
                next_macro=IPV4,
                size=4)

    VLAN_0 \
        .Conditions(tpid=0x86dd) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                size=4)

    VLAN_0 \
        .Conditions(tpid=0x8847) \
        .Action(macro,
                next_macro=MPLS_0,
                size=4)

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
                size=4)

    VLAN_1 \
        .Conditions() \
        .Action(macro,
                next_macro=ETHERTYPE,
                advance_data=False)

    ETHERTYPE \
        .Conditions(tpid=0x806) \
        .Action(macro,
                next_macro=ARP,
                size=4)

    # PTP over Vlan over Eth
    ETHERTYPE \
        .Conditions(tpid=0x88f7) \
        .Action(macro,
                next_macro=PTP,
                size=4)

    # L2CP CFM
    ETHERTYPE \
        .Conditions(tpid=0x8902) \
        .Action(macro,
                next_macro=CFM,
                size=4)

    # PFC pause frames
    ETHERTYPE \
        .Conditions(tpid=0x8808) \
        .Action(macro,
                next_macro=PFC,
                size=4)

    # MACSEC over EthoVLANoVLAN - RFC MACSEC
    ETHERTYPE \
        .Conditions(tpid=0x888e) \
        .Action(macro,
                next_macro=MACSEC,
                size=4)

    # MACSEC over EthoVLANoVLAN - Propriety MACSEC
    ETHERTYPE \
        .Conditions(tpid=0x876f) \
        .Action(macro,
                next_macro=MACSEC,
                size=4)

    # MACSEC over EthoVLANoVLAN - Propriety MACSEC
    ETHERTYPE \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                size=4)

    # ARP tcam entries
    ARP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                size=28)

    # ICMP tcam entries
    ICMP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                size=8)

    # IGMP tcam entries
    IGMP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                size=8)

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
                header_flags=flag_sip_multicast)

    # sip is broadcast. Always catch error packet and stop parsing
    IPV4 \
        .Conditions(sip_24_msb=0xffffff) \
        .Action(macro,
                next_macro=UNDEF,
                header_flags=flag_sip_multicast)

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
                header_type=PROTOCOL_TYPE_IPV4_L4,
                next_macro=UDP)

    # TCP
    IPV4 \
        .Conditions(protocol=0x6) \
        .Action(macro,
                header_type=PROTOCOL_TYPE_IPV4_L4,
                next_macro=TCP)

    # IPV4-IGMP
    IPV4 \
        .Conditions(protocol=0x2) \
        .Action(macro,
                header_type=PROTOCOL_TYPE_IPV4_L4,
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
                header_flags=flag_header_error,
                size=6)

    # IPv6 Hop-limit == 0 -> header_error=1, advance 6B
    #.Conditions(hop_limit_sip_16_msb={"key": 0x000000, "mask": 0xff0000}) \
    IPV6_FIRST \
        .Conditions(hop_limit=0) \
        .Action(macro,
                next_macro=IPV6_SECOND,
                header_flags=flag_header_error,
                size=6)

    # IPv6 SIP[127:112] == 0 -> sip_msbs_are_0=1, advance 6B
    #.Conditions(hop_limit_sip_16_msb={"key": 0x000000, "mask": 0x00ffff}, version=0x6) \
    # IPV6_FIRST \
    #     .Conditions(sip_16_msb=0, version=0x6) \
    #     .Action(macro,
    #             next_macro=IPV6_SECOND,
    #             header_flags=flag_sip_msbs_eq_0,
    #             size=6)
    # NOTES: Above should ideally should be a full 128 bit all_zeros.  Checking only 16 bit msbs conflicts
    #        with some valid cases such as ipv4 over ipv6.

    # IPv6 version==6 and no other error -> go to next nacro IPV6_SECOND, advance 6B
    IPV6_FIRST \
        .Conditions(version=0x6) \
        .Action(macro,
                next_macro=IPV6_SECOND,
                size=6)

    # IPv6 version!=6 and no other error -> Stop processing, advance 40B
    IPV6_FIRST \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_flags=flag_header_error,
                size=40)

    # IPv6 NxtHdr==UDP
    IPV6_SECOND \
        .Conditions(next_header=0x11) \
        .Action(macro,
                header_type=PROTOCOL_TYPE_IPV6_L4,
                next_macro=UDP,
                size=34)

    # IPv6 NxtHdr==TCP
    IPV6_SECOND \
        .Conditions(next_header=0x6) \
        .Action(macro,
                header_type=PROTOCOL_TYPE_IPV6_L4,
                next_macro=TCP,
                size=34)

    # IPv6 NxtHdr == GRE
    IPV6_SECOND \
        .Conditions(next_header=0x2f) \
        .Action(macro,
                next_macro=GRE,
                size=34)

    # IPv6 NxtHdr==ICMP
    IPV6_SECOND \
        .Conditions(next_header=0x3a) \
        .Action(macro,
                next_macro=ICMP,
                size=34)

    # IPv6 in IPv6
    IPV6_SECOND \
        .Conditions(next_header=0x29) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                size=34)

    # IPv4 in IPv6
    IPV6_SECOND \
        .Conditions(next_header=0x4) \
        .Action(macro,
                next_macro=IPV4,
                size=34)

    # IPv6 NxtHdr==Frag EH
    IPV6_SECOND \
        .Conditions(next_header=0x2c) \
        .Action(macro,
                next_macro=IPV6_FRAG_EH,
                size=34)

    # IPv6 NxtHdr==Destination EH
    IPV6_SECOND \
        .Conditions(next_header=0x3c) \
        .Action(macro,
                next_macro=IPV6_EH,
                size=34)

    # IPv6 NxtHdr==Routing EH
    IPV6_SECOND \
        .Conditions(next_header=0x2b) \
        .Action(macro,
                next_macro=IPV6_EH,
                size=34)

    # IPv6 NxtHdr==Authentication EH
    IPV6_SECOND \
        .Conditions(next_header=0x33) \
        .Action(macro,
                next_macro=IPV6_EH,
                size=34)

    # IPv6 NxtHdr==Mobility EH
    IPV6_SECOND \
        .Conditions(next_header=0x87) \
        .Action(macro,
                next_macro=IPV6_EH,
                size=34)

    # IPv6 NxtHdr==HIP EH
    IPV6_SECOND \
        .Conditions(next_header=0x8b) \
        .Action(macro,
                next_macro=IPV6_EH,
                size=34)

    # IPv6 NxtHdr==SHIM6 EH
    IPV6_SECOND \
        .Conditions(next_header=0x8c) \
        .Action(macro,
                next_macro=IPV6_EH,
                size=34)

    # IPv6 EH NxtHdr==UDP
    IPV6_EH \
        .Conditions(next_protocol=0x11) \
        .Action(macro,
                next_macro=UDP)

    # IPv6 EH NxtHdr==TCP
    IPV6_EH \
        .Conditions(next_protocol=0x6) \
        .Action(macro,
                next_macro=TCP)

    # IPv6 EH NxtHdr==ICMP
    IPV6_EH \
        .Conditions(next_protocol=0x3a) \
        .Action(macro,
                next_macro=ICMP)

    # IPv6 EH NxtHdr== inner IPV6
    IPV6_EH \
        .Conditions(next_protocol=0x29) \
        .Action(macro,
                next_macro=IPV6_FIRST)

    # IPv6 EH NxtHdr== inner IPV4
    IPV6_EH \
        .Conditions(next_protocol=0x4) \
        .Action(macro,
                next_macro=IPV4)

    # IPv6 EH NxtHdr== inner GRE
    IPV6_EH \
        .Conditions(next_protocol=0x2f) \
        .Action(macro,
                next_macro=GRE)

    # IPv6 EH NxtHdr==Frag EH
    IPV6_EH \
        .Conditions(next_protocol=0x2c) \
        .Action(macro,
                next_macro=IPV6_FRAG_EH)

    # IPv6 EH NxtHdr==Destination EH
    IPV6_EH \
        .Conditions(next_protocol=0x3c) \
        .Action(macro,
                next_macro=IPV6_EH)

    # IPv6 EH NxtHdr==Routing EH
    IPV6_EH \
        .Conditions(next_protocol=0x2b) \
        .Action(macro,
                next_macro=IPV6_EH)

    # IPv6 EH NxtHdr==Authentication EH
    IPV6_EH \
        .Conditions(next_protocol=0x33) \
        .Action(macro,
                next_macro=IPV6_EH)

    # IPv6 EH NxtHdr==Mobility EH
    IPV6_EH \
        .Conditions(next_protocol=0x87) \
        .Action(macro,
                next_macro=IPV6_EH)

    # IPv6 EH NxtHdr==HIP EH
    IPV6_EH \
        .Conditions(next_protocol=0x8b) \
        .Action(macro,
                next_macro=IPV6_EH)

    # IPv6 EH NxtHdr==SHIM6 EH
    IPV6_EH \
        .Conditions(next_protocol=0x8c) \
        .Action(macro,
                next_macro=IPV6_EH)

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
                header_flags=flag_is_fragmented)

    # GRE
    # supported: checksum, key, sequence number
    # not supported: routing

    # IPv4 over GRE
    # checksum flag = 0
    GRE \
        .Conditions(cs=0, protocol=0x800) \
        .Action(macro,
                next_macro=IPV4,
                size=4)

    # IPv6 over GRE
    # checksum flag = 0
    GRE \
        .Conditions(cs=0, protocol=0x86dd) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                size=4)

    # MPLS over GRE
    # checksum flag = 0
    GRE \
        .Conditions(cs=0, protocol=0x8847) \
        .Action(macro,
                next_macro=MPLS_0,
                size=4)

    # Ethernet over GRE
    # checksum flag = 0
    GRE \
        .Conditions(cs=0, protocol=0x6558) \
        .Action(macro,
                next_macro=ETH,
                size=4)

    # not supported protocol with checksum flag = 0
    GRE \
        .Conditions(cs=0) \
        .Action(macro,
                next_macro=UNDEF,
                size=4)

    # IPv4 over GRE
    # checksum flag = 1
    GRE \
        .Conditions(cs=1, protocol=0x800) \
        .Action(macro,
                next_macro=IPV4,
                size=8)

    # IPv6 over GRE
    # checksum flag = 1
    GRE \
        .Conditions(cs=1, protocol=0x86dd) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                size=8)

    # MPLS over GRE
    # checksum flag = 1
    GRE \
        .Conditions(cs=1, protocol=0x8847) \
        .Action(macro,
                next_macro=MPLS_0,
                size=8)

    # Ethernet over GRE
    # checksum flag = 1
    GRE \
        .Conditions(cs=1, protocol=0x6558) \
        .Action(macro,
                next_macro=ETH,
                size=8)

    # not supported protocol with checksum flag = 1
    GRE \
        .Conditions(cs=1) \
        .Action(macro,
                next_macro=UNDEF,
                size=8)

    # UDP tcam entries - VXLAN AFTER UDP
    UDP \
        .Conditions(dst_port=0x12b5) \
        .Action(macro,
                next_macro=VXLAN,
                size=8)

    # UDP tcam entries - GTP-U
    UDP \
        .Conditions(dst_port=0x868) \
        .Action(macro,
                next_macro=GTP,
                size=8)

    # user defined/PVC tunnel
    UDP \
        .Conditions(dst_port=0xfa) \
        .Action(macro,
                next_macro=IP_OVER_UDP,
                size=16)

    # UDP tcam entries - IP AFTER UDP-GUE
    UDP \
        .Conditions(dst_port=0x17c0, ip_version=0x4) \
        .Action(macro,
                next_macro=IPV4,
                size=8)

    # UDP tcam entries - IP AFTER UDP-GUE
    UDP \
        .Conditions(dst_port=0x17c0, ip_version=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                size=8)

    # UDP tcam entries - MPLS AFTER UDP
    UDP \
        .Conditions(dst_port=0x19eb) \
        .Action(macro,
                next_macro=MPLS_0,
                size=8)

    # UDP tcam entries - Default UDP
    UDP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                size=8)

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
                next_macro=GTP)

    # default TCP
    TCP \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF)

    VXLAN \
        .Conditions() \
        .Action(macro,
                next_macro=ETH,
                size=8)

    # TODO not supported
    # Extended PORT VLAN
    # EXTENDED_VLAN \
    #     .Conditions() \
    #     .Action(macro,
    #         next_macro=ETH,
    #         header_type=PROTOCOL_TYPE_VLAN_0,
    #         size=4)

    # inject down - Header size is 17 + trailer size calculated using ALU
    # On inject down we do not process the packet contrents so no need to continue parsing
    SYSTEM_INJECT \
        .Conditions(inject_header_type={"key": INJECT_HEADER_TYPE_DOWN, "mask": 0x7e}) \
        .Action(macro,
                next_macro=UNDEF,
                size=17)

    # inject up - Header size is 17 + trailer size calculated using ALU
    #  Inject up next protocol is encoded in the 2 lsb of the header type:
    #    Ethernet - 10
    #    IPv4     - 01
    #    IPv6     - 00
    #    Other    - 11
    SYSTEM_INJECT \
        .Conditions(inject_header_type={"key": 0b10, "mask": 0x3}) \
        .Action(macro,
                next_macro=ETH,
                size=17)

    SYSTEM_INJECT \
        .Conditions(inject_header_type={"key": 0b01, "mask": 0x3}) \
        .Action(macro,
                next_macro=IPV4,
                size=17)

    SYSTEM_INJECT \
        .Conditions(inject_header_type={"key": 0b00, "mask": 0x3}) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                size=17)

    SYSTEM_INJECT \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                size=17)

    # Recycle punt header tcam entries
    #   first phase - advance data with max databus size
    # 0xCE is MC_LPTS punt code.  Continue parsing beyond punt header as needed by LPTS processing.
    # all other cases, punt header is terminal-- no need to parse beyond.
    SYSTEM_PUNT_PHASE1 \
        .Conditions(punt_code=0xCE) \
        .Action(macro,
                next_macro=ETH,
                size=28)

    SYSTEM_PUNT_PHASE1 \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                size=28)

   # These are not really used? May alias with MAC header if speculating
   # v4/v6
   #
   # # Recycle punt header tcam entries
   # # punt_code_4_msb - next header first nibble (speculative ipv4)
   # SYSTEM_PUNT_PHASE2 \
   #     .Conditions(punt_code_4_msb=0x4) \
   #     .Action(macro,
   #             next_macro=IPV4,
   #             size=3)
   #
   # # Recycle punt header tcam entries
   # SYSTEM_PUNT_PHASE2 \
   #     .Conditions(punt_code_4_msb=0x6) \
   #     .Action(macro,
   #             next_macro=IPV6_FIRST,
   #             size=3)

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
                header_flags=flag_illegal_ipv4 | flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries
    # null+bos, next-spculative-is-v4
    MPLS_0 \
        .Conditions(label=0, bos=1, speculative_next_nibble=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_flags=flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries
    # null+bos, next-spculative-is-v6
    MPLS_0 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=1, speculative_next_nibble=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_flags=flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries
    # null+bos
    MPLS_0 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=1) \
        .Action(macro,
                next_macro=ETH,
                header_flags=flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries
    # null+not-bos
    MPLS_0 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=0) \
        .Action(macro,
                next_macro=MPLS_1,
                header_flags=flag_is_null,
                size=4)

    # MPLS tcam entries
    # ELI Label
    MPLS_0 \
        .Conditions(label=0x7, bos=0) \
        .Action(macro,
                next_macro=MPLS_EL,
                header_flags=flag_is_null,
                size=4)

    # not null -> do mpls-stack logic
    MPLS_0 \
        .Conditions() \
        .Action(macro,
                next_macro=MPLS_2,
                mask_hardwired_flags=flag_is_bos,
                mask_hardwired_size=0b111111)

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
                header_flags=flag_illegal_ipv4 | flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries
    # null+bos, next-spculative-is-v4
    MPLS_1 \
        .Conditions(label=0, bos=1, speculative_next_nibble=0x4) \
        .Action(macro,
                next_macro=IPV4,
                header_flags=flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries
    # null+bos, next-spculative-is-v6
    MPLS_1 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=1, speculative_next_nibble=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_flags=flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries
    # null+bos where not IPv4/IPv6 -> assuming Ethernet
    MPLS_1 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=1) \
        .Action(macro,
                next_macro=ETH,
                header_flags=flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries
    # null+not-bos
    MPLS_1 \
        .Conditions(label={"key": 0x0, "mask": 0xffffd}, bos=0) \
        .Action(macro,
                next_macro=MPLS_1,
                header_flags=flag_is_null,
                size=4)

    # ELI
    MPLS_1 \
        .Conditions(label=0x7, bos=0) \
        .Action(macro,
                next_macro=MPLS_EL,
                header_flags=flag_is_null,
                size=4)

    # not null -> close null and start mpls-stack header on NEXT macro
    MPLS_1 \
        .Conditions() \
        .Action(macro,
                next_macro=MPLS_2,
                start_header=True)

    # prev macro is not bos -> do mpls-stack logic
    MPLS_2 \
        .Conditions(prev_bos=0) \
        .Action(macro,
                next_macro=MPLS_2,
                mask_hardwired_flags=flag_is_bos,
                mask_hardwired_size=0b111111)

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
                header_flags=flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries */
    # EL + bos, next-spculative-is-v6
    MPLS_EL \
        .Conditions(bos=1, speculative_next_nibble=0x6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                header_flags=flag_is_null | flag_is_bos,
                size=4)

    # MPLS tcam entries
    # EL + bos
    MPLS_EL \
        .Conditions(bos=1) \
        .Action(macro,
                next_macro=ETH,
                header_flags=flag_is_null | flag_is_bos,
                size=4)

    # EL not BOS -> check if next label closes the null stack
    MPLS_EL \
        .Conditions() \
        .Action(macro,
                next_macro=MPLS_1,
                header_flags=flag_is_null,
                size=4)

    OAMP \
        .Conditions(fwd_header_type=FWD_HEADER_TYPE_IPV4) \
        .Action(macro,
                next_macro=IPV4,
                size=32)

    OAMP \
        .Conditions(fwd_header_type=FWD_HEADER_TYPE_IPV6) \
        .Action(macro,
                next_macro=IPV6_FIRST,
                size=32)

    OAMP \
        .Conditions() \
        .Action(macro,
                next_macro=ETH,
                mask_alu_size=0,
                size=32)

    # fabric context
    # fbric/tm headers part
    # first header is fabric, followed by TM, followed by NPU(aka SMS)  header.
    # first we configure the first-macro-table, then the tcam entris that will lead us to the next macro. since there are 4 TM headers type - we have 4 entries in the "fabric TCAM"(it's the same TCAM for all),
    # but logically it's adiffrenet one.
    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET) \
        .Action(macro,
                next_macro=TM,
                header_type=FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET,
                size=6)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS) \
        .Action(macro,
                next_macro=TM,
                header_type=FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS,
                size=7)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET) \
        .Action(macro,
                next_macro=TM,
                header_type=FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET,
                size=12)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS) \
        .Action(macro,
                next_macro=TM,
                header_type=FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS,
                size=13)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_SN_TS_PLB_KEEPALIVE) \
        .Action(macro,
                next_macro=TM,
                header_type=FABRIC_HEADER_TYPE_SN_TS_PLB_KEEPALIVE,
                size=10)

    FABRIC \
        .Conditions(fabric_header_type=FABRIC_HEADER_TYPE_FLB) \
        .Action(macro,
                next_macro=TM,
                header_type=FABRIC_HEADER_TYPE_FLB,
                size=3)

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
                header_type=TM_HEADER_TYPE_UNICAST_OR_MUU_PLB << 2,
                size=uc_or_muu_plb_tm_header_size)

    TM \
        .Conditions(tm_header_type=TM_HEADER_TYPE_UNICAST_FLB) \
        .Action(macro,
                next_macro=UNDEF,
                header_type=TM_HEADER_TYPE_UNICAST_FLB << 2,  # type is 2 bits, padding with 0 in msb and 2'b0 in lsb
                size=3)

    TM \
        .Conditions(tm_header_type=TM_HEADER_TYPE_MMM_PLB_OR_FLB) \
        .Action(macro,
                next_macro=UNDEF,
                header_type=TM_HEADER_TYPE_MMM_PLB_OR_FLB << 2,  # type is 2 bits, padding with 0 in msb and 2'b0 in lsb
                size=3)

    TM \
        .Conditions(tm_header_type=TM_HEADER_TYPE_MUM_PLB) \
        .Action(macro,
                next_macro=UNDEF,
                header_type=TM_HEADER_TYPE_MUM_PLB << 2,  # type is 2 bits, padding with 0 in msb and 2'b0 in lsb
                size=5)

    FABRIC \
        .Conditions() \
        .Action(macro,
                next_macro=UNDEF,
                header_type=FABRIC_HEADER_TYPE_FLB,
                size=3)

    UNDEF \
        .Conditions(mask_macro_id=0) \
        .Action(macro,
                next_macro=UNDEF)

    FiMacro.populate_macro(macro)
