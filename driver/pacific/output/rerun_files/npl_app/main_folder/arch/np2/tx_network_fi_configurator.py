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
    IS_RXPP = False
    ########################
    # STAGE 3 macro config #
    ########################

    STAGE = PFI_STAGE_3
    macro_config = {NETWORK_CONTEXT:[]}

    # macro config
    TX_PFI_3_ETH = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_3_MACRO_ID_ETH,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_ETHERNET) \
        .Key('ether_type_or_tpid', EthernetHeader().ether_type_or_tpid) \
        .Hardwired(FI_HARDWIRED_LOGIC_ETHERNET, mask_hw_logic_header_format_flags=flag_da_is_bc | flag_sa_is_mc | flag_sa_eq_da) \
        .AddMacro(macro_config)

    # (header-error can be: TTL==0, Version, HLN, SIP multicast)
    TX_PFI_3_IPV4 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_3_MACRO_ID_IPV4,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV4) \
        .Hardwired(FI_HARDWIRED_LOGIC_IPV4, mask_hw_logic_header_format_flags=flag_header_error | flag_is_fragmented | flag_checksum_error) \
        .Key('sip_24_msb', IPv4Header().sip.Slice(31, 8)) \
        .Key('protocol', IPv4Header().protocol) \
        .Shifter(IPv4Header().hln, 2) \
        .AddMacro(macro_config)

    TX_PFI_3_IPV6_FIRST = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_3_MACRO_ID_IPV6_FIRST,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV6) \
        .Key('next_header', IPv6Header().next_header) \
        .AddMacro(macro_config)

    FiMacro.populate_macro_config(macro_config=macro_config, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 4 macro config #
    ########################

    STAGE = PFI_STAGE_4
    macro_config = {NETWORK_CONTEXT:[]}

    # macro config
    TX_PFI_4_VLAN_0 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_VLAN_0,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_VLAN_0) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hw_logic_header_format_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    TX_PFI_4_VLAN_1 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_VLAN_1,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_VLAN_1) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hw_logic_header_format_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    # (header-error can be: TTL==0, Version, HLN, SIP multicast)
    TX_PFI_4_IPV4 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_IPV4,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV4) \
        .Hardwired(FI_HARDWIRED_LOGIC_IPV4, mask_hw_logic_header_format_flags=flag_header_error | flag_is_fragmented | flag_checksum_error) \
        .Key('sip_24_msb', IPv4Header().sip.Slice(31, 8)) \
        .Key('protocol', IPv4Header().protocol) \
        .Shifter(IPv4Header().hln, 2) \
        .AddMacro(macro_config)

    TX_PFI_4_IPV6_FIRST = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_IPV6_FIRST,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV6) \
        .Key('next_header', IPv6Header().next_header) \
        .AddMacro(macro_config)

    TX_PFI_4_UDP = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_UDP,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_UDP) \
        .Key('dst_port', UDPHeader().dst_port) \
        .Key('ip_version', UDPHeader().ip_version) \
        .AddMacro(macro_config)

    # TODO replace hw logic when nsim is ready
    TX_PFI_4_GRE = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_GRE,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_GRE) \
        .Hardwired(FI_HARDWIRED_LOGIC_NONE, mask_hw_logic_header_format_flags=flag_header_error | flag_is_fragmented | flag_checksum_error, mask_hw_logic_calc_header_size=True) \
        .Key('protocol', GREHeader().protocol) \
        .AddMacro(macro_config)

    TX_PFI_4_IPV6_FIRST = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_IPV6_FIRST,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV6) \
        .Key('next_header', IPv6Header().next_header) \
        .AddMacro(macro_config)

    TX_PFI_4_MPLS_0 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_MPLS_0,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_MPLS) \
        .Hardwired(FI_HARDWIRED_LOGIC_MPLS) \
        .Key('label', MPLSHeader().label) \
        .Key('exp', MPLSHeader().exp) \
        .Key('bos', MPLSHeader().bos) \
        .Key('speculative_next_nibble', MPLSHeader().speculative_next_nibble) \
        .AddMacro(macro_config)

    TX_PFI_4_CFM = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_CFM,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_CFM) \
        .AddMacro(macro_config)

    FiMacro.populate_macro_config(macro_config=macro_config, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 5 macro config #
    ########################

    STAGE = PFI_STAGE_5
    macro_config = {NETWORK_CONTEXT:[]}

    # macro config
    TX_PFI_5_VLAN_0 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_5_MACRO_ID_VLAN_0,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_VLAN_0) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hw_logic_header_format_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    TX_PFI_5_VLAN_1 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_5_MACRO_ID_VLAN_1,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_VLAN_1) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hw_logic_header_format_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    # (header-error can be: TTL==0, Version, HLN, SIP multicast)
    TX_PFI_5_IPV4 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_5_MACRO_ID_IPV4,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV4) \
        .Hardwired(FI_HARDWIRED_LOGIC_IPV4, mask_hw_logic_header_format_flags=flag_header_error | flag_is_fragmented | flag_checksum_error) \
        .Key('sip_24_msb', IPv4Header().sip.Slice(31, 8)) \
        .Key('protocol', IPv4Header().protocol) \
        .Shifter(IPv4Header().hln, 2) \
        .AddMacro(macro_config)

    TX_PFI_5_IPV6_FIRST = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_5_MACRO_ID_IPV6_FIRST,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV6) \
        .Key('next_header', IPv6Header().next_header) \
        .AddMacro(macro_config)

    TX_PFI_5_UDP = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_5_MACRO_ID_UDP,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_UDP) \
        .Key('dst_port', UDPHeader().dst_port) \
        .Key('ip_version', UDPHeader().ip_version) \
        .AddMacro(macro_config)

    # TODO replace hw logic when nsim is ready
    TX_PFI_5_GRE = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_5_MACRO_ID_GRE,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_GRE) \
        .Hardwired(FI_HARDWIRED_LOGIC_NONE, mask_hw_logic_header_format_flags=flag_header_error | flag_is_fragmented | flag_checksum_error, mask_hw_logic_calc_header_size=True) \
        .Key('protocol', GREHeader().protocol) \
        .AddMacro(macro_config)

    TX_PFI_5_MPLS_0 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_5_MACRO_ID_MPLS_0,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_MPLS) \
        .Hardwired(FI_HARDWIRED_LOGIC_MPLS) \
        .Key('label', MPLSHeader().label) \
        .Key('exp', MPLSHeader().exp) \
        .Key('bos', MPLSHeader().bos) \
        .Key('speculative_next_nibble', MPLSHeader().speculative_next_nibble) \
        .AddMacro(macro_config)

    TX_PFI_5_CFM = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_5_MACRO_ID_CFM,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_CFM) \
        .AddMacro(macro_config)

    FiMacro.populate_macro_config(macro_config=macro_config, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 6 macro config #
    ########################

    STAGE = PFI_STAGE_6
    macro_config = {NETWORK_CONTEXT:[]}

    TX_PFI_6_VLAN_0 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_6_MACRO_ID_VLAN_0,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_VLAN_0) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hw_logic_header_format_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    TX_PFI_6_VLAN_1 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_6_MACRO_ID_VLAN_1,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_VLAN_1) \
        .Hardwired(FI_HARDWIRED_LOGIC_VLAN, mask_hw_logic_header_format_flags=flag_is_priority) \
        .Key('tpid', VlanHeader().tpid) \
        .AddMacro(macro_config)

    TX_PFI_6_IPV4 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_6_MACRO_ID_IPV4,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_IPV4) \
        .Hardwired(FI_HARDWIRED_LOGIC_IPV4, mask_hw_logic_header_format_flags=flag_header_error | flag_is_fragmented | flag_checksum_error) \
        .Key('sip_24_msb', IPv4Header().sip.Slice(31, 8)) \
        .Key('protocol', IPv4Header().protocol) \
        .Shifter(IPv4Header().hln, 2) \
        .AddMacro(macro_config)

    TX_PFI_6_IPV6_FIRST = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_6_MACRO_ID_IPV6_FIRST,
        start_new_header=True,
        start_new_layer=True,
        last_macro=True,
        header_format_type=PROTOCOL_TYPE_IPV6) \
        .Key('next_header', IPv6Header().next_header) \
        .AddMacro(macro_config)

    TX_PFI_6_UDP = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_6_MACRO_ID_UDP,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_UDP) \
        .Key('dst_port', UDPHeader().dst_port) \
        .Key('ip_version', UDPHeader().ip_version) \
        .AddMacro(macro_config)

    # TODO replace hw logic when nsim is ready
    TX_PFI_6_GRE = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_6_MACRO_ID_GRE,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=PROTOCOL_TYPE_GRE) \
        .Hardwired(FI_HARDWIRED_LOGIC_NONE, mask_hw_logic_header_format_flags=flag_header_error | flag_is_fragmented | flag_checksum_error, mask_hw_logic_calc_header_size=True) \
        .Key('protocol', GREHeader().protocol) \
        .AddMacro(macro_config)

    TX_PFI_6_MPLS_0 = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_6_MACRO_ID_MPLS_0,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_MPLS) \
        .Hardwired(FI_HARDWIRED_LOGIC_MPLS) \
        .Key('label', MPLSHeader().label) \
        .Key('exp', MPLSHeader().exp) \
        .Key('bos', MPLSHeader().bos) \
        .Key('speculative_next_nibble', MPLSHeader().speculative_next_nibble) \
        .AddMacro(macro_config)

    TX_PFI_6_CFM = FiMacro(
        contexts=[NETWORK_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_6_MACRO_ID_CFM,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=PROTOCOL_TYPE_CFM) \
        .AddMacro(macro_config)

    TX_PFI_6_UNDEF = FiMacro([],
                             stage=STAGE,
                             macro_id=TX_PFI_6_MACRO_ID_UNDEF,
                             start_new_header=True,
                             start_new_layer=True,
                             last_macro=True) \

    FiMacro.populate_macro_config(macro_config=macro_config, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 3 tcam config  #
    ########################

    # FI config - tcam entries
    STAGE = PFI_STAGE_3
    macro = {NETWORK_CONTEXT:[]}

    TX_PFI_3_ETH \
        .Conditions(ether_type_or_tpid=0x8100) \
        .Action(macro,
                next_macro=TX_PFI_4_VLAN_0,
                header_size=14)

    # /* (Ethernet QinQ) */
    TX_PFI_3_ETH \
        .Conditions(ether_type_or_tpid=0x9100) \
        .Action(macro,
                next_macro=TX_PFI_4_VLAN_1,
                header_size=14)

    # /* (Ethernet QinQ) */
    TX_PFI_3_ETH \
        .Conditions(ether_type_or_tpid=0x88a8) \
        .Action(macro,
                next_macro=TX_PFI_4_VLAN_1,
                header_size=14)

    TX_PFI_3_ETH \
        .Conditions(ether_type_or_tpid=0x9200) \
        .Action(macro,
                next_macro=TX_PFI_4_VLAN_1,
                header_size=14)

    TX_PFI_3_ETH \
        .Conditions(ether_type_or_tpid=0x0800) \
        .Action(macro,
                next_macro=TX_PFI_4_IPV4,
                header_size=14)

    TX_PFI_3_ETH \
        .Conditions(ether_type_or_tpid=0x86dd) \
        .Action(macro,
                next_macro=TX_PFI_4_IPV6_FIRST,
                header_size=14)

    TX_PFI_3_ETH \
        .Conditions(ether_type_or_tpid=0x8847) \
        .Action(macro,
                next_macro=TX_PFI_4_MPLS_0,
                header_size=14)

    TX_PFI_3_ETH \
        .Conditions(ether_type_or_tpid=0x8848) \
        .Action(macro,
                next_macro=TX_PFI_4_MPLS_0,
                header_size=14)

    TX_PFI_3_ETH \
        .Conditions(ether_type_or_tpid=0x8902) \
        .Action(macro,
                next_macro=TX_PFI_4_CFM,
                header_size=14)

    TX_PFI_3_ETH \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=14)

    TX_PFI_3_IPV4 \
        .Conditions(protocol=0x2f) \
        .Action(macro,
                next_macro=TX_PFI_4_GRE)

    TX_PFI_3_IPV4 \
        .Conditions(protocol=0x11) \
        .Action(macro,
                next_macro=TX_PFI_4_UDP)

    TX_PFI_3_IPV4 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF)

    TX_PFI_3_IPV6_FIRST \
        .Conditions(next_header=0x11) \
        .Action(macro,
                next_macro=TX_PFI_4_UDP,
                header_size=40)

    TX_PFI_3_IPV6_FIRST \
        .Conditions(next_header=0x2f) \
        .Action(macro,
                next_macro=TX_PFI_4_GRE,
                header_size=40)

    TX_PFI_3_IPV6_FIRST \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=40)

    FiMacro.populate_macro(macro=macro, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 4 tcam config  #
    ########################

    # FI config - tcam entries
    STAGE = PFI_STAGE_4
    macro = {NETWORK_CONTEXT:[]}

    TX_PFI_4_VLAN_0 \
        .Conditions(tpid=0x8100) \
        .Action(macro,
                next_macro=TX_PFI_5_VLAN_0,
                header_size=4)

    TX_PFI_4_VLAN_0 \
        .Conditions(tpid=0x9100) \
        .Action(macro,
                next_macro=TX_PFI_5_VLAN_0,
                header_size=4)

    TX_PFI_4_VLAN_0 \
        .Conditions(tpid=0x88a8) \
        .Action(macro,
                next_macro=TX_PFI_5_VLAN_0,
                header_size=4)

    TX_PFI_4_VLAN_0 \
        .Conditions(tpid=0x9200) \
        .Action(macro,
                next_macro=TX_PFI_5_VLAN_0,
                header_size=4)

    TX_PFI_4_VLAN_0 \
        .Conditions(tpid=0x0800) \
        .Action(macro,
                next_macro=TX_PFI_5_IPV4,
                header_size=4)

    TX_PFI_4_VLAN_0 \
        .Conditions(tpid=0x86dd) \
        .Action(macro,
                next_macro=TX_PFI_5_IPV6_FIRST,
                header_size=4)

    TX_PFI_4_VLAN_0 \
        .Conditions(tpid=0x8847) \
        .Action(macro,
                next_macro=TX_PFI_5_MPLS_0,
                header_size=4)

    TX_PFI_4_VLAN_0 \
        .Conditions(tpid=0x8902) \
        .Action(macro,
                next_macro=TX_PFI_5_CFM,
                header_size=4)

    TX_PFI_4_VLAN_0 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_4_VLAN_1 \
        .Conditions(tpid=0x8100) \
        .Action(macro,
                next_macro=TX_PFI_5_VLAN_0,
                header_size=4)

    TX_PFI_4_VLAN_1 \
        .Conditions(tpid=0x8902) \
        .Action(macro,
                next_macro=TX_PFI_5_CFM,
                header_size=4)

    TX_PFI_4_VLAN_1 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_4_IPV4 \
        .Conditions(protocol=0x2f) \
        .Action(macro,
                next_macro=TX_PFI_5_GRE)

    TX_PFI_4_IPV4 \
        .Conditions(protocol=0x11) \
        .Action(macro,
                next_macro=TX_PFI_5_UDP)

    TX_PFI_4_IPV4 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF)

    TX_PFI_4_IPV6_FIRST \
        .Conditions(next_header=0x11) \
        .Action(macro,
                next_macro=TX_PFI_5_UDP,
                header_size=40)

    TX_PFI_4_IPV6_FIRST \
        .Conditions(next_header=0x2f) \
        .Action(macro,
                next_macro=TX_PFI_5_GRE,
                header_size=40)

    TX_PFI_4_IPV6_FIRST \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=40)

    TX_PFI_4_MPLS_0 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_4_UDP \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=8)

    TX_PFI_4_GRE \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_4_CFM \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF)

    FiMacro.populate_macro(macro=macro, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 5 tcam config  #
    ########################

    # FI config - tcam entries
    STAGE = PFI_STAGE_5
    macro = {NETWORK_CONTEXT:[]}

    TX_PFI_5_VLAN_0 \
        .Conditions(tpid=0x8100) \
        .Action(macro,
                next_macro=TX_PFI_6_VLAN_0,
                header_size=4)

    TX_PFI_5_VLAN_0 \
        .Conditions(tpid=0x0800) \
        .Action(macro,
                next_macro=TX_PFI_6_IPV4,
                header_size=4)

    TX_PFI_5_VLAN_0 \
        .Conditions(tpid=0x86dd) \
        .Action(macro,
                next_macro=TX_PFI_6_IPV6_FIRST,
                header_size=4)

    TX_PFI_5_VLAN_0 \
        .Conditions(tpid=0x8847) \
        .Action(macro,
                next_macro=TX_PFI_6_MPLS_0,
                header_size=4)

    TX_PFI_5_VLAN_0 \
        .Conditions(tpid=0x8902) \
        .Action(macro,
                next_macro=TX_PFI_6_CFM,
                header_size=4)

    TX_PFI_5_VLAN_0 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_5_VLAN_1 \
        .Conditions(tpid=0x8100) \
        .Action(macro,
                next_macro=TX_PFI_6_VLAN_0,
                header_size=4)

    TX_PFI_5_VLAN_1 \
        .Conditions(tpid=0x8902) \
        .Action(macro,
                next_macro=TX_PFI_6_CFM,
                header_size=4)

    TX_PFI_5_VLAN_1 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_5_IPV4 \
        .Conditions(protocol=0x2f) \
        .Action(macro,
                next_macro=TX_PFI_6_GRE)

    TX_PFI_5_IPV4 \
        .Conditions(protocol=0x11) \
        .Action(macro,
                next_macro=TX_PFI_6_UDP)

    TX_PFI_5_IPV4 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF)

    TX_PFI_5_IPV6_FIRST \
        .Conditions(next_header=0x11) \
        .Action(macro,
                next_macro=TX_PFI_6_UDP,
                header_size=40)

    TX_PFI_5_IPV6_FIRST \
        .Conditions(next_header=0x2f) \
        .Action(macro,
                next_macro=TX_PFI_6_GRE,
                header_size=40)

    TX_PFI_5_IPV6_FIRST \
        .Conditions(next_header=0x2f) \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=40)

    TX_PFI_5_IPV6_FIRST \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=40)

    TX_PFI_5_MPLS_0 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_5_UDP \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=8)

    TX_PFI_5_GRE \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_5_CFM \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF)

    FiMacro.populate_macro(macro=macro, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 6 tcam config  #
    ########################

    # FI config - tcam entries
    STAGE = PFI_STAGE_6
    macro = {NETWORK_CONTEXT:[]}

    TX_PFI_6_VLAN_0 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_5_VLAN_1 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_6_IPV4 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF)

    TX_PFI_6_IPV6_FIRST \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=40)

    TX_PFI_6_MPLS_0 \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_6_UDP \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=8)

    TX_PFI_6_GRE \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF,
                header_size=4)

    TX_PFI_6_CFM \
        .Conditions() \
        .Action(macro,
                next_macro=TX_PFI_6_UNDEF)

    FiMacro.populate_macro(macro=macro, stage=STAGE, is_rxpp=IS_RXPP)
