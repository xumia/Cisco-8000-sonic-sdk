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

PACIFIC_COMPATIBLE_TM_HEADERS_MODE = True

if PACIFIC_COMPATIBLE_TM_HEADERS_MODE:
    uc_or_muu_plb_tm_header_size = 4
else:  # GB
    uc_or_muu_plb_tm_header_size = 5


def config_tables():
    config_light_fi_stages_cfg_table()
    config_light_fi_fabric_table()
    config_light_fi_tm_table()
    config_light_fi_npu_base_table()
    config_light_fi_npu_encap_table()
    config_light_fi_nw_0_table()
    config_light_fi_nw_1_table()
    config_light_fi_nw_2_table()
    config_light_fi_nw_3_table()


def config_light_fi_stages_cfg_table():

    data_light_fi_stages_cfg_table = [
        {
            "key": 0,
            "value": [
                1,     # update_protocol_is_layer        : 1; # added in GB
                1,     # update_current_header_info      : 1; # on fabric/tm/npu header, pointer is to the current-header-type
                0,     # size_width                      : 4;
                0,     # size_offset                     : 6; # ptr to fwd-offset
                1,     # next_protocol_or_type_width     : 3;
                61     # next_protocol_or_type_offset    : 6;
            ]
        },

        {
            "key": 1,
            "value": [
                1,     # update_protocol_is_layer        : 1; # added in GB
                1,     # update_current_header_info      : 1; on fabric/tm/npu header, pointer is to the current-header-type
                0,     # size_width                      : 4;
                0,     # size_offset                     : 6;
                1,     # next_protocol_or_type_width     : 3;
                61     # next_protocol_or_type_offset    : 6;
            ]
        },


        {
            "key": 2,
            "value": [
                1,     # update_protocol_is_layer        : 1; # added in GB
                1,     # update_current_header_info      : 1; on fabric/tm/npu header, pointer is to the current-header-type
                7,     # size_width                      : 4;
                21,    # size_offset                     : 6; # = NPU_HEADER_OFFSET_IN_BITS_TO_FWD_OFFSET/4 # fwd-header-offset.
                1,     # next_protocol_or_type_width     : 3;
                12     # next_protocol_or_type_offset    : 6; # = NPU_HEADER_OFFSET_IN_BITS_TO_FWD_TYPE/4-3
            ]
        },

        {
            "key": 3,
            "value": [
                1,     # update_protocol_is_layer        : 1; # added in GB
                1,     # update_current_header_info      : 1; on fabric/m/npu header, pointer is to the current-header-type
                7,     # size_width                      : 4;
                21,    # size_offset                     : 6; # = NPU_HEADER_OFFSET_IN_BITS_TO_FWD_OFFSET/4 # fwd-header-offset.
                1,     # next_protocol_or_type_width     : 3;
                12     # next_protocol_or_type_offset    : 6; # = NPU_HEADER_OFFSET_IN_BITS_TO_FWD_TYPE/4-3
            ]
        },

        {  # ETH stage
            "key": 4,
            "value": [
                1,     # update_protocol_is_layer        : 1; # added in GB
                0,     # update_current_header_info      : 1; on network, the pointer is to the next-protocol-type
                0,     # size_width                      : 4;
                0,     # size_offset                     : 6; #  will not be used because "use-size"
                4,     # next_protocol_or_type_width     : 3; # with of ether-type in Ethernet-header
                24     # next_protocol_or_type_offset    : 6; # offset to ether-type for Ethernet-header
            ]
        },

        {  # VLAN stage
            "key": 5,
            "value": [
                1,     # update_protocol_is_layer        : 1; # added in GB
                0,     # update_current_header_info      : 1; on network, the pointer is to the next-protocol-type
                0,     # size_width                      : 4;
                0,     # size_offset                     : 6; #  will not be used because "use-size"
                4,     # next_protocol_or_type_width     : 3; # width of ether-type in Vlan-header
                4      # next_protocol_or_type_offset    : 6; # offset to ether-type for vlan-header
            ]
        },

        {  # VLAN stage
            "key": 6,
            "value": [
                1,     # update_protocol_is_layer        : 1; # added in GB
                0,     # update_current_header_info      : 1; on network, the pointer is to the next-protocol-type
                0,     # size_width                      : 4;
                0,     # size_offset                     : 6; #  will not be used because "use-size
                4,     # next_protocol_or_type_width     : 3; # width of ether-type in Vlan-header
                4      # next_protocol_or_type_offset    : 6; # offset to ether-type for vlan-header
            ]
        },


        {  # IPv4 stage
            "key": 7,
            "value": [
                1,     # update_protocol_is_layer        : 1; # added in GB
                0,     # update_current_header_info      : 1; on network, the pointer is to the next-protocol-type
                0,     # size_width                      : 4;
                0,     # size_offset                     : 6; #  will not be used because "use-size
                2,     # next_protocol_or_type_width     : 3; # width of protocol in IPv4 header
                18     # next_protocol_or_type_offset    : 6; # offset to protocol in IPv4 header
            ]
        }
    ]

    # INIT light_fi_stages_cfg_table
    table = light_fi_stages_cfg_table
    for line in data_light_fi_stages_cfg_table:
        # init key
        key = light_fi_stages_cfg_table_key_t(macro_id=line["key"])
        # init value
        val = line["value"]
        conf_data = light_fi_stage_cfg_t(update_protocol_is_layer=val[0],
                                         update_current_header_info=val[1],
                                         size_width=val[2],
                                         size_offset=val[3],
                                         next_protocol_or_type_width=val[4],
                                         next_protocol_or_type_offset=val[5])
        value = light_fi_stages_cfg_table_value_t(light_fi_stage_cfg=conf_data)
        # insert to table
        table.insert(NETWORK_CONTEXT, key, value)
        table.insert(FABRIC_CONTEXT, key, value)
        table.insert(FABRIC_ELEMENT_CONTEXT, key, value)


def config_light_fi_fabric_table():

    data_light_fi_fabric_table = [
        {
            "key": 0,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                          # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_TX_MACRO,                                  # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_NPU_WITH_IVE]              # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 1,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                          # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_TX_MACRO,                                  # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_NPU_NO_IVE]                # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 2,
            "value": [
                0,                                                # use_additional_size                 : 1;
                6,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                1,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET]     # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 3,
            "value": [
                0,                                                # use_additional_size                 : 1;
                7,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                1,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS]    # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 4,
            "value": [
                0,                                                # use_additional_size                 : 1;
                12,                                               # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                1,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET]        # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 5,
            "value": [
                0,                                                # use_additional_size                 : 1;
                13,                                               # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                1,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS]       # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 6,
            "value": [
                0,                                                # use_additional_size                 : 1;
                11,                                               # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_SN_TS_PLB_KEEPALIVE]       # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 7,
            "value": [
                0,                                                # use_additional_size                 : 1;
                3,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_FLB]                       # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 8,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_PEER_DELAY_REQUEST]        # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 9,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_PEER_DELAY_REPLY]          # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 10,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_FABRIC_TIME_SYNC]          # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 11,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_CREDIT_SCHEDULER_CONTROL]  # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 12,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, 0]                                            # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 13,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, 0]                                            # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 14,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, 0]                                            # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": 15,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_TM,                                # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_ELEMENT_TX_MACRO,                          # npe_macro_id                        : 8;
                1,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, 0]                                            # header_format                       : header_format_t; (8)
            ]
        },
    ]

    # INIT light_fi_fabric_table
    table = light_fi_fabric_table
    for line in data_light_fi_fabric_table:
        # init key
        key = light_fi_fabric_table_key_t(fabric_header_type=line["key"])
        # init value
        val = line["value"]
        next_header_format = header_format_t(flags=val[7][0], type=val[7][1])
        header_format = header_format_t(flags=val[8][0], type=val[8][1])
        value = light_fi_fabric_table_value_t(use_additional_size=val[0],
                                              base_size=val[1],
                                              is_next_protocol_layer=val[2],
                                              is_protocol_layer=val[3],
                                              next_fi_macro_id=val[4],
                                              npe_macro_id=val[5],
                                              npe_macro_id_valid=val[6],
                                              next_header_format=next_header_format,
                                              header_format=header_format)
        # insert to table
        table.insert(NETWORK_CONTEXT, key, value)
        table.insert(FABRIC_CONTEXT, key, value)
        # For FE set the macro id to FABRIC_ELEMENT_TX_MACRO in all keys.
        value.payloads.light_fi_leaba_table_hit.npe_macro_id = FABRIC_ELEMENT_TX_MACRO
        table.insert(FABRIC_ELEMENT_CONTEXT, key, value)


def config_light_fi_tm_table():

    data_light_fi_tm_table = [

        {
            "key": 0,  # 'UNICAST_OR_MUU_PLB' type is 2b. configuring 4 entries as key is 4 bits.
            "value": [
                0,                                           # use_additional_size                 : 1;
                uc_or_muu_plb_tm_header_size,                # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_UNICAST_OR_MUU_PLB]       # header_format                       : header_format_t; (8) # 0-3
            ]
        },

        {
            "key": 1,  # 'UNICAST_OR_MUU_PLB' type is 2b. configuring 4 entries as key is 4 bits.
            "value": [
                0,                                           # use_additional_size                 : 1;
                uc_or_muu_plb_tm_header_size,                # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_UNICAST_OR_MUU_PLB]       # header_format                       : header_format_t; (8) # 0-3
            ]
        },

        {
            "key": 2,  # 'UNICAST_OR_MUU_PLB' type is 2b. configuring 4 entries as key is 4 bits.
            "value": [
                0,                                           # use_additional_size                 : 1;
                uc_or_muu_plb_tm_header_size,                # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_UNICAST_OR_MUU_PLB]       # header_format                       : header_format_t; (8) # 0-3
            ]
        },

        {
            "key": 3,  # 'UNICAST_OR_MUU_PLB' type is 2b. configuring 4 entries as key is 4 bits.
            "value": [
                0,                                           # use_additional_size                 : 1;
                uc_or_muu_plb_tm_header_size,                # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_UNICAST_OR_MUU_PLB]       # header_format                       : header_format_t; (8) # 0-3
            ]
        },

        {
            "key": 4,
            "value": [
                0,                                           # use_additional_size                 : 1;
                3,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_UNICAST_FLB]              # header_format                       : header_format_t; (8) # 4-7
            ]
        },

        {
            "key": 5,
            "value": [
                0,                                           # use_additional_size                 : 1;
                3,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_UNICAST_FLB]              # header_format                       : header_format_t; (8) # 4-7
            ]
        },

        {
            "key": 6,
            "value": [
                0,                                           # use_additional_size                 : 1;
                3,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_UNICAST_FLB]              # header_format                       : header_format_t; (8) # 4-7
            ]
        },

        {
            "key": 7,
            "value": [
                0,                                           # use_additional_size                 : 1;
                3,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_UNICAST_FLB]              # header_format                       : header_format_t; (8) # 4-7
            ]
        },

        {
            "key": 8,
            "value": [
                0,                                           # use_additional_size                 : 1;
                3,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_MMM_PLB_OR_FLB]           # header_format                       : header_format_t; (8) # 8-11
            ]
        },

        {
            "key": 9,
            "value": [
                0,                                           # use_additional_size                 : 1;
                3,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_MMM_PLB_OR_FLB]           # header_format                       : header_format_t; (8) # 8-11
            ]
        },

        {
            "key": 10,
            "value": [
                0,                                           # use_additional_size                 : 1;
                3,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_MMM_PLB_OR_FLB]           # header_format                       : header_format_t; (8) # 8-11
            ]
        },

        {
            "key": 11,
            "value": [
                0,                                           # use_additional_size                 : 1;
                3,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_MMM_PLB_OR_FLB]           # header_format                       : header_format_t; (8) # 8-11
            ]
        },

        {
            "key": 12,
            "value": [
                0,                                           # use_additional_size                 : 1;
                5,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_MUM_PLB]                  # header_format                       : header_format_t; (8) # 12-15
            ]
        },

        {
            "key": 13,
            "value": [
                0,                                           # use_additional_size                 : 1;
                5,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_MUM_PLB]                  # header_format                       : header_format_t; (8) # 12-15
            ]
        },


        {
            "key": 14,
            "value": [
                0,                                           # use_additional_size                 : 1;
                5,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_MUM_PLB]                  # header_format                       : header_format_t; (8) # 12-15
            ]
        },


        {
            "key": 15,
            "value": [
                0,                                           # use_additional_size                 : 1;
                5,                                           # base_size                           : 7;
                0,                                           # next_is_protocol_layer              : 1; added in GB
                0,                                           # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                     # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                0x00,                                        # npe_macro_id                        : 8;
                0,                                           # npe_macro_id_valid                  : 1;
                [0, 0],                                      # next_header_format                  : header_format_t; (8)
                [0, TM_HEADER_TYPE_MUM_PLB]                  # header_format                       : header_format_t; (8) # 12-15
            ]
        },
    ]

    # INIT light_fi_tm_table
    table = light_fi_tm_table
    for line in data_light_fi_tm_table:
        # init key
        key = light_fi_tm_table_key_t(tm_header_type=line["key"])
        # init value
        val = line["value"]
        next_header_format = header_format_t(flags=val[7][0], type=val[7][1])
        header_format = header_format_t(flags=val[8][0], type=val[8][1])
        value = light_fi_tm_table_value_t(use_additional_size=val[0],
                                          base_size=val[1],
                                          is_next_protocol_layer=val[2],
                                          is_protocol_layer=val[3],
                                          next_fi_macro_id=val[4],
                                          npe_macro_id=val[5],
                                          npe_macro_id_valid=val[6],
                                          next_header_format=next_header_format,
                                          header_format=header_format)
        # insert to table
        table.insert(NETWORK_CONTEXT, key, value)
        table.insert(FABRIC_CONTEXT, key, value)
        table.insert(FABRIC_ELEMENT_CONTEXT, key, value)


def config_light_fi_npu_base_table():

    data_light_fi_npu_base_table = [

        {
            "key": FWD_HEADER_TYPE_ETHERNET,
            "value": [
                1,                                         # use_additional_size                 : 1;
                0,                                         # base_size                           : 7;
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_ETHERNET],               # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_IPV4,
            "value": [
                1,                                         # use_additional_size                 : 1;
                # base_size                           : 7;
                0,
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_IPV4],                   # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_IPV4_COLLAPSED_MC,
            "value": [
                1,                                         # use_additional_size                 : 1;
                # base_size                           : 7;
                0,
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_ETHERNET],               # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_IPV6,
            "value": [
                1,                                         # use_additional_size                 : 1;
                # base_size                           : 7;
                0,
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_IPV6],                   # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_IPV6_COLLAPSED_MC,
            "value": [
                1,                                         # use_additional_size                 : 1;
                # base_size                           : 7;
                0,
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_ETHERNET],               # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_REDIRECT,
            "value": [
                1,                                         # use_additional_size                 : 1;
                0,                                         # base_size                           : 7;
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_ETHERNET],               # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_INJECT_DOWN,
            "value": [
                1,                                         # use_additional_size                 : 1;
                0,                                         # base_size                           : 7;
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_ETHERNET],               # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_MPLS_BOS_IPV4,
            "value": [
                1,                                         # use_additional_size                 : 1;
                4,                                         # base_size                           : 7; # fwd_offset + 4 bytes forwarding label
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_IPV4],                   # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_MPLS_BOS_ETHERNET,
            "value": [
                1,                                         # use_additional_size                 : 1;
                4,                                         # base_size                           : 7; # fwd_offset + 4 bytes forwarding label
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_ETHERNET],               # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_MPLS_NO_BOS,
            "value": [
                1,                                         # use_additional_size                 : 1;
                4,                                         # base_size                           : 7; # fwd_offset + 4 bytes forwarding label
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_ETHERNET],               # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_MPLS_BOS_IPV6,
            "value": [
                1,                                         # use_additional_size                 : 1;
                4,                                         # base_size                           : 7; # fwd_offset + 4 bytes forwarding label
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_IPV6],                   # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },

        {
            "key": FWD_HEADER_TYPE_SVL,
            "value": [
                1,                                         # use_additional_size                 : 1;
                0,                                         # base_size                           : 7;
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, PROTOCOL_TYPE_ETHERNET],               # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        },
    ]

    # INIT light_fi_npu_base_table
    table = light_fi_npu_base_table
    for line in data_light_fi_npu_base_table:
        # init key
        key = light_fi_npu_base_table_key_t(npu_header_type=line["key"])
        # init value
        val = line["value"]
        next_header_format = header_format_t(flags=val[7][0], type=val[7][1])
        header_format = header_format_t(flags=val[8][0], type=val[8][1])
        value = light_fi_npu_base_table_value_t(use_additional_size=val[0],
                                                base_size=val[1],
                                                is_next_protocol_layer=val[2],
                                                is_protocol_layer=val[3],
                                                next_fi_macro_id=val[4],
                                                npe_macro_id=val[5],
                                                npe_macro_id_valid=val[6],
                                                next_header_format=next_header_format,
                                                header_format=header_format)
        # insert to table
        table.insert(NETWORK_CONTEXT, key, value)

        # For FE: set the macro id to invalid
        value.payloads.light_fi_leaba_table_hit.npe_macro_id_valid = 0
        table.insert(FABRIC_ELEMENT_CONTEXT, key, value)

        value.payloads.light_fi_leaba_table_hit.npe_macro_id_valid = 1
        value.payloads.light_fi_leaba_table_hit.npe_macro_id = FABRIC_TX_MACRO
        table.insert(FABRIC_CONTEXT, key, value)


def config_light_fi_npu_encap_table():

    data_light_fi_npu_encap_table = [

        {
            "key": [
                [4, 0],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b10],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b11],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b100],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b101],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b110],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b111],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1000],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1001],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1010],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1011],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1100],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1101],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1110],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1111],
                [4, FWD_HEADER_TYPE_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b10],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b11],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b100],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b101],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b110],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b111],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1000],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1001],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1010],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1011],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1100],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1101],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1110],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1111],
                [4, FWD_HEADER_TYPE_IPV4]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b10],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b11],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b100],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b101],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b110],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b111],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1000],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1001],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1010],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1011],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1100],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1101],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1110],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1111],
                [4, FWD_HEADER_TYPE_IPV4_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b10],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b11],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b100],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b101],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b110],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b111],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1000],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1001],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1010],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1011],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1100],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1101],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1110],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1111],
                [4, FWD_HEADER_TYPE_IPV6]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b10],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b11],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b100],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b101],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b110],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b111],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1000],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1001],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1010],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1011],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1100],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1101],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1110],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0b1111],
                [4, FWD_HEADER_TYPE_IPV6_COLLAPSED_MC]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b.
            ]
        },

        {
            "key": [
                [4, 0],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b10],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b11],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b100],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b101],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b110],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b111],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1000],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1001],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1010],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1011],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1100],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1101],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1110],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1111],
                [4, FWD_HEADER_TYPE_REDIRECT]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                14                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b10],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b11],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b100],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b101],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b110],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b111],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1000],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1001],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1010],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1011],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1100],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1101],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1110],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1111],
                [4, FWD_HEADER_TYPE_INJECT_DOWN]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                24                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b10],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b11],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b100],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b101],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b110],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b111],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1000],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1001],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1010],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1011],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1100],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },


        {
            "key": [
                [4, 0b1101],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },


        {
            "key": [
                [4, 0b1110],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },

        {
            "key": [
                [4, 0b1111],
                [4, FWD_HEADER_TYPE_MPLS_BOS_ETHERNET]
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0                          # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },
    ]

    # INIT light_fi_npu_encap_table
    table = light_fi_npu_encap_table
    for line in data_light_fi_npu_encap_table:
        # init key
        key_tag = 0
        for ent in line["key"]:
            key_tag <<= ent[0]
            key_tag += ent[1]
        key = light_fi_npu_encap_table_key_t(next_header_type=key_tag)
        # init value
        val = line["value"]
        value = light_fi_npu_encap_table_value_t(spare=val[0],
                                                 next_stage_size_width=val[1],
                                                 next_stage_size_offset=val[2],
                                                 next_stage_protocol_or_type_offset=val[3])
        # insert to table
        table.insert(NETWORK_CONTEXT, key, value)
        table.insert(FABRIC_CONTEXT, key, value)
        table.insert(FABRIC_ELEMENT_CONTEXT, key, value)


def config_light_fi_nw_0_table():

    data_light_fi_nw_0_table = [

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x8100]
            ],
            "mask": [
                [5, 0x1F],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_0],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x9100]
            ],
            "mask": [
                [5, 0x1F],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x88A8]
            ],
            "mask": [
                [5, 0x1F],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x9200]
            ],
            "mask": [
                [5, 0x1F],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x0800]
            ],
            "mask": [
                [5, 0x1F],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_IPV4],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x86DD]
            ],
            "mask": [
                [5, 0x1F],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                12,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_IPV6],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x8847]
            ],  # MPLS_UC
            "mask": [
                [5, 0x1F],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6; # Will hit default
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_MPLS],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x8848]
            ],  # MPLS MC
            "mask": [
                [5, 0x1F],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6; # Will hit default
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_MPLS],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x8902]
            ],  # MPLS MC
            "mask": [
                [5, 0x1F],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6; # Will hit default
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_CFM],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_ETHERNET],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                14,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1; # always first fwd-header is set as new layer!
                LIGHT_FI_STAGE_NETWORK_1,   # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_IPV4],
                [8, 0x11],
                [8, 0x0]
            ],
            "mask": [
                [5, 0x1F],
                [8, 0xff],
                [8, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UDP],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        # Other (can be also for the case that the header is not ipv4. e.g. ipv6)
        {
            "key": [
                [5, PROTOCOL_TYPE_IPV4],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,   # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_IPV6],
                [8, 0x11],
                [8, 0x0]
            ],
            "mask": [
                [5, 0x1F],
                [8, 0xff],
                [8, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                40,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,  # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UDP],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        # Other (can be also for the case that the header is not ipv4. e.g. ipv6)
        {
            "key": [
                [5, PROTOCOL_TYPE_IPV6],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                40,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_1,   # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, 0],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                0,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1; # always first fwd-header is set as new layer!
                LIGHT_FI_STAGE_NETWORK_1,   # next_fi_macro_id           : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format    : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },
    ]

    assert(len(data_light_fi_nw_0_table) <= 16)

    # INIT light_fi_nw_0_table
    table = light_fi_nw_0_table
    location = 0
    for line in data_light_fi_nw_0_table:
        # init key
        key_next_protocol = 0
        for ent in line["key"][1:]:        # key[0] is the current_header_type
            key_next_protocol <<= ent[0]
            key_next_protocol += ent[1]
        key = light_fi_nw_0_table_key_t(next_protocol_field=key_next_protocol,
                                        current_header_type=line["key"][0][1])
        # init mask
        mask_next_protocol = 0
        for ent in line["mask"][1:]:       # mask[0] is the current_header_type
            mask_next_protocol <<= ent[0]
            mask_next_protocol += ent[1]
        mask = light_fi_nw_0_table_key_t(next_protocol_field=mask_next_protocol,
                                         current_header_type=line["mask"][0][1])
        # init value
        val = line["value"]
        next_header_format = header_format_t(flags=val[8][0], type=val[8][1])
        value = light_fi_nw_0_table_value_t(next_stage_size_width=val[0],
                                            next_stage_size_offset=val[1],
                                            next_stage_protocol_or_type_offset=val[2],
                                            use_additional_size=val[3],
                                            base_size=val[4],
                                            is_next_protocol_layer=val[5],
                                            is_protocol_layer=val[6],
                                            next_fi_macro_id=val[7],
                                            next_header_format=next_header_format,
                                            header_format=val[9])
        # insert to table
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        table.insert(FABRIC_CONTEXT, location, key, mask, value)
        table.insert(FABRIC_ELEMENT_CONTEXT, location, key, mask, value)
        location += 1


def config_light_fi_nw_1_table():

    data_light_fi_nw_1_table = [

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x8100]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_0],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x9100]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x88A8]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x9200]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x0800]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_IPV4],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x86DD]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                12,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_IPV6],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x8902]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                12,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_CFM],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x0000]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_IPV4],
                [8, 0x11],
                [8, 0x0]
            ],
            "mask": [
                [5, 0x1F],
                [8, 0xff],
                [8, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UDP],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        # Other (can be also for the case that the header is not ipv4. e.g. ipv6)
        {
            "key": [
                [5, PROTOCOL_TYPE_IPV4],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_IPV6],
                [8, 0x11],
                [8, 0x0]
            ],
            "mask": [
                [5, 0x1F],
                [8, 0xff],
                [8, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UDP],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        # Other (can be also for the case that the header is not ipv4. e.g. ipv6)
        {
            "key": [
                [5, PROTOCOL_TYPE_IPV6],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_2,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_UDP],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                           # next_stage_size_width               : 4;
                0,                           # next_stage_size_offset              : 6;
                0,                           # next_stage_protocol_or_type_offset  : 6;
                0,                           # use_additional_size                 : 1;
                0,                           # base_size                           : 7;
                1,                           # next_is_protocol_layer              : 1; # added in GB
                0,                           # is_protocol_layer                   : 1; # set last parsed as new layer
                LIGHT_FI_STAGE_NETWORK_2,    # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                            # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, 0],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                0,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1; # set last parsed as new layer
                LIGHT_FI_STAGE_NETWORK_2,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },
    ]

    assert(len(data_light_fi_nw_1_table) <= 16)

    # INIT light_fi_nw_1_table
    table = light_fi_nw_1_table
    location = 0
    current_header_type_width = 5
    for line in data_light_fi_nw_1_table:
        width = 0
        idx = 0
        # find the partitions of the key fields
        key_arr = line["key"]
        while width < current_header_type_width:
            width += key_arr[idx][0]
            idx += 1
        # init key
        key_current_header_type = 0
        for ent in key_arr[:idx]:                    # key_arr[:idx] is the the current_header_type
            key_current_header_type <<= ent[0]
            key_current_header_type += ent[1]

        key_next_protocol = 0
        for ent in key_arr[idx:]:                    # key_arr[:idx] is the the next_protocol_field
            key_next_protocol <<= ent[0]
            key_next_protocol += ent[1]

        key = light_fi_nw_1_table_key_t(next_protocol_field=key_next_protocol,
                                        current_header_type=key_current_header_type)
        # init mask
        mask_arr = line["mask"]
        mask_current_header_type = 0
        for ent in mask_arr[:idx]:                   # mask_arr[:idx] is the the current_header_type
            mask_current_header_type <<= ent[0]
            mask_current_header_type += ent[1]

        mask_next_protocol = 0
        for ent in mask_arr[idx:]:                   # mask_arr[:idx] is the the next_protocol_field
            mask_next_protocol <<= ent[0]
            mask_next_protocol += ent[1]

        mask = light_fi_nw_1_table_key_t(next_protocol_field=mask_next_protocol,
                                         current_header_type=mask_current_header_type)
        # init value
        val = line["value"]
        next_header_format = header_format_t(flags=val[8][0], type=val[8][1])
        value = light_fi_nw_1_table_value_t(next_stage_size_width=val[0],
                                            next_stage_size_offset=val[1],
                                            next_stage_protocol_or_type_offset=val[2],
                                            use_additional_size=val[3],
                                            base_size=val[4],
                                            is_next_protocol_layer=val[5],
                                            is_protocol_layer=val[6],
                                            next_fi_macro_id=val[7],
                                            next_header_format=next_header_format,
                                            header_format=val[9])
        # insert to table
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        table.insert(FABRIC_CONTEXT, location, key, mask, value)
        table.insert(FABRIC_ELEMENT_CONTEXT, location, key, mask, value)
        location += 1


def config_light_fi_nw_2_table():

    data_light_fi_nw_2_table = [

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x8100]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_0],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x9100]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x88A8]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x9200]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x0800]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_IPV4],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x86DD]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                12,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_IPV6],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x8902]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                12,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; // added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_CFM],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x0000]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_IPV4],
                [8, 0x11],
                [8, 0x0]
            ],
            "mask": [
                [5, 0x1F],
                [8, 0xff],
                [8, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UDP],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        # Other (can be also for the case that the header is not ipv4. e.g. ipv6)
        {
            "key": [
                [5, PROTOCOL_TYPE_IPV4],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0  # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_IPV6],
                [8, 0x11],
                [8, 0x0]
            ],
            "mask": [
                [5, 0x1F],
                [8, 0xff],
                [8, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UDP],  # next_header_format                  : 8;
                0  # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        # Other (can be also for the case that the header is not ipv4. e.g. ipv6)
        {
            "key": [
                [5, PROTOCOL_TYPE_IPV6],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_UDP],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                           # next_stage_size_width               : 4;
                0,                           # next_stage_size_offset              : 6;
                0,                           # next_stage_protocol_or_type_offset  : 6;
                0,                           # use_additional_size                 : 1;
                0,                           # base_size                           : 7;
                1,                           # next_is_protocol_layer              : 1; # added in GB
                0,                           # is_protocol_layer                   : 1; # set last parsed as new layer
                LIGHT_FI_STAGE_NETWORK_3,    # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                            # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, 0],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                0,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; // added in GB
                1,                         # is_protocol_layer                   : 1; # set last parsed as new layer
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },
    ]

    assert(len(data_light_fi_nw_2_table) <= 16)

    # INIT light_fi_nw_2_table
    table = light_fi_nw_2_table
    location = 0
    current_header_type_width = 5
    for line in data_light_fi_nw_2_table:
        width = 0
        idx = 0
        # find the partitions of the key fields
        key_arr = line["key"]
        while width < current_header_type_width:
            width += key_arr[idx][0]
            idx += 1
        # init key
        key_current_header_type = 0
        for ent in key_arr[:idx]:                    # key_arr[:idx] is the the current_header_type
            key_current_header_type <<= ent[0]
            key_current_header_type += ent[1]

        key_next_protocol = 0
        for ent in key_arr[idx:]:                    # key_arr[:idx] is the the next_protocol_field
            key_next_protocol <<= ent[0]
            key_next_protocol += ent[1]

        key = light_fi_nw_2_table_key_t(next_protocol_field=key_next_protocol,
                                        current_header_type=key_current_header_type)
        # init mask
        mask_arr = line["mask"]
        mask_current_header_type = 0
        for ent in mask_arr[:idx]:                   # mask_arr[:idx] is the the current_header_type
            mask_current_header_type <<= ent[0]
            mask_current_header_type += ent[1]

        mask_next_protocol = 0
        for ent in mask_arr[idx:]:                   # mask_arr[:idx] is the the next_protocol_field
            mask_next_protocol <<= ent[0]
            mask_next_protocol += ent[1]

        mask = light_fi_nw_2_table_key_t(next_protocol_field=mask_next_protocol,
                                         current_header_type=mask_current_header_type)
        # init value
        val = line["value"]
        next_header_format = header_format_t(flags=val[8][0], type=val[8][1])
        value = light_fi_nw_2_table_value_t(next_stage_size_width=val[0],
                                            next_stage_size_offset=val[1],
                                            next_stage_protocol_or_type_offset=val[2],
                                            use_additional_size=val[3],
                                            base_size=val[4],
                                            is_next_protocol_layer=val[5],
                                            is_protocol_layer=val[6],
                                            next_fi_macro_id=val[7],
                                            next_header_format=next_header_format,
                                            header_format=val[9])
        # insert to table
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        table.insert(FABRIC_CONTEXT, location, key, mask, value)
        table.insert(FABRIC_ELEMENT_CONTEXT, location, key, mask, value)
        location += 1


def config_light_fi_nw_3_table():

    data_light_fi_nw_3_table = [

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x8100]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_0],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x9100]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x88A8]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x9200]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_VLAN_1],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x0800]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                18,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_IPV4],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x86DD]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                12,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_IPV6],   # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x8902]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0xFFFF]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                12,                        # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; # added in GB
                0,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,  # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_CFM],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [3, PROTOCOL_TYPE_VLAN_PREFIX],
                [2, 0b00],
                [16, 0x0000]
            ],  # VLAN_0-3
            "mask": [
                [3, 0b111],
                [2, 0b00],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                4,                         # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_IPV4],
                [8, 0x11],
                [8, 0x0]
            ],
            "mask": [
                [5, 0x1F],
                [8, 0xff],
                [8, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UDP],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        # Other (can be also for the case that the header is not ipv4. e.g. ipv6)
        {
            "key": [
                [5, PROTOCOL_TYPE_IPV4],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_IPV6],
                [8, 0x11],
                [8, 0x0]
            ],
            "mask": [
                [5, 0x1F],
                [8, 0xff],
                [8, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UDP],    # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        # Other (can be also for the case that the header is not ipv4. e.g. ipv6)
        {
            "key": [
                [5, PROTOCOL_TYPE_IPV6],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                20,                        # base_size                           : 7;
                1,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, PROTOCOL_TYPE_UDP],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0x1f],
                [16, 0x0000]
            ],
            "value": [
                0,                          # next_stage_size_width               : 4;
                0,                          # next_stage_size_offset              : 6;
                0,                          # next_stage_protocol_or_type_offset  : 6;
                0,                          # use_additional_size                 : 1;
                0,                          # base_size                           : 7;
                1,                          # next_is_protocol_layer              : 1; # added in GB
                0,                          # is_protocol_layer                   : 1; # set last parsed as new layer
                LIGHT_FI_STAGE_NETWORK_3,   # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                           # header_format                       : 8; # no update of current-header-format for network
            ]
        },

        {
            "key": [
                [5, 0],
                [16, 0x0000]
            ],
            "mask": [
                [5, 0],
                [16, 0x0000]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                0,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1; # set last parsed as new layer
                LIGHT_FI_STAGE_NETWORK_3,     # next_fi_macro_id                    : 3; # configuring stage < network stages will finish parsing
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        },
    ]

    assert(len(data_light_fi_nw_3_table) <= 16)

    # INIT light_fi_nw_3_table
    table = light_fi_nw_3_table
    location = 0
    current_header_type_width = 5
    for line in data_light_fi_nw_3_table:
        width = 0
        idx = 0
        # find the partitions of the key fields
        key_arr = line["key"]
        while width < current_header_type_width:
            width += key_arr[idx][0]
            idx += 1
        # init key
        key_current_header_type = 0
        for ent in key_arr[:idx]:                    # key_arr[:idx] is the the current_header_type
            key_current_header_type <<= ent[0]
            key_current_header_type += ent[1]

        key_next_protocol = 0
        for ent in key_arr[idx:]:                    # key_arr[:idx] is the the next_protocol_field
            key_next_protocol <<= ent[0]
            key_next_protocol += ent[1]

        key = light_fi_nw_3_table_key_t(next_protocol_field=key_next_protocol,
                                        current_header_type=key_current_header_type)
        # init mask
        mask_arr = line["mask"]
        mask_current_header_type = 0
        for ent in mask_arr[:idx]:                   # mask_arr[:idx] is the the current_header_type
            mask_current_header_type <<= ent[0]
            mask_current_header_type += ent[1]

        mask_next_protocol = 0
        for ent in mask_arr[idx:]:                   # mask_arr[:idx] is the the next_protocol_field
            mask_next_protocol <<= ent[0]
            mask_next_protocol += ent[1]

        mask = light_fi_nw_3_table_key_t(next_protocol_field=mask_next_protocol,
                                         current_header_type=mask_current_header_type)
        # init value
        val = line["value"]
        next_header_format = header_format_t(flags=val[8][0], type=val[8][1])
        value = light_fi_nw_3_table_value_t(next_stage_size_width=val[0],
                                            next_stage_size_offset=val[1],
                                            next_stage_protocol_or_type_offset=val[2],
                                            use_additional_size=val[3],
                                            base_size=val[4],
                                            is_next_protocol_layer=val[5],
                                            is_protocol_layer=val[6],
                                            next_fi_macro_id=val[7],
                                            next_header_format=next_header_format,
                                            header_format=val[9])
        # insert to table
        table.insert(NETWORK_CONTEXT, location, key, mask, value)
        table.insert(FABRIC_CONTEXT, location, key, mask, value)
        table.insert(FABRIC_ELEMENT_CONTEXT, location, key, mask, value)
        location += 1
