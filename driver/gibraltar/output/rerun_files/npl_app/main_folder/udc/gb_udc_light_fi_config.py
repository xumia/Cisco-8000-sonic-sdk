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


def config_tables():
    config_light_fi_stages_cfg_table()
    config_light_fi_fabric_table()
    config_light_fi_npu_base_table()
    config_light_fi_npu_encap_table()
    config_light_fi_nw_0_table()
    config_light_fi_nw_1_table()
    config_light_fi_nw_2_table()
    config_light_fi_nw_3_table()


def config_light_fi_stages_cfg_table():

    udc_data_light_fi_stages_cfg_table = [
        {
            "key": 0,
            "value": [
                1,     # update_protocol_is_layer        : 1; # added in GB
                1,     # update_current_header_info      : 1; # on fabric/tm/npu header, pointer is to the current-header-type
                0,     # size_width                      : 4;
                0,     # size_offset                     : 6; # ptr to fwd-offset
                0,     # next_protocol_or_type_width     : 3;
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
                0,     # next_protocol_or_type_width     : 3;
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
                0,     # next_protocol_or_type_width     : 3;
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
                0,     # next_protocol_or_type_width     : 3;
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
    for line in udc_data_light_fi_stages_cfg_table:
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
        table.insert(UDC_CONTEXT, key, value)


def config_light_fi_fabric_table():

    udc_data_light_fi_fabric_table = [
        {
            "key": 0,
            "value": [
                0,                                                # use_additional_size                 : 1;
                0,                                                # base_size                           : 7;
                0,                                                # next_is_protocol_layer              : 1; added in GB
                0,                                                # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NPU_BASE,                          # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                FABRIC_TX_MACRO,                                  # npe_macro_id                        : 8;
                0,                                                # npe_macro_id_valid                  : 1;
                [0, 0],                                           # next_header_format                  : header_format_t; (8)
                [0, FABRIC_HEADER_TYPE_NPU_WITH_IVE]              # header_format                       : header_format_t; (8)
            ]
        }
    ]

    # INIT light_fi_fabric_table
    table = light_fi_fabric_table
    for line in udc_data_light_fi_fabric_table:
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
        table.insert(UDC_CONTEXT, key, value)


def config_light_fi_npu_base_table():

    udc_data_light_fi_npu_base_table = [
        # UDC doesn't care about the forwarding type. Size of selector is 0. Only one entry is needed.
        {
            "key": 0,
            "value": [
                0,                                         # use_additional_size                 : 1;
                40,                                        # base_size                           : 7;
                0,                                         # next_is_protocol_layer              : 1; # added in GB
                1,                                         # is_protocol_layer                   : 1;
                LIGHT_FI_STAGE_NETWORK_0,                  # next_fi_macro_id                    : light_fi_stage_type_e; (3)
                1,  # GB 0->1                               # npe_macro_id                        : 8;
                1,  # GB 0->1                               # npe_macro_id_valid                  : 1; # macro-id is chosen in npe-macro_id-resolution
                [0, UDC_FI_MACRO_ID_DB_ACCESS_COMMON_TRANS],  # next_header_format                  : header_format_t; (8)
                [0, 0b11111]                               # header_format                       : header_format_t; (8)
            ]
        }
    ]

    # INIT light_fi_npu_base_table
    table = light_fi_npu_base_table
    for line in udc_data_light_fi_npu_base_table:
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
        table.insert(UDC_CONTEXT, key, value)


def config_light_fi_npu_encap_table():

    udc_data_light_fi_npu_encap_table = [

        {
            "key": [
                [8, 0],
            ],
            "value": [
                0,                         # npu_encap_spare                     : 22; # GB 21'->22'
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                0,                         # next_stage_protocol_or_type_offset  : 6; # width for the field select is always 16b
            ]
        },
    ]

    table = light_fi_npu_encap_table
    for line in udc_data_light_fi_npu_encap_table:
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
        table.insert(UDC_CONTEXT, key, value)


def config_light_fi_nw_0_table():

    udc_data_light_fi_nw_0_table = [
        {
            "key": [
                [1, 0x0],
                [20, 0x0]
            ],
            "mask": [
                [1, 0x0],
                [20, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                1,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                0,                         # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        }
    ]

    # INIT light_fi_nw_0_table
    table = light_fi_nw_0_table
    location = 0
    for line in udc_data_light_fi_nw_0_table:
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
        table.insert(UDC_CONTEXT, location, key, mask, value)
        location += 1


def config_light_fi_nw_1_table():

    # dummy table for future inserts
    udc_data_light_fi_nw_1_table = [
        {
            "key": [
                [1, 0x0],
                [20, 0x0]
            ],
            "mask": [
                [1, 0x0],
                [20, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                1,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                0,                         # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        }
    ]

    # INIT light_fi_nw_1_table
    table = light_fi_nw_1_table
    location = 0
    for line in udc_data_light_fi_nw_1_table:
        # init key
        key_next_protocol = 0
        for ent in line["key"][1:]:        # key[0] is the current_header_type
            key_next_protocol <<= ent[0]
            key_next_protocol += ent[1]
        key = light_fi_nw_1_table_key_t(next_protocol_field=key_next_protocol,
                                        current_header_type=line["key"][0][1])
        # init mask
        mask_next_protocol = 0
        for ent in line["mask"][1:]:       # mask[0] is the current_header_type
            mask_next_protocol <<= ent[0]
            mask_next_protocol += ent[1]
        mask = light_fi_nw_1_table_key_t(next_protocol_field=mask_next_protocol,
                                         current_header_type=line["mask"][0][1])
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
        table.insert(UDC_CONTEXT, location, key, mask, value)
        location += 1


def config_light_fi_nw_2_table():

    # dummy table for future inserts
    udc_data_light_fi_nw_2_table = [
        {
            "key": [
                [1, 0x0],
                [20, 0x0]
            ],
            "mask": [
                [1, 0x0],
                [20, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                1,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                0,                         # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        }
    ]

    # INIT light_fi_nw_2_table
    table = light_fi_nw_2_table
    location = 0
    for line in udc_data_light_fi_nw_2_table:
        # init key
        key_next_protocol = 0
        for ent in line["key"][1:]:        # key[0] is the current_header_type
            key_next_protocol <<= ent[0]
            key_next_protocol += ent[1]
        key = light_fi_nw_2_table_key_t(next_protocol_field=key_next_protocol,
                                        current_header_type=line["key"][0][1])
        # init mask
        mask_next_protocol = 0
        for ent in line["mask"][1:]:       # mask[0] is the current_header_type
            mask_next_protocol <<= ent[0]
            mask_next_protocol += ent[1]
        mask = light_fi_nw_2_table_key_t(next_protocol_field=mask_next_protocol,
                                         current_header_type=line["mask"][0][1])
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
        table.insert(UDC_CONTEXT, location, key, mask, value)
        location += 1


def config_light_fi_nw_3_table():

    # dummy table for future inserts
    udc_data_light_fi_nw_3_table = [
        {
            "key": [
                [1, 0x0],
                [20, 0x0]
            ],
            "mask": [
                [1, 0x0],
                [20, 0x0]
            ],
            "value": [
                0,                         # next_stage_size_width               : 4;
                0,                         # next_stage_size_offset              : 6;
                4,                         # next_stage_protocol_or_type_offset  : 6;
                0,                         # use_additional_size                 : 1;
                1,                         # base_size                           : 7;
                0,                         # next_is_protocol_layer              : 1; # added in GB
                1,                         # is_protocol_layer                   : 1;
                0,                         # next_fi_macro_id                    : 3;
                [0, PROTOCOL_TYPE_UNKNOWN],  # next_header_format                  : 8;
                0                          # header_format                       : 8; # no update of current-header-format for network
            ]
        }
    ]

    # INIT light_fi_nw_3_table
    table = light_fi_nw_3_table
    location = 0
    for line in udc_data_light_fi_nw_3_table:
        # init key
        key_next_protocol = 0
        for ent in line["key"][1:]:        # key[0] is the current_header_type
            key_next_protocol <<= ent[0]
            key_next_protocol += ent[1]
        key = light_fi_nw_3_table_key_t(next_protocol_field=key_next_protocol,
                                        current_header_type=line["key"][0][1])
        # init mask
        mask_next_protocol = 0
        for ent in line["mask"][1:]:       # mask[0] is the current_header_type
            mask_next_protocol <<= ent[0]
            mask_next_protocol += ent[1]
        mask = light_fi_nw_3_table_key_t(next_protocol_field=mask_next_protocol,
                                         current_header_type=line["mask"][0][1])
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
        table.insert(UDC_CONTEXT, location, key, mask, value)
        location += 1
