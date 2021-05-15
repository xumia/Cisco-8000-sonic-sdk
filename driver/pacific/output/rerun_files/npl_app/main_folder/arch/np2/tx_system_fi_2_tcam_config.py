# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
    table_data_network = [
        # Eth tcam entries
        {
            "key": FWD_HEADER_TYPE_ETHERNET,
            "value": [
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_ETH},          # next_macro                             : 8;
                PROTOCOL_TYPE_ETHERNET,                       # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                0,                                           # header_size                            : 6;
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },

        # IPV4 tcam entries
        # Unicast
        {
            "key": FWD_HEADER_TYPE_IPV4,
            "value": [
                # next_macro                             : 8;
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_IPV4},
                PROTOCOL_TYPE_IPV4,                       # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                0,  # THIS IS TEMP!                                           # header_size                            : 6; #Was 40
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },


        # IPV4 tcam entries
        # Multicast
        {
            "key": FWD_HEADER_TYPE_IPV4_COLLAPSED_MC,
            "value": [
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_ETH},          # next_macro                             : 8;
                PROTOCOL_TYPE_ETHERNET,                       # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                0,  # THIS IS TEMP!                                           # header_size                            : 6; #Was 40
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },

        # IPV6 tcam entries
        {
            "key": FWD_HEADER_TYPE_IPV6,
            "value": [
                # next_macro                             : 8;
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_IPV6_FIRST},
                PROTOCOL_TYPE_IPV6,                       # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                0,                                            # header_size                            : 6;
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },

        # Multicast
        {
            "key": FWD_HEADER_TYPE_IPV6_COLLAPSED_MC,
            "value": [
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_ETH},          # next_macro                             : 8;
                PROTOCOL_TYPE_ETHERNET,                       # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                0,  # THIS IS TEMP!                                           # header_size                            : 6; #Was 40
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },

        # Redirect tcam entries
        {
            "key": FWD_HEADER_TYPE_REDIRECT,
            "value": [
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_ETH},          # next_macro                             : 8;
                PROTOCOL_TYPE_ETHERNET,                       # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                0,                                           # header_size                            : 6;
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },

        # Inject down tcam entries
        {
            "key": FWD_HEADER_TYPE_INJECT_DOWN,
            "value": [
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_ETH},          # next_macro                             : 8;
                PROTOCOL_TYPE_ETHERNET,                       # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                0,                                            # header_size                            : 6;
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },
        #
        {
            "key": FWD_HEADER_TYPE_MPLS_BOS_IPV4,
            "value": [
                # next_macro                             : 8;
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_IPV4},
                PROTOCOL_TYPE_IPV4,                           # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                4,                                            # header_size                            : 6;
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },

        {
            "key": FWD_HEADER_TYPE_MPLS_BOS_ETHERNET,
            "value": [
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_ETH},          # next_macro                             : 8;
                PROTOCOL_TYPE_ETHERNET,                       # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                4,                                            # header_size                            : 6;
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },

        {
            "key": FWD_HEADER_TYPE_MPLS_NO_BOS,
            "value": [
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_ETH},          # next_macro                             : 8;
                PROTOCOL_TYPE_ETHERNET,                       # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                4,                                            # header_size                            : 6;
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },

        {
            "key": FWD_HEADER_TYPE_MPLS_BOS_IPV6,
            "value": [
                # next_macro                             : 8;
                {"next_stage": PFI_STAGE_3, "macro_type": TX_PFI_3_MACRO_ID_IPV6_FIRST},
                PROTOCOL_TYPE_IPV6,                           # next_header_format.type                : 5;
                1,                                            # start_new_layer                        : 1;
                4,                                            # header_size                            : 6;
                1,                                            # start_new_header                       : 1;
                0b11111,                                      # header_format.type                     : 5;
                0,                                            # update_header_format_type              : 1;
                0,                                            # tcam_mask_hw_logic_calc_header_size    : 1;
                0,                                            # header_format.flags                    : 3
                1,                                            # tcam_mask_hw_header_size_in            : 1; #Get NPU header size from pre-logic
                0b000,                                        # tcam_mask_hw_logic_header_format.flags : 3;
                0,                                            # last_macro                             : 1;
                0,                                            # tcam_mask_hw_logic_last_macro          : 1;
                0,                                            # tcam_mask_hw_logic_advance_data        : 1;
                1                                             # advance_data                           : 1;

            ],
        },
    ]

    # INIT NETWORK FI
    table = txpp_fi_stage2_sram_table

    for line in table_data_network:
        # we can have entries commented out as string
        if not isinstance(line, dict):
            continue
        val = line["value"]
        key = txpp_fi_stage2_sram_table_key_t(header_data=line["key"])
        tcam_assoc_pl_mid = pfi_pl_mid_t(
            stage_id=val[0]["next_stage"],
            macro_type=val[0]["macro_type"])
        tcam_assoc_common_data = fi_core_table_assoc_common_data_t(
            next_header_format_type=val[1],
            start_new_layer=val[2],
            header_size=val[3],
            start_new_header=val[4],
            header_format_type=val[5],
            update_header_format_type=val[6],
            mask_hw_logic_calc_header_size=val[7],
            header_format_flags=val[8],
            mask_hw_logic_header_size_in=val[9],
            mask_hw_logic_header_format_flags=val[10],
            last_macro=val[11],
            mask_hw_logic_last_macro=val[12],
            mask_hw_logic_advance_data=val[13],
            advance_data=val[14]
        )

        value = txpp_fi_stage2_sram_table_value_t(
            pl_mid=tcam_assoc_pl_mid.get_value(),
            common_data=tcam_assoc_common_data)
        table.insert(NETWORK_CONTEXT, key, value)
