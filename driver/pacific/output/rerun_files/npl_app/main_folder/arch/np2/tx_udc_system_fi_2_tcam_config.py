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
    table_data_udc = [
        {
            "key": 0,
            "value": [
                {"next_stage": PFI_STAGE_3,
                 "macro_type": TX_PFI_3_MACRO_ID_UDC_DB_ACCESS_COMMON_TRANS},
                # next_macro                             : 8;
                0b00000,                                      # next_header_format.type                : 5;
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
    ]

    # INIT UDC FI
    table = txpp_fi_stage2_sram_table

    for line in table_data_udc:
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
        table.insert(UDC_CONTEXT, key, value)
