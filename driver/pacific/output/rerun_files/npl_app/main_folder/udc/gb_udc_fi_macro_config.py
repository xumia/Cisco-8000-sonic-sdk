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
    udc_table_data = [
        {
            "key": UDC_FI_MACRO_ID_DB_ACCESS_COMMON_TERM,
            "value": [
                0,                          # tcam_key_inst1_offset   : 5;
                0,                          # tcam_key_inst1_width    : 6;
                0,                          # tcam_key_inst0_offset   : 6;
                0,                          # tcam_key_inst0_width    : 5;
                0,                          # alu_shift2              : 5;
                0,                          # alu_shift1              : 4;
                FI_HARDWIRED_LOGIC_NONE,    # hw_logic_select         : fi_hardwired_logic_e (3);
                0,                          # alu_mux2_select         : 1;
                0,                          # alu_mux1_select         : 1;
                0,                          # fs2_const               : 8;
                0,                          # fs1_const               : 8;
                0,                          # alu_fs2_valid_bits      : 4;
                0,                          # alu_fs2_offset          : 6;
                0,                          # alu_fs1_valid_bits      : 4;
                0                           # alu_fs1_offset          : 6;
            ]
        },

        {
            "key": UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TERM,
            "value": [
                0,                          # tcam_key_inst1_offset   : 5;
                0,                          # tcam_key_inst1_width    : 6;
                0,                          # tcam_key_inst0_offset   : 6;
                0,                          # tcam_key_inst0_width    : 5;
                0,                          # alu_shift2              : 5;
                0,                          # alu_shift1              : 4;
                FI_HARDWIRED_LOGIC_NONE,    # hw_logic_select         : fi_hardwired_logic_e (3);
                0,                          # alu_mux2_select         : 1;
                0,                          # alu_mux1_select         : 1;
                0,                          # fs2_const               : 8;
                0,                          # fs1_const               : 8;
                0,                          # alu_fs2_valid_bits      : 4;
                0,                          # alu_fs2_offset          : 6;
                0,                          # alu_fs1_valid_bits      : 4;
                0                           # alu_fs1_offset          : 6;
            ]
        },

        {
            "key": UDC_FI_MACRO_ID_DB_ACCESS_COMMON_FWD,
            "value": [
                0,                          # tcam_key_inst1_offset   : 5;
                0,                          # tcam_key_inst1_width    : 6;
                0,                          # tcam_key_inst0_offset   : 6;
                0,                          # tcam_key_inst0_width    : 5;
                0,                          # alu_shift2              : 5;
                0,                          # alu_shift1              : 4;
                FI_HARDWIRED_LOGIC_NONE,    # hw_logic_select         : fi_hardwired_logic_e (3);
                0,                          # alu_mux2_select         : 1;
                0,                          # alu_mux1_select         : 1;
                0,                          # fs2_const               : 8;
                0,                          # fs1_const               : 8;
                0,                          # alu_fs2_valid_bits      : 4;
                0,                          # alu_fs2_offset          : 6;
                0,                          # alu_fs1_valid_bits      : 4;
                0                           # alu_fs1_offset          : 6;
            ]
        },

        {
            "key": UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_FWD,
            "value": [
                0,                          # tcam_key_inst1_offset   : 5;
                0,                          # tcam_key_inst1_width    : 6;
                0,                          # tcam_key_inst0_offset   : 6;
                0,                          # tcam_key_inst0_width    : 5;
                0,                          # alu_shift2              : 5;
                0,                          # alu_shift1              : 4;
                FI_HARDWIRED_LOGIC_NONE,    # hw_logic_select         : fi_hardwired_logic_e (3);
                0,                          # alu_mux2_select         : 1;
                0,                          # alu_mux1_select         : 1;
                0,                          # fs2_const               : 8;
                0,                          # fs1_const               : 8;
                0,                          # alu_fs2_valid_bits      : 4;
                0,                          # alu_fs2_offset          : 6;
                0,                          # alu_fs1_valid_bits      : 4;
                0                           # alu_fs1_offset          : 6;
            ]
        },

        {
            "key": UDC_FI_MACRO_ID_DB_ACCESS_COMMON_TRANS,
            "value": [
                0,                          # tcam_key_inst1_offset   : 5;
                0,                          # tcam_key_inst1_width    : 6;
                0,                          # tcam_key_inst0_offset   : 6;
                0,                          # tcam_key_inst0_width    : 5;
                0,                          # alu_shift2              : 5;
                0,                          # alu_shift1              : 4;
                FI_HARDWIRED_LOGIC_NONE,    # hw_logic_select         : fi_hardwired_logic_e (3);
                0,                          # alu_mux2_select         : 1;
                0,                          # alu_mux1_select         : 1;
                0,                          # fs2_const               : 8;
                0,                          # fs1_const               : 8;
                0,                          # alu_fs2_valid_bits      : 4;
                0,                          # alu_fs2_offset          : 6;
                0,                          # alu_fs1_valid_bits      : 4;
                0                           # alu_fs1_offset          : 6;
            ]
        },

        {
            "key": UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TRANS,
            "value": [
                0,                          # tcam_key_inst1_offset   : 5;
                0,                          # tcam_key_inst1_width    : 6;
                0,                          # tcam_key_inst0_offset   : 6;
                0,                          # tcam_key_inst0_width    : 5;
                0,                          # alu_shift2              : 5;
                0,                          # alu_shift1              : 4;
                FI_HARDWIRED_LOGIC_NONE,    # hw_logic_select         : fi_hardwired_logic_e (3);
                0,                          # alu_mux2_select         : 1;
                0,                          # alu_mux1_select         : 1;
                0,                          # fs2_const               : 8;
                0,                          # fs1_const               : 8;
                0,                          # alu_fs2_valid_bits      : 4;
                0,                          # alu_fs2_offset          : 6;
                0,                          # alu_fs1_valid_bits      : 4;
                0                           # alu_fs1_offset          : 6;
            ]
        },

        {
            "key": UDC_FI_MACRO_ID_UNDEF,
            "value": [
                0,                          # tcam_key_inst1_offset   : 5;
                0,                          # tcam_key_inst1_width    : 6;
                0,                          # tcam_key_inst0_offset   : 6;
                0,                          # tcam_key_inst0_width    : 5;
                0,                          # alu_shift2              : 5;
                0,                          # alu_shift1              : 4;
                FI_HARDWIRED_LOGIC_NONE,    # hw_logic_select         : fi_hardwired_logic_e (3);
                0,                          # alu_mux2_select         : 1;
                0,                          # alu_mux1_select         : 1;
                0,                          # fs2_const               : 8;
                0,                          # fs1_const               : 8;
                0,                          # alu_fs2_valid_bits      : 4;
                0,                          # alu_fs2_offset          : 6;
                0,                          # alu_fs1_valid_bits      : 4;
                0                           # alu_fs1_offset          : 6;
            ]
        }
    ]

    table = fi_macro_config_table
    for line in udc_table_data:
        key = fi_macro_config_table_key_t(fi_macro=line["key"])
        val = line["value"]
        conf_data = fi_macro_config_data_t(tcam_key_inst1_offset=val[0],
                                           tcam_key_inst1_width=val[1],
                                           tcam_key_inst0_offset=val[2],
                                           tcam_key_inst0_width=val[3],
                                           alu_shift2=val[4],
                                           alu_shift1=val[5],
                                           hw_logic_select=val[6],
                                           alu_mux2_select=val[7],
                                           alu_mux1_select=val[8],
                                           fs2_const=val[9],
                                           fs1_const=val[10],
                                           alu_fs2_valid_bits=val[11],
                                           alu_fs2_offset=val[12],
                                           alu_fs1_valid_bits=val[13],
                                           alu_fs1_offset=val[14])
        value = fi_macro_config_table_value_t(fi_macro_config_data=conf_data)
        table.insert(UDC_CONTEXT, key, value)
