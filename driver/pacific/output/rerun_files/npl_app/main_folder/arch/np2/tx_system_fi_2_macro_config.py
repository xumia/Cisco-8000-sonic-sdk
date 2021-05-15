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
    table_data = [
        # Eth macro config table entry
        {
            "key": 0,  # TEMP - NPU HEADER
            "value": [
                FI_HARDWIRED_LOGIC_NONE,  # hw_logic_select         : fi_hardwired_logic_e (3);

                13,                         # tcam_key_inst0_offset   : 6;
                4,                          # tcam_key_inst0_width    : 5;
                0,                          # tcam_key_inst1_offset   : 5;
                0,                          # tcam_key_inst1_width    : 6;

                7,                          # size_width              : 3;
                12,                         # size_offset             : 4;
                0,                          # size_shift              : 4;
                7  # amir fix                 # size_mask               : 3;
            ]
        },

        {
            "key": FI_MACRO_ID_SYSTEM_PUNT_PHASE2,  # TEMP - NPU HEADER
            "value": [
                FI_HARDWIRED_LOGIC_NONE,  # hw_logic_select         : fi_hardwired_logic_e (3);

                13,                         # tcam_key_inst0_offset   : 6;
                4,                          # tcam_key_inst0_width    : 5;
                0,                          # tcam_key_inst1_offset   : 5;
                0,                          # tcam_key_inst1_width    : 6;

                7,                          # size_width              : 3;
                12,                         # size_offset             : 4;
                0,                          # size_shift              : 4;
                7  # amir fix                 # size_mask               : 3;
            ]
        }
    ]

    table = txpp_fi_stage2_macro_config_table
    for line in table_data:
        key = txpp_fi_stage2_macro_config_table_key_t(fi_macro=line["key"])
        val = line["value"]
        conf_data = fi_macro_config_data_t(hw_logic_select=val[0],
                                           tcam_key_inst0_offset=val[1],
                                           tcam_key_inst0_width=val[2],
                                           tcam_key_inst1_offset=val[3],
                                           tcam_key_inst1_width=val[4],
                                           size_width=val[5],
                                           size_offset=val[6],
                                           size_shift=val[7],
                                           size_mask=val[8])
        value = txpp_fi_stage2_macro_config_table_value_t(fi_macro_config_data=conf_data)
        table.insert(NETWORK_CONTEXT, key, value)
