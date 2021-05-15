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
        # UDC headers part
        # For DB access application the order is transmit, termination and forwarding
        # Nop Application is expected to reach the catch all entry
        {
            "key": [
                UDC_FI_MACRO_ID_DB_ACCESS_COMMON_TRANS,        # macro_id
                [34, 0],                                       # padding
            ],
            "mask": [
                [6, 0x3f],  # macro_id
                [34, 0]     # padding
            ],
            "value": [
                UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TRANS,  # next_macro                             : 6;
                0,                                         # last_macro                             : 1;
                1,                                         # start_new_header                       : 1;
                0,                                         # start_new_layer                        : 1;
                1,                                         # advance_data                           : 1;
                0,                                         # tcam_mask_alu_header_format.flags      : 3;
                0,                                         # tcam_mask_alu_header_format.type       : 5;
                0,                                         # tcam_mask_alu_header_size              : 6;
                0,                                         # tcam_mask_hw_logic_advance_data        : 1;
                0,                                         # tcam_mask_hw_logic_last_macro          : 1;
                0b000,                                     # tcam_mask_hw_logic_header_format.flags : 3;
                0b00000,                                   # tcam_mask_hw_logic_header_format.type  : 5;
                0,                                         # tcam_mask_hw_logic_header_size         : 6;
                0,                                         # header_format.flags                    : 3;
                UDC_DB_ACCESS_COMMON_TRANS,                # header_format.type                     : 5;
                1                                          # header_size                            : 6; # in_bytes
            ],
        },

        {
            "key": [
                UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TRANS,        # macro_id
                [34, 0],                                       # padding
            ],
            "mask": [
                [6, 0x3f],  # macro_id
                [34, 0]     # padding
            ],
            "value": [
                UDC_DB_ACCESS_COMMON_TERM,                 # next_macro                             : 6;
                0,                                         # last_macro                             : 1;
                1,                                         # start_new_header                       : 1;
                1,                                         # start_new_layer                        : 1;
                1,                                         # advance_data                           : 1;
                0,                                         # tcam_mask_alu_header_format.flags      : 3;
                0,                                         # tcam_mask_alu_header_format.type       : 5;
                0,                                         # tcam_mask_alu_header_size              : 6;
                0,                                         # tcam_mask_hw_logic_advance_data        : 1;
                0,                                         # tcam_mask_hw_logic_last_macro          : 1;
                0b000,                                     # tcam_mask_hw_logic_header_format.flags : 3;
                0b00000,                                   # tcam_mask_hw_logic_header_format.type  : 5;
                0,                                         # tcam_mask_hw_logic_header_size         : 6;
                0,                                         # header_format.flags                    : 3;
                UDC_DB_ACCESS_HEADER_ACCESS_TRANS,         # header_format.type                     : 5;
                DB_ACCESS_TRANSMIT_MACRO_DESTS_HEADER_SIZE_IN_BYTES * 5  # header_size                            : 6; # in_bytes
            ],
        },

        {
            "key": [
                UDC_DB_ACCESS_COMMON_TERM,                     # macro_id
                [34, 0]                                        # padding
            ],
            "mask": [
                [6, 0x3f],  # macro_id
                [34, 0]     # padding
            ],
            "value": [
                UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TERM,  # next_macro                             : 6;
                0,                                         # last_macro                             : 1;
                1,                                         # start_new_header                       : 1;
                0,                                         # start_new_layer                        : 1;
                1,                                         # advance_data                           : 1;
                0,                                         # tcam_mask_alu_header_format.flags      : 3;
                0,                                         # tcam_mask_alu_header_format.type       : 5;
                0,                                         # tcam_mask_alu_header_size              : 6;
                0,                                         # tcam_mask_hw_logic_advance_data        : 1;
                0,                                         # tcam_mask_hw_logic_last_macro          : 1;
                0b000,                                     # tcam_mask_hw_logic_header_format.flags : 3;
                0b00000,                                   # tcam_mask_hw_logic_header_format.type  : 5;
                0,                                         # tcam_mask_hw_logic_header_size         : 6;
                0,                                         # header_format.flags                    : 3;
                UDC_DB_ACCESS_COMMON_TERM,                 # header_format.type                     : 5;
                1                                          # header_size                            : 6; # in_bytes
            ],
        },

        {
            "key": [
                UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TERM,        # macro_id
                [34, 0]                                        # padding
            ],
            "mask": [
                [6, 0x3f],  # macro_id
                [34, 0]     # padding
            ],
            "value": [
                UDC_DB_ACCESS_COMMON_FWD,                  # next_macro                             : 6;
                0,                                         # last_macro                             : 1;
                1,                                         # start_new_header                       : 1;
                1,                                         # start_new_layer                        : 1;
                1,                                         # advance_data                           : 1;
                0,                                         # tcam_mask_alu_header_format.flags      : 3;
                0,                                         # tcam_mask_alu_header_format.type       : 5;
                0,                                         # tcam_mask_alu_header_size              : 6;
                0,                                         # tcam_mask_hw_logic_advance_data        : 1;
                0,                                         # tcam_mask_hw_logic_last_macro          : 1;
                0b000,                                     # tcam_mask_hw_logic_header_format.flags : 3;
                0b00000,                                   # tcam_mask_hw_logic_header_format.type  : 5;
                0,                                         # tcam_mask_hw_logic_header_size         : 6;
                0,                                         # header_format.flags                    : 3;
                UDC_DB_ACCESS_HEADER_ACCESS_TERM,          # header_format.type                     : 5;
                DB_ACCESS_TERM_MACRO_DESTS_HEADER_SIZE_IN_BYTES * 5  # header_size                            : 6; # in_bytes
            ],
        },

        {
            "key": [
                UDC_DB_ACCESS_COMMON_FWD,                      # macro_id
                [34, 0]                                        # padding
            ],
            "mask": [
                [6, 0x3f],  # macro_id
                [34, 0]     # padding
            ],
            "value": [
                UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_FWD,  # next_macro                             : 6;
                0,                                         # last_macro                             : 1;
                1,                                         # start_new_header                       : 1;
                0,                                         # start_new_layer                        : 1;
                1,                                         # advance_data                           : 1;
                0,                                         # tcam_mask_alu_header_format.flags      : 3;
                0,                                         # tcam_mask_alu_header_format.type       : 5;
                0,                                         # tcam_mask_alu_header_size              : 6;
                0,                                         # tcam_mask_hw_logic_advance_data        : 1;
                0,                                         # tcam_mask_hw_logic_last_macro          : 1;
                0b000,                                     # tcam_mask_hw_logic_header_format.flags : 3;
                0b00000,                                   # tcam_mask_hw_logic_header_format.type  : 5;
                0,                                         # tcam_mask_hw_logic_header_size         : 6;
                0,                                         # header_format.flags                    : 3;
                UDC_DB_ACCESS_COMMON_FWD,                  # header_format.type                     : 5;
                1                                          # header_size                            : 6; # in_bytes
            ],
        },

        {
            "key": [
                UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_FWD,   # macro_id
                [34, 0]                                        # padding
            ],
            "mask": [
                [6, 0x3f],  # macro_id
                [34, 0]     # padding
            ],
            "value": [
                UDC_DB_ACCESS_COMMON_FWD,                  # next_macro                             : 6;
                1,                                         # last_macro                             : 1;
                1,                                         # start_new_header                       : 1;
                0,                                         # start_new_layer                        : 1;
                1,                                         # advance_data                           : 1;
                0,                                         # tcam_mask_alu_header_format.flags      : 3;
                0,                                         # tcam_mask_alu_header_format.type       : 5;
                0,                                         # tcam_mask_alu_header_size              : 6;
                0,                                         # tcam_mask_hw_logic_advance_data        : 1;
                0,                                         # tcam_mask_hw_logic_last_macro          : 1;
                0b000,                                     # tcam_mask_hw_logic_header_format.flags : 3;
                0b00000,                                   # tcam_mask_hw_logic_header_format.type  : 5;
                0,                                         # tcam_mask_hw_logic_header_size         : 6;
                0,                                         # header_format.flags                    : 3;
                UDC_DB_ACCESS_HEADER_ACCESS_FWD,                 # header_format.type                     : 5;
                DB_ACCESS_FWD_MACRO_DESTS_HEADER_SIZE_IN_BYTES * 5  # header_size                            : 6; # in_bytes
            ],
        },

        # Default entry - catches all keys
        {
            "key": [
                FI_MACRO_ID_UNDEF,                             # macro_id
                [34, 0]                                        # padding
            ],
            "mask": [
                [6, 0x0],  # macro_id
                [34, 0]     # padding
            ],
            "value": [
                FI_MACRO_ID_UNDEF,                         # next_macro                             : 6;
                1,                                         # last_macro                             : 1;
                1,                                         # start_new_header                       : 1;
                0,                                         # start_new_layer                        : 1;
                1,                                         # advance_data                           : 1;
                0,                                         # tcam_mask_alu_header_format.flags      : 3;
                0,                                         # tcam_mask_alu_header_format.type       : 5;
                0,                                         # tcam_mask_alu_header_size              : 6;
                0,                                         # tcam_mask_hw_logic_advance_data        : 1;
                0,                                         # tcam_mask_hw_logic_last_macro          : 1;
                0b000,                                     # tcam_mask_hw_logic_header_format.flags : 3;
                0b00000,                                   # tcam_mask_hw_logic_header_format.type  : 5;
                0,                                         # tcam_mask_hw_logic_header_size         : 6;
                0,                                         # header_format.flags                    : 3;
                0b11111,                                   # header_format.type                     : 5;
                1                                          # header_size                            : 6; # in_bytes
            ],
        }
    ]

    # INIT UDC FI
    table = fi_core_tcam_table

    location = 0
    for line in table_data_udc:
        # we can have entries commented out as string
        if not isinstance(line, dict):
            continue
        val = line["value"]
        mask_alu_header_format = header_format_t(flags=val[5], type=val[6])
        hw_logic_header_format = header_format_t(flags=val[10], type=val[11])
        header_format = header_format_t(flags=val[13], type=val[14])
        tcam_assoc_data = fi_core_tcam_assoc_data_t(next_macro=val[0],
                                                    last_macro=val[1],
                                                    start_new_header=val[2],
                                                    start_new_layer=val[3],
                                                    advance_data=val[4],
                                                    tcam_mask_alu_header_format=mask_alu_header_format,
                                                    tcam_mask_alu_header_size=val[7],
                                                    tcam_mask_hw_logic_advance_data=val[8],
                                                    tcam_mask_hw_logic_last_macro=val[9],
                                                    tcam_mask_hw_logic_header_format=hw_logic_header_format,
                                                    tcam_mask_hw_logic_header_size=val[12],
                                                    header_format=header_format,
                                                    header_size=val[15]
                                                    )
        value = fi_core_tcam_table_value_t(fi_core_tcam_assoc_data=tcam_assoc_data)
        key_header_data = 0
        # key[0] is the macro id
        for ent in line["key"][1:]:
            key_header_data <<= ent[0]
            key_header_data += ent[1]
        mask_header_data = 0
        # mask[0] is the macro id mask
        for ent in line["mask"][1:]:
            mask_header_data <<= ent[0]
            mask_header_data += ent[1]
        key = fi_core_tcam_table_key_t(header_data=key_header_data, fi_macro=line["key"][0])
        mask = fi_core_tcam_table_key_t(header_data=mask_header_data, fi_macro=line["mask"][0][1])
        table.insert(UDC_CONTEXT, location, key, mask, value)
        location += 1
