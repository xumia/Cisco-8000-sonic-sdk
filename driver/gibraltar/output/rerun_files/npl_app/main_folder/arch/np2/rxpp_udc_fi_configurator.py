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
    STAGE = PFI_STAGE_6 #RTC for rx
    IS_RXPP = True
    macro = {UDC_CONTEXT:[]}
    macro_config = {UDC_CONTEXT:[]}
    PACIFIC_COMPATIBLE_TM_HEADERS_MODE = True

#UDC_FI_MACRO_ID_CATCH_RESERVED = 6'h3e;

    # macro config
    COMMON_TRANS = FiMacro(
        contexts=[UDC_CONTEXT],
        macro_id=FI_MACRO_UDC_ID_DB_ACCESS_COMMON_TRANS,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=UDC_DB_ACCESS_COMMON_TRANS) \
        .AddMacro(macro_config)

    LOOKUPS_TRANS = FiMacro(
        contexts=[UDC_CONTEXT],
        macro_id=FI_MACRO_UDC_ID_DB_ACCESS_HEADER_ACCESS_TRANS,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=UDC_DB_ACCESS_HEADER_ACCESS_TRANS) \
        .AddMacro(macro_config)

    COMMON_TERM = FiMacro(
        contexts=[UDC_CONTEXT],
        macro_id=FI_MACRO_UDC_ID_DB_ACCESS_COMMON_TERM,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=UDC_DB_ACCESS_COMMON_TERM) \
        .AddMacro(macro_config)

    LOOKUPS_TERM = FiMacro(
        contexts=[UDC_CONTEXT],
        macro_id=FI_MACRO_UDC_ID_DB_ACCESS_HEADER_ACCESS_TERM,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=UDC_DB_ACCESS_HEADER_ACCESS_TERM) \
        .AddMacro(macro_config)

    COMMON_FWD = FiMacro(
        contexts=[UDC_CONTEXT],
        macro_id=FI_MACRO_UDC_ID_DB_ACCESS_COMMON_FWD,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=UDC_DB_ACCESS_COMMON_FWD) \
        .AddMacro(macro_config)

    LOOKUPS_FWD = FiMacro(
        contexts=[UDC_CONTEXT],
        macro_id=FI_MACRO_UDC_ID_DB_ACCESS_HEADER_ACCESS_FWD,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=UDC_DB_ACCESS_HEADER_ACCESS_FWD) \
        .AddMacro(macro_config)

    UNDEF = FiMacro([UDC_CONTEXT],
                    macro_id=FI_MACRO_ID_UNDEF,
                    start_new_header=True,
                    start_new_layer=False,
                    last_macro=True,
                    header_format_type=FI_MACRO_ID_UNDEF) \
        .AddMacro(macro_config)

    CATCH_RESERVED = FiMacro([UDC_CONTEXT],
                             macro_id=FI_MACRO_UDC_ID_CATCH_RESERVED,
                             start_new_header=True,
                             start_new_layer=False,
                             last_macro=True) \
        .AddMacro(macro_config)

    FiMacro.populate_macro_config(macro_config=macro_config, stage=STAGE, is_rxpp=IS_RXPP)

    # TCAM - no need to check the macro id - it's already does that
    COMMON_TRANS \
        .Conditions() \
        .Action(macro,
                header_format_type=UDC_DB_ACCESS_COMMON_TRANS,
                next_macro=LOOKUPS_TRANS,
                header_size=1)

    LOOKUPS_TRANS \
        .Conditions() \
        .Action(macro,
                header_format_type=UDC_DB_ACCESS_HEADER_ACCESS_TRANS,
                next_macro=COMMON_TERM,
                header_size=DB_ACCESS_TRANSMIT_MACRO_DESTS_HEADER_SIZE_IN_BYTES * 5)

    COMMON_TERM \
        .Conditions() \
        .Action(macro,
                header_format_type=UDC_DB_ACCESS_COMMON_TERM,
                next_macro=LOOKUPS_TERM,
                header_size=1)

    LOOKUPS_TERM \
        .Conditions() \
        .Action(macro,
                header_format_type=UDC_DB_ACCESS_HEADER_ACCESS_TERM,
                next_macro=COMMON_FWD,
                header_size=DB_ACCESS_TERM_MACRO_DESTS_HEADER_SIZE_IN_BYTES * 5)

    COMMON_FWD \
        .Conditions() \
        .Action(macro,
                header_format_type=UDC_DB_ACCESS_COMMON_FWD,
                next_macro=LOOKUPS_FWD,
                header_size=1)

    LOOKUPS_FWD \
        .Conditions() \
        .Action(macro,
                header_format_type=UDC_DB_ACCESS_HEADER_ACCESS_FWD,
                next_macro=UNDEF,
                header_size= DB_ACCESS_FWD_MACRO_DESTS_HEADER_SIZE_IN_BYTES * 5)

#not sure we need the last one
    UNDEF \
        .Conditions(mask_macro_id=0) \
        .Action(macro,
                header_format_type=FI_MACRO_ID_UNDEF,
                next_macro=UNDEF,
                header_size=1)

    CATCH_RESERVED \
        .Conditions(mask_macro_id=0) \
        .Action(macro,
                header_format_type=FI_MACRO_UDC_ID_CATCH_RESERVED,
                next_macro=UNDEF,
                header_size=1)

    FiMacro.populate_macro(macro=macro, stage=STAGE, is_rxpp=IS_RXPP)
