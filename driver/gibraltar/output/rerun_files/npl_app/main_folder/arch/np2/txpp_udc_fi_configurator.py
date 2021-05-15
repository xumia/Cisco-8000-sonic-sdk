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


#UDC_FI_MACRO_ID_CATCH_RESERVED = 6'h3e;

    ########################
    # STAGE 3 macro config #
    ########################

    STAGE = PFI_STAGE_3
    macro_config = {UDC_CONTEXT:[]}

    # macro config
    TX_PFI_3_COMMON_TRANS = FiMacro(
        contexts=[UDC_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_3_MACRO_ID_UDC_DB_ACCESS_COMMON_TRANS,
        start_new_header=True,
        start_new_layer=True,
        header_format_type=UDC_DB_ACCESS_COMMON_TRANS) \
        .AddMacro(macro_config)

    FiMacro.populate_macro_config(macro_config=macro_config, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 4 macro config #
    ########################

    STAGE = PFI_STAGE_4
    macro_config = {UDC_CONTEXT:[]}

    # macro config
    TX_PFI_4_LOOKUPS_TRANS = FiMacro(
        contexts=[UDC_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_4_MACRO_ID_UDC_DB_ACCESS_HEADER_ACCESS_TRANS,
        start_new_header=True,
        start_new_layer=False,
        header_format_type=UDC_DB_ACCESS_HEADER_ACCESS_TRANS) \
        .AddMacro(macro_config)

    FiMacro.populate_macro_config(macro_config=macro_config, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 5 macro config #
    ########################

    STAGE = PFI_STAGE_5
    macro_config = {UDC_CONTEXT:[]}

    # macro config
    TX_PFI_5_UNDEF = FiMacro(
        contexts=[UDC_CONTEXT],
        stage=STAGE,
        macro_id=TX_PFI_5_MACRO_ID_UNDEF,
        start_new_header=True,
        start_new_layer=False,
        last_macro=True) \

    FiMacro.populate_macro_config(macro_config=macro_config, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 6 macro config #
    ########################

    ########################
    # STAGE 3 tcam config  #
    ########################

    # FI config - tcam entries
    STAGE = PFI_STAGE_3
    macro = {UDC_CONTEXT:[]}

    TX_PFI_3_COMMON_TRANS \
        .Conditions() \
        .Action(macro,
                #header_format_type=UDC_DB_ACCESS_COMMON_TRANS,
                next_macro=TX_PFI_4_LOOKUPS_TRANS,
                header_size=1)

    FiMacro.populate_macro(macro=macro, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 4 tcam config  #
    ########################

    # FI config - tcam entries
    STAGE = PFI_STAGE_4
    macro = {UDC_CONTEXT:[]}

    TX_PFI_4_LOOKUPS_TRANS \
        .Conditions() \
        .Action(macro,
                #header_format_type=UDC_DB_ACCESS_HEADER_ACCESS_TRANS,
                next_macro=TX_PFI_5_UNDEF,
                header_size=DB_ACCESS_TRANSMIT_MACRO_DESTS_HEADER_SIZE_IN_BYTES * 5)

    FiMacro.populate_macro(macro=macro, stage=STAGE, is_rxpp=IS_RXPP)

    ########################
    # STAGE 5 tcam config  #
    ########################
