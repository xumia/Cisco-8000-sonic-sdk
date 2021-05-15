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

# Since we manually indented tables in this file, we don't want pep8 to mess with spaces
# This directive is read by leaba_format.py script
# pep8_extra_args = "--ignore=E2 --max-line-length 200"
# pep8_extra_args "--ignore=E2,E5,W2"
from config_tables_utils import *

ENE_END_MACRO = 0
DONT_CARE = 0
ALL_1 = (1 << 128) - 1


def config_tables():
    config_fabric_npuh_size_calculation_static_table()
    config_fabric_header_types_static_table()
    config_fabric_and_tm_header_size_static_table()
    config_fabric_term_error_checker_static_table()
    config_fabric_transmit_error_checker_static_table()
    config_erpp_fabric_counters_table()


def config_fabric_npuh_size_calculation_static_table():
    table = fabric_npuh_size_calculation_static_table
    table_data = [
        # +---------------------+------------------------------+--------------+-----------------------------+---------------+----------------+----------------   +-------------+
        # | tx_cud[23:20]       | encapsulation_type           | is_inject_up | fwd_header_type             | is_inject_pkt |is_network_pkt  |ene_with_soft_npuh |  npuh_size  |
        # +---------------------+------------------------------+--------------+-----------------------------+---------------+----------------+-------------------+-------------+
        # |  4'b1101            |   DONT_CARE                  | DONT_CARE    | DONT_CARE                   | 0             |0               |1                  | 40          |
        # | //IBM Unicast       |                              |              |                             |               |                |                   |             |
        # +---------------------+------------------------------+--------------+-----------------------------+---------------+----------------+-------------------+-------------+
        # |  4'b100x            |   DONT_CARE                  | DONT_CARE    | DONT_CARE                   | 0             |0               |1                  | 40          |
        # | //IBM MC GRP ID     |                              |              |                             |               |                |                   |             |
        # +---------------------+------------------------------+--------------+-----------------------------+---------------+----------------+-------------------+-------------+
        # |  DONT_CARE          | NPU_ENCAP_MIRROR_OR_REDIRECT | DONT_CARE    | FWD_HEADER_TYPE_REDIRECT    | 0             |0               |1                  | 40          |
        # +---------------------+------------------------------+--------------+-----------------------------+---------------+----------------+-------------------+-------------+
        # |  DONT_CARE          |   DONT_CARE                  | 1            | DONT_CARE                   | 1             |1               |1                  | 40          |
        # +---------------------+------------------------------+--------------+-----------------------------+---------------+----------------+-------------------+-------------+
        # |  DONT_CARE          |   DONT_CARE                  | DONT_CARE    | FWD_HEADER_TYPE_INJECT_DOWN | 1             |1               |1                  | 40          |
        # +---------------------+------------------------------+--------------+-----------------------------+---------------+----------------+-------------------+-------------+
        # | DEFAULT   (Network) |                              |              |                             | 0             |1               |0                  | 32          |
        # +---------------------+------------------------------+--------------+-----------------------------+---------------+----------------+-------------------+-------------+
        #=========================================================================================================================
        {"cud_type": (0b1101,ALL_1),  "encap_type": (0,DONT_CARE),                        "is_inject_up": (0,DONT_CARE),
         "fwd_header_type": (0,DONT_CARE),                       "is_inject_pkt": 0, "is_network_pkt": 0, "ene_with_soft_npuh": 1, "npuh_size": 40},
        {"cud_type": (0b1000,0b1110), "encap_type": (0,DONT_CARE),                        "is_inject_up": (0,DONT_CARE),
         "fwd_header_type": (0,DONT_CARE),                       "is_inject_pkt": 0, "is_network_pkt": 0, "ene_with_soft_npuh": 1, "npuh_size": 40},
        {"cud_type": (0,DONT_CARE),   "encap_type": (NPU_ENCAP_MIRROR_OR_REDIRECT,ALL_1), "is_inject_up": (0,DONT_CARE),
         "fwd_header_type": (FWD_HEADER_TYPE_REDIRECT,ALL_1),    "is_inject_pkt": 0, "is_network_pkt": 0, "ene_with_soft_npuh": 1, "npuh_size": 40},
        {"cud_type": (0,DONT_CARE),   "encap_type": (0,DONT_CARE),                        "is_inject_up": (1,ALL_1),
         "fwd_header_type": (0,DONT_CARE),                       "is_inject_pkt": 1, "is_network_pkt": 1, "ene_with_soft_npuh": 1, "npuh_size": 40},
        {"cud_type": (0,DONT_CARE),   "encap_type": (0,DONT_CARE),                        "is_inject_up": (0,DONT_CARE),
         "fwd_header_type": (FWD_HEADER_TYPE_INJECT_DOWN,ALL_1), "is_inject_pkt": 1, "is_network_pkt": 1, "ene_with_soft_npuh": 1, "npuh_size": 40}
        #========================================================================================================================
    ]

    location = 0
    for line in table_data:
        key = fabric_npuh_size_calculation_static_table_key_t(device_tx_cud_msb_4bits=line["cud_type"][0],
                                                              packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type=line["encap_type"][0],
                                                              packet_tx_npu_header_is_inject_up=line["is_inject_up"][0],
                                                              packet_tx_npu_header_fwd_header_type=line["fwd_header_type"][0])
        mask = fabric_npuh_size_calculation_static_table_key_t(device_tx_cud_msb_4bits=line["cud_type"][1],
                                                               packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type=line["encap_type"][1],
                                                               packet_tx_npu_header_is_inject_up=line["is_inject_up"][1],
                                                               packet_tx_npu_header_fwd_header_type=line["fwd_header_type"][1])
        value = fabric_npuh_size_calculation_static_table_value_t(is_inject_pkt=line["is_inject_pkt"], is_network_pkt=line["is_network_pkt"],
                                                                  ene_with_soft_npuh=line["ene_with_soft_npuh"], npuh_size=line["npuh_size"])
        table.insert(FABRIC_CONTEXT, location, key, mask, value)
        location += 1


# A static table to verify fabric header type.
# if miss, it means the fabric header type is illegal
def config_fabric_header_types_static_table():
    table = fabric_header_types_static_table
    table_config = DirectTableConfig("fabric_header_types_static_table")
    table_data = [
        {"key": ["fabric_header_type"],                         "value": ["fabric_header_type_ok"]},
        {"key": [FABRIC_HEADER_TYPE_NPU_WITH_IVE],              "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_NPU_NO_IVE],                "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET],     "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS],    "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET],        "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS],       "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_FLB],                       "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_PEER_DELAY_REQUEST],        "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_PEER_DELAY_REPLY],          "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_FABRIC_TIME_SYNC],          "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_CREDIT_SCHEDULER_CONTROL],  "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_FABRIC_ROUTING_PROTOCOL],   "value": [1]},
        {"key": [FABRIC_HEADER_TYPE_SOURCE_ROUTED],             "value": [1]},
    ]
    table_config.create_table(table_data, FABRIC_CONTEXT, init_table=True)


PACIFIC_COMPATIBLE_TM_HEADERS_MODE = True

if PACIFIC_COMPATIBLE_TM_HEADERS_MODE:
    uc_or_muu_plb_tm_header_size = 4
else:  # GB once we diverge, this table would have different PC,GB implementation
    uc_or_muu_plb_tm_header_size = 5


def config_fabric_and_tm_header_size_static_table():
    table = fabric_and_tm_header_size_static_table
    table_config = TcamTableConfig("fabric_and_tm_header_size_static_table")
    table_data = [
        {"key": ["fabric_header_type"                       , "tm_header_type"               , "npuh_size"], "value": ["fabric_tm_npu_headers_size"]},
        {"key": [FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS, TM_HEADER_TYPE_UNICAST_OR_MUU_PLB,     32     ], "value": [7 + uc_or_muu_plb_tm_header_size + 32]},
        {"key": [FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS, TM_HEADER_TYPE_UNICAST_OR_MUU_PLB,     40     ], "value": [7 + uc_or_muu_plb_tm_header_size + 40]},
        {"key": [FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS   , TM_HEADER_TYPE_UNICAST_OR_MUU_PLB,     32     ], "value": [13 + uc_or_muu_plb_tm_header_size + 32]},
        {"key": [FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS   , TM_HEADER_TYPE_UNICAST_OR_MUU_PLB,     40     ], "value": [13 + uc_or_muu_plb_tm_header_size + 40]}
    ]
    table_config.create_table(table_data, FABRIC_CONTEXT)

# Fabric error cases identify at Termination stage, if so return a unique error_code per error case


def config_fabric_term_error_checker_static_table():
    table = fabric_term_error_checker_static_table
    table_config = TcamTableConfig("fabric_term_error_checker_static_table")
    # mismatch_indications = mismatch_issu|mismatch_pkt_size|is_single_fragment
    IS_NOT_SINGLE_FRAGMENT = 0b000
    PKT_SIZE_MISMATCH      = 0b010
    ISSU_MISMATCH          = 0b100
    table_data = [
        {"key": ["is_keepalive", "fabric_header_type_ok", "fabric_init_cfg_table_hit",          "mismatch_indications"                ], "value": ["pd_fabric_error_event_error_code"]},
        # non-network Rxpp got non-keepalive packet with illegal fabric header
        {"key": [   False      ,                 False   ,           DONT_CARE        ,                 DONT_CARE                      ], "value": [                   1           ]},
        # non-network Rxpp got keepalive packet with non single fragment
        {"key": [   True       ,            DONT_CARE    ,           DONT_CARE        ,  Key(IS_NOT_SINGLE_FRAGMENT, mask=0b001)       ], "value": [                   2           ]},
        # non-network Rxpp got packed-packet with illegal first packet size
        {"key": [   DONT_CARE  ,            DONT_CARE    ,           DONT_CARE        ,  Key(PKT_SIZE_MISMATCH, mask=PKT_SIZE_MISMATCH)], "value": [                   3           ]},
        # non-network Rxpp illegal issu bit
        {"key": [   DONT_CARE  ,            DONT_CARE    ,           True             ,  Key(ISSU_MISMATCH, mask=ISSU_MISMATCH)        ], "value": [                   4           ]},
    ]
    table_config.create_table(table_data, FABRIC_CONTEXT)


# Fabric error cases identify at Transmit stage, if so return a unique error_code per error case
def config_fabric_transmit_error_checker_static_table():
    table = fabric_transmit_error_checker_static_table
    table_config = TcamTableConfig("fabric_transmit_error_checker_static_table")
    table_data = [
        {"key": ["npu_header"            , "fabric_init_cfg_table_hit", "expected_issu", "pkt_issu"], "value": ["fabric_error_event_error_code"]},
        # ingress Txpp got packet with first header which is not NPU header (npu header =0/1)
        {"key": [Key(0b0010, mask=0b0010),       DONT_CARE            ,     DONT_CARE  ,  DONT_CARE], "value": [                   1           ]},
        {"key": [Key(0b0100, mask=0b0100),       DONT_CARE            ,     DONT_CARE  ,  DONT_CARE], "value": [                   1           ]},
        {"key": [Key(0b1000, mask=0b1000),       DONT_CARE            ,     DONT_CARE  ,  DONT_CARE], "value": [                   1           ]},
        # non-network Txpp illegal issu bit
        {"key": [     DONT_CARE          ,         True               ,       1        ,   0       ], "value": [                   2           ]},
        {"key": [     DONT_CARE          ,         True               ,       0        ,   1       ], "value": [                   2           ]},
    ]
    table_config.create_table(table_data, FABRIC_CONTEXT, init_table=True)


# initialize the debug counters table to zeros at init stage
def config_erpp_fabric_counters_table():
    table = erpp_fabric_counters_table
    table_config = TcamTableConfig("erpp_fabric_counters_table")
    table_data = [
        {"key": ["dest_device", "dest_slice", "dest_oq"], "value":["debug_counter_valid", "debug_counter_ptr"]},
    ]
    table_config.create_table(table_data, FABRIC_CONTEXT, init_table=True)
