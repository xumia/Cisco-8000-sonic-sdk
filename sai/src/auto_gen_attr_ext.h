// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef __SAI_GEN_ATTR_EXT_H__
#define __SAI_GEN_ATTR_EXT_H__

#include <../../build/src/auto_gen_attr.h>
extern "C" {
#include "sai_attr_ext.h"
}

DEFINE_attr_templ(sai_vlan_member_attr_t, u16, sai_vlan_member_attr_t_u16);

using SAI_VLAN_MEMBER_ATTR_EXT_EGR_DOT1Q_TAG_VLAN_VAL
    = sai_vlan_member_attr_t_u16<((sai_vlan_member_attr_t)SAI_VLAN_MEMBER_ATTR_EXT_EGR_DOT1Q_TAG_VLAN), sai_uint16_t>;

using SAI_ROUTER_INTERFACE_ATTR_EXT_EGR_DOT1Q_TAG_VLAN_VAL
    = sai_router_interface_attr_t_u16<((sai_router_interface_attr_t)SAI_ROUTER_INTERFACE_ATTR_EXT_EGR_DOT1Q_TAG_VLAN),
                                      sai_uint16_t>;

DEFINE_attr_templ(sai_port_serdes_attr_t, s32list, sai_port_serdes_attr_t_s32list);

using SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_PRE1_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_PRE1), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_PRE2_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_PRE2), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_PRE3_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_PRE3), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_MAIN_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_MAIN), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_POST_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_POST), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_POST2_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_POST2), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_POST3_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_POST3), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING), sai_s32_list_t>;
using SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS_VAL
    = sai_port_serdes_attr_t_s32list<((sai_port_serdes_attr_t)SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS), sai_s32_list_t>;

DEFINE_attr_templ(sai_switch_attr_t, s32list, sai_switch_attr_ext_t_s32list);
using SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST_VAL
    = sai_switch_attr_ext_t_s32list<(sai_switch_attr_t)SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, sai_s32_list_t>;

DEFINE_attr_templ(sai_switch_attr_t, u16, sai_switch_attr_ext_t_u16);
using SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE_VAL
    = sai_switch_attr_ext_t_u16<(sai_switch_attr_t)SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE, sai_uint16_t>;

DEFINE_attr_templ(sai_port_attr_t, u16, sai_port_attr_ext_t_u16);
using SAI_PORT_ATTR_EXT_SYSTEM_PORT_ID_VAL
    = sai_port_attr_ext_t_u16<(sai_port_attr_t)SAI_PORT_ATTR_EXT_SYSTEM_PORT_ID, sai_uint16_t>;

DEFINE_attr_templ(sai_lag_attr_t, booldata, sai_lag_attr_ext_t_booldata);
using SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL_VAL
    = sai_lag_attr_ext_t_booldata<(sai_lag_attr_t)SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL, bool>;

//////////////////////////////////////////////////
// TODO: This is the sai_switch_event_type_t and SAI_TAM_EVENT_ATTR_TYPE defination copied from PR1119.
//       We need to remove this once the pull requet is merged to SAI
//       https://github.com/opencomputeproject/SAI/pull/1119
//
DEFINE_attr_templ(sai_tam_event_attr_t, s32list, sai_tam_event_attr_t_s32list);

using SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE_VAL
    = sai_tam_event_attr_t_s32list<((sai_tam_event_attr_t)SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE), sai_s32_list_t>;
// end TODO
//////////////////////////////////////////////////

#endif // __SAI_GEN_ATTR_EXT_H__
