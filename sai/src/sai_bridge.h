// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __SAI_BRIDGE_H__
#define __SAI_BRIDGE_H__

extern "C" {
#include "sai.h"
}

#include "api/npu/la_switch.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{

struct lsai_bridge_t {
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;
    sai_bridge_type_t m_type;
    la_obj_wrap<la_switch> m_sdk_switch;

    sai_bridge_flood_control_type_t m_ucast_flood_type = SAI_BRIDGE_FLOOD_CONTROL_TYPE_SUB_PORTS;
    sai_bridge_flood_control_type_t m_mcast_flood_type = SAI_BRIDGE_FLOOD_CONTROL_TYPE_SUB_PORTS;
    sai_bridge_flood_control_type_t m_bcast_flood_type = SAI_BRIDGE_FLOOD_CONTROL_TYPE_SUB_PORTS;
};
}
}
#endif
