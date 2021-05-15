// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __CEREAL_ACL_TYPES_SERIALIZATION_H__
#define __CEREAL_ACL_TYPES_SERIALIZATION_H__

#include "api/types/la_acl_types.h"

namespace cereal
{
// Manual save/load for some ACL structs and unions
template <class Archive>
void
save(Archive& ar, const silicon_one::la_acl_command_action& cmd)
{
    ar(cmd.type);
    switch (cmd.type) {
    case silicon_one::la_acl_action_type_e::TRAFFIC_CLASS:
        ar(cmd.data.traffic_class);
        break;
    case silicon_one::la_acl_action_type_e::COLOR:
        ar(cmd.data.color);
        break;
    case silicon_one::la_acl_action_type_e::QOS_OR_METER_COUNTER_OFFSET:
        ar(cmd.data.qos_offset);
        break;
    case silicon_one::la_acl_action_type_e::ENCAP_EXP:
        ar(cmd.data.encap_exp);
        break;
    case silicon_one::la_acl_action_type_e::REMARK_FWD:
        ar(cmd.data.remark_fwd);
        break;
    case silicon_one::la_acl_action_type_e::REMARK_GROUP:
        ar(cmd.data.remark_group);
        break;
    case silicon_one::la_acl_action_type_e::DROP:
        ar(cmd.data.drop);
        break;
    case silicon_one::la_acl_action_type_e::PUNT:
        ar(cmd.data.punt);
        break;
    case silicon_one::la_acl_action_type_e::DO_MIRROR:
        ar(cmd.data.do_mirror);
        break;
    case silicon_one::la_acl_action_type_e::MIRROR_CMD:
        ar(cmd.data.mirror_cmd);
        break;
    case silicon_one::la_acl_action_type_e::COUNTER_TYPE:
        ar(cmd.data.counter_type);
        break;
    case silicon_one::la_acl_action_type_e::COUNTER:
        ar(cmd.data.counter);
        break;
    case silicon_one::la_acl_action_type_e::L2_DESTINATION:
        ar(cmd.data.l2_dest);
        break;
    case silicon_one::la_acl_action_type_e::L3_DESTINATION:
        ar(cmd.data.l3_dest);
        break;
    case silicon_one::la_acl_action_type_e::METER:
        ar(cmd.data.meter);
        break;
    default:
        break;
    }
}

template <class Archive>
void
load(Archive& ar, silicon_one::la_acl_command_action& cmd)
{
    ar(cmd.type);
    switch (cmd.type) {
    case silicon_one::la_acl_action_type_e::TRAFFIC_CLASS:
        ar(cmd.data.traffic_class);
        break;
    case silicon_one::la_acl_action_type_e::COLOR:
        ar(cmd.data.color);
        break;
    case silicon_one::la_acl_action_type_e::QOS_OR_METER_COUNTER_OFFSET:
        ar(cmd.data.qos_offset);
        break;
    case silicon_one::la_acl_action_type_e::ENCAP_EXP:
        ar(cmd.data.encap_exp);
        break;
    case silicon_one::la_acl_action_type_e::REMARK_FWD:
        ar(cmd.data.remark_fwd);
        break;
    case silicon_one::la_acl_action_type_e::REMARK_GROUP:
        ar(cmd.data.remark_group);
        break;
    case silicon_one::la_acl_action_type_e::DROP:
        ar(cmd.data.drop);
        break;
    case silicon_one::la_acl_action_type_e::PUNT:
        ar(cmd.data.punt);
        break;
    case silicon_one::la_acl_action_type_e::DO_MIRROR:
        ar(cmd.data.do_mirror);
        break;
    case silicon_one::la_acl_action_type_e::MIRROR_CMD:
        ar(cmd.data.mirror_cmd);
        break;
    case silicon_one::la_acl_action_type_e::COUNTER_TYPE:
        ar(cmd.data.counter_type);
        break;
    case silicon_one::la_acl_action_type_e::COUNTER:
        ar(cmd.data.counter);
        break;
    case silicon_one::la_acl_action_type_e::L2_DESTINATION:
        ar(cmd.data.l2_dest);
        break;
    case silicon_one::la_acl_action_type_e::L3_DESTINATION:
        ar(cmd.data.l3_dest);
        break;
    case silicon_one::la_acl_action_type_e::METER:
        ar(cmd.data.meter);
        break;
    default:
        break;
    }
}
}

#endif // __CEREAL_ACL_TYPES_SERIALIZATION_H__
