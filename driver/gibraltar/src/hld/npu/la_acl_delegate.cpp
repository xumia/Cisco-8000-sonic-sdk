// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <algorithm>

#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l3_destination.h"
#include "api/npu/la_vrf.h"
#include "api/system/la_mirror_command.h"
#include "counter_utils.h"
#include "la_acl_delegate.h"
#include "la_counter_set_impl.h"
#include "nplapi/npl_types.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"

#include "common/defines.h"
#include "common/logger.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "nplapi/npl_table_types.h"
#include "resolution_utils.h"

namespace silicon_one
{

la_acl_delegate::la_acl_delegate(const la_device_impl_wptr& device, const la_acl_wptr& parent)
    : m_device(device), m_stage(la_acl::stage_e::LAST), m_acl_type(la_acl::type_e::LAST), m_parent(parent), m_qos_cmd_count(0)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
}

la_acl_delegate::~la_acl_delegate()
{
}

// la_acl API-s
la_status
la_acl_delegate::get_id(la_slice_pair_id_t slice_pair, la_acl_id_t& out_id) const
{
    if (slice_pair >= m_slice_pair_data.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_id = m_slice_pair_data[slice_pair].acl_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::get_type(la_acl::type_e& out_type) const
{
    out_type = m_acl_type;

    return LA_STATUS_SUCCESS;
}

const la_pcl_wcptr
la_acl_delegate::get_src_pcl() const
{
    return m_src_pcl;
}

const la_pcl_wcptr
la_acl_delegate::get_dst_pcl() const
{
    return m_dst_pcl;
}

la_status
la_acl_delegate::get_count(size_t& out_count) const
{
    out_count = m_aces.size();

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::append(const la_acl_key& key_val, const la_acl_command_actions& cmd)
{
    return insert(m_aces.size(), key_val, cmd);
}

la_status
la_acl_delegate::add_entry_command(la_acl_direction_e dir, const la_acl_command_actions& cmd)
{
    transaction txn;
    la_counter_set* counter = nullptr;
    la_l2_destination* l2_dest = nullptr;
    la_l3_destination* l3_dest = nullptr;
    la_meter_set* meter = nullptr;

    if (dir == la_acl_direction_e::EGRESS) {
        for (const auto action : cmd) {
            if (action.type == la_acl_action_type_e::COUNTER) {
                counter = action.data.counter;
            }
        }
        if (counter != nullptr) {
            auto counter_impl = static_cast<la_counter_set_impl*>(counter);
            la_status status = counter_impl->add_ace_counter(COUNTER_DIRECTION_EGRESS, m_ifg_use_count->get_ifgs());
            return_on_error(status);

            m_device->add_ifg_dependency(m_parent, counter_impl);
            m_device->add_object_dependency(counter_impl, m_parent);
        }
        return LA_STATUS_SUCCESS;
    }

    for (const auto action : cmd) {
        if (action.type == la_acl_action_type_e::COUNTER) {
            counter = action.data.counter;
        }
        if (action.type == la_acl_action_type_e::L2_DESTINATION) {
            l2_dest = action.data.l2_dest;
        }
        if (action.type == la_acl_action_type_e::L3_DESTINATION) {
            l3_dest = action.data.l3_dest;
        }
        if (action.type == la_acl_action_type_e::METER) {
            meter = action.data.meter;
        }
    }

    if (counter != nullptr) {
        auto counter_impl = static_cast<la_counter_set_impl*>(counter);
        txn.status = counter_impl->add_ace_counter(COUNTER_DIRECTION_INGRESS, m_ifg_use_count->get_ifgs());
        return_on_error(txn.status);

        m_device->add_ifg_dependency(m_parent, counter_impl);
        m_device->add_object_dependency(counter_impl, m_parent);

        txn.on_fail([=]() {
            m_device->remove_object_dependency(counter_impl, m_parent);
            m_device->remove_ifg_dependency(m_parent, counter_impl);
            counter_impl->remove_ace_counter(m_ifg_use_count->get_ifgs());
        });
    }

    if (meter != nullptr) {
        // Police or redirect
        if (meter->type() != la_object::object_type_e::METER_SET) {
            return LA_STATUS_EINVAL;
        }

        if (meter->get_type() != la_meter_set::type_e::PER_IFG_EXACT) {
            log_err(HLD,
                    "Police/Redirect PBR entry should be configured with per-IFG exact meter in ingress PBR ACL = %s",
                    silicon_one::to_string(m_parent).c_str());
            return LA_STATUS_EINVAL;
        }

        la_meter_set_impl* meter_impl = static_cast<la_meter_set_impl*>(meter);
        txn.status = meter_impl->attach_user(m_parent, true /*is_aggregate*/, false /*is_lpts_entry_meter*/);
        return_on_error(txn.status);
    }

    if (l2_dest != nullptr) {
        m_device->add_object_dependency(l2_dest, m_parent);
        txn.on_fail([=]() { m_device->remove_object_dependency(l2_dest, m_parent); });
    }

    // Establish resolution dependencies if destination set
    if (l3_dest != nullptr) {
        txn.status = instantiate_resolution_object(m_device->get_sptr(l3_dest), RESOLUTION_STEP_FORWARD_L3);
        return_on_error(txn.status);

        txn.on_fail([=]() { uninstantiate_resolution_object(m_device->get_sptr(l3_dest), RESOLUTION_STEP_FORWARD_L3); });

        m_device->add_object_dependency(l3_dest, m_parent);
    }

    return LA_STATUS_SUCCESS;
}

static la_status
validate_key(const la_acl_key& key_val)
{
    bool src_bincode = false;
    bool dst_bincode = false;
    bool msg_code = false;
    bool msg_type = false;
    bool sport = false;

    for (const auto acl_field : key_val) {
        if (acl_field.type == la_acl_field_type_e::SRC_PCL_BINCODE) {
            src_bincode = true;
            if (acl_field.val.src_pcl_bincode > 1 << (NPL_OBJECT_GROUP_COMPRESSION_CODE_LEN)) {
                return LA_STATUS_EINVAL;
            }
        }
        if (acl_field.type == la_acl_field_type_e::DST_PCL_BINCODE) {
            dst_bincode = true;
            if (acl_field.val.dst_pcl_bincode > 1 << (NPL_OBJECT_GROUP_COMPRESSION_CODE_LEN)) {
                return LA_STATUS_EINVAL;
            }
        }
        if (acl_field.type == la_acl_field_type_e::MSG_CODE) {
            msg_code = true;
        }
        if (acl_field.type == la_acl_field_type_e::MSG_TYPE) {
            msg_type = true;
        }
        if (acl_field.type == la_acl_field_type_e::SPORT) {
            sport = true;
        }
    }

    if (((msg_code) || (msg_type)) && (sport)) {
        log_err(HLD, "la_acl_delegate:can't include both icmp (msg_code or msg_type) and tcp/udp src port");
        return LA_STATUS_EINVAL;
    }

    if ((dst_bincode) && (src_bincode)) {
        return LA_STATUS_SUCCESS;
    } else if ((dst_bincode) || (src_bincode)) {
        // Must configure both src and dst bincodes
        log_err(HLD, "la_acl_delegate:og_acl, must configure both src&dst bincodes");
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::insert(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd)
{
    transaction txn;
    la_acl_key_def_vec_t acl_key_def;
    la_acl_command_def_vec_t acl_command_def;
    la_acl_direction_e dir;
    bool found_field_in_key_profile;
    bool found_action_in_command_profile;

    la_status status = validate_key(key_val);
    return_on_error(status);

    m_acl_key_profile->get_key_definition(acl_key_def);
    m_acl_command_profile->get_command_definition(acl_command_def);
    dir = m_acl_key_profile->get_direction();

    for (const auto field : key_val) {
        found_field_in_key_profile = false;
        for (auto profile_field : acl_key_def) {
            if (field.type == profile_field.type) {
                found_field_in_key_profile = true;
                break;
            }
        }
        if (!found_field_in_key_profile) {
            log_err(HLD,
                    "la_acl_delegate::%s ACE key field type %s not found in acl key profile",
                    __func__,
                    silicon_one::to_string(field.type).c_str());
            return LA_STATUS_EINVAL;
        }
    }

    for (const auto action : cmd) {
        found_action_in_command_profile = false;
        for (auto profile_action : acl_command_def) {
            if (action.type == profile_action.type) {
                found_action_in_command_profile = true;
                break;
            }
        }
        if (!found_action_in_command_profile) {
            log_err(HLD,
                    "la_acl_delegate::%s ACE command action field type %s not found in acl command profile",
                    __func__,
                    silicon_one::to_string(action.type).c_str());
            return LA_STATUS_EINVAL;
        }
    }
    // If too long, then append per API doc
    if (position > m_aces.size()) {
        position = m_aces.size();
    }

    // Check tcam space on all applied slices before we start
    const auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        if (get_tcam_fullness(slice) >= get_tcam_size(slice)) {
            log_err(HLD,
                    "la_acl_delegate::%s Insufficient TCAM space to insert ACL entry on slice %d. Fullness: %ld/%ld",
                    __func__,
                    slice,
                    get_tcam_fullness(slice),
                    get_tcam_size(slice));
            return LA_STATUS_ERESOURCE;
        }
    }

    // Handle command items like counters and destinations
    txn.status = add_entry_command(dir, cmd);
    if (txn.status != LA_STATUS_SUCCESS) {
        return txn.status;
    }
    txn.on_fail([&]() { remove_entry_command(dir, cmd); });

    // Program tcam entry on applied slices
    for (auto slice : slices) {
        // locate empty line after last ACE
        size_t index = 0;

        if (m_aces.size() == 0) {
            // Locate the first free tcam line after the last entry in the table
            txn.status = locate_free_tcam_line_after_last_entry(slice, index);
            if (txn.status != LA_STATUS_SUCCESS) {
                log_err(HLD,
                        "Unable to find free tcam entry for ACL with fullness %ld/%ld",
                        get_tcam_fullness(slice),
                        get_tcam_size(slice));
                return txn.status;
            }
        } else if (position > 0) {
            // Locate the last ACE before the required position
            txn.status = get_tcam_line_index(slice, position - 1, index);
            if (txn.status != LA_STATUS_SUCCESS) {
                return txn.status;
            }

            index += 1;
        } else {
            // (position=0) Locate the ACE in position 0
            txn.status = get_tcam_line_index(slice, 0, index);
            if (txn.status != LA_STATUS_SUCCESS) {
                return txn.status;
            }
        }

        // update table
        txn.status = set_tcam_line(slice, index, true /* push */, key_val, cmd);
        if (txn.status == LA_STATUS_ERESOURCE) {
            // TODO: add resource and retry
            return txn.status;
        }

        if (txn.status != LA_STATUS_SUCCESS) {
            return txn.status;
        }
        txn.on_fail([=]() { erase_tcam_line(slice, index); });
    }
    // Update shadow
    acl_entry_desc desc;
    desc.key_val = key_val;
    desc.cmd_actions = cmd;
    m_aces.insert(m_aces.begin() + position, desc);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::set(size_t position, const la_acl_key& key_val, const la_acl_command_actions& cmd)
{
    // Check arguments
    if (position >= m_aces.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    transaction txn;

    la_acl_key_def_vec_t acl_key_def;
    la_acl_direction_e dir;

    m_acl_key_profile->get_key_definition(acl_key_def);
    dir = m_acl_key_profile->get_direction();
    bool found_field_in_key_profile;

    for (const auto field : key_val) {
        found_field_in_key_profile = false;
        for (auto profile_field : acl_key_def) {
            if (field.type == profile_field.type) {
                found_field_in_key_profile = true;
                break;
            }
        }
        if (!found_field_in_key_profile) {
            log_err(HLD,
                    "la_acl_delegate::%s ACE key field type %s not found in acl key profile",
                    __func__,
                    silicon_one::to_string(field.type).c_str());
            return LA_STATUS_EINVAL;
        }
    }

    txn.status = add_entry_command(dir, cmd);
    if (txn.status != LA_STATUS_SUCCESS) {
        return txn.status;
    }
    txn.on_fail([&]() { remove_entry_command(dir, cmd); });

    for (auto slice : m_ifg_use_count->get_slices()) {
        size_t index = 0;

        txn.status = get_tcam_line_index(slice, position, index);
        if (txn.status != LA_STATUS_SUCCESS) {
            return txn.status;
        }

        txn.status = set_tcam_line(slice, index, false /* push */, key_val, cmd);
        if (txn.status != LA_STATUS_SUCCESS) {
            return txn.status;
        }
        txn.on_fail(
            [=]() { set_tcam_line(slice, index, false /* push */, m_aces[position].key_val, m_aces[position].cmd_actions); });
    }

    txn.status = remove_entry_command(dir, m_aces[position].cmd_actions);
    if (txn.status != LA_STATUS_SUCCESS) {
        return txn.status;
    }

    acl_entry_desc desc;
    desc.key_val = key_val;
    desc.cmd_actions = cmd;
    m_aces[position] = desc;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::remove_entry_command(la_acl_direction_e dir, const la_acl_command_actions& cmd)
{
    la_counter_set* counter = nullptr;
    la_l2_destination* l2_dest = nullptr;
    la_l3_destination* l3_dest = nullptr;
    la_meter_set* meter = nullptr;

    if (dir == la_acl_direction_e::EGRESS) {
        for (const auto action : cmd) {
            if (action.type == la_acl_action_type_e::COUNTER) {
                counter = action.data.counter;
            }
        }
        if (counter != nullptr) {
            auto counter_impl = static_cast<la_counter_set_impl*>(counter);
            la_status status = counter_impl->remove_ace_counter(m_ifg_use_count->get_ifgs());
            return_on_error(status);

            m_device->remove_ifg_dependency(m_parent, counter_impl);
            m_device->remove_object_dependency(counter_impl, m_parent);
        }
        return LA_STATUS_SUCCESS;
    }

    for (const auto action : cmd) {
        if (action.type == la_acl_action_type_e::COUNTER) {
            counter = action.data.counter;
        }
        if (action.type == la_acl_action_type_e::L2_DESTINATION) {
            l2_dest = action.data.l2_dest;
        }
        if (action.type == la_acl_action_type_e::L3_DESTINATION) {
            l3_dest = action.data.l3_dest;
        }
        if (action.type == la_acl_action_type_e::METER) {
            meter = action.data.meter;
        }
    }

    if (counter != nullptr) {
        auto counter_impl = static_cast<la_counter_set_impl*>(counter);
        la_status status = counter_impl->remove_ace_counter(m_ifg_use_count->get_ifgs());
        return_on_error(status);

        m_device->remove_ifg_dependency(m_parent, counter_impl);
        m_device->remove_object_dependency(counter_impl, m_parent);
    }

    // Police or redirect
    if (meter && meter->type() == la_object::object_type_e::METER_SET) {
        auto meter_impl = static_cast<la_meter_set_impl*>(meter);
        meter_impl->detach_user(m_parent);
    }

    if (l2_dest != nullptr) {
        m_device->remove_object_dependency(l2_dest, m_parent);
    }

    if (l3_dest != nullptr) {
        la_status status = uninstantiate_resolution_object(m_device->get_sptr(l3_dest), RESOLUTION_STEP_FORWARD_L3);
        return_on_error(status);

        m_device->remove_object_dependency(l3_dest, m_parent);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::erase(size_t position)
{
    la_status status = LA_STATUS_SUCCESS;
    la_acl_direction_e dir;

    if (position > m_aces.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }
    dir = m_acl_key_profile->get_direction();

    for (auto slice : m_ifg_use_count->get_slices()) {
        // locate the ACE
        size_t index = 0;

        status = get_tcam_line_index(slice, position, index);
        return_on_error(status);

        // update table - erase
        status = erase_tcam_line(slice, index);
        return_on_error(status);
    }

    acl_entry_desc desc = m_aces[position];
    status = remove_entry_command(dir, desc.cmd_actions);
    return_on_error(status);

    m_aces.erase(m_aces.begin() + position);

    return status;
}

const la_acl_wptr&
la_acl_delegate::get_acl_parent() const
{
    return m_parent;
}

la_status
la_acl_delegate::clear()
{
    while (!m_aces.empty()) {
        la_status status = erase(0);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::get(size_t position, acl_entry_desc& out_acl_entry_desc) const
{
    if (position >= m_aces.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_acl_entry_desc = m_aces[position];
    return LA_STATUS_SUCCESS;
}

// Helper functions
void
la_acl_delegate::copy_npl_to_acl_command(const npl_rtf_result_profile_0_t& npl_result, la_acl_command_actions& out_acl_cmd) const
{
    out_acl_cmd = la_acl_command_actions();
    auto traffic_class_cmd = la_acl_command_action();
    auto color_cmd = la_acl_command_action();
    auto qos_or_meter_cmd = la_acl_command_action();
    auto encap_exp_cmd = la_acl_command_action();
    auto remark_fwd_cmd = la_acl_command_action();
    auto remark_group_cmd = la_acl_command_action();
    auto drop_cmd = la_acl_command_action();
    auto punt_cmd = la_acl_command_action();
    auto do_mirror_cmd = la_acl_command_action();
    auto mirror_cmd = la_acl_command_action();
    auto counter_type_cmd = la_acl_command_action();
    auto l2_dest_cmd = la_acl_command_action();
    auto l3_dest_cmd = la_acl_command_action();
#if 0
    auto counter_cmd = la_acl_command_action();
    auto meter_cmd = la_acl_command_action();
#endif

    if (npl_result.override_phb == 1) {
        traffic_class_cmd.type = la_acl_action_type_e::TRAFFIC_CLASS;
        traffic_class_cmd.data.traffic_class = npl_result.phb.tc;
        out_acl_cmd.push_back(traffic_class_cmd);

        color_cmd.type = la_acl_action_type_e::COLOR;
        color_cmd.data.color = static_cast<la_qos_color_e>(npl_result.phb.dp);
        out_acl_cmd.push_back(color_cmd);
    }

    if (npl_result.ingress_qos_remark.encap_mpls_exp.valid == 1) {
        encap_exp_cmd.type = la_acl_action_type_e::ENCAP_EXP;
        encap_exp_cmd.data.encap_exp = npl_result.ingress_qos_remark.encap_mpls_exp.exp;
        out_acl_cmd.push_back(encap_exp_cmd);
    }

    if (npl_result.ingress_qos_remark.enable_ingress_remark == 1) {
        remark_fwd_cmd.type = la_acl_action_type_e::REMARK_FWD;
        remark_fwd_cmd.data.remark_fwd = npl_result.ingress_qos_remark.fwd_qos_tag;
        out_acl_cmd.push_back(remark_fwd_cmd);
    }

    if (npl_result.override_qos_group == 1) {
        remark_group_cmd.type = la_acl_action_type_e::REMARK_GROUP;
        remark_group_cmd.data.remark_group = npl_result.ingress_qos_remark.qos_group;
        out_acl_cmd.push_back(remark_group_cmd);
    }

    if (npl_result.counter_action_type == NPL_COUNTING) {
        counter_type_cmd.type = la_acl_action_type_e::COUNTER_TYPE;
        counter_type_cmd.data.counter_type = la_acl_counter_type_e::DO_QOS_COUNTING;
        out_acl_cmd.push_back(counter_type_cmd);

        qos_or_meter_cmd.type = la_acl_action_type_e::QOS_OR_METER_COUNTER_OFFSET;
        qos_or_meter_cmd.data.qos_offset = npl_result.q_m_offset_5bits;
        out_acl_cmd.push_back(qos_or_meter_cmd);
    } else if (npl_result.counter_action_type == NPL_METERING) {
        counter_type_cmd.type = la_acl_action_type_e::COUNTER_TYPE;
        counter_type_cmd.data.counter_type = la_acl_counter_type_e::DO_METERING;
        out_acl_cmd.push_back(counter_type_cmd);

        qos_or_meter_cmd.type = la_acl_action_type_e::QOS_OR_METER_COUNTER_OFFSET;
        qos_or_meter_cmd.data.meter_offset = npl_result.q_m_offset_5bits;
        out_acl_cmd.push_back(qos_or_meter_cmd);
    } else if (npl_result.counter_action_type == NPL_NO_ACTION) {
        counter_type_cmd.type = la_acl_action_type_e::COUNTER_TYPE;
        counter_type_cmd.data.counter_type = la_acl_counter_type_e::NONE;
        out_acl_cmd.push_back(counter_type_cmd);
    }

    if (npl_result.rtf_sec_action == NPL_DROP) {
        drop_cmd.type = la_acl_action_type_e::DROP;
        drop_cmd.data.drop = true;
        out_acl_cmd.push_back(drop_cmd);
    }

    if (npl_result.rtf_sec_action == NPL_FORCE_PUNT) {
        punt_cmd.type = la_acl_action_type_e::PUNT;
        punt_cmd.data.drop = true;
        out_acl_cmd.push_back(punt_cmd);
    }

    if (npl_result.mirror_action == 1) {
        do_mirror_cmd.type = la_acl_action_type_e::DO_MIRROR;
        do_mirror_cmd.data.do_mirror = la_acl_mirror_src_e::DO_MIRROR_FROM_LP;
        out_acl_cmd.push_back(do_mirror_cmd);
    }

    if ((npl_result.mirror_action == 0) && (npl_result.mirror_cmd_or_offset.mirror_cmd != 0)) {
        do_mirror_cmd.type = la_acl_action_type_e::DO_MIRROR;
        do_mirror_cmd.data.do_mirror = la_acl_mirror_src_e::DO_MIRROR_FROM_CMD;
        out_acl_cmd.push_back(do_mirror_cmd);

        mirror_cmd.type = la_acl_action_type_e::MIRROR_CMD;
        mirror_cmd.data.mirror_cmd = npl_result.mirror_cmd_or_offset.mirror_cmd;
        out_acl_cmd.push_back(mirror_cmd);
    }

    if (npl_result.counter_action_type == NPL_OVERRIDE_POLICER) {
        counter_type_cmd.type = la_acl_action_type_e::COUNTER_TYPE;
        counter_type_cmd.data.counter_type = la_acl_counter_type_e::OVERRIDE_METERING_PTR;
        out_acl_cmd.push_back(counter_type_cmd);
    }
#if 0
    if (npl_result.force.drop_counter != nullptr) {
        counter_cmd.type = la_acl_action_type_e::COUNTER;
        counter_cmd.data.counter = npl_result.force.drop_counter;
        out_acl_cmd.push_back(counter_cmd);
    }
#endif
#if 0
    if (npl_result.force.permit_ace_cntr != nullptr) {
        counter_cmd.type = la_acl_action_type_e::COUNTER;
        counter_cmd.data.counter = npl_result.force.permit_ace_cntr;
        out_acl_cmd.push_back(counter_cmd);
    }
#endif
    if (npl_result.rtf_sec_action == NPL_CHANGE_DESTINATION) {
        destination_id dest_id(npl_result.force.destination.val);
        destination_type_e destination_type = get_destination_type(dest_id);
        if (destination_type == DESTINATION_TYPE_L2) {
            la_l2_destination_gid_t l2_gid = npl_result.force.destination.val;
            const auto& l2_destination = m_device->get_l2_destination_by_gid(l2_gid);
            l2_dest_cmd.type = la_acl_action_type_e::L2_DESTINATION;
            l2_dest_cmd.data.l2_dest = l2_destination.get();
            out_acl_cmd.push_back(l2_dest_cmd);
        } else {
            la_l3_destination_gid_t l3_gid = npl_result.force.destination.val;
            const auto& l3_destination = m_device->get_l3_destination_by_gid(l3_gid);
            l3_dest_cmd.type = la_acl_action_type_e::L3_DESTINATION;
            l3_dest_cmd.data.l3_dest = l3_destination.get();
            out_acl_cmd.push_back(l3_dest_cmd);
        }
    }
#if 0
    if (npl_result.force.meter_ptr != nullptr) {
        meter_cmd.type = la_acl_action_type_e::METER;
        meter_cmd.data.meter = npl_result.force.meter_ptr;
        out_acl_cmd.push_back(meter_cmd);
    }
#endif
}

void
la_acl_delegate::copy_npl_to_acl_command(const npl_egress_sec_acl_result_t& npl_sec, la_acl_command_actions& out_acl_cmd) const
{
    out_acl_cmd = la_acl_command_actions();
    auto drop_cmd = la_acl_command_action();
    auto punt_cmd = la_acl_command_action();
    auto mirror_cmd = la_acl_command_action();

    drop_cmd.type = la_acl_action_type_e::DROP;
    drop_cmd.data.drop = npl_sec.drop_punt_or_permit.drop;
    out_acl_cmd.push_back(drop_cmd);

    if (npl_sec.drop_punt_or_permit.force_punt) {
        punt_cmd.type = la_acl_action_type_e::PUNT;
        punt_cmd.data.punt = npl_sec.drop_punt_or_permit.force_punt;
        out_acl_cmd.push_back(punt_cmd);
    }
    if (npl_sec.mirror_valid) {
        mirror_cmd.type = la_acl_action_type_e::DO_MIRROR;
        mirror_cmd.data.do_mirror = la_acl_mirror_src_e::DO_MIRROR_FROM_LP;
        out_acl_cmd.push_back(mirror_cmd);
    }
}

la_status
la_acl_delegate::copy_acl_command_to_npl(la_slice_id_t slice,
                                         const la_acl_command_actions& acl_cmd_actions,
                                         npl_egress_sec_acl_result_t& npl_sec) const
{
    bool drop = false;

    for (auto cmd : acl_cmd_actions) {
        if (cmd.type == la_acl_action_type_e::DROP) {
            drop = cmd.data.drop;
        }
    }

    for (auto cmd : acl_cmd_actions) {
        if (cmd.type == la_acl_action_type_e::DROP) {
            npl_sec.drop_punt_or_permit.drop = cmd.data.drop;
        }
        if (cmd.type == la_acl_action_type_e::PUNT) {
            npl_sec.drop_punt_or_permit.force_punt = cmd.data.punt;
        }
        if (cmd.type == la_acl_action_type_e::DO_MIRROR) {
            npl_sec.mirror_valid = true;
        }
        if (cmd.type == la_acl_action_type_e::COUNTER) {
            if (cmd.data.counter != nullptr) {
                auto ctr_impl = static_cast<la_counter_set_impl*>(cmd.data.counter);
                npl_sec.drop_punt_or_permit.permit_count_enable = !drop;
                if (drop) {
                    npl_sec.drop_or_permit.drop_counter
                        = populate_counter_ptr_slice(m_device->get_sptr(ctr_impl), slice, COUNTER_DIRECTION_EGRESS);
                } else {
                    npl_sec.drop_or_permit.permit_ace_cntr
                        = populate_counter_ptr_slice(m_device->get_sptr(ctr_impl), slice, COUNTER_DIRECTION_EGRESS);
                }
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::copy_acl_command_to_npl(la_slice_id_t slice,
                                         const la_acl_command_actions& acl_cmd_actions,
                                         npl_rtf_payload_t& out_npl) const
{
    bool do_drop = false;
    bool found_do_mirror = false;
    bool found_mirror_cmd = false;
    bool found_punt_cmd = false;
    auto do_mirror_cmd = la_acl_command_action();
    la_acl_counter_type_e counter_type = la_acl_counter_type_e::NONE;

    npl_rtf_profile_type_e command_profile;
    la_status status = get_acl_command_profile(acl_cmd_actions, command_profile);
    return_on_error(status);

    for (auto cmd : acl_cmd_actions) {
        if (cmd.type == la_acl_action_type_e::DROP) {
            do_drop = cmd.data.drop;
        }
        if (cmd.type == la_acl_action_type_e::COUNTER_TYPE) {
            counter_type = cmd.data.counter_type;
        }
        if (cmd.type == la_acl_action_type_e::DO_MIRROR) {
            found_do_mirror = true;
            do_mirror_cmd = cmd;
        }
        if (cmd.type == la_acl_action_type_e::MIRROR_CMD) {
            if (cmd.data.mirror_cmd == 0) {
                // Mirror Command 0 can't be used in ACL mirroring.
                log_err(HLD, "unsupported Mirror CMD Value in acl action ");
                return LA_STATUS_EINVAL;
            }
            found_mirror_cmd = true;
        }
        if (cmd.type == la_acl_action_type_e::PUNT) {
            found_punt_cmd = true;
        }
    }

    out_npl.rtf_profile_index = command_profile;
    if (command_profile == NPL_RTF_PROFILE_0) {
        npl_rtf_result_profile_0_t rtf_result_profile_0 = {};

        out_npl.rtf_profile_index = NPL_RTF_PROFILE_0;
        for (auto cmd : acl_cmd_actions) {
            switch (cmd.type) {
            case la_acl_action_type_e::TRAFFIC_CLASS:
                rtf_result_profile_0.phb.tc = cmd.data.traffic_class;
                rtf_result_profile_0.override_phb = 1;
                break;
            case la_acl_action_type_e::COLOR:
                rtf_result_profile_0.phb.dp = (uint64_t)cmd.data.color;
                rtf_result_profile_0.override_phb = 1;
                break;
            case la_acl_action_type_e::QOS_OR_METER_COUNTER_OFFSET:
                switch (counter_type) {
                case la_acl_counter_type_e::DO_QOS_COUNTING:
                    rtf_result_profile_0.q_m_offset_5bits = cmd.data.qos_offset;
                    break;
                case la_acl_counter_type_e::DO_METERING:
                    rtf_result_profile_0.q_m_offset_5bits = cmd.data.meter_offset;
                    break;
                default:
                    return LA_STATUS_EINVAL;
                }
                break;
            case la_acl_action_type_e::ENCAP_EXP:
                rtf_result_profile_0.ingress_qos_remark.encap_mpls_exp.valid = 1;
                rtf_result_profile_0.ingress_qos_remark.encap_mpls_exp.exp = cmd.data.encap_exp;
                break;
            case la_acl_action_type_e::REMARK_FWD:
                rtf_result_profile_0.ingress_qos_remark.enable_ingress_remark = 1;
                rtf_result_profile_0.ingress_qos_remark.fwd_qos_tag = cmd.data.remark_fwd;
                break;
            case la_acl_action_type_e::REMARK_GROUP:
                rtf_result_profile_0.ingress_qos_remark.qos_group = cmd.data.remark_group;
                rtf_result_profile_0.override_qos_group = 1;
                break;
            case la_acl_action_type_e::DROP:
                if (cmd.data.drop) {
                    rtf_result_profile_0.rtf_sec_action = NPL_DROP;
                }
                break;
            case la_acl_action_type_e::PUNT:
                if (cmd.data.punt) {
                    rtf_result_profile_0.rtf_sec_action = NPL_FORCE_PUNT;
                }
                break;
            case la_acl_action_type_e::DO_MIRROR:
                if (cmd.data.do_mirror == la_acl_mirror_src_e::DO_MIRROR_FROM_LP) {
                    rtf_result_profile_0.mirror_action = npl_mirror_action_e::NPL_MIRROR_OFFSET;
                    rtf_result_profile_0.mirror_cmd_or_offset.mirror_cmd = 0;
                } else if (!found_mirror_cmd) {
                    return LA_STATUS_EINVAL;
                }
                break;
            case la_acl_action_type_e::MIRROR_CMD:
                if (found_do_mirror && (do_mirror_cmd.data.do_mirror == la_acl_mirror_src_e::DO_MIRROR_FROM_CMD)) {
                    rtf_result_profile_0.mirror_action = npl_mirror_action_e::NPL_MIRROR_DIRECT;
                    rtf_result_profile_0.mirror_cmd_or_offset.mirror_cmd = cmd.data.mirror_cmd;
                } else {
                    return LA_STATUS_EINVAL;
                }
                break;
            case la_acl_action_type_e::COUNTER_TYPE:
                switch (counter_type) {
                case la_acl_counter_type_e::DO_QOS_COUNTING:
                    rtf_result_profile_0.counter_action_type = NPL_COUNTING;
                    break;
                case la_acl_counter_type_e::DO_METERING:
                    rtf_result_profile_0.counter_action_type = NPL_METERING;
                    break;
                case la_acl_counter_type_e::OVERRIDE_METERING_PTR:
                    rtf_result_profile_0.counter_action_type = NPL_OVERRIDE_POLICER;
                    break;
                case la_acl_counter_type_e::NONE:
                    rtf_result_profile_0.counter_action_type = NPL_NO_ACTION;
                    break;
                default:
                    return LA_STATUS_EINVAL;
                }
                break;
            case la_acl_action_type_e::COUNTER:
                if (cmd.data.counter != nullptr) {
                    auto ctr_impl = static_cast<la_counter_set_impl*>(cmd.data.counter);
                    if (!do_drop) {
                        if (!found_punt_cmd) {
                            rtf_result_profile_0.rtf_sec_action = NPL_PERMIT_COUNT_ENABLE;
                        }
                        rtf_result_profile_0.force.permit_ace_cntr
                            = populate_counter_ptr_slice(m_device->get_sptr(ctr_impl), slice, COUNTER_DIRECTION_INGRESS);
                    } else {
                        rtf_result_profile_0.force.drop_counter
                            = populate_counter_ptr_slice(m_device->get_sptr(ctr_impl), slice, COUNTER_DIRECTION_INGRESS);
                    }
                }
                break;
            case la_acl_action_type_e::L2_DESTINATION:
                if (cmd.data.l2_dest != nullptr) {
                    rtf_result_profile_0.rtf_sec_action = NPL_CHANGE_DESTINATION;
                    rtf_result_profile_0.force.destination.val
                        = m_device->get_l2_destination_gid(m_device->get_sptr(cmd.data.l2_dest));
                    if (rtf_result_profile_0.force.destination.val == DESTINATION_ID_INVALID.val) {
                        return LA_STATUS_EINVAL;
                    }
                }
                break;
            case la_acl_action_type_e::L3_DESTINATION:
                if (cmd.data.l3_dest != nullptr) {
                    rtf_result_profile_0.rtf_sec_action = NPL_CHANGE_DESTINATION;
                    rtf_result_profile_0.force.destination.val
                        = m_device->get_l3_destination_gid(m_device->get_sptr(cmd.data.l3_dest), false /* is_lpm_destination */);
                    if (rtf_result_profile_0.force.destination.val == DESTINATION_ID_INVALID.val) {
                        return LA_STATUS_EINVAL;
                    }
                }
                break;
            case la_acl_action_type_e::METER:
                if (counter_type == la_acl_counter_type_e::OVERRIDE_METERING_PTR) {
                    la_meter_set_impl* meter_impl = static_cast<la_meter_set_impl*>(cmd.data.meter);
                    rtf_result_profile_0.force.meter_ptr
                        = populate_counter_ptr_slice(m_device->get_sptr(meter_impl), slice, COUNTER_DIRECTION_INGRESS);
                }
                break;
            default:
                log_err(HLD,
                        "la_acl_delegate::%s received unsupported acl action type (%s)",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EUNKNOWN;
            }
        }
        out_npl.rtf_result_profile.rtf_result_profile_0 = rtf_result_profile_0;
    } else {
        npl_rtf_result_profile_1_t rtf_result_profile_1 = {};

        for (auto cmd : acl_cmd_actions) {
            switch (cmd.type) {
            case la_acl_action_type_e::L2_DESTINATION:
                if (cmd.data.l2_dest != nullptr) {
                    rtf_result_profile_1.destination.val = m_device->get_l2_destination_gid(m_device->get_sptr(cmd.data.l2_dest));
                    if (rtf_result_profile_1.destination.val == DESTINATION_ID_INVALID.val) {
                        return LA_STATUS_EINVAL;
                    }
                }
                break;
            case la_acl_action_type_e::L3_DESTINATION:
                if (cmd.data.l3_dest != nullptr) {
                    rtf_result_profile_1.destination.val
                        = m_device->get_l3_destination_gid(m_device->get_sptr(cmd.data.l3_dest), false /* is_lpm_destination */);
                    if (rtf_result_profile_1.destination.val == DESTINATION_ID_INVALID.val) {
                        return LA_STATUS_EINVAL;
                    }
                }
                break;
            case la_acl_action_type_e::COUNTER:
                if (cmd.data.counter != nullptr) {
                    auto ctr_impl = static_cast<la_counter_set_impl*>(cmd.data.counter);
                    rtf_result_profile_1.rtf_res_profile_1_action = NPL_CHANGE_DEST_COUNTING;
                    rtf_result_profile_1.meter_or_counter.counter_ptr
                        = populate_counter_ptr_slice(m_device->get_sptr(ctr_impl), slice, COUNTER_DIRECTION_INGRESS);
                }
                break;
            case la_acl_action_type_e::METER:
                if (cmd.data.meter != nullptr) {
                    la_meter_set_impl* meter_impl = static_cast<la_meter_set_impl*>(cmd.data.meter);
                    rtf_result_profile_1.rtf_res_profile_1_action = NPL_CHANGE_DEST_OVERIDE_METER_QOS_REMARK;
                    rtf_result_profile_1.meter_or_counter.meter_ptr
                        = populate_counter_ptr_slice(m_device->get_sptr(meter_impl), slice, COUNTER_DIRECTION_INGRESS);
                }
                break;
            case la_acl_action_type_e::ENCAP_EXP:
                rtf_result_profile_1.ingress_qos_remark.encap_mpls_exp.valid = 1;
                rtf_result_profile_1.ingress_qos_remark.encap_mpls_exp.exp = cmd.data.encap_exp;
                break;
            case la_acl_action_type_e::REMARK_FWD:
                rtf_result_profile_1.ingress_qos_remark.enable_ingress_remark = 1;
                rtf_result_profile_1.ingress_qos_remark.fwd_qos_tag = cmd.data.remark_fwd;
                break;
            case la_acl_action_type_e::REMARK_GROUP:
                rtf_result_profile_1.ingress_qos_remark.qos_group = cmd.data.remark_group;
                rtf_result_profile_1.override_qos_group = 1;
                break;
            default:
                log_err(HLD,
                        "la_acl_delegate::%s received unsupported acl action type (%s) for rtf_result_profile_1",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EUNKNOWN;
            }
        }
        out_npl.rtf_result_profile.rtf_result_profile_1 = rtf_result_profile_1;
    }

    return LA_STATUS_SUCCESS;
}

void
la_acl_delegate::copy_npl_to_security_group_acl_command(const npl_sgacl_payload_t& npl_sgacl,
                                                        la_acl_command_actions& out_acl_cmd) const
{
    out_acl_cmd = la_acl_command_actions();

    auto sgacl_cmd = la_acl_command_action();
    sgacl_cmd.type = la_acl_action_type_e::DROP;
    sgacl_cmd.data.drop = npl_sgacl.drop;
    out_acl_cmd.push_back(sgacl_cmd);
}

la_status
la_acl_delegate::copy_security_group_acl_command_to_npl(la_slice_id_t slice,
                                                        const la_acl_command_actions& acl_cmd,
                                                        npl_sgacl_payload_t& npl_sgacl) const
{
    for (auto cmd : acl_cmd) {
        switch (cmd.type) {
        case la_acl_action_type_e::DROP:
            npl_sgacl.drop = cmd.data.drop;
            break;
        default:
            break;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::update_acl_properties_table(la_slice_pair_id_t slice_pair, bool is_valid)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::get_tcam_line_index(la_slice_id_t slice, size_t position, size_t& tcam_line_index) const
{
    size_t tcam_size = get_tcam_size(slice);

    // locate the ACE
    size_t ace_found = 0; // Count ACE from the ACL found

    for (size_t index = 0; (index < tcam_size) && (ace_found <= position); index++) {
        bool contains;
        la_status status = is_tcam_line_contains_ace(slice, index, contains);
        return_on_error(status);

        if (!contains) {
            continue;
        }

        ace_found++;

        if (ace_found > position) {
            tcam_line_index = index;
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
la_acl_delegate::reserve()
{
    transaction txn;

    for (la_slice_ifg slice_ifg : m_device->get_used_ifgs()) {
        txn.status = add_ifg(slice_ifg);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(HLD, "Failed to reserve ACL: %s, (%d,%d)", la_status2str(txn.status).c_str(), slice_ifg.slice, slice_ifg.ifg);
            return txn.status;
        }
        txn.on_fail([=]() { remove_ifg(slice_ifg); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::add_ifg(la_slice_ifg ifg)
{
    bool ifg_added, slice_added, slice_pair_added;

    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);

    if (!ifg_added) {
        return LA_STATUS_SUCCESS;
    }

    transaction txn;
    txn.on_fail([=]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    // Notify users
    txn.status = m_device->notify_ifg_added(m_parent, ifg);
    if (txn.status != LA_STATUS_SUCCESS) {
        log_err(HLD, "notify_ifg_added failed");
        return txn.status;
    }
    txn.on_fail([=]() { m_device->notify_ifg_removed(m_parent, ifg); });

    // Allocate ACL id for new slice-pair
    if (slice_pair_added) {
        txn.status = allocate_acl_id(ifg.slice / 2);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(HLD, "Failed to allocate ACL index, error: %s", la_status2str(txn.status).c_str());
            return txn.status;
        }
        txn.on_fail([=]() { release_acl_id(ifg.slice / 2); });
    }

    // Program TCAM rules
    if (slice_added) {
        txn.status = add_tcam_entries_to_slice(ifg.slice);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(HLD, "Failed to add entry to slice %d, error: %s", ifg.slice, la_status2str(txn.status).c_str());
            return txn.status;
        }
        txn.on_fail([=]() { remove_tcam_entries_from_slice(ifg.slice); });
    }

    // Enable ACL id only after ACL id has been allocated and TCAM rules are programmed
    if (slice_pair_added) {
        txn.status = update_acl_properties_table(ifg.slice / 2, true /*is_valid*/);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(HLD, "Failed to update ACL properties, error: %s", la_status2str(txn.status).c_str());
            return txn.status;
        }
        txn.on_fail([=]() { update_acl_properties_table(ifg.slice / 2, false /*is_valid*/); });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::remove_ifg(la_slice_ifg ifg)
{
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    if (!ifg_removed) {
        return LA_STATUS_SUCCESS;
    }

    // Disable ACL id
    if (slice_pair_removed) {
        la_status status = update_acl_properties_table(ifg.slice / 2, false /*is_valid*/);
        return_on_error(status);
    }

    // Unporgram ACL rules
    if (slice_removed) {
        la_status status = remove_tcam_entries_from_slice(ifg.slice);
        return_on_error(status);
    }

    // Release ACL id
    if (slice_pair_removed) {
        la_status status = release_acl_id(ifg.slice / 2);
        return_on_error(status);
    }

    // Notify users
    la_status status = m_device->notify_ifg_removed(m_parent, ifg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

slice_ifg_vec_t
la_acl_delegate::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_status
la_acl_delegate::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }

    default:
        log_err(HLD,
                "la_acl_delegate::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

void
la_acl_delegate::set_qos_id(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id)
{
    m_slice_pair_data[slice_pair].acl_id = qos_id;
}

void
la_acl_delegate::clear_qos_id()
{
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    for (la_slice_pair_id_t slice_pair : slice_pairs) {
        m_slice_pair_data[slice_pair].acl_id = la_device_impl::NUM_INGRESS_QOS_PROFILES_PER_SLICE_PAIR;
    }
}

la_status
la_acl_delegate::add_tcam_entries_to_slice(la_slice_id_t slice)
{
    log_debug(HLD, "slice %d, size=%ld", slice, m_aces.size());

    if ((get_tcam_fullness(slice) + m_aces.size()) > get_tcam_size(slice)) {
        log_err(HLD,
                "Insufficient TCAM space to program ACL on slice %d. Reqd %ld, Fullness: %ld/%ld",
                slice,
                m_aces.size(),
                get_tcam_fullness(slice),
                get_tcam_size(slice));
        return LA_STATUS_ERESOURCE;
    }

    transaction txn;

    size_t entries_num = m_aces.size();

    size_t position = 0;

    if (entries_num > 0) {
        txn.status = locate_free_tcam_line_after_last_entry(slice, position);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(HLD,
                    "Unable to find free tcam entry for ACL with fullness %ld/%ld",
                    get_tcam_fullness(slice),
                    get_tcam_size(slice));
            return txn.status;
        }

        vector_alloc<acl_entry_desc> entries(entries_num);

        for (size_t i = 0; i < entries_num; i++) {
            entries[i].key_val = m_aces[i].key_val;
            entries[i].cmd_actions = m_aces[i].cmd_actions;
        }

        // update table
        txn.status = push_tcam_lines(slice, position, entries_num, entries);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(HLD, "slice %d, Unable to set tcam entries for ACL", slice);
            return txn.status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::remove_tcam_entries_from_slice(la_slice_id_t slice)
{
    log_debug(HLD, "slice %d", slice);

    for (size_t i = 0; i < m_aces.size(); ++i) {
        size_t index = 0;
        la_status status = get_tcam_line_index(slice, 0, index);
        return_on_error(status);
        status = erase_tcam_line(slice, index);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::allocate_l2_egress_sec_acl_id(la_slice_pair_id_t slice_pair)
{
    const npl_mac_sec_acl_type_e mac_sec_key_map[(int)la_acl_key_type_e::LAST]
        = {NPL_MAC_SEC_ACL_TYPE_DEFAULT, NPL_MAC_SEC_ACL_TYPE_NONE, NPL_MAC_SEC_ACL_TYPE_NONE};

    la_status status = find_l2_egress_free_acl_id(slice_pair);

    return_on_error(status);

    la_acl_key_type_e key_type;
    m_acl_key_profile->get_key_type(key_type);
    status = reserve_l2_egress_acl_id(slice_pair, mac_sec_key_map[(int)key_type], NPL_MAC_QOS_ACL_TYPE_NONE);

    return status;
}

la_status
la_acl_delegate::release_l2_egress_sec_acl_id(la_slice_pair_id_t slice_pair)
{
    la_status status = reserve_l2_egress_acl_id(slice_pair, NPL_MAC_SEC_ACL_TYPE_NONE, NPL_MAC_QOS_ACL_TYPE_NONE);
    return_on_error(status);

    m_slice_pair_data[slice_pair].acl_id = la_device_impl::ACL_INVALID_ID;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::find_l2_egress_free_acl_id(la_slice_pair_id_t slice_pair)
{

    if (m_slice_pair_data[slice_pair].acl_id == la_device_impl::ACL_INVALID_ID) {
        // No empty slot
        return LA_STATUS_ERESOURCE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::reserve_l2_egress_acl_id(la_slice_pair_id_t slice_pair,
                                          npl_mac_sec_acl_type_e sec_key,
                                          npl_mac_qos_acl_type_e qos_key)
{
    log_debug(HLD, "reserving l2 egress acl id on slice-pair %d for sec=%d, qos=%d", slice_pair, sec_key, qos_key);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::allocate_ipv4_egress_sec_acl_id(la_slice_pair_id_t slice_pair)
{
    la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;

    bool allocated = m_device->m_index_generators.slice_pair[slice_pair].egress_ipv4_acl_ids.allocate(acl_id);
    if (!allocated) {
        log_err(HLD, "Failed to allocate egress ipv4 ACL index in slice_pair: %d", slice_pair);
        return LA_STATUS_ERESOURCE;
    }
    m_slice_pair_data[slice_pair].acl_id = acl_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::release_ipv4_egress_sec_acl_id(la_slice_pair_id_t slice_pair)
{
    m_device->m_index_generators.slice_pair[slice_pair].egress_ipv4_acl_ids.release(m_slice_pair_data[slice_pair].acl_id);
    m_slice_pair_data[slice_pair].acl_id = la_device_impl::ACL_INVALID_ID;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::allocate_ipv6_egress_sec_acl_id(la_slice_pair_id_t slice_pair)
{
    la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;

    bool allocated = m_device->m_index_generators.slice_pair[slice_pair].egress_ipv6_acl_ids.allocate(acl_id);
    if (!allocated) {
        log_err(HLD, "Failed to allocate egress ipv6 ACL index in slice_pair: %d", slice_pair);
        return LA_STATUS_ERESOURCE;
    }
    m_slice_pair_data[slice_pair].acl_id = acl_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::release_ipv6_egress_sec_acl_id(la_slice_pair_id_t slice_pair)
{
    m_device->m_index_generators.slice_pair[slice_pair].egress_ipv6_acl_ids.release(m_slice_pair_data[slice_pair].acl_id);
    m_slice_pair_data[slice_pair].acl_id = la_device_impl::ACL_INVALID_ID;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::initialize_pcls(const la_pcl_wptr& src_pcl, const la_pcl_wptr& dst_pcl)
{
    m_src_pcl = src_pcl;
    m_dst_pcl = dst_pcl;

    return LA_STATUS_SUCCESS;
}

la_uint32_t
la_acl_delegate::get_sgacl_id()
{
    return 0;
}

la_status
la_acl_delegate::get_acl_command_profile(const la_acl_command_actions& acl_cmd_actions,
                                         npl_rtf_profile_type_e& out_command_profile) const
{
    uint16_t traffic_class_cnt = 0;
    uint16_t color_cnt = 0;
    uint16_t qos_or_meter_counter_offset_cnt = 0;
    uint16_t encap_exp_cnt = 0;
    uint16_t remark_fwd_cnt = 0;
    uint16_t remark_group_cnt = 0;
    uint16_t drop_cnt = 0;
    uint16_t punt_cnt = 0;
    uint16_t do_mirror_cnt = 0;
    uint16_t mirror_cmd_cnt = 0;
    uint16_t counter_type_cnt = 0;
    uint16_t counter_cnt = 0;
    uint16_t l2_destination_cnt = 0;
    uint16_t l3_destination_cnt = 0;
    uint16_t meter_cnt = 0;
    la_acl_counter_type_e counter_type = la_acl_counter_type_e::NONE;
    out_command_profile = NPL_RTF_PROFILE_0;

    for (auto cmd : acl_cmd_actions) {
        switch (cmd.type) {
        case la_acl_action_type_e::TRAFFIC_CLASS:
            traffic_class_cnt++;
            if (traffic_class_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::COLOR:
            color_cnt++;
            if (color_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::QOS_OR_METER_COUNTER_OFFSET:
            qos_or_meter_counter_offset_cnt++;
            if (qos_or_meter_counter_offset_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::ENCAP_EXP:
            encap_exp_cnt++;
            if (encap_exp_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::REMARK_FWD:
            remark_fwd_cnt++;
            if (remark_fwd_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::REMARK_GROUP:
            remark_group_cnt++;
            if (remark_group_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::DROP:
            drop_cnt++;
            if (drop_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::PUNT:
            punt_cnt++;
            if (punt_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::DO_MIRROR:
            do_mirror_cnt++;
            if (do_mirror_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::MIRROR_CMD:
            mirror_cmd_cnt++;
            if (mirror_cmd_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::COUNTER_TYPE:
            counter_type_cnt++;
            counter_type = cmd.data.counter_type;
            if (counter_type_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::COUNTER:
            counter_cnt++;
            if (counter_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::L2_DESTINATION:
            l2_destination_cnt++;
            if (l2_destination_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::L3_DESTINATION:
            l3_destination_cnt++;
            if (l3_destination_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        case la_acl_action_type_e::METER:
            meter_cnt++;
            if (meter_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s acl action type %s appears more than once",
                        __func__,
                        silicon_one::to_string(cmd.type).c_str());
                return LA_STATUS_EINVAL;
            }
            break;
        default:
            log_err(HLD, "la_acl_delegate::%s unsupported acl action type %s", __func__, silicon_one::to_string(cmd.type).c_str());
            return LA_STATUS_EINVAL;
        }
    }

    // check phb actions (all or nothing)
    if (traffic_class_cnt + color_cnt == 1) {
        if (traffic_class_cnt == 1) {
            log_err(
                HLD,
                "la_acl_delegate::%s acl action types TRAFFIC_CLASS and COLOR must be set together, but only TRAFFIC_CLASS is set",
                __func__);
        } else {
            log_err(HLD,
                    "la_acl_delegate::%s acl action types TRAFFIC_CLASS and COLOR must be set together, but only COLOR is set",
                    __func__);
        }
        return LA_STATUS_EINVAL;
    }

    // check qos actions:
    // {QOS_OR_METER_COUNTER_OFFSET, REMARK_GROUP, ENCAP_EXP, REMARK_FWD}
    // {QOS_OR_METER_COUNTER_OFFSET, REMARK_GROUP, ENCAP_EXP}
    // {QOS_OR_METER_COUNTER_OFFSET, REMARK_GROUP, REMARK_FWD}
    // {QOS_OR_METER_COUNTER_OFFSET, REMARK_GROUP}

    uint16_t qos_actions_cnt
        = qos_or_meter_counter_offset_cnt + encap_exp_cnt + remark_fwd_cnt + remark_group_cnt + counter_type_cnt;

    if (qos_actions_cnt && counter_type_cnt && (counter_type != la_acl_counter_type_e::OVERRIDE_METERING_PTR)) {
        if (qos_or_meter_counter_offset_cnt && remark_group_cnt && encap_exp_cnt && remark_fwd_cnt) {
            // valid configuration
        } else if (qos_or_meter_counter_offset_cnt && remark_group_cnt && encap_exp_cnt) {
            // valid configuration
        } else if (qos_or_meter_counter_offset_cnt && remark_group_cnt && remark_fwd_cnt) {
            // valid configuration
        } else if (qos_or_meter_counter_offset_cnt && remark_group_cnt) {
            // valid configuration
        } else if (qos_or_meter_counter_offset_cnt && remark_group_cnt) {
            log_err(HLD,
                    "la_acl_delegate::%s illegal set of acl qos action types "
                    "(QOS_OR_METER_COUNTER_OFFSET,ENCAP_EXP,REMARK_FWD,REMARK_GROUP,COUNTER_TYPE)",
                    __func__);
            return LA_STATUS_EINVAL;
        }
    }

    // check that no more than one of (DROP,PUNT,COUNTER,METER,L2_DESTINATION,L3_DESTINATION) acl action types is set
    uint16_t mutex_actions_cnt = drop_cnt + punt_cnt + counter_cnt + l2_destination_cnt + l3_destination_cnt + meter_cnt;
    if (mutex_actions_cnt == 2 && ((drop_cnt == 1 && counter_cnt == 1) || (punt_cnt == 1 && counter_cnt == 1))) {
        return LA_STATUS_SUCCESS;
    }

    // check if it's profile 1
    if (mutex_actions_cnt > 1) {
        if (traffic_class_cnt + color_cnt + qos_or_meter_counter_offset_cnt + drop_cnt + punt_cnt + do_mirror_cnt + mirror_cmd_cnt
                + counter_type_cnt
            == 0) {
            if (counter_cnt + meter_cnt > 1) {
                log_err(HLD,
                        "la_acl_delegate::%s no more than one of (COUNTER, METER) acl action "
                        "types can be set",
                        __func__);
                return LA_STATUS_EINVAL;
            }

            out_command_profile = NPL_RTF_PROFILE_1;
            return LA_STATUS_SUCCESS;
        } else {
            log_err(HLD,
                    "la_acl_delegate::%s no more than one of (DROP,PUNT,COUNTER,METER,L2_DESTINATION,L3_DESTINATION) acl action "
                    "types can be set",
                    __func__);
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::set_unknown_sgacl_id()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::set_default_sgacl_id()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_delegate::get_tcam_max_available_space(size_t& out_space) const
{
    la_status status = LA_STATUS_SUCCESS;

    la_slice_id_vec_t slices = m_ifg_use_count->get_slices();
    size_t smallest_available_space = (size_t)-1;

    size_t translator_available_space = 0;
    for (auto slice : slices) {
        status = get_tcam_max_available_space(slice, translator_available_space);
        smallest_available_space = std::min(smallest_available_space, translator_available_space);
    }

    out_space = smallest_available_space;
    return status;
}

} // namespace silicon_one
