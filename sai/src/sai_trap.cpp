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

#include "sai_trap.h"

#include "api/npu/la_copc.h"
#include "api/types/la_system_types.h"
#include "nplapi/npl_enums.h"
#include "sai_constants.h"
#include "sai_device.h"
#include "sai_policer.h"
#include "api/system/la_l2_mirror_command.h"
#include "sai_logger.h"

namespace silicon_one
{
namespace sai
{

#define SAI_GET_TRAP_SDEV(oid)                                                                                                     \
    lsai_object la_oid(oid);                                                                                                       \
    auto sdev = la_oid.get_device();                                                                                               \
    if (sdev == nullptr || sdev->m_trap_manager == nullptr) {                                                                      \
        return LA_STATUS_EINVAL;                                                                                                   \
    }

#define SAI_GET_TRAP_SDEV_VOID_RETURN(oid)                                                                                         \
    lsai_object la_oid(oid);                                                                                                       \
    auto sdev = la_oid.get_device();                                                                                               \
    if (sdev == nullptr || sdev->m_trap_manager == nullptr) {                                                                      \
        return;                                                                                                                    \
    }

sai_status_t
laobj_db_hostif_trap::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    return sdev->m_trap_manager->get_object_count(sdev, count);
}

sai_status_t
laobj_db_hostif_trap::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                      uint32_t* object_count,
                                      sai_object_key_t* object_list) const
{
    return sdev->m_trap_manager->get_object_keys(sdev, object_count, object_list);
}

trap_manager::~trap_manager()
{
    if (!m_sdev->sdk_operations_allowed()) {
        return;
    }

    for (auto& p : m_config_map) {
        remove_trap(p.first);
    }

    for (auto lpts : m_lpts_ptrs) {
        m_sdev->destroy_la_object(lpts);
    }
}

la_status
trap_manager::get_trap_priority(sai_hostif_trap_type_t trap_type, la_uint_t& priority) const
{
    // check if the trap_type supported
    auto it = m_config_map.find(trap_type);
    if (it == m_config_map.end()) {
        return LA_STATUS_EINVAL;
    }

    auto& trap = it->second.trap;
    if (trap != nullptr) {
        priority = trap->get_priority();
        return LA_STATUS_SUCCESS;
    }
    return LA_STATUS_EINVAL;
}

la_status
trap_manager::get_trap_action(sai_hostif_trap_type_t trap_type, sai_packet_action_t& action) const
{
    auto it = m_config_map.find(trap_type);
    if (it == m_config_map.end()) {
        return LA_STATUS_EINVAL;
    }

    auto& trap = it->second.trap;
    if (trap != nullptr) {
        action = trap->get_action();
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_EINVAL;
}

la_status
trap_manager::get_trap_group(sai_hostif_trap_type_t trap_type, sai_object_id_t& group) const
{
    auto it = m_config_map.find(trap_type);
    if (it == m_config_map.end()) {
        return LA_STATUS_EINVAL;
    }

    auto& trap = it->second.trap;
    if (trap != nullptr) {
        group = trap->get_group();
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_EINVAL;
}

la_status
trap_manager::update_trap_priority(sai_hostif_trap_type_t trap_type, la_uint_t priority)
{
    auto it = m_config_map.find(trap_type);
    if (it == m_config_map.end()) {
        return LA_STATUS_EINVAL;
    }

    auto& trap = it->second.trap;
    if (trap != nullptr) {
        if (priority == trap->get_priority()) {
            return LA_STATUS_SUCCESS;
        }
        return trap->update_priority(priority);
    }

    return LA_STATUS_EINVAL;
}

la_status
trap_manager::update_trap_action(sai_hostif_trap_type_t trap_type, sai_packet_action_t action)
{
    auto it = m_config_map.find(trap_type);
    if (it == m_config_map.end()) {
        return LA_STATUS_EINVAL;
    }

    auto& trap = it->second.trap;
    if (trap != nullptr) {
        return trap->update_action(action);
    }

    return LA_STATUS_EINVAL;
}

la_status
trap_manager::update_trap_group(sai_hostif_trap_type_t trap_type, sai_object_id_t group_id)
{
    auto it = m_config_map.find(trap_type);
    if (it == m_config_map.end()) {
        return LA_STATUS_EINVAL;
    }

    auto& trap = it->second.trap;
    if (trap != nullptr) {
        return trap->update_group(group_id);
    }

    return LA_STATUS_EINVAL;
}

la_status
trap_manager::create_trap_group(sai_object_id_t& trap_group_id, bool admin_state, uint32_t queue_index, sai_object_id_t policer_id)
{
    transaction txn = {};

    std::shared_ptr<trap_group> my_trap_group
        = std::make_shared<trap_group>(shared_from_this(), admin_state, queue_index, policer_id);
    if (my_trap_group == nullptr) {
        return LA_STATUS_EOUTOFMEMORY;
    }

    uint32_t group_idx = 0;
    txn.status = m_groups.allocate_id(group_idx);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_groups.release_id(group_idx); });

    lsai_object la_group(m_sdev->m_switch_id);
    la_group.index = group_idx;
    m_groups.set(trap_group_id, my_trap_group, la_group);
    my_trap_group->set_id(trap_group_id);

    txn.status = my_trap_group->initialize(m_sdev);
    la_return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::remove_trap_group(uint32_t group_idx)
{
    std::shared_ptr<trap_group> group_ptr;
    la_status status = m_groups.get(group_idx, group_ptr);
    la_return_on_error(status);

    group_ptr->clear();

    m_groups.erase_id(group_idx);
    m_groups.release_id(group_idx);

    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::get_trap_group_admin_state(uint32_t group_index, bool& admin_state)
{
    std::shared_ptr<trap_group> trap_group;
    la_status status = m_groups.get(group_index, trap_group);
    la_return_on_error(status);

    admin_state = trap_group->get_admin_state();
    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::get_trap_group_queue(uint32_t group_index, uint32_t& queue_index)
{
    std::shared_ptr<trap_group> trap_group;
    la_status status = m_groups.get(group_index, trap_group);
    la_return_on_error(status);

    queue_index = trap_group->get_queue();
    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::get_trap_group_policer(uint32_t group_index, sai_object_id_t& policer)
{
    std::shared_ptr<trap_group> trap_group;
    la_status status = m_groups.get(group_index, trap_group);
    la_return_on_error(status);

    policer = trap_group->get_policer();
    return LA_STATUS_SUCCESS;
}

void
trap_group::get_meters(std::vector<la_meter_set*>& meters)
{
    lsai_object la_group(m_group_id);
    auto sdev = la_group.get_device();

    la_meter_set* meter = m_lpts_ipv4_meters[0];
    if (meter != nullptr) {
        meters.push_back(meter);
    }

    meter = m_lpts_ipv6_meters[0];
    if (meter != nullptr) {
        meters.push_back(meter);
    }

    // find all la events in the trap list of this trap group
    for (auto tt : m_trap_list) {
        auto& config = sdev->m_trap_manager->m_config_map[tt];
        if ((config.config_type != trap_config_type_e::EVENT && config.config_type != trap_config_type_e::L2CP)
            || config.trap == nullptr) {
            continue;
        }

        lsai_object la_oid(config.trap->m_oid);
        auto events = sdev->m_trap_manager->m_events_by_trap[(sai_hostif_trap_type_t)la_oid.index];
        for (auto ev : events) {
            meters.push_back(sdev->m_trap_manager->m_event_meters[ev]);
        }
    }
}

std::vector<la_meter_set*>
trap_manager::get_trap_group_meters(sai_object_id_t trap_group_id)
{
    lsai_object la_obj(trap_group_id);

    std::shared_ptr<trap_group> trap_group;
    la_status status = m_groups.get(la_obj.index, trap_group);

    std::vector<la_meter_set*> tg_meters;
    if (trap_group != nullptr) {
        trap_group->get_meters(tg_meters);
    }

    return tg_meters;
}

la_status
trap_manager::set_trap_group_admin_state(uint32_t group_index, bool admin_state)
{
    if (admin_state) {
        return LA_STATUS_SUCCESS;
    } else {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
}

la_status
trap_manager::set_trap_group_queue(uint32_t group_index, uint32_t queue_index)
{
    if (queue_index >= NUM_QUEUE_PER_PORT) {
        sai_log_error(SAI_API_HOSTIF, "Trap group queue %d out of range", queue_index);
        return LA_STATUS_EINVAL;
    }

    std::shared_ptr<trap_group> trap_group;
    la_status status = m_groups.get(group_index, trap_group);
    la_return_on_error(status);

    trap_group->update_queue(queue_index);

    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::update_trap_group_policer(uint32_t group_index, lasai_policer* new_policer)
{
    std::shared_ptr<trap_group> trap_group = nullptr;
    la_status status = m_groups.get(group_index, trap_group);
    la_return_on_error(status);

    trap_group->update_policer(new_policer);

    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::set_trap_group_policer(uint32_t group_index, sai_object_id_t policer_id)
{
    std::shared_ptr<trap_group> trap_group = nullptr;
    la_status status = m_groups.get(group_index, trap_group);
    la_return_on_error(status);

    trap_group->set_policer(policer_id);

    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::create_trap(sai_object_id_t oid, sai_packet_action_t action, la_uint_t priority, sai_object_id_t group_id)
{
    lsai_object la_oid(oid);
    auto trap_type = (sai_hostif_trap_type_t)la_oid.index;

    auto it = m_config_map.find(trap_type);
    if (it == m_config_map.end()) {
        // not supported trap_type
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    switch (it->second.config_type) {
    case trap_config_type_e::EVENT:
        m_config_map[trap_type].trap = std::unique_ptr<trap_base>(new trap_event(oid));
        break;
    case trap_config_type_e::L2CP:
        m_config_map[trap_type].trap = std::unique_ptr<trap_base>(new trap_l2cp(oid));
        break;
    case trap_config_type_e::IPV4:
        m_config_map[trap_type].trap = std::unique_ptr<trap_base>(new trap_lpts_v4(oid));
        break;
    case trap_config_type_e::IPV6:
        m_config_map[trap_type].trap = std::unique_ptr<trap_base>(new trap_lpts_v6(oid));
        break;
    case trap_config_type_e::IPV4_IPV6:
        m_config_map[trap_type].trap = std::unique_ptr<trap_base>(new trap_lpts_v4_v6(oid));
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    la_status status = m_config_map[trap_type].trap->initialize(action, priority, group_id);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::remove_trap(sai_hostif_trap_type_t trap_type)
{
    if (m_config_map[trap_type].trap != nullptr) {
        m_config_map[trap_type].trap->cleanup_snoop_configurations();
        m_config_map[trap_type].trap->cleanup_trap_configurations();
    }

    auto it = std::find(m_event_vec.begin(), m_event_vec.end(), trap_type);
    if (it != m_event_vec.end()) {
        m_event_vec.erase(it);
    }

    m_config_map[trap_type].trap = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::dump_default_trap_meter_stats()
{
    lsai_object la_group{};
    std::shared_ptr<trap_group> trap_group;
    m_groups.get(m_default_trap_group_id, trap_group, la_group);
    if (trap_group == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    size_t packets = 0, bytes = 0;
    if (trap_group->m_lpts_ipv4_meters[0] != nullptr) {
        trap_group->m_lpts_ipv4_meters[0]->read(0, false, false, la_qos_color_e::GREEN, packets, bytes);
        if (packets != 0 && bytes != 0) {
            printf("lpts packets %ld bytes %ld\n", packets, bytes);
        }
    }

    packets = 0;
    bytes = 0;
    if (trap_group->m_lpts_ipv6_meters[0] != nullptr) {
        trap_group->m_lpts_ipv6_meters[0]->read(0, false, false, la_qos_color_e::GREEN, packets, bytes);
        if (packets != 0 && bytes != 0) {
            printf("lpts packets %ld bytes %ld\n", packets, bytes);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::create_default_meter(la_meter_set*& meter)
{
    la_status status = m_sdev->m_dev->create_meter(la_meter_set::type_e::PER_IFG_EXACT, 1, meter);
    la_return_on_error(status);

    status = meter->set_committed_bucket_coupling_mode(0, la_meter_set::coupling_mode_e::TO_EXCESS_BUCKET);
    la_return_on_error(status);

    status = meter->set_meter_profile(0, m_sdev->m_policer_manager->get_bps_policer_profile());
    la_return_on_error(status);

    status = meter->set_meter_action_profile(0, m_sdev->m_policer_manager->get_meter_action_profile());
    la_return_on_error(status);

    for (la_slice_id_t slice_id = 0; slice_id < m_sdev->m_dev_params.slices_per_dev; slice_id++) {
        for (la_ifg_id_t ifg = 0; ifg < m_sdev->m_dev_params.ifgs_per_slice; ifg++) {
            la_slice_ifg slice_ifg{slice_id, ifg};
            status = meter->set_cir(0, slice_ifg, 10000000);
            la_return_on_error(status);

            status = meter->set_eir(0, slice_ifg, 10000000 * 2);
            la_return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

void
trap_manager::initialize_config_map()
{
    m_config_map[SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST].config_type = trap_config_type_e::EVENT;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE].config_type = trap_config_type_e::EVENT;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_LLDP].config_type = trap_config_type_e::L2CP;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_LACP].config_type = trap_config_type_e::L2CP;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_UDLD].config_type = trap_config_type_e::L2CP;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER].config_type = trap_config_type_e::EVENT;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY].config_type = trap_config_type_e::IPV6;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_IP2ME].config_type = trap_config_type_e::IPV4_IPV6;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_DHCP].config_type = trap_config_type_e::IPV4;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_DHCPV6].config_type = trap_config_type_e::IPV6;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_TTL_ERROR].config_type = trap_config_type_e::EVENT;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR].config_type = trap_config_type_e::EVENT;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_BGP].config_type = trap_config_type_e::IPV4;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_BGPV6].config_type = trap_config_type_e::IPV6;
    m_config_map[SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET].config_type = trap_config_type_e::EVENT;
}

void
trap_manager::initialize_events_by_trap()
{
    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST].push_back(LA_EVENT_ETHERNET_ARP);

    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE].push_back(LA_EVENT_ETHERNET_ARP);

    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_LACP].push_back(LA_EVENT_ETHERNET_LACP);

    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_LLDP].push_back(LA_EVENT_ETHERNET_L2CP0);

    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_TTL_ERROR].push_back(LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE);

    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR].push_back(LA_EVENT_L3_TX_MTU_FAILURE);

    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_UDLD].push_back(LA_EVENT_ETHERNET_CISCO_PROTOCOLS);

    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER].push_back(LA_EVENT_IPV4_CHECKSUM);

    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET].push_back(LA_EVENT_L3_INGRESS_MONITOR);
    m_events_by_trap[SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET].push_back(LA_EVENT_L3_EGRESS_MONITOR);
}

void
trap_manager::initialize_trap_type_punt_code_map()
{
    m_trap_type_by_punt_code.push_back(SAI_HOSTIF_TRAP_TYPE_IP2ME); // 0
    m_trap_type_by_punt_code.push_back(SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY);
    m_trap_type_by_punt_code.push_back(SAI_HOSTIF_TRAP_TYPE_BGP);
    m_trap_type_by_punt_code.push_back(SAI_HOSTIF_TRAP_TYPE_BGPV6);
    m_trap_type_by_punt_code.push_back(SAI_HOSTIF_TRAP_TYPE_DHCP);
    m_trap_type_by_punt_code.push_back(SAI_HOSTIF_TRAP_TYPE_DHCPV6);

    m_punt_code_by_trap_type[SAI_HOSTIF_TRAP_TYPE_IP2ME] = punt_code_e::IP2ME;
    m_punt_code_by_trap_type[SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY] = punt_code_e::V6_NEIGHBOR_DISCOVERY;
    m_punt_code_by_trap_type[SAI_HOSTIF_TRAP_TYPE_BGP] = punt_code_e::BGP;
    m_punt_code_by_trap_type[SAI_HOSTIF_TRAP_TYPE_BGPV6] = punt_code_e::BGPV6;
    m_punt_code_by_trap_type[SAI_HOSTIF_TRAP_TYPE_DHCP] = punt_code_e::DHCP;
    m_punt_code_by_trap_type[SAI_HOSTIF_TRAP_TYPE_DHCPV6] = punt_code_e::DHCPV6;
}

// this table initialize event_code to trap type
// for trap type to event (is many to one) see config_map
void
trap_manager::initialize_trap_type_event_code_map()
{
    m_trap_type_by_event_code[LA_EVENT_ETHERNET_ARP] = SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST;
    m_trap_type_by_event_code[LA_EVENT_ETHERNET_L2CP0] = SAI_HOSTIF_TRAP_TYPE_LLDP;
    m_trap_type_by_event_code[LA_EVENT_ETHERNET_LACP] = SAI_HOSTIF_TRAP_TYPE_LACP;
    m_trap_type_by_event_code[LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE] = SAI_HOSTIF_TRAP_TYPE_TTL_ERROR;
    m_trap_type_by_event_code[LA_EVENT_L3_TX_MTU_FAILURE] = SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR;
    m_trap_type_by_event_code[LA_EVENT_ETHERNET_CISCO_PROTOCOLS] = SAI_HOSTIF_TRAP_TYPE_UDLD;
    m_trap_type_by_event_code[LA_EVENT_IPV4_CHECKSUM] = SAI_HOSTIF_TRAP_TYPE_PIPELINE_DISCARD_ROUTER;
    m_trap_type_by_event_code[LA_EVENT_L3_INGRESS_MONITOR] = SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET;
    m_trap_type_by_event_code[LA_EVENT_L3_EGRESS_MONITOR] = SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET;
}

//
// initialize m_lpts_trap_info table
//
void
trap_manager::initialize_lpts_info_map()
{
    // for IPV6
    //
    int idx = (int)lpts_type_e::LPTS_TYPE_IPV6;

    // for SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY default drop
    la_lpts_key key = {};
    key.type = lpts_type_e::LPTS_TYPE_IPV6;
    key.val.ipv6.protocol = la_l4_protocol_e::IPV6_ICMP;
    key.mask.ipv6.protocol = la_l4_protocol_e::RESERVED;
    // ICMP type 133-137 are NDP
    key.val.ipv6.ports.sport = 133 << 8;
    key.mask.ipv6.ports.sport = 0xff00;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY].push_back(key);

    key.val.ipv6.ports.sport = 134 << 8;
    key.mask.ipv6.ports.sport = 0xfe00;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY].push_back(key);

    key.val.ipv6.ports.sport = 136 << 8;
    key.mask.ipv6.ports.sport = 0xfe00;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY].push_back(key);

    // for SAI_HOSTIF_TRAP_TYPE_IP2ME default drop
    key = {};
    key.type = lpts_type_e::LPTS_TYPE_IPV6;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_IP2ME].push_back(key);

    // for SAI_HOSTIF_TRAP_TYPE_BGPV6
    key = {};
    key.type = lpts_type_e::LPTS_TYPE_IPV6;
    key.val.ipv6.protocol = la_l4_protocol_e::TCP;
    key.mask.ipv6.protocol = la_l4_protocol_e::RESERVED;
    key.val.ipv6.ports.dport = 179;
    key.mask.ipv6.ports.dport = 0xFFFF;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_BGPV6].push_back(key);

    key = {};
    key.type = lpts_type_e::LPTS_TYPE_IPV6;
    key.val.ipv6.protocol = la_l4_protocol_e::TCP;
    key.mask.ipv6.protocol = la_l4_protocol_e::RESERVED;
    key.val.ipv6.ports.sport = 179;
    key.mask.ipv6.ports.sport = 0xFFFF;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_BGPV6].push_back(key);

    // for SAI_HOSTIF_TRAP_TYPE_DHCPV6 default drop
    key = {};
    key.type = lpts_type_e::LPTS_TYPE_IPV6;
    key.val.ipv6.protocol = la_l4_protocol_e::UDP;
    // todo: This makes test_trap_lpts.py fail on DHCPV6 packets
    // key.mask.ipv6.protocol = la_l4_protocol_e::RESERVED;
    key.val.ipv6.ports.dport = 67;
    key.mask.ipv6.ports.dport = 0xFFFF;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_DHCPV6].push_back(key);
    key.val.ipv6.ports.dport = 68;
    key.mask.ipv6.ports.dport = 0xFFFF;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_DHCPV6].push_back(key);

    //
    // for IPV4
    //
    idx = (int)lpts_type_e::LPTS_TYPE_IPV4;

    // for SAI_HOSTIF_TRAP_TYPE_BGP
    key = {};
    key.type = lpts_type_e::LPTS_TYPE_IPV4;
    key.val.ipv4.protocol = la_l4_protocol_e::TCP;
    key.val.ipv4.ports.dport = 179;
    key.mask.ipv4.protocol = la_l4_protocol_e::RESERVED;
    key.mask.ipv4.ports.dport = 0xFFFF;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_BGP].push_back(key);

    key = {};
    key.type = lpts_type_e::LPTS_TYPE_IPV4;
    key.val.ipv4.protocol = la_l4_protocol_e::TCP;
    key.val.ipv4.ports.sport = 179;
    key.mask.ipv4.protocol = la_l4_protocol_e::RESERVED;
    key.mask.ipv4.ports.sport = 0xFFFF;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_BGP].push_back(key);

    // for SAI_HOSTIF_TRAP_TYPE_IP2ME default drop
    key = {};
    key.type = lpts_type_e::LPTS_TYPE_IPV4;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_IP2ME].push_back(key);

    // for SAI_HOSTIF_TRAP_TYPE_DHCP default drop
    key = {};
    key.type = lpts_type_e::LPTS_TYPE_IPV4;
    key.val.ipv4.protocol = la_l4_protocol_e::UDP;
    key.mask.ipv4.protocol = la_l4_protocol_e::RESERVED;
    key.val.ipv4.ports.dport = 67;
    key.mask.ipv4.ports.dport = 0xFFFF;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_DHCP].push_back(key);
    key.val.ipv4.ports.dport = 68;
    key.mask.ipv4.ports.dport = 0xFFFF;
    m_lpts_info_map[idx][SAI_HOSTIF_TRAP_TYPE_DHCP].push_back(key);
}

// initialze static data, that we don't need to save/restore during warm boot
void
trap_manager::initialize_warm()
{
    initialize_config_map();
    initialize_trap_type_punt_code_map();
    initialize_trap_type_event_code_map();
    initialize_lpts_info_map();
    initialize_events_by_trap();
}

la_status
trap_manager::initialize()
{
    la_status status = LA_STATUS_SUCCESS;

    initialize_warm();

    la_lpts* lpts_ptr = nullptr;
    status = m_sdev->m_dev->create_lpts(lpts_type_e::LPTS_TYPE_IPV4, lpts_ptr);
    la_return_on_error(status);
    m_lpts_ptrs[(int)lpts_type_e::LPTS_TYPE_IPV4] = lpts_ptr;

    lpts_ptr = nullptr;
    status = m_sdev->m_dev->create_lpts(lpts_type_e::LPTS_TYPE_IPV6, lpts_ptr);
    la_return_on_error(status);
    m_lpts_ptrs[(int)lpts_type_e::LPTS_TYPE_IPV6] = lpts_ptr;

    status = create_trap_group(m_default_trap_group_id, true, 0, SAI_NULL_OBJECT_ID);
    la_return_on_error(status, "fail to create default trap groups");
    // Ignore the object we created in get_object_count/key
    m_groups.set_ignore_in_get_num(1);

    for (auto& it : m_events_by_trap) {
        for (auto ev : it.second) {
            la_meter_set* meter = nullptr;
            status = create_statistical_policer(meter, &m_default_policer);
            la_return_on_error(status);
            m_event_meters[ev] = meter;
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::add_mirror_id_to_type_map(uint32_t id, sai_hostif_trap_type_t trap_type)
{
    if (id != INVALID_MIRROR_ID) {
        m_trap_type_by_mirror_id[id] = trap_type;
        return LA_STATUS_SUCCESS;
    }
    return LA_STATUS_EINVAL;
}

la_status
trap_manager::remove_mirror_id_from_type_map(uint32_t id)
{
    if (m_trap_type_by_mirror_id.count(id) == 0) {
        return LA_STATUS_EINVAL;
    }

    m_trap_type_by_mirror_id.erase(id);
    return LA_STATUS_SUCCESS;
}

la_status
trap_manager::get_trap_base_id(uint32_t sw_id, uint8_t code, uint8_t source, sai_object_id_t& trap_obj, bool& action_cont)
{
    sai_hostif_trap_type_t trap_type;

    action_cont = true;
    switch (source) {
    case NPL_PUNT_SRC_LPTS_FORWARDING: {
        if (code >= (int)punt_code_e::LAST) {
            la_return_on_error(LA_STATUS_EUNKNOWN, "Invalid punt code %u", code);
        }
        trap_type = m_trap_type_by_punt_code[code];
    } break;
    case NPL_PUNT_SRC_INBOUND_MIRROR:
    case NPL_PUNT_SRC_OUTBOUND_MIRROR: {
        if (m_trap_type_by_mirror_id.count(code) == 0) {
            // do not always print it in the punt path
            sai_log_info(SAI_API_HOSTIF, "Invalid mirror ID, possible ACL COPY %u", code);
            return LA_STATUS_EUNKNOWN;
        }
        trap_type = m_trap_type_by_mirror_id[code];
    } break;
    case NPL_PUNT_SRC_SNOOP:
    case NPL_PUNT_SRC_INGRESS_ACL:
    case NPL_PUNT_SRC_INGRESS_TRAP:
    case NPL_PUNT_SRC_INGRESS_INCOMPLETE:
    case NPL_PUNT_SRC_INGRESS_BFD:
    case NPL_PUNT_SRC_EGRESS_ACL:
    case NPL_PUNT_SRC_EGRESS_TRAP:
    case NPL_PUNT_SRC_ERROR:
    case NPL_PUNT_SRC_LC:
    case NPL_PUNT_SRC_RSP:
    case NPL_PUNT_SRC_NPUH: {
        auto ecode = static_cast<la_event_e>(code);
        if (m_trap_type_by_event_code.count(ecode) == 0) {
            la_return_on_error(LA_STATUS_EUNKNOWN, "Invalid trap event code %u", code);
        }
        trap_type = m_trap_type_by_event_code[ecode];
        if (ecode == LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE) {
            action_cont = false;
        }
    } break;
    default:
        la_return_on_error(LA_STATUS_EUNKNOWN, "Invalid punt source %u", source);
    }

    lsai_object la_obj(SAI_OBJECT_TYPE_HOSTIF_TRAP, sw_id, ((int)trap_type));
    trap_obj = la_obj.object_id();
    return LA_STATUS_SUCCESS;
}

sai_status_t
trap_manager::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    *count = 0;

    for (auto& element : m_config_map) {
        if (element.second.trap != nullptr) {
            (*count)++;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
trap_manager::get_object_keys(std::shared_ptr<lsai_device> sdev, uint32_t* object_count, sai_object_key_t* object_list) const
{
    uint32_t object_index = 0;
    lsai_object la_obj(SAI_OBJECT_TYPE_HOSTIF_TRAP, sdev->m_switch_id, 0);
    uint32_t requested_object_count = *object_count;
    *object_count = 0;

    sdev->m_trap_manager->get_object_count(sdev, object_count);

    if (requested_object_count < *object_count) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    for (auto trap_iter = m_config_map.begin(); trap_iter != m_config_map.end(); trap_iter++) {
        if (trap_iter->second.trap != nullptr) {
            la_obj.index = trap_iter->first;
            object_list[object_index].key.object_id = la_obj.object_id();
            object_index++;
        }
    }

    return SAI_STATUS_SUCCESS;
}

void
trap_group::clear()
{
    SAI_GET_TRAP_SDEV_VOID_RETURN(m_group_id);

    // move all the traps to the defaults
    for (auto tt : m_trap_list) {
        auto& trap = sdev->m_trap_manager->m_config_map[tt].trap;
        if (trap != nullptr) {
            trap->update_group(sdev->m_trap_manager->m_default_trap_group_id);
        }
    }

    if (m_policer_id != SAI_NULL_OBJECT_ID) {
        sdev->m_policer_manager->unbind_policer(m_group_id, m_policer_id);
        m_policer_id = SAI_NULL_OBJECT_ID;
    }
}

la_status
trap_group::initialize(std::shared_ptr<lsai_device>& sdev)
{

    return update_policer(&(sdev->m_trap_manager->m_default_policer));
}

trap_group::~trap_group()
{
    lsai_object la_group(m_group_id);
    auto sdev = la_group.get_device();
    if (sdev != nullptr) {
        for (auto meter : m_lpts_ipv4_meters) {
            sdev->destroy_la_object(meter);
        }

        for (auto meter : m_lpts_ipv6_meters) {
            sdev->destroy_la_object(meter);
        }
    }
}

la_status
trap_group::add_trap(sai_hostif_trap_type_t trap_type)
{

    if (std::find(m_trap_list.begin(), m_trap_list.end(), trap_type) == m_trap_list.end()) {
        m_trap_list.push_back(trap_type);
    }

    return LA_STATUS_SUCCESS;
}

void
trap_group::remove_trap(sai_hostif_trap_type_t trap_type)
{
    auto it = std::find(m_trap_list.begin(), m_trap_list.end(), trap_type);
    if (it != m_trap_list.end()) {
        m_trap_list.erase(it);
    }
}

la_status
trap_group::update_queue(uint32_t queue_index)
{
    if (m_tc == queue_index) {
        return LA_STATUS_SUCCESS;
    }

    SAI_GET_TRAP_SDEV(m_group_id);

    m_tc = queue_index;

    la_status status;
    for (auto tt : m_trap_list) {
        auto& ctrap = sdev->m_trap_manager->m_config_map[tt];
        if (ctrap.trap != nullptr) {
            status = ctrap.trap->update_group(m_group_id);
            la_return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

// once a trap group is created, 3 different la_meter_set are created
// two for lpts and one for event.
// The sai policer can only change the trap group meter's cir and eir.

la_status
trap_group::set_policer(sai_object_id_t policer_id)
{
    if (m_policer_id == policer_id) {
        return LA_STATUS_SUCCESS;
    }

    lsai_object la_new(policer_id);
    auto sdev = la_new.get_device();

    lasai_policer* new_policer = nullptr;
    if (policer_id != SAI_NULL_OBJECT_ID) {
        new_policer = sdev->m_policer_manager->m_policer_db.get_ptr(la_new.index);
    }

    transaction txn;
    // change original policer binding from m_policer_id to nullptr
    txn.status = sdev->m_policer_manager->unbind_policer(m_group_id, m_policer_id);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { sdev->m_policer_manager->bind_policer(m_group_id, m_policer_id); });

    // change trap group meters to the new_policer spec.
    txn.status = update_policer(new_policer);
    la_return_on_error(txn.status);
    txn.on_fail([=]() {
        lasai_policer* old_policer = nullptr;
        if (m_policer_id != SAI_NULL_OBJECT_ID) {
            lsai_object la_old(m_policer_id);
            sdev->m_policer_manager->m_policer_db.get_ptr(la_old.index);
        }
        update_policer(old_policer);
    });

    // change all the trapsin the group to new_policer
    txn.status = sdev->m_policer_manager->bind_policer(m_group_id, policer_id);
    la_return_on_error(txn.status);

    m_policer_id = policer_id;

    return LA_STATUS_SUCCESS;
}

trap_base::~trap_base()
{
}

sai_packet_action_t
trap_base::get_action() const
{
    return m_action;
}

uint32_t
trap_base::get_priority() const
{
    return m_priority;
}

sai_object_id_t
trap_base::get_group() const
{
    return m_group_id;
}

trap_event::~trap_event()
{
}

la_status
trap_event::initialize(sai_packet_action_t action, uint32_t priority, sai_object_id_t group_id)
{
    SAI_GET_TRAP_SDEV(m_oid);

    set_priority(priority);

    m_action = action;
    m_group_id = (group_id == SAI_NULL_OBJECT_ID) ? sdev->m_trap_manager->m_default_trap_group_id : group_id;

    lsai_object la_group{};
    std::shared_ptr<trap_group> trap_group;

    la_status status = sdev->m_trap_manager->m_groups.get(m_group_id, trap_group, la_group);
    la_return_on_error(status);

    status = trap_group->add_trap((sai_hostif_trap_type_t)la_oid.index);
    la_return_on_error(status);

    return update();
}

la_status
trap_event::create_mirror_cmd()
{
    SAI_GET_TRAP_SDEV(m_oid);

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    txn.status = sdev->m_mirror_handler->allocate_mirror_session_instance(m_mirror_id);
    la_return_on_error(txn.status);
    txn.on_fail([=]() {
        sdev->m_mirror_handler->free_mirror_session_instance(m_mirror_id);
        m_mirror_id = INVALID_MIRROR_ID;
    });

    // create mirror cmd
    la_mac_addr_t mac_addr{.flat = 0x0a0b0c0d0e0fULL};
    float probability = 1;
    la_vlan_tag_tci_t vlan_tag{};
    la_uint_t voq_offset = 1;

    la_l2_mirror_command* mirror_cmd = nullptr;
    la_uint64_t out_limit;
    la_status status = sdev->m_dev->get_limit(limit_type_e::DEVICE__MIN_INGRESS_MIRROR_GID, out_limit);
    status = sdev->m_dev->create_l2_mirror_command(m_mirror_id + out_limit,
                                                   (la_punt_inject_port*)sdev->m_punt_inject_port,
                                                   mac_addr,
                                                   vlan_tag,
                                                   voq_offset,
                                                   nullptr,
                                                   probability,
                                                   mirror_cmd);
    la_return_on_error(status);

    if (m_mirror_id != INVALID_MIRROR_ID) {
        sdev->m_trap_manager->m_trap_type_by_mirror_id[m_mirror_id + out_limit] = (sai_hostif_trap_type_t)la_oid.index;
        sdev->m_trap_manager->m_snoop_l2_mirror_cmd[m_mirror_id] = mirror_cmd;
    }

    return LA_STATUS_SUCCESS;
}

la_uint_t
trap_event::get_la_priority()
{
    lsai_object la_oid(m_oid);
    auto sdev = la_oid.get_device();
    if (sdev == nullptr || sdev->m_trap_manager == nullptr) {
        return (la_uint_t)LA_EVENT_INTERNAL_LAST;
    }

    auto& event_vec = sdev->m_trap_manager->m_event_vec;
    auto it = std::find(event_vec.begin(), event_vec.end(), (sai_hostif_trap_type_t)la_oid.index);
    if (it != event_vec.end()) {
        return std::distance(event_vec.begin(), it);
    }
    return event_vec.size();
}

void
trap_event::set_priority(uint32_t priority)
{
    SAI_GET_TRAP_SDEV_VOID_RETURN(m_oid);

    auto& event_vec = sdev->m_trap_manager->m_event_vec;

    auto current_location = std::find(event_vec.begin(), event_vec.end(), (sai_hostif_trap_type_t)la_oid.index);

    auto new_location = std::partition_point(event_vec.begin(), event_vec.end(), [=](sai_hostif_trap_type_t event) {
        return priority < sdev->m_trap_manager->m_config_map[event].trap->m_priority;
    });

    m_priority = priority;

    sai_log_debug(SAI_API_HOSTIF, "event priority new location %d", std::distance(event_vec.begin(), new_location));

    if (current_location == event_vec.end()) {
        event_vec.insert(new_location, (sai_hostif_trap_type_t)la_oid.index);
    } else if (current_location < new_location) {
        std::rotate(current_location, current_location + 1, new_location);
    } else {
        std::rotate(new_location, current_location, current_location + 1);
    }
}

// update action, priority and group in hardware for the event trap
la_status
trap_event::update()
{
    SAI_GET_TRAP_SDEV(m_oid);

    la_uint_t la_priority = get_la_priority();
    la_punt_destination* punt_dest = (la_punt_destination*)(la_l2_punt_destination*)sdev->m_punt_dest;
    auto events = sdev->m_trap_manager->m_events_by_trap[(sai_hostif_trap_type_t)la_oid.index];
    la_counter_set* counter_set = nullptr;
    la_meter_set* meter = nullptr;

    lsai_object la_group{};
    std::shared_ptr<trap_group> trap_group;
    la_status status = sdev->m_trap_manager->m_groups.get(m_group_id, trap_group, la_group);
    la_return_on_error(status);

    switch (m_action) {
    case SAI_PACKET_ACTION_DROP:
    case SAI_PACKET_ACTION_DENY: {
        cleanup_snoop_configurations();

        la_status status;
        for (auto ev : events) {
            counter_set = sdev->m_event_counters[ev];
            status = sdev->m_dev->set_trap_configuration(ev, la_priority, counter_set, nullptr, false, false, true, 0);
            la_return_on_error(status);
        }
        break;
    }

    case SAI_PACKET_ACTION_COPY_CANCEL:
    case SAI_PACKET_ACTION_FORWARD:
    case SAI_PACKET_ACTION_TRANSIT: {
        cleanup_snoop_configurations();
        cleanup_trap_configurations();
        break;
    }

    case SAI_PACKET_ACTION_TRAP: {
        cleanup_snoop_configurations();

        for (auto ev : events) {
            counter_set = sdev->m_event_counters[ev];

            la_meter_set* meter = sdev->m_trap_manager->m_event_meters[ev];
            auto counter_meter = (meter == nullptr) ? static_cast<la_counter_or_meter_set*>(counter_set)
                                                    : static_cast<la_counter_or_meter_set*>(meter);
            status = sdev->m_dev->set_trap_configuration(
                ev, la_priority, counter_meter, punt_dest, true, false, true, trap_group->m_tc);
            la_return_on_error(status);
        }
        break;
    }

    case SAI_PACKET_ACTION_COPY:
    case SAI_PACKET_ACTION_LOG: {
        la_status status;

        if (m_mirror_id == INVALID_MIRROR_ID) {
            status = create_mirror_cmd();
            la_return_on_error(status);
        }

        la_obj_wrap<la_l2_mirror_command> mirror_cmd;
        if (m_mirror_id != INVALID_MIRROR_ID) {
            mirror_cmd = sdev->m_trap_manager->m_snoop_l2_mirror_cmd[m_mirror_id];
        }

        cleanup_trap_configurations();

        if (mirror_cmd) {
            if (meter != nullptr) {
                status = mirror_cmd->set_meter(meter);
                la_return_on_error(status);
            }
            status = mirror_cmd->set_voq_offset(trap_group->m_tc);
            la_return_on_error(status);
        }

        for (auto ev : events) {
            // ignore the status for clear_trap
            status = sdev->m_dev->set_snoop_configuration(ev, (la_snoop_priority_t)la_priority, false, false, mirror_cmd);
            la_return_on_error(status);
        }
        break;
    }
    default:
        break;
    }

    return LA_STATUS_SUCCESS;
}

void
trap_event::cleanup_snoop_configurations()
{
    SAI_GET_TRAP_SDEV_VOID_RETURN(m_oid);

    if (!sdev->sdk_operations_allowed()) {
        return;
    }

    if (m_mirror_id != INVALID_MIRROR_ID) {
        // clear snoop before removing the mirror
        auto events = sdev->m_trap_manager->m_events_by_trap[(sai_hostif_trap_type_t)la_oid.index];
        for (auto ev : events) {
            sdev->m_dev->clear_snoop_configuration(ev);
        }

        la_obj_wrap<la_l2_mirror_command> mirror_cmd;
        mirror_cmd = sdev->m_trap_manager->m_snoop_l2_mirror_cmd[m_mirror_id];
        sdev->m_trap_manager->m_snoop_l2_mirror_cmd.erase(m_mirror_id);
        if (mirror_cmd != nullptr) {
            sdev->m_mirror_handler->free_mirror_session_instance(m_mirror_id);
            sdev->destroy_la_object(mirror_cmd);
        }
        m_mirror_id = INVALID_MIRROR_ID;
    }
}

void
trap_event::cleanup_trap_configurations()
{
    SAI_GET_TRAP_SDEV_VOID_RETURN(m_oid);

    if (!sdev->sdk_operations_allowed()) {
        return;
    }

    auto events = sdev->m_trap_manager->m_events_by_trap[(sai_hostif_trap_type_t)la_oid.index];
    // in warmboot shutdown m_dev might by NULL
    for (auto ev : events) {
        sdev->m_dev->clear_trap_configuration(ev);
    }
}

la_status
trap_event::update_action(sai_packet_action_t action)
{
    if (m_action == action) {
        return LA_STATUS_SUCCESS;
    }

    m_action = action;

    return update();
}

la_status
trap_event::update_priority(uint32_t priority)
{
    set_priority(priority);

    return update();
}

la_status
trap_event::update_group(sai_object_id_t group_id)
{
    SAI_GET_TRAP_SDEV(m_oid);

    lsai_object la_new_group(group_id);
    std::shared_ptr<trap_group> new_trap_group;
    la_status status = sdev->m_trap_manager->m_groups.get(group_id, new_trap_group, la_new_group);
    la_return_on_error(status);

    lsai_object la_old_group(m_group_id);
    std::shared_ptr<trap_group> old_trap_group;
    status = sdev->m_trap_manager->m_groups.get(m_group_id, old_trap_group, la_old_group);
    la_return_on_error(status);

    if (group_id != m_group_id) {
        old_trap_group->remove_trap((sai_hostif_trap_type_t)la_oid.index);

        status = new_trap_group->add_trap((sai_hostif_trap_type_t)la_oid.index);
        la_return_on_error(status);

        m_group_id = group_id;
    }

    return update();
}

la_status
trap_group::update_policer(lasai_policer* new_policer)
{
    // trap group always has meter defined regardless with or without policer assigned
    // la_meter_set profiles can not be changed but the cir and pir can be changed
    lsai_object la_group(m_group_id);
    auto sdev = la_group.get_device();

    if (new_policer == nullptr) {
        return LA_STATUS_EINVAL;
    }

    // if the group is new assigned the policers
    if (m_lpts_ipv4_meters[0] == nullptr) {
        // create lpts default meter

        la_status status = LA_STATUS_SUCCESS;

        status = sdev->m_trap_manager->create_default_meter(m_lpts_ipv4_meters[0]);
        la_return_on_error(status);

        status = sdev->m_trap_manager->create_default_meter(m_lpts_ipv6_meters[0]);
        la_return_on_error(status);

        // statistical is packet only now to do test byte in future
        status = sdev->m_trap_manager->create_statistical_policer(m_lpts_ipv4_meters[1], new_policer);
        la_return_on_error(status);

        status = sdev->m_trap_manager->create_statistical_policer(m_lpts_ipv6_meters[1], new_policer);
        la_return_on_error(status);

        return status;
    }

    la_status status = m_lpts_ipv4_meters[1]->set_cir(0, new_policer->m_cir);
    la_return_on_error(status);

    status = m_lpts_ipv4_meters[1]->set_eir(0, new_policer->m_pir + new_policer->m_cir);
    la_return_on_error(status);

    status = m_lpts_ipv6_meters[1]->set_cir(0, new_policer->m_cir);
    la_return_on_error(status);

    status = m_lpts_ipv6_meters[1]->set_eir(0, new_policer->m_pir + new_policer->m_cir);
    la_return_on_error(status);

    for (auto tt : m_trap_list) {
        auto& config = sdev->m_trap_manager->m_config_map[tt];
        if (config.config_type != trap_config_type_e::EVENT && config.config_type != trap_config_type_e::L2CP) {
            continue;
        }

        if (config.trap == nullptr) {
            continue;
        }

        lsai_object la_oid(config.trap->m_oid);
        auto events = sdev->m_trap_manager->m_events_by_trap[(sai_hostif_trap_type_t)la_oid.index];
        for (auto ev : events) {
            la_meter_set* meter = sdev->m_trap_manager->m_event_meters[ev];
            la_status status = meter->set_cir(0, new_policer->m_cir);
            la_return_on_error(status);

            status = meter->set_eir(0, new_policer->m_pir + new_policer->m_cir);
            la_return_on_error(status);
        }
    }

    return status;
}

la_status
trap_manager::create_statistical_policer(la_meter_set*& meter, lasai_policer* new_policer)
{
    transaction txn;

    // create new meter
    txn.status = m_sdev->m_dev->create_meter(la_meter_set::type_e::STATISTICAL, 1, meter);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_sdev->m_dev->destroy(meter); });
    txn.status = meter->set_committed_bucket_coupling_mode(0, la_meter_set::coupling_mode_e::TO_EXCESS_BUCKET);
    la_return_on_error(txn.status);

    txn.status = meter->set_meter_profile(0, m_sdev->m_policer_manager->get_meter_profile(new_policer));
    la_return_on_error(txn.status);

    txn.status = meter->set_meter_action_profile(0, m_sdev->m_policer_manager->get_meter_action_profile());
    la_return_on_error(txn.status);

    meter->set_cir(0, new_policer->m_cir);
    la_return_on_error(txn.status);

    meter->set_eir(0, new_policer->m_pir + new_policer->m_cir);
    la_return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

trap_l2cp::~trap_l2cp()
{
    lsai_object la_oid(m_oid);
    auto sdev = la_oid.get_device();

    // in warmboot shutdown m_dev might by nullptr
    if (sdev != nullptr && sdev->m_dev != nullptr) {
        if (sdev->m_trap_manager) {
            auto& events = sdev->m_trap_manager->m_events_by_trap[(sai_hostif_trap_type_t)la_oid.index];
            la_event_e event = events[0];
            size_t entry_count;
            sdev->m_copc_mac->get_count(entry_count);

            for (size_t index = 0; index < entry_count; index++) {
                la_control_plane_classifier::entry_desc entry;
                sdev->m_copc_mac->get(index, entry);
                if (entry.result.event == event) {
                    sdev->m_copc_mac->pop(index);
                    break;
                }
            }
        } else {
            // Called as result of m_trap_manager destructor
            sdev->m_copc_mac->clear();
        }
    }
}

la_status
trap_l2cp::initialize(sai_packet_action_t action, uint32_t priority, sai_object_id_t group_id)
{
    SAI_GET_TRAP_SDEV(m_oid);

    m_priority = priority;
    m_action = action;
    m_group_id = (group_id == SAI_NULL_OBJECT_ID) ? sdev->m_trap_manager->m_default_trap_group_id : group_id;

    auto& events = sdev->m_trap_manager->m_events_by_trap[(sai_hostif_trap_type_t)la_oid.index];
    la_event_e event = events[0];

    la_control_plane_classifier::key key;
    la_control_plane_classifier::result result;
    la_control_plane_classifier::field field;

    result.event = event;

    field.type.mac = la_control_plane_classifier::mac_field_type_e::ETHERNET_PROFILE_ID;
    field.val.mac.ethernet_profile_id = LSAI_L2CP_PROFILE;
    field.mask.mac.ethernet_profile_id = LSAI_L2CP_PROFILE;
    key.push_back(field);

    switch (event) {
    case LA_EVENT_ETHERNET_L2CP0:
        // LLDP (Link layer discovery protocol)
        field.type.mac = la_control_plane_classifier::mac_field_type_e::ETHERTYPE;
        field.val.mac.ethertype = 0x88cc;
        field.mask.mac.ethertype = 0xffff;
        key.push_back(field);

        field.type.mac = la_control_plane_classifier::mac_field_type_e::DA;
        field.val.mac.da.flat = 0x0180c2000000;
        field.mask.mac.da.flat = 0xffffffffff00;
        key.push_back(field);
        break;
    case LA_EVENT_ETHERNET_LACP:
        // LACP
        field.type.mac = la_control_plane_classifier::mac_field_type_e::ETHERTYPE;
        field.val.mac.ethertype = 0x8809;
        field.mask.mac.ethertype = 0xffff;
        key.push_back(field);

        field.type.mac = la_control_plane_classifier::mac_field_type_e::DA;
        field.val.mac.da.flat = 0x0180c2000000;
        field.mask.mac.da.flat = 0xffffffffff00;
        key.push_back(field);
        break;
    case LA_EVENT_ETHERNET_CISCO_PROTOCOLS:
        field.type.mac = la_control_plane_classifier::mac_field_type_e::DA;
        field.val.mac.da.flat = 0x01000ccccccc;
        field.mask.mac.da.flat = 0xffffffffffff;
        key.push_back(field);
        break;
    default:
        // We can't get here
        return LA_STATUS_SUCCESS;
    };

    la_status status = sdev->m_copc_mac->append(key, result);
    la_return_on_error(status);

    m_key = key;
    return trap_event::initialize(action, priority, group_id);
}

//
// for LPTS
// DROP, DENY, COPY_CANCEL and TRANSIT, FORWARD not to cpu
// TRAP, COPY and LOG are to cpu
//
// all lpts ignore priority
//

la_status
trap_lpts::insert_tcam(lpts_type_e ip_type, la_uint_t hw_dist, la_lpts_result& result)
{
    SAI_GET_TRAP_SDEV(m_oid);

    auto& lpts_info = sdev->m_trap_manager->m_lpts_info_map[(int)ip_type];
    auto& lpts_ptr = sdev->m_trap_manager->m_lpts_ptrs[(int)ip_type];
    auto key_list = lpts_info[(sai_hostif_trap_type_t)la_oid.index]; // vector la_lpts_key

    transaction txn = {};
    for (auto key : key_list) {
        txn.status = lpts_ptr->push(hw_dist, key, result);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { lpts_ptr->pop(hw_dist); });
        hw_dist++;
    }

    return txn.status;
}

void
trap_lpts::remove_tcam(lpts_type_e ip_type, la_uint_t hw_dist)
{
    SAI_GET_TRAP_SDEV_VOID_RETURN(m_oid);

    auto& lpts_info = sdev->m_trap_manager->m_lpts_info_map[(int)ip_type];
    auto& lpts_ptr = sdev->m_trap_manager->m_lpts_ptrs[(int)ip_type];

    la_uint_t size = lpts_info[(sai_hostif_trap_type_t)la_oid.index].size(); // vector la_lpts_key

    for (la_uint_t i = 0; i < size; i++) {
        lpts_ptr->pop(hw_dist);
    }

    return;
}

//
// find_lpts : go through m_lpts_vec list to find if exist
// if found the ip_type, then
//      the pos is the location of the ip_type
//      return success
// if not found then
//      the pos is the location of the ip_type to insert
//      the hw_dist is the tcam line location
//      return not found
la_status
trap_lpts::find_lpts(lpts_type_e ip_type, uint32_t& pos, uint32_t& hw_dist)
{
    SAI_GET_TRAP_SDEV(m_oid);

    auto& lpts_info = sdev->m_trap_manager->m_lpts_info_map[(int)ip_type];
    auto& lpts_vec = sdev->m_trap_manager->m_lpts_vec[(int)ip_type];

    uint32_t idx = 0, new_pos = 0, new_hw_dist = 0;
    auto size = lpts_vec.size();

    hw_dist = 0;

    sai_hostif_trap_type_t trap_type = SAI_HOSTIF_TRAP_TYPE_END;
    for (idx = 0; idx < size; idx++) {
        trap_type = lpts_vec[idx];
        if (trap_type == (sai_hostif_trap_type_t)la_oid.index) {
            break;
        }

        auto lpts_trap = static_cast<trap_lpts*>(sdev->m_trap_manager->m_config_map[trap_type].trap.get());
        if (lpts_trap && lpts_trap->m_priority > m_priority) {
            new_pos = idx + 1;
        }

        if (lpts_trap && lpts_trap->m_punt_dest != nullptr) {
            hw_dist += lpts_info[trap_type].size();
            if (lpts_trap->m_priority > m_priority) {
                new_hw_dist += lpts_info[trap_type].size();
            }
        }
    }

    pos = idx;
    if (trap_type == (sai_hostif_trap_type_t)la_oid.index) {
        return LA_STATUS_SUCCESS;
    }

    pos = new_pos;
    hw_dist = new_hw_dist;
    return LA_STATUS_ENOTFOUND;
}

la_status
trap_lpts::insert(lpts_type_e ip_type)
{
    SAI_GET_TRAP_SDEV(m_oid);

    uint32_t pos = 0, hw_dist = 0;
    la_status status = find_lpts(ip_type, pos, hw_dist);

    if (status == LA_STATUS_SUCCESS) {
        return LA_STATUS_SUCCESS;
    }

    // insert to the lpts ordered list
    auto& lpts_vec = sdev->m_trap_manager->m_lpts_vec[(int)ip_type];
    lpts_vec.insert(lpts_vec.begin() + pos, (sai_hostif_trap_type_t)la_oid.index);

    // insert to the tcam if punt_dest is not nullptr
    if (m_punt_dest != nullptr) {
        lsai_object la_group{};
        std::shared_ptr<trap_group> trap_group;
        la_status status = sdev->m_trap_manager->m_groups.get(m_group_id, trap_group, la_group);
        la_return_on_error(status);

        la_counter_or_meter_set* counter_meter = nullptr;
        la_meter_set* meter = nullptr;
        trap_group->get_lpts_meter(ip_type, counter_meter, meter);
        la_lpts_result result = {0, 0, 0, counter_meter, meter, m_punt_dest};

        auto it = sdev->m_trap_manager->m_punt_code_by_trap_type.find((sai_hostif_trap_type_t)la_oid.index);
        if (it == sdev->m_trap_manager->m_punt_code_by_trap_type.end()) {
            result.punt_code = (int)punt_code_e::LAST;
        } else {
            result.punt_code = (int)it->second;
        }
        result.tc = trap_group->m_tc;

        status = insert_tcam(ip_type, hw_dist, result);
        la_return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
trap_lpts::remove(lpts_type_e ip_type)
{
    SAI_GET_TRAP_SDEV_VOID_RETURN(m_oid);

    // In warm boot shutdown we are not allowed to access SDK objects
    if (!sdev->sdk_operations_allowed()) {
        return;
    }

    uint32_t pos = 0, hw_dist = 0;
    la_status status = find_lpts(ip_type, pos, hw_dist);

    if (status == LA_STATUS_SUCCESS) {
        auto it = sdev->m_trap_manager->m_lpts_vec[(int)ip_type].begin();
        sdev->m_trap_manager->m_lpts_vec[(int)ip_type].erase(it + pos);
        if (m_punt_dest != nullptr) {
            remove_tcam(ip_type, hw_dist);
        }
    }
}

la_status
trap_lpts::update_action(sai_packet_action_t a, lpts_type_e ip_type, la_l2_punt_destination* punt_dest)
{
    SAI_GET_TRAP_SDEV(m_oid);

    uint32_t pos = 0, hw_dist = 0;
    la_status status = find_lpts(ip_type, pos, hw_dist);

    if (status == LA_STATUS_SUCCESS) {
        // found sai_type
        if (m_punt_dest != nullptr && punt_dest == nullptr) {
            remove_tcam(ip_type, hw_dist);
        } else if (m_punt_dest == nullptr && punt_dest != nullptr) {
            lsai_object la_group{};
            std::shared_ptr<trap_group> trap_group;
            status = sdev->m_trap_manager->m_groups.get(m_group_id, trap_group, la_group);
            la_return_on_error(status);

            la_counter_or_meter_set* counter_meter = nullptr;
            la_meter_set* meter = nullptr;
            trap_group->get_lpts_meter(ip_type, counter_meter, meter);
            la_lpts_result result = {0, 0, 0, counter_meter, meter, punt_dest};

            auto it = sdev->m_trap_manager->m_punt_code_by_trap_type.find((sai_hostif_trap_type_t)la_oid.index);
            result.punt_code = (int)(it == sdev->m_trap_manager->m_punt_code_by_trap_type.end() ? punt_code_e::LAST : it->second);
            result.tc = trap_group->m_tc;

            status = insert_tcam(ip_type, hw_dist, result);
            la_return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
trap_lpts::update_group(sai_object_id_t group_id, lpts_type_e ip_type)
{
    if (m_punt_dest == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    SAI_GET_TRAP_SDEV(m_oid);

    lsai_object la_new_group(group_id);
    std::shared_ptr<trap_group> new_trap_group;
    la_status status = sdev->m_trap_manager->m_groups.get(group_id, new_trap_group, la_new_group);
    la_return_on_error(status);

    lsai_object la_old_group(m_group_id);
    std::shared_ptr<trap_group> old_trap_group;
    status = sdev->m_trap_manager->m_groups.get(m_group_id, old_trap_group, la_old_group);
    la_return_on_error(status);

    if (group_id != m_group_id) {
        old_trap_group->remove_trap((sai_hostif_trap_type_t)la_oid.index);

        status = new_trap_group->add_trap((sai_hostif_trap_type_t)la_oid.index);
        la_return_on_error(status);

        m_group_id = group_id;
    }

    uint32_t pos = 0, hw_dist = 0;
    status = find_lpts(ip_type, pos, hw_dist);

    if (status == LA_STATUS_SUCCESS) {
        remove_tcam(ip_type, hw_dist);
    }

    la_counter_or_meter_set* counter_meter = nullptr;
    la_meter_set* meter = nullptr;
    new_trap_group->get_lpts_meter(ip_type, counter_meter, meter);
    la_lpts_result result = {0, 0, 0, counter_meter, meter, m_punt_dest};

    auto it = sdev->m_trap_manager->m_punt_code_by_trap_type.find((sai_hostif_trap_type_t)la_oid.index);
    result.punt_code = (int)(it == sdev->m_trap_manager->m_punt_code_by_trap_type.end() ? punt_code_e::LAST : it->second);
    result.tc = new_trap_group->m_tc;

    return insert_tcam(ip_type, hw_dist, result);
}

//
// for NON-LPTS
// action DROP means DROP
// action FORWARD means clear trap
// action TRAP means punt
// action COPY/LOG means snoop
//
//
//
// for LPTS
// action DROP and FORWARD are not going to CPU (still forwarded)
// action COPY and LOG are going to CPU and forward
//
la_status
trap_lpts::get_punt_dest(sai_packet_action_t action, la_l2_punt_destination*& l2_punt_dest) const
{
    SAI_GET_TRAP_SDEV(m_oid);

    switch (action) {
    case SAI_PACKET_ACTION_DROP:
    case SAI_PACKET_ACTION_DENY:
    case SAI_PACKET_ACTION_FORWARD:
    case SAI_PACKET_ACTION_COPY_CANCEL:
    case SAI_PACKET_ACTION_TRANSIT:
        l2_punt_dest = nullptr;
        return LA_STATUS_SUCCESS;

    case SAI_PACKET_ACTION_TRAP:
    case SAI_PACKET_ACTION_LOG:
    case SAI_PACKET_ACTION_COPY:
        l2_punt_dest = sdev->m_trap_manager->m_sdev->m_punt_dest;
        return LA_STATUS_SUCCESS;

    // todo snoop the packet
    default:
        break;
    }
    return LA_STATUS_ENOTIMPLEMENTED;
}

void
trap_lpts::set_group_id(sai_object_id_t g)
{
    SAI_GET_TRAP_SDEV_VOID_RETURN(m_oid);

    sai_object_id_t groupid = (g == SAI_NULL_OBJECT_ID) ? sdev->m_trap_manager->m_default_trap_group_id : g;
    m_group_id = groupid;

    lsai_object la_group{};
    std::shared_ptr<trap_group> trap_group;
    sdev->m_trap_manager->m_groups.get(m_group_id, trap_group, la_group);
    if (trap_group != nullptr) {
        la_status status = trap_group->add_trap((sai_hostif_trap_type_t)la_oid.index);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_HOSTIF, "can not add trap 0x%0lx to group 0x%0lx", (sai_hostif_trap_type_t)la_oid.index, groupid);
        }
    }
}

trap_lpts_v4::~trap_lpts_v4()
{
    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV4);
}

la_status
trap_lpts_v4::update_action(sai_packet_action_t a)
{
    la_l2_punt_destination* punt_dest = nullptr;
    la_status status = get_punt_dest(a, punt_dest);
    la_return_on_error(status);

    if (m_punt_dest == punt_dest) {
        return LA_STATUS_SUCCESS;
    }

    status = trap_lpts::update_action(a, lpts_type_e::LPTS_TYPE_IPV4, punt_dest);
    la_return_on_error(status);

    m_punt_dest = punt_dest;
    trap_lpts::set_action(a);

    return LA_STATUS_SUCCESS;
}

la_status
trap_lpts_v4::update_priority(uint32_t p)
{
    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV4);

    trap_lpts::set_priority(p);
    return trap_lpts::insert(lpts_type_e::LPTS_TYPE_IPV4);
}

la_status
trap_lpts_v4::update_group(sai_object_id_t group_id)
{
    return trap_lpts::update_group(group_id, lpts_type_e::LPTS_TYPE_IPV4);
}

la_status
trap_lpts_v4::initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t group_id)
{
    la_l2_punt_destination* punt_dest = nullptr;
    la_status status = get_punt_dest(a, punt_dest);
    la_return_on_error(status);

    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV4);

    trap_lpts::set_priority(p);
    trap_lpts::set_action(a);
    trap_lpts::set_group_id(group_id);

    m_punt_dest = punt_dest;

    return trap_lpts::insert(lpts_type_e::LPTS_TYPE_IPV4);
}

trap_lpts_v6::~trap_lpts_v6()
{
    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV6);
}

la_status
trap_lpts_v6::update_action(sai_packet_action_t a)
{
    la_l2_punt_destination* punt_dest = nullptr;
    la_status status = get_punt_dest(a, punt_dest);
    la_return_on_error(status);

    if (m_punt_dest == punt_dest) {
        return LA_STATUS_SUCCESS;
    }

    status = trap_lpts::update_action(a, lpts_type_e::LPTS_TYPE_IPV6, punt_dest);
    la_return_on_error(status);

    m_punt_dest = punt_dest;
    trap_lpts::set_action(a);

    return LA_STATUS_SUCCESS;
}

la_status
trap_lpts_v6::update_priority(uint32_t p)
{
    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV6);

    trap_lpts::set_priority(p);

    return trap_lpts::insert(lpts_type_e::LPTS_TYPE_IPV6);
}

la_status
trap_lpts_v6::update_group(sai_object_id_t group_id)
{
    return trap_lpts::update_group(group_id, lpts_type_e::LPTS_TYPE_IPV6);
}

la_status
trap_lpts_v6::initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t group_id)
{
    la_l2_punt_destination* punt_dest = nullptr;
    la_status status = get_punt_dest(a, punt_dest);
    la_return_on_error(status);

    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV6);

    trap_lpts::set_priority(p);
    trap_lpts::set_action(a);
    trap_lpts::set_group_id(group_id);
    m_punt_dest = punt_dest;

    return trap_lpts::insert(lpts_type_e::LPTS_TYPE_IPV6);
}

trap_lpts_v4_v6::~trap_lpts_v4_v6()
{
    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV4);
    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV6);
}

la_status
trap_lpts_v4_v6::update_action(sai_packet_action_t a)
{
    la_l2_punt_destination* punt_dest = nullptr;
    la_status status = get_punt_dest(a, punt_dest);
    la_return_on_error(status);

    if (m_punt_dest == punt_dest) {
        return LA_STATUS_SUCCESS;
    }

    status = trap_lpts::update_action(a, lpts_type_e::LPTS_TYPE_IPV4, punt_dest);
    la_return_on_error(status);

    status = trap_lpts::update_action(a, lpts_type_e::LPTS_TYPE_IPV6, punt_dest);
    la_return_on_error(status);

    m_punt_dest = punt_dest;
    trap_lpts::set_action(a);

    return LA_STATUS_SUCCESS;
}

la_status
trap_lpts_v4_v6::update_priority(uint32_t p)
{
    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV4);
    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV6);

    trap_lpts::set_priority(p);

    la_status status = trap_lpts::insert(lpts_type_e::LPTS_TYPE_IPV6);
    la_return_on_error(status);

    status = trap_lpts::insert(lpts_type_e::LPTS_TYPE_IPV6);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
trap_lpts_v4_v6::update_group(sai_object_id_t group_id)
{
    la_status status = trap_lpts::update_group(group_id, lpts_type_e::LPTS_TYPE_IPV4);
    la_return_on_error(status);
    return trap_lpts::update_group(group_id, lpts_type_e::LPTS_TYPE_IPV6);
}

la_status
trap_lpts_v4_v6::initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t group_id)
{
    la_l2_punt_destination* punt_dest = nullptr;
    la_status status = get_punt_dest(a, punt_dest);
    la_return_on_error(status);

    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV4);
    trap_lpts::remove(lpts_type_e::LPTS_TYPE_IPV6);

    trap_lpts::set_priority(p);
    trap_lpts::set_action(a);
    trap_lpts::set_group_id(group_id);
    m_punt_dest = punt_dest;

    status = trap_lpts::insert(lpts_type_e::LPTS_TYPE_IPV4);
    la_return_on_error(status);

    return trap_lpts::insert(lpts_type_e::LPTS_TYPE_IPV6);
}
}
}
