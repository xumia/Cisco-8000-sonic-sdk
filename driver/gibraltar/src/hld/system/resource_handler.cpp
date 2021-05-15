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

#include "resource_handler.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/logical_em.h"
#include "hw_tables/logical_lpm.h"
#include "ra/resource_manager.h"
#include "system/counter_manager.h"
#include "system/la_device_impl.h"
#include "system/slice_id_manager_base.h"

#include <array>

namespace silicon_one
{

static const std::array<la_resource_descriptor::type_e, (size_t)la_resource_descriptor::type_e::LAST + 1> m_types
    = {{la_resource_descriptor::type_e::AC_PROFILE,
        la_resource_descriptor::type_e::COUNTER_BANK,
        la_resource_descriptor::type_e::ACL_GROUP,
        la_resource_descriptor::type_e::EGRESS_IPV4_ACL,
        la_resource_descriptor::type_e::EGRESS_IPV6_ACL,
        la_resource_descriptor::type_e::INGRESS_ETH_NARROW_DB1_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_ETH_NARROW_DB2_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB1_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB2_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB3_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB4_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB1_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB2_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB3_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB4_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB1_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB2_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB3_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB4_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB1_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB2_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB3_INTERFACE0_ACL,
        la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB4_INTERFACE0_ACL,
        la_resource_descriptor::type_e::IPV4_LPTS,
        la_resource_descriptor::type_e::IPV4_VRF_DIP_EM_TABLE,
        la_resource_descriptor::type_e::IPV6_LPTS,
        la_resource_descriptor::type_e::IPV6_VRF_DIP_EM_TABLE,
        la_resource_descriptor::type_e::L2_SERVICE_PORT,
        la_resource_descriptor::type_e::L3_AC_PORT,
        la_resource_descriptor::type_e::LPM,
        la_resource_descriptor::type_e::LPM_IPV4_ROUTES,
        la_resource_descriptor::type_e::LPM_IPV6_ROUTES,
        la_resource_descriptor::type_e::MAC_FORWARDING_TABLE,
        la_resource_descriptor::type_e::METER_ACTION,
        la_resource_descriptor::type_e::METER_PROFILE,
        la_resource_descriptor::type_e::NATIVE_FEC_ENTRY,
        la_resource_descriptor::type_e::STAGE1_LB_GROUP,
        la_resource_descriptor::type_e::STAGE1_LB_MEMBER,
        la_resource_descriptor::type_e::STAGE1_PROTECTION_MONITOR,
        la_resource_descriptor::type_e::STAGE2_LB_GROUP,
        la_resource_descriptor::type_e::STAGE2_LB_MEMBER,
        la_resource_descriptor::type_e::STAGE2_PROTECTION_MONITOR,
        la_resource_descriptor::type_e::STAGE3_LB_MEMBER,
        la_resource_descriptor::type_e::TC_PROFILE,
        la_resource_descriptor::type_e::TCAM_EGRESS_NARROW_POOL_0,
        la_resource_descriptor::type_e::TCAM_EGRESS_WIDE,
        la_resource_descriptor::type_e::TCAM_INGRESS_NARROW_POOL_0,
        la_resource_descriptor::type_e::TCAM_INGRESS_NARROW_POOL_1,
        la_resource_descriptor::type_e::TCAM_INGRESS_WIDE,
        la_resource_descriptor::type_e::VOQ_CGM_EVICTED_PROFILE,
        la_resource_descriptor::type_e::VOQ_CGM_PROFILE,
        la_resource_descriptor::type_e::EGRESS_LARGE_ENCAP_EM,
        la_resource_descriptor::type_e::EGRESS_SMALL_ENCAP_EM,
        la_resource_descriptor::type_e::EGRESS_L3_DLP0_EM,
        la_resource_descriptor::type_e::TUNNEL_0_EM,
        la_resource_descriptor::type_e::CENTRAL_EM,
        la_resource_descriptor::type_e::IPV6_COMPRESSED_SIPS,
        la_resource_descriptor::type_e::INGRESS_QOS_PROFILES,
        la_resource_descriptor::type_e::EGRESS_QOS_PROFILES,
        la_resource_descriptor::type_e::MC_EMDB,
        la_resource_descriptor::type_e::NEXT_HOP,
        la_resource_descriptor::type_e::MY_IPV4_TABLE,
        la_resource_descriptor::type_e::SIP_INDEX_TABLE}};

resource_handler::resource_handler(const la_device_impl_wptr& device) : m_device(device)
{
}

resource_handler::~resource_handler()
{
}

template <class _Resource_Type>
la_status
resource_handler::add_resource(const _Resource_Type& resource_instance, const la_resource_descriptor& descriptor)
{
    resource_monitor_sptr rm = nullptr;
    la_status status = allocate_resource_monitor(descriptor, resource_instance->max_size(), resource_instance->size(), rm);
    return_on_error(status);

    resource_instance->set_resource_monitor(rm);
    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::add_resource_monitored_by_device(const size_t max_size,
                                                   const size_t size,
                                                   const la_resource_descriptor& descriptor)
{
    resource_monitor_sptr rm = nullptr;
    la_status status = allocate_resource_monitor(descriptor, max_size, size, rm);
    return_on_error(status);

    status = m_device->set_resource_monitor(descriptor.m_resource_type, rm);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::initialize()
{
    la_status status = initialize_resources_types();
    return_on_error(status);

    return initialize_resources_instances();
}

la_status
resource_handler::initialize_resources_types()
{
    m_resource_monitors.resize((size_t)la_resource_descriptor::type_e::LAST + 1);

    std::vector<la_resource_granularity> resources((size_t)la_resource_descriptor::type_e::LAST + 1);
    resources[(size_t)la_resource_descriptor::type_e::AC_PROFILE] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::COUNTER_BANK] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::ACL_GROUP] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::EGRESS_IPV4_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::EGRESS_IPV6_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_ETH_NARROW_DB1_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_ETH_NARROW_DB2_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB1_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB2_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB3_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB4_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB1_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB2_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB3_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB4_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB1_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB2_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB3_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB4_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB1_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB2_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB3_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB4_INTERFACE0_ACL] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::IPV4_LPTS] = la_resource_granularity::SLICE;
    resources[(size_t)la_resource_descriptor::type_e::IPV4_VRF_DIP_EM_TABLE] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::IPV6_LPTS] = la_resource_granularity::SLICE;
    resources[(size_t)la_resource_descriptor::type_e::IPV6_VRF_DIP_EM_TABLE] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::L2_SERVICE_PORT] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::L3_AC_PORT] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::LPM] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::LPM_IPV4_ROUTES] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::LPM_IPV6_ROUTES] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::MAC_FORWARDING_TABLE] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::METER_ACTION] = la_resource_granularity::IFG;
    resources[(size_t)la_resource_descriptor::type_e::METER_PROFILE] = la_resource_granularity::IFG;
    resources[(size_t)la_resource_descriptor::type_e::NATIVE_FEC_ENTRY] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::STAGE1_LB_GROUP] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::STAGE1_LB_MEMBER] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::STAGE1_PROTECTION_MONITOR] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::STAGE2_LB_GROUP] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::STAGE2_LB_MEMBER] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::STAGE2_PROTECTION_MONITOR] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::STAGE3_LB_GROUP] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::STAGE3_LB_MEMBER] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::TC_PROFILE] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::TCAM_EGRESS_NARROW_POOL_0] = la_resource_granularity::SLICE;
    resources[(size_t)la_resource_descriptor::type_e::TCAM_EGRESS_WIDE] = la_resource_granularity::SLICE;
    resources[(size_t)la_resource_descriptor::type_e::TCAM_INGRESS_NARROW_POOL_0] = la_resource_granularity::SLICE;
    resources[(size_t)la_resource_descriptor::type_e::TCAM_INGRESS_NARROW_POOL_1] = la_resource_granularity::SLICE;
    resources[(size_t)la_resource_descriptor::type_e::TCAM_INGRESS_WIDE] = la_resource_granularity::SLICE;
    resources[(size_t)la_resource_descriptor::type_e::VOQ_CGM_EVICTED_PROFILE] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::VOQ_CGM_PROFILE] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::EGRESS_LARGE_ENCAP_EM] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::EGRESS_SMALL_ENCAP_EM] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::EGRESS_L3_DLP0_EM] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::TUNNEL_0_EM] = la_resource_granularity::SLICE;
    resources[(size_t)la_resource_descriptor::type_e::CENTRAL_EM] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::IPV6_COMPRESSED_SIPS] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::INGRESS_QOS_PROFILES] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::EGRESS_QOS_PROFILES] = la_resource_granularity::SLICE_PAIR;
    resources[(size_t)la_resource_descriptor::type_e::MC_EMDB] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::NEXT_HOP] = la_resource_granularity::DEVICE;
    resources[(size_t)la_resource_descriptor::type_e::MY_IPV4_TABLE] = la_resource_granularity::SLICE;
    resources[(size_t)la_resource_descriptor::type_e::SIP_INDEX_TABLE] = la_resource_granularity::DEVICE;

    for (size_t i = 0; i < resources.size(); i++) {
        size_t num_instances;
        la_status status = get_num_instances(resources[i], num_instances);
        return_on_error(status);

        m_resource_monitors[i].granularity = resources[i];
        m_resource_monitors[i].monitors.resize(num_instances);
    }

    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::initialize_resources_instances()
{
    la_resource_descriptor resource_descriptor;
    bzero(&resource_descriptor, sizeof(resource_descriptor));

    // Global resources
    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::AC_PROFILE;
    add_resource(&(m_device->m_index_generators.ac_profiles), resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::COUNTER_BANK;
    add_resource(m_device->m_counter_bank_manager, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::ACL_GROUP;
    add_resource(m_device->m_profile_allocators.acl_group_entries, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::NATIVE_FEC_ENTRY;
    add_resource(m_device->m_tables.fec_table, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::STAGE1_LB_GROUP;
    add_resource(&(m_device->m_index_generators.ecmp_groups[RESOLUTION_STEP_STAGE0_ECMP]), resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::STAGE2_LB_GROUP;
    add_resource(&(m_device->m_index_generators.ecmp_groups[RESOLUTION_STEP_STAGE1_ECMP]), resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::STAGE2_LB_MEMBER;
    add_resource(m_device->m_tables.stage1_em_table, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::STAGE1_LB_MEMBER;
    add_resource(m_device->m_tables.stage0_em_table, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::STAGE1_PROTECTION_MONITOR;
    add_resource(m_device->m_tables.stage0_protection_table, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::STAGE2_PROTECTION_MONITOR;
    add_resource(m_device->m_tables.stage1_protection_table, resource_descriptor);

#if 0
    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::STAGE3_LB_GROUP;
    add_resource(&(m_device->m_index_generators.ecmp_groups[RESOLUTION_STEP_STAGE1_ECMP]), resource_descriptor);
#endif

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::STAGE3_LB_MEMBER;
    add_resource(m_device->m_tables.stage2_em_table, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::VOQ_CGM_EVICTED_PROFILE;
    add_resource(&(m_device->m_index_generators.voq_cgm_evicted_profiles), resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::VOQ_CGM_PROFILE;
    add_resource(&(m_device->m_index_generators.voq_cgm_profiles), resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::TC_PROFILE;
    add_resource(&(m_device->m_index_generators.tc_profiles), resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::LPM;
    const auto& l_lpm = m_device->m_resource_manager->get_lpm();
    if (l_lpm) {
        add_resource(l_lpm, resource_descriptor);
    }

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::CENTRAL_EM;
    const auto& cem_db = m_device->m_resource_manager->get_cem();
    if (cem_db) {
        add_resource(cem_db, resource_descriptor);
    }

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::IPV6_COMPRESSED_SIPS;
    add_resource(&(m_device->m_index_generators.ipv6_compressed_sips), resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::MC_EMDB;
    const auto& mc_emdb = m_device->m_resource_manager->get_mc_emdb();
    if (mc_emdb) {
        add_resource(mc_emdb, resource_descriptor);
    }

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::MAC_FORWARDING_TABLE;
    add_resource(m_device->m_tables.mac_forwarding_table, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::NEXT_HOP;
    add_resource_monitored_by_device(la_device_impl::MAX_NEXT_HOP_GID, 0, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::IPV4_VRF_DIP_EM_TABLE;
    add_resource(m_device->m_tables.ipv4_vrf_dip_em_table, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::IPV6_VRF_DIP_EM_TABLE;
    add_resource(m_device->m_tables.ipv6_vrf_dip_em_table, resource_descriptor);

    resource_descriptor.m_resource_type = la_resource_descriptor::type_e::SIP_INDEX_TABLE;
    add_resource(m_device->m_profile_allocators.ipv4_sip_index, resource_descriptor);

    la_device_impl::acl_key_profile_type_e ipv4_type;
    la_device_impl::acl_key_profile_type_e ipv6_type;
    m_device->get_acl_key_profile_types(ipv4_type, ipv6_type);

    // Per Slice resources
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        resource_descriptor.m_index.slice_ifg_id.slice = slice_id;

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::IPV4_LPTS;
        add_resource(m_device->m_tables.ipv4_lpts_table[slice_id], resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::IPV6_LPTS;
        add_resource(m_device->m_tables.ipv6_lpts_table[slice_id], resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::TUNNEL_0_EM;
        const auto& tunnel_0_em_db = m_device->m_resource_manager->get_em_db(la_resource_descriptor::type_e::TUNNEL_0_EM, slice_id);
        if (tunnel_0_em_db != nullptr) {
            add_resource(tunnel_0_em_db, resource_descriptor);
        }

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::MY_IPV4_TABLE;
        add_resource(&(m_device->m_index_generators.slice[slice_id].my_ipv4_table_id), resource_descriptor);
    }

    // Per IFG resources
    for (la_slice_ifg s_ifg : m_device->get_used_ifgs()) {
        resource_descriptor.m_index.slice_ifg_id.slice = s_ifg.slice;
        resource_descriptor.m_index.slice_ifg_id.ifg = s_ifg.ifg;
        size_t ifg_idx = m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(s_ifg);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::METER_ACTION;
        add_resource(&(m_device->m_index_generators.exact_meter_action_profile_id[ifg_idx]), resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::METER_PROFILE;
        add_resource(&(m_device->m_index_generators.exact_meter_profile_id[ifg_idx]), resource_descriptor);
    }

    // Per slice pair resource
    for (la_slice_pair_id_t slice_pair_id : m_device->get_used_slice_pairs()) {
        resource_descriptor.m_index.slice_pair_id = slice_pair_id;

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::EGRESS_IPV4_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].egress_ipv4_acl_ids), resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::EGRESS_IPV6_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].egress_ipv6_acl_ids), resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_ETH_NARROW_DB1_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_eth_db1_160_f0_acl_ids), resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_ETH_NARROW_DB2_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_eth_db2_160_f0_acl_ids), resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB1_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv4_db1_160_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB2_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv4_db2_160_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB3_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv4_db3_160_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV4_NARROW_DB4_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv4_db4_160_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB1_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv4_db1_320_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB2_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv4_db2_320_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB3_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv4_db3_320_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV4_WIDE_DB4_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv4_db4_320_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB1_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv6_db1_160_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB2_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv6_db2_160_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB3_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv6_db3_160_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV6_NARROW_DB4_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv6_db4_160_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB1_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv6_db1_320_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB2_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv6_db2_320_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB3_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv6_db3_320_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_IPV6_WIDE_DB4_INTERFACE0_ACL;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_ipv6_db4_320_f0_acl_ids),
                     resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::L2_SERVICE_PORT;
        add_resource(m_device->m_tables.l2_dlp_table[slice_pair_id], resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::L3_AC_PORT;
        add_resource(m_device->m_tables.l3_dlp_table[slice_pair_id], resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::EGRESS_LARGE_ENCAP_EM;
        const auto& large_enc_em_db
            = m_device->m_resource_manager->get_em_db(la_resource_descriptor::type_e::EGRESS_LARGE_ENCAP_EM, slice_pair_id);
        if (large_enc_em_db != nullptr) {
            add_resource(large_enc_em_db, resource_descriptor);
        }

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::EGRESS_SMALL_ENCAP_EM;
        const auto& small_enc_em_db
            = m_device->m_resource_manager->get_em_db(la_resource_descriptor::type_e::EGRESS_SMALL_ENCAP_EM, slice_pair_id);
        if (small_enc_em_db != nullptr) {
            add_resource(small_enc_em_db, resource_descriptor);
        }

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::EGRESS_L3_DLP0_EM;
        const auto& l3_dlp0_enc_em_db
            = m_device->m_resource_manager->get_em_db(la_resource_descriptor::type_e::EGRESS_L3_DLP0_EM, slice_pair_id);
        if (l3_dlp0_enc_em_db != nullptr) {
            add_resource(l3_dlp0_enc_em_db, resource_descriptor);
        }

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::INGRESS_QOS_PROFILES;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].ingress_qos_profiles), resource_descriptor);

        resource_descriptor.m_resource_type = la_resource_descriptor::type_e::EGRESS_QOS_PROFILES;
        add_resource(&(m_device->m_index_generators.slice_pair[slice_pair_id].egress_qos_profiles), resource_descriptor);
    }

    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::allocate_resource_monitor(const la_resource_descriptor& descriptor,
                                            size_t max_size,
                                            size_t size,
                                            resource_monitor_sptr& out_resource_monitor)
{
    la_resource_instance_index_t instance_idx;
    la_status status = get_instance_index(descriptor, instance_idx);
    return_on_error(status);

    size_t resource_idx = (size_t)descriptor.m_resource_type;
    if (instance_idx > m_resource_monitors[resource_idx].monitors.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_resource_monitors[resource_idx].monitors[instance_idx] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto action_cb = std::make_shared<res_monitor_action_cb>(shared_from_this(), descriptor);

    m_resource_monitors[resource_idx].monitors[instance_idx]
        = make_unique<resource_monitor>(action_cb, max_size, size, resource_idx, instance_idx);
    out_resource_monitor = m_resource_monitors[resource_idx].monitors[instance_idx];

    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::get_granularity(la_resource_descriptor::type_e resource_type, la_resource_granularity& out_granularity) const
{
    size_t vector_size = m_resource_monitors[(size_t)resource_type].monitors.size();
    switch (vector_size) {
    case 1:
        out_granularity = la_resource_granularity::DEVICE;
        return LA_STATUS_SUCCESS;
    case NUM_SLICE_PAIRS_PER_DEVICE:
        out_granularity = la_resource_granularity::SLICE_PAIR;
        return LA_STATUS_SUCCESS;
    case ASIC_MAX_SLICES_PER_DEVICE_NUM:
        out_granularity = la_resource_granularity::SLICE;
        return LA_STATUS_SUCCESS;
    case NUM_IFGS_PER_DEVICE:
        out_granularity = la_resource_granularity::IFG;
        return LA_STATUS_SUCCESS;
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resource_handler::get_num_instances(la_resource_granularity granularity, size_t& out_num_instances) const
{
    switch (granularity) {
    case la_resource_granularity::DEVICE:
        out_num_instances = 1;
        return LA_STATUS_SUCCESS;
    case la_resource_granularity::SLICE_PAIR:
        out_num_instances = NUM_SLICE_PAIRS_PER_DEVICE;
        return LA_STATUS_SUCCESS;
    case la_resource_granularity::SLICE:
        out_num_instances = ASIC_MAX_SLICES_PER_DEVICE_NUM;
        return LA_STATUS_SUCCESS;
    case la_resource_granularity::IFG:
        out_num_instances = NUM_IFGS_PER_DEVICE;
        return LA_STATUS_SUCCESS;
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resource_handler::get_enabled_indices(la_resource_granularity granularity, index_vect& out_ind_vect) const
{
    switch (granularity) {
    case la_resource_granularity::DEVICE:
        out_ind_vect.push_back(0);
        return LA_STATUS_SUCCESS;
    case la_resource_granularity::SLICE_PAIR:
        for (size_t i : get_slice_pairs(m_device, la_slice_mode_e::NETWORK))
            out_ind_vect.push_back(i);
        return LA_STATUS_SUCCESS;
    case la_resource_granularity::SLICE:
        for (size_t i : get_slices(m_device, la_slice_mode_e::NETWORK))
            out_ind_vect.push_back(i);
        return LA_STATUS_SUCCESS;
    case la_resource_granularity::IFG:
        for (la_slice_ifg s_ifg : get_all_network_ifgs(m_device)) {
            size_t ifg_idx = m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(s_ifg);
            out_ind_vect.push_back(ifg_idx);
        }
        return LA_STATUS_SUCCESS;
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
resource_handler::set_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                       const std::vector<la_resource_thresholds>& thresholds_vec)
{
    la_resource_granularity granularity;
    la_status status = get_granularity(resource_type, granularity);
    return_on_error(status);
    index_vect vect;
    get_enabled_indices(granularity, vect);
    return_on_error(status);
    for (size_t i : vect) {
        la_status status = set_single_notification_threshold(i, resource_type, thresholds_vec);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::get_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                       std::vector<la_resource_thresholds>& out_thresholds_vec) const
{
    if (m_resource_monitors[(size_t)resource_type].monitors.size() == 0) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    // All monitors should have the same thresholds as they are set by type and not instance, so take the first valid one.
    la_resource_granularity granularity;
    la_status status = get_granularity(resource_type, granularity);
    return_on_error(status);
    index_vect enabled_indices;
    get_enabled_indices(granularity, enabled_indices);
    return_on_error(status);

    resource_monitor_sptr rm = m_resource_monitors[(size_t)resource_type].monitors[enabled_indices[0]];
    rm->get_thresholds(out_thresholds_vec);

    return LA_STATUS_SUCCESS;
}

resource_monitor_sptr
resource_handler::get_resource_monitor(const la_resource_descriptor& descriptor) const
{
    size_t resource_idx = (size_t)descriptor.m_resource_type;
    la_resource_instance_index_t instance_idx;
    la_status status = get_instance_index(descriptor, instance_idx);
    if (status != LA_STATUS_SUCCESS) {
        return nullptr;
    }

    return m_resource_monitors[resource_idx].monitors[instance_idx];
}

la_status
resource_handler::get_instance_index(const la_resource_descriptor& descriptor, la_resource_instance_index_t& out_index) const
{
    la_resource_granularity granularity;
    la_status status = get_granularity(descriptor.m_resource_type, granularity);
    return_on_error(status);

    switch (granularity) {
    case la_resource_granularity::DEVICE:
        out_index = 0;
        break;
    case la_resource_granularity::SLICE_PAIR:
        out_index = descriptor.m_index.slice_pair_id;
        break;
    case la_resource_granularity::SLICE:
        out_index = descriptor.m_index.slice_id;
        break;
    case la_resource_granularity::IFG:
        out_index = m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(descriptor.m_index.slice_ifg_id);
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

// WA for dependent tables only
template <class _Table>
la_status
resource_handler::get_usage_from_table_instance(const _Table& table, la_resource_usage_descriptor& out_descriptor) const
{
    size_t used = table->size(); // get resource used
    out_descriptor.used = used;

    // get resource total
    return get_total_from_table_instance(table, out_descriptor, used);
}

// WA for dependent tables only
template <class _Table>
la_status
resource_handler::get_total_from_table_instance(const _Table& table,
                                                la_resource_usage_descriptor& out_descriptor,
                                                const size_t resource_used) const
{
    // get resource available
    size_t out_available_entries = (size_t)-1;
    la_status status = table->get_available_entries(out_available_entries);
    return_on_error(status);

    // calc resource total ( = used + available)
    out_descriptor.total = resource_used + out_available_entries;
    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::get_resource_usage(const la_resource_descriptor& descriptor, la_resource_usage_descriptor& out_descriptor) const
{
    out_descriptor.desc = descriptor;

    // get resource_monitor
    resource_monitor_sptr rm = get_resource_monitor(descriptor);
    if (rm != nullptr) {
        out_descriptor.total = rm->get_max_size();
        out_descriptor.used = rm->get_size();
        out_descriptor.state = rm->get_state();
    }

    // dependent resources - need to ask the npl_table for usage
    //
    // temp workaround until npl_table_base class will be implemented.
    // then, rm can hold a comminicator base class that holds the npl_table_base as a member.
    else {

        // get instance idx
        la_resource_instance_index_t instance_idx;
        la_status status = get_instance_index(descriptor, instance_idx);
        return_on_error(status);

        switch (descriptor.m_resource_type) {

        // LPM DEPENDENT RESOURCES:
        // total is calculated by table_used + table_available
        case la_resource_descriptor::type_e::LPM_IPV4_ROUTES: {
            auto& table = m_device->m_tables.ipv4_lpm_table;
            status = get_usage_from_table_instance(table, out_descriptor);
            break;
        }
        case la_resource_descriptor::type_e::LPM_IPV6_ROUTES: {
            auto& table = m_device->m_tables.ipv6_lpm_table;
            status = get_usage_from_table_instance(table, out_descriptor);
            break;
        }

        // CEM DEPENDENT RESOURCES:
        // total is calculated by table_used + table_available
        case la_resource_descriptor::type_e::MAC_FORWARDING_TABLE: {
            auto& table = m_device->m_tables.mac_forwarding_table;
            status = get_usage_from_table_instance(table, out_descriptor);
            break;
        }

        // TCAM DEPENDENT RESOURCES:
        // used of tcam group = used of all the tables in the group
        // available of tcam group = available of each of each table in the group
        // total is calculated by group_used + group_available
        case la_resource_descriptor::type_e::TCAM_EGRESS_NARROW_POOL_0: {
            // calc used
            size_t used = m_device->m_tables.default_egress_ipv4_sec_acl_table[instance_idx]->size();
            out_descriptor.used = used;

            // calc total
            auto& table = m_device->m_tables.default_egress_ipv4_sec_acl_table[instance_idx]; // pick random table in the group
            status = get_total_from_table_instance(table, out_descriptor, used);              // calc total

            break;
        }
        case la_resource_descriptor::type_e::TCAM_EGRESS_WIDE: {
            // calc used
            size_t used = m_device->m_tables.default_egress_ipv6_acl_sec_table[instance_idx]->size();
            out_descriptor.used = used;

            // calc total
            auto& table = m_device->m_tables.default_egress_ipv6_acl_sec_table[instance_idx]; // pick random table in the group
            status = get_total_from_table_instance(table, out_descriptor, used);              // calc total

            break;
        }

        case la_resource_descriptor::type_e::TCAM_INGRESS_NARROW_POOL_0: {
            // calc used
            size_t used = m_device->m_tables.ingress_rtf_eth_db1_160_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_eth_db2_160_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db1_160_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db2_160_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db3_160_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db4_160_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db1_160_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db2_160_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db3_160_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db4_160_f0_table[instance_idx]->size();

            out_descriptor.used = used;

            // calc total
            auto& table = m_device->m_tables.ingress_rtf_eth_db1_160_f0_table[instance_idx]; // pick random table in the group
            status = get_total_from_table_instance(table, out_descriptor, used);             // calc total

            break;
        }
        case la_resource_descriptor::type_e::TCAM_INGRESS_NARROW_POOL_1: {
            // calc used
            size_t used = m_device->m_tables.ingress_rtf_ipv4_db1_160_f1_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db2_160_f1_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db3_160_f1_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db4_160_f1_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db1_160_f1_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db2_160_f1_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db3_160_f1_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db4_160_f1_table[instance_idx]->size();

            out_descriptor.used = used;

            // calc total
            auto& table = m_device->m_tables.ingress_rtf_ipv4_db1_160_f1_table[instance_idx]; // pick random table in the group
            status = get_total_from_table_instance(table, out_descriptor, used);              // calc total

            break;
        }
        case la_resource_descriptor::type_e::TCAM_INGRESS_WIDE: {
            // calc used
            size_t used = m_device->m_tables.ingress_rtf_ipv4_db1_320_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db2_320_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db3_320_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv4_db4_320_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db1_320_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db2_320_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db3_320_f0_table[instance_idx]->size()
                          + m_device->m_tables.ingress_rtf_ipv6_db4_320_f0_table[instance_idx]->size();

            out_descriptor.used = used;

            // calc total
            auto& table = m_device->m_tables.ingress_rtf_ipv4_db1_320_f0_table[instance_idx]; // pick random table in the group
            status = get_total_from_table_instance(table, out_descriptor, used);              // calc total

            break;
        }

        default:
            return LA_STATUS_EINVAL;
        }

        return_on_error(status);

        // invalid - in this WA there is no rm for the dependent table instance, so this field is irrelevant.
        out_descriptor.state = -1;
    }
    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::get_resource_usage(la_resource_descriptor::type_e resource_type,
                                     la_resource_usage_descriptor_vec& out_descriptors) const
{
    out_descriptors.clear();
    out_descriptors.resize(m_resource_monitors[(size_t)resource_type].monitors.size());
    la_resource_descriptor resource_descriptor;
    resource_descriptor.m_resource_type = resource_type;
    la_resource_granularity granularity;
    la_status status = get_granularity(resource_type, granularity);
    return_on_error(status);
    index_vect enabled_indices;
    get_enabled_indices(granularity, enabled_indices);
    return_on_error(status);

    for (size_t i : enabled_indices) {
        switch (granularity) {
        case la_resource_granularity::DEVICE:
            break;
        case la_resource_granularity::SLICE_PAIR:
            resource_descriptor.m_index.slice_pair_id = i;
            break;
        case la_resource_granularity::SLICE:
            resource_descriptor.m_index.slice_id = i;
            break;
        case la_resource_granularity::IFG:
            auto s_ifg = m_device->get_slice_id_manager()->global_ifg_2_slice_ifg(i);
            resource_descriptor.m_index.slice_ifg_id = s_ifg;
            break;
        }
        status = get_resource_usage(resource_descriptor, out_descriptors[i]);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::get_resource_usage(la_resource_usage_descriptor_vec& out_descriptors) const
{
    out_descriptors.clear();

    for (auto resource_type : m_types) {
        la_resource_usage_descriptor_vec type_vec;
        la_status status = get_resource_usage(resource_type, type_vec);
        return_on_error(status);
        out_descriptors.insert(std::end(out_descriptors), std::begin(type_vec), std::end(type_vec));
    }

    return LA_STATUS_SUCCESS;
}

la_status
resource_handler::notify(const la_resource_descriptor& descriptor, size_t state, size_t max_size, size_t current_size)
{
    log_debug(HLD, "%s: max_size=%zu, current_size=%zu", __func__, max_size, current_size);

    la_notification_desc desc;
    bzero(&desc, sizeof(desc));
    desc.type = la_notification_type_e::RESOURCE_MONITOR;
    desc.u.resource_monitor.resource_usage.desc = descriptor;
    desc.u.resource_monitor.resource_usage.state = state;
    desc.u.resource_monitor.resource_usage.used = current_size;
    desc.u.resource_monitor.resource_usage.total = max_size;

    return m_device->get_notificator()->notify(desc);
}

resource_handler::res_monitor_action_cb::res_monitor_action_cb(const resource_handler_sptr& parent,
                                                               const la_resource_descriptor& res_desc)
    : m_parent(parent), m_res_desc(res_desc)
{
}

la_status
resource_handler::res_monitor_action_cb::operator()(size_t state, size_t max_size, size_t current_size)
{
    return m_parent->notify(m_res_desc, state, max_size, current_size);
}

la_status
resource_handler::set_single_notification_threshold(size_t i,
                                                    la_resource_descriptor::type_e resource_type,
                                                    const std::vector<la_resource_thresholds>& thresholds_vec)
{
    resource_monitor_sptr rm = m_resource_monitors[(size_t)resource_type].monitors[i];
    if (rm == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = rm->set_thresholds(thresholds_vec);
    return status;
}

} // namespace silicon_one
