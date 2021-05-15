// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
#include <cmath>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <jansson.h>
#include <list>
#include <numeric>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <utility>

#include "apb/apb.h"
#include "api/cgm/la_voq_cgm_profile.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_limit_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_object.h"
#include "cgm/la_rx_cgm_sq_profile_impl.h"
#include "cgm/la_voq_cgm_evicted_profile_impl.h"
#include "cgm/la_voq_cgm_profile_impl.h"
#include "cgm/rx_cgm_handler.h"
#include "cgm/voq_cgm_handler.h"
#include "counter_manager.h"
#include "cpu2jtag/cpu2jtag.h"
#include "cud_range_manager.h"
#include "gibraltar_pvt_handler.h"
#include "hld_types.h"
#include "la_strings.h"
#include "npu/mc_copy_id_manager.h"
#include "system/device_configurator_base.h"
#include "system/ifg_handler_gibraltar.h"
#include "system/resource_handler.h"

#include "api/system/la_css_memory_layout.h"
#include "hw_tables/cem.h"
#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/pacific_reg_structs.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_enums.h"
#include "nplapi/npl_table_types.h"
#include "nplapi/nplapi_tables.h"
#include "npu/counter_utils.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_acl_command_profile_base.h"
#include "npu/la_acl_group_gibraltar.h"
#include "npu/la_acl_impl.h"
#include "npu/la_acl_key_profile_gibraltar.h"
#include "npu/la_acl_scaled_impl.h"
#include "npu/la_asbr_lsp_impl.h"
#include "npu/la_bfd_session_gibraltar.h"
#include "npu/la_copc_base.h"
#include "npu/la_copc_gibraltar.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_destination_pe_impl.h"
#include "npu/la_ecmp_group_impl.h"
#include "npu/la_ethernet_port_gibraltar.h"
#include "npu/la_fabric_multicast_group_impl.h"
#include "npu/la_filter_group_impl.h"
#include "npu/la_forus_destination_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_gue_port_impl.h"
#include "npu/la_ip_multicast_group_gibraltar.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_ip_tunnel_destination_impl.h"
#include "npu/la_l2_multicast_group_base.h"
#include "npu/la_l2_multicast_group_gibraltar.h"
#include "npu/la_l2_protection_group_gibraltar.h"
#include "npu/la_l2_service_port_gibraltar.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_l3_protection_group_impl.h"
#include "npu/la_lpts_impl.h"
#include "npu/la_lsr_impl.h"
#include "npu/la_mldp_vpn_decap_impl.h"
#include "npu/la_mpls_label_destination_impl.h"
#include "npu/la_mpls_multicast_group_impl.h"
#include "npu/la_mpls_nhlfe_impl.h"
#include "npu/la_mpls_vpn_decap_impl.h"
#include "npu/la_mpls_vpn_encap_impl.h"
#include "npu/la_multicast_group_common_gibraltar.h"
#include "npu/la_multicast_protection_group_base.h"
#include "npu/la_multicast_protection_monitor_base.h"
#include "npu/la_next_hop_gibraltar.h"
#include "npu/la_og_lpts_application_impl.h"
#include "npu/la_pbts_group_impl.h"
#include "npu/la_pcl_impl.h"
#include "npu/la_prefix_object_gibraltar.h"
#include "npu/la_protection_monitor_impl.h"
#include "npu/la_rate_limiter_set_gibraltar.h"
#include "npu/la_security_group_cell_base.h"
#include "npu/la_security_group_cell_gibraltar.h"
#include "npu/la_stack_port_base.h"
#include "npu/la_stack_port_gibraltar.h"
#include "npu/la_svi_port_gibraltar.h"
#include "npu/la_switch_impl.h"
#include "npu/la_te_tunnel_impl.h"
#include "npu/la_vrf_impl.h"
#include "npu/la_vrf_port_common_gibraltar.h"
#include "npu/la_vxlan_next_hop_gibraltar.h"
#include "npu/mc_copy_id_manager.h"
#include "npu/resolution_utils.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_action_profile_impl.h"
#include "qos/la_meter_markdown_profile_impl.h"
#include "qos/la_meter_profile_impl.h"
#include "qos/la_meter_set_exact_impl.h"
#include "qos/la_meter_set_impl.h"
#include "qos/la_meter_set_statistical_impl.h"
#include "system/device_configurator_base.h"
#include "system/device_model_types.h"
#include "system/hld_translator_creator.h"
#include "system/la_device_impl.h"
#include "system/la_erspan_mirror_command_gibraltar.h"
#include "system/la_fabric_port_impl.h"
#include "system/la_flow_cache_handler_impl.h"
#include "system/la_hbm_handler_impl.h"
#include "system/la_l2_mirror_command_gibraltar.h"
#include "system/la_l2_punt_destination_impl.h"
#include "system/la_mac_port_gibraltar.h"
#include "system/la_npu_host_destination_impl.h"
#include "system/la_npu_host_port_gibraltar.h"
#include "system/la_pbts_map_profile_impl.h"
#include "system/la_pci_port_gibraltar.h"
#include "system/la_punt_inject_port_gibraltar.h"
#include "system/la_recycle_port_gibraltar.h"
#include "system/la_remote_device_base.h"
#include "system/la_remote_port_impl.h"
#include "system/la_spa_port_gibraltar.h"
#include "system/la_system_port_gibraltar.h"
#include "system/mac_pool_port.h"
#include "system/npu_host_event_queue_gibraltar.h"
#include "system/npu_static_config.h"
#include "system/warm_boot_version.h"
#include "tm/la_fabric_port_scheduler_impl.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/la_logical_port_scheduler_impl.h"
#include "tm/la_output_queue_scheduler_impl.h"
#include "tm/la_system_port_scheduler_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/la_voq_set_impl.h"
#include "tm/restricted_voq_set_impl.h"
#include "tm/tm_utils.h"
#include "tm/voq_counter_set.h"

#include "apb/apb.h"
#include "srm/srm.h"
#include "system/device_port_handler_gibraltar.h"

#include "resolution_macro_cfg.h"

#include "ra/resource_manager.h"

#include "lld/ll_device.h"
#include "lld/lld_block.h"
#include "lld/lld_register.h"
#include "lld/lld_utils.h"

#include "common/bit_utils.h"
#include "common/cereal_utils.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/la_lock_guard.h"
#include "common/math_utils.h"
#include "common/transaction.h"

#include "api_tracer.h"
#include "common/file_utils.h"
#include "common/logger.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "state_writer.h"
#include "system/slice_id_manager_base.h"
#include "system/slice_id_manager_gibraltar.h"

#include "system/hld_notification_gibraltar.h"
#include <numeric>
#include <sstream>

#ifdef ENABLE_SERIALIZATION
#if CEREAL_MODE == CEREAL_MODE_BINARY
#include <cereal/archives/binary.hpp>
#elif CEREAL_MODE == CEREAL_MODE_JSON
#include <cereal/archives/json.hpp>
#elif CEREAL_MODE == CEREAL_MODE_XML
#include <cereal/archives/xml.hpp>
#endif

#include <cereal/types/memory.hpp>

// Forward decalarations for la_device_impl serialization functions
namespace cereal
{
template <class Archive>
void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive>
void load(Archive&, silicon_one::la_device_impl&);

// forward declaration of all modules set version functions
void cereal_gen_set_serialization_version_apb(unsigned int);
void cereal_gen_set_serialization_version_api(unsigned int);
void cereal_gen_set_serialization_version_common(unsigned int);
void cereal_gen_set_serialization_version_cpu2jtag(unsigned int);
void cereal_gen_set_serialization_version_hld(unsigned int);
void cereal_gen_set_serialization_version_hw_tables(unsigned int);
void cereal_gen_set_serialization_version_lld(unsigned int);
void cereal_gen_set_serialization_version_nplapi(unsigned int);
void cereal_gen_set_serialization_version_nsim_provider(unsigned int);
void cereal_gen_set_serialization_version_ra(unsigned int);
}
#endif

using namespace std;

// m_devices is needed in initialize_phase_topology() but defined as static in la_device_impl_common
extern array<silicon_one::la_device_impl_sptr, silicon_one::la_device_impl::MAX_DEVICES> m_devices;

static constexpr size_t CSS_MEMORY_HEARTBEAT_SLOW_BASE = (size_t)silicon_one::la_css_memory_layout_e::HEARTBEAT_SLOW / 4;

namespace silicon_one
{

constexpr size_t la_device_impl::INVALID_BUNDLE;
constexpr size_t la_device_impl::INVALID_LINK;
constexpr size_t la_device_impl::PFC_WATCHDOG_POLL_TIME_MS;

enum {
    LB_CRC_INITIAL_VEC = 0xffff,
    FUSE_BIT_HAS_HBM = 138,           ///< Efuse bit indicates if gb device has HBM.
    FUSE_BIT_MATILDA_MODEL_64 = 95,   ///< First of four eFuse bits indicating if gb device is of one of the Matilda Models.
    FUSE_BIT_MATILDA_MODEL_32 = 94,   ///< only 3 slices active, to know which there are bits No. 93, 92
    FUSE_BIT_MATILDA_MODEL_32_A = 93, ///< slices 3-5 are inactive
    FUSE_BIT_MATILDA_MODEL_32_B = 92, ///< slices 0-2 are inactive
    FUSE_BIT_MATILDA_MODEL_8T_A = 96, ///< slice 5 are inactive
    FUSE_BIT_MATILDA_MODEL_8T_B = 97, ///< slice 4 are inactive

    TX_PUNT_ETH_ENCAP_ID = (1 << 8), ///< Logical table ID for compound table tx_punt_eth_encap.
    OVERHEAD_ACCOUTING_LIMIT = 64,   ///< Overhead accounting limit value.

    VOQ_IN_DRAM_MAX_SIZE = (1 << 16) - 1, ///< Max VOQ size in the HBM.

    // 96 first VOQs are allocated to MC
    LAST_MC_VOQ = constexpr_max(SA_MC_VSC_RANGE_END, FABRIC_MC_VSC_RANGE_END), //=95
    // TC profile ID used for DSP that drop
    DROP_DSP_TC_PROFILE = 0,
    // Since the TC profile configured in the drop DSPs is not reserved, its configurable by the user and it can map any allowed VOQ
    // offset.
    // Therefore need to allocate MAX_VOQ_SET_SIZE VOQs for the drop DSPs.
    // 8 VOQs are allocated for the lookup error WA DSP0, and the base is chosen to align to the voq_counter_set requirements
    LOOKUP_ERROR_VOQ_SIZE = la_device_impl::MAX_VOQ_SET_SIZE,
    LOOKUP_ERROR_VOQ_BASE = round_up(LAST_MC_VOQ, voq_counter_set::NUM_VOQS_IN_SET),
    // 8 VOQs are allocated for RX drop destination.
    // Its OK group LOOKUP_ERROR_VOQ and RX_DROP_VOQ in a single NUM_VOQS_IN_SET since they can map to a single VOQ counter set
    RX_DROP_VOQ_SIZE = la_device_impl::MAX_VOQ_SET_SIZE,
    RX_DROP_VOQ_BASE = LOOKUP_ERROR_VOQ_BASE + LOOKUP_ERROR_VOQ_SIZE,
    RX_NOT_CNT_DROP_VOQ_SIZE = la_device_impl::MAX_VOQ_SET_SIZE,
    RX_NOT_CNT_DROP_VOQ_BASE = RX_DROP_VOQ_BASE + RX_DROP_VOQ_SIZE,

    FIRST_AVAILABLE_BASE_VOQ = round_up(RX_NOT_CNT_DROP_VOQ_BASE + RX_NOT_CNT_DROP_VOQ_SIZE, voq_counter_set::NUM_VOQS_IN_SET),

    AAPL_PACIFIC_IDCODE = 0x4510100f, ///< ID Code for Pacific device configured in AAPL

    // Hardcoded mirror GID if PFC with HBM buffers is used.
    PFC_MEASUREMENT_MIRROR_GID = la_device_impl::MIRROR_GID_INGRESS_OFFSET + 29,

    DEFAULT_LOAD_BALANCING_NODE_ID = 0x1,
};

matilda_model_e
read_matilda_model_from_efuse(const bit_vector& e_fuse_userbits)
{
    if (e_fuse_userbits.bit(FUSE_BIT_MATILDA_MODEL_64)) {
        // matilda 6.4
        return matilda_model_e::MATILDA_64;
    } else if (e_fuse_userbits.bit(FUSE_BIT_MATILDA_MODEL_32)) {
        // matilda 3.2T, check which subtype
        if (e_fuse_userbits.bit(FUSE_BIT_MATILDA_MODEL_32_A)) {
            return matilda_model_e::MATILDA_32A;
        } else if (e_fuse_userbits.bit(FUSE_BIT_MATILDA_MODEL_32_B)) {
            return matilda_model_e::MATILDA_32B;
        }
    } else if (e_fuse_userbits.bit(FUSE_BIT_MATILDA_MODEL_8T_A)) {
        // GB 8T, sub type A
        return matilda_model_e::MATILDA_8T_A;
    } else if (e_fuse_userbits.bit(FUSE_BIT_MATILDA_MODEL_8T_B)) {
        // GB 8T, sub type B
        return matilda_model_e::MATILDA_8T_B;
        ;
    }
    return matilda_model_e::GIBRALTAR_REGULAR;
}

la_device_impl::native_voq_set_desc::native_voq_set_desc()
    : dest_device(-1), dest_slice(-1), dest_ifg(-1), base_vsc_vec(ASIC_MAX_SLICES_PER_DEVICE_NUM, LA_VSC_GID_INVALID), is_busy{0}
{
}

la_device_impl::native_voq_set_desc::native_voq_set_desc(const native_voq_set_desc& ref)
    : dest_device(ref.dest_device),
      dest_slice(ref.dest_slice),
      dest_ifg(ref.dest_ifg),
      base_vsc_vec(ref.base_vsc_vec),
      is_busy(ref.is_busy)
{
}

la_device_impl::native_voq_set_desc::native_voq_set_desc(const la_vsc_gid_vec_t& vsc_vec,
                                                         la_device_id_t device,
                                                         la_slice_id_t slice,
                                                         la_ifg_id_t ifg)
    : dest_device(device), dest_slice(slice), dest_ifg(ifg), base_vsc_vec(vsc_vec), is_busy{0}
{
}

bool
la_device_impl::native_voq_set_desc::operator==(const native_voq_set_desc& ref) const
{
    if ((dest_device != ref.dest_device) || (dest_slice != ref.dest_slice) || (dest_ifg != ref.dest_ifg)) {
        return false;
    }

    for (la_slice_id_t src_slice = 0; src_slice < base_vsc_vec.size(); src_slice++) {
        if (round_down(base_vsc_vec[src_slice], NATIVE_VOQ_SET_SIZE)
            != round_down(ref.base_vsc_vec[src_slice], NATIVE_VOQ_SET_SIZE)) {
            return false;
        }
    }

    return true;
}

bool
la_device_impl::native_voq_set_desc::operator!=(const native_voq_set_desc& ref) const
{
    return !(*this == ref);
}

la_device_impl::native_voq_set_desc&
la_device_impl::native_voq_set_desc::operator=(const native_voq_set_desc& ref)
{
    dest_device = ref.dest_device;
    dest_slice = ref.dest_slice;
    dest_ifg = ref.dest_ifg;
    base_vsc_vec = ref.base_vsc_vec;

    return *this;
}

bool
la_device_impl::is_multi_device_aware_slice(la_slice_id_t slice_id)
{
    return slice_id < MAX_REMOTE_SLICE;
}

bool
la_device_impl::is_voq_id_in_range(la_slice_id_t slice_id, la_voq_gid_t voq_id)
{
    la_voq_gid_t last_available_base_voq = MAX_AVAILABLE_VOQS_PER_SLICE;

    // Because of a HW bug in GB, only 56K (=MAX_AVAILABLE_VOQS_PER_SLICE) VOQs are usable out of 64K,
    // and the invalid indication still uses 64K-1, hence, because of this bug we don't need to subtract NATIVE_VOQ_SET_SIZE.
    // TODO: Once the bug is fixed and MAX_AVAILABLE_VOQS_PER_SLICE is removed, this code should be uncommented.
    // The last VOQ is used by the HW for invalid indication. Reserve the whole native VOQ set size.
    // la_voq_gid_t last_available_base_voq -= NATIVE_VOQ_SET_SIZE;

    return FIRST_AVAILABLE_BASE_VOQ <= voq_id && voq_id < last_available_base_voq;
}

bool
la_device_impl::is_dsp_in_range(la_system_port_gid_t system_port_gid) const
{
    bool ecn_queuing_enabled = false;
    get_bool_property(la_device_property_e::ENABLE_ECN_QUEUING, ecn_queuing_enabled);
    if (ecn_queuing_enabled) {
        return (MIN_SYSTEM_PORT_GID <= system_port_gid && system_port_gid < MAX_SYSTEM_PORT_GID_WITH_ECN_ENABLED);
    } else {
        return (MIN_SYSTEM_PORT_GID <= system_port_gid && system_port_gid < MAX_SYSTEM_PORT_GID);
    }
}

bool
la_device_impl::is_vsc_id_in_range(la_slice_id_t slice_id, la_vsc_gid_t vsc_id)
{
    la_vsc_gid_t vscs_per_ifg = MAX_VSCS_PER_IFG_IN_SLICE;
    // la_vsc_gid_t vscs_per_ifg
    //    = is_multi_device_aware_slice(slice_id) ? MAX_VSCS_PER_IFG_IN_LINECARD_DEVICE : MAX_VSCS_PER_IFG_IN_STANDALONE_DEVICE;

    return vsc_id < vscs_per_ifg;
}

destination_id
la_device_impl::get_actual_destination_id(destination_id dest_id)
{
    bool svl_mode = false;
    get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    if (svl_mode) {
        destination_id actual_dest_id;
        actual_dest_id.val = (dest_id.val | (m_ll_device->get_device_id() << SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID));
        return actual_dest_id;
    } else {
        return dest_id;
    }
}

la_status
la_device_impl::get_stack_port_from_remote_sys_port_gid(la_system_port_gid_t remote_sys_port_gid,
                                                        const la_stack_port*& out_stack_port)
{
    bool svl_mode = false;
    out_stack_port = nullptr;

    get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    if (!svl_mode) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_device_id_t remote_device_id = ((remote_sys_port_gid >> SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID) & 0x1);
    auto stack_ports = get_objects(object_type_e::STACK_PORT);
    for (auto stack_port : stack_ports) {
        la_stack_port_base* stack_port_base = static_cast<la_stack_port_base*>(stack_port);
        if (stack_port_base->get_peer_device_id() == remote_device_id) {
            out_stack_port = static_cast<la_stack_port*>(stack_port);
            return LA_STATUS_SUCCESS;
        }
    }
    return LA_STATUS_ENOTFOUND;
}

destination_id
la_device_impl::get_stack_remote_resolution_destination_id() const
{
    bool svl_mode = false;
    get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    if (svl_mode) {
        destination_id actual_dest_id;
        actual_dest_id.val
            = (SVL_REMOTE_RESOLUTION_GID | ((m_ll_device->get_device_id() ? 0 : 1) << SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID));
        // add prefix
        actual_dest_id.val = (NPL_DESTINATION_MASK_DSP | actual_dest_id.val);
        return actual_dest_id;
    } else {
        return DESTINATION_ID_INVALID;
    }
}

la_device_impl::la_device_impl() = default;

la_device_impl::la_device_impl(ll_device_sptr ldevice)
    : la_device_impl_base(ldevice),
      m_og_lpts_app_ids_allocated(0),
      m_tables(ldevice->get_device_id()),
      m_oid(0),
      m_reconnect_handler(nullptr),
      m_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e::PIPE),
      m_acl_scaled_enabled(false),
      m_l2pt_trap_enabled(false),
      m_fabric_ports_initialized(false),
      m_ecmp_hash_seed(LB_CRC_INITIAL_VEC),
      m_spa_hash_seed(LB_CRC_INITIAL_VEC),
      m_load_balancing_node_id(DEFAULT_LOAD_BALANCING_NODE_ID),
      m_device_frequency_int_khz(DEFAULT_DEVICE_FREQUENCY),
      m_device_frequency_float_ghz((float)DEFAULT_DEVICE_FREQUENCY / 1000000),
      m_device_clock_interval(1 / ((float)DEFAULT_DEVICE_FREQUENCY / 1000000)),
      m_tck_frequency_mhz(DEFAULT_TCK_FREQUENCY),
      m_meter_shaper_rate(-1),
      m_rate_limiters_shaper_rate(-1),
      m_pfc_tuning_enabled(false),
      m_mcg_counter_tc_profile(nullptr),
      m_trap_counters_or_meters({{nullptr}}),
      m_trap_entries(),
      m_snoop_entries(),
      m_vsc_is_busy({{nullptr}}),
      m_fe_mode(fe_mode_e::NONE),
      m_fe_fabric_reachability_enabled(true),
      m_lookup_error_drop_dsp_counter(nullptr),
      m_fe_routing_table_last_pool_time_point(std::chrono::steady_clock::now()),
      m_valid_links_thresholds(),
      m_congested_links_thresholds(),
      m_learn_mode(learn_mode_e::SYSTEM),
      m_mac_aging_interval(LA_MAC_AGING_TIME_NEVER),
      m_lpts_allocation_cache_initialized(false),
      m_is_in_pacific_mode(true),
      m_fabric_mac_ports_mode(fabric_mac_ports_mode_e::E_2x50),
      m_global_min_fabric_links_threshold(DEFAULT_MIN_LINKS_THRESHOLD),
      m_device_configurator(nullptr),
      m_sda_mode(false)
{
    m_punt_recycle_port_exist.fill(false);
}

la_status
la_device_impl::init_fuse_userbits()
{
    bit_vector dword[NUMBER_OF_FUSE_REGISTERS];

    la_status rc = m_ll_device->read_register(*m_gb_tree->top_regfile->fuse_read_data_reg0, dword[0]);
    rc = m_ll_device->read_register(*m_gb_tree->top_regfile->fuse_read_data_reg1, dword[1]);
    return_on_error(rc);
    rc = m_ll_device->read_register(*m_gb_tree->top_regfile->fuse_read_data_reg2, dword[2]);
    return_on_error(rc);
    rc = m_ll_device->read_register(*m_gb_tree->top_regfile->fuse_read_data_reg3, dword[3]);
    return_on_error(rc);
    rc = m_ll_device->read_register(*m_gb_tree->top_regfile->fuse_read_data_reg4, dword[4]);
    return_on_error(rc);
    rc = m_ll_device->read_register(*m_gb_tree->top_regfile->fuse_read_data_reg5, dword[5]);
    return_on_error(rc);

    for (size_t i = 0; i < NUMBER_OF_FUSE_REGISTERS; ++i) {
        m_fuse_userbits |= (dword[i] << (32 * i));
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::pre_initialize()
{
    la_device_impl_base::pre_initialize(std::make_shared<slice_id_manager_gibraltar>() /* slice_id_manager */);
    m_gb_tree = m_ll_device->get_gibraltar_tree_scptr();

    // Profile allocators
    auto& pa = m_profile_allocators;
    pa.ipv4_sip_index = make_shared<profile_allocators::ipv4_sip_index_profile_allocator>(0, NUM_IPV4_SIP_INDEX);
    pa.l3vxlan_smac_msb_index
        = make_shared<profile_allocators::l3vxlan_smac_msb_index_profile_allocator>(0, NUM_L3VXLAN_SMAC_MSB_INDEX);
    pa.npu_host_max_ccm_counters = make_shared<profile_allocators::npu_host_max_ccm_counters_profile_allocator>(
        delayed_ranged_index_generator(0, 8, std::chrono::seconds(2)));
    pa.npu_host_packet_intervals = make_shared<profile_allocators::npu_host_packet_intervals_profile_allocator>(0, 8);
    pa.bfd_local_ipv6_addresses = make_shared<profile_allocators::bfd_local_ipv6_addresses_profile_allocator>(0, 256);
    pa.npu_host_detection_times = make_shared<profile_allocators::npu_host_detection_times_profile_allocator>(0, 16);
    pa.lpts_meters = make_shared<profile_allocators::lpts_meters_profile_allocator>(0, la_device_impl::LPTS_METER_SIZE);
    pa.lpts_em_entries = make_shared<profile_allocators::lpts_em_entries_profile_allocator>(0, la_device_impl::LPTS_EM_SIZE);
    pa.bfd_rx_entries = make_shared<profile_allocators::bfd_rx_entries_profile_allocator>(0, NUM_NPUH_MEP_ENTRIES_PER_DEVICE);
    pa.oam_punt_encap
        = make_shared<profile_allocators::oam_punt_encap_profile_allocator>(0, NUM_OAMP_TRAP_ENCAP_ENTRIES_PER_DEVICE);
    pa.voq_probability_profile = make_shared<profile_allocators::voq_probability_profile_profile_allocator>(0, 32);
    pa.l2_slp_acl_indices
        = make_shared<profile_allocators::l2_slp_acl_indices_profile_allocator>(1 /* lower_bound */, ACL_SELECT_TABLE_SIZE);
    pa.acl_group_entries
        = make_shared<profile_allocators::acl_group_entries_profile_allocator>(1 /* lower_bound */, NUM_RTF_CONF_SET);

    // System objects
    m_objects.resize(MAX_OIDS);
    m_index_generators.oids = ranged_index_generator(1, MAX_OIDS);
    m_is_builtin_objects.resize(MAX_OIDS, false);
    m_slice_mode.fill(la_slice_mode_e::INVALID);
    m_slice_clos_direction.fill(CLOS_DIRECTION_INVALID);
    m_trap_entries.reserve(LA_EVENT_INTERNAL_LAST + 1);
    m_snoop_entries.reserve(LA_EVENT_INTERNAL_LAST + 1);

    // heartbeat
    m_heartbeat = {0, 0};

    m_notification = std::make_shared<hld_notification_gibraltar>(shared_from_this());

    // Initialize the internals and load the interrupt tree
    m_notification->initialize();

    m_cpu2jtag_handler.reset(cpu2jtag::create(m_ll_device));
    m_pvt_handler = silicon_one::make_unique<gibraltar_pvt_handler>(shared_from_this());
    const size_t num_ifgs_per_slice = m_slice_id_manager->maximal_num_ifg_per_slice();
    // Create IFGB handlers
    for (la_slice_ifg ifg : m_slice_id_manager->get_all_possible_ifgs()) {
        m_ifg_handlers[ifg.slice][ifg.ifg]
            = silicon_one::make_unique<ifg_handler_gibraltar>(shared_from_this(), ifg.slice, ifg.ifg);
    }

    m_serdes_inuse.resize(ASIC_MAX_SLICES_PER_DEVICE_NUM);
    for (la_slice_id_t sid : m_slice_id_manager->get_all_possible_slices()) {
        m_serdes_inuse[sid].resize(num_ifgs_per_slice, ifg_serdes_bitset());
    }

    // CGM global handler
    m_voq_cgm_handler = silicon_one::make_unique<voq_cgm_handler>(shared_from_this());

    // TM objects
    m_ifg_schedulers.resize(ASIC_MAX_SLICES_PER_DEVICE_NUM);
    for (la_slice_id_t sid : m_slice_id_manager->get_all_possible_slices()) {
        m_ifg_schedulers[sid].resize(num_ifgs_per_slice);
        for (la_ifg_id_t ifg_id = 0; ifg_id < num_ifgs_per_slice; ifg_id++) {
            m_index_generators.output_queue_scheduler[sid][ifg_id] = make_shared<ranged_index_generator>(
                FIRST_LP_QUEUING_OQSE, tm_utils::IFG_OUTPUT_QUEUE_SCHEDULERS, true /* support_pairs */);
            size_t ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(sid, ifg_id);
            m_index_generators.exact_meter_action_profile_id[ifg_idx]
                = ranged_index_generator(0, la_meter_action_profile_impl::NUM_EXACT_METER_ACTION_PROFILE_PER_IFG);
            m_index_generators.exact_meter_profile_id[ifg_idx]
                = ranged_index_generator(0, la_meter_profile_impl::NUM_EXACT_METER_PROFILES_PER_IFG);
            m_mcg_tx_npu_host_ports[sid][ifg_id] = nullptr;
        }
    }

    for (la_slice_id_t sid : m_slice_id_manager->get_all_possible_slices()) {
        m_index_generators.slice[sid].my_ipv4_table_id = ranged_index_generator(0, NUM_MY_IPV4_TABLE_INDEX);
    }

    initialize_device_properties();
    la_status retval = init_fuse_userbits();
    return_on_error(retval);
    // check if this device is a Matilda Model (init property from eFuse)
    m_matilda_eFuse_type = read_matilda_model_from_efuse(m_fuse_userbits);
    m_device_properties[(int)la_device_property_e::MATILDA_MODEL_TYPE].int_val = (int)m_matilda_eFuse_type;
    log_info(HLD, "setting Matilda Model type from eFuse value: model=%d", (int)m_matilda_eFuse_type);

    m_reconnect_handler = silicon_one::make_unique<reconnect_handler>(shared_from_this());

    m_init_performance_helper = silicon_one::make_unique<init_performance_helper_base>(shared_from_this());

    // set_int_property(la_device_property_e::MATILDA_MODEL_TYPE, matilda_model);

    // Initialize the UDK library
    m_udk_library = silicon_one::make_unique<runtime_flexibility_library>(nullptr, is_simulated_device(), 0);
    m_vxlan_vni_profile.resize((la_uint_t)la_switch::vxlan_termination_mode_e::LAST + 1);
    for (size_t i = 0; i <= (size_t)apb_interface_type_e::LAST; ++i) {
        auto type = (apb_interface_type_e)i;
        apb_sptr apb_handler(apb::create(m_ll_device, type));
        m_apb_handlers[type] = move(apb_handler);
    }

    apb* apb_serdes_handler = m_apb_handlers[apb_interface_type_e::SERDES].get();
    srm::set_apb(apb_serdes_handler);

    m_index_generators.rtf_eth_f0_160_table_id = ranged_index_generator(0, 2);
    m_index_generators.rtf_ipv4_f0_160_table_id = ranged_index_generator(0, 4);
    m_index_generators.rtf_ipv4_f0_320_table_id = ranged_index_generator(0, 4);
    m_index_generators.rtf_ipv6_f0_160_table_id = ranged_index_generator(0, 4);
    m_index_generators.rtf_ipv6_f0_320_table_id = ranged_index_generator(0, 4);

    m_acl_command_profiles[0] = LA_ACL_COMMAND;
    for (auto i = 1; i < NUM_ACL_COMMAND_PROFILES; i++) {
        m_acl_command_profiles[i] = {};
    }

    m_npu_host_eventq = silicon_one::make_unique<npu_host_event_queue_gibraltar>(shared_from_this());

    memset(m_mldp_bud_info, 0, sizeof(m_mldp_bud_info));

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_first_ifgs()
{
    const size_t num_ifgs_per_slice = m_slice_id_manager->maximal_num_ifg_per_slice();
    for (la_slice_id_t sid : m_slice_id_manager->get_all_possible_slices()) {
        for (la_ifg_id_t ifg_id = 0; ifg_id < num_ifgs_per_slice; ifg_id++) {
            m_ifg_handlers[sid][ifg_id]->pre_initialize();
        }
    }

    m_serdes_info.resize(ASIC_MAX_SLICES_PER_DEVICE_NUM);
    m_serdes_status.resize(ASIC_MAX_SLICES_PER_DEVICE_NUM);
    for (la_slice_id_t sid : m_slice_id_manager->get_all_possible_slices()) {
        m_serdes_info[sid].resize(num_ifgs_per_slice);
        m_serdes_status[sid].resize(num_ifgs_per_slice);
        for (la_ifg_id_t ifg_id = 0; ifg_id < num_ifgs_per_slice; ifg_id++) {
            size_t serdes_count = m_ifg_handlers[sid][ifg_id]->get_serdes_count();
            m_serdes_info[sid][ifg_id].resize(serdes_count);
            m_serdes_status[sid][ifg_id].resize(serdes_count);
            for (la_uint_t serdes_id = 0; serdes_id < serdes_count; serdes_id++) {
                m_serdes_info[sid][ifg_id][serdes_id].rx_source = serdes_id;
                m_serdes_info[sid][ifg_id][serdes_id].anlt_order = serdes_id;
                m_serdes_info[sid][ifg_id][serdes_id].rx_polarity_inversion = false;
                m_serdes_info[sid][ifg_id][serdes_id].tx_polarity_inversion = false;
                m_serdes_status[sid][ifg_id][serdes_id].rx_enabled = false;
                m_serdes_status[sid][ifg_id][serdes_id].tx_enabled = false;
            }
        }
    }

    return m_reconnect_handler->pre_initialize_ifgs();
}

void
la_device_impl::initialize_resolution_index_generators()
{
    m_index_generators.fecs = ranged_index_generator(0, MAX_FEC_GID);
    m_index_generators.protection_monitors = ranged_index_generator(0, MAX_PROTECTION_MONITOR_GID);

    for (int i = 0; i < NUM_PBTS_LEVELS; i++) {
        m_index_generators.pbts_map_profiles[i] = ranged_index_generator(0, MAX_PBTS_MAP_PROFILE_ID);
    }
    m_index_generators.ecmp_groups[RESOLUTION_STEP_STAGE0_ECMP] = ranged_index_generator(0, MAX_ECMP_GROUP_STAGE0);
    m_index_generators.ecmp_groups[RESOLUTION_STEP_STAGE1_ECMP] = ranged_index_generator(0, MAX_ECMP_GROUP_STAGE1);
}

void
la_device_impl::initialize_resolution_configurators()
{
    for (int i = 0; i < NUM_RESOLUTION_STAGES; i++) {
        m_resolution_configurators[i].initialize(i, shared_from_this());
    }
}

la_status
la_device_impl::initialize_ip_tunnel_inner_ttl_decrement_config_table()
{
    for (int tunnel_type = 0; tunnel_type <= (int)la_ip_tunnel_type_e::LAST; tunnel_type++) {
        la_ip_tunnel_type_e type = (la_ip_tunnel_type_e)tunnel_type;
        la_status retval = set_decap_ttl_decrement_enabled(type, true);
        return_on_error(retval);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_svl_mode_table(bool svl_mode)
{
    const auto& tables(m_tables.svl_mode_table);
    npl_svl_mode_table_t::key_type k;
    npl_svl_mode_table_t::value_type v;

    v.payloads.svl_mode.val = static_cast<npl_bool_e>(svl_mode);

    la_status status = per_slice_tables_insert(m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return status;
}

la_status
la_device_impl::initialize_l3_termination_classify_ip_tunnels_table()
{
    npl_l3_termination_classify_ip_tunnels_table_key_t k; // from npl_table_types.h based on NPL
    npl_l3_termination_classify_ip_tunnels_table_key_t m; // from npl_table_types.h based on NPL
    // npl_table_types.h: npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t

    npl_protocol_type_e hdr_type_ALL_1 = static_cast<npl_protocol_type_e>(bit_utils::get_lsb_mask(5));
    uint64_t udp_dst_port_or_gre_proto_ALL_1 = static_cast<uint64_t>(bit_utils::get_lsb_mask(16));

    struct npl_l3_termination_classify_ip_tunnels_table_value_t value_union; // // npl_table_types.h

    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_VXLAN;
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.force_pipe_ttl = false;
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.ingress_ptp_info.ptp_transport_type
        = NPL_PTP_TRANSPORT_ETHERNET;
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.ingress_ptp_info.is_ptp_trans_sup = false;

    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_null.force_pipe_ttl = false;
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_null.ingress_ptp_info.ptp_transport_type
        = NPL_PTP_TRANSPORT_ETHERNET;
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_null.ingress_ptp_info.is_ptp_trans_sup = false;

    k.l3_protocol_type = 0;
    k.l4_protocol_type = NPL_PROTOCOL_TYPE_UDP;
    k.udp_dst_port_or_gre_proto = NPL_UDP_VXLAN_DST_PORT;
    m.l3_protocol_type = 0;
    m.l4_protocol_type = hdr_type_ALL_1;
    m.udp_dst_port_or_gre_proto = udp_dst_port_or_gre_proto_ALL_1;

    m_l3_termination_classify_ip_tunnels_table[0].key = k;
    m_l3_termination_classify_ip_tunnels_table[0].mask = m;
    m_l3_termination_classify_ip_tunnels_table[0].value = value_union;

    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_GUE;
    k.l3_protocol_type = 0;
    k.l4_protocol_type = NPL_PROTOCOL_TYPE_UDP;
    k.udp_dst_port_or_gre_proto = NPL_UDP_MPLS_DST_PORT;
    m.l3_protocol_type = 0;
    m.l4_protocol_type = hdr_type_ALL_1;
    m.udp_dst_port_or_gre_proto = udp_dst_port_or_gre_proto_ALL_1;

    m_l3_termination_classify_ip_tunnels_table[1].key = k;
    m_l3_termination_classify_ip_tunnels_table[1].mask = m;
    m_l3_termination_classify_ip_tunnels_table[1].value = value_union;

    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_GUE;
    k.l3_protocol_type = 0;
    k.l4_protocol_type = NPL_PROTOCOL_TYPE_UDP;
    k.udp_dst_port_or_gre_proto = NPL_UDP_IP_DST_PORT;
    m.l3_protocol_type = 0;
    m.l4_protocol_type = hdr_type_ALL_1;
    m.udp_dst_port_or_gre_proto = udp_dst_port_or_gre_proto_ALL_1;

    m_l3_termination_classify_ip_tunnels_table[2].key = k;
    m_l3_termination_classify_ip_tunnels_table[2].mask = m;
    m_l3_termination_classify_ip_tunnels_table[2].value = value_union;

    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_NVGRE;
    k.l3_protocol_type = 0;
    k.l4_protocol_type = NPL_PROTOCOL_TYPE_GRE;
    k.udp_dst_port_or_gre_proto = NPL_IPV4_PROTOCOL_NVGRE;
    m.l3_protocol_type = 0;
    m.l4_protocol_type = hdr_type_ALL_1;
    m.udp_dst_port_or_gre_proto = udp_dst_port_or_gre_proto_ALL_1;

    m_l3_termination_classify_ip_tunnels_table[3].key = k;
    m_l3_termination_classify_ip_tunnels_table[3].mask = m;
    m_l3_termination_classify_ip_tunnels_table[3].value = value_union;

    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_GRE;
    k.l3_protocol_type = 0;
    k.l4_protocol_type = NPL_PROTOCOL_TYPE_GRE;
    k.udp_dst_port_or_gre_proto = 0;
    m.l3_protocol_type = 0;
    m.l4_protocol_type = hdr_type_ALL_1;
    m.udp_dst_port_or_gre_proto = 0;

    m_l3_termination_classify_ip_tunnels_table[4].key = k;
    m_l3_termination_classify_ip_tunnels_table[4].mask = m;
    m_l3_termination_classify_ip_tunnels_table[4].value = value_union;

    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.force_pipe_ttl = false; // for 5
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_null.force_pipe_ttl = false;
    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_IP_IN_IP;
    k.l3_protocol_type = 0;
    k.l4_protocol_type = NPL_PROTOCOL_TYPE_IPV4;
    k.udp_dst_port_or_gre_proto = 0;
    m.l3_protocol_type = 0;
    m.l4_protocol_type = (npl_protocol_type_e)0xF;
    m.udp_dst_port_or_gre_proto = 0;

    m_l3_termination_classify_ip_tunnels_table[5].key = k;
    m_l3_termination_classify_ip_tunnels_table[5].mask = m;
    m_l3_termination_classify_ip_tunnels_table[5].value = value_union;

    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_IP_IN_IP;
    k.l3_protocol_type = 0;
    k.l4_protocol_type = NPL_PROTOCOL_TYPE_IPV6;
    k.udp_dst_port_or_gre_proto = 0;
    m.l3_protocol_type = 0;
    m.l4_protocol_type = (npl_protocol_type_e)0xF;
    m.udp_dst_port_or_gre_proto = 0;

    m_l3_termination_classify_ip_tunnels_table[6].key = k;
    m_l3_termination_classify_ip_tunnels_table[6].mask = m;
    m_l3_termination_classify_ip_tunnels_table[6].value = value_union;

    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.force_pipe_ttl = false; // for 7 and 8
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_null.force_pipe_ttl = false;

    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.ingress_ptp_info.ptp_transport_type = NPL_PTP_TRANSPORT_IPV4;
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.ingress_ptp_info.is_ptp_trans_sup = true;
    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_PTP;
    k.l3_protocol_type = 4; // IPv4 .. see NPL enum_type protocol_type_e
    k.l4_protocol_type = NPL_PROTOCOL_TYPE_UDP;
    k.udp_dst_port_or_gre_proto = NPL_PTP_L3_UDP_DPORT;
    m.l3_protocol_type = 0xF;
    m.l4_protocol_type = hdr_type_ALL_1;
    m.udp_dst_port_or_gre_proto = udp_dst_port_or_gre_proto_ALL_1;

    m_l3_termination_classify_ip_tunnels_table[7].key = k;
    m_l3_termination_classify_ip_tunnels_table[7].mask = m;
    m_l3_termination_classify_ip_tunnels_table[7].value = value_union;

    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.ingress_ptp_info.ptp_transport_type = NPL_PTP_TRANSPORT_IPV6;
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.ingress_ptp_info.is_ptp_trans_sup = true;

    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_PTP;
    k.l3_protocol_type = 6; // IPv6 .. .. see NPL enum_type protocol_type_e
    k.l4_protocol_type = NPL_PROTOCOL_TYPE_UDP;
    k.udp_dst_port_or_gre_proto = NPL_PTP_L3_UDP_DPORT;
    m.l3_protocol_type = 0xF;
    m.l4_protocol_type = hdr_type_ALL_1;
    m.udp_dst_port_or_gre_proto = udp_dst_port_or_gre_proto_ALL_1;

    m_l3_termination_classify_ip_tunnels_table[8].key = k;
    m_l3_termination_classify_ip_tunnels_table[8].mask = m;
    m_l3_termination_classify_ip_tunnels_table[8].value = value_union;

    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.force_pipe_ttl = false; // default entry
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_null.force_pipe_ttl = false; // default entry

    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.ingress_ptp_info.ptp_transport_type
        = NPL_PTP_TRANSPORT_ETHERNET;
    value_union.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.ingress_ptp_info.is_ptp_trans_sup = false;
    value_union.payloads.tunnel_type.tunnel_type = NPL_IP_TUNNEL_NONE;
    k.l3_protocol_type = 0;
    k.l4_protocol_type = (npl_protocol_type_e)0;
    k.udp_dst_port_or_gre_proto = 0;
    m.l3_protocol_type = 0;
    m.l4_protocol_type = (npl_protocol_type_e)0;
    m.udp_dst_port_or_gre_proto = 0;

    m_l3_termination_classify_ip_tunnels_table[9].key = k;
    m_l3_termination_classify_ip_tunnels_table[9].mask = m;
    m_l3_termination_classify_ip_tunnels_table[9].value = value_union;

    la_status table_set_status;
    for (unsigned int i = 0;
         i < sizeof(m_l3_termination_classify_ip_tunnels_table) / sizeof(m_l3_termination_classify_ip_tunnels_table[0]);
         i = i + 1) // init loop
    {
        table_set_status = set_l3_termination_classify_ip_tunnels_table(
            i,                                            // entry line in table
            m_l3_termination_classify_ip_tunnels_table[i] // npl_l3_termination_classify_ip_tunnels_table_key_value_t
                                                          // key_mask_value // la_device_impl.h array element
            );
        if (table_set_status != LA_STATUS_SUCCESS)
            break;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_svl_remote_destination_resolution_table()
{
    la_status status;
    npl_svl_is_dsp_remote_t::key_type k;
    npl_svl_is_dsp_remote_t::key_type m;
    npl_svl_is_dsp_remote_t::value_type v;

    la_device_id_t device_id = m_ll_device->get_device_id();

    //
    // device id range check is not added for now.
    //
    // stack device object will be created to cater the supporting ASICs
    // backside stacking and stackwise virtual.  The device id
    // based usage will be replaced with stack device's node id
    //
    if (device_id > 1) {
        // only two nodes are supported
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // remote destination match using destination[19:8]
    m.destmsb = ((NPL_DESTINATION_DSP_PREFIX << 7) | (1 << (SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID - 8)));
    if (device_id == 0) {
        k.destmsb = ((NPL_DESTINATION_DSP_PREFIX << 7) | (1 << (SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID - 8)));
    } else {
        k.destmsb = (NPL_DESTINATION_DSP_PREFIX << 7);
    }
    v.payloads.svl_local_resolve_data.svl_dsp_remote_flag = 1;

    for (la_slice_id_t slice : get_used_slices()) {
        const auto& table(m_tables.svl_is_dsp_remote[slice]);
        npl_svl_is_dsp_remote_t::entry_pointer_type e = nullptr;
        status = table->set(0, k, m, v, e);
        return_on_error(status);
    }

    // local destination match
    m.destmsb = ((NPL_DESTINATION_DSP_PREFIX << 7) | (1 << (SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID - 8)));
    if (device_id != 0) {
        k.destmsb = ((NPL_DESTINATION_DSP_PREFIX << 7) | (1 << (SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID - 8)));
    } else {
        k.destmsb = (NPL_DESTINATION_DSP_PREFIX << 7);
    }
    v.payloads.svl_local_resolve_data.svl_dsp_remote_flag = 0;

    for (la_slice_id_t slice : get_used_slices()) {
        const auto& table(m_tables.svl_is_dsp_remote[slice]);
        npl_svl_is_dsp_remote_t::entry_pointer_type e = nullptr;
        status = table->set(1, k, m, v, e);
        return_on_error(status);
    }

    // catch-all
    m.destmsb = 0;
    k.destmsb = 0;
    v.payloads.svl_local_resolve_data.svl_dsp_remote_flag = 0;

    for (la_slice_id_t slice : get_used_slices()) {
        const auto& table(m_tables.svl_is_dsp_remote[slice]);
        npl_svl_is_dsp_remote_t::entry_pointer_type e = nullptr;
        status = table->set(2, k, m, v, e);
        return_on_error(status);
    }
    return status;
}

la_status
la_device_impl::initialize_phase_topology(const translator_creator_sptr& creator)
{
    la_status retval;

    // Since the shared pointer wrapping la_device is already instantiated in m_devices, copy it from there.
    m_objects[0] = m_devices[get_id()];

    m_device_port_handler->set_fabric_mode(m_fabric_mac_ports_mode);

    // prepare system init variables:
    bool is_hbm;
    retval = hbm_exists(is_hbm);
    return_on_error(retval);

    double frequency_mhz = m_device_frequency_int_khz / double(1000);
    size_t numnwk = 0;
    size_t numfab = 0;

    vector<device_configurator_base::lbr_slice_mode_e> slices_type;
    for (la_slice_id_t slice : get_used_slices()) {
        device_configurator_base::lbr_slice_mode_e sl_type = is_network_slice(slice)
                                                                 ? device_configurator_base::lbr_slice_mode_e::NETWORK
                                                                 : device_configurator_base::lbr_slice_mode_e::FABRIC;

        slices_type.push_back(sl_type);
        numnwk += (sl_type == device_configurator_base::lbr_slice_mode_e::NETWORK);
        numfab += (sl_type == device_configurator_base::lbr_slice_mode_e::FABRIC);
    }
    int mat_state;
    retval = get_int_property(la_device_property_e::MATILDA_MODEL_TYPE, mat_state);
    return_on_error(retval);

    bool is_100g_fabric_port_mode = (m_fabric_mac_ports_mode == (fabric_mac_ports_mode_e::E_2x50));

    int credit_in_bytes;
    retval = get_int_property(la_device_property_e::CREDIT_SIZE_IN_BYTES, credit_in_bytes);
    return_on_error(retval);

    start_profiling(device_configurator_profiler, "Device configurator");
    device_configurator_base::system_init_vars system_vars{frequency_mhz,
                                                           m_ll_device->get_device_id(),
                                                           is_hbm,
                                                           is_100g_fabric_port_mode,
                                                           numnwk,
                                                           numfab,
                                                           mat_state == 1 /* is_Matilda_64T */,
                                                           mat_state == 2 /* is_Matilda_32T_A */,
                                                           mat_state == 3 /* is_Matilda_32T_B */,
                                                           (size_t)credit_in_bytes};

    m_device_configurator = silicon_one::make_unique<device_configurator_base>(m_ll_device);
    retval = m_device_configurator->initialize(m_device_mode, system_vars, std::move(slices_type), get_used_slices());
    return_on_error(retval);

    retval = m_device_configurator->configure_device(init_stage_e::PRE_SOFT_RESET);
    return_on_error(retval);

    device_configurator_profiler.stop();

    if (m_gb_tree->get_revision() == la_device_revision_e::GIBRALTAR_A1) {
        retval = apply_gibraltar_a1_workarounds();
        return_on_error(retval);
    }

    // Resource manager mode
    bool is_fabric = (m_device_mode == device_mode_e::FABRIC_ELEMENT);
    m_resource_manager->set_device_mode(is_fabric);

    bool gb_initialization_other = false;
    get_bool_property(la_device_property_e::GB_INITIALIZE_OTHER, gb_initialization_other);
    if (gb_initialization_other) {
        log_debug(HLD, "%s: translator_creator", __func__);
        retval = initialize_translator_creator(creator);
        return_on_error(retval);
    }

    npu_static_config npu_cfg(shared_from_this());

    if (gb_initialization_other) {
        // Low level NPU config.
        log_debug(HLD, "%s: configure_hw", __func__);
        retval = npu_cfg.configure_hw();
        return_on_error(retval);
    }

    log_debug(HLD, "%s: init_topology", __func__);
    retval = init_topology();
    return_on_error(retval);

    if (gb_initialization_other) {
        log_debug(HLD, "%s: dmc", __func__);
        retval = init_dmc();
        return_on_error(retval);

        log_debug(HLD, "%s: sms_main", __func__);
        retval = init_sms_main();
        return_on_error(retval);

        // Central TCAM mapping
        log_debug(HLD, "%s: central TCAM mapping", __func__);

        bool is_linecard_mode = (m_device_mode == device_mode_e::LINECARD);

        size_t number_of_used_slices = m_slice_id_manager->get_used_slices_internal().size();

        m_resource_manager->init_ctm(is_linecard_mode, number_of_used_slices);

        // Initialize tables
        log_debug(HLD, "%s: tables", __func__);
        retval = m_tables.initialize_tables(*creator);
        return_on_error(retval);

        // Apply workarounds of HW hard reset issues.
        log_debug(HLD, "%s: apply workaround of HW hard reset issues", __func__);
        retval = apply_init_workarounds();

        return_on_error(retval);

        // Initialize slice modes
        log_debug(HLD, "%s: slice modes", __func__);
        retval = initialize_slice_modes();
        return_on_error(retval);
    }

    // Write device mode into table for simulator.
    retval = initialize_device_mode_table();
    return_on_error(retval);

    // Initialize link_up_vector to ones. For simulator.
    retval = initialize_link_up_vector();
    return_on_error(retval);

    // Initialize all_reachable_vector to zeros. For simulator.
    retval = initialize_all_reachable_vector();
    return_on_error(retval);

    // Initialize IFG handlers
    log_debug(HLD, "%s: ifg", __func__);
    retval = initialize_ifg();
    return_on_error(retval);

    if (gb_initialization_other) {
        if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
            // Initialize the MAC address manager
            m_mac_addr_manager = silicon_one::make_unique<mac_address_manager>(shared_from_this());

            // Initialize mac_da table
            retval = initialize_mac_da_table();
            return_on_error(retval);

            // Initialize the COPC protocol manager
            m_copc_protocol_manager = silicon_one::make_unique<copc_protocol_manager_base>(shared_from_this());

            // Initialize copc_protocol table
            retval = initialize_copc_protocol_table();
            return_on_error(retval);

            // Initialize trap settings
            log_debug(HLD, "%s: traps", __func__);
            retval = initialize_traps();
            // TODO-GB - fix initialize_traps and re-enable the return on error
            if (retval != LA_STATUS_SUCCESS) {
                log_err(HLD, "would fail config");
            }
            //  return_on_error(retval);

            // Initialize QoS mapping tables
            log_debug(HLD, "%s: QoS mapping tables", __func__);
            retval = initialize_qos_mapping_tables();
            return_on_error(retval);
        }

        log_debug(HLD, "%s: default vlaues for tables", __func__);

        // Initialize default values for bvn_tc_map table.
        retval = initialize_bvn_tc_map_default_values();
        return_on_error(retval);

        // Call before initialize_ip_tunnel_inner_ttl_decrement_config_table()
        retval = initialize_l3_termination_classify_ip_tunnels_table();
        return_on_error(retval);

        // Initialize default values for npl_ip_tunnel_inner_ttl_decrement_config_table
        retval = initialize_ip_tunnel_inner_ttl_decrement_config_table();
        return_on_error(retval);

        // Initialize default values for rewrite_sa_prefix_index table.
        // Shouldn't be used but NPL reads entry 0x00 of the table and doesn't use it.
        // In NPL2 it shouldn't happen and we need to remove this initialization.
        retval = initialize_rewrite_sa_prefix_index_table();
        return_on_error(retval);

        // Initialize scaffoldings
        log_debug(HLD, "%s: scaffolds", __func__);
        retval = initialize_scaffolds();
        return_on_error(retval);

        // Initialize the MAC address manager
        m_ipv4_tunnel_ep_manager = silicon_one::make_unique<ipv4_tunnel_ep_manager>(shared_from_this());

        // Initialize the IPv4 SIP index manager
        m_ipv4_sip_index_manager = silicon_one::make_unique<ipv4_sip_index_manager>(shared_from_this());

        // Initialize the CUD range manager
        retval = initialize_cud_range_managers();
        return_on_error(retval);

        retval = initialize_lpts_counter_tables();
        return_on_error(retval);

        // Initialize default values for counters_voq_block_map table
        retval = initialize_counters_voq_block_map_table();
        return_on_error(retval);

        // Create an LSR instance
        retval = create_lsr();
        return_on_error(retval);

        if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
            log_debug(HLD, "%s: forus destination", __func__);
            retval = create_forus_destination();
            return_on_error(retval);
        }

        retval = create_flow_cache_handler();
        return_on_error(retval);

        // Configure static tables
        log_debug(HLD, "%s: static tables", __func__);
        retval = configure_static_tables();
        return_on_error(retval);

        log_debug(HLD, "%s: mc_bitmap_tc_map_table", __func__);
        retval = configure_mc_bitmap_tc_map_table();
        return_on_error(retval);

        retval = configure_mc_emdb_tc_map_table();
        return_on_error(retval);

        retval = configure_tr_lc_sa_configuration_registers();
        return_on_error(retval);

        retval = configure_ibm_tc_map_table();
        return_on_error(retval);

        retval = configure_mirror_to_dsp_in_npu_soft_header_table();
        return_on_error(retval);

        retval = configure_snoop_to_dsp_in_npu_soft_header_table(0, 0);
        return_on_error(retval);

        retval = configure_multicast_scale_threshold_table(MAX_MC_LOCAL_MCID - 1);
        return_on_error(retval);

        // Initialize the counter manager
        m_counter_bank_manager = std::make_shared<counter_manager>(shared_from_this());
        retval = m_counter_bank_manager->initialize();
        return_on_error(retval);

        if (m_device_mode == device_mode_e::LINECARD) {
            log_debug(HLD, "%s: fabric_init_cfg_table", __func__);
            retval = configure_fabric_init_cfg_table();
            return_on_error(retval);
        }

        log_debug(HLD, "%s: device properties", __func__);
        retval = configure_device_properties_phase_topology();
        return_on_error(retval);

        for (la_slice_id_t slice : get_used_slices()) {
            m_mc_copy_id_manager[slice] = silicon_one::make_unique<mc_copy_id_manager>(shared_from_this(), slice);
            retval = m_mc_copy_id_manager[slice]->initialize();
            return_on_error(retval);
        }

        retval = initialize_sgacl_allocation_cache();
        return_on_error(retval);
    }

    // Soft reset
    log_debug(HLD, "%s: soft reset #0", __func__);
    retval = init_time_soft_reset(1 /*on*/);
    return_on_error(retval);

    // Wait till soft reset ends
    retval = poll_init_done();
    return_on_error(retval);

    if (gb_initialization_other) {
        log_debug(HLD, "%s: dynamic memories", __func__);

        retval = init_dynamic_memories();
        return_on_error(retval);

        retval = npu_cfg.configure_dynamic_memories();
        return_on_error(retval);
    }

    // WORKAROUND
    // Since there is a cyclic dependency between dynamic memories
    // which have to be initialized after soft reset
    // and other HW machines, which depend on them, Pacific should toggle
    // soft reset after dynamic memories are initialized
    /////////////////
    log_debug(HLD, "%s: soft reset #1", __func__);
    retval = init_time_soft_reset(0); // off
    return_on_error(retval);

    log_debug(HLD, "command::step_no_response %d", 10);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    log_debug(HLD, "%s: soft reset #2", __func__);
    retval = init_time_soft_reset(1); // on
    return_on_error(retval);

    retval = poll_init_done();
    return_on_error(retval);
    // end WORKAROUND

    retval = apply_topology_pre_2nd_soft_reset_workaround();
    return_on_error(retval);

    retval = m_device_configurator->configure_device(init_stage_e::POST_SOFT_RESET);
    return_on_error(retval);
    log_info(HLD, "FINISHED POST SOFT RESET INIT");

    retval = apply_post_init_config_workaround();
    return_on_error(retval);

    retval = apply_topology_post_soft_reset_workaround();
    return_on_error(retval);

    // Initialize internal error counters
    retval = init_internal_error_handling();
    if (retval != LA_STATUS_SUCCESS) {
        return retval;
    }

    if (gb_initialization_other) {
        log_debug(HLD, "%s: post soft reset", __func__);

        // Configure CDB ARC
        log_debug(HLD, "%s: CDB ARC", __func__);
        retval = npu_cfg.configure_cdb_arc();
        return_on_error(retval);

        // Initialize the resource manager and its resources
        retval = init_resource_management();
        return_on_error(retval);

        retval = disable_ipv4_header_checking();
        return_on_error(retval);

        retval = init_meters();
        return_on_error(retval);

        retval = configure_npu_host();
        return_on_error(retval);

        retval = configure_learn_manager();
        return_on_error(retval);

        // Read default CGM values.
        if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
            retval = m_voq_cgm_handler->save_voq_cgm_defaults();
            return_on_error(retval);

            retval = configure_voq_cgm_default_evicted_profile();
            return_on_error(retval);

            retval = configure_voq_cgm_drop_profile();
            return_on_error(retval);

            retval = configure_default_rx_cgm_sq_profile();
            return_on_error(retval);

            retval = configure_static_voqs();
            return_on_error(retval);
        }

        // Lookup error WA - PACIFIC_A0_WA
        // Catch all lookup error packets and drop them.
        if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
            retval = configure_lookup_error_drop_dsp();
            return_on_error(retval);

            // Special DSP that is used for as drop destination
            retval = configure_rx_drop_dsp();
            return_on_error(retval);

            // Special DSP that is used for as drop destination without counter
            retval = configure_rx_not_cnt_drop_dsp();
            return_on_error(retval);
        }

        // Updating minimum links is needed in LC for multicast traffic, it is used in updating the fmc_eligble vector!
        if (m_device_mode != device_mode_e::STANDALONE) {
            retval = init_fabric_minimum_links();
            return_on_error(retval);
        }
    }

    bool svl_mode = false;
    get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);

    retval = configure_svl_mode_table(svl_mode);
    return_on_error(retval);

    if (svl_mode) {
        retval = configure_svl_remote_destination_resolution_table();
        return_on_error(retval);
    }

    // Prepare dedicated system ports for MCG counter Tx packets processing.
    init_valid_ifgs_for_mcg_counters();
    retval = prepare_dedicated_oq_for_mcg_counter();
    return_on_error(retval);

    // Reserve exact meter profile tables for statistical meter counter purpose.
    retval = create_exact_meter_as_counter_profiles();
    return_on_error(retval);

    retval = init_resolution_set_next_macro_table();
    return_on_error(retval);

    retval = configure_fabric_tables();
    return_on_error(retval);

    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        retval = m_voq_cgm_handler->initialize();
        return_on_error(retval);
    }

    bool power_saving_mode = false;
    get_bool_property(la_device_property_e::ENABLE_POWER_SAVING_MODE, power_saving_mode);
    if (power_saving_mode) {
        la_status status = rxpp_use_single_npe_on_fabric_slices();
        log_on_error(status, HLD, ERROR, "Failed to configure using single NPE on fabric slices.");
        status = turn_off_idb_res_and_encdb_blocks();
        log_on_error(status, HLD, ERROR, "Failed to disable idb_res and idb_encdb blocks.");
    }

    log_debug(HLD, "%s: start notifications", __func__);
    retval = start_notifications();
    return_on_error(retval);

    // Initialize SDA mode
    retval = configure_sda_mode(false);
    return_on_error(retval);

    retval = m_init_performance_helper->set_init_completed();
    log_on_error(retval, HLD, WARNING, "Failed to commit device initialization data to CSS memory");

    log_debug(HLD, "%s: done", __func__);

    return retval;
}

la_status
la_device_impl::start_notifications()
{
    if (m_reconnect_handler->is_reconnect_in_progress()) {
        log_debug(HLD, "%s: skip, reconnect is in progress", __func__);
        return LA_STATUS_SUCCESS;
    }

    register_pollers();
    m_notification->get_interrupt_tree()->clear();

    log_debug(HLD, "%s: start worker threads", __func__);

    // Start interrupt+polling threads.
    return m_notification->start();
}

la_status
la_device_impl::apply_post_init_config_workaround()
{
    // TODO: frequency-based initialization, should move to LBR init_config once frequency-based expressions are supported.
    if (m_reconnect_handler->is_reconnect_in_progress()) {
        return LA_STATUS_SUCCESS;
    }

    la_status rc = m_hbm_handler->apply_post_init_config_workaround();

    return rc;
}

la_status
la_device_impl::remove_network_slices_entry_from_recycle_override_table(uint64_t key_recycle_code,
                                                                        uint64_t key_recycle_data,
                                                                        uint64_t key_sched_rcy)
{
    npl_recycle_override_table_t::key_type k;

    k.rxpp_npu_input_rcy_code_1_ = key_recycle_code;
    k.packet_is_rescheduled_recycle = key_sched_rcy;
    k.rxpp_npu_input_tx_to_rx_rcy_data_3_0_ = key_recycle_data & 0xF; // only 4 LSBs used

    const auto& tables(m_tables.recycle_override_table);
    la_status status = per_slice_tables_erase(m_slice_mode, tables, {la_slice_mode_e::NETWORK}, k);

    return status;
}

la_status
la_device_impl::configure_recycle_override_network_slices_entry(uint64_t key_recycle_code,
                                                                uint64_t key_recycle_data,
                                                                uint64_t key_sched_rcy,
                                                                bool override_src,
                                                                npl_macro_e np_macro,
                                                                npl_fi_macro_ids_e fi_macro)
{
    npl_recycle_override_table_t::key_type k;
    npl_recycle_override_table_t::value_type v;
    npl_recycle_override_table_t::entry_pointer_type e = nullptr;

    k.rxpp_npu_input_rcy_code_1_ = key_recycle_code;
    k.packet_is_rescheduled_recycle = key_sched_rcy;
    k.rxpp_npu_input_tx_to_rx_rcy_data_3_0_ = key_recycle_data & 0xF; /* only 4 LSBs used */
    v.action = NPL_RECYCLE_OVERRIDE_TABLE_ACTION_INIT_RX_DATA;
    v.payloads.init_rx_data.override_source_port_table = override_src;
    v.payloads.init_rx_data.initial_layer_index = 0;
    v.payloads.init_rx_data.initial_rx_data.init_recycle_fields.initial_is_rcy_if = 1;
    v.payloads.init_rx_data.tag_swap_cmd = NPL_NO_TAG_SWAP;
    v.payloads.init_rx_data.np_macro_id = np_macro;
    v.payloads.init_rx_data.fi_macro_id = fi_macro;
    v.payloads.init_rx_data.first_header_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    v.payloads.init_rx_data.first_header_is_layer = 1;

    npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t init_data;
    memset(&init_data, 0, sizeof(npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t));

    la_status stat;
    for (size_t slice_id : get_used_slices()) {
        // Fabric slices on LC should have zero in the config.
        if (m_slice_mode[slice_id] != la_slice_mode_e::NETWORK) {
            continue;
        }
        v.payloads.init_rx_data.initial_rx_data.init_recycle_fields.init_data = init_data; /* Initialize init_data with '0' */
        v.payloads.init_rx_data.initial_rx_data.init_recycle_fields.init_data.initial_slice_id = slice_id;
        stat = m_tables.recycle_override_table[slice_id]->insert(k, v, e);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_recycle_override_table()
{
    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        la_status status = configure_recycle_override_table_fe();

        return status;
    }

    la_status status = configure_recycle_override_table_sa_lc();

    return status;
}

la_status
la_device_impl::configure_recycle_override_table_fe()
{
    // TODO - maybe this code is not needed. Verify with Asaf Shalom
    npl_recycle_override_table_t::key_type k;
    npl_recycle_override_table_t::value_type v;
    npl_recycle_override_table_t::entry_pointer_type e = nullptr;

    v.action = NPL_RECYCLE_OVERRIDE_TABLE_ACTION_INIT_RX_DATA;

    // Assume that all fields of the value are zero-ed.
    v.payloads.init_rx_data.override_source_port_table = 1;
    v.payloads.init_rx_data.fi_macro_id = NPL_FI_MACRO_ID_FABRIC;
    v.payloads.init_rx_data.np_macro_id = NPL_FABRIC_ELEMENT_RX_TERM_MACRO;

    for (size_t i = 0; i < (1 << RECYCLE_OVERRIDE_TABLE_KEY_LEN); i++) {
        k.rxpp_npu_input_rcy_code_1_ = bit_utils::get_bits(i, 0 /*msb*/, 0 /*lsb*/);
        k.packet_is_rescheduled_recycle = bit_utils::get_bits(i, 1 /*msb*/, 1 /*lsb*/);
        k.rxpp_npu_input_tx_to_rx_rcy_data_3_0_ = bit_utils::get_bits(i, 5 /*msb*/, 2 /*lsb*/);

        la_status status;
        for (size_t slice_id : get_used_slices()) {
            if (m_slice_mode[slice_id] != la_slice_mode_e::CARRIER_FABRIC) {
                continue;
            }

            v.payloads.init_rx_data.initial_rx_data.init_recycle_fields.init_data.initial_npp_attributes_index = 0;
            v.payloads.init_rx_data.initial_rx_data.init_recycle_fields.init_data.initial_slice_id = slice_id;
            status = m_tables.recycle_override_table[slice_id]->insert(k, v, e);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_recycle_override_table_sa_lc()
{
    la_status status;

    status = configure_recycle_override_table_sa_lc_network_slices();
    return_on_error(status);

    if (m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    status = configure_recycle_override_table_lc_fabric_slices();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_recycle_override_table_sa_lc_network_slices()
{
    la_status status = configure_recycle_override_network_slices_entry(0 /* key_recycle_code */,
                                                                       0 /* key_recycle_data */,
                                                                       0 /* key_sched_rcy */,
                                                                       false /* override_src */,
                                                                       (npl_macro_e)0 /* np_macro */,
                                                                       (npl_fi_macro_ids_e)0 /* fi_macro */);
    return_on_error(status);

    status = configure_recycle_override_network_slices_entry(0 /* key_recycle_code */,
                                                             0 /* key_recycle_data */,
                                                             1 /* key_sched_rcy */,
                                                             false /* override_src */,
                                                             (npl_macro_e)0 /* np_macro */,
                                                             (npl_fi_macro_ids_e)0 /* fi_macro */);
    return_on_error(status);

    status = configure_recycle_override_network_slices_entry(1 /* key_recycle_code */,
                                                             NPL_TX2RX_RCY_DATA_TX_REDIRECT_TO_DEST /* key_recycle_data */,
                                                             0 /* key_sched_rcy */,
                                                             true /* override_src */,
                                                             NPL_RX_INJECT_MACRO /* np_macro */,
                                                             NPL_FI_MACRO_ID_ETH /* fi_macro */
                                                             );
    return_on_error(status);

    status = configure_recycle_override_network_slices_entry(1 /* key_recycle_code */,
                                                             NPL_TX2RX_RCY_DATA_TX_REDIRECT_TO_DEST /* key_recycle_data */,
                                                             1 /* key_sched_rcy */,
                                                             true /* override_src */,
                                                             NPL_RX_INJECT_MACRO /* np_macro */,
                                                             NPL_FI_MACRO_ID_ETH /* fi_macro */
                                                             );
    return_on_error(status);

    status = configure_recycle_override_network_slices_entry(1 /* key_recycle_code */,
                                                             NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT /* key_recycle_data */,
                                                             1 /* key_sched_rcy */,
                                                             true /* override_src */,
                                                             NPL_OUTBOUND_MIRROR_RX_MACRO /* np_macro */,
                                                             NPL_FI_MACRO_ID_ETH /* fi_macro */
                                                             );
    return_on_error(status);

    status = configure_recycle_override_network_slices_entry(0 /* key_recycle_code */,
                                                             NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT /* key_recycle_data */,
                                                             1 /* key_sched_rcy */,
                                                             true /* override_src */,
                                                             NPL_OUTBOUND_MIRROR_RX_MACRO /* np_macro */,
                                                             NPL_FI_MACRO_ID_ETH /* fi_macro */
                                                             );

    status = configure_recycle_override_network_slices_entry(1 /* key_recycle_code */,
                                                             NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT /* key_recycle_data */,
                                                             0 /* key_sched_rcy */,
                                                             true /* override_src */,
                                                             NPL_OUTBOUND_MIRROR_RX_MACRO /* np_macro */,
                                                             NPL_FI_MACRO_ID_ETH /* fi_macro */
                                                             );
    return_on_error(status);

    status = configure_recycle_override_network_slices_entry(0 /* key_recycle_code */,
                                                             NPL_TX2RX_SCHED_RCY_DATA_TX_REDIRECT_TO_DEST /* key_recycle_data */,
                                                             1 /* key_sched_rcy */,
                                                             true /* override_src */,
                                                             NPL_RX_INJECT_MACRO /* np_macro */,
                                                             NPL_FI_MACRO_ID_ETH /* fi_macro */
                                                             );
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_recycle_override_table_lc_fabric_slices()
{
    const auto& tables(m_tables.recycle_override_table);

    // TODO - maybe this code can be unified with the FE slice config. Verify with Asaf Shalom
    npl_recycle_override_table_t::key_type k;
    npl_recycle_override_table_t::value_type v;

    v.action = NPL_RECYCLE_OVERRIDE_TABLE_ACTION_INIT_RX_DATA;

    // Assume that all fields of the value are zero-ed.

    for (size_t i = 0; i < (1 << RECYCLE_OVERRIDE_TABLE_KEY_LEN); i++) {
        k.rxpp_npu_input_rcy_code_1_ = bit_utils::get_bits(i, 0 /*msb*/, 0 /*lsb*/);
        k.packet_is_rescheduled_recycle = bit_utils::get_bits(i, 1 /*msb*/, 1 /*lsb*/);
        k.rxpp_npu_input_tx_to_rx_rcy_data_3_0_ = bit_utils::get_bits(i, 5 /*msb*/, 2 /*lsb*/);

        la_status status = per_slice_tables_insert(m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::retrieve_overhead_accounting(int& out_overhead) const
{
    // TODO GB - impl needs to change (pdvoq, ics). not mandatory for bringup.

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::initialize_fabric_ifgb(la_mac_port::fc_mode_e fc_mode)
{
    for (la_slice_id_t sid : get_used_slices()) {
        if (m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }
        for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
            la_status status = m_ifg_handlers[sid][ifg_id]->configure_fabric_ports(fc_mode);
            return_on_error(status);
        }
    }

    m_fabric_ports_initialized = true;
    m_fabric_fc_mode = fc_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_ifg()
{
    for (la_slice_id_t sid : get_used_slices()) {
        for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
            la_status status = m_ifg_handlers[sid][ifg_id]->initialize();
            return_on_error(status);

            m_ifg_schedulers[sid][ifg_id] = std::make_shared<la_ifg_scheduler_impl>(shared_from_this(), sid, ifg_id);
            la_object_id_t oid;
            status = register_object(m_ifg_schedulers[sid][ifg_id], oid);
            return_on_error(status);

            status = m_ifg_schedulers[sid][ifg_id]->initialize(oid);
            if (status != LA_STATUS_SUCCESS) {
                deregister_object(oid);
                return status;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_slice_modes()
{
    // Set the slice modes table of hardware.npl
    const auto& table(m_tables.slice_modes_table);
    npl_slice_modes_table_t::key_type k;
    npl_slice_modes_table_t::value_type v;
    npl_slice_modes_table_t::entry_pointer_type e = nullptr;

    v.action = NPL_SLICE_MODES_TABLE_ACTION_WRITE;

    for (la_slice_id_t sid : get_used_slices()) {
        k.slice_id = sid;
        la_slice_mode_e slice_mode = m_slice_mode[sid];
        v.payloads.slice_modes_table_in_out_vars_slice_mode = la_2_npl_slice_mode(slice_mode);
        la_status status = table->insert(k, v, e);
        return_on_error(status);
    }
    for (la_slice_id_t sid : get_used_slices()) {
        if (m_slice_mode[sid] == la_slice_mode_e::INVALID) {
            std::cout << "Slice " << sid << " invalid\n";
            m_slice_mode[sid] = la_slice_mode_e::DISABLED;
        }
    }

    return LA_STATUS_SUCCESS;
}

bool
la_device_impl::is_event_type_disabled(la_event_e trap)
{
    switch (trap) {
    case LA_EVENT_IPV4_MC_FORWARDING_DISABLED:
    case LA_EVENT_IPV4_UC_FORWARDING_DISABLED:
    case LA_EVENT_IPV6_MC_FORWARDING_DISABLED:
    case LA_EVENT_IPV6_UC_FORWARDING_DISABLED:
    case LA_EVENT_MPLS_FORWARDING_DISABLED:
        return true;
    default:
        return false;
    }
}

bool
la_device_impl::skip_trap_init(la_event_e trap)
{
    switch (trap) {
    // Non-inject is a special case for handling only network packets
    case LA_EVENT_L3_DROP_ADJ_NON_INJECT:
    // Snoop events should not be set as a trap configuration
    case LA_EVENT_L3_IP_MC_SNOOP_DC_PASS:
    case LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL:
    case LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS:
        return true;
    default:
        return false;
    }
}

la_status
la_device_impl::initialize_traps()
{
    la_status status = initialize_internal_traps();
    return_on_error(status);

    // Verify that the internal traps are placed after the user-configurable traps.
    static_assert(LA_EVENT_SVL_LAST < LA_EVENT_INTERNAL_FIRST, "Internal traps must be placed after the user-configurable traps.");

    // Enable all traps.
    // Any trap will currently cause a drop.
    destination_id drop_dest_id = get_actual_destination_id(RX_DROP_DSP);
    for (size_t idx = LA_EVENT_ETHERNET_FIRST; idx <= LA_EVENT_SVL_LAST; idx++) {
        la_event_e trap = (la_event_e)idx;
        // Some special case events should not be initialized as trap
        if (skip_trap_init(trap)) {
            continue;
        }

        uint64_t redirect_code = get_drop_redirect_destination(trap);
        bool disable_snoop = is_event_type_disabled(trap);

        status = configure_redirect_code(redirect_code,
                                         disable_snoop,
                                         false /* is_l3_trap */,
                                         nullptr /*counter*/,
                                         drop_dest_id,
                                         NPL_PUNT_NW_ETH_ENCAP_TYPE,
                                         DUMMY_REDIRECT_ENCAP_PTR,
                                         true,
                                         0 /* tc */);
        return_on_error(status);

        // For the following traps configure so inject up packets will not trigger them
        bool skip_inject_up_packets = false;
        switch (trap) {
        case LA_EVENT_IPV4_HEADER_ERROR:
        case LA_EVENT_IPV6_HEADER_ERROR:
        case LA_EVENT_ETHERNET_SA_DA_ERROR:
        case LA_EVENT_ETHERNET_DA_ERROR:
        case LA_EVENT_ETHERNET_SA_ERROR:
            skip_inject_up_packets = true;
            break;
        default:
            break;
        }

        la_trap_priority_t priority = get_default_trap_priority(trap);

        la_trap_config_entry trap_cfg;
        trap_cfg.trap = trap;
        trap_cfg.priority = priority;
        trap_cfg.counter_or_meter = {};
        trap_cfg.punt_dest = {};
        trap_cfg.skip_inject_up_packets = skip_inject_up_packets;
        trap_cfg.skip_p2p_packets = false;
        trap_cfg.overwrite_phb = true;
        trap_cfg.tc = 0;

        // Find trap's location. The new-location logic assumes that entries at the location and forth will be pushed down.
        // So actually need to find the first inferior trap index.
        size_t location = 0;
        for (; location < m_trap_entries.size(); location++) {
            if (m_trap_entries[location].priority > priority) {
                break;
            }
        }

        m_trap_entries.insert(m_trap_entries.begin() + location, trap_cfg);
    }

    // m_trap_entries was built to cohere with the redirect_table order:
    for (size_t idx = 0; idx < m_trap_entries.size(); ++idx) {
        la_event_e trap = m_trap_entries[idx].trap;
        uint64_t redirect_code = get_drop_redirect_destination(trap);
        bool skip_inject_up_packets = m_trap_entries[idx].skip_inject_up_packets;

        status = configure_event_to_redirect_code(
            trap, idx, redirect_code, skip_inject_up_packets, false /*p2p*/, false /*is_overwrite*/);
        return_on_error(status);
    }

    status = configure_recycle_override_table();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_internal_traps()
{
    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        // Configure dummy Ethernet encapsulation for dropped packets.
        uint8_t encap_ptr = DUMMY_REDIRECT_ENCAP_PTR;
        la_mac_addr_t da = {.flat = 0};
        la_mac_addr_t sa = {.flat = 0};
        la_vlan_tag_tci_t vlan_tag = {.raw = 0};

        la_status status = configure_redirect_eth_encap(encap_ptr, da, sa, vlan_tag);
        return_on_error(status);

        // Configure the redirect destination to the drop destination.
        // LPTS code
        destination_id drop_dest_id = get_actual_destination_id(RX_DROP_DSP);
        status = configure_redirect_code(NPL_REDIRECT_CODE_LPM_LPTS,
                                         false /* disable_snoop */,
                                         true /* is_l3_trap */,
                                         nullptr /*counter*/,
                                         drop_dest_id,
                                         NPL_PUNT_NW_ETH_ENCAP_TYPE,
                                         encap_ptr,
                                         true,
                                         0 /* tc */);
        return_on_error(status);

        // Configure the redirect destination to the drop destination.
        // LPTS code
        status = configure_redirect_code(NPL_REDIRECT_CODE_LPM_MC_LPTS,
                                         false /* disable_snoop */,
                                         true /* is_l3_trap */,
                                         nullptr /*counter*/,
                                         drop_dest_id,
                                         NPL_PUNT_NW_ETH_ENCAP_TYPE,
                                         encap_ptr,
                                         true,
                                         0 /* tc */);
        return_on_error(status);
    }

    // Map internal npl traps to their redirect code:
    for (size_t idx = LA_EVENT_INTERNAL_FIRST; idx <= LA_EVENT_INTERNAL_LAST; idx++) {
        la_event_e trap = (la_event_e)idx;
        la_trap_priority_t priority = get_default_trap_priority(trap);

        la_trap_config_entry trap_cfg;
        trap_cfg.trap = trap;
        trap_cfg.priority = priority;
        trap_cfg.counter_or_meter = {};
        trap_cfg.punt_dest = {};
        trap_cfg.skip_inject_up_packets = true;
        trap_cfg.skip_p2p_packets = false;
        trap_cfg.overwrite_phb = true;
        trap_cfg.tc = 0;

        // Find trap's location. The new-location logic assumes that entries at the location and forth will be pushed down.
        // So actually need to find the first inferior trap index.
        size_t location = 0;
        for (; location < m_trap_entries.size(); location++) {
            if (m_trap_entries[location].priority > priority) {
                break;
            }
        }

        m_trap_entries.insert(m_trap_entries.begin() + location, trap_cfg);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_scaffolds()
{
    la_status status;

    status = initialize_scaffold_vlan_edit_tables();
    return_on_error(status);

    la_slice_id_vec_t network_slicepairs = get_slice_pairs(shared_from_this(), la_slice_mode_e::NETWORK);
    for (la_slice_pair_id_t slice_pair : network_slicepairs) {
        status = initialize_acl_select_tables(slice_pair);
        return_on_error(status);
    }

    status = set_acl_scaled_enabled(false);
    return_on_error(status);

    status = initialize_scaffold_encap_qos_tag_table();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::initialize_mac_da_table()
{
    return m_mac_addr_manager->initialize();
}

la_status
la_device_impl::initialize_copc_protocol_table()
{
    return m_copc_protocol_manager->initialize();
}

la_status
la_device_impl::initialize_lpts_counter_tables()
{
    // Set entry 0 of the LPTS compressed counters to point at the null counter
    for (la_slice_id_t slice : get_used_slices()) {
        const auto& t(m_tables.lpts_meter_table[slice]);
        npl_lpts_meter_table_t::key_type k;
        npl_lpts_meter_table_t::value_type v;
        npl_lpts_meter_table_t::entry_pointer_type e = nullptr;

        k.meter_index_msb = 0;
        k.meter_index_lsb = 0;
        v.payloads.counter_ptr.update_or_read = 0;
        v.payloads.counter_ptr = NPU_COUNTER_INVALID;

        la_status status = t->insert(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_counters_voq_block_map_table()
{
    npl_counters_voq_block_map_table_t::key_type k;
    npl_counters_voq_block_map_table_t::value_type v;
    npl_counters_voq_block_map_table_t::entry_pointer_type entry_ptr = nullptr;

    // Initialize all entries to same value
    v.payloads.counters_voq_block_map_result.bank_id = COUNTERS_VOQ_BLOCK_MAP_TABLE_INVALID_BANK_ID;
    v.payloads.counters_voq_block_map_result.map_groups_size = 0;
    v.payloads.counters_voq_block_map_result.tc_profile = 0;
    v.payloads.counters_voq_block_map_result.counter_offset = 0;
    v.action = NPL_COUNTERS_VOQ_BLOCK_MAP_TABLE_ACTION_WRITE;

    for (la_slice_id_t slice : get_used_slices()) {
        const auto& table(m_tables.counters_voq_block_map_table[slice]);
        size_t num_lines = 1 << BITS_SIZEOF(k, voq_base_id);
        for (size_t line = 0; line < num_lines; line++) {
            k.voq_base_id = line;
            la_status write_status = table->insert(k, v, entry_ptr);
            return_on_error(write_status);
        }
    }

    return LA_STATUS_SUCCESS;
}

uint64_t
la_device_impl::get_drop_redirect_destination(la_event_e trap)
{
    switch (trap) {
    case LA_EVENT_ETHERNET_ACL_DROP:
        return NPL_REDIRECT_CODE_L2_ACL_DROP;
    case LA_EVENT_L3_ACL_DROP:
        return NPL_REDIRECT_CODE_L3_ACL_DROP;
    case LA_EVENT_ETHERNET_ACL_FORCE_PUNT:
        return NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT;
    case LA_EVENT_L3_ACL_FORCE_PUNT:
        return NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT;
    case LA_EVENT_INTERNAL_L3_LPM_LPTS:
    case LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_ROUTING:
    case LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_ROUTING:
        return NPL_REDIRECT_CODE_LPM_LPTS;
    case LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_BRIDGING:
    case LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_BRIDGING:
        return NPL_REDIRECT_CODE_LPM_LPTS;
    case LA_EVENT_L3_TX_FRR_DROP:
        return NPL_REDIRECT_CODE_DROP_NO_RECYCLE;
    default:
        return trap;
    }
}

la_trap_priority_t
la_device_impl::get_default_trap_priority(la_event_e trap)
{
    const set<la_event_e> MOST_PRIORITIZED_INTERNAL_TRAPS = {LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_ROUTING,
                                                             LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_ROUTING,
                                                             LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_BRIDGING,
                                                             LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_BRIDGING};

    auto it = MOST_PRIORITIZED_INTERNAL_TRAPS.find(trap);
    if (it != MOST_PRIORITIZED_INTERNAL_TRAPS.end()) {
        return 0;
    } else if (trap == LA_EVENT_INTERNAL_L3_LPM_LPTS) {
        return (LAST_USER_ALLOWED_PRIORITY + 1);
    }
    return trap;
}

la_status
la_device_impl::create_exact_meter_as_counter_profiles()
{
    la_status status;
    la_meter_profile* meter_profile;
    status = create_meter_profile(la_meter_profile::type_e::PER_IFG,
                                  la_meter_profile::meter_measure_mode_e::BYTES,
                                  la_meter_profile::meter_rate_mode_e::SR_TCM,
                                  la_meter_profile::color_awareness_mode_e::AWARE,
                                  meter_profile);
    return_on_error(status);
    m_exact_meter_profile = get_sptr(static_cast<la_meter_profile_impl*>(meter_profile));

    // Committed and excess burst size in bytes. The configuration is based on max interface MTU.
    // The recommended configuration of burst is 10 times interface MTU.
    const la_uint64_t CBS = (10 * UNITS_IN_KIBI);
    const la_uint64_t EBS_OR_PBS = (2 * CBS);

    for (la_slice_ifg slice_ifg : this->get_used_ifgs()) {
        status = m_exact_meter_profile->set_cbs(slice_ifg, CBS);
        return_on_error(status);
        status = m_exact_meter_profile->set_ebs_or_pbs(slice_ifg, EBS_OR_PBS);
        return_on_error(status);
    }
    m_is_builtin_objects[m_exact_meter_profile->oid()] = true;

    la_meter_action_profile* meter_action_profile;
    status = create_meter_action_profile(meter_action_profile);
    return_on_error(status);
    m_exact_meter_action_profile = get_sptr(meter_action_profile);

    // This is a special meter action table used by hidden exact meter. Exact meter is used to support
    // counters(G/Y/R) for statistical meter. Exact meter is configured with maximum rate to mimic
    // counter behaviour. Action table is configured to produce the outgoing meter color as incoming packet
    // color and Rx-CGM color as GREEN.
    bool drop_enable = false;
    bool mark_ecn = false;
    const la_qos_color_e colors[] = {la_qos_color_e::GREEN, la_qos_color_e::YELLOW, la_qos_color_e::RED};
    for (auto meter_color : colors) {
        for (auto rate_limiter_color : colors) {
            status = m_exact_meter_action_profile->set_action(
                meter_color, rate_limiter_color, drop_enable, mark_ecn, rate_limiter_color, la_qos_color_e::GREEN);
            return_on_error(status);
        }
    }
    m_is_builtin_objects[m_exact_meter_action_profile->oid()] = true;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_sda_mode(bool mode)
{
    start_api_call("mode=", mode);

    if (m_sda_mode == mode) {
        return LA_STATUS_SUCCESS;
    }

    return configure_sda_mode(mode);
}

la_status
la_device_impl::configure_sda_mode(bool mode)
{
    const auto& table(m_tables.sda_fabric_enable_table);
    npl_sda_fabric_enable_table_t::key_type k;
    npl_sda_fabric_enable_table_t::value_type v;
    npl_sda_fabric_enable_table_t::entry_pointer_type entry_ptr = nullptr;

    k.l2_enforcement = 1;

    v.action = NPL_SDA_FABRIC_ENABLE_TABLE_ACTION_WRITE;
    v.payloads.sda_fabric_feature.enable = mode;
    v.payloads.sda_fabric_feature.l2_enforcement = 1;

    la_status status = table->set(k, v, entry_ptr);
    return_on_error(status);

    k.l2_enforcement = 0;

    v.action = NPL_SDA_FABRIC_ENABLE_TABLE_ACTION_WRITE;
    v.payloads.sda_fabric_feature.enable = mode;
    v.payloads.sda_fabric_feature.l2_enforcement = 0;

    status = table->set(k, v, entry_ptr);
    return_on_error(status);

    m_sda_mode = mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_sda_mode(bool& out_mode) const
{
    start_api_getter_call();

    out_mode = m_sda_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_security_group_cell(la_sgt_t sgt,
                                           la_dgt_t dgt,
                                           la_ip_version_e ip_version,
                                           la_security_group_cell*& out_security_group_cell)
{
    start_api_call("sgt=", sgt, "dgt=", dgt, "ip_version=", ip_version);

    auto sg_cell = std::make_shared<la_security_group_cell_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(sg_cell, oid);

    status = sg_cell->initialize(oid, sgt, dgt, ip_version, nullptr);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return_on_error(status);
    }

    out_security_group_cell = sg_cell.get();

    la_device_impl::security_group_cell_t cell = {.sgt = sgt, .dgt = dgt, .ip_version = ip_version};
    m_security_group_cell_map[cell] = sg_cell;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::add_trap_counter_or_meter(uint64_t redirect_code, const la_counter_or_meter_set_wptr& counter_or_meter)
{
    if (counter_or_meter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (!of_same_device(counter_or_meter, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto prev_counter_or_meter = m_trap_counters_or_meters[redirect_code];
    if (counter_or_meter == prev_counter_or_meter) {
        return LA_STATUS_SUCCESS;
    }

    if (counter_or_meter->type() == la_object::object_type_e::COUNTER_SET) {
        auto counter_impl = counter_or_meter.weak_ptr_static_cast<la_counter_set_impl>();
        la_uint64_t counter_set_max_size = 0;
        get_limit(limit_type_e::COUNTER_SET__MAX_PIF_COUNTER_OFFSET, counter_set_max_size);
        if (counter_impl->get_set_size() != 1 && counter_impl->get_set_size() != counter_set_max_size) {
            // Counter set must either be single counter or 26 to accommodate counter for all PIFs
            return LA_STATUS_EINVAL;
        }
        la_status status = counter_impl->add_trap_counter(COUNTER_DIRECTION_INGRESS);
        return_on_error(status);
        add_object_dependency(counter_impl, this);
    } else {
        auto meter_impl = counter_or_meter.weak_ptr_static_cast<la_meter_set_impl>();
        // Traps are configured for all slices so the meter should be aggregate
        la_status status = meter_impl->attach_user(shared_from_this(), true /*is_aggregate*/);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::remove_trap_counter_or_meter(uint64_t redirect_code)
{
    la_status status;
    const auto& counter_or_meter = m_trap_counters_or_meters[redirect_code];

    if (counter_or_meter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (counter_or_meter->type() == la_object::object_type_e::COUNTER_SET) {
        auto counter_impl = counter_or_meter.weak_ptr_static_cast<la_counter_set_impl>();
        status = counter_impl->remove_trap_counter(COUNTER_DIRECTION_INGRESS);
        remove_object_dependency(counter_impl, this);
    } else {
        auto meter_impl = counter_or_meter.weak_ptr_static_cast<la_meter_set_impl>();
        status = meter_impl->detach_user(shared_from_this());
    }

    return_on_error(status);

    m_trap_counters_or_meters[redirect_code] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_redirect_eth_encap(uint64_t encap_ptr, la_mac_addr_t da, la_mac_addr_t sa, la_vlan_tag_tci_t vlan_tag)
{
    npl_tx_punt_eth_encap_table_t::key_type k;
    npl_tx_punt_eth_encap_table_t::value_type v;
    npl_tx_punt_eth_encap_table_t::entry_pointer_type e = nullptr;
    uint64_t smac_index;
    bool remove_old_smac = false;
    la_mac_addr_t old_smac;
    la_status status;

    auto smac_it = m_encap_ptr_smac_map.find(encap_ptr);
    if (smac_it != m_encap_ptr_smac_map.end()) {
        old_smac.flat = smac_it->second.flat;
        remove_old_smac = true;
    }

    status = m_mac_addr_manager->add(sa, NPL_MAC_DA_TYPE_UC);
    return_on_error(status);

    m_encap_ptr_smac_map[encap_ptr] = sa;
    status = m_mac_addr_manager->get_index(sa, smac_index);
    return_on_error(status);

    k.punt_encap = TX_PUNT_ETH_ENCAP_ID | encap_ptr;

    v.action = NPL_TX_PUNT_ETH_ENCAP_TABLE_ACTION_FOUND;
    v.payloads.found.wide_bit = 1;
    v.payloads.found.punt_eth_or_npu_host_encap.punt_eth_nw_encap_data.punt_host_da.mac_address = da.flat;
    v.payloads.found.punt_eth_or_npu_host_encap.punt_eth_nw_encap_data.sa_or_npuh.punt_if_sa_lsb
        = mac_address_manager::get_lsbits(sa);
    v.payloads.found.punt_eth_or_npu_host_encap.punt_eth_nw_encap_data.punt_if_sa_rewrite_idx = smac_index;

    v.payloads.found.eth_pcp_dei.dei = vlan_tag.fields.dei;
    v.payloads.found.eth_pcp_dei.pcp = vlan_tag.fields.pcp;
    v.payloads.found.punt_eth_or_npu_host_encap.punt_eth_nw_encap_data.punt_eth_vid.id = vlan_tag.fields.vid;

    status = m_tables.tx_punt_eth_encap_table->set(k, v, e);
    return_on_error(status);

    if (remove_old_smac) {
        status = m_mac_addr_manager->remove(old_smac, NPL_MAC_DA_TYPE_UC);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_redirect_eth_encap(uint64_t encap_ptr)
{
    npl_tx_punt_eth_encap_table_t::key_type k;

    k.punt_encap = TX_PUNT_ETH_ENCAP_ID | encap_ptr;

    la_status status = m_tables.tx_punt_eth_encap_table->erase(k);
    return_on_error(status);

    auto smac_it = m_encap_ptr_smac_map.find(encap_ptr);
    if (smac_it == m_encap_ptr_smac_map.end()) {
        return LA_STATUS_EUNKNOWN;
    }
    status = m_mac_addr_manager->remove(smac_it->second, NPL_MAC_DA_TYPE_UC);
    return_on_error(status);

    m_encap_ptr_smac_map.erase(smac_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_redirect_npuh_encap(uint64_t encap_ptr, uint32_t fi_macro, uint32_t npuh_macro)
{
    {
        npl_tx_punt_eth_encap_table_t::key_type k{};
        npl_tx_punt_eth_encap_table_t::value_type v{};
        npl_tx_punt_eth_encap_table_t::entry_pointer_type e = nullptr;

        k.punt_encap = TX_PUNT_ETH_ENCAP_ID | encap_ptr;

        v.action = NPL_TX_PUNT_ETH_ENCAP_TABLE_ACTION_FOUND;
        v.payloads.found.wide_bit = 1;
        v.payloads.found.punt_eth_or_npu_host_encap.punt_eth_nw_encap_data.sa_or_npuh.punt_npu_host_data.first_fi_macro_id
            = fi_macro;
        v.payloads.found.punt_eth_or_npu_host_encap.punt_eth_nw_encap_data.sa_or_npuh.punt_npu_host_data.first_npe_macro_id
            = npuh_macro;

        la_status status = m_tables.tx_punt_eth_encap_table->set(k, v, e);
        return_on_error(status);
    }

    {
        npl_punt_rcy_inject_header_ene_encap_table_t::key_type k{};
        npl_punt_rcy_inject_header_ene_encap_table_t::value_type v{};
        npl_punt_rcy_inject_header_ene_encap_table_t::entry_pointer_type e = nullptr;

        k.punt_nw_encap_ptr.ptr = encap_ptr;

        v.action = NPL_PUNT_RCY_INJECT_HEADER_ENE_ENCAP_TABLE_ACTION_FOUND;
        v.payloads.found.ene_inject_down_payload.ene_inject_destination.val = 0;
        v.payloads.found.ene_inject_down_payload.ene_inject_phb.tc = 0;
        v.payloads.found.ene_inject_down_payload.ene_inject_down_encap_type = NPL_INJECT_DOWN_ENCAP_TYPE_NONE;

        la_status status = m_tables.punt_rcy_inject_header_ene_encap_table->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_oamp_redirect_code(uint64_t redirect_code,
                                             const la_counter_or_meter_set_wptr& counter_or_meter,
                                             const destination_id& redirect_dest,
                                             la_traffic_class_t tc,
                                             la_uint_t encap_ptr)
{
    destination_id rx_not_cnt_drop_dest = get_actual_destination_id(RX_NOT_CNT_DROP_DSP);
    la_status status = add_trap_counter_or_meter(redirect_code, counter_or_meter);
    return_on_error(status);
    la_slice_ifg s_ifg = m_slice_id_manager->get_npu_host_port_ifg();
    {
        npl_oamp_redirect_table_t::key_type k{};
        npl_oamp_redirect_table_t::value_type v{};
        npl_oamp_redirect_table_t::entry_pointer_type e = nullptr;

        k.redirect_code = redirect_code;

        v.payloads.oamp_redirect_action.destination.val = redirect_dest.val;
        v.payloads.oamp_redirect_action.phb.dp = 0;
        v.payloads.oamp_redirect_action.phb.tc = tc;
        v.payloads.oamp_redirect_action.encap_ptr = encap_ptr;

        // For some traps if the destination is set to drop, drop the packet in the NPU host.
        // Otherwise send it to the RxPP to count them before dropping.
        switch (redirect_code) {
        case LA_EVENT_OAMP_PFC_LOOKUP_FAILED:
            if (redirect_dest == rx_not_cnt_drop_dest) {
                v.payloads.oamp_redirect_action.drop = 1;
            } else {
                v.payloads.oamp_redirect_action.drop = 0;
            }
            break;
        default:
            v.payloads.oamp_redirect_action.drop = 0;
            break;
        }

        // For some traps we will use the counter from the application vs. the counter for the trap.
        switch (redirect_code) {
        case LA_EVENT_OAMP_BFD_SESSION_RECEIVED:
            v.payloads.oamp_redirect_action.keep_counter = 1;
            break;
        default:
            v.payloads.oamp_redirect_action.keep_counter = 0;
            break;
        }
        v.payloads.oamp_redirect_action.ifg = get_slice_id_manager()->slice_ifg_2_global_ifg(s_ifg);
        v.payloads.oamp_redirect_action.type = NPL_INJECT_HEADER_TYPE_DOWN_RX_COUNT;

        status = m_tables.oamp_redirect_table->set(k, v, e);
        return_on_error(status);
    }

    {
        npl_oamp_redirect_get_counter_table_t::key_type k{};
        npl_oamp_redirect_get_counter_table_t::value_type v{};
        npl_oamp_redirect_get_counter_table_t::entry_pointer_type e = nullptr;

        k.redirect_code = redirect_code;

        auto counter_impl = counter_or_meter.weak_ptr_static_cast<la_counter_set_impl>();

        v.payloads.counter_ptr = populate_counter_ptr_slice(counter_impl, s_ifg.slice, COUNTER_DIRECTION_INGRESS);

        status = m_tables.oamp_redirect_get_counter_table->set(k, v, e);
        return_on_error(status);
    }

    // Remove the previous trap counter_or_meter
    const auto& prev_counter_or_meter = m_trap_counters_or_meters[redirect_code];
    if (prev_counter_or_meter != counter_or_meter) {
        status = remove_trap_counter_or_meter(redirect_code);
        return_on_error(status);
    }

    m_trap_counters_or_meters[redirect_code] = counter_or_meter;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_oamp_redirect_code(uint64_t redirect_code)
{
    la_status status;

    {
        npl_oamp_redirect_table_t::key_type k{};

        k.redirect_code = redirect_code;

        status = m_tables.oamp_redirect_table->erase(k);
        if (status == LA_STATUS_ENOTFOUND) {
            // This may happen in case user didn't configure the given oamp trap, as
            // default initialization doesn't write to the oamp tables
            return LA_STATUS_SUCCESS;
        }

        return_on_error(status);
    }

    {
        npl_oamp_redirect_get_counter_table_t::key_type k{};

        k.redirect_code = redirect_code;

        status = m_tables.oamp_redirect_get_counter_table->erase(k);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_redirect_code(uint64_t redirect_code,
                                        bool disable_snoop,
                                        bool is_l3_trap,
                                        const la_counter_or_meter_set_wptr& counter_or_meter,
                                        const destination_id& redirect_dest,
                                        npl_punt_nw_encap_type_e redirect_type,
                                        la_uint_t encap_ptr,
                                        bool overwrite_phb,
                                        la_traffic_class_t tc)
{
    la_status status = add_trap_counter_or_meter(redirect_code, counter_or_meter);
    return_on_error(status);

    bool do_configure_meter_in_rx_obm_table = false;
    if ((counter_or_meter != nullptr) && (counter_or_meter->type() == la_object::object_type_e::METER_SET)) {
        do_configure_meter_in_rx_obm_table = true;
    }

    npl_rx_redirect_code_table_key_t rk;
    npl_rx_redirect_code_table_value_t rv;
    npl_rx_redirect_code_table_entry_t* re = nullptr;

    rk.redirect_code = redirect_code;
    rv.action = NPL_RX_REDIRECT_CODE_TABLE_ACTION_RX_REDIRECT_ACTION;
    rv.payloads.rx_redirect_action.destination = redirect_dest.val;
    rv.payloads.rx_redirect_action.disable_snoop = (uint64_t)disable_snoop;
    rv.payloads.rx_redirect_action.is_l3_trap = is_l3_trap;
    rv.payloads.rx_redirect_action.punt_encap_data_lsb.punt_nw_encap_type = redirect_type;
    rv.payloads.rx_redirect_action.punt_encap_data_lsb.punt_nw_encap_ptr.ptr = encap_ptr;
    rv.payloads.rx_redirect_action.punt_encap_data_lsb.punt_controls.mirror_local_encap_format = 0;
    rv.payloads.rx_redirect_action.phb.dp = 0;
    rv.payloads.rx_redirect_action.phb.tc = tc;
    rv.payloads.rx_redirect_action.override_phb = overwrite_phb;
    rv.payloads.rx_redirect_action.cntr_stamp_cmd.offset = 0;
    rv.payloads.rx_redirect_action.ts_cmd.op = 0;
    rv.payloads.rx_redirect_action.stamp_into_packet_header = NPL_STAMP_ON_ENCAP_HEADER;
    if ((counter_or_meter != nullptr) && (counter_or_meter->type() == la_object::object_type_e::COUNTER_SET)) {
        const auto& counter_impl = counter_or_meter.weak_ptr_static_cast<const la_counter_set_impl>();
        la_uint64_t counter_set_max_size = 0;
        get_limit(limit_type_e::COUNTER_SET__MAX_PIF_COUNTER_OFFSET, counter_set_max_size);
        if (counter_impl->get_set_size() == counter_set_max_size) {
            rv.payloads.rx_redirect_action.per_pif_trap_mode = NPL_PER_PIF_TRAP_MODE_ENABLED;
        } else {
            rv.payloads.rx_redirect_action.per_pif_trap_mode = NPL_PER_PIF_TRAP_MODE_DISABLED;
        }
    }

    la_slice_id_vec_t network_slices = get_slices(shared_from_this(), la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : network_slices) {
        // meter is set in obm-table
        rv.payloads.rx_redirect_action.redirect_counter = populate_counter_ptr_slice(
            do_configure_meter_in_rx_obm_table ? nullptr : counter_or_meter, slice, COUNTER_DIRECTION_INGRESS);
        la_status status = m_tables.rx_redirect_code_table[slice]->lookup(rk, re);
        if (status == LA_STATUS_SUCCESS) {
            re->update(rv);
        } else {
            status = m_tables.rx_redirect_code_table[slice]->insert(rk, rv, re);
            return_on_error(status);
        }
    }

    npl_rx_redirect_code_ext_table_key_t ext_rk;
    npl_rx_redirect_code_ext_table_value_t ext_rv;
    npl_rx_redirect_code_ext_table_entry_t* ext_re = nullptr;

    ext_rk.redirect_code = redirect_code;
    ext_rv.action = NPL_RX_REDIRECT_CODE_EXT_TABLE_ACTION_RX_REDIRECT_ACTION_EXT;
    network_slices = get_slices(shared_from_this(), la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : network_slices) {
        // meter is taken from obm table. adding it here would duplicate it
        ext_rv.payloads.rx_redirect_action_ext.meter_counter
            = populate_counter_ptr_slice(nullptr, slice, COUNTER_DIRECTION_INGRESS);
        la_status status = m_tables.rx_redirect_code_ext_table[slice]->set(ext_rk, ext_rv, ext_re);
        return_on_error(status);
    }

    npl_tx_redirect_code_table_key_t tk;
    npl_tx_redirect_code_table_value_t tv;
    npl_tx_redirect_code_table_t::entry_pointer_type te = nullptr;

    bool is_acl_drop_or_punt = false;
    switch (redirect_code) {
    case NPL_REDIRECT_CODE_L2_ACL_DROP:
    case NPL_REDIRECT_CODE_L3_ACL_DROP:
    case NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT:
    case NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT:
        is_acl_drop_or_punt = true;
        break;
    default:
        break;
    }

    tk.tx_redirect_code = redirect_code;
    tv.action = NPL_TX_REDIRECT_CODE_TABLE_ACTION_TX_REDIRECT_ACTION;
    tv.payloads.tx_redirect_action.is_drop_action = is_acl_drop_or_punt ? NPL_IS_DROP_ACTION : NPL_NOT_DROP_ACTION;
    tv.payloads.tx_redirect_action.cntr_stamp_cmd.offset = 0;
    tv.payloads.tx_redirect_action.ts_cmd.op = 0;
    tv.payloads.tx_redirect_action.stamp_into_packet_header = NPL_STAMP_ON_ENCAP_HEADER;
    tv.payloads.tx_redirect_action.tx_punt_nw_encap_ptr.punt_nw_encap_type = redirect_type;
    tv.payloads.tx_redirect_action.tx_punt_nw_encap_ptr.punt_nw_encap_ptr.ptr = encap_ptr;
    tv.payloads.tx_redirect_action.ts_cmd.offset = 0;
    tv.payloads.tx_redirect_action.ts_cmd.op = 0;

    status = m_tables.tx_redirect_code_table->lookup(tk, te);
    if (status == LA_STATUS_SUCCESS) {
        te->update(tv);
    } else {
        status = m_tables.tx_redirect_code_table->insert(tk, tv, te);
        return_on_error(status);
    }

    npl_inject_down_tx_redirect_counter_table_key_t tck;
    npl_inject_down_tx_redirect_counter_table_value_t tcv;
    npl_inject_down_tx_redirect_counter_table_entry_t* tce = nullptr;

    tck.tx_redirect_code = redirect_code;

    if ((counter_or_meter != nullptr) && (counter_or_meter->type() == la_object::object_type_e::COUNTER_SET)) {
        const auto& counter_impl = counter_or_meter.weak_ptr_static_cast<const la_counter_set_impl>();
        la_uint64_t counter_set_max_size = 0;
        get_limit(limit_type_e::COUNTER_SET__MAX_PIF_COUNTER_OFFSET, counter_set_max_size);
        if (counter_impl->get_set_size() == counter_set_max_size) {
            tcv.payloads.counter_meter_found.per_pif_trap_mode = NPL_PER_PIF_TRAP_MODE_ENABLED;
        } else {
            tcv.payloads.counter_meter_found.per_pif_trap_mode = NPL_PER_PIF_TRAP_MODE_DISABLED;
        }
    }

    auto tcv_meter = do_configure_meter_in_rx_obm_table ? nullptr : counter_or_meter;
    la_slice_id_vec_t network_slicepairs = get_slice_pairs(shared_from_this(), la_slice_mode_e::NETWORK);
    for (la_slice_pair_id_t pair_idx : network_slicepairs) {
        tcv.payloads.counter_meter_found.counter_ptr
            = populate_counter_ptr_slice_pair(tcv_meter, pair_idx, COUNTER_DIRECTION_INGRESS);
        status = m_tables.inject_down_tx_redirect_counter_table[pair_idx]->set(tck, tcv, tce);
        return_on_error(status);
    }

    npl_punt_rcy_inject_header_ene_encap_table_t::key_type ptk;
    npl_punt_rcy_inject_header_ene_encap_table_t::value_type ptv;
    npl_punt_rcy_inject_header_ene_encap_table_t::entry_pointer_type pte = nullptr;

    ptk.punt_nw_encap_ptr.ptr = encap_ptr;
    ptv.action = NPL_PUNT_RCY_INJECT_HEADER_ENE_ENCAP_TABLE_ACTION_FOUND;
    ptv.payloads.found.ene_inject_down_payload.ene_inject_destination.val = redirect_dest.val;
    ptv.payloads.found.ene_inject_down_payload.ene_inject_phb.dp = 0;
    ptv.payloads.found.ene_inject_down_payload.ene_inject_phb.tc = tc;
    ptv.payloads.found.ene_inject_down_payload.ene_inject_down_encap_type = NPL_INJECT_DOWN_ENCAP_TYPE_PUNT;

    status = m_tables.punt_rcy_inject_header_ene_encap_table->set(ptk, ptv, pte);
    return_on_error(status);

    // Remove the previous trap-counter
    const auto& prev_counter_or_meter = m_trap_counters_or_meters[redirect_code];
    if (prev_counter_or_meter != counter_or_meter) {
        status = remove_trap_counter_or_meter(redirect_code);
        return_on_error(status);
    }

    m_trap_counters_or_meters[redirect_code] = counter_or_meter;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_redirect_code(uint64_t redirect_code)
{
    npl_rx_redirect_code_table_t::key_type rk;

    rk.redirect_code = redirect_code;
    for (la_slice_id_t slice : get_used_slices()) {
        la_status status = m_tables.rx_redirect_code_table[slice]->erase(rk);
        return_on_error(status);
    }

    npl_rx_redirect_code_ext_table_t::key_type rk_ext;

    rk_ext.redirect_code = redirect_code;
    for (la_slice_id_t slice : get_used_slices()) {
        la_status status = m_tables.rx_redirect_code_ext_table[slice]->erase(rk_ext);
        return_on_error(status);
    }

    npl_tx_redirect_code_table_t::key_type tk;

    tk.tx_redirect_code = redirect_code;
    la_status status = m_tables.tx_redirect_code_table->erase(tk);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::event_to_trap_struct(la_event_e trap_event,
                                     npl_traps_t& trap_struct,
                                     npl_trap_conditions_t& trap_conditions_struct,
                                     bool skip_inject_up_packets,
                                     bool skip_p2p_packets)
{
    memset(&trap_struct, 0, sizeof(trap_struct));

    if (trap_event <= LA_EVENT_ETHERNET_LAST) {
        auto flat = trap_struct.ethernet.pack();
        flat.set_bit(LA_EVENT_ETHERNET_LAST - trap_event, 1);
        trap_struct.ethernet.unpack(flat);
    } else if (trap_event <= LA_EVENT_IPV4_LAST) {
        auto flat = trap_struct.ipv4.pack();
        flat.set_bit(LA_EVENT_IPV4_LAST - trap_event, 1);
        trap_struct.ipv4.unpack(flat);
    } else if (trap_event <= LA_EVENT_IPV6_LAST) {
        auto flat = trap_struct.ipv6.pack();
        flat.set_bit(LA_EVENT_IPV6_LAST - trap_event, 1);
        trap_struct.ipv6.unpack(flat);
    } else if (trap_event <= LA_EVENT_MPLS_LAST) {
        auto flat = trap_struct.mpls.pack();
        flat.set_bit(LA_EVENT_MPLS_LAST - trap_event, 1);
        trap_struct.mpls.unpack(flat);
    } else if (trap_event <= LA_EVENT_L3_LAST) {
        auto flat = trap_struct.l3.pack();
        flat.set_bit(LA_EVENT_L3_LAST - trap_event, 1);
        trap_struct.l3.unpack(flat);
    } else if (trap_event <= LA_EVENT_OAMP_LAST) {
        auto flat = trap_struct.oamp.pack();
        flat.set_bit(LA_EVENT_OAMP_LAST - trap_event, 1);
        trap_struct.oamp.unpack(flat);
    } else if (trap_event <= LA_EVENT_APP_LAST) {
        auto flat = trap_struct.app.pack();
        flat.set_bit(LA_EVENT_APP_LAST - trap_event, 1);
        trap_struct.app.unpack(flat);
    } else if (trap_event <= LA_EVENT_SVL_LAST) {
        auto flat = trap_struct.svl.pack();
        flat.set_bit(LA_EVENT_SVL_LAST - trap_event, 1);
        trap_struct.svl.unpack(flat);
    } else if (trap_event <= LA_EVENT_L2_LPTS_LAST) {
        auto flat = trap_struct.l2_lpts.pack();
        flat.set_bit(LA_EVENT_L2_LPTS_LAST - trap_event, 1);
        trap_struct.l2_lpts.unpack(flat);
    } else if (trap_event <= LA_EVENT_INTERNAL_LAST) {
        auto flat = trap_struct.internal.pack();
        flat.set_bit(LA_EVENT_INTERNAL_LAST - trap_event, 1);
        trap_struct.internal.unpack(flat);
    } else {
        return LA_STATUS_EINVAL;
    }

    // Configuration for inject up packets to not trigger the trap
    if (skip_inject_up_packets) {
        auto flat = trap_conditions_struct.pack();
        flat.set_bit(LA_EVENT_CONDITION_LAST - LA_EVENT_CONDITION_NON_INJECT_UP, 1);
        trap_conditions_struct.unpack(flat);
    }

    // Configuration for p2p packets to not trigger the trap
    if (skip_p2p_packets) {
        auto flat = trap_conditions_struct.pack();
        flat.set_bit(LA_EVENT_CONDITION_LAST - LA_EVENT_CONDITION_SKIP_P2P, 1);
        trap_conditions_struct.unpack(flat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_event_to_redirect_code(la_event_e trap,
                                                 size_t location,
                                                 uint64_t redirect_code,
                                                 bool skip_inject_up_packets,
                                                 bool skip_p2p_packets,
                                                 bool is_overwrite)
{
    npl_redirect_table_t::key_type k;
    npl_redirect_table_t::value_type v;
    npl_redirect_table_t::entry_pointer_type e = nullptr;

    // Temporary fix for this specific event to allow different action for inject up packets
    if (trap == LA_EVENT_L3_DROP_ADJ_NON_INJECT) {
        trap = LA_EVENT_L3_DROP_ADJ; // Changing trap value only for table key purpose, redirect code remains different.
    }

    la_status status = event_to_trap_struct(trap, k.traps, k.trap_conditions, skip_inject_up_packets, skip_p2p_packets);
    return_on_error(status);

    v.action = NPL_REDIRECT_TABLE_ACTION_WRITE;
    v.payloads.redirect_code.val = redirect_code;

    if (is_overwrite) {
        status = m_tables.redirect_table->set(location, k, k, v, e);
        return_on_error(status);
    } else {
        status = m_tables.redirect_table->push(location, k, k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_event_to_redirect_code(size_t location)
{
    // The ra_trap_ternary_translator both on erase() and pop() behaves like pop() by pulling entries up.
    // To keep the NPL-ternary table in full sync, pop() also from the NPL table.
    la_status status = m_tables.redirect_table->pop(location);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_rx_obm_punt_src_and_code(uint64_t punt_code,
                                                   uint64_t punt_source,
                                                   la_traffic_class_t tc,
                                                   uint8_t dp,
                                                   const la_meter_set_wptr& meter,
                                                   const la_meter_set_wptr& counter,
                                                   la_voq_gid_t punt_voq_id)
{
    npl_rx_obm_punt_src_and_code_table_key_t k;
    npl_rx_obm_punt_src_and_code_table_value_t v;
    npl_rx_obm_punt_src_and_code_table_entry_t* e = nullptr;

    k.is_dma = NPL_PUNT_HOST_DMA_ENCAP_TYPE;
    k.punt_src_and_code = ((punt_source << 8) | punt_code);

    destination_id dest_id = destination_id(NPL_DESTINATION_MASK_BVN | punt_voq_id);
    npl_destination_t dest{.val = dest_id.val};

    v.action = NPL_RX_OBM_PUNT_SRC_AND_CODE_TABLE_ACTION_WRITE;
    v.payloads.rx_obm_punt_src_and_code_data.phb.tc = tc;
    v.payloads.rx_obm_punt_src_and_code_data.phb.dp = dp;
    v.payloads.rx_obm_punt_src_and_code_data.punt_bvn_dest = dest;

    for (la_slice_id_t slice : get_used_slices()) {
        v.payloads.rx_obm_punt_src_and_code_data.meter_ptr = populate_counter_ptr_slice(meter, slice, COUNTER_DIRECTION_INGRESS);
        v.payloads.rx_obm_punt_src_and_code_data.cntr_ptr = populate_counter_ptr_slice(counter, slice, COUNTER_DIRECTION_INGRESS);
        la_status status = m_tables.rx_obm_punt_src_and_code_table[slice]->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_rx_obm_punt_src_and_code(uint64_t punt_code, uint64_t punt_source)
{
    npl_rx_obm_punt_src_and_code_table_key_t k;

    k.is_dma = NPL_PUNT_HOST_DMA_ENCAP_TYPE;
    k.punt_src_and_code = ((punt_source << 8) | punt_code);

    for (la_slice_id_t slice : get_used_slices()) {
        m_tables.rx_obm_punt_src_and_code_table[slice]->erase(k);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_snoop_code_to_ibm(uint64_t code, la_uint_t ibm_cmd)
{
    npl_snoop_code_hw_table_key_t k;
    npl_snoop_code_hw_table_value_t v;
    npl_snoop_code_hw_table_entry_t* e = nullptr;

    k.pd_common_leaba_fields_snoop_code = code;
    v.action = NPL_SNOOP_CODE_HW_TABLE_ACTION_WRITE;
    v.payloads.rxpp_pd_in_mirror_cmd0 = ibm_cmd;

    // Check if exists, if yes -> overwrite
    la_status status = m_tables.snoop_code_hw_table->set(k, v, e);

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_snoop_code_to_ibm(uint64_t code)
{
    npl_snoop_code_hw_table_t::key_type k;

    k.pd_common_leaba_fields_snoop_code = code;

    m_tables.snoop_code_hw_table->erase(k);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_mirror_code_to_ibm(uint64_t code, la_uint_t ibm_cmd)
{
    npl_mirror_code_hw_table_t::key_type k;
    npl_mirror_code_hw_table_t::value_type v;
    npl_mirror_code_hw_table_t::entry_pointer_type e = nullptr;

    k.pd_common_leaba_fields_mirror_code = code;
    v.action = NPL_MIRROR_CODE_HW_TABLE_ACTION_WRITE;
    v.payloads.rxpp_pd_rxn_in_mirror_cmd1 = ibm_cmd;

    // Check if exists, if yes -> overwrite
    la_status status = m_tables.mirror_code_hw_table->set(k, v, e);

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_mirror_code_to_ibm(uint64_t code)
{
    npl_mirror_code_hw_table_t::key_type k;

    k.pd_common_leaba_fields_mirror_code = code;

    m_tables.mirror_code_hw_table->erase(k);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_event_to_snoop_code(la_event_e trap,
                                              size_t location,
                                              uint64_t code,
                                              bool skip_inject_up_packets,
                                              bool skip_p2p_packets)
{
    npl_snoop_table_t::key_type k;
    npl_snoop_table_t::value_type v;
    npl_snoop_table_t::entry_pointer_type e = nullptr;

    la_status status = event_to_trap_struct(trap, k.traps, k.trap_conditions, skip_inject_up_packets, skip_p2p_packets);
    return_on_error(status);

    // If already exists with same key, erase
    size_t location_prev = 0;
    status = m_tables.snoop_table->find(k, k, e, location_prev);
    if (status == LA_STATUS_SUCCESS) {
        status = m_tables.snoop_table->erase(location_prev);
        return_on_error(status);
    }

    v.action = NPL_SNOOP_TABLE_ACTION_WRITE;
    v.payloads.snoop_code.val = code;

    status = m_tables.snoop_table->push(location, k, k, v, e);

    return status;
}

la_status
la_device_impl::clear_entry_from_snoop_table(la_event_e trap, snoop_skip_attribute_e attribute)
{
    bool skip_inject_up_packets = false;
    bool skip_p2p_packets = false;
    npl_snoop_table_t::key_type k;
    npl_snoop_table_t::entry_pointer_type e = nullptr;

    switch (attribute) {
    case snoop_skip_attribute_e::NO_SKIP:
        skip_inject_up_packets = false;
        skip_p2p_packets = false;
        break;
    case snoop_skip_attribute_e::SKIP_INJECT_UP:
        skip_inject_up_packets = true;
        skip_p2p_packets = false;
        break;
    case snoop_skip_attribute_e::SKIP_P2P:
        skip_inject_up_packets = false;
        skip_p2p_packets = true;
        break;
    case snoop_skip_attribute_e::SKIP_ALL:
        skip_inject_up_packets = true;
        skip_p2p_packets = true;
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    la_status status = event_to_trap_struct(trap, k.traps, k.trap_conditions, skip_inject_up_packets, skip_p2p_packets);
    return_on_error(status);

    size_t location = 0;
    status = m_tables.snoop_table->find(k, k, e, location);
    return_on_error(status);

    status = m_tables.snoop_table->erase(location);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_event_to_snoop_code(la_event_e trap)
{
    la_status status = LA_STATUS_SUCCESS;
    bool entry_cleared = false;

    for (size_t loop_cnt = snoop_skip_attribute_e::NO_SKIP; loop_cnt < snoop_skip_attribute_e::SKIP_LAST; loop_cnt++) {
        /* Loop to clear all entries which matches given trap irrespective of attributes */
        snoop_skip_attribute_e attribute = static_cast<snoop_skip_attribute_e>(loop_cnt);
        status = clear_entry_from_snoop_table(trap, attribute);
        if (status == LA_STATUS_SUCCESS) {
            entry_cleared = true;
        }
    }

    if (entry_cleared == true) {
        return LA_STATUS_SUCCESS;
    }

    return status;
}

la_status
la_device_impl::initialize_scaffold_vlan_edit_tables()
{
    // Current supported TPID-s are hard-coded.
    m_supported_tpid_pairs.push_back(make_pair(0x8100, 0x0));
    m_supported_tpid_pairs.push_back(make_pair(0x88a8, 0x8100));
    m_supported_tpid_pairs.push_back(make_pair(0x9100, 0x8100));

    // Initialize VLAN edit TPID profiles tables
    for (size_t i = 0; i < m_supported_tpid_pairs.size(); i++) {
        npl_vlan_edit_tpid1_profile_hw_table_t::key_type k1;
        npl_vlan_edit_tpid1_profile_hw_table_t::value_type v1;
        npl_vlan_edit_tpid1_profile_hw_table_t::entry_pointer_type e1;

        npl_vlan_edit_tpid2_profile_hw_table_t::key_type k2;
        npl_vlan_edit_tpid2_profile_hw_table_t::value_type v2;
        npl_vlan_edit_tpid2_profile_hw_table_t::entry_pointer_type e2;

        k1.vlan_edit_info_tpid_profile = i;
        v1.action = NPL_VLAN_EDIT_TPID1_PROFILE_HW_TABLE_ACTION_WRITE;
        v1.payloads.vlan_edit_info_tpid1 = m_supported_tpid_pairs[i].first;

        k2.vlan_edit_info_tpid_profile = i;
        v2.action = NPL_VLAN_EDIT_TPID2_PROFILE_HW_TABLE_ACTION_WRITE;
        v2.payloads.vlan_edit_info_tpid2 = m_supported_tpid_pairs[i].second;

        la_status s1 = m_tables.vlan_edit_tpid1_profile_hw_table->insert(k1, v1, e1);
        la_status s2 = m_tables.vlan_edit_tpid2_profile_hw_table->insert(k2, v2, e2);

        if (s1 != LA_STATUS_SUCCESS || s2 != LA_STATUS_SUCCESS) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_scaffold_encap_qos_tag_table()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_static_tables()
{
    la_status status = configure_static_resolution_tables();
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table();
    return_on_error(status);

    status = configure_cud_is_multicast_bitmap_table();
    return_on_error(status);

    status = configure_rpf_fec_access_map_table();
    return_on_error(status);

    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        status = configure_tunnel_dlp_p_counter_offset_table();
        return_on_error(status);

        status = configure_l3_dlp_p_counter_offset_table();
        return_on_error(status);

        status = configure_te_headend_lsp_counter_offset_table();
        return_on_error(status);
    }

    status = configure_dsp_dest_msbs_for_ecn_table();
    return_on_error(status);

    status = configure_pdoq_oq_ifc_mapping();
    return_on_error(status);

    status = configure_reassembly_source_port_map_table();
    return_on_error(status);

    status = configure_rx_npu_to_tm_dest_table();
    return_on_error(status);

    status = configure_fabric_tm_headers_table();
    return_on_error(status);

    if (m_device_mode == device_mode_e::LINECARD) {
        status = configure_fabric_headers_type_table();
        return_on_error(status);

        status = configure_fabric_out_color_map_table();
        return_on_error(status);

        status = configure_fabric_header_ene_macro_table();
        return_on_error(status);
    }

    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        status = configure_set_ene_macro_and_bytes_to_remove_table();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_static_resolution_tables()
{
    la_status retval;
    retval = configure_static_resolution_destination_decoding_table();
    return_on_error(retval);

    retval = configure_decoding_tables(this);
    return_on_error(retval);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_static_resolution_destination_decoding_table()
{
    for (uint64_t index = 0; index < (1 << RESOLUTION_ENCODING_PREFIX_MAX_LEN); ++index) {
        npl_dest_type_decoding_table_t::key_type k;
        npl_dest_type_decoding_table_t::value_type v;

        k.dest_type.dest_type = index;

        npl_resolution_dest_type_decoding_result_t dest_decoding_table_entry
            = get_resolution_destination_decoding_value(k.dest_type.dest_type);
        v.action = NPL_DEST_TYPE_DECODING_TABLE_ACTION_WRITE;
        v.payloads.resolution_dest_type_decoding_result = dest_decoding_table_entry;

        npl_dest_type_decoding_table_t::entry_type* dummy_entry;
        la_status status = m_tables.dest_type_decoding_table->insert(k, v, dummy_entry);
        return_on_error(status);
    }

    if (is_pbts_enabled()) {
        // additional entries for higher PrefixObject range to disable PBTS
        // 00xx0 -> Destination MSB  5 bits are mapped to perform PBTS calculation
        // This encoding (MSB:00) is prefix object.
        // 00xx---------------- 16 Bits range of prefix objects is 64K
        // 00xx0x-------------- First 32K Range (0-32K) to be used as non-PBTS
        // 00xx1x-------------- Second 32k Range (32K-64k) are enabled for PBTS

        auto entries = {0b000010, 0b000110, 0b001010, 0b001110, 0b000011, 0b000111, 0b001011, 0b001111};
        npl_resolution_dest_type_decoding_result_t result = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_AFTER_PBTS,
                                                             NPL_RESOLUTION_PBTS_ENABLED,
                                                             NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                                             NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                                             NPL_RESOLUTION_TABLE_STAGE0};
        for (auto entry : entries) {
            npl_dest_type_decoding_table_t::key_type k;
            npl_dest_type_decoding_table_t::value_type v;

            k.dest_type.dest_type = entry;
            v.action = NPL_DEST_TYPE_DECODING_TABLE_ACTION_WRITE;
            v.payloads.resolution_dest_type_decoding_result = result;

            npl_dest_type_decoding_table_t::entry_type* dummy_entry;
            la_status status = m_tables.dest_type_decoding_table->set(k, v, dummy_entry);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

npl_resolution_dest_type_decoding_result_t
la_device_impl::get_resolution_destination_decoding_value(uint64_t destination_encoding)
{
    npl_resolution_dest_type_e destination_type = get_resolution_destination_type(destination_encoding);

    // WA for erratum 'IDB: Resolution performance degradation on some application mixes' -
    // change the resolution stage of all bypass destinations to NATIVE instead of RETURN
    const npl_resolution_table_e bypass_resulution_stage = NPL_RESOLUTION_TABLE_PROCESSING_DONE;

    const npl_resolution_dest_type_decoding_result_t destination_decoding_value_arr[NPL_DESTINATION_TYPE_UNKNOWN + 1]
        = {// lb_table_behavior, resolution_table, resolution_stage
               // end of resolution
               [NPL_DESTINATION_TYPE_BVN] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                             NPL_RESOLUTION_PBTS_DISABLED,
                                             NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                             NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                             bypass_resulution_stage},

               [NPL_DESTINATION_TYPE_MC] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                            NPL_RESOLUTION_PBTS_DISABLED,
                                            NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                            NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                            bypass_resulution_stage},

               [NPL_DESTINATION_TYPE_FLBG] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                              NPL_RESOLUTION_PBTS_DISABLED,
                                              NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                              NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                              bypass_resulution_stage},

               [NPL_DESTINATION_TYPE_DSP] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                             NPL_RESOLUTION_PBTS_DISABLED,
                                             NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                             NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                             bypass_resulution_stage},

               // Stage-FEC
               [NPL_DESTINATION_TYPE_FEC] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                             NPL_RESOLUTION_PBTS_DISABLED,
                                             NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                             NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                             NPL_RESOLUTION_TABLE_FEC},

               // Stage-0
               [NPL_DESTINATION_TYPE_L2_DLP] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                                NPL_RESOLUTION_PBTS_DISABLED,
                                                NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                                NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                                NPL_RESOLUTION_TABLE_STAGE0},

               [NPL_DESTINATION_TYPE_L2_DLPA_OR_ECMP] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                                         NPL_RESOLUTION_PBTS_DISABLED,
                                                         NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                                         NPL_RESOLUTION_EM_SELECT_LB,
                                                         NPL_RESOLUTION_TABLE_STAGE0},

               [NPL_DESTINATION_TYPE_FRR] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                             NPL_RESOLUTION_PBTS_DISABLED,
                                             NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                             NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                             bypass_resulution_stage},

               [NPL_DESTINATION_TYPE_CE_PTR] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                                NPL_RESOLUTION_PBTS_DISABLED,
                                                NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                                NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                                NPL_RESOLUTION_TABLE_STAGE0},

               // Stage-1
               [NPL_DESTINATION_TYPE_LEVEL2_ECMP] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                                     NPL_RESOLUTION_PBTS_DISABLED,
                                                     NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                                     NPL_RESOLUTION_EM_SELECT_LB,
                                                     NPL_RESOLUTION_TABLE_STAGE1},

               [NPL_DESTINATION_TYPE_P_L3_NH] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                                 NPL_RESOLUTION_PBTS_DISABLED,
                                                 NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                                 NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                                 NPL_RESOLUTION_TABLE_STAGE1},

               // Stage-2
               [NPL_DESTINATION_TYPE_NPP] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                             NPL_RESOLUTION_PBTS_DISABLED,
                                             NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                             NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                             bypass_resulution_stage},

               [NPL_DESTINATION_TYPE_L3_NH] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                               NPL_RESOLUTION_PBTS_DISABLED,
                                               NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                               NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                               NPL_RESOLUTION_TABLE_STAGE2},

               // Stage-3
               [NPL_DESTINATION_TYPE_DSPA] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                              NPL_RESOLUTION_PBTS_DISABLED,
                                              NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                              NPL_RESOLUTION_EM_SELECT_LB,
                                              NPL_RESOLUTION_TABLE_STAGE3},

               // unknown prefix
               [NPL_DESTINATION_TYPE_UNKNOWN] = {NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS,
                                                 NPL_RESOLUTION_PBTS_DISABLED,
                                                 NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED,
                                                 NPL_RESOLUTION_EM_SELECT_DEST_MAP,
                                                 bypass_resulution_stage}};

    return destination_decoding_value_arr[destination_type];
}

npl_resolution_dest_type_e
la_device_impl::get_resolution_destination_type(uint64_t destination_encoding)
{
    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_BVN_PREFIX, NPL_DESTINATION_BVN_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_BVN;
    }
    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_MC_PREFIX, NPL_DESTINATION_MC_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_MC;
    }
    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_DSPA_PREFIX, NPL_DESTINATION_DSPA_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_DSPA;
    }
    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_DSP_PREFIX, NPL_DESTINATION_DSP_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_DSP;
    }
    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_FEC_PREFIX, NPL_DESTINATION_FEC_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_FEC;
    }
    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_ECMP_PREFIX, NPL_DESTINATION_ECMP_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_L2_DLPA_OR_ECMP;
    }
    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_L2_DLP_PREFIX, NPL_DESTINATION_L2_DLP_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_L2_DLP;
    }
    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_CE_PTR_PREFIX, NPL_DESTINATION_CE_PTR_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_CE_PTR;
    }

    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_P_L3_NH_PREFIX, NPL_DESTINATION_P_L3_NH_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_P_L3_NH;
    }
    if (does_encoding_match_prefix(
            destination_encoding, NPL_DESTINATION_LEVEL2_ECMP_PREFIX, NPL_DESTINATION_LEVEL2_ECMP_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_LEVEL2_ECMP;
    }

    if (does_encoding_match_prefix(destination_encoding, NPL_DESTINATION_L3_NH_PREFIX, NPL_DESTINATION_L3_NH_PREFIX_LEN)) {
        return NPL_DESTINATION_TYPE_L3_NH;
    }

    return NPL_DESTINATION_TYPE_UNKNOWN;
}

bool
la_device_impl::does_encoding_match_prefix(uint64_t destination_encoding, uint64_t prefix, uint64_t prefix_len)
{
    if ((destination_encoding >> (RESOLUTION_ENCODING_PREFIX_MAX_LEN - prefix_len)) == prefix) {
        return true;
    }

    return false;
}

la_status
la_device_impl::configure_rx_npu_to_tm_dest_table()
{
    la_status status;

    status = configure_rx_npu_to_tm_dest_table_rx_network_slices();
    return_on_error(status);

    status = configure_rx_npu_to_tm_dest_table_rx_fabric_slices();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_rx_npu_to_tm_dest_table_rx_network_slices()
{
    const auto& tables(m_tables.rx_npu_to_tm_dest_table);
    npl_rx_npu_to_tm_dest_table_key_t k;
    npl_rx_npu_to_tm_dest_table_value_t v;

    v.action = NPL_RX_NPU_TO_TM_DEST_TABLE_ACTION_WRITE;

    // constant DESTINATION_MC_PREFIX                  4'b1110;
    // to
    // constant TM_DESTINATION_MCID_PREFIX             4'b1111;
    //
    // MCID is 16 bits while the key to the table is 6 bits --> lower 2 bits of the key are
    // the higher 2 bits of the MCID. MCID bits need to be preserved so a separate entry is needed
    // for each possible 2 higher MCID bits.
    for (uint64_t mcid_higher_bits = 0; mcid_higher_bits < 4; mcid_higher_bits++) {
        k.rxpp_pd_fwd_destination_19_14_ = (NPL_DESTINATION_MC_PREFIX << 2) + mcid_higher_bits;
        v.payloads.pd_rx_tm_destination_prefix = (NPL_TM_DESTINATION_MCID_PREFIX << 2) + mcid_higher_bits;
        la_status status = per_slice_tables_insert(m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
        return_on_error(status);
    }

    // constant DESTINATION_BVN_PREFIX                  4'b1111;
    // to
    // constant TM_DESTINATION_VOQ_PREFIX               4'b1110;
    //
    // VOQ prefix is 16 bits while the key to the table is 6 bits --> lower 2 bits of the key are
    // the higher 2 bits of the VOQ. VOQ bits need to be preserved so a separate entry is needed
    // for each possible 2 higher VOQ bits.
    for (uint64_t higher_bits = 0; higher_bits < (1 << (6 - NPL_DESTINATION_BVN_PREFIX_LEN)); higher_bits++) {
        k.rxpp_pd_fwd_destination_19_14_ = (NPL_DESTINATION_BVN_PREFIX << (6 - NPL_DESTINATION_BVN_PREFIX_LEN)) + higher_bits;
        v.payloads.pd_rx_tm_destination_prefix = (NPL_TM_DESTINATION_VOQ_PREFIX << 2) + higher_bits;
        la_status status = per_slice_tables_insert(m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
        return_on_error(status);
    }

    // constant DESTINATION_DSP_PREFIX                 5'b01011;
    // to
    // constant TM_DESTINATION_DSP_PREFIX              6'b1101_00;
    //
    // DSP is 14 bits so there are no bits to preserve, but there has to be an entry for
    // each possible combination in the redundant 1 bits in the DSP.
    for (uint64_t dsp_redundant_bits = 0; dsp_redundant_bits < (1 << (6 - NPL_DESTINATION_DSP_PREFIX_LEN)); dsp_redundant_bits++) {
        k.rxpp_pd_fwd_destination_19_14_
            = (NPL_DESTINATION_DSP_PREFIX << (6 - NPL_DESTINATION_DSP_PREFIX_LEN)) + dsp_redundant_bits;
        v.payloads.pd_rx_tm_destination_prefix = NPL_TM_DESTINATION_DSP_PREFIX;
        la_status status = per_slice_tables_insert(m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
        return_on_error(status);
    }

    // constant 0                                      4'b0000;
    // to
    // constant TM_DESTINATION_DSP_PREFIX              6'b1101_00;
    //
    // Due to lookup error PD is not updated and 0 is used.
    k.rxpp_pd_fwd_destination_19_14_ = 0;
    v.payloads.pd_rx_tm_destination_prefix = NPL_TM_DESTINATION_DSP_PREFIX;
    la_status status = per_slice_tables_insert(m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_rx_npu_to_tm_dest_table_rx_fabric_slices()
{
    const auto& tables(m_tables.rx_npu_to_tm_dest_table);
    npl_rx_npu_to_tm_dest_table_key_t k;
    npl_rx_npu_to_tm_dest_table_value_t v;

    v.action = NPL_RX_NPU_TO_TM_DEST_TABLE_ACTION_WRITE;

    // In RX fabric slices do a 1-to-1 mapping. The destination is already after the mapping from the ingress device/slice.
    for (size_t line = 0; line < (1 << 6); line++) {
        k.rxpp_pd_fwd_destination_19_14_ = line;
        v.payloads.pd_rx_tm_destination_prefix = line;
        la_status status = per_slice_tables_insert(m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_bvn_tc_map_default_values()
{
    for (size_t i = 0; i < 32; ++i) {
        npl_bvn_tc_map_table_t::key_type bvn_key;
        npl_bvn_tc_map_table_t::value_type bvn_value;
        npl_bvn_tc_map_table_entry_t* bvn_dummy_entry = nullptr;

        bvn_key.tc_map_profile = (i >> 2);
        bvn_key.tc = i;
        la_status status = m_tables.bvn_tc_map_table->insert(bvn_key, bvn_value, bvn_dummy_entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_rewrite_sa_prefix_index_table()
{
    npl_ene_rewrite_sa_prefix_index_table_t::entry* dummy_ret = nullptr;
    npl_ene_rewrite_sa_prefix_index_table_t::key_type key;
    npl_ene_rewrite_sa_prefix_index_table_t::value_type value;

    key.rewrite_sa_index = 0;
    value.action = NPL_ENE_REWRITE_SA_PREFIX_INDEX_TABLE_ACTION_WRITE;
    value.payloads.sa_msb.msb = 0;

    la_status status = m_tables.ene_rewrite_sa_prefix_index_table->insert(key, value, dummy_ret);
    return status;
}

la_status
la_device_impl::initialize_qos_mapping_tables()
{
    la_status status = initialize_dscp_to_qos_tag_table();
    return_on_error(status);

    status = initialize_txpp_fwd_qos_mapping_table();
    return_on_error(status);

    status = initialize_txpp_encap_qos_mapping_table();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_dscp_to_qos_tag_table()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_txpp_fwd_qos_mapping_table()
{
    // This table maps from {ingress mapped qos tag, la_qos_color_e, ingress lp qos_acl_id} ->  ingress mapped qos tag
    // By default its configured to the one-to-one mapping, ignoring other key parameters.
    // The NPL should be updated from the {ingress lp qos_acl_id} to an "egress color mapping profile", and then the SDK will have a
    // profile that configures this table. Profile-id 15 is reserved for system defaults.
    const auto& table(m_tables.txpp_fwd_qos_mapping_table);
    npl_txpp_fwd_qos_mapping_table_t::key_type k;
    npl_txpp_fwd_qos_mapping_table_t::value_type v;
    npl_txpp_fwd_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    // Set write action
    v.action = NPL_TXPP_FWD_QOS_MAPPING_TABLE_ACTION_WRITE;

    for (la_uint8_t qos_color = 0; qos_color < (la_uint8_t)la_qos_color_e::LAST; qos_color++) {
        k.pd_tx_out_color = qos_color;
        k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = la_ingress_qos_profile_impl::LA_RSVD_METER_MARKDOWN_PROFILE_ID;

        // Set PCPDEI one-to-one mapping
        for (la_uint8_t pcpdei = 0; pcpdei < MAX_VLAN_PCPDEI_VALUE; pcpdei++) {
            la_vlan_pcpdei vlan_pcpdei(pcpdei);
            k.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = get_prefixed_qos_field(vlan_pcpdei);
            v.payloads.txpp_npu_header_fwd_qos_tag = get_prefixed_qos_field(vlan_pcpdei);
            la_status status = table->insert(k, v, entry_ptr);
            return_on_error(status);
        }

        // Set DSCP one-to-one mapping
        for (la_uint8_t dscp = 0; dscp < MAX_IP_DSCP_VALUE; dscp++) {
            la_ip_dscp ip_dscp = {.value = dscp};
            k.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = get_prefixed_qos_field(ip_dscp);
            v.payloads.txpp_npu_header_fwd_qos_tag = get_prefixed_qos_field(ip_dscp);
            la_status status = table->insert(k, v, entry_ptr);
            return_on_error(status);
        }

        // Set MPLS-TC one-to-one mapping
        for (la_uint8_t tc = 0; tc < MAX_MPLS_TC_VALUE; tc++) {
            la_mpls_tc mpls_tc = {.value = tc};
            k.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = get_prefixed_qos_field(mpls_tc);
            v.payloads.txpp_npu_header_fwd_qos_tag = get_prefixed_qos_field(mpls_tc);
            la_status status = table->insert(k, v, entry_ptr);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_txpp_encap_qos_mapping_table()
{
    // This table maps from {la_ingress_encap_qos_tag_t, la_qos_color_e, ingress lp qos_acl_id} ->  la_egress_encap_qos_tag_t.
    // The result of this table controls whether the encapsulating headers' qos field values are taken from the
    // mac/ip/mpls_fwd_qos_tag_table or from encap_qos_tag_table.
    // By default its configured such that no value is taken from encap_qos_tag_table.
    // The NPL should be updated from the {ingress lp qos_acl_id} to an "egress color mapping profile", and then the SDK will have a
    // profile that configures this table. Profile-id 15 is reserved for system defaults.
    const auto& table(m_tables.txpp_encap_qos_mapping_table);
    npl_txpp_encap_qos_mapping_table_t::key_type k;
    npl_txpp_encap_qos_mapping_table_t::value_type v;
    npl_txpp_encap_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    for (la_uint_t encap_qos_tag = 0; encap_qos_tag < LA_MAX_INGRESS_ENCAP_QOS_TAG; encap_qos_tag++) {
        k.packet_protocol_layer_none__tx_npu_header_encap_qos_tag = encap_qos_tag;
        v.payloads.txpp_npu_header_encap_qos_tag = encap_qos_tag;
        v.action = NPL_TXPP_ENCAP_QOS_MAPPING_TABLE_ACTION_WRITE;

        for (la_uint8_t qos_color = 0; qos_color < (la_uint8_t)la_qos_color_e::LAST; qos_color++) {
            k.pd_tx_out_color = qos_color;
            k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = la_ingress_qos_profile_impl::LA_RSVD_METER_MARKDOWN_PROFILE_ID;
            la_status status = table->insert(k, v, entry_ptr);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_termination_to_forwarding_fi_hardwired_table_network_entry(npl_protocol_type_e header_type,
                                                                                     npl_fi_hardwired_type_e hw_type)
{
    for (la_slice_id_t slice_id : get_used_slices()) {
        if (m_slice_mode[slice_id] != la_slice_mode_e::NETWORK) {
            continue;
        }

        const auto& table(m_tables.termination_to_forwarding_fi_hardwired_table[slice_id]);
        npl_termination_to_forwarding_fi_hardwired_table_t::key_type k;
        npl_termination_to_forwarding_fi_hardwired_table_t::value_type v;
        npl_termination_to_forwarding_fi_hardwired_table_t::entry_pointer_type e = nullptr;

        k.packet_protocol_layer_current__header_0__header_info_type = header_type;
        v.action = NPL_TERMINATION_TO_FORWARDING_FI_HARDWIRED_TABLE_ACTION_WRITE;
        v.payloads.termination_to_forwarding_fields_fi_hardwired_type = hw_type;

        la_status status = table->insert(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_termination_to_forwarding_fi_hardwired_table()
{
    la_status status;
    status = configure_termination_to_forwarding_fi_hardwired_table_network();
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table_fabric();

    return status;
}

la_status
la_device_impl::configure_termination_to_forwarding_fi_hardwired_table_network()
{
    la_status status;
    status = configure_termination_to_forwarding_fi_hardwired_table_network_entry(NPL_PROTOCOL_TYPE_UNKNOWN, NPL_FI_NO_HARDWIRED);
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table_network_entry(NPL_PROTOCOL_TYPE_ETHERNET,
                                                                                  NPL_FI_ETHERNET_HARDWIRED);
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table_network_entry(NPL_PROTOCOL_TYPE_ETHERNET_VLAN,
                                                                                  NPL_FI_ETHERNET_HARDWIRED);
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table_network_entry(NPL_PROTOCOL_TYPE_IPV4, NPL_FI_IPV4_HARDWIRED);
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table_network_entry(NPL_PROTOCOL_TYPE_IPV4_L4, NPL_FI_IPV4_HARDWIRED);
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table_network_entry(NPL_PROTOCOL_TYPE_IPV6, NPL_FI_NO_HARDWIRED);
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table_network_entry(NPL_PROTOCOL_TYPE_IPV6_L4, NPL_FI_NO_HARDWIRED);
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table_network_entry(NPL_PROTOCOL_TYPE_MPLS, NPL_FI_NO_HARDWIRED);
    return_on_error(status);

    status = configure_termination_to_forwarding_fi_hardwired_table_network_entry(NPL_PROTOCOL_TYPE_INJECT, NPL_FI_NO_HARDWIRED);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_termination_to_forwarding_fi_hardwired_table_fabric()
{
    for (la_slice_id_t slice_id : get_used_slices()) {
        if (m_slice_mode[slice_id] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        const auto& table(m_tables.termination_to_forwarding_fi_hardwired_table[slice_id]);
        npl_termination_to_forwarding_fi_hardwired_table_t::value_type v;
        npl_termination_to_forwarding_fi_hardwired_table_t::key_type k;

        v.action = NPL_TERMINATION_TO_FORWARDING_FI_HARDWIRED_TABLE_ACTION_WRITE;
        v.payloads.termination_to_forwarding_fields_fi_hardwired_type = NPL_FI_NO_HARDWIRED;
        npl_termination_to_forwarding_fi_hardwired_table_t::entry_pointer_type e = nullptr;

        for (size_t i = 0; i < TERMINATION_TO_FORWARDING_FI_HARDWIRED_TABLE_KEY_LEN; i++) {
            k.packet_protocol_layer_current__header_0__header_info_type = (npl_protocol_type_e)i;

            la_status status = table->insert(k, v, e);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

bool
la_device_impl::is_multicast_scale_mode_configured() const
{
    int mc_mcid_scale_threshold = 0;
    get_int_property(la_device_property_e::MULTICAST_MCID_SCALE_THRESHOLD, mc_mcid_scale_threshold);
    return (mc_mcid_scale_threshold != MAX_MC_LOCAL_MCID);
}

bool
la_device_impl::is_scale_mode_smcid(const la_multicast_group_gid_t mcid) const
{
    int mc_mcid_scale_threshold = 0;
    get_int_property(la_device_property_e::MULTICAST_MCID_SCALE_THRESHOLD, mc_mcid_scale_threshold);
    return ((int)mcid >= mc_mcid_scale_threshold);
}

bool
la_device_impl::is_reserved_smcid(const la_multicast_group_gid_t mcid) const
{
    if (m_device_mode == device_mode_e::STANDALONE) {
        // reserved MCIDs are only used in liencard and fabric element mode
        return false;
    }

    if (is_scale_mode_smcid(mcid)) {
        if ((mcid == MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_0)
            || (mcid == MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_1)
            || (mcid == MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_0)
            || (mcid == MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_1)
            || (mcid == MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_0)
            || (mcid == MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_1)
            || (mcid == MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE)) {
            return true;
        }
    }
    return false;
}

la_status
la_device_impl::configure_cud_is_multicast_bitmap_table()
{
    la_status status;

    // Configure CUD encoding prefixes - bits[23:20]

    // CUD has MC-Copy-ID, multicast true
    status = configure_cud_is_multicast_bitmap_entry(NPL_TX_CUD_MC_COPY_ID_PREFIX, NPL_TX_CUD_MC_COPY_ID_PREFIX_LEN, true);
    return_on_error(status);

    // CUD has MCID, multicast false
    status = configure_cud_is_multicast_bitmap_entry(NPL_TX_CUD_MC_ID_PREFIX, NPL_TX_CUD_MC_ID_PREFIX_LEN, false);
    return_on_error(status);

    // CUD has DSP, multicast false
    status = configure_cud_is_multicast_bitmap_entry(NPL_TX_CUD_DSP_PREFIX, NPL_TX_CUD_DSP_PREFIX_LEN, false);
    return_on_error(status);

    // CUD has IBM command, multicast true
    status = configure_cud_is_multicast_bitmap_entry(NPL_TX_CUD_IBM_CMD_PREFIX, NPL_TX_CUD_IBM_CMD_PREFIX_LEN, true);
    return_on_error(status);

    // CUD Reserved command, multicast false
    status = configure_cud_is_multicast_bitmap_entry(NPL_TX_CUD_DROP_TRAP_PREFIX, NPL_TX_CUD_DROP_TRAP_PREFIX_LEN, false);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_cud_is_multicast_bitmap_entry(uint8_t bitmap, size_t prefix_len, bool is_mc)
{
    const auto& table(m_tables.cud_is_multicast_bitmap);
    npl_cud_is_multicast_bitmap_t::key_type k;
    npl_cud_is_multicast_bitmap_t::value_type v;
    npl_cud_is_multicast_bitmap_t::entry_pointer_type e = nullptr;

    // Prepare value
    v.action = NPL_CUD_IS_MULTICAST_BITMAP_ACTION_WRITE;
    v.payloads.cud_mapping_local_vars_cud_is_multicast = is_mc;

    // Assume that the bitmap value represents a left-aligned prefix, of which has prefix_len correct MSBs, and zero in LSBs.
    // So the need iterate over all free LSBs.
    dassert_crit(prefix_len <= CUD_IS_MULTICAST_BITMAP_TX_CUD_PREFIX_LEN);
    size_t num_of_free_bits = CUD_IS_MULTICAST_BITMAP_TX_CUD_PREFIX_LEN - prefix_len;

    for (size_t j = 0; j < (1ULL << num_of_free_bits); j++) {
        // Prepare key
        k.tx_cud_prefix = bitmap + j;

        // Update table
        la_status status = table->insert(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_pdoq_oq_ifc_mapping()
{
    for (la_slice_id_t sid : get_used_slices()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            switch (m_slice_mode[sid]) {
            case la_slice_mode_e::UDC:
            case la_slice_mode_e::NETWORK: {
                la_status status = configure_pdoq_oq_ifc_mapping_network(sid, ifg);
                return_on_error(status);
                break;
            }

            case la_slice_mode_e::CARRIER_FABRIC: {
                return LA_STATUS_SUCCESS;
            }

            default:
                return LA_STATUS_ENOTIMPLEMENTED;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_pdoq_oq_ifc_mapping_network_entry(la_slice_id_t sid, la_ifg_id_t ifg, la_uint_t serdes)
{
    la_uint_t oq_base = ifg * NUM_OQ_PER_IFG;
    for (la_uint_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
        const auto& table(m_tables.pdoq_oq_ifc_mapping[sid]);
        npl_pdoq_oq_ifc_mapping_key_t key;
        npl_pdoq_oq_ifc_mapping_value_t value;
        npl_pdoq_oq_ifc_mapping_entry_t* entry = nullptr;

        key.dest_oq = oq_base + (serdes * NUM_TC_CLASSES) + tc;

        value.action = NPL_PDOQ_OQ_IFC_MAPPING_ACTION_WRITE;

        value.payloads.pdoq_oq_ifc_mapping_result.fcn_profile = 0;
        // The parsed data is used by the TX network NPL code
        value.payloads.pdoq_oq_ifc_mapping_result.txpp_map_data.parsed.ifg = ifg;
        value.payloads.pdoq_oq_ifc_mapping_result.txpp_map_data.parsed.pif = serdes;
        value.payloads.pdoq_oq_ifc_mapping_result.dest_pif = serdes;

        la_status status = table->insert(key, value, entry);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_pdoq_oq_ifc_mapping_network(la_slice_id_t sid, la_ifg_id_t ifg)
{
    size_t serdes_count = m_ifg_handlers[sid][ifg]->get_serdes_count();
    for (la_uint_t serdes = 0; serdes < serdes_count; serdes++) {
        la_status status = configure_pdoq_oq_ifc_mapping_network_entry(sid, ifg, serdes);
        return_on_error(status);
    }

    la_status status = configure_pdoq_oq_ifc_mapping_network_entry(sid, ifg, HOST_PIF_ID);
    return_on_error(status);

    status = configure_pdoq_oq_ifc_mapping_network_entry(sid, ifg, RECYCLE_PIF_ID);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_reassembly_source_port_map_table()
{
    // TODO - this function is not needed for GB
    // Commented to not overwrite the init values from LBR.

    // for (la_slice_ifg slice_ifg = {.slice = 0, .ifg = 0}; slice_ifg.slice < ASIC_MAX_SLICES_PER_DEVICE_NUM_OBSOLETE;
    // slice_ifg.slice++) {
    //    for (slice_ifg.ifg = 0; slice_ifg.ifg < NUM_IFGS_PER_SLICE; slice_ifg.ifg++) {
    //        size_t serdes_count = m_ifg_handlers[slice_ifg.slice][slice_ifg.ifg]->get_serdes_count();
    //        for (la_uint_t serdes = 0; serdes < serdes_count + NUM_INTERNAL_IFCS_PER_IFG; serdes++) {
    //            const auto&
    //            table(m_tables.reassembly_source_port_map_table[slice_ifg->slice]);
    //            npl_reassembly_source_port_map_table_t::key_type k;
    //            npl_reassembly_source_port_map_table_t::value_type v;
    //            npl_reassembly_source_port_map_table_t::entry_pointer_type e = nullptr;
    //
    //            k.source_if.ifg = get_physical_ifg(slice_ifg.slice, slice_ifg.ifg);
    //            k.source_if.pif = serdes;
    //
    //            v.action = NPL_REASSEMBLY_SOURCE_PORT_MAP_TABLE_ACTION_WRITE;
    //            v.payloads.reassembly_source_port_map_result.tm_ifc = slice_ifg.ifg * tm_utils::IFG_SYSTEM_PORT_SCHEDULERS +
    //            serdes;
    //
    //            la_status status = table.insert(k, v, e);
    //            return_on_error(status);
    //        }
    //    }
    //}

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_rpf_fec_access_map_table()
{
    const auto& table(m_tables.rpf_fec_access_map_table);
    npl_rpf_fec_access_map_table_t::key_type key;
    npl_rpf_fec_access_map_table_t::value_type value;
    npl_rpf_fec_access_map_table_t::entry_pointer_type entry = nullptr;

    bool enable_class_id_acls = false;
    get_bool_property(la_device_property_e::ENABLE_CLASS_ID_ACLS, enable_class_id_acls);
    for (size_t line = 0; line < 32; ++line) {
        key.prefix = line;
        if (key.prefix == NPL_DESTINATION_FEC_PREFIX) {
            // When the access_fec_table is enabled, p4 sets
            // ip_lpm_result.rtype to be
            // IP_LPM_RESULT_TYPE_DESTINATION_FROM_FEC and the class ID is not
            // obtained from LPM payload as desired. To address this, we have a
            // device propert for Class ID ACL. When the Class ID property is
            // enabled, access_fec_table is disabled and the P4 sets
            // ip_lpm_result.rtype to IP_LPM_RESULT_TYPE_DESTINATION_FROM_LPM.
            // The Class ID is also obtained from LPM as required.
            if (enable_class_id_acls) {
                value.payloads.lpm_prefix_fec_access_map.access_fec_table = 0;
            } else {
                value.payloads.lpm_prefix_fec_access_map.access_fec_table = 1;
            }
        } else {
            value.payloads.lpm_prefix_fec_access_map.access_fec_table = 0;
        }

        la_status status = table->set(key, value, entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_tunnel_dlp_p_counter_offset_table()
{
    npl_tunnel_dlp_p_counter_offset_table_t::key_type key;
    npl_tunnel_dlp_p_counter_offset_table_t::key_type mask;
    npl_tunnel_dlp_p_counter_offset_table_t::value_type value;
    npl_tunnel_dlp_p_counter_offset_table_t::entry_pointer_type entry = nullptr;
    la_status status = LA_STATUS_SUCCESS;

    auto nw_slices = get_slices(shared_from_this(), la_slice_mode_e::NETWORK);
    for (auto slice : nw_slices) {
        size_t location = 0;
        const auto& table(m_tables.tunnel_dlp_p_counter_offset_table[slice]);

        key.is_mc = 0;
        key.is_mpls = 1;
        key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV4;
        key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
        mask.is_mc = 0;
        mask.is_mpls = 1;
        mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
        mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
        value.payloads.cntr_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
        status = table->insert(location++, key, mask, value, entry);
        return_on_error(status);

        key.is_mc = 0;
        key.is_mpls = 1;
        key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV6;
        key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
        mask.is_mc = 0;
        mask.is_mpls = 1;
        mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
        mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
        value.payloads.cntr_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
        status = table->insert(location++, key, mask, value, entry);
        return_on_error(status);

        key.is_mc = 1;
        key.is_mpls = 1;
        key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV4;
        key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
        mask.is_mc = 1;
        mask.is_mpls = 1;
        mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
        mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
        value.payloads.cntr_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
        status = table->insert(location++, key, mask, value, entry);
        return_on_error(status);

        key.is_mc = 1;
        key.is_mpls = 1;
        key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV6;
        key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
        mask.is_mc = 1;
        mask.is_mpls = 1;
        mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
        mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
        value.payloads.cntr_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
        status = table->insert(location++, key, mask, value, entry);
        return_on_error(status);

        key.is_mc = 0;
        key.is_mpls = 0;
        key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
        key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV4;
        mask.is_mc = 0;
        mask.is_mpls = 0;
        mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
        mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
        value.payloads.cntr_offset.offset = (size_t)la_l3_protocol_counter_e::IPV4_UC;
        status = table->insert(location++, key, mask, value, entry);
        return_on_error(status);

        key.is_mc = 0;
        key.is_mpls = 0;
        key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
        key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV6;
        mask.is_mc = 0;
        mask.is_mpls = 0;
        mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
        mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
        value.payloads.cntr_offset.offset = (size_t)la_l3_protocol_counter_e::IPV6_UC;
        status = table->insert(location++, key, mask, value, entry);
        return_on_error(status);

        key.is_mc = 1;
        key.is_mpls = 0;
        key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
        key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV4;
        mask.is_mc = 1;
        mask.is_mpls = 0;
        mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
        mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
        value.payloads.cntr_offset.offset = (size_t)la_l3_protocol_counter_e::IPV4_MC;
        status = table->insert(location++, key, mask, value, entry);
        return_on_error(status);

        key.is_mc = 1;
        key.is_mpls = 0;
        key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
        key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV6;
        mask.is_mc = 1;
        mask.is_mpls = 0;
        mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
        mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
        value.payloads.cntr_offset.offset = (size_t)la_l3_protocol_counter_e::IPV6_MC;
        status = table->insert(location++, key, mask, value, entry);
        return_on_error(status);
    }
    return status;
}

la_status
la_device_impl::configure_l3_dlp_p_counter_offset_table()
{
    const auto& table(m_tables.l3_dlp_p_counter_offset_table);
    npl_l3_dlp_p_counter_offset_table_t::key_type key;
    npl_l3_dlp_p_counter_offset_table_t::key_type mask;
    npl_l3_dlp_p_counter_offset_table_t::value_type value;
    npl_l3_dlp_p_counter_offset_table_t::entry_pointer_type entry = nullptr;
    size_t location = 0;
    la_status status;

    if (is_mpls_sr_accounting_enabled()) {
        key = {};
        key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR;
        mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
        mask.is_mc = 0;
        mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0x0);
        mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
        value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS_SR;
        status = table->insert(location++, key, mask, value, entry);
        return_on_error(status);
    }

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_ETHERNET;
    key.is_mc = 0;
    key.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0x0);
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0x0);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_ETHERNET;
    key.is_mc = 0;
    key.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0x0);
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0x0);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_ETHERNET;
    key.is_mc = 0;
    key.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0x0);
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0x0);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_ETHERNET;
    key.is_mc = 0;
    key.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0x0);
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0x0);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV4;
    key.is_mc = 0;
    key.ip_acl_macro_control = NPL_IP_ROUTING_TO_NH_UC;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 1;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::IPV4_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    // for GRE IPv4 tunnel counters
    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV4;
    key.is_mc = 0;
    key.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::IPV4_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV4;
    key.is_mc = 1;
    key.ip_acl_macro_control = NPL_IP_ROUTING_TO_NH_UC;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 1;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0xf);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::IPV4_MC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV6;
    key.is_mc = 0;
    key.ip_acl_macro_control = NPL_IP_ROUTING_TO_NH_UC;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 1;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::IPV6_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    // for GRE Encap, IPv6 Payload egress interface counters
    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV6;
    key.is_mc = 0;
    key.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::IPV4_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV4;
    key.is_mc = 1;
    key.ip_acl_macro_control = NPL_MPLS_PHP;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 1;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0xf);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::IPV4_MC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV6;
    key.is_mc = 0;
    key.ip_acl_macro_control = NPL_MPLS_PHP;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 1;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0xf);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::IPV6_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV6;
    key.is_mc = 1;
    key.ip_acl_macro_control = NPL_IP_ROUTING_TO_NH_UC;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 1;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0xf);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::IPV6_MC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    // All routing flows into mpls tunnel have the msb of the acl macro control set
    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV4;
    key.is_mc = 0;
    key.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    // All routing flows into mpls tunnel have the msb of the acl macro control set
    key = {};
    key.fwd_header_type = NPL_FWD_HEADER_TYPE_IPV6;
    key.is_mc = 0;
    key.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    // All routing flows into mpls tunnel have the msb of the acl macro control set
    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_HEADER_TYPE_MPLS_HEADERS_PREFIX << 2);
    key.is_mc = 0;
    key.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0xc);
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(1 << 3);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    // PHP in QoS Macro assume MPLS
    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_HEADER_TYPE_MPLS_HEADERS_PREFIX << 2);
    key.is_mc = 0;
    key.ip_acl_macro_control = NPL_MPLS_PHP;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0xc);
    mask.is_mc = 0;
    mask.ip_acl_macro_control = static_cast<npl_ip_acl_macro_control_e>(0xf);
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.local_tx_counter_offset.offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_te_headend_lsp_counter_offset_table()
{
    const auto& table(m_tables.te_headend_lsp_counter_offset_table);
    npl_te_headend_lsp_counter_offset_table_t::key_type key;
    npl_te_headend_lsp_counter_offset_table_t::key_type mask;
    npl_te_headend_lsp_counter_offset_table_t::value_type value;
    npl_te_headend_lsp_counter_offset_table_t::entry_pointer_type entry = nullptr;
    size_t location = 0;
    la_status status;

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_IPV4);
    key.is_mc = 0;
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_mpls_sr_protocol_counter_e::IP_UC;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset
        = is_mpls_sr_accounting_enabled() ? (size_t)la_l3_protocol_counter_e::MPLS_SR : (size_t)la_l3_protocol_counter_e::IPV4_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_IPV6);
    key.is_mc = 0;
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_mpls_sr_protocol_counter_e::IP_UC;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset
        = is_mpls_sr_accounting_enabled() ? (size_t)la_l3_protocol_counter_e::MPLS_SR : (size_t)la_l3_protocol_counter_e::IPV6_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV4);
    key.is_mc = 0;
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_mpls_sr_protocol_counter_e::MPLS;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset
        = is_mpls_sr_accounting_enabled() ? (size_t)la_l3_protocol_counter_e::MPLS_SR : (size_t)la_l3_protocol_counter_e::IPV4_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV6);
    key.is_mc = 0;
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_mpls_sr_protocol_counter_e::MPLS;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset
        = is_mpls_sr_accounting_enabled() ? (size_t)la_l3_protocol_counter_e::MPLS_SR : (size_t)la_l3_protocol_counter_e::IPV6_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(0);
    key.is_mc = 0;
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_mpls_sr_protocol_counter_e::MPLS;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset
        = is_mpls_sr_accounting_enabled() ? (size_t)la_l3_protocol_counter_e::MPLS_SR : (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_IPV4);
    key.is_mc = 0;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = 0;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_l3_protocol_counter_e::IPV4_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_IPV6);
    key.is_mc = 0;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = 0;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_l3_protocol_counter_e::IPV6_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV4);
    key.is_mc = 0;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = 0;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_l3_protocol_counter_e::IPV4_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV6);
    key.is_mc = 0;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = 0;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_l3_protocol_counter_e::IPV6_UC;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_MPLS_NO_BOS);
    key.is_mc = 0;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(0);
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = 0;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
    key.is_mc = 0;
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = 0;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
    key.is_mc = 0;
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = 0;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key = {};
    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
    key.is_mc = 0;
    key.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(0x0);
    mask.is_mc = 0;
    mask.l3_encap_type = static_cast<npl_npu_encap_l3_header_type_e>(bit_utils::get_lsb_mask(4));
    value.payloads.offsets.lsp_counter_offset.cntr_offset.offset.base_cntr_offset = 0;
    value.payloads.offsets.php_counter_offset.cntr_offset.offset.base_cntr_offset = (size_t)la_l3_protocol_counter_e::MPLS;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_dsp_dest_msbs_for_ecn_table()
{
    bool ecn_queuing_enabled = false;
    la_status status = get_bool_property(la_device_property_e::ENABLE_ECN_QUEUING, ecn_queuing_enabled);
    return_on_error(status);

    if (!ecn_queuing_enabled) {
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_tables.dsp_dest_msbs_for_ecn_table);
    npl_dsp_dest_msbs_for_ecn_table_t::key_type key;
    npl_dsp_dest_msbs_for_ecn_table_t::key_type mask;
    npl_dsp_dest_msbs_for_ecn_table_t::value_type value;
    npl_dsp_dest_msbs_for_ecn_table_t::entry_pointer_type entry = nullptr;
    size_t location = 0;

    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_IPV4);
    key.ipv4_ecn = 0;
    key.ipv6_ecn = 0;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.ipv4_ecn = 0x3;
    mask.ipv6_ecn = 0;
    value.payloads.dsp_dest_msbs = NPL_DSP_DEST_MSBS_DEFAULT;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_IPV4);
    key.ipv4_ecn = 0;
    key.ipv6_ecn = 0;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.ipv4_ecn = 0;
    mask.ipv6_ecn = 0;
    value.payloads.dsp_dest_msbs = NPL_DSP_DEST_MSBS_ALTERNATE;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_IPV6);
    key.ipv4_ecn = 0;
    key.ipv6_ecn = 0;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.ipv4_ecn = 0;
    mask.ipv6_ecn = 0x3;
    value.payloads.dsp_dest_msbs = NPL_DSP_DEST_MSBS_DEFAULT;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    key.fwd_header_type = static_cast<npl_fwd_header_type_e>(NPL_FWD_HEADER_TYPE_IPV6);
    key.ipv4_ecn = 0;
    key.ipv6_ecn = 0;
    mask.fwd_header_type = static_cast<npl_fwd_header_type_e>(bit_utils::get_lsb_mask(4));
    mask.ipv4_ecn = 0;
    mask.ipv6_ecn = 0;
    value.payloads.dsp_dest_msbs = NPL_DSP_DEST_MSBS_ALTERNATE;
    status = table->insert(location++, key, mask, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

std::vector<la_object*>
la_device_impl::get_objects(object_type_e type) const
{
    std::vector<la_object*> objects_attached;
    // Iterating on indices is easier for debug
    for (size_t oid = 0; oid < m_objects.size(); oid++) {
        if (m_objects[oid] == nullptr) {
            continue;
        }

        if (m_objects[oid]->type() == type) {
            objects_attached.push_back(m_objects[oid].get());
        }
    }

    return objects_attached;
}

std::vector<la_object_wptr>
la_device_impl::get_objects_wptr(object_type_e type) const
{
    std::vector<la_object_wptr> objects_attached;
    // Iterating on indices is easier for debug
    for (size_t oid = 0; oid < m_objects.size(); oid++) {
        if (m_objects[oid] == nullptr) {
            continue;
        }

        if (m_objects[oid]->type() == type) {
            objects_attached.push_back(m_objects[oid]);
        }
    }

    return objects_attached;
}

std::vector<la_object*>
la_device_impl::get_objects() const
{
    std::vector<la_object*> objects_attached;
    for (auto& object : m_objects) {
        if (object) {
            objects_attached.push_back(object.get());
        }
    }

    return objects_attached;
}

la_object*
la_device_impl::get_object(la_object_id_t oid) const
{
    if (oid >= m_objects.size()) {
        return nullptr;
    }
    return m_objects[oid].get();
}

ll_device_sptr
la_device_impl::get_ll_device_sptr() const
{
    return m_ll_device;
}

la_status
la_device_impl::get_device_information(la_device_info_t& out_dev_info) const
{
    gibraltar::top_chip_id_reg_register dev_id_reg{{0}};

    la_status status = m_ll_device->read_register(m_gb_tree->top_regfile->chip_id_reg, dev_id_reg);
    return_on_error(status);

    out_dev_info.family = m_ll_device->get_device_revision();
    out_dev_info.extension = dev_id_reg.fields.manufacturer_identity_code;
    out_dev_info.revision = dev_id_reg.fields.version_code;
    out_dev_info.part_num = dev_id_reg.fields.part_number_code;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_slice_mode(la_slice_id_t slice_id, la_slice_mode_e& out_slice_mode) const
{
    // this is intentional - seting / geting the slice mode  should be enabled also for disabled slices
    if (slice_id >= m_slice_mode.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_slice_mode = m_slice_mode[slice_id];

    return la_status_e::SUCCESS;
}

la_status
la_device_impl::set_slice_mode(la_slice_id_t sid, la_slice_mode_e slice_mode)
{
    start_api_call("sid=", sid, "slice_mode=", slice_mode);
    if (m_init_phase == init_phase_e::TOPOLOGY) {
        // Wrong stage to change slice mode
        return LA_STATUS_EBUSY;
    }

    la_status status = m_slice_id_manager->is_slice_valid(sid);
    return_on_error(status);

    m_slice_mode[sid] = slice_mode;
    // Set SliceMode field of DqcGeneralConfiguration register in PDOQ of the relevant slice
    /*
    LA_SLICE_MODE_CRF_NWK_TS    = 0,  ///< Linecard mode CRF TS network slice
    LA_SLICE_MODE_CRF_NWK_SN    = 1,  ///< Linecard mode CRF SN network slice
    LA_SLICE_MODE_CRF_FAB_TS    = 2,  ///< Linecard mode CRF TS fabric slice
    LA_SLICE_MODE_CRF_FAB_SN    = 3,  ///< Linecard mode CRF SN fabric slice
    LA_SLICE_MODE_TOR_NWK       = 4,  ///< TOR mode network slice
    LA_SLICE_MODE_TOR_FAB       = 5,  ///< TOR mode fabric slice
    LA_SLICE_MODE_FE_TS         = 6,  ///< FE mode with TS
    LA_SLICE_MODE_FE_SN         = 7,  ///< FE mode with SN
    LA_SLICE_MODE_SA            = 8,  ///< Stand alone device
    LA_SLICE_MODE_DRAM          = 9,  ///< DRAM slice
    */
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_fabric_mac_ports_mode(fabric_mac_ports_mode_e& out_fabric_mac_ports_mode) const
{
    start_api_getter_call();
    out_fabric_mac_ports_mode = m_fabric_mac_ports_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_fabric_mac_ports_mode(fabric_mac_ports_mode_e fabric_mac_ports_mode)
{
    start_api_call("fabric_mac_ports_mode=", fabric_mac_ports_mode);
    if (m_init_phase == init_phase_e::TOPOLOGY) {
        // Wrong stage to change slice mode
        return LA_STATUS_EBUSY;
    }

    m_fabric_mac_ports_mode = fabric_mac_ports_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_fabric_slice_clos_direction(la_slice_id_t slice_id, la_clos_direction_e clos_direction)
{
    start_api_call("slice_id=", slice_id, "clos_direction=", clos_direction);
    // this is intentional - seting / geting the close direction should be enabled also for disabled slices
    if (slice_id >= m_slice_clos_direction.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    m_slice_clos_direction[slice_id] = clos_direction;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_fabric_slice_clos_direction(la_slice_id_t slice_id, la_clos_direction_e& out_clos_direction) const
{
    // this is intentional - seting / geting the close direction should be enabled also for disabled slices
    if (slice_id >= m_slice_clos_direction.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_slice_clos_direction[slice_id] == CLOS_DIRECTION_INVALID) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    out_clos_direction = m_slice_clos_direction[slice_id];

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_is_fabric_time_master(bool is_master)
{
    if (m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_EINVAL;
    }

    gibraltar::fte_fabric_time_force_reg_register reg = {.u8 = {0}};
    reg.fields.fabric_time_sync_force_value = is_master;
    reg.fields.fabric_time_force_value = 0x000ffffff;

    la_status status = m_ll_device->write_register(m_gb_tree->dmc->fte->fabric_time_force_reg, reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_fabric_time_sync_status(bool& out_sync_status) const
{
    if (m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_EINVAL;
    }

    gibraltar::fte_time_status_reg_register reg;

    la_status status = m_ll_device->read_register(m_gb_tree->dmc->fte->time_status_reg, reg);

    return_on_error(status);

    out_sync_status = reg.fields.fabric_time_sync_status;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_num_of_serdes(la_slice_id_t slice_id, la_ifg_id_t ifg_id, size_t& out_num_of_serdes) const
{
    out_num_of_serdes = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_serdes_source(la_slice_id_t slice_id, la_ifg_id_t ifg_id, std::vector<la_uint_t>& out_serdes_mapping_vec) const
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    out_serdes_mapping_vec.resize(serdes_count, 0);

    for (size_t serdes_id = 0; serdes_id < serdes_count; serdes_id++) {
        out_serdes_mapping_vec[serdes_id] = m_serdes_info[slice_id][ifg_id][serdes_id].rx_source;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_serdes_source(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_uint_t serdes_index, la_uint_t& out_serdes) const
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    if (serdes_index >= m_ifg_handlers[slice_id][ifg_id]->get_serdes_count()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_serdes = m_serdes_info[slice_id][ifg_id][serdes_index].rx_source;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::check_serdes_mapping(la_slice_id_t slice_id,
                                     la_ifg_id_t ifg_id,
                                     la_serdes_direction_e direction,
                                     std::vector<la_uint_t> serdes_mapping_vec)
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    if (serdes_mapping_vec.size() != serdes_count) {
        log_err(HLD, "%s: bad serdes_count, %ld vs %ld", __func__, serdes_mapping_vec.size(), serdes_count);
        return LA_STATUS_EINVAL;
    }

    // Check vector validity
    std::vector<bool> tmp_vec(serdes_count, false);
    // Do reverse mapping and check
    for (size_t serdes_id = 0; serdes_id < serdes_count; serdes_id++) {
        size_t mapped_serdes = serdes_mapping_vec[serdes_id];

        if (mapped_serdes >= serdes_count) {
            return LA_STATUS_EOUTOFRANGE;
        }

        if (tmp_vec[mapped_serdes]) {
            // Already used for other SerDes
            log_err(HLD,
                    "%s: %d/%d/%ld : serdes_id=%ld, mapped_serdes=%ld, already in use",
                    __func__,
                    slice_id,
                    ifg_id,
                    serdes_id,
                    serdes_id,
                    mapped_serdes);
            return LA_STATUS_EINVAL;
        }

        // A group of serdes is 4 ports for RX swap, and 8 for ANLT order
        // swap is allowed only within the group
        const size_t log_group_size = (direction == la_serdes_direction_e::RX) ? 2 : 3;
        size_t serdes_group = serdes_id >> log_group_size;
        size_t mapped_serdes_group = mapped_serdes >> log_group_size;

        if (serdes_group != mapped_serdes_group) {
            log_err(HLD, "%s: mismatch, serdes_group=%ld, mapped_serdes_group=%ld", __func__, serdes_group, mapped_serdes_group);
            return LA_STATUS_EINVAL;
        }

        tmp_vec[mapped_serdes] = true;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_serdes_source(la_slice_id_t slice_id, la_ifg_id_t ifg_id, std::vector<la_uint_t> serdes_mapping_vec)
{
    start_api_call("slice_id=", slice_id, "ifg_id=", ifg_id, "serdes_mapping_vec=", serdes_mapping_vec);

    if (m_init_phase == init_phase_e::TOPOLOGY) {
        // Wrong stage to change slice mode
        return LA_STATUS_EBUSY;
    }

    la_status status = check_serdes_mapping(slice_id, ifg_id, la_serdes_direction_e::RX, serdes_mapping_vec);
    return_on_error(status);

    // Update data members
    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    for (size_t serdes_id = 0; serdes_id < serdes_count; serdes_id++) {
        m_serdes_info[slice_id][ifg_id][serdes_id].rx_source = serdes_mapping_vec[serdes_id];
    }
    m_reconnect_handler->update_serdes_mapping(slice_id, ifg_id, la_serdes_direction_e::RX, serdes_mapping_vec);

    status = m_ifg_handlers[slice_id][ifg_id]->set_rx_lane_swap();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_serdes_anlt_order(la_slice_id_t slice_id,
                                      la_ifg_id_t ifg_id,
                                      std::vector<la_uint_t>& out_serdes_anlt_order_vec) const
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    out_serdes_anlt_order_vec.resize(serdes_count, 0);

    for (size_t serdes_id = 0; serdes_id < serdes_count; serdes_id++) {
        out_serdes_anlt_order_vec[serdes_id] = m_serdes_info[slice_id][ifg_id][serdes_id].anlt_order;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_serdes_anlt_order(la_slice_id_t slice_id, la_ifg_id_t ifg_id, std::vector<la_uint_t> serdes_anlt_order_vec)
{
    if (m_init_phase == init_phase_e::TOPOLOGY) {
        // Wrong stage to change slice mode
        return LA_STATUS_EBUSY;
    }

    la_status status = check_serdes_mapping(slice_id, ifg_id, la_serdes_direction_e::TX, serdes_anlt_order_vec);
    return_on_error(status);

    // Update data members
    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    for (size_t serdes_id = 0; serdes_id < serdes_count; serdes_id++) {
        m_serdes_info[slice_id][ifg_id][serdes_id].anlt_order = serdes_anlt_order_vec[serdes_id];
    }

    m_reconnect_handler->update_serdes_mapping(slice_id, ifg_id, la_serdes_direction_e::TX, serdes_anlt_order_vec);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_serdes_polarity_inversion(la_slice_id_t slice_id,
                                              la_ifg_id_t ifg_id,
                                              la_uint_t serdes_id,
                                              la_serdes_direction_e direction,
                                              bool& out_invert) const
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();

    if (serdes_id >= serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_invert = (direction == la_serdes_direction_e::RX) ? m_serdes_info[slice_id][ifg_id][serdes_id].rx_polarity_inversion
                                                          : m_serdes_info[slice_id][ifg_id][serdes_id].tx_polarity_inversion;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_serdes_polarity_inversion(la_slice_id_t slice_id,
                                              la_ifg_id_t ifg_id,
                                              la_uint_t serdes_id,
                                              la_serdes_direction_e direction,
                                              bool invert)
{
    start_api_call("slice_id=", slice_id, "ifg_id=", ifg_id, "serdes_id=", serdes_id, "direction=", direction, "invert=", invert);

    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    if (serdes_id >= serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (direction == la_serdes_direction_e::RX) {
        m_serdes_info[slice_id][ifg_id][serdes_id].rx_polarity_inversion = invert;
    } else {
        m_serdes_info[slice_id][ifg_id][serdes_id].tx_polarity_inversion = invert;
    }

    m_reconnect_handler->update_serdes_polarity_inversion(slice_id, ifg_id, serdes_id, direction, invert);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_serdes_addr(la_slice_id_t slice,
                                la_ifg_id_t ifg,
                                la_uint_t serdes_idx,
                                la_serdes_direction_e direction,
                                uint32_t& out_serdes_addr)
{
    size_t serdes_count = m_ifg_handlers[slice][ifg]->get_serdes_count();
    if (serdes_idx > serdes_count) {
        log_err(HLD,
                "%s: serdes_idx=%d higher than slice=%d ifg_id=%d SerDes count %d",
                __func__,
                serdes_idx,
                slice,
                ifg,
                (int)serdes_count);
        return LA_STATUS_EOUTOFRANGE;
    }

    return m_serdes_device_handler->get_serdes_addr(slice, ifg, serdes_idx, direction, out_serdes_addr);
}

la_uint_t
la_device_impl::get_pif_from_serdes(la_uint_t serdes_idx)
{
    return serdes_idx; // in GB each serdes represent 1 pif
}
static bool
is_destructible_from_api(const la_object_wcptr& object)
{
    std::vector<la_object::object_type_e> not_destructible_from_api = {
        la_object::object_type_e::LSR,
        la_object::object_type_e::FORUS_DESTINATION,
        la_object::object_type_e::HBM_HANDLER,
        la_object::object_type_e::FABRIC_PORT_SCHEDULER,
        la_object::object_type_e::IFG_SCHEDULER,
        la_object::object_type_e::INTERFACE_SCHEDULER,
        la_object::object_type_e::LOGICAL_PORT_SCHEDULER,
        la_object::object_type_e::SYSTEM_PORT_SCHEDULER,
    };

    return std::find(not_destructible_from_api.begin(), not_destructible_from_api.end(), object->type())
           == not_destructible_from_api.end();
}

la_status
la_device_impl::destroy(la_object* object)
{
    start_api_call("object=", object);

    if (object == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_object_id_t oid = object->oid();
    if (m_is_builtin_objects[oid]) {
        return LA_STATUS_EINVAL;
    }

    auto object_sptr = get_sptr(object);

    if (!is_destructible_from_api(object_sptr)) {
        return LA_STATUS_EINVAL;
    }

    la_status status = do_destroy(object_sptr);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_destroy(const la_object_wptr& object)
{
    la_object::object_type_e type = object->type();

    auto status = LA_STATUS_EUNKNOWN;

    switch (type) {

    case la_object::object_type_e::LSR: {
        auto oi = object.weak_ptr_static_cast<la_lsr_impl>();
        status = oi->destroy();
    } break;
    case la_object::object_type_e::FORUS_DESTINATION: {
        auto oi = object.weak_ptr_static_cast<la_forus_destination_impl>();
        status = oi->destroy();
    } break;
    case la_object::object_type_e::HBM_HANDLER: {
        auto oi = object.weak_ptr_static_cast<la_hbm_handler_impl>();
        status = oi->destroy();
    } break;
    case la_object::object_type_e::FABRIC_PORT_SCHEDULER: {
        auto oi = object.weak_ptr_static_cast<la_fabric_port_scheduler_impl>();
        status = oi->destroy();
    } break;
    case la_object::object_type_e::IFG_SCHEDULER: {
        auto oi = object.weak_ptr_static_cast<la_ifg_scheduler_impl>();
        status = oi->destroy();
    } break;
    case la_object::object_type_e::INTERFACE_SCHEDULER: {
        auto oi = object.weak_ptr_static_cast<la_interface_scheduler_impl>();
        status = oi->destroy();
    } break;
    case la_object::object_type_e::LOGICAL_PORT_SCHEDULER: {
        auto oi = object.weak_ptr_static_cast<la_logical_port_scheduler_impl>();
        status = oi->destroy();
    } break;
    case la_object::object_type_e::SYSTEM_PORT_SCHEDULER: {
        auto oi = object.weak_ptr_static_cast<la_system_port_scheduler_impl>();
        status = oi->destroy();
    } break;

    case la_object::object_type_e::AC_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_ac_profile_impl>();
        status = destroy_ac_profile(profile);
    } break;
    case la_object::object_type_e::ACL: {
        auto acl = object.weak_ptr_static_cast<la_acl_impl>();
        status = destroy_acl(acl);
    } break;
    case la_object::object_type_e::ACL_KEY_PROFILE: {
        auto acl_key_profile = object.weak_ptr_static_cast<la_acl_key_profile_base>();
        status = destroy_acl_key_profile(acl_key_profile);
    } break;
    case la_object::object_type_e::ACL_COMMAND_PROFILE: {
        auto acl_command_profile = object.weak_ptr_static_cast<la_acl_command_profile_base>();
        status = destroy_acl_command_profile(acl_command_profile);
    } break;
    case la_object::object_type_e::ACL_GROUP: {
        auto acl_group = object.weak_ptr_static_cast<la_acl_group_base>();
        status = destroy_acl_group(acl_group);
    } break;
    case la_object::object_type_e::ACL_SCALED: {
        auto acl = object.weak_ptr_static_cast<la_acl_scaled_impl>();
        status = destroy_acl_scaled(acl);
    } break;
    case la_object::object_type_e::ASBR_LSP: {
        auto asbr_lsp = object.weak_ptr_static_cast<la_asbr_lsp_impl>();
        status = destroy_asbr_lsp(asbr_lsp);
    } break;
    case la_object::object_type_e::BFD_SESSION: {
        auto bfd_session = object.weak_ptr_static_cast<la_bfd_session_base>();
        status = destroy_bfd_session(bfd_session);
    } break;
    case la_object::object_type_e::COUNTER_SET: {
        auto set = object.weak_ptr_static_cast<la_counter_set_impl>();
        status = destroy_counter(set);
    } break;
    case la_object::object_type_e::DESTINATION_PE: {
        auto destination_pe = object.weak_ptr_static_cast<la_destination_pe_impl>();
        status = destroy_destination_pe(destination_pe);
    } break;
    case la_object::object_type_e::ECMP_GROUP: {
        auto group = object.weak_ptr_static_cast<la_ecmp_group_impl>();
        status = destroy_ecmp_group(group);
    } break;
    case la_object::object_type_e::EGRESS_QOS_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_egress_qos_profile_impl>();
        status = destroy_egress_qos_profile(profile);
    } break;
    case la_object::object_type_e::ERSPAN_MIRROR_COMMAND: {
        auto command = object.weak_ptr_static_cast<la_erspan_mirror_command_base>();
        status = destroy_erspan_mirror_command(command);
    } break;
    case la_object::object_type_e::ETHERNET_PORT: {
        auto port = object.weak_ptr_static_cast<la_ethernet_port_gibraltar>();
        status = destroy_ethernet_port(port);
    } break;
    case la_object::object_type_e::FABRIC_PORT: {
        auto port = object.weak_ptr_static_cast<la_fabric_port_impl>();
        status = destroy_fabric_port(port);
    } break;
    case la_object::object_type_e::FEC: {
        auto fec = object.weak_ptr_static_cast<la_l3_fec_impl>();
        status = destroy_l3_fec(fec);
    } break;
    case la_object::object_type_e::FILTER_GROUP: {
        auto group = object.weak_ptr_static_cast<la_filter_group_impl>();
        status = destroy_filter_group(group);
    } break;
    case la_object::object_type_e::INGRESS_QOS_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_ingress_qos_profile_impl>();
        status = destroy_ingress_qos_profile(profile);
    } break;
    case la_object::object_type_e::IP_MULTICAST_GROUP: {
        auto group = object.weak_ptr_static_cast<la_ip_multicast_group_base>();
        status = destroy_ip_multicast_group(group);
    } break;
    case la_object::object_type_e::IP_TUNNEL_DESTINATION: {
        auto dest = object.weak_ptr_static_cast<la_ip_tunnel_destination_impl>();
        status = destroy_ip_tunnel_destination(dest);
    } break;
    case la_object::object_type_e::L2_MIRROR_COMMAND: {
        auto command = object.weak_ptr_static_cast<la_l2_mirror_command_base>();
        status = destroy_l2_mirror_command(command);
    } break;
    case la_object::object_type_e::L2_MULTICAST_GROUP: {
        auto group = object.weak_ptr_static_cast<la_l2_multicast_group_base>();
        status = destroy_l2_multicast_group(group);
    } break;
    case la_object::object_type_e::FABRIC_MULTICAST_GROUP: {
        auto group = object.weak_ptr_static_cast<la_fabric_multicast_group_impl>();
        status = destroy_fabric_multicast_group(group);
    } break;
    case la_object::object_type_e::L2_PROTECTION_GROUP: {
        auto group = object.weak_ptr_static_cast<la_l2_protection_group_base>();
        status = destroy_l2_protection_group(group);
    } break;
    case la_object::object_type_e::L3_PROTECTION_GROUP: {
        auto group = object.weak_ptr_static_cast<la_l3_protection_group_impl>();
        status = destroy_l3_protection_group(group);
    } break;
    case la_object::object_type_e::L2_PUNT_DESTINATION: {
        auto dest = object.weak_ptr_static_cast<la_l2_punt_destination_impl>();
        status = destroy_l2_punt_destination(dest);
    } break;
    case la_object::object_type_e::L2_SERVICE_PORT: {
        auto port = object.weak_ptr_static_cast<la_l2_service_port_gibraltar>();
        status = destroy_l2_service_port(port);
    } break;
    case la_object::object_type_e::L3_AC_PORT: {
        auto port = object.weak_ptr_static_cast<la_l3_ac_port_impl>();
        status = destroy_l3_ac_port(port);
    } break;
    case la_object::object_type_e::MAC_PORT: {
        auto port = object.weak_ptr_static_cast<la_mac_port_base>();
        status = destroy_mac_port(port);
    } break;
    case la_object::object_type_e::METER_ACTION_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_meter_action_profile_impl>();
        status = destroy_meter_action_profile(profile);
    } break;
    case la_object::object_type_e::METER_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_meter_profile_impl>();
        status = destroy_meter_profile(profile);
    } break;
    case la_object::object_type_e::METER_SET: {
        auto set = object.weak_ptr_static_cast<la_meter_set_impl>();
        status = destroy_meter(set);
    } break;
    case la_object::object_type_e::MPLS_LABEL_DESTINATION: {
        auto dest = object.weak_ptr_static_cast<la_mpls_label_destination_impl>();
        status = destroy_mpls_label_destination(dest);
    } break;
    case la_object::object_type_e::MPLS_NHLFE: {
        auto nhlfe = object.weak_ptr_static_cast<la_mpls_nhlfe_impl>();
        status = destroy_mpls_nhlfe(nhlfe);
    } break;
    case la_object::object_type_e::MPLS_VPN_DECAP: {
        auto vpn_decap = object.weak_ptr_static_cast<la_mpls_vpn_decap_impl>();
        status = destroy_mpls_vpn_decap(vpn_decap);
    } break;
    case la_object::object_type_e::MPLS_VPN_ENCAP: {
        auto vpn_encap = object.weak_ptr_static_cast<la_mpls_vpn_encap_impl>();
        status = destroy_mpls_vpn_encap(vpn_encap);
    } break;
    case la_object::object_type_e::MLDP_VPN_DECAP: {
        auto vpn_decap = object.weak_ptr_static_cast<la_mldp_vpn_decap_impl>();
        status = destroy_mldp_vpn_decap(vpn_decap);
    } break;
    case la_object::object_type_e::MPLS_MULTICAST_GROUP: {
        auto mcg = object.weak_ptr_static_cast<la_mpls_multicast_group_impl>();
        status = destroy_mpls_multicast_group(mcg);
    } break;
    case la_object::object_type_e::MULTICAST_PROTECTION_GROUP: {
        auto mpg = object.weak_ptr_static_cast<la_multicast_protection_group_base>();
        status = destroy_multicast_protection_group(mpg);
    } break;
    case la_object::object_type_e::MULTICAST_PROTECTION_MONITOR: {
        auto mpm = object.weak_ptr_static_cast<la_multicast_protection_monitor_base>();
        status = destroy_multicast_protection_monitor(mpm);
    } break;
    case la_object::object_type_e::NEXT_HOP: {
        auto hop = object.weak_ptr_static_cast<la_next_hop_base>();
        status = destroy_next_hop(hop);
    } break;
    case la_object::object_type_e::NPU_HOST_DESTINATION: {
        auto port = object.weak_ptr_static_cast<la_npu_host_destination_impl>();
        status = destroy_npu_host_destination(port);
    } break;
    case la_object::object_type_e::NPU_HOST_PORT: {
        auto port = object.weak_ptr_static_cast<la_npu_host_port_base>();
        status = destroy_npu_host_port(port);
    } break;
    case la_object::object_type_e::OG_LPTS_APPLICATION: {
        auto og_lpts_app = object.weak_ptr_static_cast<la_og_lpts_application_impl>();
        status = destroy_og_lpts_app(og_lpts_app);
    } break;
    case la_object::object_type_e::OUTPUT_QUEUE_SCHEDULER: {
        auto scheduler = object.weak_ptr_static_cast<la_output_queue_scheduler_impl>();
        status = destroy_output_queue_scheduler(scheduler);
    } break;
    case la_object::object_type_e::PCI_PORT: {
        auto port = object.weak_ptr_static_cast<la_pci_port_base>();
        status = destroy_pci_port(port);
    } break;
    case la_object::object_type_e::PCL: {
        auto pcl = object.weak_ptr_static_cast<la_pcl_impl>();
        status = destroy_pcl(pcl);
    } break;
    case la_object::object_type_e::PREFIX_OBJECT: {
        auto dest = object.weak_ptr_static_cast<la_prefix_object_base>();
        status = destroy_prefix_object(dest);
    } break;
    case la_object::object_type_e::PROTECTION_MONITOR: {
        auto monitor = object.weak_ptr_static_cast<la_protection_monitor_impl>();
        status = destroy_protection_monitor(monitor);
    } break;
    case la_object::object_type_e::PUNT_INJECT_PORT: {
        auto port = object.weak_ptr_static_cast<la_punt_inject_port_base>();
        status = destroy_punt_inject_port(port);
    } break;
    case la_object::object_type_e::RECYCLE_PORT: {
        auto port = object.weak_ptr_static_cast<la_recycle_port_base>();
        status = destroy_recycle_port(port);
    } break;
    case la_object::object_type_e::REMOTE_PORT: {
        auto port = object.weak_ptr_static_cast<la_remote_port_impl>();
        status = destroy_remote_port(port);
    } break;
    case la_object::object_type_e::REMOTE_DEVICE: {
        auto remote_device = object.weak_ptr_static_cast<la_remote_device_base>();
        status = destroy_remote_device(remote_device);
    } break;
    case la_object::object_type_e::RX_CGM_SQ_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_rx_cgm_sq_profile_impl>();
        status = destroy_rx_cgm_sq_profile(profile);
    } break;
    case la_object::object_type_e::SPA_PORT: {
        auto port = object.weak_ptr_static_cast<la_spa_port_base>();
        status = destroy_spa_port(port);
    } break;
    case la_object::object_type_e::STACK_PORT: {
        auto stackport = object.weak_ptr_static_cast<la_stack_port_base>();
        status = destroy_stack_port(stackport);
    } break;
    case la_object::object_type_e::SVI_PORT: {
        auto port = object.weak_ptr_static_cast<la_svi_port_base>();
        status = destroy_svi_port(port);
    } break;
    case la_object::object_type_e::GRE_PORT: {
        auto port = object.weak_ptr_static_cast<la_gre_port_impl>();
        status = destroy_gre_port(port);
    } break;
    case la_object::object_type_e::SWITCH: {
        auto switch1 = object.weak_ptr_static_cast<la_switch_impl>();
        status = destroy_switch(switch1);
    } break;
    case la_object::object_type_e::SYSTEM_PORT: {
        auto port = object.weak_ptr_static_cast<la_system_port_base>();
        status = destroy_system_port(port);
    } break;
    case la_object::object_type_e::TE_TUNNEL: {
        auto dest = object.weak_ptr_static_cast<la_te_tunnel_impl>();
        status = destroy_te_tunnel(dest);
    } break;
    case la_object::object_type_e::TC_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_tc_profile_impl>();
        status = destroy_tc_profile(profile);
    } break;
    case la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT: {
        auto port = object.weak_ptr_static_cast<la_ip_over_ip_tunnel_port_impl>();
        status = destroy_ip_over_ip_tunnel_port(port);
    } break;
    case la_object::object_type_e::GUE_PORT: {
        auto port = object.weak_ptr_static_cast<la_gue_port_impl>();
        status = destroy_gue_port(port);
    } break;
    case la_object::object_type_e::VOQ_CGM_EVICTED_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_voq_cgm_evicted_profile_impl>();
        status = destroy_voq_cgm_evicted_profile(profile);
    } break;
    case la_object::object_type_e::VOQ_CGM_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_voq_cgm_profile_impl>();
        status = destroy_voq_cgm_profile(profile);
    } break;
    case la_object::object_type_e::VOQ_SET: {
        auto set = object.weak_ptr_static_cast<la_voq_set_impl>();
        status = destroy_voq_set(set);
    } break;
    case la_object::object_type_e::VRF: {
        auto vrf = object.weak_ptr_static_cast<la_vrf_impl>();
        status = destroy_vrf(vrf);
    } break;
    case la_object::object_type_e::VXLAN_NEXT_HOP: {
        auto hop = object.weak_ptr_static_cast<la_vxlan_next_hop_gibraltar>();
        status = destroy_vxlan_next_hop(hop);
    } break;
    case la_object::object_type_e::RTF_CONF_SET: {
        return LA_STATUS_EINVAL;
    } break;
    case la_object::object_type_e::LPTS: {
        auto lpts = object.weak_ptr_static_cast<la_lpts_impl>();
        status = destroy_lpts(lpts);
    } break;
    case la_object::object_type_e::RATE_LIMITER_SET: {
        auto rate_limiters = object.weak_ptr_static_cast<la_rate_limiter_set_base>();
        status = destroy_rate_limiters(rate_limiters);
    } break;
    case la_object::object_type_e::METER_MARKDOWN_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_meter_markdown_profile_impl>();
        status = destroy_meter_markdown_profile(profile);
    } break;
    case la_object::object_type_e::COPC: {
        auto copc = object.weak_ptr_static_cast<la_copc_base>();
        status = destroy_copc(copc);
    } break;
    case la_object::object_type_e::SECURITY_GROUP_CELL: {
        auto sg_cell = object.weak_ptr_static_cast<la_security_group_cell_base>();
        status = destroy_security_group_cell(sg_cell);
    } break;
    case la_object::object_type_e::PBTS_MAP_PROFILE: {
        auto profile = object.weak_ptr_static_cast<la_pbts_map_profile_impl>();
        status = destroy_pbts_map_profile(profile);
    } break;
    case la_object::object_type_e::PBTS_GROUP: {
        auto group = object.weak_ptr_static_cast<la_pbts_group_impl>();
        status = destroy_pbts_group(group);
    } break;
    case la_object::object_type_e::VRF_REDIRECT_DESTINATION: {
        auto vrf_redirect_dest = object.weak_ptr_static_cast<la_vrf_redirect_destination_impl>();
        status = destroy_vrf_redirect_destination(vrf_redirect_dest);
    } break;
    default:
        status = LA_STATUS_EINVAL;
    }

    return_on_error(status);

    // Most objects call deregister_object (and do the associated cleanup of m_objects[oid] from inside la_*_impl::destroy().
    // This will decrement the use count to 0, and cause the object to be deleted while still inside the destroy() function.
    //
    // Ideally, should have deregister happen centrally outside the objects, but some do it before the last line.
    // Therefore, this requires a finer-grained handling.
    //
    // Yair, 21.4.2020
    deregister_object(object->oid());

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_filter_group(la_filter_group*& out_filter_group)
{
    start_api_call("");
    uint64_t group_index = 0;

    bool allocated = m_index_generators.filter_groups.allocate(group_index);
    if (!allocated) {
        return LA_STATUS_ERESOURCE;
    }

    auto group = std::make_shared<la_filter_group_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(group, oid);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.filter_groups.release(group_index);
        return status;
    }

    status = group->initialize(oid, group_index);

    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.filter_groups.release(group_index);
        deregister_object(oid);
        return_on_error(status);
    }

    m_filter_groups[group_index] = group;
    out_filter_group = group.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_filter_group(const la_filter_group_impl_wptr& filter_group)
{
    if (!of_same_device(filter_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(filter_group)) {
        return LA_STATUS_EBUSY;
    }

    uint64_t id = filter_group->get_id();

    const auto& device_filter_group = m_filter_groups[id];

    if (device_filter_group != filter_group) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = filter_group->destroy();
    return_on_error(status);

    m_index_generators.filter_groups.release(id);
    m_filter_groups[id] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_uint_t
la_device_impl::get_available_filter_groups() const
{
    return m_index_generators.filter_groups.available();
}

la_status
la_device_impl::get_valid_mac_port_configs(la_mac_port::mac_config_vec& out_config_vec) const
{
    return m_device_port_handler->get_valid_configs(out_config_vec);
}

la_status
la_device_impl::create_mac_port(la_slice_id_t slice_id,
                                la_ifg_id_t ifg_id,
                                la_uint_t first_serdes_id,
                                la_uint_t last_serdes_id,
                                la_mac_port::port_speed_e speed,
                                la_mac_port::fc_mode_e fc_mode,
                                la_mac_port::fec_mode_e fec_mode,
                                la_mac_port*& out_mac_port)
{
    start_api_call("slice_id=",
                   slice_id,
                   "ifg_id=",
                   ifg_id,
                   "first_serdes_id=",
                   first_serdes_id,
                   "last_serdes_id=",
                   last_serdes_id,
                   "speed=",
                   speed,
                   "fc_mode=",
                   fc_mode,
                   "fec_mode=",
                   fec_mode);
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    if (last_serdes_id >= serdes_count) {
        return LA_STATUS_EINVAL;
    }
    if (first_serdes_id > last_serdes_id) {
        return LA_STATUS_EINVAL;
    }

    // TODO add verification that the MAC is created only on network-eligible slices/ports
    bool is_lender_ifg_en = is_lender_ifg(slice_id, ifg_id);
    bool is_potentially_lended_port = (first_serdes_id >= IFG_LENDED_SERDES_ID);

    if ((is_lender_ifg_en == true) && (is_potentially_lended_port == true)) {
        return LA_STATUS_EINVAL;
    }

    for (la_uint_t index = first_serdes_id; index <= last_serdes_id; index++) {
        if (m_serdes_inuse[slice_id][ifg_id][index] == true)
            return LA_STATUS_EBUSY;
    }

    auto mac_port = std::make_shared<la_mac_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    status = register_object(mac_port, oid);
    return_on_error(status);
    status = mac_port->initialize_network(oid,
                                          slice_id,
                                          ifg_id,
                                          first_serdes_id,
                                          last_serdes_id - first_serdes_id + 1,
                                          speed,
                                          false /*is_extended*/,
                                          fc_mode,
                                          fc_mode,
                                          fec_mode);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_mac_ports[mac_port->get_location()] = mac_port;
    out_mac_port = mac_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_mac_port(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_uint_t serdes_id, la_mac_port*& out_mac_port) const
{
    start_api_getter_call("slice_id=", slice_id, "ifg_id=", ifg_id, "serdes_id=", serdes_id);

    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    if (serdes_id >= serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_mac_ports.empty()) {
        log_debug(HLD, "%s: no MAC ports have been created yet", __func__);
        return LA_STATUS_ENOTFOUND;
    }

    // Lookup the first element whose key is higher than '{slice_id, ifg_id, serdes_id}'
    auto it = m_mac_ports.upper_bound(la_mac_port_base::location{slice_id, ifg_id, serdes_id});
    if (it == m_mac_ports.begin()) {
        log_debug(HLD, "%s: no MAC port found (%d,%d,%d)", __func__, slice_id, ifg_id, serdes_id);
        return LA_STATUS_ENOTFOUND;
    }

    it = std::prev(it);

    const auto& port = it->second;

    if (port->get_slice() != slice_id || port->get_ifg() != ifg_id) {
        return LA_STATUS_ENOTFOUND;
    }

    la_uint_t first_serdes = port->get_first_serdes_id();
    la_uint_t num_of_serdes = port->get_num_of_serdes();
    if (serdes_id >= first_serdes && serdes_id < first_serdes + num_of_serdes) {
        out_mac_port = port.get();
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
la_device_impl::create_channelized_mac_port(la_slice_id_t slice_id,
                                            la_ifg_id_t ifg_id,
                                            la_uint_t first_serdes_id,
                                            la_uint_t last_serdes_id,
                                            la_mac_port::port_speed_e speed,
                                            la_mac_port::fc_mode_e fc_mode,
                                            la_mac_port::fec_mode_e fec_mode,
                                            la_mac_port*& out_mac_port)
{
    start_api_call("slice_id=",
                   slice_id,
                   "ifg_id=",
                   ifg_id,
                   "first_serdes_id=",
                   first_serdes_id,
                   "last_serdes_id=",
                   last_serdes_id,
                   "speed=",
                   speed,
                   "fc_mode=",
                   fc_mode,
                   "fec_mode=",
                   fec_mode);

    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    if (last_serdes_id >= serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (first_serdes_id > last_serdes_id) {
        return LA_STATUS_EINVAL;
    }

    for (la_uint_t index = first_serdes_id; index <= last_serdes_id; index++) {
        if (m_serdes_inuse[slice_id][ifg_id][index] == true)
            return LA_STATUS_EBUSY;
    }

    // TODO add verification that the MAC is created only on network-eligible slices/ports
    bool is_lender_ifg_en = is_lender_ifg(slice_id, ifg_id);
    bool is_potentially_lended_port = (first_serdes_id >= IFG_LENDED_SERDES_ID);

    if ((is_lender_ifg_en == true) && (is_potentially_lended_port == true)) {
        return LA_STATUS_EINVAL;
    }

    auto mac_port = std::make_shared<la_mac_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    status = register_object(mac_port, oid);
    return_on_error(status);
    status = mac_port->initialize_network(oid,
                                          slice_id,
                                          ifg_id,
                                          first_serdes_id,
                                          last_serdes_id - first_serdes_id + 1,
                                          speed,
                                          true /* is_extended */,
                                          fc_mode,
                                          fc_mode,
                                          fec_mode);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_mac_ports[mac_port->get_location()] = mac_port;
    out_mac_port = mac_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_fabric_mac_port(la_slice_id_t slice_id,
                                       la_ifg_id_t ifg_id,
                                       la_uint_t first_serdes_id,
                                       la_uint_t last_serdes_id,
                                       la_mac_port::port_speed_e speed,
                                       la_mac_port::fc_mode_e fc_mode,
                                       la_mac_port*& out_mac_port)
{
    start_api_call("slice_id=",
                   slice_id,
                   "ifg_id=",
                   ifg_id,
                   "first_serdes_id=",
                   first_serdes_id,
                   "last_serdes_id=",
                   last_serdes_id,
                   "speed=",
                   speed,
                   "fc_mode=",
                   fc_mode);

    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);
    size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
    if (last_serdes_id >= serdes_count) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (first_serdes_id > last_serdes_id) {
        return LA_STATUS_EINVAL;
    }
    if (speed == la_mac_port::port_speed_e::E_800G) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    device_port_handler_base::fabric_data fabric_data;
    m_device_port_handler->get_fabric_data(fabric_data);
    if (fabric_data.speed != speed) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t port_num;
    status = m_ifg_handlers[slice_id][ifg_id]->get_fabric_port_number(first_serdes_id, port_num);
    return_on_error(status);
    if (port_num == INVALID_FABRIC_PORT_NUM) {
        log_err(
            HLD, "%s: slice=%d, ifg_id=%d, serdes=%d cannot be used for fabric port.", __func__, slice_id, ifg_id, first_serdes_id);
        return LA_STATUS_EINVAL;
    }

    for (la_uint_t index = first_serdes_id; index <= last_serdes_id; index++) {
        if (m_serdes_inuse[slice_id][ifg_id][index] == true) {
            log_err(HLD, "%s: slice=%d, ifg_id=%d, serdes=%d is already in use", __func__, slice_id, ifg_id, index);
            return LA_STATUS_EBUSY;
        }
    }

    if (!m_fabric_ports_initialized) {
        status = initialize_fabric_ifgb(fc_mode);
        return_on_error(status);

    } else if (fc_mode != m_fabric_fc_mode) {
        log_err(HLD,
                "Only a single FC mode is supported in runtime for all fabric ports; current FC mode is %s, provided FC mode is %s",
                silicon_one::to_string(m_fabric_fc_mode).c_str(),
                silicon_one::to_string(fc_mode).c_str());
        return LA_STATUS_EINVAL;
    }

    bool is_fabric_port_supporting_serdes_en = is_fabric_port_supporting_serdes(slice_id, ifg_id, first_serdes_id);

    if (is_fabric_port_supporting_serdes_en == false) {
        log_err(HLD, "Bad {slice=%d, ifg=%d, serdes=%d} for a fabric port mode", slice_id, ifg_id, first_serdes_id);
        return LA_STATUS_EINVAL;
    }

    auto mac_port = std::make_shared<la_mac_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    status = register_object(mac_port, oid);
    return_on_error(status);
    status
        = mac_port->initialize_fabric(oid, slice_id, ifg_id, first_serdes_id, last_serdes_id - first_serdes_id + 1, speed, fc_mode);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_reconnect_handler->add_mac_port(mac_port);
    m_mac_ports[mac_port->get_location()] = mac_port;
    out_mac_port = mac_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_mac_port(const la_mac_port_base_wptr& port)
{
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = port->destroy();
    return_on_error(status);

    m_reconnect_handler->remove_mac_port(port);
    m_mac_ports.erase(port->get_location());

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_fabric_port(la_mac_port* fabric_mac_port, la_fabric_port*& out_fabric_port)
{
    start_api_call("fabric_mac_port=", fabric_mac_port);

    // Check arguments
    if (fabric_mac_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(fabric_mac_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(fabric_mac_port)) {
        return LA_STATUS_EBUSY;
    }

    auto fabric_port = std::make_shared<la_fabric_port_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(fabric_port, oid);
    return_on_error(status);

    status = fabric_port->initialize(oid, fabric_mac_port);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    status = m_reconnect_handler->add_fabric_port(fabric_port);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    la_uint_t fabric_port_num;
    status = fabric_port->get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    m_fabric_ports[fabric_port_num] = fabric_port;
    out_fabric_port = fabric_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_fabric_port(const la_fabric_port_impl_wptr& fabric_port)
{
    if (fabric_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(fabric_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_uint_t fabric_port_num;
    la_status status = fabric_port->get_fabric_port_num_in_device(fabric_port_num);
    return_on_error(status);

    status = fabric_port->destroy();
    return_on_error(status);

    m_reconnect_handler->remove_fabric_port(fabric_port);

    m_fabric_ports[fabric_port_num] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_pci_port(la_slice_id_t slice_id, la_ifg_id_t ifg_id, bool skip_kernel_driver, la_pci_port*& out_pci_port)
{
    start_api_call("slice_id=", slice_id, "ifg_id=", ifg_id, "skip_kernel_driver=", skip_kernel_driver);

    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    la_uint_t ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(slice_id, ifg_id);

    if (m_pci_ports[ifg_idx] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto pci_port = std::make_shared<la_pci_port_gibraltar>(shared_from_this(), skip_kernel_driver);
    la_object_id_t oid;
    status = register_object(pci_port, oid);
    return_on_error(status);
    status = pci_port->initialize(oid, slice_id, ifg_id);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_pci_ports[ifg_idx] = pci_port;
    out_pci_port = pci_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_pci_port(const la_pci_port_base_wptr& port)
{
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_slice_id_t slice_id = port->get_slice();
    la_ifg_id_t ifg_id = port->get_ifg();
    la_uint_t ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(slice_id, ifg_id);

    la_status status = port->destroy();
    return_on_error(status);

    m_pci_ports[ifg_idx] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_recycle_port(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_recycle_port*& out_recycle_port)
{
    start_api_call("slice_id=", slice_id, "ifg_id=", ifg_id);

    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    la_uint_t ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(slice_id, ifg_id);

    if (m_recycle_ports[ifg_idx] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto recycle_port = std::make_shared<la_recycle_port_gibraltar>(shared_from_this());

    la_object_id_t oid;
    status = register_object(recycle_port, oid);
    return_on_error(status);

    status = recycle_port->initialize(oid, slice_id, ifg_id);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_recycle_ports[ifg_idx] = recycle_port;
    out_recycle_port = recycle_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_recycle_port(const la_recycle_port_base_wptr& recycle_port)
{
    if (recycle_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(recycle_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_slice_id_t slice_id = recycle_port->get_slice();
    la_ifg_id_t ifg_id = recycle_port->get_ifg();
    la_uint_t ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(slice_id, ifg_id);

    la_status status = recycle_port->destroy();
    return_on_error(status);

    m_recycle_ports[ifg_idx] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_system_port(la_system_port_gid_t system_port_gid,
                                   la_mac_port* mac_port,
                                   la_voq_set* voq_set,
                                   const la_tc_profile* tc_profile,
                                   la_system_port*& out_system_port)
{
    start_api_call("system_port_gid=", system_port_gid, "mac_port=", mac_port, "voq_set=", voq_set, "profile=", tc_profile);

    if (!is_dsp_in_range(system_port_gid)) {
        return LA_STATUS_EINVAL;
    }

    if (m_system_ports[system_port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto system_port = std::make_shared<la_system_port_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(system_port, oid);
    return_on_error(status);

    status = system_port->initialize(oid, get_sptr(mac_port), system_port_gid, get_sptr(voq_set), get_sptr(tc_profile));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_system_ports[system_port_gid] = system_port;
    out_system_port = system_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_system_port(la_system_port_gid_t system_port_gid,
                                   la_port_extender_vid_t port_extender_vid,
                                   la_mac_port* mac_port,
                                   la_voq_set* voq_set,
                                   const la_tc_profile* tc_profile,
                                   la_system_port*& out_system_port)
{

    start_api_call("system_port_gid=",
                   system_port_gid,
                   "port_extender_vid=",
                   port_extender_vid,
                   "mac_port=",
                   mac_port,
                   "voq_set=",
                   voq_set,
                   "profile=",
                   tc_profile);

    if (!is_dsp_in_range(system_port_gid)) {
        return LA_STATUS_EINVAL;
    }

    if (m_system_ports[system_port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto system_port = std::make_shared<la_system_port_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(system_port, oid);
    return_on_error(status);

    status = system_port->initialize(oid, get_sptr(mac_port), system_port_gid, get_sptr(voq_set), get_sptr(tc_profile));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_system_ports[system_port_gid] = system_port;
    out_system_port = system_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_system_port(la_system_port_gid_t system_port_gid,
                                   la_recycle_port* recycle_port_in,
                                   la_voq_set* voq_set,
                                   const la_tc_profile* tc_profile,
                                   la_system_port*& out_system_port)
{
    start_api_call(
        "system_port_gid=", system_port_gid, "recycle_port=", recycle_port_in, "voq_set=", voq_set, "profile=", tc_profile);
    la_recycle_port_base* recycle_port = static_cast<la_recycle_port_base*>(recycle_port_in);

    if (!is_dsp_in_range(system_port_gid)) {
        return LA_STATUS_EINVAL;
    }

    if (m_system_ports[system_port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto system_port = std::make_shared<la_system_port_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(system_port, oid);
    return_on_error(status);

    status = system_port->initialize(oid, get_sptr(recycle_port), system_port_gid, get_sptr(voq_set), get_sptr(tc_profile));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_system_ports[system_port_gid] = system_port;
    size_t ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(recycle_port->get_slice(), recycle_port->get_ifg());
    m_rcy_system_ports[ifg_idx] = system_port;
    out_system_port = system_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_system_port(la_system_port_gid_t system_port_gid,
                                   la_pci_port* pci_port,
                                   la_voq_set* voq_set,
                                   const la_tc_profile* tc_profile,
                                   la_system_port*& out_system_port)
{
    start_api_call("system_port_gid=", system_port_gid, "pci_port=", pci_port, "voq_set=", voq_set, "profile=", tc_profile);

    if (!is_dsp_in_range(system_port_gid)) {
        return LA_STATUS_EINVAL;
    }

    if (m_system_ports[system_port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto system_port = std::make_shared<la_system_port_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(system_port, oid);
    return_on_error(status);

    status = system_port->initialize(oid, get_sptr(pci_port), system_port_gid, get_sptr(voq_set), get_sptr(tc_profile));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_system_ports[system_port_gid] = system_port;
    out_system_port = system_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_system_port(la_system_port_gid_t system_port_gid,
                                   la_remote_port* remote_port,
                                   la_voq_set* voq_set,
                                   const la_tc_profile* tc_profile,
                                   la_system_port*& out_system_port)
{
    start_api_call("system_port_gid=", system_port_gid, "remote_port=", remote_port, "voq_set=", voq_set, "profile=", tc_profile);

    if (!is_dsp_in_range(system_port_gid)) {
        return LA_STATUS_EINVAL;
    }

    if (m_system_ports[system_port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto system_port = std::make_shared<la_system_port_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(system_port, oid);
    return_on_error(status);

    status = system_port->initialize(oid, get_sptr(remote_port), system_port_gid, get_sptr(voq_set), get_sptr(tc_profile));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_system_ports[system_port_gid] = system_port;
    out_system_port = system_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_system_port(const la_system_port_base_wptr& system_port)
{
    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(system_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_system_port_gid_t system_port_gid = system_port->get_gid();

    size_t ifg_idx = (size_t)-1;
    if (system_port->get_port_type() == la_system_port_base::port_type_e::RECYCLE) {
        ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(system_port->get_slice(), system_port->get_ifg());
    }

    la_status status = system_port->destroy();
    return_on_error(status);

    m_system_ports[system_port_gid] = nullptr;
    if (ifg_idx != (size_t)-1) {
        m_rcy_system_ports[ifg_idx] = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_spa_port(la_spa_port_gid_t spa_port_gid, la_spa_port*& out_spa_port)
{
    start_api_call("spa_port_gid=", spa_port_gid);
    if (spa_port_gid >= MAX_SPA_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_spa_ports[spa_port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto spa_port = std::make_shared<la_spa_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(spa_port, oid);
    return_on_error(status);
    status = spa_port->initialize(oid, spa_port_gid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_spa_ports[spa_port_gid] = spa_port;
    out_spa_port = spa_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_spa_port(const la_spa_port_base_wptr& spa_port)
{
    if (spa_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(spa_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_spa_port_gid_t spa_port_gid = spa_port->get_gid();

    la_status status = spa_port->destroy();
    return_on_error(status);

    m_spa_ports[spa_port_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_lsr()
{
    // Create and initialize L3 for-us destination
    auto lsr = std::make_shared<la_lsr_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(lsr, oid);
    return_on_error(status);

    status = lsr->initialize(oid);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_lsr = lsr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_forus_destination()
{
    // Create and initialize L3 for-us destination
    auto forus_destination = std::make_shared<la_forus_destination_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(forus_destination, oid);
    return_on_error(status);
    status = forus_destination->initialize(oid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // Update mappings
    la_l3_destination_gid_t l3_dest_gid = get_l3_destination_gid(forus_destination, true /* is_lpm_destination */);
    m_l3_destinations[l3_dest_gid] = forus_destination;
    m_forus_destination = forus_destination;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_flow_cache_handler()
{
    auto flow_cache_handler_impl = std::make_shared<la_flow_cache_handler_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(flow_cache_handler_impl, oid);
    return_on_error(status);
    status = flow_cache_handler_impl->initialize(oid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_flow_cache_handler = flow_cache_handler_impl;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_punt_inject_port(la_system_port* system_port,
                                        la_mac_addr_t mac_addr,
                                        la_punt_inject_port*& out_punt_inject_port)
{
    start_api_call("system_port=", system_port, "mac_addr=", mac_addr);
    // Check arguments
    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(system_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(system_port)) {
        return LA_STATUS_EBUSY;
    }

    // Create and initialize punt/inject port
    la_system_port_base* system_port_base = static_cast<la_system_port_base*>(system_port);

    auto punt_inject_port = std::make_shared<la_punt_inject_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(punt_inject_port, oid);
    return_on_error(status);
    status = punt_inject_port->initialize(oid, system_port_base, mac_addr);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // Update mappings
    out_punt_inject_port = punt_inject_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_punt_inject_port(const la_punt_inject_port_base_wptr& pi_port)
{
    // Check arguments
    if (pi_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(pi_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(pi_port)) {
        return LA_STATUS_EBUSY;
    }

    // retrieve implementation objects
    la_status status = pi_port->destroy();

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l2_punt_destination(la_l2_punt_destination_gid_t gid,
                                           la_punt_inject_port* pi_port,
                                           la_mac_addr_t mac_addr,
                                           la_vlan_tag_tci_t vlan_tag,
                                           la_l2_punt_destination*& out_punt_dest)
{
    start_api_call("gid=", gid, "pi_port=", pi_port, "mac_addr=", mac_addr, "vlan_tag=", vlan_tag);

    // Check arguments
    if (gid >= MAX_L2_PUNT_DESTINATION_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l2_punt_destinations[gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (pi_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(pi_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Create and initialize L2 punt/inject destination
    la_punt_inject_port_base* pi_port_impl = static_cast<la_punt_inject_port_base*>(pi_port);

    auto l2_punt_inject_destination = std::make_shared<la_l2_punt_destination_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(l2_punt_inject_destination, oid);
    return_on_error(status);
    status = l2_punt_inject_destination->initialize(oid, gid, pi_port_impl, mac_addr, vlan_tag);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // Update mappings
    m_l2_punt_destinations[gid] = l2_punt_inject_destination;
    out_punt_dest = l2_punt_inject_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l2_punt_destination(la_l2_punt_destination_gid_t gid,
                                           la_stack_port* stack_port,
                                           la_mac_addr_t mac_addr,
                                           la_vlan_tag_tci_t vlan_tag,
                                           la_l2_punt_destination*& out_punt_dest)
{
    start_api_call("gid=", gid, "stack_port=", stack_port, "mac_addr=", mac_addr, "vlan_tag=", vlan_tag);

    // Check arguments
    if (gid >= MAX_L2_PUNT_DESTINATION_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l2_punt_destinations[gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (stack_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (stack_port->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_stack_port_base* stack_port_base = static_cast<la_stack_port_base*>(stack_port);

    auto l2_punt_inject_destination = std::make_shared<la_l2_punt_destination_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(l2_punt_inject_destination, oid);
    return_on_error(status);

    status = l2_punt_inject_destination->initialize(oid, gid, stack_port_base, mac_addr, vlan_tag);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    // Update mappings
    m_l2_punt_destinations[gid] = l2_punt_inject_destination;
    out_punt_dest = l2_punt_inject_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_l2_punt_destination(const la_l2_punt_destination_impl_wptr& punt_dest)
{
    // Check arguments
    if (punt_dest == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(punt_dest, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(punt_dest)) {
        return LA_STATUS_EBUSY;
    }

    la_l2_punt_destination_gid_t gid = punt_dest->get_gid();
    auto l2_punt_destination = m_l2_punt_destinations[gid];

    if (l2_punt_destination != punt_dest) {
        return LA_STATUS_EUNKNOWN;
    }

    // retrieve implementation objects
    la_status status = punt_dest->destroy();

    return_on_error(status);

    m_l2_punt_destinations[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_npu_host_port(la_remote_device* remote_device,
                                     la_system_port_gid_t system_port_gid,
                                     la_voq_set* voq_set,
                                     const la_tc_profile* tc_profile,
                                     la_npu_host_port*& out_npu_host_port)
{
    start_api_call(
        "remote_device=", remote_device, "system_port_gid=", system_port_gid, "voq_set=", voq_set, "tc_profile=", tc_profile);

    if (voq_set == nullptr || tc_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(voq_set, this) || !of_same_device(tc_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto npu_host_port = std::make_shared<la_npu_host_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(npu_host_port, oid);
    return_on_error(status);

    status = npu_host_port->initialize(oid, remote_device, system_port_gid, voq_set, tc_profile);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_npu_host_port = npu_host_port.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_npu_host_port(const la_npu_host_port_base_wptr& port)
{
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = port->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_npu_host_destination(la_npu_host_port* npu_host_port, la_npu_host_destination*& out_npu_host_dest)
{
    start_api_call("npu_host_port=", npu_host_port);

    // Check arguments
    if (npu_host_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(npu_host_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto npu_host_destination = std::make_shared<la_npu_host_destination_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(npu_host_destination, oid);
    return_on_error(status);
    status = npu_host_destination->initialize(oid, npu_host_port);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // Update mappings
    out_npu_host_dest = npu_host_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_npu_host_destination(const la_npu_host_destination_impl_wptr& npu_host_dest)
{
    // Check arguments
    if (npu_host_dest == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(npu_host_dest, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(npu_host_dest)) {
        return LA_STATUS_EBUSY;
    }

    // retrieve implementation objects
    la_status status = npu_host_dest->destroy();

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_erspan_mirror_command(la_mirror_gid_t mirror_gid,
                                             la_erspan_mirror_command::ipv4_encapsulation encap_data,
                                             la_uint_t voq_offset,
                                             const la_system_port* dsp,
                                             float probability,
                                             la_erspan_mirror_command*& out_mirror_cmd)
{
    start_api_call(
        "mirror_gid=", mirror_gid, "encap_data=", encap_data, "voq_offset=", voq_offset, "dsp=", dsp, "probability=", probability);

    // Check arguments
    if (mirror_gid >= MAX_MIRROR_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_mirror_commands[mirror_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if ((encap_data.type != la_erspan_mirror_command::type_e::ERSPAN)
        && (encap_data.type != la_erspan_mirror_command::type_e::SFLOW_TUNNEL)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto erspan_mirror_command = std::make_shared<la_erspan_mirror_command_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(erspan_mirror_command, oid);
    return_on_error(status);

    if (encap_data.type == la_erspan_mirror_command::type_e::ERSPAN) {
        status = erspan_mirror_command->initialize(oid,
                                                   la_erspan_mirror_command::type_e::ERSPAN,
                                                   mirror_gid,
                                                   encap_data.session.session_id,
                                                   encap_data.mac_addr,
                                                   encap_data.source_mac_addr,
                                                   encap_data.vlan_tag,
                                                   encap_data.ipv4.tunnel_dest_addr,
                                                   encap_data.ipv4.tunnel_source_addr,
                                                   encap_data.ipv4.ttl,
                                                   encap_data.ipv4.dscp,
                                                   voq_offset,
                                                   dsp,
                                                   probability,
                                                   la_ip_version_e::IPV4);
    } else {
        status = erspan_mirror_command->initialize(oid,
                                                   la_erspan_mirror_command::type_e::SFLOW_TUNNEL,
                                                   mirror_gid,
                                                   encap_data.mac_addr,
                                                   encap_data.source_mac_addr,
                                                   encap_data.vlan_tag,
                                                   encap_data.ipv4.tunnel_dest_addr,
                                                   encap_data.ipv4.tunnel_source_addr,
                                                   encap_data.ipv4.ttl,
                                                   encap_data.ipv4.dscp,
                                                   encap_data.session.sflow.sport,
                                                   encap_data.session.sflow.dport,
                                                   voq_offset,
                                                   dsp,
                                                   probability,
                                                   la_ip_version_e::IPV4);
    }

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    // Update mappings
    out_mirror_cmd = erspan_mirror_command.get();

    m_mirror_commands[mirror_gid] = erspan_mirror_command;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_erspan_mirror_command(la_mirror_gid_t mirror_gid,
                                             la_erspan_mirror_command::ipv6_encapsulation encap_data,
                                             la_uint_t voq_offset,
                                             const la_system_port* dsp,
                                             float probability,
                                             la_erspan_mirror_command*& out_mirror_cmd)
{
    start_api_call(
        "mirror_gid=", mirror_gid, "encap_data=", encap_data, "voq_offset=", voq_offset, "dsp=", dsp, "probability=", probability);

    // Check arguments
    if (mirror_gid >= MAX_MIRROR_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_mirror_commands[mirror_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if ((encap_data.type != la_erspan_mirror_command::type_e::ERSPAN)
        && (encap_data.type != la_erspan_mirror_command::type_e::SFLOW_TUNNEL)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto erspan_mirror_command = std::make_shared<la_erspan_mirror_command_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(erspan_mirror_command, oid);
    return_on_error(status);

    if (encap_data.type == la_erspan_mirror_command::type_e::ERSPAN) {
        status = erspan_mirror_command->initialize(oid,
                                                   la_erspan_mirror_command::type_e::ERSPAN,
                                                   mirror_gid,
                                                   encap_data.session.session_id,
                                                   encap_data.mac_addr,
                                                   encap_data.source_mac_addr,
                                                   encap_data.vlan_tag,
                                                   encap_data.ipv6.tunnel_dest_addr,
                                                   encap_data.ipv6.tunnel_source_addr,
                                                   encap_data.ipv6.ttl,
                                                   encap_data.ipv6.dscp,
                                                   voq_offset,
                                                   dsp,
                                                   probability,
                                                   la_ip_version_e::IPV6);
    } else {
        status = erspan_mirror_command->initialize(oid,
                                                   la_erspan_mirror_command::type_e::SFLOW_TUNNEL,
                                                   mirror_gid,
                                                   encap_data.mac_addr,
                                                   encap_data.source_mac_addr,
                                                   encap_data.vlan_tag,
                                                   encap_data.ipv6.tunnel_dest_addr,
                                                   encap_data.ipv6.tunnel_source_addr,
                                                   encap_data.ipv6.ttl,
                                                   encap_data.ipv6.dscp,
                                                   encap_data.session.sflow.sport,
                                                   encap_data.session.sflow.dport,
                                                   voq_offset,
                                                   dsp,
                                                   probability,
                                                   la_ip_version_e::IPV6);
    }

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    // Update mappings
    out_mirror_cmd = erspan_mirror_command.get();

    m_mirror_commands[mirror_gid] = erspan_mirror_command;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_erspan_mirror_command(const la_erspan_mirror_command_base_wptr& mirror_cmd)
{
    // Check arguments
    if (mirror_cmd == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(mirror_cmd, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(mirror_cmd)) {
        return LA_STATUS_EBUSY;
    }

    la_mirror_gid_t mirror_gid = mirror_cmd->get_gid();

    // retrieve implementation objects
    la_status status = mirror_cmd->destroy();
    return_on_error(status);

    m_mirror_commands[mirror_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_create_l2_mirror_command(la_mirror_gid_t mirror_gid,
                                            la_punt_inject_port* pi_port,
                                            la_system_port* system_port,
                                            la_mac_addr_t mac_addr,
                                            la_vlan_tag_tci_t vlan_tag,
                                            la_uint_t voq_offset,
                                            const la_meter_set* meter,
                                            float probability,
                                            la_l2_mirror_command*& out_mirror_cmd)
{
    // Check arguments
    if (((pi_port == nullptr) && (system_port == nullptr)) || ((pi_port != nullptr) && (system_port != nullptr))) {
        return LA_STATUS_EINVAL;
    }

    if (mirror_gid >= MAX_MIRROR_GID) {
        return LA_STATUS_EINVAL;
    }

    // Check the offset value against the Number of OQs.
    if (voq_offset >= NUM_OQ_PER_PIF) {
        return LA_STATUS_EINVAL;
    }

    if (m_mirror_commands[mirror_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if ((pi_port != nullptr) && (pi_port->get_device() != this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }
    if ((system_port != nullptr) && (system_port->get_device() != this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Create and initialize L2 punt/inject destination
    auto l2_mirror_command = std::make_shared<la_l2_mirror_command_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(l2_mirror_command, oid);
    return_on_error(status);

    const auto& pi_port_sp = get_sptr<la_punt_inject_port_base>(pi_port);
    const auto& system_port_sp = get_sptr<la_system_port_base>(system_port);
    const auto& meter_sp = get_sptr(meter);
    const auto& non_const_meter_sp = std::const_pointer_cast<la_meter_set>(meter_sp);

    status = l2_mirror_command->initialize(
        oid, mirror_gid, pi_port_sp, system_port_sp, mac_addr, vlan_tag, voq_offset, non_const_meter_sp, probability);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // Update mappings
    out_mirror_cmd = l2_mirror_command.get();

    m_mirror_commands[mirror_gid] = l2_mirror_command;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l2_mirror_command(la_mirror_gid_t mirror_gid,
                                         la_punt_inject_port* pi_port,
                                         la_mac_addr_t mac_addr,
                                         la_vlan_tag_tci_t vlan_tag,
                                         la_uint_t voq_offset,
                                         const la_meter_set* meter,
                                         float probability,
                                         la_l2_mirror_command*& out_mirror_cmd)
{
    start_api_call("mirror_gid=",
                   mirror_gid,
                   "pi_port=",
                   pi_port,
                   "mac_addr=",
                   mac_addr,
                   "vlan_tag=",
                   vlan_tag,
                   "voq_offset=",
                   voq_offset,
                   "meter=",
                   meter,
                   "probability=",
                   probability);

    return do_create_l2_mirror_command(
        mirror_gid, pi_port, nullptr, mac_addr, vlan_tag, voq_offset, meter, probability, out_mirror_cmd);
}

la_status
la_device_impl::create_l2_mirror_command(la_mirror_gid_t mirror_gid,
                                         la_ethernet_port* eth_port,
                                         la_system_port* system_port,
                                         la_uint_t voq_offset,
                                         float probability,
                                         la_l2_mirror_command*& out_mirror_cmd)
{

    start_api_call("mirror_gid=",
                   mirror_gid,
                   "eth_port=",
                   eth_port,
                   "system_port=",
                   system_port,
                   "voq_offset=",
                   voq_offset,
                   "probability=",
                   probability);

    if (eth_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (mirror_gid >= MAX_MIRROR_GID) {
        return LA_STATUS_EINVAL;
    }

    // Check the offset value against the Number of OQs.
    if (voq_offset >= NUM_OQ_PER_PIF) {
        return LA_STATUS_EINVAL;
    }

    if (m_mirror_commands[mirror_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if (!of_same_device(eth_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Create and initialize L2 ethernet destination
    la_ethernet_port_gibraltar* eth_port_impl = static_cast<la_ethernet_port_gibraltar*>(eth_port);
    la_system_port_base* system_port_base = static_cast<la_system_port_base*>(system_port);

    auto l2_mirror_command = std::make_shared<la_l2_mirror_command_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(l2_mirror_command, oid);
    return_on_error(status);
    status = l2_mirror_command->initialize(
        oid, mirror_gid, get_sptr(eth_port_impl), get_sptr(system_port_base), voq_offset, probability);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_mirror_cmd = l2_mirror_command.get();

    // Update mappings
    m_mirror_commands[mirror_gid] = l2_mirror_command;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_mc_lpts_mirror_command(la_mirror_gid_t mirror_gid,
                                              la_system_port* system_port,
                                              la_l2_mirror_command*& out_mirror_cmd)
{
    start_api_call("mirror_gid=", mirror_gid, "system_port=", system_port);

    float probability = 1.0;
    la_mac_addr_t dummy_mac_addr;
    la_vlan_tag_tci_t dummy_vlan_tag;

    return do_create_l2_mirror_command(
        mirror_gid, nullptr, system_port, dummy_mac_addr, dummy_vlan_tag, 0, nullptr, probability, out_mirror_cmd);
}

la_status
la_device_impl::create_pfc_mirror_command(la_mirror_gid_t mirror_gid,
                                          const la_punt_inject_port_base_wptr& pi_port,
                                          la_uint_t voq_offset,
                                          float probability,
                                          la_l2_mirror_command_wptr& out_mirror_cmd)
{
    // Check arguments
    if (pi_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (mirror_gid >= MAX_MIRROR_GID) {
        return LA_STATUS_EINVAL;
    }

    // Check the offset value against the Number of OQs.
    if (voq_offset >= NUM_OQ_PER_PIF) {
        return LA_STATUS_EINVAL;
    }

    if (m_mirror_commands[mirror_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if (!of_same_device(pi_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Create and initialize recycle port destination
    auto l2_mirror_command = std::make_shared<la_l2_mirror_command_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(l2_mirror_command, oid);
    return_on_error(status);
    status = l2_mirror_command->initialize(oid, mirror_gid, pi_port, voq_offset, probability);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // PFC mirror requires the mirrored packet to be sent to the same destination.
    status = l2_mirror_command->set_mirror_to_dest(true);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(l2_mirror_command->oid());
        return status;
    }

    // PFC mirrored packets need to be truncated to 128B to reduce the bandwidth.
    status = l2_mirror_command->set_truncate(true);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(l2_mirror_command->oid());
        return status;
    }

    // Update mappings
    out_mirror_cmd = l2_mirror_command;

    m_mirror_commands[mirror_gid] = l2_mirror_command;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_l2_mirror_command(const la_l2_mirror_command_base_wptr& mirror_cmd)
{
    // Check arguments
    if (mirror_cmd == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(mirror_cmd, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(mirror_cmd)) {
        return LA_STATUS_EBUSY;
    }

    la_mirror_gid_t mirror_gid = mirror_cmd->get_gid();

    // retrieve implementation objects
    la_status status = mirror_cmd->destroy();
    return_on_error(status);

    m_mirror_commands[mirror_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

static bool
is_oam_trap(la_event_e trap)
{
    return ((trap >= LA_EVENT_OAMP_FIRST) && (trap <= LA_EVENT_OAMP_LAST));
}

la_status
la_device_impl::do_get_trap_configuration(la_event_e trap,
                                          la_trap_priority_t& out_priority,
                                          la_counter_or_meter_set_wptr& out_counter_or_meter,
                                          la_punt_destination_wcptr& out_destination,
                                          bool& out_skip_inject_up_packets,
                                          bool& out_skip_p2p_packets,
                                          bool& out_overwrite_phb,
                                          la_traffic_class_t& out_tc)
{
    if (trap > LA_EVENT_L2_LPTS_LAST) {
        return LA_STATUS_EINVAL;
    }

    for (auto& trap_cfg : m_trap_entries) {
        if (trap_cfg.trap == trap) {
            out_priority = trap_cfg.priority;
            out_counter_or_meter = trap_cfg.counter_or_meter;
            out_destination = trap_cfg.punt_dest;
            out_skip_inject_up_packets = trap_cfg.skip_inject_up_packets;
            out_skip_p2p_packets = trap_cfg.skip_p2p_packets;
            out_overwrite_phb = trap_cfg.overwrite_phb;
            out_tc = trap_cfg.tc;
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
la_device_impl::configure_oamp_punt_eth_hdr_table(const la_punt_destination_wcptr& destination,
                                                  profile_allocator<oam_encap_info_t>::profile_ptr& oam_encap)
{
    la_status status;
    la_mac_addr_t da_addr;
    la_mac_addr_t sa_addr;
    la_vlan_tag_tci_t vlan_tag;

    if (!destination) {
        return LA_STATUS_EINVAL;
    }

    if (destination->type() != object_type_e::L2_PUNT_DESTINATION) {
        return LA_STATUS_SUCCESS;
    }

    const auto& punt_dest_impl = destination.weak_ptr_static_cast<const la_l2_punt_destination_impl>();
    punt_dest_impl->get_mac(da_addr);
    punt_dest_impl->get_vlan_tag(vlan_tag);

    auto inject_port = punt_dest_impl->get_punt_inject_port();
    if (!inject_port) {
        return LA_STATUS_EINVAL;
    }

    inject_port->get_mac(sa_addr);

    oam_encap_info_t oam_encap_info;

    oam_encap_info.da_addr = da_addr;
    oam_encap_info.sa_addr = sa_addr;
    oam_encap_info.vlan_tag.raw = vlan_tag.raw;

    status = m_profile_allocators.oam_punt_encap->reallocate(oam_encap, oam_encap_info);
    return_on_error(status, HLD, ERROR, "Out of oam encap profiles");
    la_uint_t id = oam_encap->id();

    {
        npl_oamp_redirect_punt_eth_hdr_1_table_t::key_type k{};
        npl_oamp_redirect_punt_eth_hdr_1_table_t::value_type v{};
        npl_oamp_redirect_punt_eth_hdr_1_table_t::entry_pointer_type e = nullptr;

        k.encap_selector = id;
        // Set the higher 32b of the DA
        v.payloads.set_inject_eth.da = (da_addr.flat >> 16) & 0xffffffff;

        status = m_tables.oamp_redirect_punt_eth_hdr_1_table->set(k, v, e);
        return_on_error(status);
    }

    {
        npl_oamp_redirect_punt_eth_hdr_2_table_t::key_type k{};
        npl_oamp_redirect_punt_eth_hdr_2_table_t::value_type v{};
        npl_oamp_redirect_punt_eth_hdr_2_table_t::entry_pointer_type e = nullptr;

        k.encap_selector = id;
        // Set the lower 16b of the da and upper 16b of the sa
        v.payloads.set_inject_eth.da = da_addr.word[0];
        v.payloads.set_inject_eth.sa = sa_addr.word[2];

        status = m_tables.oamp_redirect_punt_eth_hdr_2_table->set(k, v, e);
        return_on_error(status);
    }

    {
        npl_oamp_redirect_punt_eth_hdr_3_table_t::key_type k{};
        npl_oamp_redirect_punt_eth_hdr_3_table_t::value_type v{};
        npl_oamp_redirect_punt_eth_hdr_3_table_t::entry_pointer_type e = nullptr;

        k.encap_selector = id;
        // Set the lower 32b of the sa
        v.payloads.set_inject_eth.sa = sa_addr.flat & 0xffffffff;

        status = m_tables.oamp_redirect_punt_eth_hdr_3_table->set(k, v, e);
        return_on_error(status);
    }

    {
        npl_oamp_redirect_punt_eth_hdr_4_table_t::key_type k{};
        npl_oamp_redirect_punt_eth_hdr_4_table_t::value_type v{};
        npl_oamp_redirect_punt_eth_hdr_4_table_t::entry_pointer_type e = nullptr;

        k.encap_selector = id;
        // Set the vid
        v.payloads.set_inject_eth.dei_vid = (vlan_tag.fields.pcp << 13 | vlan_tag.fields.dei << 12 | vlan_tag.fields.vid);

        status = m_tables.oamp_redirect_punt_eth_hdr_4_table->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_trap_configuration_for_npu_host(la_event_e trap,
                                                    la_trap_priority_t priority,
                                                    const la_counter_or_meter_set_wptr& counter_or_meter,
                                                    const la_punt_destination_wcptr& destination,
                                                    la_traffic_class_t tc)
{
    la_uint_t redirect_code = get_drop_redirect_destination(trap);
    la_uint_t encap_ptr = 0;
    la_status status;

    destination_id sp_destination = get_actual_destination_id(RX_NOT_CNT_DROP_DSP);
    if (destination != nullptr) {
        sp_destination = get_destination_id(destination, RESOLUTION_STEP_FIRST);
    }

    // Check if the trap already exists. Overwrite existing entry.
    size_t existing_entry_idx = 0;
    bool found_trap = false;
    for (; existing_entry_idx < m_trap_entries.size(); existing_entry_idx++) {
        if (m_trap_entries[existing_entry_idx].trap == trap) {
            found_trap = true;
            break;
        }
    }

    // If exists, remove dependency of previous punt_dest
    if ((found_trap) && (m_trap_entries[existing_entry_idx].punt_dest != nullptr)) {
        remove_object_dependency(m_trap_entries[existing_entry_idx].punt_dest, this);
        m_trap_entries[existing_entry_idx].oam_encap.reset();
    }

    // Prepare the value to update in m_trap_entries.
    // Note that priority is not used for npu host traps but is saved
    // only to be returned in general traps APIs.
    profile_allocator<oam_encap_info_t>::profile_ptr oam_encap;
    if (destination != nullptr) {
        status = configure_oamp_punt_eth_hdr_table(destination, oam_encap);
        return_on_error(status);

        encap_ptr = oam_encap->id();
    }

    la_trap_config_entry oam_trap_cfg = {.trap = trap,
                                         .priority = priority,
                                         .counter_or_meter = counter_or_meter,
                                         .punt_dest = destination,
                                         .skip_inject_up_packets = false,
                                         .skip_p2p_packets = false,
                                         .overwrite_phb = true,
                                         .tc = tc,
                                         .oam_encap = oam_encap};

    status = configure_oamp_redirect_code(redirect_code, counter_or_meter, sp_destination, tc, encap_ptr);
    return_on_error(status);

    if (found_trap) {
        m_trap_entries[existing_entry_idx] = oam_trap_cfg;
    } else {
        m_trap_entries.push_back(oam_trap_cfg);
    }

    // Update object dependencies
    if (destination != nullptr) {
        add_object_dependency(destination, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_trap_configuration(la_event_e trap,
                                       la_trap_priority_t& out_priority,
                                       la_counter_or_meter_set*& out_counter_or_meter,
                                       const la_punt_destination*& out_destination,
                                       bool& out_skip_inject_up_packets,
                                       bool& out_skip_p2p_packets,
                                       bool& out_overwrite_phb,
                                       la_traffic_class_t& out_tc)
{
    start_api_getter_call();

    la_punt_destination_wcptr punt_dest;
    la_counter_or_meter_set_wptr counter_or_meter;
    auto status = do_get_trap_configuration(trap,
                                            out_priority,
                                            counter_or_meter,
                                            punt_dest,
                                            out_skip_inject_up_packets,
                                            out_skip_p2p_packets,
                                            out_overwrite_phb,
                                            out_tc);
    return_on_error(status);

    out_destination = punt_dest.get();
    out_counter_or_meter = counter_or_meter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_trap_configuration(la_event_e trap,
                                       la_trap_priority_t priority,
                                       la_counter_or_meter_set* counter_or_meter,
                                       const la_punt_destination* destination,
                                       bool skip_inject_up_packets,
                                       bool skip_p2p_packets,
                                       bool overwrite_phb,
                                       la_traffic_class_t tc)
{
    start_api_call("trap=",
                   trap,
                   "priority=",
                   priority,
                   "counter_or_meter=",
                   counter_or_meter,
                   "destination=",
                   destination,
                   "skip_inject_up_packets=",
                   skip_inject_up_packets,
                   "skip_p2p_packets=",
                   skip_p2p_packets,
                   "overwrite_phb=",
                   overwrite_phb,
                   "tc=",
                   tc);

    auto counter_or_meter_sptr = get_sptr(counter_or_meter);
    auto destination_sptr = get_sptr(destination);
    return do_set_trap_configuration(
        trap, priority, counter_or_meter_sptr, destination_sptr, skip_inject_up_packets, skip_p2p_packets, overwrite_phb, tc);
}

la_status
la_device_impl::check_trap_skip_p2p_packets(la_event_e trap, bool skip_p2p_packets)
{
    if (!skip_p2p_packets) {
        return LA_STATUS_SUCCESS;
    }

    // Skip_p2p flag is only applicable for ethernet traps.
    if ((trap < LA_EVENT_ETHERNET_FIRST) || (trap > LA_EVENT_ETHERNET_LAST)) {
        return LA_STATUS_EINVAL;
    }

    // Following ethernet traps cannot be skipped by skip p2p flag.
    switch (trap) {
    case LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT:
    case LA_EVENT_ETHERNET_NO_SIP_MAPPING:
    case LA_EVENT_ETHERNET_NO_VNI_MAPPING:
    case LA_EVENT_ETHERNET_NO_VSID_MAPPING:
    case LA_EVENT_ETHERNET_LEARN_PUNT:
    case LA_EVENT_ETHERNET_PFC_SAMPLE:
    case LA_EVENT_ETHERNET_L2_DLP_NOT_FOUND:
    case LA_EVENT_ETHERNET_SAME_INTERFACE:
    case LA_EVENT_ETHERNET_DSPA_MC_TRIM:
    case LA_EVENT_ETHERNET_EGRESS_STP_BLOCK:
    case LA_EVENT_ETHERNET_SPLIT_HORIZON:
    case LA_EVENT_ETHERNET_DISABLED:
    case LA_EVENT_ETHERNET_INCOMPATIBLE_EVE_CMD:
    case LA_EVENT_ETHERNET_PADDING_RESIDUE_IN_SECOND_LINE:
    case LA_EVENT_ETHERNET_PFC_DIRECT_SAMPLE:
        return LA_STATUS_EINVAL;

    default:
        break;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_set_trap_configuration(la_event_e trap,
                                          la_trap_priority_t priority,
                                          const la_counter_or_meter_set_wptr& counter_or_meter,
                                          const la_punt_destination_wcptr& destination,
                                          bool skip_inject_up_packets,
                                          bool skip_p2p_packets,
                                          bool overwrite_phb,
                                          la_traffic_class_t tc)
{
    if (trap > LA_EVENT_L2_LPTS_LAST) {
        return LA_STATUS_EINVAL;
    }

    if (priority > LAST_USER_ALLOWED_PRIORITY) {
        log_err(
            HLD, "%s: required priority (%d) exceeds the max allowed value (%d)", __func__, priority, LAST_USER_ALLOWED_PRIORITY);
        return LA_STATUS_EINVAL;
    }

    // Check arguments
    if ((destination != nullptr) && !of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if ((counter_or_meter != nullptr) && !of_same_device(counter_or_meter, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if ((trap >= LA_EVENT_OAMP_FIRST) && (trap <= LA_EVENT_OAMP_LAST)) {
        return set_trap_configuration_for_npu_host(trap, priority, counter_or_meter, destination, tc);
    }

    la_status status = check_trap_skip_p2p_packets(trap, skip_p2p_packets);
    return_on_error(status);

    if (trap != LA_EVENT_L3_ACL_FORCE_PUNT && trap != LA_EVENT_ETHERNET_ACL_FORCE_PUNT) {
        if (overwrite_phb == false) {
            return LA_STATUS_EINVAL;
        }
    }

    // Temporary fix for LA_EVENT_L3_DROP_ADJ to allow different actions for inject up packets
    // The below 2 conditions enforces the following statements:
    // 1) For LA_EVENT_L3_DROP_ADJ: skip_inject_up_packets == false
    // 2) For LA_EVENT_L3_DROP_ADJ_NON_INJECT: skip_inject_up_packets == true
    // 3) For both above events: the below inject_policy_changed calculation will always result in false
    if ((trap == LA_EVENT_L3_DROP_ADJ) && skip_inject_up_packets) {
        log_err(HLD,
                "LA_EVENT_L3_DROP_ADJ can't be configured with skip_inject_up_packets == true, as there is a special "
                "event for this scenario: LA_EVENT_L3_DROP_ADJ_NON_INJECT");
        return LA_STATUS_EINVAL;
    }
    if ((trap == LA_EVENT_L3_DROP_ADJ_NON_INJECT) && !skip_inject_up_packets) {
        skip_inject_up_packets = true; // This is a special event for non inject up packets - so forcing the parameter
    }

    // Configure redirect code
    // First redirect codes used for mirror commands
    la_uint_t redirect_code = get_drop_redirect_destination(trap);

    la_l2_punt_destination_impl_wcptr punt_dest_impl;
    bool is_l3_trap = ((trap >= LA_EVENT_IPV4_FIRST) && (trap <= LA_EVENT_L3_LAST));
    bool disable_snoop = is_event_type_disabled(trap);

    destination_id drop_dest_id = get_actual_destination_id(RX_DROP_DSP);

    if (destination != nullptr) {
        if (destination->type() == la_object::object_type_e::NPU_HOST_DESTINATION) {
            const destination_id sp_destination = get_destination_id(destination, RESOLUTION_STEP_FIRST);
            la_l2_punt_destination_gid_t encap_ptr;
            // If its a L2 control trap and its destined to the NPU host, assume its handled by PFC.
            if ((trap >= LA_EVENT_ETHERNET_L2CP0) && (trap <= LA_EVENT_ETHERNET_L2CP7)) {
                encap_ptr = NPU_HOST_PFC_ENCAP_PTR;
            } else {
                encap_ptr = NPU_HOST_BFD_ENCAP_PTR;
            }
            status = configure_redirect_code(redirect_code,
                                             disable_snoop,
                                             is_l3_trap,
                                             counter_or_meter,
                                             sp_destination,
                                             NPL_PUNT_NW_NPU_HOST_ENCAP_TYPE,
                                             encap_ptr,
                                             overwrite_phb,
                                             tc);
            return_on_error(status);
        } else {
            punt_dest_impl = destination.weak_ptr_static_cast<const la_l2_punt_destination_impl>();

            const destination_id sp_destination = get_destination_id(destination, RESOLUTION_STEP_FIRST);
            la_l2_punt_destination_gid_t encap_ptr = punt_dest_impl->get_gid();
            status = configure_redirect_code(redirect_code,
                                             disable_snoop,
                                             is_l3_trap,
                                             counter_or_meter,
                                             sp_destination,
                                             NPL_PUNT_NW_ETH_ENCAP_TYPE,
                                             encap_ptr,
                                             overwrite_phb,
                                             tc);
            return_on_error(status);
        }
    } else if (counter_or_meter != nullptr) {
        status = configure_redirect_code(redirect_code,
                                         disable_snoop,
                                         is_l3_trap,
                                         counter_or_meter,
                                         drop_dest_id,
                                         NPL_PUNT_NW_ETH_ENCAP_TYPE,
                                         DUMMY_REDIRECT_ENCAP_PTR,
                                         overwrite_phb,
                                         tc);
        return_on_error(status);
    } else {
        status = configure_redirect_code(redirect_code,
                                         disable_snoop,
                                         false /* is_l3_trap */,
                                         nullptr /*counter_or_meter*/,
                                         drop_dest_id,
                                         NPL_PUNT_NW_ETH_ENCAP_TYPE,
                                         DUMMY_REDIRECT_ENCAP_PTR,
                                         overwrite_phb,
                                         tc);
        return_on_error(status);
    }

    // Prepare the value to update in m_trap_entries
    la_trap_config_entry trap_cfg = {.trap = trap,
                                     .priority = priority,
                                     .counter_or_meter = counter_or_meter,
                                     .punt_dest = punt_dest_impl,
                                     .skip_inject_up_packets = skip_inject_up_packets,
                                     .skip_p2p_packets = skip_p2p_packets,
                                     .overwrite_phb = overwrite_phb,
                                     .tc = tc};

    // If the trap already exists and it has the same priority as the existing one, overwrite existing entry.
    // Otherwise clear the existing entry and write a new one.
    size_t existing_entry_idx = 0;
    bool found_trap = false;
    for (; existing_entry_idx < m_trap_entries.size(); existing_entry_idx++) {
        if (m_trap_entries[existing_entry_idx].trap == trap) {
            found_trap = true;
            // There should be only one trap_entry with the same trap (regardless of skip_inject_up_packets)
            break;
        }
    }

    // If exists, remove dependency of previous punt_dest
    if ((found_trap) && (m_trap_entries[existing_entry_idx].punt_dest != nullptr)) {
        remove_object_dependency(m_trap_entries[existing_entry_idx].punt_dest, this);
    }

    // get the effective meter and counter pointers for obm_punt_src_and_code_table
    la_meter_set_exact_impl_wptr exact_meter_set_impl;
    la_meter_set_impl_wptr meter_impl;
    if ((counter_or_meter != nullptr) && (counter_or_meter->type() == la_object::object_type_e::METER_SET)) {
        meter_impl = counter_or_meter.weak_ptr_static_cast<la_meter_set_impl>();
        if (meter_impl->get_type() == la_meter_set::type_e::STATISTICAL) {
            auto s_meter_set_impl = meter_impl.weak_ptr_static_cast<la_meter_set_statistical_impl>();
            exact_meter_set_impl = s_meter_set_impl->get_exact_meter_set_as_counter();
        }
    }

    if ((found_trap) && (m_trap_entries[existing_entry_idx].priority == priority)) {
        // Overwrite existing entry
        status = configure_event_to_redirect_code(
            trap, existing_entry_idx, redirect_code, skip_inject_up_packets, skip_p2p_packets, true /*is_overwrite*/);
        return_on_error(status);

        // Update object dependencies
        if (punt_dest_impl != nullptr) {
            add_object_dependency(punt_dest_impl, this);
        }

        m_trap_entries[existing_entry_idx] = trap_cfg;

        int num_offsets = overwrite_phb ? 1 : 8;
        for (int offset = 0; offset < num_offsets; ++offset) {
            // Configure RX OBM Table for Ingress/Egress sources only for PCI/DMA
            status = configure_rx_obm_punt_src_and_code(
                redirect_code + offset, NPL_PUNT_SRC_INGRESS_TRAP, tc + offset, 0, meter_impl, exact_meter_set_impl, 0);
            return_on_error(status);

            status = configure_rx_obm_punt_src_and_code(
                redirect_code + offset, NPL_PUNT_SRC_EGRESS_TRAP, tc + offset, 0, meter_impl, exact_meter_set_impl, 0);
            return_on_error(status);
        }

        return LA_STATUS_SUCCESS;
    }

    if (found_trap) {
        // Clear the existing entry and write a new one.
        status = clear_event_to_redirect_code(existing_entry_idx);
        return_on_error(status);

        m_trap_entries.erase(m_trap_entries.begin() + existing_entry_idx);
    }

    // Find new location. The new-location logic assumes that entries at the location and forth will be pushed down.
    // So actually need to find the first inferior trap index.
    size_t new_location = 0;
    for (; new_location < m_trap_entries.size(); new_location++) {
        if (m_trap_entries[new_location].priority > priority) {
            break;
        }
    }

    // Update TCAM
    status = configure_event_to_redirect_code(
        trap, new_location, redirect_code, skip_inject_up_packets, skip_p2p_packets, false /*is_overwrite*/);
    return_on_error(status);

    m_trap_entries.insert(m_trap_entries.begin() + new_location, trap_cfg);

    // Update object dependencies
    if (punt_dest_impl != nullptr) {
        add_object_dependency(punt_dest_impl, this);
    }

    int num_offsets = overwrite_phb ? 1 : 8;
    for (int offset = 0; offset < num_offsets; ++offset) {
        // Configure RX OBM Table for Ingress/Egress sources only for PCI/DMA
        status = configure_rx_obm_punt_src_and_code(
            redirect_code + offset, NPL_PUNT_SRC_INGRESS_TRAP, tc + offset, 0, meter_impl, exact_meter_set_impl, 0);
        return_on_error(status);

        status = configure_rx_obm_punt_src_and_code(
            redirect_code + offset, NPL_PUNT_SRC_EGRESS_TRAP, tc + offset, 0, meter_impl, exact_meter_set_impl, 0);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_clear_trap_configuration(la_event_e trap)
{
    // Find trap entry
    auto entry = m_trap_entries.begin();
    for (; entry != m_trap_entries.end(); ++entry) {
        if (entry->trap == trap) {
            break;
        }
    }

    if (entry == m_trap_entries.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    // Remove dependency
    if (entry->punt_dest != nullptr) {
        remove_object_dependency(entry->punt_dest, this);
    }

    la_uint_t redirect_code = get_drop_redirect_destination(trap);
    if (entry->counter_or_meter != nullptr) {
        dassert_crit(entry->counter_or_meter == m_trap_counters_or_meters[redirect_code]);
        la_status status = remove_trap_counter_or_meter(redirect_code);
        return_on_error(status);
    }

    if (is_oam_trap(trap)) {
        // OAM traps
        auto status = clear_oamp_redirect_code(redirect_code);
        return_on_error(status);

        m_trap_entries.erase(entry);
        return LA_STATUS_SUCCESS;
    }

    // Non-OAM traps

    // Clear TCAM.
    size_t location = std::distance(m_trap_entries.begin(), entry);
    la_status status = clear_event_to_redirect_code(location);
    return_on_error(status);

    status = clear_redirect_code(redirect_code);
    if ((status != LA_STATUS_SUCCESS) && (status != LA_STATUS_ENOTFOUND)) {
        return status;
    }

    m_trap_entries.erase(entry);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_trap_configuration(la_event_e trap)
{
    start_api_call("trap=", trap);

    if (trap > LA_EVENT_L2_LPTS_LAST) {
        return LA_STATUS_EINVAL;
    }

    return do_clear_trap_configuration(trap);
}

la_status
la_device_impl::get_snoop_configuration(la_event_e snoop,
                                        la_snoop_priority_t& out_priority,
                                        const la_mirror_command*& out_mirror_cmd)
{
    if (snoop > LA_EVENT_L2_LPTS_LAST) {
        return LA_STATUS_EINVAL;
    }

    for (auto& snoop_cfg : m_snoop_entries) {
        if (snoop_cfg.snoop == snoop) {
            out_priority = snoop_cfg.priority;
            out_mirror_cmd = snoop_cfg.mirror_cmd.get();
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
la_device_impl::do_set_snoop_configuration(la_event_e snoop,
                                           la_snoop_priority_t priority,
                                           bool skip_inject_up_packets,
                                           bool skip_p2p_packets,
                                           const la_mirror_command* mirror_cmd)
{
    la_mirror_command_wcptr mirror_cmd_wptr = get_sptr(mirror_cmd);

    // Check arguments
    if (mirror_cmd_wptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(this, mirror_cmd_wptr)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_mirror_gid_t ibm_cmd = mirror_cmd_wptr->get_gid();

    // Find if exists
    auto entry_cur = m_snoop_entries.begin();
    bool entry_found = false;
    for (; entry_cur != m_snoop_entries.end(); ++entry_cur) {
        if (entry_cur->snoop == snoop) {
            entry_found = true;
            break;
        }
    }

    // Configure snoop code to mirror command
    la_uint_t snoop_code = snoop;
    la_status status = configure_snoop_code_to_ibm(snoop_code, ibm_cmd);
    return_on_error(status);

    // Remove dependency to previous mirror command
    if ((entry_found) && (entry_cur->mirror_cmd != nullptr)) {
        remove_object_dependency(entry_cur->mirror_cmd, this);
    }

    // If already exists and same priority -> no need to update TCAM.
    if ((entry_found) && (entry_cur->priority == priority)) {
        entry_cur->mirror_cmd = mirror_cmd_wptr;

        // Update object dependencies
        add_object_dependency(mirror_cmd_wptr, this);

        return LA_STATUS_SUCCESS;
    }

    // Otherwise, erase previous TCAM entry and add new in the correct location.
    if (entry_found) {
        m_snoop_entries.erase(entry_cur);
    }

    // Find location
    auto entry = m_snoop_entries.begin();
    for (; entry != m_snoop_entries.end(); ++entry) {
        if (entry->priority >= priority) {
            break;
        }
    }
    size_t location = std::distance(m_snoop_entries.begin(), entry);

    // Configure event to snoop code
    // Update TCAM
    status = configure_event_to_snoop_code(snoop, location, snoop_code, skip_inject_up_packets, skip_p2p_packets);
    return_on_error(status);

    bool dsp_mode = false;

    get_bool_property(la_device_property_e::DESTINATION_SYSTEM_PORT_IN_IBM_METADATA, dsp_mode);

    status = configure_snoop_to_dsp_in_npu_soft_header_table(snoop_code, dsp_mode);
    return_on_error(status);

    // Update table
    la_snoop_config_entry snoop_cfg;
    snoop_cfg.priority = priority;
    snoop_cfg.snoop = snoop;
    snoop_cfg.mirror_cmd = mirror_cmd_wptr;
    m_snoop_entries.insert(entry, snoop_cfg);

    // Update object dependencies
    add_object_dependency(mirror_cmd_wptr, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_snoop_configuration(la_event_e snoop,
                                        la_snoop_priority_t priority,
                                        bool skip_inject_up_packets,
                                        bool skip_p2p_packets,
                                        const la_mirror_command* mirror_cmd)
{
    start_api_call("snoop=",
                   snoop,
                   "priority=",
                   priority,
                   "skip_inject_up_packets =",
                   skip_inject_up_packets,
                   "skip_p2p_packets =",
                   skip_p2p_packets,
                   "mirror_cmd=",
                   mirror_cmd);
    return do_set_snoop_configuration(snoop, priority, skip_inject_up_packets, skip_p2p_packets, mirror_cmd);
}

la_status
la_device_impl::set_mc_lpts_snoop_configuration(la_snoop_priority_t priority,
                                                bool skip_inject_up_packets,
                                                bool skip_p2p_packets,
                                                const la_mirror_command* mirror_cmd)
{
    start_api_call("priority = ",
                   priority,
                   "skip_inject_up_packets =",
                   skip_inject_up_packets,
                   "skip_p2p_packets =",
                   skip_p2p_packets,
                   "mirror_cmd = ",
                   mirror_cmd);

    la_status status = do_clear_trap_configuration(LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_BRIDGING);
    return_on_error(status);

    status = do_set_snoop_configuration(
        LA_EVENT_INTERNAL_IPV4_NON_ROUTABLE_MC_BRIDGING, priority, skip_inject_up_packets, skip_p2p_packets, mirror_cmd);
    return_on_error(status);

    status = do_clear_trap_configuration(LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_BRIDGING);
    return_on_error(status);

    status = do_set_snoop_configuration(
        LA_EVENT_INTERNAL_IPV6_NON_ROUTABLE_MC_BRIDGING, priority, skip_inject_up_packets, skip_p2p_packets, mirror_cmd);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_snoop_configuration(la_event_e snoop)
{
    start_api_call("snoop=", snoop);
    // Find snoop entry
    auto entry = m_snoop_entries.begin();
    for (; entry != m_snoop_entries.end(); ++entry) {
        if (entry->snoop == snoop) {
            break;
        }
    }

    if (entry == m_snoop_entries.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    // Remove dependency
    if (entry->mirror_cmd != nullptr) {
        remove_object_dependency(entry->mirror_cmd, this);
    }

    m_snoop_entries.erase(entry);

    // Clear TCAM
    la_status status = clear_event_to_snoop_code(snoop);
    return_on_error(status);

    status = clear_snoop_code_to_ibm(snoop);
    if ((status != LA_STATUS_SUCCESS) && (status != LA_STATUS_ENOTFOUND)) {
        return status;
    }

    status = clear_snoop_to_dsp_in_npu_soft_header_table(snoop);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_ethernet_port(la_system_port* system_port,
                                     la_ethernet_port::port_type_e type,
                                     la_ethernet_port*& out_ethernet_port)
{
    start_api_call("system_port=", system_port, "type=", type);
    // Check arguments
    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(system_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Get port ID
    uint64_t port_id = 0;
    bool is_success = m_index_generators.ethernet_ports.allocate(port_id);
    if (!is_success) {
        return LA_STATUS_ERESOURCE;
    }

    // Create and initialize ethernet port
    la_system_port_base* system_port_base = static_cast<la_system_port_base*>(system_port);

    auto ethernet_port = std::make_shared<la_ethernet_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(ethernet_port, oid);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.ethernet_ports.release(port_id);
        return status;
    }
    status = ethernet_port->initialize(oid, system_port_base, port_id, type);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        m_index_generators.ethernet_ports.release(port_id);
        return status;
    }

    // Update mappings
    m_l2_destinations[port_id] = ethernet_port;

    out_ethernet_port = ethernet_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_ethernet_port(la_spa_port* spa_port,
                                     la_ethernet_port::port_type_e type,
                                     la_ethernet_port*& out_ethernet_port)
{
    start_api_call("spa_port=", spa_port, "type=", type);
    // Check arguments
    if (spa_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(spa_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Get port ID
    uint64_t port_id = 0;
    bool is_success = m_index_generators.ethernet_ports.allocate(port_id);
    if (!is_success) {
        return LA_STATUS_ERESOURCE;
    }

    // Create and initialize ethernet port
    la_spa_port_base* spa_port_base = static_cast<la_spa_port_base*>(spa_port);

    auto ethernet_port = std::make_shared<la_ethernet_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    auto status = register_object(ethernet_port, oid);
    return_on_error(status);
    status = ethernet_port->initialize(oid, spa_port_base, port_id, type);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.ethernet_ports.release(port_id);
        deregister_object(oid);
        return status;
    }

    // Update mappings
    m_l2_destinations[port_id] = ethernet_port;

    out_ethernet_port = ethernet_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_ethernet_port(const la_ethernet_port_gibraltar_wptr& ethernet_port)
{
    if (ethernet_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ethernet_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(ethernet_port)) {
        return LA_STATUS_EBUSY;
    }

    if (ethernet_port != ethernet_port) {
        return LA_STATUS_EUNKNOWN;
    }

    la_l2_port_gid_t id = ethernet_port->get_id();

    la_status status = ethernet_port->destroy();
    return_on_error(status);
    m_index_generators.ethernet_ports.release(id);
    m_l2_destinations[id] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_ac_l2_service_port(la_l2_port_gid_t port_gid,
                                          const la_ethernet_port* ethernet_port,
                                          la_vlan_id_t vid1,
                                          la_vlan_id_t vid2,
                                          const la_filter_group* filter_group,
                                          la_ingress_qos_profile* ingress_qos_profile,
                                          la_egress_qos_profile* egress_qos_profile,
                                          la_l2_service_port*& out_l2_service_port)
{
    start_api_call("port_gid=",
                   port_gid,
                   "ethernet_port=",
                   ethernet_port,
                   "vid1=",
                   vid1,
                   "vid2=",
                   vid2,
                   "filter_group=",
                   filter_group,
                   "ingress_qos_profile=",
                   ingress_qos_profile,
                   "egress_qos_profile=",
                   egress_qos_profile);

    // Check arguments
    if (port_gid >= MAX_L2_SERVICE_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l2_ports[port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (ethernet_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ethernet_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (filter_group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(filter_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const la_ethernet_port_gibraltar* ethernet_port_impl = static_cast<const la_ethernet_port_gibraltar*>(ethernet_port);

    // Create and initialize AC port
    la_ingress_qos_profile_impl* ingress_qos_profile_impl = static_cast<la_ingress_qos_profile_impl*>(ingress_qos_profile);
    la_egress_qos_profile_impl* egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);
    const la_filter_group_impl* filter_group_impl = static_cast<const la_filter_group_impl*>(filter_group);
    auto service_port_impl = std::make_shared<la_l2_service_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(service_port_impl, oid);
    return_on_error(status);
    status = service_port_impl->initialize_ac(oid,
                                              port_gid,
                                              get_sptr(ethernet_port_impl),
                                              vid1,
                                              vid2,
                                              get_sptr(filter_group_impl),
                                              get_sptr(ingress_qos_profile_impl),
                                              get_sptr(egress_qos_profile_impl));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    // Update mappings
    m_l2_ports[port_gid] = service_port_impl;
    out_l2_service_port = service_port_impl.get();

    la_l2_destination_gid_t gid = get_l2_destination_gid(service_port_impl);
    m_l2_destinations[gid] = service_port_impl;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_rate_limiter(silicon_one::la_system_port* system_port, la_rate_limiter_set*& out_rate_limiter_set)
{

    start_api_call("system_port=", system_port);
    if (!of_same_device(system_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }
    auto rl_impl = std::make_shared<la_rate_limiter_set_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(rl_impl, oid);
    return_on_error(status);

    status = rl_impl->initialize(oid, get_sptr(system_port));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_rate_limiter_set = rl_impl.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_pwe_l2_service_port(la_l2_port_gid_t port_gid,
                                           la_mpls_label local_label,
                                           la_mpls_label remote_label,
                                           la_pwe_gid_t pwe_gid,
                                           la_l3_destination* destination,
                                           la_ingress_qos_profile* ingress_qos_profile,
                                           la_egress_qos_profile* egress_qos_profile,
                                           la_l2_service_port*& out_l2_service_port)
{
    start_api_call("port_gid=",
                   port_gid,
                   "local_label=",
                   local_label,
                   "remote_label=",
                   remote_label,
                   "pwe_gid=",
                   pwe_gid,
                   "destination=",
                   destination,
                   "ingress_qos_profile=",
                   ingress_qos_profile,
                   "egress_qos_profile=",
                   egress_qos_profile);

    // Check arguments
    if (port_gid >= MAX_L2_SERVICE_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l2_ports[port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (pwe_gid >= MAX_PWE_SERVICE_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_pwe_ports[pwe_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_ingress_qos_profile_impl* ingress_qos_profile_impl = static_cast<la_ingress_qos_profile_impl*>(ingress_qos_profile);
    la_egress_qos_profile_impl* egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);

    auto service_port_impl = std::make_shared<la_l2_service_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(service_port_impl, oid);
    return_on_error(status);
    status = service_port_impl->initialize_pwe(oid,
                                               port_gid,
                                               local_label,
                                               remote_label,
                                               pwe_gid,
                                               get_sptr(destination),
                                               get_sptr(ingress_qos_profile_impl),
                                               get_sptr(egress_qos_profile_impl));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    // Update mappings

    m_l2_ports[port_gid] = service_port_impl;
    m_pwe_ports[pwe_gid] = service_port_impl;
    out_l2_service_port = service_port_impl.get();

    la_l2_destination_gid_t gid = get_l2_destination_gid(service_port_impl);
    m_l2_destinations[gid] = service_port_impl;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_pwe_tagged_l2_service_port(la_l2_port_gid_t port_gid,
                                                  la_mpls_label local_label,
                                                  la_mpls_label remote_label,
                                                  la_l3_destination* destination,
                                                  la_vlan_id_t vid1,
                                                  la_ingress_qos_profile* ingress_qos_profile,
                                                  la_egress_qos_profile* egress_qos_profile,
                                                  la_l2_service_port*& out_l2_service_port)
{
    start_api_call("port_gid=",
                   port_gid,
                   "local_label=",
                   local_label,
                   "remote_label=",
                   remote_label,
                   "destination=",
                   destination,
                   "vid1=",
                   vid1,
                   "ingress_qos_profile=",
                   ingress_qos_profile,
                   "egress_qos_profile=",
                   egress_qos_profile);

    // Check arguments
    if (port_gid >= MAX_L2_SERVICE_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l2_ports[port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_ingress_qos_profile_impl* ingress_qos_profile_impl = static_cast<la_ingress_qos_profile_impl*>(ingress_qos_profile);
    la_egress_qos_profile_impl* egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);

    auto service_port_impl = std::make_shared<la_l2_service_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(service_port_impl, oid);
    return_on_error(status);
    status = service_port_impl->initialize_pwe_tagged(oid,
                                                      port_gid,
                                                      local_label,
                                                      remote_label,
                                                      vid1,
                                                      get_sptr(destination),
                                                      get_sptr(ingress_qos_profile_impl),
                                                      get_sptr(egress_qos_profile_impl));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    // Update mappings

    m_l2_ports[port_gid] = service_port_impl;
    out_l2_service_port = service_port_impl.get();

    la_l2_destination_gid_t gid = get_l2_destination_gid(service_port_impl);
    m_l2_destinations[gid] = service_port_impl;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_vxlan_l2_service_port(la_l2_port_gid_t port_gid,
                                             la_ipv4_addr_t local_ip_addr,
                                             la_ipv4_addr_t remote_ip_addr,
                                             la_vrf* vrf,
                                             la_l2_service_port*& out_l2_service_port)
{
    start_api_call("port_gid=", port_gid, "local_ip_addr=", local_ip_addr, "remote_ip_addr=", remote_ip_addr, "vrf=", vrf);

    // Check arguments
    if (port_gid >= MAX_L2_SERVICE_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l2_ports[port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto service_port_impl = std::make_shared<la_l2_service_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(service_port_impl, oid);
    return_on_error(status);

    status = service_port_impl->initialize_vxlan(oid, port_gid, local_ip_addr, remote_ip_addr, get_sptr(vrf));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    // Update mappings

    m_l2_ports[port_gid] = service_port_impl;
    out_l2_service_port = service_port_impl.get();

    la_l2_destination_gid_t gid = get_l2_destination_gid(service_port_impl);
    m_l2_destinations[gid] = service_port_impl;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_vxlan_l2_service_port(la_l2_port_gid_t port_gid,
                                             la_ip_tunnel_mode_e tunnel_mode,
                                             la_ipv4_prefix_t local_ip_prefix,
                                             la_ipv4_addr_t remote_ip_addr,
                                             la_vrf* vrf,
                                             la_l2_service_port*& out_l2_service_port)
{
    start_api_call("port_gid=",
                   port_gid,
                   "tunnel_mode=",
                   tunnel_mode,
                   "local_ip_prefix=",
                   local_ip_prefix,
                   "remote_ip_addr=",
                   remote_ip_addr,
                   "vrf=",
                   vrf);

    // Check arguments
    if (port_gid >= MAX_L2_SERVICE_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l2_ports[port_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto service_port_impl = std::make_shared<la_l2_service_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(service_port_impl, oid);
    return_on_error(status);

    status = service_port_impl->initialize_vxlan(oid, port_gid, tunnel_mode, local_ip_prefix, remote_ip_addr, get_sptr(vrf));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    // Update mappings
    m_l2_ports[port_gid] = service_port_impl;
    out_l2_service_port = service_port_impl.get();

    la_l2_destination_gid_t gid = get_l2_destination_gid(service_port_impl);
    m_l2_destinations[gid] = service_port_impl;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_l2_service_port(const la_l2_service_port_gibraltar_wptr& port)
{
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l2_port_gid_t gid = port->get_gid();
    const auto& l2_port = m_l2_ports[gid].weak_ptr_static_cast<la_l2_port>();

    if (l2_port != port) {
        return LA_STATUS_EUNKNOWN;
    }

    la_pwe_gid_t pwe_gid;
    bool is_pwe = false;

    la_status status = port->get_pwe_gid(pwe_gid);
    if (status == LA_STATUS_SUCCESS) {
        const auto& pwe_port = m_pwe_ports[pwe_gid].weak_ptr_static_cast<la_l2_port>();

        if (pwe_port != port) {
            return LA_STATUS_EUNKNOWN;
        }
        is_pwe = true;
    }

    status = port->destroy();
    return_on_error(status);

    m_l2_ports[gid] = nullptr;
    la_l2_destination_gid_t l2_gid = get_l2_destination_gid(port);
    m_l2_destinations[l2_gid] = nullptr;
    if (is_pwe) {
        m_pwe_ports[pwe_gid] = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_multicast_protection_monitor(la_multicast_protection_monitor*& out_protection_monitor)
{
    start_api_call("");

    auto protection_monitor = std::make_shared<la_multicast_protection_monitor_base>(shared_from_this());

    uint64_t protection_monitor_gid = 0;
    bool is_success = m_index_generators.multicast_protection_monitors.allocate(protection_monitor_gid);
    if (!is_success) {
        return LA_STATUS_ERESOURCE;
    }

    la_object_id_t oid;
    la_status status = register_object(protection_monitor, oid);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.multicast_protection_monitors.release(protection_monitor_gid);
        return status;
    }

    status = protection_monitor->initialize(oid, protection_monitor_gid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        m_index_generators.multicast_protection_monitors.release(protection_monitor_gid);
        return status;
    }

    out_protection_monitor = protection_monitor.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_stack_port(la_system_port* system_port, la_stack_port*& out_stack_port)
{
    start_api_call("system_port=", system_port);

    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (system_port->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto stack_port = std::make_shared<la_stack_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(stack_port, oid);
    return_on_error(status);

    status = stack_port->initialize(oid, get_sptr<la_system_port_base>(system_port));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_stack_port = stack_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_stack_port(la_spa_port* spa_port, la_stack_port*& out_stack_port)
{
    start_api_call("spa_port=", spa_port);

    if (spa_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (spa_port->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto stack_port = std::make_shared<la_stack_port_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(stack_port, oid);
    return_on_error(status);

    status = stack_port->initialize(oid, get_sptr<la_spa_port_base>(spa_port));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_stack_port = stack_port.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_multicast_protection_monitor(const la_multicast_protection_monitor_base_wptr& monitor)
{
    if (monitor == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (monitor->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(monitor)) {
        return LA_STATUS_EBUSY;
    }

    uint64_t protection_monitor_gid = monitor->get_gid();

    la_status status = monitor->destroy();
    return_on_error(status);

    m_index_generators.multicast_protection_monitors.release(protection_monitor_gid);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_stack_port(const la_stack_port_base_wptr& stack_port)
{
    if (stack_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (stack_port->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(stack_port)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = stack_port->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_protection_monitor(la_protection_monitor*& out_protection_monitor)
{
    start_api_call("");
    auto protection_monitor = std::make_shared<la_protection_monitor_impl>(shared_from_this());

    uint64_t protection_monitor_gid = 0;
    bool is_success = m_index_generators.protection_monitors.allocate(protection_monitor_gid);
    if (!is_success) {
        return LA_STATUS_ERESOURCE;
    }

    la_object_id_t oid;
    la_status status = register_object(protection_monitor, oid);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.protection_monitors.release(protection_monitor_gid);
        return status;
    }

    status = protection_monitor->initialize(oid, protection_monitor_gid);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        m_index_generators.protection_monitors.release(protection_monitor_gid);
        return status;
    }

    m_protection_monitors[protection_monitor_gid] = protection_monitor;
    out_protection_monitor = protection_monitor.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_protection_monitor(const la_protection_monitor_impl_wptr& protection_monitor)
{
    if (protection_monitor == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(protection_monitor, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(protection_monitor)) {
        return LA_STATUS_EBUSY;
    }

    uint64_t protection_monitor_gid = protection_monitor->get_gid();

    la_status status = protection_monitor->destroy();
    return_on_error(status);
    m_index_generators.protection_monitors.release(protection_monitor_gid);
    m_protection_monitors[protection_monitor_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l2_protection_group(la_l2_port_gid_t group_gid,
                                           la_l2_destination* primary_destination,
                                           la_l2_destination* protecting_destination,
                                           la_protection_monitor* protection_monitor,
                                           la_l2_protection_group*& out_l2_protection_group)
{
    start_api_call("group_gid=",
                   group_gid,
                   "primary_destination=",
                   primary_destination,
                   "protecting_destination=",
                   protecting_destination,
                   "protection_monitor=",
                   protection_monitor);

    if (group_gid >= MAX_L2_SERVICE_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l2_ports[group_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (primary_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (protecting_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (protection_monitor == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto l2_protection_group = std::make_shared<la_l2_protection_group_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(l2_protection_group, oid);
    return_on_error(status);

    status = l2_protection_group->initialize(
        oid, group_gid, get_sptr(primary_destination), get_sptr(protecting_destination), get_sptr(protection_monitor));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_l2_ports[group_gid] = l2_protection_group;
    out_l2_protection_group = l2_protection_group.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_l2_protection_group(const la_l2_protection_group_base_wptr& l2_protection_group)
{
    if (!of_same_device(l2_protection_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l2_destination_gid_t gid = l2_protection_group->get_gid();
    la_status status = l2_protection_group->destroy();
    return_on_error(status);

    m_l2_ports[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_l2_protection_group_by_id(la_l2_port_gid_t group_gid, la_l2_protection_group*& out_l2_protection_group) const
{
    if (group_gid >= MAX_L2_SERVICE_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    const auto& l2_destination = m_l2_ports[group_gid];
    if (l2_destination == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    if (l2_destination->type() != object_type_e::L2_PROTECTION_GROUP) {
        return LA_STATUS_ENOTFOUND;
    }

    out_l2_protection_group = l2_destination.weak_ptr_static_cast<la_l2_protection_group>().get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_multicast_protection_group(la_next_hop* primary_destination,
                                                  la_system_port* primary_system_port,
                                                  la_next_hop* protecting_destination,
                                                  la_system_port* protecting_system_port,
                                                  la_multicast_protection_monitor* protection_monitor,
                                                  la_multicast_protection_group*& out_multicast_protection_group)
{
    start_api_call("primary_destination=",
                   primary_destination,
                   "primary_system_port=",
                   primary_system_port,
                   "protecting_destination=",
                   protecting_destination,
                   "la_system_port=",
                   protecting_system_port,
                   "protection_monitor=",
                   protection_monitor);

    if (primary_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (primary_system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (protection_monitor == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto multicast_protection_group = std::make_shared<la_multicast_protection_group_base>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(multicast_protection_group, oid);
    return_on_error(status);

    status = multicast_protection_group->initialize(oid,
                                                    get_sptr(primary_destination),
                                                    get_sptr(primary_system_port),
                                                    get_sptr(protecting_destination),
                                                    get_sptr(protecting_system_port),
                                                    get_sptr(protection_monitor));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_multicast_protection_group = multicast_protection_group.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_multicast_protection_group(const la_multicast_protection_group_base_wptr& multicast_protection_group)
{
    if (!of_same_device(multicast_protection_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = multicast_protection_group->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l3_protection_group(la_l3_protection_group_gid_t group_gid,
                                           la_l3_destination* primary_destination,
                                           la_l3_destination* protecting_destination,
                                           la_protection_monitor* protection_monitor,
                                           la_l3_protection_group*& out_l3_protection_group)
{
    start_api_call("group_gid=",
                   group_gid,
                   "primary_destination=",
                   primary_destination,
                   "protecting_destination=",
                   protecting_destination,
                   "protection_monitor=",
                   protection_monitor);

    if (group_gid >= MAX_L3_PROTECTED_GIDS) {
        return LA_STATUS_EINVAL;
    }

    if (m_l3_protected_entries[group_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto l3_protection_group = std::make_shared<la_l3_protection_group_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(l3_protection_group, oid);
    return_on_error(status);

    status = l3_protection_group->initialize(
        oid, group_gid, get_sptr(primary_destination), get_sptr(protecting_destination), get_sptr(protection_monitor));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_l3_protected_entries[group_gid] = l3_protection_group;
    out_l3_protection_group = l3_protection_group.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_l3_protection_group(const la_l3_protection_group_impl_wptr& l3_protection_group)
{
    if (!of_same_device(l3_protection_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l3_destination_gid_t gid = l3_protection_group->get_gid();

    la_status status = l3_protection_group->destroy();
    return_on_error(status);

    m_l3_protected_entries[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_l3_protection_group_by_id(la_l3_protection_group_gid_t group_gid,
                                              la_l3_protection_group*& out_l3_protection_group) const
{
    if (group_gid >= MAX_L3_PROTECTED_GIDS) {
        return LA_STATUS_EINVAL;
    }

    const auto& l3_destination = m_l3_protected_entries[group_gid];
    if (l3_destination == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    if (l3_destination->type() != object_type_e::L3_PROTECTION_GROUP) {
        return LA_STATUS_ENOTFOUND;
    }

    out_l3_protection_group = l3_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_switch(la_switch_gid_t switch_gid, la_switch*& out_switch)
{
    start_api_call("switch_gid=", switch_gid);
    out_switch = nullptr;

    if (switch_gid >= MAX_SWITCH_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_switches[switch_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto sw = std::make_shared<la_switch_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(sw, oid);
    return_on_error(status);

    status = sw->initialize(oid, switch_gid);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_switches[switch_gid] = sw;
    out_switch = sw.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_switch(const la_switch_impl_wptr& sw)
{
    if (sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(sw, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_switch_gid_t switch_gid = sw->get_gid();
    la_status status = sw->destroy();
    return_on_error(status);

    m_switches[switch_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_switch*
la_device_impl::get_switch_by_id(la_switch_gid_t switch_gid)
{
    if (switch_gid >= MAX_SWITCH_GID) {
        return nullptr;
    }

    return m_switches[switch_gid].get();
}

size_t
la_device_impl::num_vlan_format_tags(const npl_vlan_format_table_t::key_type& key) const
{
    size_t tag1 = (key.header_1_type != NPL_PROTOCOL_TYPE_UNKNOWN) ? 1 : 0;
    size_t tag2 = (key.header_2_type != NPL_PROTOCOL_TYPE_UNKNOWN) ? 1 : 0;

    return (tag1 + tag2);
}

la_status
la_device_impl::update_vlan_format_table(la_switch::vxlan_termination_mode_e vni_profile, uint64_t& index)
{
    // Ensure we have enough resources
    const auto& table(m_tables.vlan_format_table);
    size_t num_entries = table->size();
    size_t max_entries = table->max_size();

    if (num_entries == max_entries) {
        return LA_STATUS_ERESOURCE;
    }
    bool allocated = m_index_generators.ac_profiles.allocate(m_vxlan_vni_profile[(la_uint_t)vni_profile].index);
    if (!allocated) {
        return LA_STATUS_ERESOURCE;
    }
    npl_vlan_format_table_t::key_type key;
    npl_vlan_format_table_t::key_type mask;
    npl_vlan_format_table_t::value_type value;

    key.vlan_profile = m_vxlan_vni_profile[(la_uint_t)vni_profile].index;
    key.is_priority = 0;
    key.header_1_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    key.header_2_type = NPL_PROTOCOL_TYPE_UNKNOWN;

    mask.vlan_profile = 0xf;
    mask.is_priority = 0;
    mask.header_1_type = (npl_protocol_type_e)0;
    mask.header_2_type = (npl_protocol_type_e)0;

    value.action = NPL_VLAN_FORMAT_TABLE_ACTION_UPDATE;
    value.payloads.update.pcp_dei_from_port = 0;
    value.payloads.update.vid_from_port = 0;
    value.payloads.update.sm_selector = NPL_SERVICE_MAPPING_SELECTOR_AC_PORT;
    value.payloads.update.sm_logical_db = NPL_SM_LDB_AC_PORT;

    switch (vni_profile) {
    case la_switch::vxlan_termination_mode_e::CHECK_DMAC:
        value.payloads.update.mac_termination_type = NPL_MAC_TERM_UC_WITH_DA;
        break;
    case la_switch::vxlan_termination_mode_e::IGNORE_DMAC:
        value.payloads.update.mac_termination_type = NPL_MAC_TERM_UC_NO_DA;
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    size_t location = 0;

    while (location < num_entries) {
        npl_vlan_format_table_t::entry_pointer_type entry = nullptr;
        table->get_entry(location, entry);

        if (entry == nullptr) {
            log_err(HLD, "VLAN format table not contiguous.");
            return LA_STATUS_EUNKNOWN;
        }

        size_t new_num_tags = num_vlan_format_tags(key);
        const npl_vlan_format_table_t::key_type& entry_key = entry->key();
        size_t curr_num_tags = num_vlan_format_tags(entry_key);
        if (new_num_tags > curr_num_tags) {
            break;
        }

        location++;
    }

    // Update entry
    npl_vlan_format_table_t::entry_pointer_type dummy_entry = nullptr;
    la_status status = table->push(location, key, mask, value, dummy_entry);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::allocate_vni_profile(la_switch::vxlan_termination_mode_e vni_profile, uint64_t& index)
{
    if (m_vxlan_vni_profile[(la_uint_t)vni_profile].refcount == 0) {
        la_status status = update_vlan_format_table(vni_profile, index);
        return_on_error(status);
    }

    m_vxlan_vni_profile[(la_uint_t)vni_profile].refcount++;

    index = m_vxlan_vni_profile[(la_uint_t)vni_profile].index;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::release_vni_profile(la_switch::vxlan_termination_mode_e vni_profile)
{
    m_vxlan_vni_profile[(la_uint_t)vni_profile].refcount--;

    if (m_vxlan_vni_profile[(la_uint_t)vni_profile].refcount == 0) {
        const auto& table(m_tables.vlan_format_table);
        size_t max_size = table->max_size();
        for (int i = max_size - 1; i >= 0; i--) {
            size_t location = (size_t)i;
            npl_vlan_format_table_t::entry_pointer_type entry = nullptr;
            la_status status = table->get_entry(location, entry);
            if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
                return status;
            }
            if (entry == nullptr) {
                continue;
            }
            if (entry->key().vlan_profile == m_vxlan_vni_profile[(la_uint_t)vni_profile].index) {
                table->pop(location);
            }
        }
        m_index_generators.ac_profiles.release(m_vxlan_vni_profile[(la_uint_t)vni_profile].index);
        m_vxlan_vni_profile[(la_uint_t)vni_profile].index = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_ac_profile(la_ac_profile*& out_ac_profile)
{
    start_api_call("");
    // Allocate an AC profile index
    uint64_t index = 0;

    bool allocated = m_index_generators.ac_profiles.allocate(index);
    if (!allocated) {
        return LA_STATUS_ERESOURCE;
    }

    // Initialize the AC profile
    auto profile = std::make_shared<la_ac_profile_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(profile, oid);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.ac_profiles.release(index);
        return status;
    }

    status = profile->initialize(oid, index);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.ac_profiles.release(index);
        deregister_object(oid);
        return LA_STATUS_EUNKNOWN;
    }

    // Update mappings

    m_ac_profiles[index] = profile;
    out_ac_profile = profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_ac_profile(const la_ac_profile_impl_wptr& profile)
{
    if (profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(profile)) {
        return LA_STATUS_EBUSY;
    }

    uint64_t profile_id = profile->get_id();

    la_status status = profile->destroy();
    return_on_error(status);

    m_index_generators.ac_profiles.release(profile_id);
    m_ac_profiles[profile_id] = nullptr;

    return LA_STATUS_SUCCESS;
}

size_t
la_device_impl::get_num_of_available_ac_profiles() const
{
    return 0;
}

la_status
la_device_impl::get_l2_multicast_group(la_multicast_group_gid_t multicast_gid, la_l2_multicast_group*& out_l2_multicast_group) const
{
    start_api_getter_call();

    if (is_multicast_scale_mode_configured()) {
        // multicast scale mode allows larger MCIDs to be configured
        if (multicast_gid >= MAX_MC_SCALE_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
        if (is_scale_mode_smcid(multicast_gid)) {
            /* scaled multicast MCID is not supported for L2 multicast */
            return LA_STATUS_EINVAL;
        }
    } else {
        if (multicast_gid >= MAX_MC_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    }

    if (m_l2_multicast_groups[multicast_gid] == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_l2_multicast_group = m_l2_multicast_groups[multicast_gid].get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l2_multicast_group(la_multicast_group_gid_t multicast_gid,
                                          la_replication_paradigm_e rep_paradigm,
                                          la_l2_multicast_group*& out_l2_multicast_group)
{
    start_api_call("multicast_gid=", multicast_gid, "rep_paradigm=", rep_paradigm);

    if (is_multicast_scale_mode_configured()) {
        // multicast scale mode allows larger MCIDs to be configured
        if (multicast_gid >= MAX_MC_SCALE_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
        if (is_scale_mode_smcid(multicast_gid)) {
            /* scaled multicast MCID is not supported for L2 multicast */
            return LA_STATUS_EINVAL;
        }
    } else {
        if (multicast_gid >= MAX_MC_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    }

    if (m_l2_multicast_groups[multicast_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    auto mcg = std::make_shared<la_l2_multicast_group_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(mcg, oid);
    return_on_error(status);

    status = mcg->initialize(oid, multicast_gid, rep_paradigm);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    la_l2_destination_gid_t gid = get_l2_destination_gid(mcg);
    m_l2_destinations[gid] = mcg;
    m_l2_multicast_groups[multicast_gid] = mcg;
    out_l2_multicast_group = mcg.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_l2_multicast_group(const la_l2_multicast_group_base_wptr& group)
{
    if (group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l2_destination_gid_t gid = get_l2_destination_gid(group);
    la_multicast_group_gid_t group_id = group->get_gid();

    la_status status = group->destroy();
    return_on_error(status);

    m_l2_destinations[gid] = nullptr;
    m_l2_multicast_groups[group_id] = nullptr;

    return status;
}

la_status
la_device_impl::get_ip_multicast_group(la_multicast_group_gid_t multicast_gid, la_ip_multicast_group*& out_ip_multicast_group) const
{
    start_api_getter_call();

    if (is_multicast_scale_mode_configured()) {
        // multicast scale mode allows larger MCIDs to be configured
        if (multicast_gid >= MAX_MC_SCALE_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    } else {
        if (multicast_gid >= MAX_MC_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    }

    if (m_ip_multicast_groups[multicast_gid] == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_ip_multicast_group = m_ip_multicast_groups[multicast_gid].get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_create_ip_multicast_group(la_multicast_group_gid_t multicast_gid,
                                             la_replication_paradigm_e rep_paradigm,
                                             la_ip_multicast_group_gibraltar_wptr& out_ip_multicast_group)
{
    auto mcg = std::make_shared<la_ip_multicast_group_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(mcg, oid);
    return_on_error(status);

    status = mcg->initialize(oid, multicast_gid, rep_paradigm);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_ip_multicast_group = mcg;
    m_ip_multicast_groups[multicast_gid] = mcg;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_ip_multicast_group(la_multicast_group_gid_t multicast_gid,
                                          la_replication_paradigm_e rep_paradigm,
                                          la_ip_multicast_group*& out_ip_multicast_group)
{
    start_api_call("multicast_gid=", multicast_gid, "rep_paradigm=", rep_paradigm);

    if (is_multicast_scale_mode_configured()) {
        // multicast scale mode allows larger MCIDs to be configured
        if (multicast_gid >= MAX_MC_SCALE_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    } else {
        if (multicast_gid >= MAX_MC_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    }

    if (m_ip_multicast_groups[multicast_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    la_ip_multicast_group_gibraltar_wptr mcg_wptr;
    la_status status = do_create_ip_multicast_group(multicast_gid, rep_paradigm, mcg_wptr);
    return_on_error(status);

    out_ip_multicast_group = mcg_wptr.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_ip_multicast_group(const la_ip_multicast_group_base_wptr& group)
{
    if (group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const auto& group_impl = group.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_multicast_group_gid_t gid = group_impl->get_gid();

    la_status status = group_impl->destroy();
    return_on_error(status);

    m_ip_multicast_groups[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_fabric_multicast_group(la_multicast_group_gid_t multicast_gid,
                                           la_fabric_multicast_group*& out_fabric_multicast_group) const
{
    start_api_getter_call();

    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        log_err(HLD, "%s: This API function is relevant only for fabric-element devices.", __func__);
        return LA_STATUS_EINVAL;
    }

    if (is_multicast_scale_mode_configured()) {
        // multicast scale mode allows larger MCIDs to be configured
        if (multicast_gid >= MAX_MC_SCALE_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    } else {
        if (multicast_gid >= MAX_MC_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    }

    if (m_fabric_multicast_groups[multicast_gid] == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_fabric_multicast_group = m_fabric_multicast_groups[multicast_gid].get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_fabric_multicast_group(la_multicast_group_gid_t multicast_gid,
                                              la_replication_paradigm_e rep_paradigm,
                                              la_fabric_multicast_group*& out_fabric_multicast_group)
{
    start_api_call("multicast_gid=", multicast_gid, "rep_paradigm=", rep_paradigm);

    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        log_err(HLD, "%s: This API function is relevant only for fabric-element devices.", __func__);
        return LA_STATUS_EINVAL;
    }

    if (is_multicast_scale_mode_configured()) {
        // multicast scale mode allows larger MCIDs to be configured
        if (multicast_gid >= MAX_MC_SCALE_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    } else {
        if (multicast_gid >= MAX_MC_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    }

    if (m_fabric_multicast_groups[multicast_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    auto fmcg = std::make_shared<la_fabric_multicast_group_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(fmcg, oid);
    return_on_error(status);

    status = fmcg->initialize(oid, multicast_gid, rep_paradigm);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_fabric_multicast_group = fmcg.get();
    m_fabric_multicast_groups[multicast_gid] = fmcg;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_fabric_multicast_group(const la_fabric_multicast_group_impl_wptr& group)
{
    if (group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = group->destroy();
    return_on_error(status);

    la_multicast_group_gid_t multicast_gid = group->get_gid();
    m_fabric_multicast_groups[multicast_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_mpls_multicast_group(la_multicast_group_gid_t multicast_gid,
                                            la_replication_paradigm_e rep_paradigm,
                                            la_mpls_multicast_group*& out_mpls_multicast_group)
{
    start_api_call("multicast_gid=", multicast_gid, "rep_paradigm=", rep_paradigm);

    if (is_multicast_scale_mode_configured()) {
        // multicast scale mode allows larger MCIDs to be configured
        if (multicast_gid >= MAX_MC_SCALE_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
        if (is_scale_mode_smcid(multicast_gid)) {
            /* scaled multicast MCID is not supported for MPLS multicast */
            return LA_STATUS_EINVAL;
        }
    } else {
        if (multicast_gid >= MAX_MC_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    }

    if (m_mpls_multicast_groups[multicast_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    auto mcg = std::make_shared<la_mpls_multicast_group_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(mcg, oid);
    return_on_error(status);

    status = mcg->initialize(oid, multicast_gid, rep_paradigm);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_mpls_multicast_group = mcg.get();
    m_mpls_multicast_groups[multicast_gid] = mcg;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_mpls_multicast_group(const la_mpls_multicast_group_impl_wptr& group)
{
    start_api_call("group=", group);

    if (group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_multicast_group_gid_t gid = group->get_gid();

    la_status status = group->destroy();
    return_on_error(status);

    m_mpls_multicast_groups[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_mpls_multicast_group(la_multicast_group_gid_t multicast_gid,
                                         la_mpls_multicast_group*& out_mpls_multicast_group) const
{
    start_api_getter_call();

    if (is_multicast_scale_mode_configured()) {
        // multicast scale mode allows larger MCIDs to be configured
        if (multicast_gid >= MAX_MC_SCALE_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
        if (is_scale_mode_smcid(multicast_gid)) {
            /* scaled multicast MCID is not supported for MPLS multicast */
            return LA_STATUS_EINVAL;
        }
    } else {
        if (multicast_gid >= MAX_MC_GROUP_CONFIGURABLE) {
            return LA_STATUS_EINVAL;
        }
    }

    if (m_mpls_multicast_groups[multicast_gid] == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_mpls_multicast_group = m_mpls_multicast_groups[multicast_gid].get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_mpls_label_destination(la_l3_destination_gid_t gid,
                                              la_mpls_label label,
                                              la_l3_destination* destination,
                                              la_mpls_label_destination*& out_mpls_label_destination)
{
    start_api_call("gid=", gid, "label=", label, "destination=", destination);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::destroy_mpls_label_destination(const la_mpls_label_destination_impl_wptr& mpls_label_destination)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::clear_destination_gid_format(const la_l3_destination_gid_t gid)
{
    size_t native_lp_id = gid / 4;
    if (m_native_lp_table_format[native_lp_id].second) {
        m_native_lp_table_format[native_lp_id].second--;
    }

    if (m_native_lp_table_format[native_lp_id].second == 0) {
        m_native_lp_table_format[native_lp_id].first = resolution_lp_table_format_e::NONE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::update_destination_gid_format(const resolution_lp_table_format_e format, const la_l3_destination_gid_t gid)
{
    size_t native_lp_id = gid / 4;
    m_native_lp_table_format[native_lp_id].first = format;
    m_native_lp_table_format[native_lp_id].second++;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::validate_destination_gid_format_match(const resolution_lp_table_format_e format,
                                                      const la_l3_destination_gid_t gid,
                                                      bool is_init)
{
    if ((format == resolution_lp_table_format_e::WIDE) && ((gid % 4 >> 1) == 1)) {
        return LA_STATUS_EINVAL;
    }

    size_t native_lp_id = gid / 4;
    if (is_init) {
        if ((format != m_native_lp_table_format[native_lp_id].first) && (m_native_lp_table_format[native_lp_id].second)) {
            return LA_STATUS_EBUSY;
        }

        return LA_STATUS_SUCCESS;
    }

    if ((format != m_native_lp_table_format[native_lp_id].first)) {
        if (m_native_lp_table_format[native_lp_id].second > 1) {
            return LA_STATUS_EBUSY;
        }

        if ((format == resolution_lp_table_format_e::WIDE)
            && ((m_prefix_objects[round_down(gid, 4) + 2] != nullptr) || (m_prefix_objects[round_down(gid, 4) + 3] != nullptr))) {
            return LA_STATUS_EBUSY;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_prefix_object(la_l3_destination_gid_t gid,
                                     const la_l3_destination* destination,
                                     la_prefix_object::prefix_type_e type,
                                     la_prefix_object*& out_prefix_object)
{
    start_api_call("gid=", gid, "destination=", destination, "prefix_type=", type);

    if (gid >= MAX_PREFIX_OBJECT_GIDS) {
        return LA_STATUS_EINVAL;
    }

    if (m_prefix_objects[gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if (m_destination_pes[gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    auto pfx_obj = std::make_shared<la_prefix_object_gibraltar>(shared_from_this());

    la_l3_destination_gid_t lpm_dest_gid = NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK | gid;
    if (get_pbts_start_id() > gid) {
        if (m_l3_destinations[lpm_dest_gid] != nullptr) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    la_object_id_t oid;
    la_status status = register_object(pfx_obj, oid);
    return_on_error(status);

    status = pfx_obj->initialize(oid, gid, get_sptr(destination), type);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    if (get_pbts_start_id() > gid) {
        m_l3_destinations[lpm_dest_gid] = pfx_obj;
    }
    m_prefix_objects[gid] = pfx_obj;
    out_prefix_object = pfx_obj.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_prefix_object(const la_prefix_object_base_wptr& prefix_object)
{
    if (!of_same_device(prefix_object, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l3_destination_gid_t gid = prefix_object->get_gid();
    la_l3_destination_gid_t lpm_gid = get_l3_destination_gid(prefix_object, true /* is_lpm_destination */);

    if (get_pbts_start_id() > gid) {
        if (m_l3_destinations[lpm_gid] != prefix_object) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    la_status status = prefix_object->destroy();
    return_on_error(status);

    status = clear_destination_gid_format(gid);
    return_on_error(status);

    m_prefix_objects[gid] = nullptr;
    m_l3_destinations[lpm_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_prefix_object_by_id(la_l3_destination_gid_t gid, la_prefix_object*& out_prefix) const
{
    if (gid >= MAX_PREFIX_OBJECT_GIDS) {
        return LA_STATUS_EINVAL;
    }

    const auto& pfx_obj = m_prefix_objects[gid].weak_ptr_static_cast<la_prefix_object>();
    if (pfx_obj == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    if (pfx_obj->type() != object_type_e::PREFIX_OBJECT) {
        return LA_STATUS_ENOTFOUND;
    }

    out_prefix = pfx_obj.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_ip_tunnel_destination(la_l3_destination_gid_t gid,
                                             const la_l3_port* ip_tunnel_port,
                                             const la_l3_destination* underlay_destination,
                                             la_ip_tunnel_destination*& out_ip_tunnel_destination)
{
    start_api_call("gid=", gid, "ip_tunnel_port=", ip_tunnel_port, "underlay_destination=", underlay_destination);

    if (gid >= MAX_PREFIX_OBJECT_GIDS) {
        return LA_STATUS_EINVAL;
    }

    if (m_prefix_objects[gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    auto tunnel_dest = std::make_shared<la_ip_tunnel_destination_impl>(shared_from_this());

    la_l3_destination_gid_t lpm_dest_gid = NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK | gid;
    if (m_l3_destinations[lpm_dest_gid] != nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    la_object_id_t oid;
    la_status status = register_object(tunnel_dest, oid);
    return_on_error(status);
    status = tunnel_dest->initialize(oid, gid, get_sptr(ip_tunnel_port), get_sptr(underlay_destination));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_l3_destinations[lpm_dest_gid] = tunnel_dest;
    m_prefix_objects[gid] = tunnel_dest;
    out_ip_tunnel_destination = tunnel_dest.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_ip_tunnel_destination(const la_ip_tunnel_destination_impl_wptr& ip_tunnel_destination)
{
    if (!of_same_device(ip_tunnel_destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l3_destination_gid_t gid = ip_tunnel_destination->get_gid();
    la_l3_destination_gid_t lpm_gid = get_l3_destination_gid(ip_tunnel_destination, true /* is_lpm_destination */);

    if (m_l3_destinations[lpm_gid] != ip_tunnel_destination) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = ip_tunnel_destination->destroy();
    return_on_error(status);

    status = clear_destination_gid_format(gid);
    return_on_error(status);

    m_prefix_objects[gid] = nullptr;
    m_l3_destinations[lpm_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_ip_tunnel_destination_by_gid(la_l3_destination_gid_t gid,
                                                 la_ip_tunnel_destination*& out_ip_tunnel_destination) const
{
    if (gid >= MAX_PREFIX_OBJECT_GIDS) {
        return LA_STATUS_EINVAL;
    }

    const auto& tunnel_dest = m_prefix_objects[gid].weak_ptr_static_cast<la_ip_tunnel_destination>();
    if (tunnel_dest == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    if (tunnel_dest->type() != object_type_e::IP_TUNNEL_DESTINATION) {
        return LA_STATUS_ENOTFOUND;
    }

    out_ip_tunnel_destination = tunnel_dest.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_destination_pe(la_l3_destination_gid_t destination_pe_gid,
                                      const la_l3_destination* destination,
                                      la_destination_pe*& out_destination_pe)
{
    start_api_call("destination_pe_gid=", destination_pe_gid, "destination=", destination);

    if (destination_pe_gid >= MAX_PREFIX_OBJECT_GIDS) {
        return LA_STATUS_EINVAL;
    }

    if (m_destination_pes[destination_pe_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if (m_prefix_objects[destination_pe_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    auto destination_pe = std::make_shared<la_destination_pe_impl>(shared_from_this());

    la_l3_destination_gid_t lpm_dest_gid = NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK | destination_pe_gid;
    if (m_l3_destinations[lpm_dest_gid] != nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    la_object_id_t oid;
    la_status status = register_object(destination_pe, oid);
    return_on_error(status);
    const auto& destination_sp = get_sptr(destination);
    status = destination_pe->initialize(oid, destination_pe_gid, destination_sp);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_l3_destinations[lpm_dest_gid] = destination_pe;
    m_destination_pes[destination_pe_gid] = destination_pe;
    out_destination_pe = destination_pe.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_destination_pe(const la_destination_pe_impl_wptr& destination_pe)
{
    if (!of_same_device(destination_pe, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    uint64_t destination_pe_gid = destination_pe->get_gid();
    la_l3_destination_gid_t lpm_gid = get_l3_destination_gid(destination_pe, true /* is_lpm_destination */);

    if (m_l3_destinations[lpm_gid] != destination_pe) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = destination_pe->destroy();
    return_on_error(status);

    status = clear_destination_gid_format(destination_pe_gid);
    return_on_error(status);

    m_destination_pes[destination_pe_gid] = nullptr;
    m_l3_destinations[lpm_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::check_asbr_lsps(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination)
{
    auto asbr_lsp_map_entry_it = m_asbr_lsp_map.find(std::make_pair(asbr, destination));
    if (asbr_lsp_map_entry_it == m_asbr_lsp_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    return LA_STATUS_EEXIST;
}

la_status
la_device_impl::update_asbr_lsp(const la_prefix_object_wcptr& asbr,
                                const la_l3_destination_wcptr& destination,
                                const la_asbr_lsp_wptr& asbr_lsp)
{
    m_asbr_lsp_map[std::make_pair(asbr, destination)] = asbr_lsp;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_asbr_lsp(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination)
{
    m_asbr_lsp_map.erase(std::make_pair(asbr, destination));

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_asbr_lsp(const la_prefix_object* asbr, const la_l3_destination* destination, la_asbr_lsp*& out_asbr_lsp)
{
    start_api_call("asbr=", asbr, "destination=", destination);

    if (asbr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(asbr, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const auto& asbr_sp = get_sptr(asbr);
    const auto& destination_sp = get_sptr(destination);
    la_status status = check_asbr_lsps(asbr_sp, destination_sp);
    if (status == LA_STATUS_EEXIST) {
        return status;
    }

    auto asbr_lsp = std::make_shared<la_asbr_lsp_impl>(shared_from_this());

    la_object_id_t oid;
    status = register_object(asbr_lsp, oid);
    return_on_error(status);

    status = asbr_lsp->initialize(oid, asbr_sp, destination_sp);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    status = update_asbr_lsp(asbr_sp, destination_sp, asbr_lsp);
    return_on_error(status);
    out_asbr_lsp = asbr_lsp.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_asbr_lsp(const la_prefix_object* asbr, const la_l3_destination* destination, la_asbr_lsp*& out_asbr_lsp)
{
    start_api_getter_call();

    if (asbr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_prefix_object_wcptr asbr_wptr = get_sptr(asbr);
    la_l3_destination_wcptr destination_wptr = get_sptr(destination);

    if (!of_same_device(asbr_wptr, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!of_same_device(destination_wptr, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto asbr_lsp_map_entry_it = m_asbr_lsp_map.find(std::make_pair(get_sptr(asbr), get_sptr(destination)));
    if (asbr_lsp_map_entry_it == m_asbr_lsp_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    out_asbr_lsp = asbr_lsp_map_entry_it->second.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_asbr_lsp(const la_asbr_lsp_impl_wptr& asbr_lsp)
{
    if (asbr_lsp == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(asbr_lsp, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = asbr_lsp->destroy();
    return_on_error(status);

    const auto& asbr_sp = get_sptr(asbr_lsp->get_asbr());
    const auto& destination_sp = get_sptr(asbr_lsp->get_destination());
    m_asbr_lsp_map.erase(std::make_pair(asbr_sp, destination_sp));

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_te_tunnel(la_te_tunnel_gid_t gid,
                                 const la_l3_destination* destination,
                                 la_te_tunnel::tunnel_type_e type,
                                 la_te_tunnel*& out_te_tunnel)
{
    start_api_call("gid=", gid, "destination=", destination, "tunnel_type=", type);

    if (gid >= MAX_TE_TUNNEL_GIDS) {
        return LA_STATUS_EINVAL;
    }

    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_te_tunnels[gid] != nullptr) {

        return LA_STATUS_EEXIST;
    }

    auto te_tunnel_obj = std::make_shared<la_te_tunnel_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(te_tunnel_obj, oid);
    return_on_error(status);

    status = te_tunnel_obj->initialize(oid, gid, get_sptr(destination), type);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_te_tunnels[gid] = te_tunnel_obj;
    out_te_tunnel = te_tunnel_obj.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_te_tunnel(const la_te_tunnel_impl_wptr& te_tunnel)
{
    if (!of_same_device(te_tunnel, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_te_tunnel_gid_t gid = te_tunnel->get_gid();

    la_status status = te_tunnel->destroy();
    return_on_error(status);

    m_te_tunnels[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_pbts_map_profile(la_pbts_map_profile::level_e level,
                                        la_pbts_destination_offset max_offset,
                                        la_pbts_map_profile*& out_pbts_map_profile)
{
    start_api_call("level=", level, "max_offset=", max_offset);

    if (level != la_pbts_map_profile::level_e::LEVEL_0) {
        return LA_STATUS_EINVAL;
    }

    auto map_profile = std::make_shared<la_pbts_map_profile_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(map_profile, oid);
    return_on_error(status);

    status = map_profile->initialize(oid, level, max_offset);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_pbts_map_profile = map_profile.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_pbts_map_profile(const la_pbts_map_profile_impl_wptr& profile)
{
    if (profile->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = profile->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_pbts_group(la_pbts_map_profile* profile, la_pbts_group*& out_pbts_group)
{

    start_api_call("profile=", profile);

    if (profile->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }
    auto group = std::make_shared<la_pbts_group_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(group, oid);
    return_on_error(status);

    status = group->initialize(oid, profile);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_pbts_group = group.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_pbts_group(const la_pbts_group_impl_wptr& group)
{
    if (group->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = group->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_lsr(la_lsr*& out_lsr)
{
    out_lsr = m_lsr.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode)
{
    start_api_call("mode=", mode);
    for (const auto& l3_port : m_l3_ports) {
        if (l3_port == nullptr) {
            continue;
        }
        la_object::object_type_e l3_port_type = l3_port->type();
        switch (l3_port_type) {
        case la_object::object_type_e::L3_AC_PORT: {
            const auto& ac_port = l3_port.weak_ptr_static_cast<la_l3_ac_port_impl>();
            la_status status = ac_port->set_ttl_inheritance_mode(mode);
            return_on_error(status);
            break;
        }
        case la_object::object_type_e::SVI_PORT: {
            const auto& svi_port = l3_port.weak_ptr_static_cast<la_svi_port_base>();
            la_status status = svi_port->set_ttl_inheritance_mode(mode);
            return_on_error(status);
            break;
        }
        case la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT: {
            break;
        }
        case la_object::object_type_e::GRE_PORT: {
            break;
        }
        case la_object::object_type_e::GUE_PORT: {
            break;
        }

        default:
            return LA_STATUS_EUNKNOWN;
        }
    }

    for (const auto& system_port : m_system_ports) {
        if (system_port == nullptr) {
            continue;
        }
        const auto& system_port_base = system_port.weak_ptr_static_cast<la_system_port_base>();
        la_status status = system_port_base->set_ttl_inheritance_mode(mode);
        return_on_error(status);
    }

    m_ttl_inheritance_mode = mode;
    return LA_STATUS_SUCCESS;
}

la_mpls_ttl_inheritance_mode_e
la_device_impl::get_ttl_inheritance_mode() const
{
    return m_ttl_inheritance_mode;
}

la_status
la_device_impl::get_forus_destination(la_forus_destination*& out_forus_destination)
{
    out_forus_destination = m_forus_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_fabric_mode(la_fabric_mode_e mode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::set_slb_fabric_delay(la_float_t delay)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::set_ifg_maximum_pps_utilization(la_float_t max_pps_percent)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_ifg_maximum_pps_utilization(la_float_t& out_max_pps_percent) const
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_ifg_scheduler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_ifg_scheduler*& out_sch) const
{
    out_sch = nullptr;

    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(status);

    out_sch = m_ifg_schedulers[slice_id][ifg_id].get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_output_queue_scheduler(la_slice_id_t slice,
                                              la_ifg_id_t ifg,
                                              la_output_queue_scheduler::scheduling_mode_e mode,
                                              la_output_queue_scheduler*& out_oq_sch)
{
    start_api_call("slice=", slice, "ifg=", ifg, "mode=", mode);
    index_handle oqse_id(m_index_generators.output_queue_scheduler[slice][ifg], tm_utils::scheduling_mode_is_8p(mode));

    if (!oqse_id) {
        log_err(HLD, "Failed to allocate output queue scheduler ID for slice %d ifg %d", slice, ifg);
        return LA_STATUS_ERESOURCE;
    }

    la_output_queue_scheduler_impl_sptr oq_sch;
    auto status = do_create_output_queue_scheduler(slice, ifg, std::move(oqse_id), mode, oq_sch);
    return_on_error(status);

    out_oq_sch = oq_sch.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_output_queue_scheduler(const la_output_queue_scheduler_impl_wptr& oq_sch)
{
    if (oq_sch == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(oq_sch, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = oq_sch->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

size_t
la_device_impl::get_native_voq_sets_index(la_voq_gid_t base_voq_id) const
{
    return round_down(base_voq_id, NATIVE_VOQ_SET_SIZE) / NATIVE_VOQ_SET_SIZE;
}

bool
la_device_impl::check_and_set_vsc_is_busy_list(const native_voq_set_desc& voq_set_desc,
                                               size_t set_size,
                                               bool check_only,
                                               bool value)
{
    bool any = false;

    // This may be the first time a destination device is queried.
    if (m_vsc_is_busy[voq_set_desc.dest_device] == nullptr) {
        // If the destination device doesn't exist yet, and check_only then the VSC is not busy
        if (check_only) {
            return false;
        }
        // Else create an entry for the destination device
        // TODO - the destination device usage object is not freed when its no longer needed.
        m_vsc_is_busy[voq_set_desc.dest_device] = silicon_one::make_unique<vsc_device_usage_t>();
    }

    vsc_device_usage_t& vsc_device_usage(*m_vsc_is_busy[voq_set_desc.dest_device]);

    for (la_slice_id_t src_slice : get_used_slices()) {
        if (!is_network_slice(src_slice)) {
            continue;
        }

        for (la_vsc_gid_t i = voq_set_desc.base_vsc_vec[src_slice]; i < voq_set_desc.base_vsc_vec[src_slice] + set_size; i++) {
            any |= vsc_device_usage[voq_set_desc.dest_slice][voq_set_desc.dest_ifg][i];
            if (!check_only) {
                vsc_device_usage[voq_set_desc.dest_slice][voq_set_desc.dest_ifg][i] = value;
            }
        }
    }

    return any;
}

la_status
la_device_impl::native_voq_set_and_vsc_is_busy_list_add(la_voq_gid_t base_voq_id,
                                                        size_t set_size,
                                                        const native_voq_set_desc& voq_set_desc)
{
    la_voq_gid_t native_base_voq = round_down(base_voq_id, NATIVE_VOQ_SET_SIZE);
    la_vsc_gid_vec_t native_base_vsc_vec = la_vsc_gid_vec_t(ASIC_MAX_SLICES_PER_DEVICE_NUM, 0);
    size_t offset = base_voq_id - native_base_voq;

    // No spanning over multiple native sets
    if ((offset + set_size) > NATIVE_VOQ_SET_SIZE) {
        return LA_STATUS_EINVAL;
    }

    // Verify that the requested VSCs are free
    if (check_and_set_vsc_is_busy_list(voq_set_desc, set_size, true /* check_only */, true /* value */)) {
        return LA_STATUS_EBUSY;
    }

    for (la_slice_id_t src_slice : get_used_slices()) {
        if (voq_set_desc.base_vsc_vec[src_slice] == LA_VSC_GID_INVALID) {
            native_base_vsc_vec[src_slice] = LA_VSC_GID_INVALID;
        } else {
            native_base_vsc_vec[src_slice] = round_down(voq_set_desc.base_vsc_vec[src_slice], NATIVE_VOQ_SET_SIZE);
        }
    }

    // Add the new VOQ set to the list of native-VOQ sets
    la_status status = native_voq_set_list_add(base_voq_id, offset, set_size, voq_set_desc);
    return_on_error(status);

    // Mark the requested VSC's as busy
    check_and_set_vsc_is_busy_list(voq_set_desc, set_size, false /* check_only */, true /* value */);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::native_voq_set_list_add(la_voq_gid_t base_voq_id,
                                        size_t offset,
                                        size_t set_size,
                                        const native_voq_set_desc& voq_set_desc)
{
    native_voq_set_desc& desc(m_native_voq_sets[get_native_voq_sets_index(base_voq_id)]);
    if (desc.is_busy.none()) {
        // Init a new native VOQ set descriptor
        desc = voq_set_desc;
    } else {
        // Verify the new set matches the existing native set
        if (desc != voq_set_desc) {
            return LA_STATUS_EINVAL;
        }

        // Verify that the requested VOQ's are free
        for (size_t i = offset; i < offset + set_size; i++) {
            if (desc.is_busy[i]) {
                return LA_STATUS_EBUSY;
            }
        }
    }

    // Mark the requested VOQ's as busy
    for (size_t i = offset; i < offset + set_size; i++) {
        desc.is_busy[i] = true;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_voq_set(la_voq_gid_t base_voq_id,
                               size_t set_size,
                               const la_vsc_gid_vec_t& base_vsc_vec,
                               la_device_id_t dest_device,
                               la_slice_id_t dest_slice,
                               la_ifg_id_t dest_ifg,
                               la_voq_set*& out_voq_set)
{
    start_api_call("base_voq_id=",
                   base_voq_id,
                   "set_size=",
                   set_size,
                   "base_vsc_vec=",
                   base_vsc_vec,
                   "dest_device=",
                   dest_device,
                   "dest_slice=",
                   dest_slice,
                   "dest_ifg=",
                   dest_ifg);

    if (dest_slice >= ASIC_MAX_SLICES_PER_DEVICE_NUM) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Verify arguments
    if ((dest_device >= MAX_DEVICES) || (dest_ifg >= NUM_IFGS_PER_SLICE)) {
        return LA_STATUS_EOUTOFRANGE;
    }

    for (la_slice_id_t src_slice : get_used_slices()) {
        if (!is_network_slice(src_slice)) {
            if (base_vsc_vec[src_slice] != LA_VSC_GID_INVALID) {
                // Base VSC must be LA_VSC_GID_INVALID for non-network slice
                log_err(HLD, "Base VSC must be LA_VSC_GID_INVALID for non-network slice (%d)", src_slice);
                return LA_STATUS_EINVAL;
            }
            continue;
        }

        if (!is_voq_id_in_range(src_slice, base_voq_id) || !is_voq_id_in_range(src_slice, base_voq_id + set_size - 1)) {
            log_err(HLD, "VOQ ID is not in range (slice %d, VOQ ID %d)", src_slice, base_voq_id);
            return LA_STATUS_EINVAL;
        }

        if (!is_vsc_id_in_range(dest_slice, base_vsc_vec[src_slice])
            || !is_vsc_id_in_range(dest_slice, base_vsc_vec[src_slice] + set_size)) {
            log_err(HLD, "VSC ID is not in range (slice %d, VSC ID %d)", dest_slice, base_vsc_vec[src_slice]);
            return LA_STATUS_EINVAL;
        }
    }

    la_voq_set_wptr voq_set_wptr = nullptr;
    la_status status = do_create_voq_set(base_voq_id, set_size, base_vsc_vec, dest_device, dest_slice, dest_ifg, voq_set_wptr);
    return_on_error(status);

    out_voq_set = voq_set_wptr.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_create_voq_set(la_voq_gid_t base_voq_id,
                                  size_t set_size,
                                  const la_vsc_gid_vec_t& base_vsc_vec,
                                  la_device_id_t dest_device,
                                  la_slice_id_t dest_slice,
                                  la_ifg_id_t dest_ifg,
                                  la_voq_set_wptr& out_voq_set)
{
    native_voq_set_desc voq_set_desc = native_voq_set_desc(base_vsc_vec, dest_device, dest_slice, dest_ifg);
    // Try to add the new VOQ-set to the list of native VOQ sets
    la_status status = native_voq_set_and_vsc_is_busy_list_add(base_voq_id, set_size, voq_set_desc);
    return_on_error(status);

    // Create the VOQ-set object
    auto voq_set = std::make_shared<la_voq_set_impl>(shared_from_this());

    la_object_id_t oid;
    status = register_object(voq_set, oid);
    if (status != LA_STATUS_SUCCESS) {
        native_voq_set_and_vsc_is_busy_list_remove(voq_set);
        return status;
    }

    status = voq_set->initialize(oid, base_voq_id, set_size, base_vsc_vec, dest_device, dest_slice, dest_ifg);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        native_voq_set_and_vsc_is_busy_list_remove(voq_set);
        return status;
    }

    m_voq_sets[base_voq_id] = voq_set;
    out_voq_set = voq_set;

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::native_voq_set_and_vsc_is_busy_list_remove(const la_voq_set_wcptr& voq_set_in)
{
    la_voq_set_base_wcptr voq_set = voq_set_in.weak_ptr_static_cast<const la_voq_set_base>();
    size_t set_size = voq_set->get_set_size();
    la_voq_gid_t base_voq_id = voq_set->get_base_voq_id();
    la_voq_gid_t native_base_voq = round_down(base_voq_id, NATIVE_VOQ_SET_SIZE);
    size_t offset = base_voq_id - native_base_voq;
    la_vsc_gid_vec_t base_vsc_vec = voq_set->get_base_vsc_vec();

    // Mark the requested VOQs as free
    native_voq_set_desc& desc(m_native_voq_sets[get_native_voq_sets_index(base_voq_id)]);
    for (size_t i = offset; i < offset + set_size; i++) {
        desc.is_busy[i] = false;
    }

    // Create descriptor for provided VOQ set, not native.
    native_voq_set_desc voq_set_desc = native_voq_set_desc((const la_vsc_gid_vec_t)base_vsc_vec,
                                                           voq_set->get_destination_device(),
                                                           voq_set->get_destination_slice(),
                                                           voq_set->get_destination_ifg());

    // Mark the requested VSCs as free
    check_and_set_vsc_is_busy_list(voq_set_desc, set_size, false /* check_only */, false /* value */);
}

la_status
la_device_impl::destroy_voq_set(const la_voq_set_impl_wptr& voq_set)
{
    if (voq_set == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(voq_set, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_voq_gid_t base_voq_id = voq_set->get_base_voq_id();
    la_status status = voq_set->destroy();
    return_on_error(status);

    native_voq_set_and_vsc_is_busy_list_remove(voq_set);
    m_voq_sets[base_voq_id] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_voq_counter_set(la_voq_set::voq_counter_type_e type,
                                       size_t group_size,
                                       la_counter_set* counter,
                                       la_voq_gid_t base_voq_id,
                                       size_t voq_set_size)
{
    size_t voq_counter_set_id = base_voq_id / voq_counter_set::NUM_VOQS_IN_SET;

    voq_counter_set_sptr& vcs(m_voq_counter_sets[voq_counter_set_id]);
    if (!vcs) {
        // Create the VOQ-counter-set object
        vcs = make_shared<voq_counter_set>(shared_from_this());
    }

    la_status status = vcs->register_voq_counter_set_user(type, group_size, base_voq_id, voq_set_size, counter->get_set_size());
    if (status != LA_STATUS_SUCCESS) {
        bool has_users = vcs->get_registered_voq_counter_set_users();
        if (has_users) {
            return status;
        }

        vcs.reset();
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_voq_counter_set(la_voq_gid_t base_voq_id, size_t voq_set_size)
{
    size_t voq_counter_set_id = base_voq_id / voq_counter_set::NUM_VOQS_IN_SET;

    voq_counter_set_sptr& vcs(m_voq_counter_sets[voq_counter_set_id]);
    if (!vcs) {
        return LA_STATUS_EINVAL;
    }

    la_status status = vcs->deregister_voq_counter_set_user(base_voq_id, voq_set_size);
    return_on_error(status);

    if (vcs->get_registered_voq_counter_set_users()) {
        return LA_STATUS_SUCCESS;
    }

    status = vcs->destroy();
    return_on_error(status);

    vcs.reset();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_npu_error_counter(la_counter_set*& out_counter)
{
    start_api_getter_call();
    out_counter = m_lookup_error_drop_dsp_counter.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_forwarding_drop_counter(la_counter_set*& out_counter)
{
    start_api_getter_call();

    out_counter = m_rx_drop_dsp_counter.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_tc_profile(la_tc_profile*& out_tc_profile)
{
    start_api_call("");

    la_tc_profile_impl_wptr tc_profile;
    la_status status = do_create_tc_profile(tc_profile);
    return_on_error(status);

    out_tc_profile = tc_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_create_tc_profile(la_tc_profile_impl_wptr& out_tc_profile)
{
    auto profile = std::make_shared<la_tc_profile_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(profile, oid);
    return_on_error(status);

    status = profile->initialize(oid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_tc_profile = profile;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_tc_profile(const la_tc_profile_impl_wptr& tc_profile)
{
    if (tc_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(tc_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(tc_profile)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = tc_profile->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::update_mc_bitmap_base_voq_lookup_table(la_slice_id_t dest_slice)
{
    // Update the VOQ lookup table
    const auto& table(m_tables.mc_bitmap_base_voq_lookup_table);
    npl_mc_bitmap_base_voq_lookup_table_key_t key;
    npl_mc_bitmap_base_voq_lookup_table_value_t value;
    npl_mc_bitmap_base_voq_lookup_table_entry_t* entry = nullptr;

    key.rxpdr_local_vars_current_slice = dest_slice;
    value.payloads.mc_bitmap_base_voq_lookup_table_result.base_voq
        = m_egress_multicast_slice_replication_voq_set[dest_slice]->get_base_voq_id();

    value.payloads.mc_bitmap_base_voq_lookup_table_result.tc_map_profile = MC_SLICE_REPLICATION_TC_PROFILE;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    return status;
}

la_status
la_device_impl::get_mc_bitmap_base_lookup_table_values(la_slice_id_t dest_slice,
                                                       uint64_t& out_tc_map_profile,
                                                       uint64_t& out_base_voq)
{

    if (m_device_mode == device_mode_e::STANDALONE) {
        out_base_voq = m_egress_multicast_slice_replication_voq_set[dest_slice]->get_base_voq_id();
    }

    if (m_device_mode == device_mode_e::LINECARD) {
        out_base_voq = m_egress_multicast_fabric_replication_voq_set->get_base_voq_id();
    }

    out_tc_map_profile = MC_SLICE_REPLICATION_TC_PROFILE;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::remove_egress_multicast_slice_replication_voq_set_from_filb_table(la_slice_id_t dest_slice)
{
    if (m_egress_multicast_slice_replication_voq_set[dest_slice] == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    for (la_slice_id_t table_slice_id : get_used_slices()) {
        if (m_slice_mode[table_slice_id] != la_slice_mode_e::NETWORK) {
            continue;
        }

        // Update the FILB VOQ mapping table
        const auto& table(m_tables.filb_voq_mapping[table_slice_id]);
        npl_filb_voq_mapping_t::key_type key;

        for (la_uint_t voq_offset = 0; voq_offset < NUM_SA_MC_VOQS; voq_offset++) {
            key.rxpdr_output_voq_nr = m_egress_multicast_slice_replication_voq_set[dest_slice]->get_base_voq_id() + voq_offset;
            la_status status = table->erase(key);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::add_egress_multicast_slice_replication_voq_set_to_filb_table(la_slice_id_t dest_slice)
{
    if (m_egress_multicast_slice_replication_voq_set[dest_slice] == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    for (la_slice_id_t table_slice_id : get_used_slices()) {
        if (m_slice_mode[table_slice_id] != la_slice_mode_e::NETWORK) {
            continue;
        }

        // Update the FILB VOQ mapping table
        const auto& table(m_tables.filb_voq_mapping[table_slice_id]);
        npl_filb_voq_mapping_t::key_type key;
        npl_filb_voq_mapping_t::value_type value;
        npl_filb_voq_mapping_t::entry_pointer_type entry = nullptr;

        value.payloads.filb_voq_mapping_result.dest_slice = dest_slice;
        value.payloads.filb_voq_mapping_result.dest_dev = NPL_LOCAL_DEVICE_ID;

        for (la_uint_t voq_offset = 0; voq_offset < NUM_SA_MC_VOQS; voq_offset++) {
            key.rxpdr_output_voq_nr = m_egress_multicast_slice_replication_voq_set[dest_slice]->get_base_voq_id() + voq_offset;
            if (voq_offset < FIRST_HIGH_PRIORITY_MC_VOQ_OFFSET) { // Low priority
                value.payloads.filb_voq_mapping_result.dest_oq = MC_OQ_ID_LO_PRIORITY;
            } else { // High priority
                value.payloads.filb_voq_mapping_result.dest_oq = MC_OQ_ID_HI_PRIORITY;
            }
            la_status status = table->set(key, value, entry);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_mc_bitmap_tc_map_table_per_tc(la_traffic_class_t tc, la_uint_t voq_offset)
{
    const auto& table(m_tables.mc_bitmap_tc_map_table);
    npl_mc_bitmap_tc_map_table_key_t key;
    npl_mc_bitmap_tc_map_table_value_t value;
    npl_mc_bitmap_tc_map_table_entry_t* entry = nullptr;

    key.mc_bitmap_base_voq_lookup_table_result_tc_map_profile = MC_SLICE_REPLICATION_TC_PROFILE;
    key.rxpp_pd_tc = tc;

    value.payloads.rxpdr_local_vars_tc_offset = voq_offset;

    la_status status = table->set(key, value, entry);

    return status;
}

la_status
la_device_impl::configure_mc_emdb_tc_map_table_per_tc(la_traffic_class_t tc, la_uint_t voq_offset)
{
    const auto& table(m_tables.mc_emdb_tc_map_table);
    npl_mc_emdb_tc_map_table_key_t key;
    npl_mc_emdb_tc_map_table_value_t value;
    npl_mc_emdb_tc_map_table_entry_t* entry = nullptr;

    key.rxpdr_local_vars_tc_map_profile_1_0_ = MC_SLICE_REPLICATION_TC_PROFILE;
    key.rxpp_pd_tc = tc;

    value.payloads.rxpdr_local_vars_tc_offset = voq_offset;

    la_status status = table->set(key, value, entry);

    return status;
}

la_status
la_device_impl::get_system_recycle_port(la_multicast_group_gid_t smcid, la_system_port_wcptr& out_sys_recycle_port)
{
    size_t ifg_idx = 0; // <slice> * NUM_IFGS_PER_SLICE_OBSOLETE + <ifg>

    // Gibraltar boards have 6 recycle ports configured, 1 per IFG, per slice
    switch (smcid) {
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_0:
        ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(0, 0);
        break;
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_1:
        ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(0, 1);
        break;
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_0:
        ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(1, 0);
        break;
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_1:
        ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(1, 1);
        break;
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_0:
        ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(2, 0);
        break;
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_1:
        ifg_idx = m_slice_id_manager->slice_ifg_2_global_ifg(2, 1);
        break;
    }

    out_sys_recycle_port = m_rcy_system_ports[ifg_idx];
    if (out_sys_recycle_port == nullptr) {
        log_err(HLD, "Unable to find a recycle port for smcid=%d", smcid);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_system_port_base_wcptr
la_device_impl::allocate_punt_recycle_port(const la_system_port_base_wcptr& target_port)
{
    slice_ifg_vec_t possible_ifgs;
    possible_ifgs = get_possible_rcy_port_slice(target_port->get_slice());
    if (target_port->get_port_type() != la_system_port_base::port_type_e::PCI) {
        auto all_s_ifgs = m_slice_id_manager->get_used_ifgs();
        possible_ifgs.reserve(possible_ifgs.size() + all_s_ifgs.size());
        possible_ifgs.insert(possible_ifgs.end(), all_s_ifgs.begin(), all_s_ifgs.end());
    }

    // look for a recycle port that points at the target
    for (auto s_ifg : possible_ifgs) {
        if (!m_punt_recycle_port_exist[s_ifg.slice]) {
            auto gifg = get_slice_id_manager()->slice_ifg_2_global_ifg(s_ifg);
            if (m_rcy_system_ports[gifg] != nullptr) {
                m_punt_recycle_port_exist[s_ifg.slice] = true;
                return m_rcy_system_ports[gifg];
            }
        }
    }

    // no free port
    return nullptr;
}

void
la_device_impl::release_punt_recycle_port(const la_system_port_base_wcptr& rcy_sys_port)
{
    auto slice = rcy_sys_port->get_slice();
    dassert_crit(m_punt_recycle_port_exist[slice]);
    m_punt_recycle_port_exist[slice] = false;
}

bool
la_device_impl::is_multicast_groups_configured() const
{
    auto fabric_mc_groups = get_objects(object_type_e::FABRIC_MULTICAST_GROUP);
    auto ip_mc_groups = get_objects(object_type_e::IP_MULTICAST_GROUP);
    auto l2_mc_groups = get_objects(object_type_e::L2_MULTICAST_GROUP);
    auto mpls_mc_groups = get_objects(object_type_e::MPLS_MULTICAST_GROUP);

    if ((fabric_mc_groups.size() > 0) || (ip_mc_groups.size() > 0) || (l2_mc_groups.size() > 0) || (mpls_mc_groups.size() > 0)) {
        return true;
    }
    return false;
}

la_status
la_device_impl::multicast_reserved_smcid_fabric_slice_bitmap(la_multicast_group_gid_t smcid, uint32_t& out_slice_bitmap)
{
    if (!is_reserved_smcid(smcid)) {
        return LA_STATUS_EINVAL;
    }

    if (smcid == MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE) {
        // the to_fabric MCID should never come from_fabric
        out_slice_bitmap = 0;
        return LA_STATUS_SUCCESS;
    }

    // gibraltar boards have 6 recycle ports configured, 1 per IFG, per slice
    switch (smcid) {
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_0:
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_1:
        out_slice_bitmap = (1 << 0); // slice 0
        break;
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_0:
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_1:
        out_slice_bitmap = (1 << 1); // slice 1
        break;
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_0:
    case la_device_impl::MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_1:
        out_slice_bitmap = (1 << 2); // slice 2
        break;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::multicast_reserved_smcid_to_local_mcid(la_multicast_group_gid_t smcid, la_multicast_group_gid_t& out_local_mcid)
{
    switch (smcid) {
    case MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE:
        out_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
        return LA_STATUS_SUCCESS;
    case MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_0:
        out_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_0_IFG_0;
        return LA_STATUS_SUCCESS;
    case MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_1:
        out_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_0_IFG_1;
        return LA_STATUS_SUCCESS;
    case MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_0:
        out_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_1_IFG_0;
        return LA_STATUS_SUCCESS;
    case MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_1:
        out_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_1_IFG_1;
        return LA_STATUS_SUCCESS;
    case MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_0:
        out_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_2_IFG_0;
        return LA_STATUS_SUCCESS;
    case MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_1:
        out_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_2_IFG_1;
        return LA_STATUS_SUCCESS;
    }
    return LA_STATUS_EINVAL;
}

la_status
la_device_impl::create_multicast_scale_reserved_groups()
{
    transaction txn;

    // ensure no multicast groups are configured
    if (is_multicast_groups_configured()) {
        log_err(HLD, "Multicast scale threshold cannot be changed while multicast groups exist.");
        return LA_STATUS_EINVAL;
    }

    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        la_multicast_group_gid_t local_mcid;
        txn.status = multicast_reserved_smcid_to_local_mcid(MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE, local_mcid);
        return_on_error(txn.status);

        // allocate the fabric reserved multicast group so it is not used
        uint64_t generator_mcid = local_mcid;
        m_index_generators.local_mcids.allocate(generator_mcid, generator_mcid);
    }

    if (m_device_mode == device_mode_e::LINECARD) {
        std::vector<la_multicast_group_gid_t> reserved_smcids = {MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE,
                                                                 MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_0,
                                                                 MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_1,
                                                                 MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_0,
                                                                 MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_1,
                                                                 MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_0,
                                                                 MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_1};
        transaction txn;

        for (auto smcid : reserved_smcids) {
            la_ip_multicast_group_gibraltar_wptr ip_mcg;

            la_multicast_group_gid_t local_mcid;
            txn.status = multicast_reserved_smcid_to_local_mcid(smcid, local_mcid);
            return_on_error(txn.status);

            // allocate the reserved multicast groups so they are not used
            uint64_t generator_mcid = local_mcid;
            m_index_generators.local_mcids.allocate(generator_mcid, generator_mcid);

            txn.status = do_create_ip_multicast_group(smcid, la_replication_paradigm_e::EGRESS, ip_mcg);
            return_on_error(txn.status);
            la_object_id_t oid = ip_mcg->oid();
            m_is_builtin_objects[oid] = true;
            txn.on_fail([=]() {
                m_is_builtin_objects[oid] = false;
                destroy_ip_multicast_group(ip_mcg);
                deregister_object(oid);
            });
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_multicast_scale_reserved_groups()
{
    std::vector<la_multicast_group_gid_t> reserved_smcids = {MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE,
                                                             MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_0,
                                                             MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_1,
                                                             MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_0,
                                                             MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_1,
                                                             MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_0,
                                                             MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_1};

    // release the resevered multicast group on the fabric element
    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        la_multicast_group_gid_t local_mcid;
        auto status = multicast_reserved_smcid_to_local_mcid(MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE, local_mcid);
        return_on_error(status);

        uint64_t generator_mcid = local_mcid;
        m_index_generators.local_mcids.release(generator_mcid);
    }

    if (m_device_mode == device_mode_e::LINECARD) {
        // destroy the resevered multicast groups
        for (auto smcid : reserved_smcids) {
            const auto& ip_mcg = m_ip_multicast_groups[smcid];
            if (ip_mcg == nullptr) {
                continue;
            }

            la_multicast_group_gid_t local_mcid;
            auto status = multicast_reserved_smcid_to_local_mcid(smcid, local_mcid);
            return_on_error(status);

            uint64_t generator_mcid = local_mcid;
            m_index_generators.local_mcids.release(generator_mcid);

            la_object_id_t oid = ip_mcg->oid();

            status = destroy_ip_multicast_group(ip_mcg);
            return_on_error(status);

            m_is_builtin_objects[oid] = false;

            deregister_object(oid);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_multicast_scale_threshold_table(uint16_t threshold)
{
    la_status status = LA_STATUS_SUCCESS;
    std::vector<uint8_t> dummy_keys = {0, 1};

    if (m_device_mode == device_mode_e::LINECARD) {

        // set the threshold on the network slices
        const auto& nw_tables(m_tables.nw_smcid_threshold_table);
        npl_nw_smcid_threshold_table_t::key_type nw_key;
        npl_nw_smcid_threshold_table_t::value_type nw_value;

        nw_value.payloads.smcid_threshold.id = threshold;

        // program both bits of the key such that the lookup always matches
        for (auto dummy_key : dummy_keys) {
            nw_key.dummy = dummy_key;
            status
                = per_slice_tables_set(m_slice_mode, nw_tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, nw_key, nw_value);
            return_on_error(status);
        }

        // set the threshold on the fabric slices
        const auto& fabric_tables(m_tables.fabric_smcid_threshold_table);
        npl_fabric_smcid_threshold_table_t::key_type fabric_key;
        npl_fabric_smcid_threshold_table_t::value_type fabric_value;

        fabric_value.payloads.smcid_threshold.id = threshold;

        // program both bits of the key such that the lookup always matches
        for (auto dummy_key : dummy_keys) {
            fabric_key.dummy = dummy_key;
            status = per_slice_tables_set(m_slice_mode, fabric_tables, {la_slice_mode_e::CARRIER_FABRIC}, fabric_key, fabric_value);
            return_on_error(status);
        }
    } else if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        const auto& fe_tables(m_tables.fe_smcid_threshold_table);
        npl_fe_smcid_threshold_table_t::key_type fe_key;
        npl_fe_smcid_threshold_table_t::value_type fe_value;

        fe_value.payloads.smcid_threshold.id = threshold;

        // program both bits of the key such that the lookup always matches
        for (auto dummy_key : dummy_keys) {
            fe_key.dummy = dummy_key;
            status = per_slice_tables_set(m_slice_mode, fe_tables, {la_slice_mode_e::CARRIER_FABRIC}, fe_key, fe_value);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_mc_bitmap_tc_map_table()
{
    for (la_traffic_class_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
        la_status status = configure_mc_bitmap_tc_map_table_per_tc(tc, 0 /*voq_offset*/);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_mc_emdb_tc_map_table()
{
    for (la_traffic_class_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
        la_status status = configure_mc_emdb_tc_map_table_per_tc(tc, 0 /*voq_offset*/);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_tr_lc_sa_configuration_registers()
{
    const int MAX_TXPDR_COPIES_PER_SLICE = 2000;
    lld_register_value_list_t reg_val_list;
    rx_pdr_2_slices_tr_lc_sa_configurations_reg1_register reg1;
    rx_pdr_2_slices_tr_lc_sa_configurations_reg2_register reg2;
    rx_pdr_2_slices_tr_lc_sa_configurations_reg3_register reg3;
    rx_pdr_2_slices_tr_lc_sa_configurations_reg4_register reg4;

    reg1.fields.slice_mc_emdb_range0_min_voq = 0x00000;
    reg1.fields.slice_mc_emdb_range0_max_voq = 0x0bfff;
    reg1.fields.slice_mc_emdb_range1_min_voq = 0x00000;
    reg1.fields.slice_mc_emdb_range1_max_voq = 0x00000;
    reg1.fields.slice_mc_emdb_range0_ucdv = MAX_TXPDR_COPIES_PER_SLICE;
    reg1.fields.slice_mc_emdb_range1_ucdv = MAX_TXPDR_COPIES_PER_SLICE;

    reg2.fields.slice_mc_emdb_range2_min_voq = 0x00000;
    reg2.fields.slice_mc_emdb_range2_max_voq = 0x00000;
    reg2.fields.slice_mc_emdb_range3_min_voq = 0x00000;
    reg2.fields.slice_mc_emdb_range3_max_voq = 0x00000;
    reg2.fields.slice_mc_emdb_range2_ucdv = MAX_TXPDR_COPIES_PER_SLICE;
    reg2.fields.slice_mc_emdb_range3_ucdv = MAX_TXPDR_COPIES_PER_SLICE;

    reg3.fields.slice_mc_emdb_range4_min_voq = 0x00000;
    reg3.fields.slice_mc_emdb_range4_max_voq = 0x00000;
    reg3.fields.slice_mc_emdb_range5_min_voq = 0x00000;
    reg3.fields.slice_mc_emdb_range5_max_voq = 0x00000;
    reg3.fields.slice_mc_emdb_range4_ucdv = MAX_TXPDR_COPIES_PER_SLICE;
    reg3.fields.slice_mc_emdb_range5_ucdv = MAX_TXPDR_COPIES_PER_SLICE;

    reg4.fields.slice_mc_emdb_txpdr_mcid_thr = MAX_MC_LOCAL_MCID;

    for (la_slice_id_t slice : get_used_slices()) {
        reg_val_list.push_back({(*m_gb_tree->slice_pair[slice / 2]->rx_pdr->tr_lc_sa_configurations_reg1)[slice % 2], reg1});
        reg_val_list.push_back({(*m_gb_tree->slice_pair[slice / 2]->rx_pdr->tr_lc_sa_configurations_reg2)[slice % 2], reg2});
        reg_val_list.push_back({(*m_gb_tree->slice_pair[slice / 2]->rx_pdr->tr_lc_sa_configurations_reg3)[slice % 2], reg3});
        reg_val_list.push_back({(*m_gb_tree->slice_pair[slice / 2]->rx_pdr->tr_lc_sa_configurations_reg4)[slice % 2], reg4});
    }

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status, HLD, ERROR, "Failed to write tr_lc_sa_configurations_reg1/2/3/4 register.");
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_ibm_tc_map_table()
{
    // IBM UC table
    const auto& ibm_table(m_tables.uc_ibm_tc_map_table);
    npl_uc_ibm_tc_map_table_key_t ibm_key;
    npl_uc_ibm_tc_map_table_value_t ibm_value;
    npl_uc_ibm_tc_map_table_entry_t* ibm_entry = nullptr;

    ibm_key.ibm_cmd_table_result_tc_map_profile = IBM_TC_PROFILE;

    for (la_traffic_class_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
        ibm_key.rxpp_pd_tc = tc;
        ibm_value.payloads.rxpdr_ibm_tc_map_result.tc_offset = 0;

        la_status status = ibm_table->set(ibm_key, ibm_value, ibm_entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_mirror_to_dsp_in_npu_soft_header_table()
{
    const auto& mirror_table(m_tables.mirror_to_dsp_in_npu_soft_header_table);
    npl_mirror_to_dsp_in_npu_soft_header_table_key_t km;
    npl_mirror_to_dsp_in_npu_soft_header_table_value_t vm;
    npl_mirror_to_dsp_in_npu_soft_header_table_entry_t* em = nullptr;

    km.mirror_code = NPL_RX_NULL_MIRROR_CODE;
    vm.payloads.update_dsp_in_npu_soft_header = 0;

    la_status status = mirror_table->set(km, vm, em);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_snoop_to_dsp_in_npu_soft_header_table(uint64_t snoop_code, uint8_t value)
{
    const auto& snoop_table(m_tables.snoop_to_dsp_in_npu_soft_header_table);
    npl_snoop_to_dsp_in_npu_soft_header_table_key_t ks;
    npl_snoop_to_dsp_in_npu_soft_header_table_value_t vs;
    npl_snoop_to_dsp_in_npu_soft_header_table_entry_t* es = nullptr;

    ks.device_snoop_code = snoop_code;
    vs.payloads.update_dsp_in_npu_soft_header = value;

    la_status status = snoop_table->set(ks, vs, es);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_snoop_to_dsp_in_npu_soft_header_table(uint64_t snoop_code)
{
    const auto& snoop_table(m_tables.snoop_to_dsp_in_npu_soft_header_table);
    npl_snoop_to_dsp_in_npu_soft_header_table_key_t ks;

    ks.device_snoop_code = snoop_code;

    la_status status = snoop_table->erase(ks);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_resource_management()
{
    // Resource handler
    m_resource_handler = make_shared<resource_handler>(shared_from_this());
    la_status status = m_resource_handler->initialize();
    if (status != LA_STATUS_SUCCESS) {
        m_resource_handler.reset();
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::disable_ipv4_header_checking()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_egress_multicast_slice_replication_tc_mapping(la_traffic_class_t tc, la_uint_t voq_offset)
{
    start_api_call("traffic_class=", tc, "voq_offset=", voq_offset);

    if (tc >= NUM_TC_CLASSES) {
        return LA_STATUS_EINVAL;
    }
    if (voq_offset >= MAX_VOQ_SET_SIZE) {
        return LA_STATUS_EINVAL;
    }

    la_status status = configure_mc_bitmap_tc_map_table_per_tc(tc, voq_offset);
    return_on_error(status);
    status = configure_mc_emdb_tc_map_table_per_tc(tc, voq_offset);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

bool
la_device_impl::check_vxrq_dup_range(la_slice_id_t dest_slice, const la_voq_set_wcptr& voq_set_in)
{
    auto voq_set = voq_set_in.weak_ptr_static_cast<const la_voq_set_base>();
    for (la_slice_id_t src_slice : get_used_slices()) {
        if (!is_network_slice(src_slice)) {
            // skip fabirc slices as there is only 1 voq set for the FILB to
            // send to fabric slices.
            continue;
        }
        la_vsc_gid_t base_vsc;
        la_status status = voq_set->get_base_vsc(src_slice, base_vsc);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "%s: get_base_vsc failed %s", __func__, la_status2str(status).c_str());
            return false;
        }

        // Cast to int to avoid compiler warning/error when vsc-range-start is 0
        if ((int)base_vsc < SA_MC_VSC_RANGE_START) {
            return false;
        }

        if ((base_vsc + voq_set->get_set_size()) >= SA_MC_VSC_RANGE_END) {
            return false;
        }
    }

    return true;
}

la_status
la_device_impl::clear_egress_multicast_slice_replication_voq_set(la_slice_id_t dest_slice)
{
    if (m_egress_multicast_slice_replication_voq_set[dest_slice] != nullptr) {
        la_status status = remove_egress_multicast_slice_replication_voq_set_from_filb_table(dest_slice);
        return_on_error(status);

        remove_object_dependency(m_egress_multicast_slice_replication_voq_set[dest_slice], this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_egress_multicast_slice_replication_voq_set(la_slice_id_t dest_slice, la_voq_set*& out_voq_set) const
{
    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_EINVAL;
    }
    out_voq_set = m_egress_multicast_slice_replication_voq_set[dest_slice].get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_egress_multicast_slice_replication_voq_set(la_slice_id_t dest_slice, const la_voq_set_impl_wptr& voq_set)
{
    if (voq_set == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(voq_set, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (voq_set->get_destination_slice() != dest_slice) {
        return LA_STATUS_EINVAL;
    }

    if (is_in_use(voq_set)) {
        return LA_STATUS_EBUSY;
    }

    if (voq_set->get_set_size() != NUM_SA_MC_VOQS) {
        return LA_STATUS_EINVAL;
    }

    if (m_egress_multicast_slice_replication_voq_set[dest_slice] != nullptr) {
        la_status status = remove_egress_multicast_slice_replication_voq_set_from_filb_table(dest_slice);
        return_on_error(status);

        remove_object_dependency(m_egress_multicast_slice_replication_voq_set[dest_slice], this);
    }

    m_egress_multicast_slice_replication_voq_set[dest_slice] = voq_set;

    la_status status = update_mc_bitmap_base_voq_lookup_table(dest_slice);
    return_on_error(status);

    status = add_egress_multicast_slice_replication_voq_set_to_filb_table(dest_slice);
    return_on_error(status);

    bool is_in_range = check_vxrq_dup_range(dest_slice, voq_set);
    if (!is_in_range) {
        log_err(HLD, "%s: VSC out of range. dest_slice=%d voq=%s", __func__, dest_slice, voq_set->to_string().c_str());

        return LA_STATUS_EOUTOFRANGE;
    }

    status = voq_set->force_local_voq_enable(false);
    return_on_error(status);

    add_object_dependency(voq_set, this);

    return LA_STATUS_SUCCESS;

    // TODO should a default VOQ priority be set at this point, or is it OK to leave it to the user ?
}

la_object::object_type_e
la_device_impl::type() const
{
    return object_type_e::DEVICE;
}

std::string
la_device_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_device_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_device_impl::oid() const
{
    return m_oid;
}

ll_device*
la_device_impl::get_ll_device() const
{
    return m_ll_device.get();
}

const device_tables*
la_device_impl::get_device_tables() const
{
    return &m_tables;
}

const la_device*
la_device_impl::get_device() const
{
    return this;
}

la_status
la_device_impl::set_ipv6_ext_header_trap_enabled(la_ipv6_extension_header_t ext_hdr_id, bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

// get_max_vrf_gids - Since Prefix compression lists (PCLs) use some
// of the VRF IDs at the top of the range, there is an integer
// device property that has been added to allow reclaiming some, or
// all of those VRF IDs should the user decide to exclude
// Prefix compression lists, or to reduce the number allocated.
la_status
la_device_impl::get_max_vrf_gids(la_uint_t& max_vrf_gids) const
{
    int max_num_pcl_gids;
    la_status status = get_int_property(la_device_property_e::MAX_NUM_PCL_GIDS, max_num_pcl_gids);
    return_on_error(status);
    max_vrf_gids = MAX_VRF_GID - max_num_pcl_gids;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_vrf(la_vrf_gid_t vrf_gid, la_vrf*& out_vrf)
{
    start_api_call("vrf_gid=", vrf_gid);
    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    if (vrf_gid >= max_vrf_gids) {
        return LA_STATUS_EINVAL;
    }

    if (m_vrfs[vrf_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    auto vrf = std::make_shared<la_vrf_impl>(shared_from_this());
    la_object_id_t oid;
    status = register_object(vrf, oid);
    return_on_error(status);
    status = vrf->initialize(oid, vrf_gid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_vrfs[vrf_gid] = vrf;
    out_vrf = vrf.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_vrf(const la_vrf_impl_wptr& vrf)
{
    if (!of_same_device(vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_vrf_gid_t vrf_gid = vrf->get_gid();

    if (vrf == nullptr) {
        // should be an assertion
        log_err(HLD, "trying to destroy an unknown vrf %u\n", vrf_gid);
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = vrf->destroy();
    return_on_error(status);

    m_vrfs[vrf_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_vrf_by_id(la_vrf_gid_t vrf_gid, la_vrf*& out_vrf) const
{
    start_api_getter_call();
    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    if (vrf_gid >= max_vrf_gids) {
        return LA_STATUS_EINVAL;
    }

    const auto& vrf = m_vrfs[vrf_gid];
    if (vrf == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_vrf = vrf.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_next_hop_by_id(la_next_hop_gid_t nh_gid, la_next_hop*& out_next_hop) const
{
    start_api_getter_call();

    if (nh_gid >= MAX_NEXT_HOP_GID) {
        return LA_STATUS_EINVAL;
    }

    const auto& next_hop = m_next_hops[nh_gid];
    if (next_hop == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_next_hop = next_hop.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_next_hop(la_next_hop_gid_t nh_gid,
                                la_mac_addr_t nh_mac_addr,
                                la_l3_port* port,
                                la_next_hop::nh_type_e nh_type,
                                la_next_hop*& out_next_hop)
{
    start_api_call("nh_gid=", nh_gid, "nh_mac_addr=", nh_mac_addr, "port=", port, "nh_type=", nh_type);
    if (nh_gid >= MAX_NEXT_HOP_GID) {
        return LA_STATUS_EINVAL;
    }

    if (port != nullptr) {
        if (!of_same_device(port, this)) {
            return LA_STATUS_EDIFFERENT_DEVS;
        }
    }

    if (m_next_hops[nh_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    auto next_hop = std::make_shared<la_next_hop_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(next_hop, oid);
    return_on_error(status);

    status = next_hop->initialize(oid, nh_gid, nh_mac_addr, get_sptr(port), nh_type);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_next_hops[nh_gid] = next_hop;
    out_next_hop = next_hop.get();

    // update resource monitor size
    auto& rm = m_resource_monitors.next_hop_resource_monitor;
    dassert_crit(rm != nullptr, "next_hop resource_monitor is uninitialized");
    rm->offset_size(1);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_next_hop(const la_next_hop_base_wptr& next_hop)
{
    if (!of_same_device(next_hop, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l3_destination_gid_t nh_gid = next_hop->get_gid();
    la_status status = next_hop->destroy();
    return_on_error(status);

    m_next_hops[nh_gid] = nullptr;

    // update resource monitor size
    m_resource_monitors.next_hop_resource_monitor->offset_size(-1);

    return status;
}

la_status
la_device_impl::create_vxlan_next_hop(la_mac_addr_t nh_mac_addr,
                                      la_l3_port* port,
                                      la_l2_service_port* vxlan_port,
                                      la_vxlan_next_hop*& out_vxlan_next_hop)
{
    start_api_call("nh_mac_addr=", nh_mac_addr, "port=", port, "vxlan_port=", vxlan_port);

    if (port != nullptr) {
        if (port->get_device() != this) {
            return LA_STATUS_EDIFFERENT_DEVS;
        }
    }

    auto vxlan_next_hop = std::make_shared<la_vxlan_next_hop_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(vxlan_next_hop, oid);
    return_on_error(status);

    status = vxlan_next_hop->initialize(oid, nh_mac_addr, get_sptr(port), get_sptr(vxlan_port));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_vxlan_next_hop = vxlan_next_hop.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_vxlan_next_hop(const la_vxlan_next_hop_gibraltar_wptr& vxlan_next_hop)
{
    if (vxlan_next_hop->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = vxlan_next_hop->destroy();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::create_l3_fec(la_l3_destination* destination, la_l3_fec*& out_fec)
{
    start_api_call("destination=", destination);

    la_l3_destination_wptr destination_wptr = get_sptr(destination);

    la_l3_fec_impl_sptr fec;
    la_status status = create_l3_fec_common(destination_wptr, false /* is_internal_wrapper */, fec);
    return_on_error(status);

    la_l3_destination_gid_t l3_dest_gid = get_l3_destination_gid(fec, true /* is_lpm_destination */);
    m_l3_destinations[l3_dest_gid] = fec;

    out_fec = fec.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l3_fec_wrapper(const la_l3_destination_wptr& destination, la_l3_fec_impl_sptr& out_fec)
{
    // FEC-wrapper is an internal object and hence it is not registered, and no shared-ptr of it
    // is kept in la-device. Therefore this function returns shared-ptr and not weak-ptr, and the
    // management of the shared-ptr is the responsibility of the caller
    la_l3_fec_impl_sptr fec;
    la_status status = create_l3_fec_common(destination, true /* is_internal_wrapper*/, fec);
    return_on_error(status);

    out_fec = fec;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l3_fec_wrapper(const la_l2_destination_wptr& destination, la_l3_fec_impl_sptr& out_fec)
{
    la_l3_fec_impl_sptr fec_impl;
    la_status status = create_l3_fec_common(destination, true /* is_internal_wrapper*/, fec_impl);
    return_on_error(status);

    out_fec = fec_impl;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l3_fec_common(const la_l3_destination_wptr& destination,
                                     bool is_internal_wrapper,
                                     la_l3_fec_impl_sptr& out_fec_impl)
{
    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    uint64_t fec_gid = 0;
    bool is_success = m_index_generators.fecs.allocate(fec_gid);
    if (!is_success) {
        return LA_STATUS_ERESOURCE;
    }

    auto fec_impl = std::make_shared<la_l3_fec_impl>(shared_from_this());

    la_object_id_t oid = LA_OBJECT_ID_INVALID;
    if (!is_internal_wrapper) {
        // Internal objects are not registered! See the comment at create_l3_fec_wrapper()
        la_status status = register_object(fec_impl, oid);
        if (status != LA_STATUS_SUCCESS) {
            m_index_generators.fecs.release(fec_gid);
            return status;
        }
    }

    auto status = fec_impl->initialize(oid, fec_gid, is_internal_wrapper, destination);
    if (status != LA_STATUS_SUCCESS) {
        if (!is_internal_wrapper) {
            deregister_object(oid);
        }
        m_index_generators.fecs.release(fec_gid);
        return status;
    }

    out_fec_impl = fec_impl;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l3_fec_common(const la_l2_destination_wptr& destination,
                                     bool is_internal_wrapper,
                                     la_l3_fec_impl_sptr& out_fec_impl)
{
    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    uint64_t fec_gid = 0;
    bool is_success = m_index_generators.fecs.allocate(fec_gid);
    if (!is_success) {
        return LA_STATUS_ERESOURCE;
    }

    auto fec_impl = std::make_shared<la_l3_fec_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(fec_impl, oid);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.fecs.release(fec_gid);
        return status;
    }

    status = fec_impl->initialize(oid, fec_gid, is_internal_wrapper, destination);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        m_index_generators.fecs.release(fec_gid);
        return status;
    }

    out_fec_impl = fec_impl;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_l3_fec(const la_l3_fec_impl_wptr& fec)
{
    if (!of_same_device(fec, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l3_destination_gid_t dest_gid = get_l3_destination_gid(fec, true /* is_lpm_destination */);

    la_status status = destroy_l3_fec_common(fec);
    return_on_error(status);

    m_l3_destinations[dest_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_l3_fec_wrapper(const la_l3_fec_impl_wptr& fec)
{
    la_status status = destroy_l3_fec_common(fec);

    return status;
}

la_status
la_device_impl::destroy_l3_fec_common(const la_l3_fec_impl_wptr& fec)
{
    la_fec_gid_t fec_gid = fec->get_gid();
    la_status status = fec->destroy();
    return_on_error(status);

    m_index_generators.fecs.release(fec_gid);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_l3_ac_port(la_l3_port_gid_t port_gid,
                                  const silicon_one::la_ethernet_port* ethernet_port,
                                  la_vlan_id_t vid1,
                                  la_vlan_id_t vid2,
                                  la_mac_addr_t mac_addr,
                                  la_vrf* vrf,
                                  la_ingress_qos_profile* ingress_qos_profile,
                                  la_egress_qos_profile* egress_qos_profile,
                                  la_l3_ac_port*& out_l3_ac_port)
{
    start_api_call("port_gid=",
                   port_gid,
                   "ethernet_port=",
                   ethernet_port,
                   "vid1=",
                   vid1,
                   "vid2=",
                   vid2,
                   "mac_addr=",
                   mac_addr,
                   "vrf=",
                   vrf,
                   "ingress_qos_profile=",
                   ingress_qos_profile,
                   "egress_qos_profile=",
                   egress_qos_profile);

    if (ethernet_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ethernet_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (port_gid >= MAX_L3_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_l3_ports[port_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    la_ingress_qos_profile_impl* ingress_qos_profile_impl = static_cast<la_ingress_qos_profile_impl*>(ingress_qos_profile);
    la_egress_qos_profile_impl* egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);

    auto ac_port = std::make_shared<la_l3_ac_port_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(ac_port, oid);
    return_on_error(status);

    status = ac_port->initialize(
        oid, port_gid, ethernet_port, vid1, vid2, mac_addr, vrf, ingress_qos_profile_impl, egress_qos_profile_impl);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_l3_ports[port_gid] = ac_port;
    out_l3_ac_port = ac_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_l3_ac_port(const la_l3_ac_port_impl_wptr& port)
{
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l3_port_gid_t gid = port->get_gid();

    if (port != port) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = port->destroy();
    return_on_error(status);

    m_l3_ports[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_svi_port(la_l3_port_gid_t gid,
                                const la_switch* sw,
                                const la_vrf* vrf,
                                la_mac_addr_t mac_addr,
                                la_ingress_qos_profile* ingress_qos_profile,
                                la_egress_qos_profile* egress_qos_profile,
                                la_svi_port*& out_svi_port)
{
    start_api_call("gid=",
                   gid,
                   "sw=",
                   sw,
                   "vrf=",
                   vrf,
                   "mac_addr=",
                   mac_addr,
                   "ingress_qos_profile=",
                   ingress_qos_profile,
                   "egress_qos_profile=",
                   egress_qos_profile);

    if (gid >= MAX_L3_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l3_ports[gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if (sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(sw, this) || !of_same_device(vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_ingress_qos_profile_impl* ingress_qos_profile_impl = static_cast<la_ingress_qos_profile_impl*>(ingress_qos_profile);
    la_egress_qos_profile_impl* egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);

    auto svi = std::make_shared<la_svi_port_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(svi, oid);
    return_on_error(status);

    status = svi->initialize(oid, gid, mac_addr, sw, vrf, ingress_qos_profile_impl, egress_qos_profile_impl);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_l3_ports[gid] = svi;
    out_svi_port = svi.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_svi_port(const la_svi_port_base_wptr& port)
{
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = port->destroy();
    return_on_error(status);

    la_l3_port_gid_t gid = port->get_gid();

    m_l3_ports[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_ip_over_ip_tunnel_port(la_l3_port_gid_t port_gid,
                                              la_vrf* underlay_vrf,
                                              la_ipv4_prefix_t prefix,
                                              la_ipv4_addr_t ip_addr,
                                              la_vrf* vrf,
                                              la_ingress_qos_profile* ingress_qos_profile,
                                              la_egress_qos_profile* egress_qos_profile,
                                              la_ip_over_ip_tunnel_port*& out_ip_over_ip_tunnel_port)

{
    return create_ip_over_ip_tunnel_port(port_gid,
                                         la_ip_tunnel_mode_e::DECAP_ONLY,
                                         underlay_vrf,
                                         prefix,
                                         ip_addr,
                                         vrf,
                                         ingress_qos_profile,
                                         egress_qos_profile,
                                         out_ip_over_ip_tunnel_port);
}

la_status
la_device_impl::create_ip_over_ip_tunnel_port(la_l3_port_gid_t port_gid,
                                              la_ip_tunnel_mode_e tunnel_mode,
                                              la_vrf* underlay_vrf,
                                              la_ipv4_prefix_t prefix,
                                              la_ipv4_addr_t ip_addr,
                                              la_vrf* vrf,
                                              la_ingress_qos_profile* ingress_qos_profile,
                                              la_egress_qos_profile* egress_qos_profile,
                                              la_ip_over_ip_tunnel_port*& out_ip_over_ip_tunnel_port)

{
    start_api_call("port_gid=",
                   port_gid,
                   "tunnel_mode=",
                   tunnel_mode,
                   "underlay_vrf=",
                   underlay_vrf,
                   "prefix=",
                   prefix,
                   "ip_addr=",
                   ip_addr,
                   "vrf=",
                   vrf,
                   "ingress_qos_profile=",
                   ingress_qos_profile,
                   "egress_qos_profile=",
                   egress_qos_profile);

    if (port_gid >= MAX_L3_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l3_ports[port_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_ingress_qos_profile_impl* ingress_qos_profile_impl = static_cast<la_ingress_qos_profile_impl*>(ingress_qos_profile);
    la_egress_qos_profile_impl* egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);

    auto ip_over_ip_tunnel_port = std::make_shared<la_ip_over_ip_tunnel_port_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(ip_over_ip_tunnel_port, oid);
    return_on_error(status);

    status = ip_over_ip_tunnel_port->initialize(
        oid, port_gid, tunnel_mode, underlay_vrf, prefix, ip_addr, vrf, ingress_qos_profile_impl, egress_qos_profile_impl);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_l3_ports[port_gid] = ip_over_ip_tunnel_port;
    out_ip_over_ip_tunnel_port = ip_over_ip_tunnel_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_gue_port(la_l3_port_gid_t port_gid,
                                la_ip_tunnel_mode_e tunnel_mode,
                                la_vrf* underlay_vrf,
                                la_ipv4_prefix_t local_prefix,
                                la_ipv4_addr_t remote_ip_addr,
                                la_vrf* overlay_vrf,
                                la_ingress_qos_profile* ingress_qos_profile,
                                la_egress_qos_profile* egress_qos_profile,
                                la_gue_port*& out_gue_port)

{
    start_api_call("port_gid=",
                   port_gid,
                   "tunnel_mode=",
                   tunnel_mode,
                   "underlay_vrf=",
                   underlay_vrf,
                   "local_prefix=",
                   local_prefix,
                   "remote_ip_addr=",
                   remote_ip_addr,
                   "overlay_vrf=",
                   overlay_vrf,
                   "ingress_qos_profile=",
                   ingress_qos_profile,
                   "egress_qos_profile=",
                   egress_qos_profile);

    if (port_gid >= MAX_L3_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (m_l3_ports[port_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (ingress_qos_profile->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (egress_qos_profile->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (tunnel_mode != la_ip_tunnel_mode_e::DECAP_ONLY) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_ingress_qos_profile_impl* ingress_qos_profile_impl = static_cast<la_ingress_qos_profile_impl*>(ingress_qos_profile);
    la_egress_qos_profile_impl* egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);

    auto gue_port = std::make_shared<la_gue_port_impl>(shared_from_this());

    auto underlay_vrf_sp = get_sptr(underlay_vrf);
    auto overlay_vrf_sp = get_sptr(overlay_vrf);
    auto ingress_qos_profile_impl_sp = get_sptr(ingress_qos_profile_impl);
    auto egress_qos_profile_impl_sp = get_sptr(egress_qos_profile_impl);

    la_object_id_t oid;
    la_status status = register_object(gue_port, oid);
    return_on_error(status);

    status = gue_port->initialize(oid,
                                  port_gid,
                                  tunnel_mode,
                                  get_sptr(underlay_vrf),
                                  local_prefix,
                                  remote_ip_addr,
                                  get_sptr(overlay_vrf),
                                  get_sptr(ingress_qos_profile_impl),
                                  get_sptr(egress_qos_profile_impl));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_l3_ports[port_gid] = gue_port;
    out_gue_port = gue_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_gue_port(const la_gue_port_impl_wptr& port)
{
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (port->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l3_port_gid_t gid = port->get_gid();

    la_status status = port->destroy();
    return_on_error(status);

    m_l3_ports[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_ip_over_ip_tunnel_port(const la_ip_over_ip_tunnel_port_impl_wptr& port)
{
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_l3_port_gid_t gid = port->get_gid();

    if (port != port) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = port->destroy();
    return_on_error(status);

    m_l3_ports[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_gre_port(la_l3_port_gid_t port_gid,
                                const la_vrf* underlay_vrf,
                                la_ipv4_addr_t local_ip_addr,
                                la_ipv4_addr_t remote_ip_addr,
                                const la_vrf* overlay_vrf,
                                la_ingress_qos_profile* ingress_qos_profile,
                                la_egress_qos_profile* egress_qos_profile,
                                la_gre_port*& out_gre_port)
{
    return create_gre_port(port_gid,
                           la_ip_tunnel_mode_e::ENCAP_DECAP,
                           underlay_vrf,
                           local_ip_addr,
                           remote_ip_addr,
                           overlay_vrf,
                           ingress_qos_profile,
                           egress_qos_profile,
                           out_gre_port);
}

la_status
la_device_impl::create_gre_port(la_l3_port_gid_t port_gid,
                                la_ip_tunnel_mode_e tunnel_mode,
                                const la_vrf* underlay_vrf,
                                la_ipv4_addr_t local_ip_addr,
                                la_ipv4_addr_t remote_ip_addr,
                                const la_vrf* overlay_vrf,
                                la_ingress_qos_profile* ingress_qos_profile,
                                la_egress_qos_profile* egress_qos_profile,
                                la_gre_port*& out_gre_port)
{
    start_api_call("port_gid=",
                   port_gid,
                   "tunnel_mode=",
                   tunnel_mode,
                   "underlay_vrf=",
                   underlay_vrf,
                   "local_ip_addr=",
                   local_ip_addr,
                   "remote_ip_addr=",
                   remote_ip_addr,
                   "overlay_vrf=",
                   overlay_vrf,
                   "ingress_qos_profile=",
                   ingress_qos_profile,
                   "egress_qos_profile=",
                   egress_qos_profile);

    if (port_gid >= MAX_L3_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    if (underlay_vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (overlay_vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_l3_ports[port_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    la_ingress_qos_profile_impl* ingress_qos_profile_impl = static_cast<la_ingress_qos_profile_impl*>(ingress_qos_profile);
    la_egress_qos_profile_impl* egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);

    auto gre_port = std::make_shared<la_gre_port_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(gre_port, oid);
    return_on_error(status);

    status = gre_port->initialize(oid,
                                  port_gid,
                                  tunnel_mode,
                                  underlay_vrf,
                                  local_ip_addr,
                                  remote_ip_addr,
                                  overlay_vrf,
                                  ingress_qos_profile_impl,
                                  egress_qos_profile_impl);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_l3_ports[port_gid] = gre_port;
    out_gre_port = gre_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_gre_port(const la_gre_port_impl_wptr& port)
{
    if (port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = port->destroy();
    return_on_error(status);

    la_l3_port_gid_t gid = port->get_gid();

    m_l3_ports[gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_gre_port_by_gid(la_l3_port_gid_t port_gid, la_gre_port*& out_gre_port) const
{
    if (port_gid >= MAX_L3_PORT_GID) {
        return LA_STATUS_EINVAL;
    }

    const auto& gre_port = m_l3_ports[port_gid].weak_ptr_static_cast<la_gre_port>();
    if (gre_port == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    if (gre_port->type() != object_type_e::GRE_PORT) {
        return LA_STATUS_ENOTFOUND;
    }

    out_gre_port = gre_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_ecmp_group(la_ecmp_group::level_e level, la_ecmp_group*& out_ecmp_group)
{

    start_api_call("level=", level);

    auto ecmp_group = std::make_shared<la_ecmp_group_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(ecmp_group, oid);
    return_on_error(status);

    status = ecmp_group->initialize(oid, level);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_ecmp_group = ecmp_group.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_ecmp_group(const la_ecmp_group_impl_wptr& ecmp_group)
{
    // Check arguments
    if (ecmp_group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ecmp_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // retrieve implementation objects

    if (is_in_use(ecmp_group)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = ecmp_group->destroy();

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::get_acl_key_profile_udf_types(la_udf_profile_type_e& out_v4_acl_key_profile,
                                              la_udf_profile_type_e& out_v6_acl_key_profile)
{
    auto acl_key_profiles = get_objects(object_type_e::ACL_KEY_PROFILE);
    for (auto acl_key_profile : acl_key_profiles) {
        la_acl_key_profile_base* acl_key_profile_impl = static_cast<la_acl_key_profile_base*>(acl_key_profile);
        la_acl_key_type_e key_type;

        acl_key_profile_impl->get_key_type(key_type);
        la_acl_key_profile_base::key_size_e key_size = acl_key_profile_impl->get_key_size();
        switch (key_type) {
        case la_acl_key_type_e::IPV4:
            if (key_size == la_acl_key_profile_base::key_size_e::SIZE_160) {
                out_v4_acl_key_profile = la_udf_profile_type_e::UDF_160;
            } else {
                out_v4_acl_key_profile = la_udf_profile_type_e::UDF_320;
            }
            break;
        case la_acl_key_type_e::IPV6:
            if (key_size == la_acl_key_profile_base::key_size_e::SIZE_160) {
                out_v6_acl_key_profile = la_udf_profile_type_e::UDF_160;
            } else {
                out_v6_acl_key_profile = la_udf_profile_type_e::UDF_320;
            }
            break;
        default:
            break;
        }
    }
}

void
la_device_impl::get_acl_key_profile_translation_info(std::vector<udk_translation_info_sptr>& trans_info)
{
    npl_tables_e table_id;
    la_status status;

    for (auto i = 0; i < NUM_UDK_TABLES_PER_DEVICE; i++) {
        trans_info[i] = nullptr;
    }
    auto acl_key_profiles = get_objects(object_type_e::ACL_KEY_PROFILE);
    for (auto acl_key_profile : acl_key_profiles) {
        la_acl_key_profile_base* acl_key_profile_impl = static_cast<la_acl_key_profile_base*>(acl_key_profile);
        acl_key_profile_impl->get_npl_table_id(table_id);

        auto curr_trans_info = acl_key_profile_impl->get_translation_info();

        switch (table_id) {
        case NPL_TABLES_INGRESS_RTF_IPV4_DB1_160_F0_TABLE:
            trans_info[0] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB1_320_F0_TABLE:
            trans_info[1] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB2_160_F0_TABLE:
            trans_info[2] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB2_320_F0_TABLE:
            trans_info[3] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB3_160_F0_TABLE:
            trans_info[4] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB3_320_F0_TABLE:
            trans_info[5] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB4_160_F0_TABLE:
            trans_info[6] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB4_320_F0_TABLE:
            trans_info[7] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB1_160_F0_TABLE:
            trans_info[8] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB1_320_F0_TABLE:
            trans_info[9] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB2_160_F0_TABLE:
            trans_info[10] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB2_320_F0_TABLE:
            trans_info[11] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB3_160_F0_TABLE:
            trans_info[12] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB3_320_F0_TABLE:
            trans_info[13] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB4_160_F0_TABLE:
            trans_info[14] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB4_320_F0_TABLE:
            trans_info[15] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_ETH_DB1_160_F0_TABLE:
            trans_info[16] = curr_trans_info;
            break;
        case NPL_TABLES_INGRESS_RTF_ETH_DB2_160_F0_TABLE:
            trans_info[17] = curr_trans_info;
            break;
        default:
            break;
        }
    }
}

void
la_device_impl::acl_key_profile_microcode_writes()
{
    auto acl_key_profiles = get_objects(object_type_e::ACL_KEY_PROFILE);
    for (auto acl_key_profile : acl_key_profiles) {
        la_acl_key_profile_base* acl_key_profile_impl = static_cast<la_acl_key_profile_base*>(acl_key_profile);
        acl_key_profile_impl->microcode_update();
    }
}

void
la_device_impl::get_acl_key_profile_types(acl_key_profile_type_e& out_ipv4_type, acl_key_profile_type_e& out_ipv6_type)
{
    out_ipv4_type = out_ipv6_type = acl_key_profile_type_e::DEFAULT;
    auto acl_key_profiles = get_objects(object_type_e::ACL_KEY_PROFILE);
    for (auto acl_key_profile : acl_key_profiles) {
        la_acl_key_profile_base* acl_key_profile_impl = static_cast<la_acl_key_profile_base*>(acl_key_profile);
        la_acl_key_type_e key_type;
        acl_key_profile_impl->get_key_type(key_type);
        la_acl_key_profile_base::key_size_e key_size = acl_key_profile_impl->get_key_size();
        if (key_type == la_acl_key_type_e::IPV4) {
            out_ipv4_type = (key_size == la_acl_key_profile_base::key_size_e::SIZE_160) ? acl_key_profile_type_e::UDK_160
                                                                                        : acl_key_profile_type_e::UDK_320;
        }
        if (key_type == la_acl_key_type_e::IPV6) {
            out_ipv6_type = (key_size == la_acl_key_profile_base::key_size_e::SIZE_160) ? acl_key_profile_type_e::UDK_160
                                                                                        : acl_key_profile_type_e::UDK_320;
        }
    }
}

la_status
la_device_impl::initialize_acl_select_tables(la_slice_pair_id_t slice_pair)
{

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_l2pt_trap_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    if (enabled == m_l2pt_trap_enabled) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    la_mac_addr_t addr;

    addr.flat = 0x01000CCDCDD0ULL;

    if (enabled) {
        status = m_mac_addr_manager->add(addr, NPL_MAC_DA_TYPE_CISCO_PROTOCOLS);
    } else {
        status = m_mac_addr_manager->remove(addr, NPL_MAC_DA_TYPE_CISCO_PROTOCOLS);
    }

    return_on_error(status);

    m_l2pt_trap_enabled = enabled;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_l2pt_trap_enabled(bool& out_enabled)
{
    out_enabled = m_l2pt_trap_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::add_copc_protocol_entry(la_control_plane_classifier::protocol_table_data& entry)
{
    return m_copc_protocol_manager->add(entry);
}

la_status
la_device_impl::remove_copc_protocol_entry(la_control_plane_classifier::protocol_table_data& entry)
{
    return m_copc_protocol_manager->remove(entry);
}

la_status
la_device_impl::get_copc_protocol_entries(la_control_plane_classifier::protocol_table_data_vec& out_entries)
{
    return m_copc_protocol_manager->get(out_entries);
}

la_status
la_device_impl::clear_copc_protocol_entries()
{
    return m_copc_protocol_manager->clear();
}

la_status
la_device_impl::set_acl_scaled_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    m_acl_scaled_enabled = enabled;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_acl_scaled_enabled(bool& out_enabled)
{
    out_enabled = m_acl_scaled_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_acl_scaled_enabled(la_slice_pair_id_t slice_pair, la_acl_id_t acl_id, bool enabled)
{
    start_api_call("slice_pair=", slice_pair, "acl_id=", acl_id, "enabled=", enabled);

    return enabled ? LA_STATUS_ENOTIMPLEMENTED : LA_STATUS_SUCCESS;

    /*
    npl_scaled_acl_key_type_select_compound_table_t::key_type k;
    npl_scaled_acl_key_type_select_compound_table_t::value_type v;
    npl_scaled_acl_key_type_select_compound_table_t::entry_pointer_type e;

    k.scaled_ipv4_sec_lv_acl_id = acl_id;
    la_status status = m_tables.scaled_acl_key_type_select_compound_table[slice_pair]->lookup(k, e);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    if (status == LA_STATUS_SUCCESS) {
        // found -> erase
        status = m_tables.scaled_acl_key_type_select_compound_table[slice_pair]->erase(k);
        if (status != LA_STATUS_SUCCESS) {
            return status;
        }
    }

    v.payloads.scaled_ipv4_sec_lv_scale_type = enabled ? NPL_SCALED_ACL_TYPE_IPV4 : NPL_SCALED_ACL_TYPE_NONE;
    status = m_tables.scaled_acl_key_type_select_compound_table[slice_pair]->insert(k, v, e);

    return status;
    */
}

la_status
la_device_impl::get_acl_scaled_enabled(la_slice_pair_id_t slice_pair, la_acl_id_t acl_id, bool& out_enabled)
{
    out_enabled = false;
    return LA_STATUS_SUCCESS;
    /*
    npl_scaled_acl_key_type_select_compound_table_t::key_type k;
    npl_scaled_acl_key_type_select_compound_table_t::entry_pointer_type e;

    k.scaled_ipv4_sec_lv_acl_id = NPL_FWD_INGRESS_ACL_DB_IPV4_SEC_DEFAULT;
    la_status status = m_tables.scaled_acl_key_type_select_compound_table[slice_pair]->lookup(k, e);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

    out_enabled = (e->value().payloads.scaled_ipv4_sec_lv_scale_type == NPL_SCALED_ACL_TYPE_IPV4);

    return status;
    */
}

la_status
la_device_impl::create_acl_key_profile(la_acl_key_type_e key_type,
                                       la_acl_direction_e dir,
                                       const la_acl_key_def_vec_t& key_def,
                                       la_acl_tcam_pool_id_t tcam_pool_id,
                                       la_acl_key_profile*& out_acl_key_profile)
{
    start_api_call("key_type=", key_type, "dir=", dir, "key_def=", key_def, "tcam_pool_id=", tcam_pool_id);
    auto acls = get_objects(object_type_e::ACL);
    if (acls.size() > 0) {
        log_err(HLD, "Can't create new acl key profiles if acls exist");
        return LA_STATUS_EINVAL;
    }

    auto acl_key_profile = std::make_shared<la_acl_key_profile_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(acl_key_profile, oid);
    return_on_error(status);

    status = acl_key_profile->initialize(oid, key_type, dir, key_def, tcam_pool_id);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_acl_key_profile = acl_key_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_acl_command_profile(const la_acl_command_def_vec_t& command_def,
                                           la_acl_command_profile*& out_acl_command_profile)
{
    start_api_call("command_def=", command_def);
    auto acl_command_profile = std::make_shared<la_acl_command_profile_base>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(acl_command_profile, oid);
    return_on_error(status);

    status = acl_command_profile->initialize(oid, command_def);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_acl_command_profile = acl_command_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_acl(const la_acl_key_profile* acl_key_profile,
                           const la_acl_command_profile* acl_command_profile,
                           la_pcl* src_pcl,
                           la_pcl* dst_pcl,
                           la_acl*& out_acl)
{
    start_api_call(
        "acl_key_profile=", acl_key_profile, "acl_command_profile=", acl_command_profile, "src_pcl=", src_pcl, "dst_pcl=", dst_pcl);
    return create_acl_internal(acl_key_profile, acl_command_profile, src_pcl, dst_pcl, out_acl);
}

la_status
la_device_impl::create_acl(const la_acl_key_profile* acl_key_profile,
                           const la_acl_command_profile* acl_command_profile,
                           la_acl*& out_acl)
{
    start_api_call("acl_key_profile=", acl_key_profile, "acl_command_profile=", acl_command_profile);
    return create_acl_internal(acl_key_profile, acl_command_profile, nullptr /*src_pcl*/, nullptr /*dst_pcl*/, out_acl);
}

la_status
la_device_impl::validate_acl_create(const la_acl_key_profile* acl_key_profile, const la_acl_command_profile* acl_command_profile)
{
    la_acl_key_type_e key_type;
    la_status status = acl_key_profile->get_key_type(key_type);
    return_on_error(status);

    if (key_type == la_acl_key_type_e::SGACL) {
        la_acl_command_def_vec_t acl_cmds;
        status = acl_command_profile->get_command_definition(acl_cmds);
        return_on_error(status);
        for (auto cmd : acl_cmds) {
            if (cmd.type != la_acl_action_type_e::DROP) {
                log_err(HLD, "Security group acls support only drop action");
                return LA_STATUS_EINVAL;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_acl_internal(const la_acl_key_profile* acl_key_profile,
                                    const la_acl_command_profile* acl_command_profile,
                                    la_pcl* src_pcl,
                                    la_pcl* dst_pcl,
                                    la_acl*& out_acl)
{
    la_status status = validate_acl_create(acl_key_profile, acl_command_profile);
    return_on_error(status);

    const la_acl_key_profile_base* acl_key_profile_impl = static_cast<const la_acl_key_profile_base*>(acl_key_profile);
    const la_acl_command_profile_base* acl_command_profile_impl
        = static_cast<const la_acl_command_profile_base*>(acl_command_profile);

    auto acl_impl = std::make_shared<la_acl_impl>(shared_from_this());
    la_object_id_t oid;
    status = register_object(acl_impl, oid);
    return_on_error(status);

    status = acl_impl->initialize(oid, acl_key_profile_impl, acl_command_profile_impl, get_sptr(src_pcl), get_sptr(dst_pcl));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    auto acls = get_objects(object_type_e::ACL);
    if (acls.size() == 1) {
        la_acl_key_profile_base* acl_key_profile_impl2
            = const_cast<la_acl_key_profile_base*>(static_cast<const la_acl_key_profile_base*>(acl_key_profile));
        status = acl_key_profile_impl2->update_all_acl_key_profiles();
        return_on_error(status);
    }

    out_acl = acl_impl.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_acl_group(la_acl_group*& out_acl_group)
{
    start_api_call("");
    auto acl_group = std::make_shared<la_acl_group_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(acl_group, oid);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

    status = acl_group->initialize(oid);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_acl_group = acl_group.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::reserve_acl(la_acl* acl)
{
    start_api_call("acl=", acl);
    if (acl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (acl->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (acl->type() != la_object::object_type_e::ACL) {
        return LA_STATUS_EINVAL;
    }

    la_acl_impl* acl_impl = static_cast<la_acl_impl*>(acl);
    if (acl_impl == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    return acl_impl->reserve();
}

la_status
la_device_impl::destroy_acl(const la_acl_impl_wptr& acl)
{
    if (acl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(acl, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (acl->type() != la_object::object_type_e::ACL) {
        return LA_STATUS_EINVAL;
    }

    la_acl_impl* acl_impl = static_cast<la_acl_impl*>(acl.get());
    la_status status = acl_impl->destroy();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::destroy_acl_key_profile(const la_acl_key_profile_wptr& acl_key_profile)
{
    auto acls = get_objects(object_type_e::ACL);
    if (acls.size() > 0) {
        log_err(HLD, "Can't destroy acl key profiles if acls exist");
        return LA_STATUS_EINVAL;
    }

    if (acl_key_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (acl_key_profile->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (acl_key_profile->type() != la_object::object_type_e::ACL_KEY_PROFILE) {
        return LA_STATUS_EINVAL;
    }

    la_acl_key_profile_base* acl_key_profile_impl = static_cast<la_acl_key_profile_base*>(acl_key_profile.get());
    la_status status = acl_key_profile_impl->destroy();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::destroy_acl_command_profile(const la_acl_command_profile_wptr& acl_command_profile)
{
    if (acl_command_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (acl_command_profile->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (acl_command_profile->type() != la_object::object_type_e::ACL_COMMAND_PROFILE) {
        return LA_STATUS_EINVAL;
    }

    la_acl_command_profile_base* acl_command_profile_impl = static_cast<la_acl_command_profile_base*>(acl_command_profile.get());
    la_status status = acl_command_profile_impl->destroy();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::destroy_acl_group(const la_acl_group_wptr& acl_group)
{
    if (acl_group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (acl_group->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (acl_group->type() != la_object::object_type_e::ACL_GROUP) {
        return LA_STATUS_EINVAL;
    }

    la_acl_group_base* acl_group_impl = static_cast<la_acl_group_base*>(acl_group.get());
    la_status status = acl_group_impl->destroy();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::destroy_acl_scaled(const la_acl_scaled_impl_wptr& acl)
{
    if (acl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(acl, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (acl->type() != la_object::object_type_e::ACL_SCALED) {
        return LA_STATUS_EINVAL;
    }

    la_status status = acl->destroy();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::set_acl_range(la_acl::stage_e stage,
                              la_acl::range_type_e range,
                              la_uint_t idx,
                              la_uint16_t rstart,
                              la_uint16_t rend)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

template <class _PrefixType>
la_status
la_device_impl::do_create_pcl(const _PrefixType& prefixes, const pcl_feature_type_e& feature, la_pcl_wptr& out_pcl)
{
    auto pcl_impl = std::make_shared<la_pcl_impl>(shared_from_this());
    la_object_id_t oid;
    auto status = register_object(pcl_impl, oid);
    return_on_error(status);

    status = pcl_impl->initialize(oid, prefixes, feature);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_pcl = pcl_impl;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_pcl(const std::vector<la_pcl_v4>& prefixes, const pcl_feature_type_e& feature, la_pcl*& out_pcl)
{
    start_api_call("prefixes=", prefixes, "feature=", feature);
    la_pcl_wptr pcl;
    auto status = do_create_pcl(prefixes, feature, pcl);
    return_on_error(status);

    out_pcl = pcl.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_pcl(const std::vector<la_pcl_v6>& prefixes, const pcl_feature_type_e& feature, la_pcl*& out_pcl)
{
    start_api_call("prefixes=", prefixes, "feature=", feature);
    la_pcl_wptr pcl;
    auto status = do_create_pcl(prefixes, feature, pcl);
    return_on_error(status);

    out_pcl = pcl.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_pcl(const la_pcl_impl_wptr& pcl)
{
    if (pcl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(pcl, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (pcl->type() != la_object::object_type_e::PCL) {
        return LA_STATUS_EINVAL;
    }

    la_status status = pcl->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_og_lpts_app(const la_lpts_app_properties& properties,
                                   silicon_one::la_pcl* src_pcl,
                                   la_og_lpts_application*& out_lpts_app)
{
    start_api_call("properties=", properties, "src_pcl=", src_pcl);
    auto lpts_app = std::make_shared<la_og_lpts_application_impl>(shared_from_this());
    la_object_id_t oid;
    auto status = register_object(lpts_app, oid);
    return_on_error(status);

    status = lpts_app->initialize(oid, properties, get_sptr(src_pcl));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_lpts_app = lpts_app.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_og_lpts_app(const la_og_lpts_application_impl_wptr& lpts_app)
{
    start_api_call("la_og_lpts_application=", lpts_app);
    if (lpts_app == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(lpts_app, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (lpts_app->type() != la_object::object_type_e::OG_LPTS_APPLICATION) {
        return LA_STATUS_EINVAL;
    }

    la_status status = lpts_app->destroy();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::assign_lpts_counter_allocation(la_slice_pair_id_t pair_idx, counter_allocation& out_allocation)
{
    if (m_lpts_allocation_cache[pair_idx].empty()) {
        return LA_STATUS_ERESOURCE;
    }

    out_allocation = m_lpts_allocation_cache[pair_idx].back();
    m_lpts_allocation_cache[pair_idx].pop_back();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::release_lpts_counter_allocation(la_slice_pair_id_t pair_idx, counter_allocation& allocation)
{
    m_lpts_allocation_cache[pair_idx].push_back(allocation);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::warm_boot_pre_save()
{
    apb* apb_serdes_handler = m_apb_handlers[apb_interface_type_e::SERDES].get();
    srm::clear_apb(apb_serdes_handler);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::warm_boot_post_restore()
{
    // srm uses global map for apb, better left raw-pointer based with manual restoration here.
    apb* apb_serdes_handler = m_apb_handlers[apb_interface_type_e::SERDES].get();
    srm::set_apb(apb_serdes_handler);

    return LA_STATUS_SUCCESS;
}

static void
warm_boot_set_serialization_version(la_uint32_t wb_revision)
{
#if ENABLE_SERIALIZATION
    ::cereal::cereal_gen_set_serialization_version_apb(wb_revision);
    ::cereal::cereal_gen_set_serialization_version_api(wb_revision);
    ::cereal::cereal_gen_set_serialization_version_common(wb_revision);
    ::cereal::cereal_gen_set_serialization_version_cpu2jtag(wb_revision);
    ::cereal::cereal_gen_set_serialization_version_hld(wb_revision);
    ::cereal::cereal_gen_set_serialization_version_hw_tables(wb_revision);
    ::cereal::cereal_gen_set_serialization_version_lld(wb_revision);
    ::cereal::cereal_gen_set_serialization_version_nplapi(wb_revision);
    ::cereal::cereal_gen_set_serialization_version_nsim_provider(wb_revision);
    ::cereal::cereal_gen_set_serialization_version_ra(wb_revision);
#endif
}

la_status
la_device_impl::initialize_lpts_allocation_cache()
{
    if (m_lpts_allocation_cache_initialized) {
        return LA_STATUS_SUCCESS;
    }

    int lpts_max_entry_counters = 0;

    la_status status = get_int_property(la_device_property_e::LPTS_MAX_ENTRY_COUNTERS, lpts_max_entry_counters);
    return_on_error(status);

    for (la_slice_pair_id_t pair_idx : get_used_slice_pairs()) {
        la_slice_ifg slice_ifg = {.slice = pair_idx * 2, .ifg = 0};
        size_t num_of_ifgs = NUM_IFGS_PER_SLICE * 2;
        size_t allocation_size = 2; // Each row in the meters-table holds 2 entries. It's a dynamic table with side effects on
                                    // writes, so a row cannot be shared between different meter-sets.
        for (int alloc = 0; alloc < lpts_max_entry_counters; alloc++) {
            auto lpts_allocation = counter_allocation();

            la_status status = m_counter_bank_manager->allocate(true /*is_slice_pair*/,
                                                                COUNTER_DIRECTION_INGRESS,
                                                                allocation_size,
                                                                slice_ifg,
                                                                num_of_ifgs,
                                                                COUNTER_USER_TYPE_METER,
                                                                lpts_allocation);
            return_on_error(status);

            m_lpts_allocation_cache[pair_idx].push_back(lpts_allocation);

            log_debug(HLD,
                      "%s: slice_ifg=%d/%d allocation=%zu %zu",
                      __func__,
                      slice_ifg.slice,
                      slice_ifg.ifg,
                      lpts_allocation.get_bank_id(),
                      lpts_allocation.get_index());
        }
    }

    m_lpts_allocation_cache_initialized = true;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::release_lpts_allocation_cache()
{
    for (la_slice_pair_id_t pair_idx : get_used_slice_pairs()) {
        if (m_lpts_allocation_cache[pair_idx].empty()) {
            continue;
        }
        auto alloc_size = m_lpts_allocation_cache[pair_idx].size();
        for (size_t alloc = 0; alloc < alloc_size; alloc++) {
            m_counter_bank_manager->release(COUNTER_USER_TYPE_METER, m_lpts_allocation_cache[pair_idx][alloc]);
        }

        m_lpts_allocation_cache[pair_idx].clear();
    }

    m_lpts_allocation_cache_initialized = false;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_lpts(lpts_type_e type, silicon_one::la_lpts*& out_lpts)
{
    start_api_call("lpts_type=", type);

    la_status status = initialize_lpts_allocation_cache();
    return_on_error(status);

    auto lpts_impl = std::make_shared<la_lpts_impl>(shared_from_this());

    status = initialize_lpts_allocation_cache();
    return_on_error(status);

    la_object_id_t oid;
    status = register_object(lpts_impl, oid);
    return_on_error(status);

    status = lpts_impl->initialize(oid, type);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_lpts = lpts_impl.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_lpts(const la_lpts_impl_wptr& lpts)
{
    start_api_call("lpts=", lpts);

    if (lpts == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(lpts, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = lpts->destroy();
    return_on_error(status);

    status = release_lpts_allocation_cache();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::create_copc(la_control_plane_classifier::type_e type, la_control_plane_classifier*& out_copc)
{
    start_api_call("type=", type);
    auto copc = std::make_shared<la_copc_gibraltar>(get_sptr(this));

    la_object_id_t oid;
    la_status status = register_object(copc, oid);
    return_on_error(status);

    status = copc->initialize(oid, type);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_copc = copc.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_copc(const la_copc_base_wptr& copc)
{
    start_api_call("copc=", copc);

    if (copc == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (copc->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = copc->destroy();
    return_on_error(status);

    return status;
}

la_status
la_device_impl::initialize_sgacl_allocation_cache()
{
    int sgacl_max_entry_counters = 0;

    la_status status = get_int_property(la_device_property_e::SGACL_MAX_CELL_COUNTERS, sgacl_max_entry_counters);
    return_on_error(status);

    if (sgacl_max_entry_counters == 0) {
        return LA_STATUS_SUCCESS;
    }

    for (la_slice_pair_id_t pair_idx : get_used_slice_pairs()) {
        la_slice_ifg slice_ifg = {.slice = pair_idx * 2, .ifg = 0};
        size_t num_of_ifgs = NUM_IFGS_PER_SLICE * 2;
        size_t allocation_size = 2;
        for (int alloc = 0; alloc < sgacl_max_entry_counters; alloc++) {
            counter_allocation sgacl_allocation;

            la_status status = m_counter_bank_manager->allocate(true /*is_slice_pair*/,
                                                                COUNTER_DIRECTION_INGRESS,
                                                                allocation_size,
                                                                slice_ifg,
                                                                num_of_ifgs,
                                                                COUNTER_USER_TYPE_SECURITY_GROUP_CELL,
                                                                sgacl_allocation);
            return_on_error(status);

            m_sgacl_allocation_cache[pair_idx].push_back(sgacl_allocation);

            log_debug(HLD,
                      "%s: slice_ifg=%d/%d allocation=%zu %zu",
                      __func__,
                      slice_ifg.slice,
                      slice_ifg.ifg,
                      sgacl_allocation.get_bank_id(),
                      sgacl_allocation.get_index());
        }
    }

    // Check symmetric indices on all the bank allocations
    for (int alloc = 0; alloc < sgacl_max_entry_counters; alloc++) {
        size_t index_on_slice_pair0 = m_sgacl_allocation_cache[0][alloc].get_index();
        size_t index_on_slice_pair1 = m_sgacl_allocation_cache[1][alloc].get_index();
        size_t index_on_slice_pair2 = m_sgacl_allocation_cache[2][alloc].get_index();
        dassert_crit(index_on_slice_pair0 == index_on_slice_pair1);
        dassert_crit(index_on_slice_pair1 == index_on_slice_pair2);
        dassert_crit(index_on_slice_pair0 == index_on_slice_pair2);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::release_sgacl_allocation_cache()
{
    int sgacl_max_entry_counters = 0;

    la_status status = get_int_property(la_device_property_e::SGACL_MAX_CELL_COUNTERS, sgacl_max_entry_counters);
    return_on_error(status);

    if (sgacl_max_entry_counters == 0) {
        return LA_STATUS_SUCCESS;
    }

    for (la_slice_pair_id_t pair_idx : get_used_slice_pairs()) {
        if (m_sgacl_allocation_cache[pair_idx].empty()) {
            continue;
        }
        auto alloc_size = m_sgacl_allocation_cache[pair_idx].size();
        for (size_t alloc = 0; alloc < alloc_size; alloc++) {
            m_counter_bank_manager->release(COUNTER_USER_TYPE_SECURITY_GROUP_CELL, m_sgacl_allocation_cache[pair_idx][alloc]);
        }

        m_sgacl_allocation_cache[pair_idx].clear();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::assign_sgacl_counter_allocation(la_slice_pair_id_t pair_idx, counter_allocation& out_allocation)
{
    if (m_sgacl_allocation_cache[pair_idx].empty()) {
        return LA_STATUS_ERESOURCE;
    }

    out_allocation = m_sgacl_allocation_cache[pair_idx].back();
    m_sgacl_allocation_cache[pair_idx].pop_back();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::release_sgacl_counter_allocation(la_slice_pair_id_t pair_idx, counter_allocation& allocation)
{
    m_sgacl_allocation_cache[pair_idx].push_back(allocation);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_voq_cgm_evicted_profile(la_voq_cgm_evicted_profile*& out_evicted_profile)
{
    start_api_call("");

    uint64_t profile_id = 0;

    bool allocated = m_index_generators.voq_cgm_evicted_profiles.allocate(profile_id);
    if (!allocated) {
        return LA_STATUS_ERESOURCE;
    }

    la_voq_cgm_evicted_profile_wptr out_profile_wptr;
    auto status = do_create_voq_cgm_evicted_profile(profile_id, out_profile_wptr);
    return_on_error(status);

    out_evicted_profile = out_profile_wptr.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_create_voq_cgm_evicted_profile(uint64_t profile_id, la_voq_cgm_evicted_profile_wptr& out_evicted_profile)
{
    auto voq_cgm_evicted_profile = std::make_shared<la_voq_cgm_evicted_profile_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(voq_cgm_evicted_profile, oid);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.voq_cgm_evicted_profiles.release(profile_id);
        return status;
    }

    status = voq_cgm_evicted_profile->initialize(oid, profile_id);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        m_index_generators.voq_cgm_evicted_profiles.release(profile_id);
        return status;
    }

    m_voq_cgm_evicted_profiles[profile_id] = voq_cgm_evicted_profile;
    out_evicted_profile = voq_cgm_evicted_profile;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_voq_cgm_evicted_profile(const la_voq_cgm_evicted_profile_impl_wptr& profile)
{
    if (profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (profile->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(profile)) {
        return LA_STATUS_EBUSY;
    }

    uint64_t profile_id = profile->get_id();

    if (profile != m_voq_cgm_evicted_profiles[profile_id]) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = profile->destroy();
    return_on_error(status);

    m_index_generators.voq_cgm_evicted_profiles.release(profile_id);

    m_voq_cgm_evicted_profiles[profile_id] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_voq_cgm_default_evicted_profile(const la_voq_cgm_evicted_profile*& out_evicted_profile) const
{
    start_api_getter_call();

    out_evicted_profile = m_voq_cgm_evicted_profiles[VOQ_CGM_DEFAULT_EVICTED_PROFILE].get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_voq_cgm_default_evicted_profile()
{
    la_voq_cgm_evicted_profile_wptr default_evicted_profile;

    la_status status = do_create_voq_cgm_evicted_profile(VOQ_CGM_DEFAULT_EVICTED_PROFILE, default_evicted_profile);
    return_on_error(status);

    auto voq_cgm_evicted_profile = default_evicted_profile.weak_ptr_static_cast<la_voq_cgm_evicted_profile_impl>();
    // Set default behavior.
    status = voq_cgm_evicted_profile->do_set_default_behavior();
    return_on_error(status);

    // default_evicted_profile exists for the life of device object.
    m_is_builtin_objects[default_evicted_profile->oid()] = true;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_voq_cgm_profile(la_voq_cgm_profile*& out_profile)
{
    start_api_call("");

    uint64_t profile_id = 0;

    bool allocated = m_index_generators.voq_cgm_profiles.allocate(profile_id);
    if (!allocated) {
        return LA_STATUS_ERESOURCE;
    }

    la_voq_cgm_profile_wptr profile_wptr;
    auto status = do_create_cgm_profile(profile_id, profile_wptr);
    return_on_error(status);

    out_profile = profile_wptr.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_create_cgm_profile(uint64_t profile_id, la_voq_cgm_profile_wptr& out_voq_cgm_profile)
{
    auto voq_cgm_profile = std::make_shared<la_voq_cgm_profile_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(voq_cgm_profile, oid);
    if (status != LA_STATUS_SUCCESS) {
        m_index_generators.voq_cgm_profiles.release(profile_id);
        return status;
    }

    status = voq_cgm_profile->initialize(oid, profile_id);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        m_index_generators.voq_cgm_profiles.release(profile_id);
        return status;
    }

    m_voq_cgm_profiles[profile_id] = voq_cgm_profile;
    out_voq_cgm_profile = voq_cgm_profile;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_voq_cgm_profile(const la_voq_cgm_profile_impl_wptr& profile)
{
    if (profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(profile)) {
        return LA_STATUS_EBUSY;
    }

    uint64_t profile_id = profile->get_id();

    if (profile != m_voq_cgm_profiles[profile_id]) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = profile->destroy();
    return_on_error(status);

    if (profile_id != MC_VOQ_CGM_PROFILE) {
        m_index_generators.voq_cgm_profiles.release(profile_id);
    }

    m_voq_cgm_profiles[profile_id] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_cgm_sms_voqs_bytes_quantization(const la_cgm_sms_bytes_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_sms_voqs_bytes_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_sms_voqs_bytes_quantization(la_cgm_sms_bytes_quantization_thresholds& out_thresholds) const
{
    la_status status = m_voq_cgm_handler->get_cgm_sms_voqs_bytes_quantization(out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_sms_voqs_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_sms_voqs_bytes_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_sms_voqs_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();
    la_status status = m_voq_cgm_handler->get_cgm_sms_voqs_bytes_quantization(out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_sms_voqs_packets_quantization(const la_cgm_sms_packets_quantization_thresholds& thresholds)
{

    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_sms_voqs_packets_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_sms_voqs_packets_quantization(la_cgm_sms_packets_quantization_thresholds& out_thresholds) const
{
    la_status status = m_voq_cgm_handler->get_cgm_sms_voqs_packets_quantization(out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_sms_voqs_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_sms_voqs_packets_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_sms_voqs_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();
    la_status status = m_voq_cgm_handler->get_cgm_sms_voqs_packets_quantization(out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_sms_evicted_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_sms_evicted_bytes_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_sms_evicted_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();
    la_status status = m_voq_cgm_handler->get_cgm_sms_evicted_bytes_quantization(out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_hbm_number_of_voqs_quantization(const la_cgm_hbm_number_of_voqs_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_hbm_number_of_voqs_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_hbm_number_of_voqs_quantization(la_cgm_hbm_number_of_voqs_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();
    la_status status = m_voq_cgm_handler->get_cgm_hbm_number_of_voqs_quantization(out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_hbm_number_of_voqs_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_hbm_number_of_voqs_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_hbm_number_of_voqs_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();
    la_status status = m_voq_cgm_handler->get_cgm_hbm_number_of_voqs_quantization(out_thresholds);
    return status;
}
la_status
la_device_impl::set_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float threshold)
{
    start_api_call("hbm_pool_id=", hbm_pool_id, "threshold=", threshold);
    if (m_init_phase == init_phase_e::TOPOLOGY) {
        log_err(API, "HBM pool max capacity can only be called before la_device::initialize(la_object_id_t oid,TOPOLOGY)");
        return LA_STATUS_EBUSY;
    }

    la_status status = m_voq_cgm_handler->set_hbm_pool_max_capacity(hbm_pool_id, threshold);
    return status;
}

la_status
la_device_impl::get_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float& out_threshold) const
{
    start_api_getter_call("hbm_pool_id=", hbm_pool_id);
    la_status status = m_voq_cgm_handler->get_hbm_pool_max_capacity(hbm_pool_id, out_threshold);
    return status;
}

la_status
la_device_impl::set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                          const la_cgm_hbm_pool_free_blocks_quantization_thresholds& thresholds)
{
    start_api_call("hbm_pool_id=", hbm_pool_id, "thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_hbm_pool_free_blocks_quantization(hbm_pool_id, thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                          la_cgm_hbm_pool_free_blocks_quantization_thresholds& out_thresholds) const
{
    la_status status = m_voq_cgm_handler->get_cgm_hbm_pool_free_blocks_quantization(hbm_pool_id, out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                          const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("hbm_pool_id=", hbm_pool_id, "thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_hbm_pool_free_blocks_quantization(hbm_pool_id, thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                          la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call("hbm_pool_id=", hbm_pool_id);
    la_status status = m_voq_cgm_handler->get_cgm_hbm_pool_free_blocks_quantization(hbm_pool_id, out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_hbm_voq_age_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_hbm_voq_age_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_hbm_voq_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();
    la_status status = m_voq_cgm_handler->get_cgm_hbm_voq_age_quantization(out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_hbm_blocks_by_voq_quantization(const la_cgm_hbm_blocks_by_voq_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_hbm_blocks_by_voq_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_hbm_blocks_by_voq_quantization(la_cgm_hbm_blocks_by_voq_quantization_thresholds& out_thresholds) const
{
    la_status status = m_voq_cgm_handler->get_cgm_hbm_blocks_by_voq_quantization(out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_hbm_blocks_by_voq_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    la_status status = m_voq_cgm_handler->set_cgm_hbm_blocks_by_voq_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_cgm_hbm_blocks_by_voq_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();
    la_status status = m_voq_cgm_handler->get_cgm_hbm_blocks_by_voq_quantization(out_thresholds);
    return status;
}

la_status
la_device_impl::set_cgm_sms_voqs_age_time_granularity(la_cgm_sms_voqs_age_time_units_t sms_voqs_age_time_units)
{
    start_api_call("sms_voqs_age_time_units=", sms_voqs_age_time_units);
    la_status status = m_voq_cgm_handler->set_cgm_sms_voqs_age_time_granularity(sms_voqs_age_time_units);
    return status;
}

la_status
la_device_impl::get_cgm_sms_voqs_age_time_granularity(la_cgm_sms_voqs_age_time_units_t& out_sms_voqs_age_time_units) const
{
    la_status status = m_voq_cgm_handler->get_cgm_sms_voqs_age_time_granularity(out_sms_voqs_age_time_units);
    return status;
}

la_status
la_device_impl::set_rx_pdr_sms_bytes_drop_thresholds(const la_rx_pdr_sms_bytes_drop_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    auto counter_thresholds_reg_2 = m_gb_tree->rx_pdr->counters_thresholds_reg2;
    gibraltar::rx_pdr_counters_thresholds_reg2_register reg;

    la_uint_t max_threshold_val = bit_utils::ones(reg.fields.COUNTER_A_DROP_THR0_WIDTH) * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    if (thresholds.thresholds[0] > max_threshold_val || thresholds.thresholds[1] > max_threshold_val) {
        return LA_STATUS_EINVAL;
    }

    if (thresholds.thresholds[1] < thresholds.thresholds[0]) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_ll_device->read_register(counter_thresholds_reg_2, reg);
    return_on_error(status);

    reg.fields.counter_a_drop_thr0 = div_round_nearest(thresholds.thresholds[0], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
    reg.fields.counter_a_drop_thr1 = div_round_nearest(thresholds.thresholds[1], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);

    status = m_ll_device->write_register(counter_thresholds_reg_2, reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_rx_pdr_sms_bytes_drop_thresholds(la_rx_pdr_sms_bytes_drop_thresholds& out_thresholds)
{
    start_api_getter_call();

    auto counter_thresholds_reg_2 = m_gb_tree->rx_pdr->counters_thresholds_reg2;
    gibraltar::rx_pdr_counters_thresholds_reg2_register reg;

    la_status status = m_ll_device->read_register(counter_thresholds_reg_2, reg);
    return_on_error(status);

    out_thresholds.thresholds[0] = reg.fields.counter_a_drop_thr0 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    out_thresholds.thresholds[1] = reg.fields.counter_a_drop_thr1 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_rx_cgm_sq_profile(la_rx_cgm_sq_profile*& out_rx_cgm_sq_profile)
{
    start_api_call("");

    auto rx_cgm_sq_profile = std::make_shared<la_rx_cgm_sq_profile_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(rx_cgm_sq_profile, oid);
    return_on_error(status);

    status = rx_cgm_sq_profile->initialize(oid, false /* is_default */);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_rx_cgm_sq_profile = rx_cgm_sq_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_rx_cgm_sq_profile(const la_rx_cgm_sq_profile_impl_wptr& profile)
{
    start_api_call("profile=", profile);

    if (profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (profile->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(profile)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = profile->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_default_rx_cgm_sq_profile(la_rx_cgm_sq_profile*& out_default_rx_cgm_sq_profile)
{
    start_api_getter_call();

    out_default_rx_cgm_sq_profile = m_default_rx_cgm_sq_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::read_rx_cgm_drop_counter(la_slice_id_t slice, la_uint_t counter_index, la_uint_t& out_packet_count)
{
    start_api_getter_call();

    la_uint_t packet_count;
    la_status status = m_rx_cgm_handler->read_rx_cgm_drop_counter(slice, counter_index, packet_count);
    return_on_error(status);

    out_packet_count = packet_count;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_pfc_headroom_mode(la_rx_cgm_headroom_mode_e mode)
{
    start_api_call("mode=", mode);

    la_status status = m_rx_cgm_handler->set_rx_cgm_hr_management_mode(mode);
    return status;
}

la_status
la_device_impl::get_pfc_headroom_mode(la_rx_cgm_headroom_mode_e& out_mode)
{
    start_api_getter_call();

    la_rx_cgm_headroom_mode_e mode;
    la_status status = m_rx_cgm_handler->get_rx_cgm_hr_management_mode(mode);
    return_on_error(status);

    out_mode = mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_rx_cgm_sms_bytes_quantization(const la_rx_cgm_sms_bytes_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    la_status status = m_rx_cgm_handler->set_rx_cgm_sms_bytes_quantization(thresholds);
    return status;
}

la_status
la_device_impl::get_rx_cgm_sms_bytes_quantization(la_rx_cgm_sms_bytes_quantization_thresholds& out_thresholds)
{
    start_api_getter_call();

    la_rx_cgm_sms_bytes_quantization_thresholds thresholds;
    la_status status = m_rx_cgm_handler->get_rx_cgm_sms_bytes_quantization(thresholds);
    return_on_error(status);

    out_thresholds = thresholds;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_rx_cgm_sqg_thresholds(la_uint_t group_index, const la_rx_cgm_sqg_thresholds& thresholds)
{
    start_api_call("group_index=", group_index, "thresholds=", thresholds);

    la_status status = m_rx_cgm_handler->set_rx_cgm_sqg_thresholds(group_index, thresholds);
    return status;
}

la_status
la_device_impl::get_rx_cgm_sqg_thresholds(la_uint_t group_index, la_rx_cgm_sqg_thresholds& out_thresholds)
{
    start_api_getter_call();

    la_rx_cgm_sqg_thresholds thresholds;
    la_status status = m_rx_cgm_handler->get_rx_cgm_sqg_thresholds(group_index, thresholds);
    return_on_error(status);

    out_thresholds = thresholds;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_default_rx_cgm_sq_profile()
{
    auto default_profile = std::make_shared<la_rx_cgm_sq_profile_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(default_profile, oid);
    return_on_error(status);

    status = default_profile->initialize(oid, true /* default_profile */);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }
    /* Default profile should always exist */
    m_is_builtin_objects[default_profile->oid()] = true;
    m_default_rx_cgm_sq_profile = default_profile;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_pacific_b0_post_initialize_workarounds()
{
    return LA_STATUS_EINVAL;
}

la_status
la_device_impl::create_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile)
{
    start_api_call("");
    auto ingress_qos_profile = std::make_shared<la_ingress_qos_profile_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(ingress_qos_profile, oid);
    return_on_error(status);

    status = ingress_qos_profile->initialize(oid);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_ingress_qos_profile = ingress_qos_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_ingress_qos_profile(const la_ingress_qos_profile_impl_wptr& ingress_qos_profile)
{
    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(ingress_qos_profile)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = ingress_qos_profile->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_egress_qos_profile(la_egress_qos_marking_source_e marking_source,
                                          la_egress_qos_profile*& out_egress_qos_profile)
{
    start_api_call("marking_source=", marking_source);
    auto egress_qos_profile = std::make_shared<la_egress_qos_profile_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(egress_qos_profile, oid);
    return_on_error(status);

    status = egress_qos_profile->initialize(oid, marking_source);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_egress_qos_profile = egress_qos_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_egress_qos_profile(const la_egress_qos_profile_impl_wptr& egress_qos_profile)
{
    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(egress_qos_profile)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = egress_qos_profile->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_device_int_capabilities(std::vector<uint32_t>& out_device_int_capabilities) const
{
    out_device_int_capabilities.resize((int)device_int_capability_e::LAST + 1);

    out_device_int_capabilities[(int)device_int_capability_e::MATILDA_MODEL] = (int)m_matilda_eFuse_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_limit(limit_type_e limit_type, la_uint64_t& out_limit) const
{
    switch (limit_type) {
    case limit_type_e::DEVICE__MAX_SMS_BYTES_QUANTIZATION_THRESHOLD: {
        la_uint64_t buffer_size = SMS_BLOCK_SIZE_IN_BYTES;
        la_uint64_t num_buffers
            = (1 << gibraltar::rx_pdr_counters_thresholds_reg1_register::fields::VOQ_CGM_COUNTER_A_THR0_WIDTH) - 1;
        out_limit = num_buffers * buffer_size;
    } break;
    case limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS: {
        npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type k;
        out_limit = (1 << BITS_SIZEOF(k, buffer_pool_available_level));
    } break;
    case limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_sms_bytes_quantization_regions = 0;
        get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_bytes_quantization_regions);
        out_limit = num_sms_bytes_quantization_regions - 1;
    } break;
    case limit_type_e::DEVICE__MAX_SMS_PACKETS_QUANTIZATION_THRESHOLD:
        out_limit = (1 << gibraltar::pdvoq_shared_mma_cgm_pool_available_region_register::fields::UC_REGION0_WIDTH) - 1;
        break;
    case limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS: {
        npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::key_type k;
        out_limit = (1 << BITS_SIZEOF(k, pd_pool_available_level));
    } break;
    case limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_sms_packets_quantization_regions = 0;
        get_limit(limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_packets_quantization_regions);
        out_limit = num_sms_packets_quantization_regions - 1;
    } break;
    case limit_type_e::DEVICE__MAX_SMS_NUM_EVICTED_BUFF_QUANTIZATION_THRESHOLD: {
        la_uint64_t buffer_size = SMS_BLOCK_SIZE_IN_BYTES;
        la_uint64_t num_buffers
            = (1 << gibraltar::ics_top_dram_global_buffer_size_cfg_register::fields::DRAM_GLOBAL_BUFFER_SIZE_TH_WIDTH) - 1;
        out_limit = num_buffers * buffer_size;
    } break;
    case limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS: {
        npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_t::key_type k;
        size_t evict_ok_key_bits = BITS_SIZEOF(k, all_evicted_voq_buff_consump_level);

        // Validate all tables have the same field width.
        npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_t::key_type evicted_buffers_key;
        size_t evicted_buffers_key_bits = BITS_SIZEOF(evicted_buffers_key, all_evicted_voq_buff_consump_level);
        dassert_crit(evict_ok_key_bits == evicted_buffers_key_bits,
                     "evicted_buffers key width mismatch bwtween evicted_ok and evicted_buffers_consumption tables");
        out_limit = (1 << evict_ok_key_bits);
    } break;
    case limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_sms_evicted_buff_quantization_regions;
        get_limit(limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS, num_sms_evicted_buff_quantization_regions);
        out_limit = num_sms_evicted_buff_quantization_regions - 1;
    } break;
    case limit_type_e::DEVICE__MAX_HBM_NUM_OF_VOQS_QUANTIZATION_THRESHOLD:
        out_limit = HBM_CONTEXT_POOL_SIZE;
        break;
    case limit_type_e::DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_REGIONS: {
        npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_t::key_type k;
        out_limit = (1 << BITS_SIZEOF(k, free_dram_cntx));
    } break;
    case limit_type_e::DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_hbm_num_of_voqs_quantization_regions = 0;
        get_limit(limit_type_e::DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_REGIONS, num_hbm_num_of_voqs_quantization_regions);
        out_limit = num_hbm_num_of_voqs_quantization_regions - 1;
    } break;
    case limit_type_e::DEVICE__MAX_HBM_POOL_BYTES_QUANTIZATION_THRESHOLD: {
        out_limit = ((1 << gibraltar::dram_cgm_quant_thresholds_register::fields::SHARED_POOL0_TH_WIDTH) - 1)
                    * voq_cgm_handler::HBM_BLOCKS_GROUP_SIZE;
    } break;
    case limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS: {
        npl_dram_cgm_cgm_lut_table_t::key_type k;
        out_limit = (1 << BITS_SIZEOF(k, shared_pool_th_level));
    } break;
    case limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_hbm_pool_free_blocks_quantization_regions = 0;
        get_limit(limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS,
                  num_hbm_pool_free_blocks_quantization_regions);
        out_limit = num_hbm_pool_free_blocks_quantization_regions - 1;
    } break;
    case limit_type_e::DEVICE__MAX_HBM_VOQ_AGE_QUANTIZATION_THRESHOLD: {
        out_limit = (1 << gibraltar::dram_cgm_quant_thresholds_register::fields::QUEUE_AGE_TH_WIDTH) - 1;
    } break;
    case limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_REGIONS: {
        npl_dram_cgm_cgm_lut_table_t::key_type k;
        out_limit = (1 << BITS_SIZEOF(k, dram_q_delay_level));
    } break;
    case limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_hbm_voq_age_quantization_regions = 0;
        get_limit(limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_REGIONS, num_hbm_voq_age_quantization_regions);
        out_limit = num_hbm_voq_age_quantization_regions - 1;
    } break;
    case limit_type_e::DEVICE__MAX_HBM_BLOCKS_BY_VOQ_QUANTIZATION_THRESHOLD:
        // For PFC, we increase max # of packets per HBM block. Thus, this value must be larger as well.
        out_limit = m_pfc_tuning_enabled ? ((1 << 20) - 1) : VOQ_IN_DRAM_MAX_SIZE;
        break;
    case limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS: {
        npl_dram_cgm_cgm_lut_table_t::key_type k;
        out_limit = (1 << BITS_SIZEOF(k, queue_size_level));
    } break;
    case limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_hbm_blocks_by_voq_quantization_regions = 0;
        get_limit(limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS, num_hbm_blocks_by_voq_quantization_regions);
        out_limit = num_hbm_blocks_by_voq_quantization_regions - 1;
    } break;
    case limit_type_e::DEVICE__NUM_CGM_HBM_POOLS:
        out_limit = NUM_CGM_HBM_POOLS;
        break;
    case limit_type_e::DEVICE__NUM_LOCAL_VOQS:
        // Because of a HW bug in GB we set this limit to MAX_AVAILABLE_VOQS_PER_SLICE.
        // Originally, it should be MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE - NATIVE_VOQ_SET_SIZE, where
        // the last VOQ is used by the HW for invalid indication.
        out_limit = MAX_AVAILABLE_VOQS_PER_SLICE;
        break;
    case limit_type_e::DEVICE__NUM_SYSTEM_VOQS:
        // Because of a HW bug in GB we set this limit to MAX_AVAILABLE_VOQS_PER_SLICE.
        // Originally, it should be MAX_VOQS_PER_SLICE_IN_LINECARD_DEVICE - NATIVE_VOQ_SET_SIZE, where
        // the last VOQ is used by the HW for invalid indication.
        out_limit = MAX_AVAILABLE_VOQS_PER_SLICE;
        break;
    case limit_type_e::DEVICE__NUM_TC_PROFILES:
        out_limit = NUM_TC_PROFILES;
        break;
    case limit_type_e::DEVICE__FIRST_ALLOCATABLE_VOQ:
        out_limit = FIRST_AVAILABLE_BASE_VOQ;
        break;
    case limit_type_e::DEVICE__MIN_ALLOCATABLE_VSC:
        if (m_device_mode == device_mode_e::INVALID) {
            return LA_STATUS_ENOTINITIALIZED;
        } else if (m_device_mode == device_mode_e::STANDALONE) {
            out_limit = SA_LAST_RESERVED_VSC + 1;
        } else if (m_device_mode == device_mode_e::LINECARD) {
            out_limit = LC_LAST_RESERVED_VSC + 1;
        } else {
            return LA_STATUS_EINVAL;
        }
        break;
    case limit_type_e::DEVICE__MAX_ALLOCATABLE_VSC:
        out_limit = MAX_VSCS_PER_IFG_IN_SLICE;
        break;
    case limit_type_e::DEVICE__MAX_PREFIX_OBJECT_GIDS:
        out_limit = MAX_PREFIX_OBJECT_GIDS;
        break;
    case limit_type_e::DEVICE__MAX_SR_EXTENDED_POLICIES:
        out_limit = NUM_SR_EXTENDED_POLICIES;
        break;
    case limit_type_e::DEVICE__MAX_OIDS:
        out_limit = MAX_OIDS;
        break;
    case limit_type_e::DEVICE__MAX_L3_PROTECTION_GROUP_GIDS:
        out_limit = MAX_L3_PROTECTED_GIDS;
        break;
    case limit_type_e::DEVICE__MAX_SYSTEM_PORT_GID: {
        bool ecn_queuing_enabled = false;
        get_bool_property(la_device_property_e::ENABLE_ECN_QUEUING, ecn_queuing_enabled);
        if (ecn_queuing_enabled) {
            out_limit = MAX_SYSTEM_PORT_GID_WITH_ECN_ENABLED - 1;
        } else {
            out_limit = MAX_SYSTEM_PORT_GID - 1;
        }
        break;
    }
    case limit_type_e::DEVICE__MAX_L2_AC_PORT_GID:
        out_limit = MAX_L2_SERVICE_PORT_GID - 1;
        break;
    case limit_type_e::DEVICE__MAX_INGRESS_MIRROR_GID:
        out_limit = MAX_INGRESS_MIRROR_GID;
        break;
    case limit_type_e::DEVICE__MIN_INGRESS_MIRROR_GID:
        out_limit = MIN_INGRESS_MIRROR_GID;
        break;
    case limit_type_e::DEVICE__MAX_EGRESS_MIRROR_GID:
        out_limit = MAX_EGRESS_MIRROR_GID;
        break;
    case limit_type_e::DEVICE__MIN_EGRESS_MIRROR_GID:
        out_limit = MIN_EGRESS_MIRROR_GID;
        break;
    case limit_type_e::DEVICE__MAX_ERSPAN_SESSION_ID:
        out_limit = MAX_ERSPAN_SESSION_ID;
        break;
    case limit_type_e::DEVICE__MIN_SYSTEM_PORT_GID:
        out_limit = MIN_SYSTEM_PORT_GID;
        break;
    case limit_type_e::DEVICE__NUM_ACL_TCAM_POOLS:
        out_limit = NUM_ACL_TCAM_POOLS;
        break;
    case limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_BYTES: {
        la_uint64_t buffer_size = SMS_BLOCK_SIZE_IN_BYTES;
        la_uint64_t num_buffers = ((1 << la_voq_cgm_profile_impl::BUFF_REGION_WIDTH) - 1);
        out_limit = buffer_size * num_buffers;
        break;
    }
    case limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_PACKETS:
        out_limit = (1 << la_voq_cgm_profile_impl::PKT_REGION_WIDTH) - 1;
        break;
    case limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_AGE: {
        la_cgm_sms_voqs_age_time_units_t granularity;
        la_status granularity_status = m_voq_cgm_handler->get_cgm_sms_voqs_age_time_granularity(granularity);
        return_on_error(granularity_status);
        out_limit = ((1 << la_voq_cgm_profile_impl::TIME_REGION_WIDTH) - 1) * granularity;
        break;
    }
    case limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_HBM_SIZE:
        out_limit = (1 << la_voq_cgm_profile_impl::WRED_REGION_WIDTH) - 1;
        break;
    case limit_type_e::METER_PROFILE__MAX_BURST_SIZE:
        // Burst-size should be limited to (max_bucket_size - max_update_chunk_size) to
        // ensure that the bucket never overflows.
        {
            size_t max_meter_bucket_size = ((1 << la_meter_set_impl::BUCKET_WIDTH) - 1);
            size_t max_update_chunk_size = la_meter_profile_impl::TOKEN_RESOLUTION * la_meter_profile_impl::TOKEN_PARTS;
            max_meter_bucket_size = max_meter_bucket_size - max_update_chunk_size;
            out_limit = round_down(max_meter_bucket_size, UNITS_IN_KIBI);
        }
        break;
    case limit_type_e::STAT_METER_PROFILE__MAX_BURST_SIZE: {
        la_uint64_t max_burst = 0;
        get_limit(limit_type_e::METER_PROFILE__MAX_BURST_SIZE, max_burst);
        out_limit = max_burst / la_meter_set_impl::STAT_PKT_FRACTION_COMPENSATION;
    } break;
    case limit_type_e::COUNTER_SET__MAX_PQ_COUNTER_OFFSET:
        out_limit = MAX_COUNTER_OFFSET;
        break;
    case limit_type_e::COUNTER_SET__MAX_PIF_COUNTER_OFFSET:
        out_limit = MAX_PIF_COUNTER_OFFSET;
        break;
    case limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS: {
        npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type k;
        out_limit = (1 << BITS_SIZEOF(k, buffer_voq_size_level));
    } break;
    case limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS: {
        npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::key_type k;
        out_limit = (1 << BITS_SIZEOF(k, pd_voq_fill_level));
    } break;
    case limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS:
        out_limit = la_voq_cgm_profile_impl::SMS_NUM_AGE_QUANTIZATION_REGIONS;
        break;
    case limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS: {
        npl_pdvoq_slice_dram_wred_lut_table_t::key_type k;
        out_limit = (1 << BITS_SIZEOF(k, queue_size_level));
    } break;
    case limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS: {
        // Packet size region is 3 bit field. region indexes 6 and 7 are not used.
        npl_pdvoq_slice_dram_wred_lut_table_t::key_type wred_key;
        size_t wred_key_bits = BITS_SIZEOF(wred_key, packet_size_range);

        // Validate all tables using packet size regions have the same field width.
        npl_voq_cgm_slice_drop_green_probability_selector_table_t::key_type drop_g_prob_key;
        size_t drop_g_key_bits = BITS_SIZEOF(drop_g_prob_key, packet_size_range);
        dassert_crit(wred_key_bits == drop_g_key_bits,
                     "Packet size range width mismatch bwtween WRED and Drop green probability tables");
        npl_voq_cgm_slice_drop_yellow_probability_selector_table_t::key_type drop_y_prob_key;
        size_t drop_y_key_bits = BITS_SIZEOF(drop_y_prob_key, packet_size_range);
        dassert_crit(wred_key_bits == drop_y_key_bits,
                     "Packet size range width mismatch bwtween WRED and Drop yellow probability tables");
        npl_voq_cgm_slice_mark_probability_selector_table_t::key_type mark_prob_key;
        size_t mark_key_bits = BITS_SIZEOF(mark_prob_key, packet_size_range);
        dassert_crit(wred_key_bits == mark_key_bits, "Packet size range width mismatch bwtween WRED and Mark probability tables");

        out_limit = (1 << wred_key_bits) - 2;
    } break;
    case limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_DROP_PROBABILITY_LEVELS: {
        npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type v;
        size_t values_per_line
            = array_size(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color);
        out_limit = (1 << BITS_SIZEOF(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g, drop_green_u)
                              / values_per_line);
    } break;
    case limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_MARK_PROBABILITY_LEVELS: {
        npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type v;
        size_t values_per_line
            = array_size(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.mark_g.mark_green.mark_color);
        out_limit = (1 << BITS_SIZEOF(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.mark_g, mark_green_u)
                              / values_per_line);
    } break;
    case limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_sms_voq_bytes_regions;
        get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
        out_limit = num_sms_voq_bytes_regions - 1;
    } break;
    case limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_sms_voq_packets_regions;
        get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_voq_packets_regions);
        out_limit = num_sms_voq_packets_regions - 1;
    } break;
    case limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_sms_voq_age_regions;
        get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_voq_age_regions);
        out_limit = num_sms_voq_age_regions - 1;
    } break;
    case limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS: {
        la_uint64_t num_wred_blocks_regions;
        get_limit(limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS, num_wred_blocks_regions);
        out_limit = num_wred_blocks_regions - 1;
    } break;
    case limit_type_e::ROUTE__MAX_CLASS_IDENTIFIER:
        out_limit = MAX_CLASS_IDENTIFIER;
        break;
    case limit_type_e::HOST__MAX_CLASS_IDENTIFIER:
        out_limit = MAX_CLASS_IDENTIFIER_FOR_HOSTS;
        break;
    case limit_type_e::MLDP_MIN_RPF_ID:
        out_limit = MLDP_MIN_RPF_ID;
        break;
    case limit_type_e::MLDP_MAX_RPF_ID:
        out_limit = MLDP_MAX_RPF_ID;
        break;

    default:
        return LA_STATUS_EINVAL;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_precision(la_precision_type_e precision_type, double& out_precision) const
{
    switch (precision_type) {
    case la_precision_type_e::VOQ_CGM_PROBABILITY_PRECISION:
        out_precision = la_voq_cgm_profile_impl::probability_precision;
        break;
    case la_precision_type_e::METER_PROFILE__CBS_RESOLUTION:
        out_precision = la_meter_profile_impl::CBS_RESOLUTION;
        break;
    case la_precision_type_e::METER_PROFILE__EBS_RESOLUTION:
        out_precision = la_meter_profile_impl::EBS_OR_PBS_RESOLUTION;
        break;

    default:
        return LA_STATUS_EINVAL;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_bool_property(la_device_property_e device_property, bool property_value)
{
    start_api_call("device_property=", device_property, "property_value=", property_value);

    device_property_type_e device_property_type = get_device_property_type(device_property);

    if (device_property_type != device_property_type_e::BOOLEAN) {
        log_err(HLD, "Property must be boolean (device_property %s)", silicon_one::to_string(device_property).c_str());
        return LA_STATUS_EINVAL;
    }

    if (is_allow_modify_property_at_phase(device_property) == false) {
        log_err(HLD,
                "Property %s cannot be changed during %s phase",
                silicon_one::to_string(device_property).c_str(),
                silicon_one::to_string(m_init_phase).c_str());
        return LA_STATUS_EBUSY;
    }

    m_device_properties[(int)device_property].bool_val = property_value;
    la_status rc = m_reconnect_handler->update_device_property(device_property, property_value);
    if (rc) {
        return rc;
    }

    rc = configure_device_bool_property(device_property);

    return rc;
}

la_status
la_device_impl::is_property_supported(la_device_property_e device_property, bool& supported) const
{
    if (device_property >= la_device_property_e::FIRST && device_property <= la_device_property_e::LAST) {
        supported = m_device_properties[(int)device_property].supported;
    } else {
        supported = false;
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_bool_property(la_device_property_e device_property, bool& out_property_value) const
{
    device_property_type_e device_property_type = get_device_property_type(device_property);

    if (device_property_type != device_property_type_e::BOOLEAN) {
        log_err(HLD, "Property must be boolean (device_property %s)", silicon_one::to_string(device_property).c_str());
        return LA_STATUS_EINVAL;
    }

    out_property_value = m_device_properties[(int)device_property].bool_val;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_int_property(la_device_property_e device_property, int property_value)
{
    start_api_call("device_property=", device_property, "property_value=", property_value);

    device_property_type_e device_property_type = get_device_property_type(device_property);

    if (device_property_type != device_property_type_e::INTEGER) {
        log_err(HLD, "Property must be integer (device_property %s)", silicon_one::to_string(device_property).c_str());
        return LA_STATUS_EINVAL;
    }

    if (is_allow_modify_property_at_phase(device_property) == false) {
        log_err(HLD,
                "Property %s cannot be changed during %s phase",
                silicon_one::to_string(device_property).c_str(),
                silicon_one::to_string(m_init_phase).c_str());
        return LA_STATUS_EBUSY;
    }

    int old_property_value = m_device_properties[(int)device_property].int_val;

    m_device_properties[(int)device_property].int_val = property_value;

    la_status status = configure_device_int_property(device_property, old_property_value);
    if (status) {
        // If there is a failure in configuring the new property value,
        // revert back to the previous value
        m_device_properties[(int)device_property].int_val = old_property_value;
        return status;
    }

    status = m_reconnect_handler->update_device_property(device_property, property_value);
    if (status) {
        return status;
    }

    return status;
}

la_status
la_device_impl::get_int_property(la_device_property_e device_property, int& out_property_value) const
{
    device_property_type_e device_property_type = get_device_property_type(device_property);

    if (device_property_type != device_property_type_e::INTEGER) {
        log_err(HLD, "Property must be integer (device_property %s)", silicon_one::to_string(device_property).c_str());
        return LA_STATUS_EINVAL;
    }

    out_property_value = m_device_properties[(int)device_property].int_val;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_string_property(la_device_property_e device_property, std::string property_value)
{
    start_api_call("device_property=", device_property, "property_value=", property_value);

    device_property_type_e device_property_type = get_device_property_type(device_property);

    if (device_property_type != device_property_type_e::STRING) {
        log_err(HLD, "Property must be string (device_property %s)", silicon_one::to_string(device_property).c_str());
        return LA_STATUS_EINVAL;
    }

    if (is_allow_modify_property_at_phase(device_property) == false) {
        log_err(HLD,
                "Property %s cannot be changed during %s phase",
                silicon_one::to_string(device_property).c_str(),
                silicon_one::to_string(m_init_phase).c_str());
        return LA_STATUS_EBUSY;
    }

    m_device_properties[(int)device_property].string_val = property_value;

    la_status status = configure_device_string_property(device_property);

    return status;
}

la_status
la_device_impl::get_string_property(la_device_property_e device_property, std::string& out_property_value) const
{
    device_property_type_e device_property_type = get_device_property_type(device_property);

    if (device_property_type != device_property_type_e::STRING) {
        log_err(HLD, "Property must be string (device_property %s)", silicon_one::to_string(device_property).c_str());
        return LA_STATUS_EINVAL;
    }

    out_property_value = m_device_properties[(int)device_property].string_val;

    return LA_STATUS_SUCCESS;
}

bool
la_device_impl::is_allow_modify_property_at_phase(la_device_property_e device_property) const
{
    if (m_init_phase != init_phase_e::CREATED) {
        if ((device_property == la_device_property_e::ENABLE_HBM)
            || (device_property == la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION)
            || (device_property == la_device_property_e::LPM_L2_MAX_SRAM_BUCKETS)
            || (device_property == la_device_property_e::HBM_FREQUENCY)
            || (device_property == la_device_property_e::HBM_LPM_FAVOR_MODE)
            || (device_property == la_device_property_e::HBM_MIN_MOVE_TO_READ)
            || (device_property == la_device_property_e::HBM_WRITE_CYCLES)
            || (device_property == la_device_property_e::HBM_READ_CYCLES)
            || (device_property == la_device_property_e::HBM_MOVE_TO_WRITE_ON_EMPTY)
            || (device_property == la_device_property_e::HBM_MOVE_TO_READ_ON_EMPTY)
            || (device_property == la_device_property_e::HBM_PHY_T_RDLAT_OFFSET)
            || (device_property == la_device_property_e::FORCE_DISABLE_HBM)
            || (device_property == la_device_property_e::LC_TYPE_2_4_T)
            || (device_property == la_device_property_e::ENABLE_MBIST_REPAIR)
            || (device_property == la_device_property_e::IGNORE_MBIST_ERRORS)
            || (device_property == la_device_property_e::EMULATED_DEVICE)
            || (device_property == la_device_property_e::DEVICE_FREQUENCY)
            || (device_property == la_device_property_e::TCK_FREQUENCY)
            || (device_property == la_device_property_e::USING_LEABA_NIC)
            || (device_property == la_device_property_e::ENABLE_NARROW_COUNTERS)
            || (device_property == la_device_property_e::MAX_COUNTER_THRESHOLD)
            || (device_property == la_device_property_e::LPM_TCAM_BANK_SIZE)
            || (device_property == la_device_property_e::LPM_TCAM_NUM_BANKSETS)
            || (device_property == la_device_property_e::ENABLE_NSIM_ACCURATE_SCALE_MODEL)
            || (device_property == la_device_property_e::ENABLE_PACIFIC_OOB_INTERLEAVING)
            || (device_property == la_device_property_e::ENABLE_PACIFIC_B0_IFG_CHANGES)
            || (device_property == la_device_property_e::MATILDA_MODEL_TYPE)
            || (device_property == la_device_property_e::ENABLE_POWER_SAVING_MODE)) {
            return false;
        }
    }

    if (m_init_phase == init_phase_e::TOPOLOGY) {
        if ((device_property == la_device_property_e::LC_FORCE_FORWARD_THROUGH_FABRIC_MODE)
            || (device_property == la_device_property_e::TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)
            || (device_property == la_device_property_e::TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES)
            || (device_property == la_device_property_e::ENABLE_MPLS_SR_ACCOUNTING)
            || (device_property == la_device_property_e::ENABLE_PBTS)
            || (device_property == la_device_property_e::LC_56_FABRIC_PORT_MODE)
            || (device_property == la_device_property_e::CREDIT_SIZE_IN_BYTES)) {

            return false;
        }
    }

    return true;
}

la_status
la_device_impl::get_bfd_inject_up_mac_address(la_mac_addr_t& addr) const
{
    addr = m_inject_up_mac;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_bfd_inject_up_mac_address(la_mac_addr_t addr)
{
    start_api_call("mac_addr=", addr);

    la_status status;
    m_inject_up_mac = addr;

    // Set the MAC address in the BFD tables
    {
        npl_bfd_inject_inner_da_high_table_t::key_type k{};
        npl_bfd_inject_inner_da_high_table_t::value_type v{};
        npl_bfd_inject_inner_da_high_table_t::entry_pointer_type e = nullptr;

        // Set the higher 16b
        v.payloads.set_inject_inner_da.da = addr.word[2];

        status = m_tables.bfd_inject_inner_da_high_table->set(k, v, e);
        return_on_error(status);
    }

    {
        npl_bfd_inject_inner_da_low_table_t::key_type k{};
        npl_bfd_inject_inner_da_low_table_t::value_type v{};
        npl_bfd_inject_inner_da_low_table_t::entry_pointer_type e = nullptr;

        // Set the lower 32b
        v.payloads.set_inject_inner_da.da = addr.flat & 0xffffffff;

        status = m_tables.bfd_inject_inner_da_low_table->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_bfd_session(la_bfd_discriminator local_discriminator,
                                   la_bfd_session::type_e session_type,
                                   la_l3_protocol_e protocol,
                                   const la_punt_destination* punt_destination,
                                   la_bfd_session*& out_bfd_session)
{
    start_api_call("local_discriminator=",
                   local_discriminator,
                   "session_type=",
                   session_type,
                   "protocol=",
                   protocol,
                   "punt_destination=",
                   punt_destination);

    // Ensure events for previously deleted sessions are cleared before possibly reusing an id
    poll_npu_host_event_queue();

    auto session = std::make_shared<la_bfd_session_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(session, oid);
    return_on_error(status);

    status = session->initialize(oid, local_discriminator, session_type, protocol, get_sptr(punt_destination));

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    // Add local sessions only to the array
    if (!session->is_remote()) {
        m_bfd_sessions[session->get_internal_id()] = session;
    }

    out_bfd_session = session.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_bfd_session(const la_bfd_session_base_wptr& bfd_session)
{
    if (bfd_session == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(bfd_session, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!bfd_session->is_remote()) {
        m_bfd_sessions[bfd_session->get_internal_id()] = nullptr;
    }

    la_status status = bfd_session->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::update_tpid_table(const la_vlan_edit_command& edit_command, size_t& out_tpid_profile)
{
    npl_vlan_edit_tpid1_profile_hw_table_t::key_type k1;
    npl_vlan_edit_tpid1_profile_hw_table_t::value_type v1;
    npl_vlan_edit_tpid1_profile_hw_table_t::entry_pointer_type e1;

    npl_vlan_edit_tpid2_profile_hw_table_t::key_type k2;
    npl_vlan_edit_tpid2_profile_hw_table_t::value_type v2;
    npl_vlan_edit_tpid2_profile_hw_table_t::entry_pointer_type e2;

    size_t tpid_profile = 0;
    for (tpid_profile = 0; tpid_profile < m_tables.vlan_edit_tpid1_profile_hw_table->size(); ++tpid_profile) {

        k1.vlan_edit_info_tpid_profile = tpid_profile;
        k2.vlan_edit_info_tpid_profile = tpid_profile;

        la_status st = m_tables.vlan_edit_tpid1_profile_hw_table->lookup(k1, e1);

        return_on_error(st);

        st = m_tables.vlan_edit_tpid2_profile_hw_table->lookup(k2, e2);

        return_on_error(st);

        v1 = e1->value();
        v2 = e2->value();

        if (edit_command.num_tags_to_push >= 1 && (v1.payloads.vlan_edit_info_tpid1 != edit_command.tag0.tpid)) {
            continue;
        }

        if ((edit_command.num_tags_to_push >= 2) && (v2.payloads.vlan_edit_info_tpid2 == LA_VLAN_TAG_UNTAGGED.tpid)) {
            out_tpid_profile = tpid_profile;
            break;
        }
        if (((edit_command.num_tags_to_push >= 2) && (v2.payloads.vlan_edit_info_tpid2 == edit_command.tag1.tpid))
            || (edit_command.num_tags_to_push == 1)) {
            out_tpid_profile = tpid_profile;
            return LA_STATUS_SUCCESS;
        }
    }

    if (tpid_profile >= NUM_TPID_PROFILES) {
        return LA_STATUS_ERESOURCE;
    }
    if (tpid_profile == m_tables.vlan_edit_tpid1_profile_hw_table->size()) {
        out_tpid_profile = m_tables.vlan_edit_tpid1_profile_hw_table->size();
    }

    k1.vlan_edit_info_tpid_profile = out_tpid_profile;
    v1.action = NPL_VLAN_EDIT_TPID1_PROFILE_HW_TABLE_ACTION_WRITE;
    v1.payloads.vlan_edit_info_tpid1 = edit_command.tag0.tpid;

    k2.vlan_edit_info_tpid_profile = out_tpid_profile;
    v2.action = NPL_VLAN_EDIT_TPID2_PROFILE_HW_TABLE_ACTION_WRITE;
    v2.payloads.vlan_edit_info_tpid2 = edit_command.tag1.tpid;

    la_status status = m_tables.vlan_edit_tpid1_profile_hw_table->set(k1, v1, e1);
    return_on_error(status);

    status = m_tables.vlan_edit_tpid2_profile_hw_table->set(k2, v2, e2);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::populate_vlan_edit_command_tpids(size_t tpid_profile, la_vlan_edit_command& out_edit_command)
{
    if (out_edit_command.num_tags_to_push == 0) {
        return LA_STATUS_SUCCESS;
    }
    npl_vlan_edit_tpid1_profile_hw_table_t::key_type k1;
    npl_vlan_edit_tpid1_profile_hw_table_t::value_type v1;
    npl_vlan_edit_tpid1_profile_hw_table_t::entry_pointer_type e1;

    k1.vlan_edit_info_tpid_profile = tpid_profile;
    la_status status = m_tables.vlan_edit_tpid1_profile_hw_table->lookup(k1, e1);
    return_on_error(status);

    v1 = e1->value();
    out_edit_command.tag0.tpid = v1.payloads.vlan_edit_info_tpid1;

    if (out_edit_command.num_tags_to_push == 1) {
        return LA_STATUS_SUCCESS;
    }

    npl_vlan_edit_tpid2_profile_hw_table_t::key_type k2;
    npl_vlan_edit_tpid2_profile_hw_table_t::value_type v2;
    npl_vlan_edit_tpid2_profile_hw_table_t::entry_pointer_type e2;

    k2.vlan_edit_info_tpid_profile = tpid_profile;
    status = m_tables.vlan_edit_tpid2_profile_hw_table->lookup(k2, e2);
    return_on_error(status);

    v2 = e2->value();
    out_edit_command.tag1.tpid = v2.payloads.vlan_edit_info_tpid2;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy()
{
    // Release sgacl counter cache.
    la_status status = release_sgacl_allocation_cache();
    return_on_error(status);

    // Disable WB checks at destruction
    m_warm_boot_disconnected = false;

    // Stop pollers, state machines and interrupt handling.
    // Must be called outside of API lock.
    // At this point, we are protected only by the global m_device_creation_mutex but not by m_mutex.
    // It means that API calls can still be made while we block on m_notification->stop().
    m_notification->stop();

    // start_api_call() and the internal api_lock_guard<> both need a healthy ll_device, which is being destroyed here.
    // Hence, don't use any of them and lock the mutex directly instead.
    std::lock_guard<std::recursive_mutex> guard(m_mutex);

    m_notification.reset();

    if (m_serdes_device_handler != nullptr) {
        m_serdes_device_handler->destroy();
    }

    apb* apb_serdes_handler = m_apb_handlers[apb_interface_type_e::SERDES].get();
    srm::clear_apb(apb_serdes_handler);

    m_apb_handlers.clear();

    m_cpu2jtag_handler->disable();
    m_cpu2jtag_handler.reset();

    // Tasks are stopped and periodic flush is not active, need to flush explicitly.
    la_flush_log();

    if (m_init_phase != init_phase_e::TOPOLOGY) {
        for (la_slice_ifg s_ifg : m_slice_id_manager->get_all_possible_ifgs()) {
            if (m_ifg_schedulers[s_ifg.slice][s_ifg.ifg] != nullptr) {
                m_ifg_schedulers[s_ifg.slice][s_ifg.ifg].reset();
            }
        }
    }

    m_objects[0].reset();
    return LA_STATUS_SUCCESS;
}

la_device_impl::~la_device_impl()
{
    // Destructor is better be left empty, shared_from_this() won't work during object's destruction.
    // Use la_device_impl::destroy() for tear down sequence.
}

la_device_impl_base_sptr
la_device_impl::get_sptr()
{
    return shared_from_this();
}

la_l2_destination_gid_t
la_device_impl::get_l2_destination_gid(const la_l2_destination_wcptr& l2_dest) const
{
    // TODO - this is a temporary function. Eventually all will call a global get_destination_id.
    destination_id dest_id = silicon_one::get_destination_id(l2_dest, RESOLUTION_STEP_FORWARD_L2);
    return dest_id.val;
}

la_l2_destination_wptr
la_device_impl::get_l2_destination_by_gid(la_l2_destination_gid_t l2_destination_gid) const
{
    if (l2_destination_gid == LA_L2_DESTINATION_GID_INVALID) {
        return nullptr;
    }

    if (l2_destination_gid > MAX_L2_DESTINATION_GID) {
        return nullptr;
    }

    return m_l2_destinations[l2_destination_gid];
}

la_status
la_device_impl::get_l2_punt_destination_by_gid(la_l2_punt_destination_gid_t gid, la_l2_punt_destination*& out_punt_dest) const
{
    if (gid >= MAX_L2_PUNT_DESTINATION_GID) {
        return LA_STATUS_EINVAL;
    }

    auto punt_dest = m_l2_punt_destinations[gid];
    if (punt_dest == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    if (punt_dest->type() != object_type_e::L2_PUNT_DESTINATION) {
        return LA_STATUS_ENOTFOUND;
    }

    out_punt_dest = punt_dest.get();

    return LA_STATUS_SUCCESS;
}

la_l3_destination_wptr
la_device_impl::get_l3_destination_by_gid(la_l3_destination_gid_t l3_destination_gid) const
{
    if (l3_destination_gid == LA_L3_DESTINATION_GID_INVALID) {
        return nullptr;
    }

    if (l3_destination_gid > MAX_L3_DESTINATION_GID) {
        return nullptr;
    }

    lpm_destination_id lpm_id = l3_destination_gid_2_lpm_destination_id(l3_destination_gid);

    return m_l3_destinations[lpm_id.val];
}

la_l3_destination_gid_t
la_device_impl::get_l3_destination_gid(const la_l3_destination_wcptr& l3_destination, bool is_lpm_format) const
{
    // TODO - this is a temporary function. Eventually all will call a global get_lpm_destination_id.

    if (is_lpm_format) {
        lpm_destination_id lpm_dest_id = silicon_one::get_lpm_destination_id(l3_destination, RESOLUTION_STEP_FORWARD_L3);
        return lpm_dest_id.val;
    } else {
        destination_id dest_id = silicon_one::get_destination_id(l3_destination, RESOLUTION_STEP_FORWARD_L3);
        return dest_id.val;
    }
}

la_mirror_command_wptr
la_device_impl::get_mirror_command_by_gid(la_mirror_gid_t mirror_gid) const
{
    if (mirror_gid >= MAX_MIRROR_GID) {
        return nullptr;
    }

    return m_mirror_commands[mirror_gid];
}

la_status
la_device_impl::create_mpls_swap_nhlfe(const la_next_hop* next_hop, la_mpls_label label, la_mpls_nhlfe*& out_nhlfe)
{
    start_api_call("next_hop=", next_hop, "label=", label);

    auto nhlfe = std::make_shared<la_mpls_nhlfe_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(nhlfe, oid);
    return_on_error(status);
    status = nhlfe->initialize_swap(oid, get_sptr(next_hop), label);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_nhlfe = nhlfe.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_mpls_tunnel_protection_nhlfe(const la_l3_protection_group* l3_protection_group,
                                                    la_mpls_label te_label,
                                                    la_mpls_label mp_label,
                                                    la_mpls_nhlfe*& out_nhlfe)
{
    start_api_call("l3_protection_group=", l3_protection_group, "te_label=", te_label, "mp_label=", mp_label);

    auto nhlfe = std::make_shared<la_mpls_nhlfe_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(nhlfe, oid);
    return_on_error(status);
    status = nhlfe->initialize_tunnel_protection(oid, get_sptr(l3_protection_group), te_label, mp_label);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_nhlfe = nhlfe.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_mpls_l2_adjacency_nhlfe(const la_prefix_object* prefix, const la_system_port* dsp, la_mpls_nhlfe*& out_nhlfe)
{
    start_api_call("prefix=", prefix, "dsp=", dsp);

    auto nhlfe = std::make_shared<la_mpls_nhlfe_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(nhlfe, oid);
    return_on_error(status);
    status = nhlfe->initialize_l2_adjacency(oid, get_sptr(prefix), get_sptr(dsp));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_nhlfe = nhlfe.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_mpls_php_nhlfe(const la_next_hop* next_hop, la_mpls_nhlfe*& out_nhlfe)
{
    start_api_call("next_hop=", next_hop);

    auto nhlfe = std::make_shared<la_mpls_nhlfe_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(nhlfe, oid);
    return_on_error(status);
    status = nhlfe->initialize_php(oid, get_sptr(next_hop));
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_nhlfe = nhlfe.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_mpls_vpn_encap(la_mpls_vpn_encap_gid_t gid, la_mpls_vpn_encap*& out_mpls_vpn_encap)
{
    start_api_call("gid=", gid);

    if (gid >= MAX_MPLS_VPN_ENCAP_GIDS) {
        return LA_STATUS_EINVAL;
    }

    if (m_mpls_vpn_encap[gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    la_l3_destination_gid_t lpm_dest_gid = NPL_DESTINATION_MASK_IP_PREFIX_ID | gid;
    if (m_l3_destinations[lpm_dest_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    auto vpn_encap = std::make_shared<la_mpls_vpn_encap_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(vpn_encap, oid);
    return_on_error(status);
    status = vpn_encap->initialize(oid, gid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_l3_destinations[lpm_dest_gid] = vpn_encap;
    m_mpls_vpn_encap[gid] = vpn_encap;

    out_mpls_vpn_encap = vpn_encap.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_mpls_vpn_encap_by_gid(la_mpls_vpn_encap_gid_t gid, la_mpls_vpn_encap*& out_mpls_vpn_encap) const
{
    start_api_getter_call("gid=", gid);

    if (gid >= MAX_MPLS_VPN_ENCAP_GIDS) {
        return LA_STATUS_EINVAL;
    }

    const auto& vpn_encap = m_mpls_vpn_encap[gid];

    if (vpn_encap == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    if (vpn_encap->type() != object_type_e::MPLS_VPN_ENCAP) {
        return LA_STATUS_ENOTFOUND;
    }

    out_mpls_vpn_encap = vpn_encap.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_mpls_nhlfe(const la_mpls_nhlfe_impl_wptr& nhlfe)
{
    if (nhlfe == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(nhlfe, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = nhlfe->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_mpls_vpn_decap(const la_mpls_vpn_decap_impl_wptr& vpn_decap)
{
    if (vpn_decap == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vpn_decap, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = vpn_decap->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_mpls_vpn_encap(const la_mpls_vpn_encap_impl_wptr& vpn_encap)
{
    if (vpn_encap == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vpn_encap, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_mpls_vpn_encap_gid_t gid = vpn_encap->get_gid();

    la_l3_destination_gid_t lpm_gid = get_l3_destination_gid(vpn_encap, true /* is_lpm_destination */);

    if (m_l3_destinations[lpm_gid] != vpn_encap) {
        return LA_STATUS_ENOTFOUND;
    }

    la_status status = vpn_encap->destroy();
    return_on_error(status);

    m_mpls_vpn_encap[gid] = nullptr;
    m_l3_destinations[lpm_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_mldp_vpn_decap(const la_mldp_vpn_decap_impl_wptr& vpn_decap)
{
    if (vpn_decap == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vpn_decap, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = vpn_decap->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_accounted_packet_overhead(int& out_overhead) const
{
    // TODO GB - impl needs to change (pdvoq, ics). not mandatory for bringup.
    // la_status status = retrieve_overhead_accounting(out_overhead);
    // return_on_error(status);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::set_accounted_packet_overhead(int overhead)
{
    // TODO GB - impl needs to change (pdvoq, ics). not mandatory for bringup.
    // la_status status = configure_overhead_accounting(overhead);
    // return_on_error(status);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::get_ifg_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::get_native_sbus_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::get_pci_aapl_handler(Aapl_t*& out_aapl)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::get_hbm_aapl_handler(size_t hbm_interface, Aapl_t*& out_aapl)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::get_hbm_handler(la_hbm_handler*& out_hbm)
{
    out_hbm = m_hbm_handler.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_ptp_handler(la_ptp_handler*& out_ptp)
{
    out_ptp = m_ptp_handler.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_apb_handler_sptr(apb_interface_type_e interface_type, apb_sptr& out_apb_sptr)
{
    if (interface_type > apb_interface_type_e::LAST) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_apb_sptr = m_apb_handlers[interface_type];

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_apb_handler(apb_interface_type_e interface_type, apb*& out_apb)
{
    start_api_getter_call("interface_type=", interface_type);

    apb_sptr apb_sptr;
    la_status status = get_apb_handler_sptr(interface_type, apb_sptr);
    return_on_error(status);
    out_apb = apb_sptr.get();

    return LA_STATUS_SUCCESS;
}

cpu2jtag_sptr
la_device_impl::get_cpu2jtag_handler_sptr()
{
    return m_cpu2jtag_handler;
}

la_status
la_device_impl::get_cpu2jtag_handler(cpu2jtag*& out_cpu2jtag)
{
    start_api_getter_call();

    cpu2jtag_sptr cpu2jtag_sptr = get_cpu2jtag_handler_sptr();

    out_cpu2jtag = cpu2jtag_sptr.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_info_phy_handler(la_info_phy_handler*& out_info_phy)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::get_flow_cache_handler(la_flow_cache_handler*& out_flow_cache_handler)
{
    start_api_getter_call();

    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_EINVAL;
    }

    out_flow_cache_handler = m_flow_cache_handler.get();

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::add_object_dependency(const la_object* dependee, const la_object* dependent)
{
    add_object_dependency(get_sptr(dependee), get_sptr<const la_object>(dependent));
}
void
la_device_impl::add_object_dependency(const la_object_wcptr& dependee, const la_object* dependent)
{
    add_object_dependency(dependee, get_sptr<const la_object>(dependent));
}
void
la_device_impl::add_object_dependency(const la_object* dependee, const la_object_wcptr& dependent)
{
    add_object_dependency(get_sptr(dependee), dependent);
}
void
la_device_impl::add_object_dependency(const la_object_wcptr& dependee, const la_object_wcptr& dependent)
{
    m_object_dependencies[dependee].insert(dependent.weak_ptr_const_cast<la_object>());
}

void
la_device_impl::remove_object_dependency(const la_object* dependee, const la_object* dependent)
{
    remove_object_dependency(get_sptr(dependee), get_sptr(dependent));
}
void
la_device_impl::remove_object_dependency(const la_object_wcptr& dependee, const la_object* dependent)
{
    remove_object_dependency(dependee, get_sptr(dependent));
}
void
la_device_impl::remove_object_dependency(const la_object* dependee, const la_object_wcptr& dependent)
{
    remove_object_dependency(get_sptr(dependee), dependent);
}
void
la_device_impl::remove_object_dependency(const la_object_wcptr& dependee, const la_object_wcptr& dependent)
{
    auto& dependencies_set = m_object_dependencies[dependee];

    auto it = dependencies_set.find(dependent.weak_ptr_const_cast<la_object>());
    if (it != dependencies_set.end()) {
        dependencies_set.erase(it);
    }

    if (dependencies_set.size() == 0) {
        m_object_dependencies.erase(dependee);
    }
}

void
la_device_impl::add_ifg_dependency(const la_object_wcptr& dependee, const dependency_listener_wptr& dependent)
{
    m_ifg_dependencies[dependee].emplace(dependent);
}

void
la_device_impl::add_ifg_dependency(const la_object_wcptr& dependee, dependency_listener* dependent)
{
    auto dependent_obj = dynamic_cast<la_object*>(dependent);
    dassert_crit(dependent_obj != nullptr);
    auto object_sptr = get_sptr(dependent_obj);
    auto dependent_sptr = std::dynamic_pointer_cast<dependency_listener>(object_sptr);
    dassert_crit(dependent_sptr != nullptr);

    add_ifg_dependency(dependee, dependent_sptr);
}

void
la_device_impl::add_ifg_dependency(const la_object* dependee, const dependency_listener_wptr& dependent)
{
    add_ifg_dependency(get_sptr(dependee), dependent);
}

void
la_device_impl::add_ifg_dependency(const la_object* dependee, dependency_listener* dependent)
{
    auto dependent_obj = dynamic_cast<la_object*>(dependent);
    dassert_crit(dependent_obj != nullptr);
    auto object_sptr = get_sptr(dependent_obj);
    auto dependent_sptr = std::dynamic_pointer_cast<dependency_listener>(object_sptr);
    dassert_crit(dependent_sptr != nullptr);

    add_ifg_dependency(get_sptr(dependee), dependent_sptr);
}

void
la_device_impl::remove_ifg_dependency(const la_object_wcptr& dependee, const dependency_listener_wptr& dependent)
{
    auto& dependencies_map = m_ifg_dependencies[dependee];

    auto it = dependencies_map.find(dependent);
    if (it != dependencies_map.end()) {
        dependencies_map.erase(it);
    }

    if (dependencies_map.size() == 0) {
        m_ifg_dependencies.erase(dependee);
    }
}

void
la_device_impl::remove_ifg_dependency(const la_object* dependee, const dependency_listener_wptr& dependent)
{
    remove_ifg_dependency(get_sptr(dependee), dependent);
}

void
la_device_impl::remove_ifg_dependency(const la_object_wcptr& dependee, dependency_listener* dependent)
{
    auto dependent_obj = dynamic_cast<la_object*>(dependent);
    dassert_crit(dependent_obj != nullptr);
    auto object_sptr = get_sptr(dependent_obj);
    auto dependent_sptr = std::dynamic_pointer_cast<dependency_listener>(object_sptr);
    dassert_crit(dependent_sptr != nullptr);

    remove_ifg_dependency(dependee, dependent_sptr);
}
void
la_device_impl::remove_ifg_dependency(const la_object* dependee, dependency_listener* dependent)
{
    auto dependent_obj = dynamic_cast<la_object*>(dependent);
    dassert_crit(dependent_obj != nullptr);
    auto object_sptr = get_sptr(dependent_obj);
    auto dependent_sptr = std::dynamic_pointer_cast<dependency_listener>(object_sptr);
    dassert_crit(dependent_sptr != nullptr);

    remove_ifg_dependency(get_sptr(dependee), dependent_sptr);
}

bool
la_device_impl::is_in_use(const la_object_wcptr& obj)
{
    const auto& it = m_object_dependencies.find(obj);

    if (it != m_object_dependencies.end()) {
        auto deplist = it->second;
        dassert_crit(deplist.size() > 0);
        auto dli = deplist.begin();
        log_debug(HLD, "%s: %s is still used by %s", __func__, obj->to_string().c_str(), (*dli)->to_string().c_str());
    }

    return (it != m_object_dependencies.end());
}

bool
la_device_impl::is_in_use(const la_object* obj)
{
    la_object_wcptr obj_wptr = get_sptr(obj);
    return is_in_use(obj_wptr);
}

std::vector<la_object*>
la_device_impl::get_dependent_objects(const la_object* dependee) const
{
    start_api_getter_call("dependee=", dependee);

    std::vector<la_object*> deps;

    if (dependee == nullptr) {
        log_err(HLD, "%s: NULL dependee", __func__);
        return deps;
    }

    if (!of_same_device(dependee, this)) {
        log_err(HLD, "%s: dependee doesn't belong to this device", __func__);
        return deps;
    }

    la_object_wcptr dependee_wptr = get_sptr(dependee);
    const auto& it = m_object_dependencies.find(dependee_wptr);
    if (it == m_object_dependencies.end()) {
        // No dependencies
        return deps;
    }

    const auto& dependecy_list = it->second;
    for (const auto& dependent : dependecy_list) {
        deps.push_back(dependent.get());
    }

    return deps;
}

la_uint_t
la_device_impl::get_dependent_objects_count(const la_object* dependee) const
{
    start_api_getter_call("dependee=", dependee);

    if (dependee == nullptr) {
        log_err(HLD, "%s: NULL dependee", __func__);
        return 0;
    }

    la_object_wcptr dependee_wptr = get_sptr(dependee);

    if (!of_same_device(this, dependee_wptr)) {
        log_err(HLD, "%s: dependee doesn't belong to this device", __func__);
        return 0;
    }

    const auto it = m_object_dependencies.find(dependee_wptr);

    if (it != m_object_dependencies.end()) {
        return it->second.size();
    }

    return 0;
}

la_status
la_device_impl::notify_ifg_added(const la_object* dependee, la_slice_ifg ifg)
{
    dependency_management_op op;
    op.type_e = dependency_management_op::management_type_e::IFG_MANAGEMENT;
    op.action.ifg_management.ifg_op = ifg_management_op::IFG_ADD;
    op.action.ifg_management.ifg = ifg;
    op.dependee = dependee;

    return do_dependency_management_op(op);
}
la_status
la_device_impl::notify_ifg_added(const la_object_wcptr& dependee, la_slice_ifg ifg)
{
    return notify_ifg_added(dependee.get(), ifg);
}

la_status
la_device_impl::notify_ifg_removed(const la_object* dependee, la_slice_ifg ifg)
{
    dependency_management_op op;
    op.type_e = dependency_management_op::management_type_e::IFG_MANAGEMENT;
    op.action.ifg_management.ifg_op = ifg_management_op::IFG_REMOVE;
    op.action.ifg_management.ifg = ifg;
    op.dependee = dependee;

    return do_dependency_management_op(op);
}
la_status
la_device_impl::notify_ifg_removed(const la_object_wcptr& dependee, la_slice_ifg ifg)
{
    return notify_ifg_removed(dependee.get(), ifg);
}

class la_object_deleter
{
public:
    void operator()(la_object* p)
    {
        delete p;
    }
};

void
la_device_impl::deregister_object(la_object_id_t oid)
{
    if (oid == LA_OBJECT_ID_INVALID) {
        return; // May happen with internal fec objects
    }

    m_index_generators.oids.release(oid);
    dassert_crit(oid < m_objects.size());
    m_objects[oid].reset();
}

void
la_device_impl::create_resource_manager(ll_device_sptr ldevice)
{
    m_resource_manager = std::make_shared<resource_manager>(ldevice);
    configure_device_int_property(la_device_property_e::LPM_REBALANCE_INTERVAL, 0);
    configure_device_int_property(la_device_property_e::LPM_REBALANCE_START_FAIRNESS_THRESHOLD_PERCENT, 0);
    configure_device_int_property(la_device_property_e::LPM_REBALANCE_END_FAIRNESS_THRESHOLD_PERCENT, 0);
    configure_device_int_property(la_device_property_e::LPM_TCAM_SINGLE_WIDTH_KEY_WEIGHT, 0);
    configure_device_int_property(la_device_property_e::LPM_TCAM_DOUBLE_WIDTH_KEY_WEIGHT, 0);
    configure_device_int_property(la_device_property_e::LPM_TCAM_QUAD_WIDTH_KEY_WEIGHT, 0);
}

resource_manager_wcptr
la_device_impl::get_resource_manager() const
{
    return m_resource_manager;
}

counter_manager_wcptr
la_device_impl::get_counter_bank_manager() const
{
    return m_counter_bank_manager;
}

la_status
la_device_impl::undo_attribute_management_op(dependency_management_op op, const dependency_listener_wptr& last_node)
{
    attribute_management_details undo_amd = op.undo(op.action.attribute_management);
    op.action.attribute_management = undo_amd;

    la_object_wcptr dependee = get_sptr(op.dependee);
    auto& attribute_map(m_attribute_dependencies[dependee]);
    auto& refcount_multimap = attribute_map[undo_amd.op];

    for (auto& it : refcount_multimap) {
        auto& dep_slot = it.first;
        if (dep_slot == last_node) {
            return LA_STATUS_SUCCESS;
        }
        la_status status = dep_slot->notify_change(op);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::undo_ifg_dependency_management_op(dependency_management_op op, const dependency_listener_wptr& last_node)
{
    la_object_wcptr dependee = get_sptr(op.dependee);
    auto& dependencies_list(m_ifg_dependencies[dependee]);
    op.action.ifg_management.ifg_op = (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD)
                                          ? ifg_management_op::IFG_REMOVE
                                          : ifg_management_op::IFG_ADD;
    for (auto dep : dependencies_list) {
        if (dep == last_node) {
            return LA_STATUS_SUCCESS;
        }
        la_status status = dep->notify_change(op);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_dependency_management_op(dependency_management_op op)
{
    la_object_wcptr dependee = get_sptr(op.dependee);
    if (op.type_e == dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT) {
        auto& dependencies_list = m_attribute_dependencies[dependee][op.action.attribute_management.op];

        for (auto& dependent : dependencies_list) {
            la_status status = dependent.first->notify_change(op);
            if (status != LA_STATUS_SUCCESS) {
                la_status undo_status = undo_attribute_management_op(op, dependent.first);
                return_on_error(undo_status);
            }
            return_on_error(status);
        }

        return LA_STATUS_SUCCESS;
    }

    auto& dependencies_list = m_ifg_dependencies[dependee];

    for (auto& dependent : dependencies_list) {
        la_status status = dependent->notify_change(op);
        if (status != LA_STATUS_SUCCESS) {
            la_status undo_status = undo_ifg_dependency_management_op(op, dependent);
            return_on_error(undo_status);
        }
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::add_attribute_dependency(const la_object_wcptr& dependee,
                                         const dependency_listener_wptr& dependent,
                                         bit_vector attributes)
{
    for (size_t attribute_index = 0; attribute_index < attributes.get_width(); attribute_index++) {
        if (attributes.bit(attribute_index)) {
            auto attr = static_cast<attribute_management_op>(1 << attribute_index);
            auto& dependency_map = m_attribute_dependencies[dependee][attr];

            auto it = dependency_map.find(dependent);
            if (it != dependency_map.end()) {
                it->second++;
            } else {
                m_attribute_dependencies[dependee][attr].emplace(dependent, 1);
            }
        }
    }
}

void
la_device_impl::add_attribute_dependency(const la_object_wcptr& dependee, dependency_listener* dependent, bit_vector attributes)
{
    auto dependent_obj = dynamic_cast<la_object*>(dependent);
    dassert_crit(dependent_obj != nullptr);
    auto object_sptr = get_sptr(dependent_obj);
    auto dependent_sptr = std::dynamic_pointer_cast<dependency_listener>(object_sptr);
    dassert_crit(dependent_sptr != nullptr);

    add_attribute_dependency(dependee, dependent_sptr, attributes);
}

void
la_device_impl::add_attribute_dependency(const la_object* dependee,
                                         const dependency_listener_wptr& dependent,
                                         bit_vector attributes)
{
    add_attribute_dependency(get_sptr(dependee), dependent, attributes);
}
void
la_device_impl::add_attribute_dependency(const la_object* dependee, dependency_listener* dependent, bit_vector attributes)
{
    auto dependent_obj = dynamic_cast<la_object*>(dependent);
    dassert_crit(dependent_obj != nullptr);
    auto object_sptr = get_sptr(dependent_obj);
    auto dependent_sptr = std::dynamic_pointer_cast<dependency_listener>(object_sptr);
    dassert_crit(dependent_sptr != nullptr);

    add_attribute_dependency(get_sptr(dependee), dependent_sptr, attributes);
}

void
la_device_impl::remove_attribute_dependency(const la_object_wcptr& dependee,
                                            const dependency_listener_wptr& dependent,
                                            bit_vector attributes)
{
    for (size_t attribute_index = 0; attribute_index < attributes.get_width(); attribute_index++) {
        if (attributes.bit(attribute_index)) {
            auto attr = static_cast<attribute_management_op>(1 << attribute_index);
            auto& dependency_map = m_attribute_dependencies[dependee][attr];

            auto it = dependency_map.find(dependent);
            if (it != dependency_map.end()) {
                it->second--;
                if (it->second == 0) {
                    dependency_map.erase(it);
                }
            }
        }
    }
}
void
la_device_impl::remove_attribute_dependency(const la_object_wcptr& dependee, dependency_listener* dependent, bit_vector attributes)
{
    auto dependent_obj = dynamic_cast<la_object*>(dependent);
    dassert_crit(dependent_obj != nullptr);
    auto object_sptr = get_sptr(dependent_obj);
    auto dependent_sptr = std::dynamic_pointer_cast<dependency_listener>(object_sptr);
    dassert_crit(dependent_sptr != nullptr);

    remove_attribute_dependency(dependee, dependent_sptr, attributes);
}
void
la_device_impl::remove_attribute_dependency(const la_object* dependee,
                                            const dependency_listener_wptr& dependent,
                                            bit_vector attributes)
{
    remove_attribute_dependency(get_sptr(dependee), dependent, attributes);
}
void
la_device_impl::remove_attribute_dependency(const la_object* dependee, dependency_listener* dependent, bit_vector attributes)
{
    auto dependent_obj = dynamic_cast<la_object*>(dependent);
    dassert_crit(dependent_obj != nullptr);
    auto object_sptr = get_sptr(dependent_obj);
    auto dependent_sptr = std::dynamic_pointer_cast<dependency_listener>(object_sptr);
    dassert_crit(dependent_sptr != nullptr);

    remove_attribute_dependency(get_sptr(dependee), dependent_sptr, attributes);
}

la_status
la_device_impl::notify_attribute_changed(const la_object* dependee,
                                         attribute_management_details& attribute,
                                         const la_amd_undo_callback_funct_t& undo)
{
    dependency_management_op op;
    op.type_e = dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT;
    op.action.attribute_management = attribute;
    op.dependee = dependee;
    op.undo = undo;

    return do_dependency_management_op(op);
}

la_status
la_device_impl::create_counter(size_t set_size, la_counter_set*& out_counter)
{
    start_api_call("set_size=", set_size);
    auto counter = std::make_shared<la_counter_set_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(counter, oid);
    return_on_error(status);

    status = counter->initialize(oid, set_size);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_counter = counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_counter(const la_counter_set_impl_wptr& counter)
{
    if (counter == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(counter, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = counter->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_create_meter(la_meter_set::type_e set_type, size_t set_size, la_meter_set_impl_wptr& out_meter)
{
    std::shared_ptr<la_meter_set_impl> meter;
    switch (set_type) {
    case la_meter_set::type_e::STATISTICAL: {
        meter = std::static_pointer_cast<la_meter_set_impl>(std::make_shared<la_meter_set_statistical_impl>(shared_from_this()));
        break;
    }
    case la_meter_set::type_e::EXACT:
    case la_meter_set::type_e::PER_IFG_EXACT: {
        meter = std::static_pointer_cast<la_meter_set_impl>(std::make_shared<la_meter_set_exact_impl>(shared_from_this()));
        break;
    }
    default: {
        out_meter = nullptr;
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    }

    la_object_id_t oid;
    la_status status = register_object(meter, oid);
    return_on_error(status);
    status = meter->initialize(oid, set_type, set_size);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_meter = meter;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_meter(la_meter_set::type_e set_type, size_t set_size, la_meter_set*& out_meter)
{
    start_api_call("set_type=", set_type, "set_size=", set_size);
    la_meter_set_impl_wptr out_meter_wptr;
    la_status status = do_create_meter(set_type, set_size, out_meter_wptr);
    return_on_error(status);

    out_meter = out_meter_wptr.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_meter(const la_meter_set_impl_wptr& meter)
{
    if (meter == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(meter, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = meter->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_rate_limiters(const la_rate_limiter_set_base_wptr& rate_limiters)
{
    if (rate_limiters == nullptr) {
        return LA_STATUS_EINVAL;
    }
    if (!of_same_device(rate_limiters, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = rate_limiters->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_security_group_cell(const la_security_group_cell_base_wptr& sg_cell)
{
    if (sg_cell == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (sg_cell->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = sg_cell->destroy();
    return_on_error(status);

    if (m_security_group_cell_map.empty()) {
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_meter_profile(la_meter_profile::type_e profile_type,
                                     la_meter_profile::meter_measure_mode_e meter_measure_mode,
                                     la_meter_profile::meter_rate_mode_e meter_rate_mode,
                                     la_meter_profile::color_awareness_mode_e color_awareness_mode,
                                     la_meter_profile*& out_meter_profile)
{
    start_api_call("profile_type=",
                   profile_type,
                   "meter_measure_mode=",
                   meter_measure_mode,
                   "meter_rate_mode=",
                   meter_rate_mode,
                   "color_awareness_mode=",
                   color_awareness_mode);

    auto meter_profile = std::make_shared<la_meter_profile_impl>(
        shared_from_this(), profile_type, meter_measure_mode, meter_rate_mode, color_awareness_mode);
    la_object_id_t oid;
    la_status status = register_object(meter_profile, oid);
    return_on_error(status);

    status = meter_profile->initialize(oid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_meter_profile = meter_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_meter_profile(const la_meter_profile_impl_wptr& meter_profile)
{

    if (meter_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(meter_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = meter_profile->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_meter_markdown_profile(la_meter_markdown_gid_t meter_markdown_gid,
                                              la_meter_markdown_profile*& out_meter_markdown_profile)
{
    start_api_call("meter_markdown_gid=", meter_markdown_gid);

    if (meter_markdown_gid >= LA_NUM_METER_MARKDOWN_PROFILES) {
        return LA_STATUS_EINVAL;
    }

    if (m_meter_markdown_profiles[meter_markdown_gid] != nullptr) {
        return LA_STATUS_EEXIST;
    }

    auto profile = std::make_shared<la_meter_markdown_profile_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(profile, oid);
    return_on_error(status);

    status = profile->initialize(oid, meter_markdown_gid);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    m_meter_markdown_profiles[meter_markdown_gid] = profile;
    out_meter_markdown_profile = profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_meter_markdown_profile_by_id(la_meter_markdown_gid_t meter_markdown_gid,
                                                 la_meter_markdown_profile*& out_meter_markdown_profile) const
{
    start_api_getter_call("meter_markdown_gid=", meter_markdown_gid);

    if (meter_markdown_gid >= LA_NUM_METER_MARKDOWN_PROFILES) {
        return LA_STATUS_EINVAL;
    }

    const auto& profile = m_meter_markdown_profiles[meter_markdown_gid];
    if (profile == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_meter_markdown_profile = profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_meter_markdown_profile(const la_meter_markdown_profile_impl_wptr& meter_markdown_profile)
{
    if (meter_markdown_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(meter_markdown_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (is_in_use(meter_markdown_profile)) {
        return LA_STATUS_EBUSY;
    }

    la_meter_markdown_gid_t meter_markdown_gid = meter_markdown_profile->get_gid();
    la_status status = meter_markdown_profile->destroy();
    return_on_error(status);

    m_meter_markdown_profiles[meter_markdown_gid] = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_meter_action_profile(la_meter_action_profile*& out_meter_action_profile)
{
    start_api_call("");

    auto meter_action_profile = std::make_shared<la_meter_action_profile_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(meter_action_profile, oid);
    return_on_error(status);

    status = meter_action_profile->initialize(oid);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_meter_action_profile = meter_action_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_meter_action_profile(const la_meter_action_profile_impl_wptr& meter_action_profile)
{
    if (meter_action_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(meter_action_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = meter_action_profile->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_granularity(la_resource_descriptor::type_e resource_type, la_resource_granularity& out_granularity) const
{
    return m_resource_handler->get_granularity(resource_type, out_granularity);
}

la_status
la_device_impl::get_resource_usage(la_resource_usage_descriptor_vec& out_descriptor) const
{
    return m_resource_handler->get_resource_usage(out_descriptor);
}

la_status
la_device_impl::get_resource_usage(la_resource_descriptor::type_e resource_type,
                                   la_resource_usage_descriptor_vec& out_descriptors) const
{
    return m_resource_handler->get_resource_usage(resource_type, out_descriptors);
}

la_status
la_device_impl::get_resource_usage(const la_resource_descriptor& resource_descriptor,
                                   la_resource_usage_descriptor& out_descriptors) const
{
    return m_resource_handler->get_resource_usage(resource_descriptor, out_descriptors);
}

la_status
la_device_impl::set_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                     const std::vector<la_resource_thresholds>& thresholds_vec)
{
    return m_resource_handler->set_resource_notification_thresholds(resource_type, thresholds_vec);
}

la_status
la_device_impl::get_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                     std::vector<la_resource_thresholds>& out_thresholds_vec) const
{
    return m_resource_handler->get_resource_notification_thresholds(resource_type, out_thresholds_vec);
}

la_status
la_device_impl::do_flush() const
{
    bit_vector dummy_bv;

    // Arbitrary volatile register with no side effects on read. Apparently any EXTERNAL will do.
    return m_ll_device->read_register((*m_gb_tree->cdb->top->access_reg)[38], dummy_bv);
}

la_status
la_device_impl::flush() const
{
    start_api_call("");
    return do_flush();
}

la_status
la_device_impl::configure_fabric_init_cfg_table()
{
    const auto& table(m_tables.fabric_init_cfg);
    npl_fabric_init_cfg_t::key_type k;
    npl_fabric_init_cfg_t::key_type m;
    npl_fabric_init_cfg_t::value_type v;
    npl_fabric_init_cfg_t::entry_pointer_type e = nullptr;

    k.ser = 0; // dummy index
    m.ser = 0;

    v.action = NPL_FABRIC_INIT_CFG_ACTION_UPDATE;
    v.payloads.update.fabric_cfg_.device = m_ll_device->get_device_id();
    v.payloads.update.fabric_cfg_.plb_type = NPL_PLB_TYPE_TS;
    // TODO: update issu_codespace

    size_t location = 0;

    la_status status = table->insert(location, k, m, v, e);

    return status;
}

la_status
la_device_impl::configure_fabric_tm_headers_table()
{
    la_status status = LA_STATUS_EUNKNOWN;

    npl_fabric_tm_headers_table_t::key_type k;
    npl_fabric_tm_headers_table_t::value_type v;

    v.action = NPL_FABRIC_TM_HEADERS_TABLE_ACTION_UPDATE_FABRIC_LOCAL_VARS;

    // PLB-UC-LOW context with UC-DSP flow
    k.fabric_oq_type = NPL_FABRIC_OQ_TYPE_PLB_UC_LOW;

    v.payloads.update_fabric_local_vars.ctrl.ts_plb.link_fc = 0;
    v.payloads.update_fabric_local_vars.ctrl.ts_plb.fcn = 0;
    v.payloads.update_fabric_local_vars.ctrl.ts_plb.plb_ctxt = NPL_FABRIC_TS_PLB_CTXT_UC_LOW;
    v.payloads.update_fabric_local_vars.ingress_multicast = 0;
    v.payloads.update_fabric_local_vars.initial_fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;
    v.payloads.update_fabric_local_vars.tm_header_type = NPL_TM_HEADER_TYPE_UNICAST_OR_MUU_PLB;

    // Without packing
    status = configure_fabric_tm_headers_table_prefix_lsb_entries(k, v, NPL_TX_CUD_DSP_PREFIX, NPL_TX_CUD_DSP_PREFIX_LEN);
    return_on_error(status);

    status = configure_fabric_tm_headers_table_prefix_lsb_entries(k, v, NPL_TX_CUD_IBM_CMD_PREFIX, NPL_TX_CUD_IBM_CMD_PREFIX_LEN);
    return_on_error(status);

    // With packing. A packed-packet is indicated by the "reserved" prefix
    status
        = configure_fabric_tm_headers_table_prefix_lsb_entries(k, v, NPL_TX_CUD_DROP_TRAP_PREFIX, NPL_TX_CUD_DROP_TRAP_PREFIX_LEN);
    return_on_error(status);

    // PLB-UC-HIGH context with UC-DSP flow
    k.fabric_oq_type = NPL_FABRIC_OQ_TYPE_PLB_UC_HIGH;

    v.payloads.update_fabric_local_vars.ctrl.ts_plb.link_fc = 0;
    v.payloads.update_fabric_local_vars.ctrl.ts_plb.fcn = 0;
    v.payloads.update_fabric_local_vars.ctrl.ts_plb.plb_ctxt = NPL_FABRIC_TS_PLB_CTXT_UC_HIGH;
    v.payloads.update_fabric_local_vars.ingress_multicast = 0;
    v.payloads.update_fabric_local_vars.initial_fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;
    v.payloads.update_fabric_local_vars.tm_header_type = NPL_TM_HEADER_TYPE_UNICAST_OR_MUU_PLB;

    // Without packing
    status = configure_fabric_tm_headers_table_prefix_lsb_entries(k, v, NPL_TX_CUD_DSP_PREFIX, NPL_TX_CUD_DSP_PREFIX_LEN);
    return_on_error(status);

    status = configure_fabric_tm_headers_table_prefix_lsb_entries(k, v, NPL_TX_CUD_IBM_CMD_PREFIX, NPL_TX_CUD_IBM_CMD_PREFIX_LEN);
    return_on_error(status);

    // With packing. A packed-packet is indicated by the "reserved" prefix
    status
        = configure_fabric_tm_headers_table_prefix_lsb_entries(k, v, NPL_TX_CUD_DROP_TRAP_PREFIX, NPL_TX_CUD_DROP_TRAP_PREFIX_LEN);
    return_on_error(status);

    // PLB-MC context with MMM-MCID flow (egress multicast)
    k.fabric_oq_type = NPL_FABRIC_OQ_TYPE_PLB_MC;

    v.payloads.update_fabric_local_vars.ctrl.ts_plb.link_fc = 0;
    v.payloads.update_fabric_local_vars.ctrl.ts_plb.fcn = 0;
    v.payloads.update_fabric_local_vars.ctrl.ts_plb.plb_ctxt = NPL_FABRIC_TS_PLB_CTXT_MC;
    v.payloads.update_fabric_local_vars.ingress_multicast = 0;
    v.payloads.update_fabric_local_vars.initial_fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;
    v.payloads.update_fabric_local_vars.tm_header_type = NPL_TM_HEADER_TYPE_MMM_PLB_OR_FLB;

    // Without packing. There is no packing of MC packets.
    status = configure_fabric_tm_headers_table_prefix_lsb_entries(k, v, NPL_TX_CUD_MC_ID_PREFIX, NPL_TX_CUD_MC_ID_PREFIX_LEN);
    return_on_error(status);

    // TODO add other fabric context and flows

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_fabric_headers_type_table()
{
    la_status status = LA_STATUS_EUNKNOWN;

    const auto& table(m_tables.fabric_headers_type_table);
    npl_fabric_headers_type_table_t::key_type k;
    npl_fabric_headers_type_table_t::key_type m;
    npl_fabric_headers_type_table_t::value_type v;
    npl_fabric_headers_type_table_t::entry_pointer_type e = nullptr;

    v.action = NPL_FABRIC_HEADERS_TYPE_TABLE_ACTION_UPDATE_FABRIC_LOCAL_VARS;
    size_t location = 0;

    // The initial_fabric_header_type value of fabric_tm_headers_table is the key to this table.

    // PLB flows
    memset(&m, 0xff, sizeof(m)); // Set all mask bits to 1

    // PLB, w/o packing, TS1
    k.initial_fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;
    k.plb_header_type = NPL_PLB_HEADER_TYPE_SN_OR_TS1;
    k.start_packing = 0;

    v.payloads.update_fabric_local_vars.fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;

    status = table->insert(location++, k, m, v, e);
    return_on_error(status);

    // PLB, with packing, TS1
    k.initial_fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;
    k.plb_header_type = NPL_PLB_HEADER_TYPE_SN_OR_TS1;
    k.start_packing = 1;

    v.payloads.update_fabric_local_vars.fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS;

    status = table->insert(location++, k, m, v, e);
    return_on_error(status);

    // PLB, w/o packing, TS3
    k.initial_fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;
    k.plb_header_type = NPL_PLB_HEADER_TYPE_TS3;
    k.start_packing = 0;

    v.payloads.update_fabric_local_vars.fabric_header_type = NPL_FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET;

    status = table->insert(location++, k, m, v, e);
    return_on_error(status);

    // PLB, with packing, TS3
    k.initial_fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;
    k.plb_header_type = NPL_PLB_HEADER_TYPE_TS3;
    k.start_packing = 1;

    v.payloads.update_fabric_local_vars.fabric_header_type = NPL_FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS;

    status = table->insert(location++, k, m, v, e);
    return_on_error(status);

    // FLB flows
    memset(&m, 0xff, sizeof(m)); // Set all mask bits to 1
    // Clear the maskable
    m.plb_header_type = (npl_plb_header_type_e)0;
    m.start_packing = 0;

    // FLB header
    k.initial_fabric_header_type = NPL_FABRIC_HEADER_TYPE_FLB;
    k.plb_header_type = (npl_plb_header_type_e)0; // masked
    k.start_packing = 0;                          // masked

    v.payloads.update_fabric_local_vars.fabric_header_type = NPL_FABRIC_HEADER_TYPE_FLB;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_fabric_out_color_map_table()
{
    la_status status = LA_STATUS_EUNKNOWN;

    const auto& table(m_tables.fabric_out_color_map_table);
    npl_fabric_out_color_map_table_t::key_type k;
    npl_fabric_out_color_map_table_t::key_type m;
    npl_fabric_out_color_map_table_t::value_type v;
    npl_fabric_out_color_map_table_t::entry_pointer_type e = nullptr;

    v.action = NPL_FABRIC_OUT_COLOR_MAP_TABLE_ACTION_WRITE;
    memset(&m, 0xff, sizeof(m)); // Set all mask bits to 1

    // Create a 1-to-1 mapping between the packet color before fabric, and on the fabric.
    for (la_uint8_t location = 0, color = 0; color < (la_uint8_t)la_qos_color_e::LAST; location++, color++) {
        k.out_color = color;
        v.payloads.dp = color;
        status = table->insert(location, k, m, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_fabric_header_ene_macro_table()
{
    la_status status = LA_STATUS_EUNKNOWN;

    const auto& table(m_tables.fabric_header_ene_macro_table);
    npl_fabric_header_ene_macro_table_t::key_type k;
    npl_fabric_header_ene_macro_table_t::key_type m;
    npl_fabric_header_ene_macro_table_t::value_type v;
    npl_fabric_header_ene_macro_table_t::entry_pointer_type e = nullptr;

    v.action = NPL_FABRIC_HEADER_ENE_MACRO_TABLE_ACTION_UPDATE;
    memset(&m, 0xff, sizeof(m)); // Set all mask bits to 1
    size_t location = 0;

    // PLB ene macros
    // PLB, w/o packing, TS1
    k.fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;
    v.payloads.update.ene_macro_id.id = NPL_TS1_PLB_FABRIC_HEADER_ONE_PACKET_ENE_MACRO;

    status = table->insert(location++, k, m, v, e);
    return_on_error(status);

    // PLB, with packing, TS1
    k.fabric_header_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS;
    v.payloads.update.ene_macro_id.id = NPL_TS1_PLB_FABRIC_HEADER_TWO_PACKETS_ENE_MACRO;

    status = table->insert(location++, k, m, v, e);
    return_on_error(status);

    // PLB, w/o packing, TS3
    k.fabric_header_type = NPL_FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET;
    v.payloads.update.ene_macro_id.id = NPL_TS3_PLB_FABRIC_HEADER_ONE_PACKET_ENE_MACRO;

    status = table->insert(location++, k, m, v, e);
    return_on_error(status);

    // PLB, with packing, TS3
    k.fabric_header_type = NPL_FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS;
    v.payloads.update.ene_macro_id.id = NPL_TS3_PLB_FABRIC_HEADER_TWO_PACKETS_ENE_MACRO;

    status = table->insert(location++, k, m, v, e);
    return_on_error(status);

    // FLB ene macros
    k.fabric_header_type = NPL_FABRIC_HEADER_TYPE_FLB;
    v.payloads.update.ene_macro_id.id = NPL_FLB_FABRIC_HEADER_ENE_MACRO;

    status = table->insert(location++, k, m, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_set_ene_macro_and_bytes_to_remove_table()
{
    for (la_uint64_t fabric_header_type_val = 0; fabric_header_type_val <= NPL_FABRIC_HEADER_TYPE_SOURCE_ROUTED;
         fabric_header_type_val++) {
        npl_fabric_header_type_e fabric_header_type = (npl_fabric_header_type_e)fabric_header_type_val;

        for (la_uint64_t plb_header_type_val = 0; plb_header_type_val <= NPL_PLB_HEADER_TYPE_TS3; plb_header_type_val++) {
            npl_plb_header_type_e plb_header_type = (npl_plb_header_type_e)plb_header_type_val;

            la_status status = configure_set_ene_macro_and_bytes_to_remove_table_entry(fabric_header_type, plb_header_type);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_set_ene_macro_and_bytes_to_remove_table_entry(npl_fabric_header_type_e fabric_header_type,
                                                                        npl_plb_header_type_e plb_header_type)
{
    // Prepare bytes to remove
    la_uint64_t bytes_to_remove = 0;

    if ((fabric_header_type == NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET)
        || (fabric_header_type == NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS)) {
        bytes_to_remove = FABRIC_HEADER_COMMON_FIELDS_SIZE + FABRIC_HEADER_TS1_FIELD_SIZE;
    }

    if ((fabric_header_type == NPL_FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET)
        || (fabric_header_type == NPL_FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS)) {
        bytes_to_remove = FABRIC_HEADER_COMMON_FIELDS_SIZE + FABRIC_HEADER_TS3_FIELD_SIZE;
    }

    // Prepare new header type
    npl_fabric_header_type_e new_hdr_type = fabric_header_type;

    if ((plb_header_type == NPL_PLB_HEADER_TYPE_TS3) && (fabric_header_type == NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET)) {
        new_hdr_type = NPL_FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET;
    }

    if ((plb_header_type == NPL_PLB_HEADER_TYPE_TS3) && (fabric_header_type == NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS)) {
        new_hdr_type = NPL_FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS;
    }

    if ((plb_header_type == NPL_PLB_HEADER_TYPE_SN_OR_TS1) && (fabric_header_type == NPL_FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET)) {
        new_hdr_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET;
    }

    if ((plb_header_type == NPL_PLB_HEADER_TYPE_SN_OR_TS1) && (fabric_header_type == NPL_FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS)) {
        new_hdr_type = NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS;
    }

    // Prepare ENE macro ID
    npl_ene_macro_ids_e ene_macro_id = NPL_ENE_NOP_MACRO;

    if (fabric_header_type == NPL_FABRIC_HEADER_TYPE_SN_TS_PLB_KEEPALIVE) {
        ene_macro_id = NPL_FABRIC_ELEMENT_KEEPALIVE_ENE_MACRO;
    }

    if ((fabric_header_type == NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET)
        || (fabric_header_type == NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS)
        || (fabric_header_type == NPL_FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET)
        || (fabric_header_type == NPL_FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS)) {

        if (plb_header_type == NPL_PLB_HEADER_TYPE_SN_OR_TS1) {
            ene_macro_id = NPL_FABRIC_ELEMENT_TS1_ENE_MACRO;
        }

        if (plb_header_type == NPL_PLB_HEADER_TYPE_TS3) {
            ene_macro_id = NPL_FABRIC_ELEMENT_TS3_ENE_MACRO;
        }
    }

    const auto& table(m_tables.set_ene_macro_and_bytes_to_remove_table);
    npl_set_ene_macro_and_bytes_to_remove_table_t::key_type k;
    npl_set_ene_macro_and_bytes_to_remove_table_t::value_type v;
    npl_set_ene_macro_and_bytes_to_remove_table_t::entry_pointer_type e = nullptr;

    k.hdr_type = fabric_header_type;
    k.plb_header_type = plb_header_type;

    v.action = NPL_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE_ACTION_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE;
    v.payloads.set_ene_macro_and_bytes_to_remove_table.bytes_to_remove = bytes_to_remove;
    v.payloads.set_ene_macro_and_bytes_to_remove_table.new_hdr_type = new_hdr_type;
    v.payloads.set_ene_macro_and_bytes_to_remove_table.ene_macro_id = ene_macro_id;

    la_status status = table->insert(k, v, e);

    return status;
}

la_status
la_device_impl::initialize_device_mode()
{
    bool has_network_slice = false;
    bool has_fabric_slice = false;
    bool has_udc_slice = false;

    for (la_slice_id_t sid : get_used_slices()) {
        bool is_network_slice = (m_slice_mode[sid] == la_slice_mode_e::NETWORK);
        bool is_fabric_slice = (m_slice_mode[sid] == la_slice_mode_e::CARRIER_FABRIC);
        bool is_udc_slice = (m_slice_mode[sid] == la_slice_mode_e::UDC);

        if ((is_network_slice == false) && (is_fabric_slice == false) && (!is_udc_slice)) {
            log_err(HLD, "%s: unexpected slice mode=%s", __func__, silicon_one::to_string(m_slice_mode[sid]).c_str());
            return LA_STATUS_ENOTIMPLEMENTED;
        }

        has_network_slice |= is_network_slice;
        has_fabric_slice |= is_fabric_slice;
        has_udc_slice |= is_udc_slice;
    }

    if ((has_network_slice == true && has_fabric_slice == false) || has_udc_slice) {
        m_device_mode = device_mode_e::STANDALONE;
    } else if (has_network_slice == false && has_fabric_slice == true) {
        m_device_mode = device_mode_e::FABRIC_ELEMENT;
    } else if (has_network_slice == true && has_fabric_slice == true) {
        m_device_mode = device_mode_e::LINECARD;
    } else {
        log_err(HLD, "%s: unknown device mode", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    log_debug(HLD, "%s: device mode=%s", __func__, silicon_one::to_string(m_device_mode).c_str());

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_device_mode_table()
{
    const auto& table(m_tables.device_mode_table);
    npl_device_mode_table_t::key_type key; // key is empty
    npl_device_mode_table_t::value_type value;
    npl_device_mode_table_t::entry_pointer_type dummy_entry;

    value.action = NPL_DEVICE_MODE_TABLE_ACTION_WRITE;
    value.payloads.device_mode_table_result.dev_mode = device_mode_2_npl_dev_mode(m_device_mode);

    la_status status = table->set(key, value, dummy_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::device_mode_optimized_storage_initialization()
{
    if (m_device_mode != device_mode_e::STANDALONE) {
        m_fabric_ports.resize(NUM_FABRIC_PORTS_IN_DEVICE);
        if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
            m_fabric_multicast_groups.resize(MAX_MC_GROUP_GID);
            return;
        }
    }

    m_pci_ports.resize(NUM_IFGS_PER_DEVICE);
    m_recycle_ports.resize(NUM_IFGS_PER_DEVICE);
    m_system_ports.resize(MAX_SYSTEM_PORT_GID);
    m_rcy_system_ports.resize(NUM_IFGS_PER_DEVICE);
    m_spa_ports.resize(MAX_SPA_PORT_GID);
    m_mirror_commands.resize(MAX_MIRROR_GID);

    // NPU objects
    m_ac_profiles.resize(NUM_AC_PROFILE_PER_DEVICE);
    m_filter_groups.resize(NUM_FILTER_GROUPS_PER_DEVICE);
    m_ingress_qos_profiles.resize(NUM_INGRESS_QOS_PROFILES_PER_SLICE_PAIR);
    m_egress_qos_profiles.resize(NUM_EGRESS_QOS_PROFILES_PER_SLICE_PAIR);

    m_switches.resize(MAX_SWITCH_GID);

    m_meter_markdown_profiles.resize(LA_NUM_METER_MARKDOWN_PROFILES);
    m_l2_destinations.resize(MAX_L2_DESTINATION_GID, nullptr);
    m_l2_punt_destinations.resize(MAX_L2_PUNT_DESTINATION_GID, nullptr);
    m_l2_ports.resize(MAX_L2_SERVICE_PORT_GID);
    m_pwe_ports.resize(MAX_PWE_SERVICE_PORT_GID);
    m_next_hops.resize(MAX_NEXT_HOP_GID);
    m_l3_destinations.resize(MAX_L3_DESTINATION_LPM_GID);
    m_l3_ports.resize(MAX_L3_PORT_GID);
    m_protection_monitors.resize(MAX_PROTECTION_MONITOR_GID);
    m_l3_protected_entries.resize(MAX_L3_PROTECTED_GIDS);
    m_prefix_objects.resize(MAX_PREFIX_OBJECT_GIDS);
    m_mpls_vpn_encap.resize(MAX_MPLS_VPN_ENCAP_GIDS);
    m_destination_pes.resize(MAX_PREFIX_OBJECT_GIDS);
    m_native_lp_table_format.resize(MAX_NATIVE_LP_TABLE_ENTRIES >> 2, make_pair(resolution_lp_table_format_e::NONE, 0));
    m_te_tunnels.resize(MAX_TE_TUNNEL_GIDS);
    m_voq_sets.resize(MAX_VOQS_PER_SLICE_IN_LINECARD_DEVICE);
    m_native_voq_sets.resize(MAX_VOQS_PER_SLICE_IN_LINECARD_DEVICE / NATIVE_VOQ_SET_SIZE, native_voq_set_desc());
    m_l2_multicast_groups.resize(MAX_MC_GROUP_GID);
    m_ip_multicast_groups.resize(MAX_MC_GROUP_GID);
    m_mpls_multicast_groups.resize(MAX_MC_GROUP_GID);
    m_bfd_sessions.resize(NUM_NPUH_MEP_ENTRIES_PER_DEVICE);

    m_lpts_allocation_cache.resize(NUM_SLICE_PAIRS_PER_DEVICE);
    m_sgacl_allocation_cache.resize(NUM_SLICE_PAIRS_PER_DEVICE);

    m_voq_counter_sets.resize(MAX_VOQS_PER_NETWORK_SLICE / voq_counter_set::NUM_VOQS_IN_SET);

    // CGM objects
    m_voq_cgm_profiles.resize(NUM_VOQ_CGM_PROFILES_PER_DEVICE);
    m_voq_cgm_evicted_profiles.resize(NUM_VOQ_CGM_EVICTED_PROFILES_PER_DEVICE);
    m_rx_cgm_handler = silicon_one::make_unique<rx_cgm_handler>(shared_from_this());

    // Index generators
    m_index_generators.ethernet_ports = ranged_index_generator(0, MAX_ETHERNET_PORT_ID);
    // Index 0 is used for IBM
    m_index_generators.tc_profiles = ranged_index_generator(0, NUM_TC_PROFILES);
    m_index_generators.ac_profiles = ranged_index_generator(0, NUM_AC_PROFILE_PER_DEVICE);
    m_index_generators.filter_groups = ranged_index_generator(0, NUM_FILTER_GROUPS_PER_DEVICE);
    m_index_generators.ipv6_compressed_sips = ranged_index_generator(1, NUM_IPV6_COMPRESSED_SIPS);

    // Index 0 is reserved for SAI/SDA
    m_index_generators.vxlan_compressed_dlp_id = ranged_index_generator(1, MAX_VXLAN_OVL_NH);

    // Index 0 is reserved for VOQ_CGM_DEFAULT_EVICTED_PROFILE
    m_index_generators.voq_cgm_evicted_profiles = ranged_index_generator(1, NUM_VOQ_CGM_EVICTED_PROFILES_PER_DEVICE);
    // VOQ CGM profile #VOQ_CGM_DROP_PROFILE (==0) is reserved for a drop profile; profile 0-1 is reserved for a fabric profile.
    // Start profiles from FIRST_ALLOCATABLE_VOQ_CGM_PROFILE_ID (=2).
    // TODO: fabric profiles may not be used on the same slices as network profiles. Therefore, it's possible that profiles
    // [1:NUM_VOQ_CGM_PROFILES]
    // should be accessible. Currently taking the risk/effort-free path.
    m_index_generators.voq_cgm_profiles
        = ranged_index_generator(FIRST_ALLOCATABLE_VOQ_CGM_PROFILE_ID, NUM_VOQ_CGM_PROFILES_PER_DEVICE);

    // Multicast protection monitors - 0 is reserved for "default"
    m_index_generators.multicast_protection_monitors = ranged_index_generator(1, NUM_MULTICAST_PROTECTION_MONITORS);

    for (size_t i = 0; i < NUM_STATISTICAL_METER_BANKS; i++) {
        m_index_generators.statistical_meter_id[i]
            = ranged_sequential_indices_generator(0, la_meter_set_impl::NUM_STATISTICAL_METERS_PER_BANK);
    }
    m_index_generators.statistical_meter_action_profile_id
        = ranged_index_generator(0, la_meter_action_profile_impl::NUM_STATISTICAL_METER_ACTION_PROFILE_PER_BANK);
    m_index_generators.statistical_meter_profile_id
        = ranged_index_generator(0, la_meter_profile_impl::NUM_STATISTICAL_METER_PROFILES_PER_BANK);

    for (la_slice_id_t slice : m_slice_id_manager->get_all_possible_slices()) {
        // NPP attributes index: 8 bits
        m_index_generators.slice[slice].npp_attributes = ranged_index_generator(0, NUM_NPP_ATTRIBUTES_PER_DEVICE);
    }
    for (la_slice_pair_id_t i = 0; i < m_slice_id_manager->num_slice_pairs_per_device(); i++) {
        // Service port SLP-s
        // P4 variable: local_slp_id
        // NOTE: value 0 is reserved for service mapping EM0 lookup misses
        m_index_generators.slice_pair[i].service_port_slps = ranged_index_generator(1, MAX_SLPS_PER_SLICE);
        m_index_generators.slice_pair[i].service_port_pwe
            = ranged_index_generator(MAX_SLPS_PER_SLICE, MAX_SLPS_PER_SLICE + MAX_PWE_PER_SLICE);
    }

    for (la_slice_id_t i : m_slice_id_manager->get_all_possible_slices()) {
        m_egress_multicast_slice_replication_voq_set[i] = nullptr;
    }

    for (la_slice_pair_id_t i = 0; i < m_slice_id_manager->num_slice_pairs_per_device(); i++) {
        // Reserve ACL ID 0 per slice pair for Sec ACL
        m_index_generators.slice_pair[i].ingress_eth_db1_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_eth_db2_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);

        m_index_generators.slice_pair[i].ingress_ipv4_db1_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv4_db2_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv4_db3_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv4_db4_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv4_db1_320_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv4_db2_320_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv4_db3_320_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv4_db4_320_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);

        m_index_generators.slice_pair[i].ingress_ipv6_db1_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv6_db2_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv6_db3_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv6_db4_160_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv6_db1_320_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv6_db2_320_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv6_db3_320_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv6_db4_320_f0_acl_ids = ranged_index_generator(1, INGRESS_ACL_ID_TABLE_SIZE);

        m_index_generators.slice_pair[i].ingress_ipv4_mirror_acl_ids = ranged_index_generator(1, SECOND_ACL_SELECT_TABLE_SIZE);
        m_index_generators.slice_pair[i].ingress_ipv6_mirror_acl_ids = ranged_index_generator(1, SECOND_ACL_SELECT_TABLE_SIZE);
        m_index_generators.slice_pair[i].egress_ipv4_acl_ids = ranged_index_generator(1, ACL_SELECT_TABLE_SIZE);
        m_index_generators.slice_pair[i].egress_ipv6_acl_ids = ranged_index_generator(1, ACL_SELECT_TABLE_SIZE);
        // qos_id is per slice pair
        m_index_generators.slice_pair[i].ingress_qos_profiles = ranged_index_generator(0, NUM_INGRESS_QOS_PROFILES_PER_SLICE_PAIR);
        m_index_generators.slice_pair[i].egress_qos_profiles = ranged_index_generator(0, NUM_EGRESS_QOS_PROFILES_PER_SLICE_PAIR);
    }

    m_index_generators.sr_extended_policies = ranged_index_generator(0, NUM_SR_EXTENDED_POLICIES);

    m_index_generators.npuh_mep_ids = make_shared<ranged_index_generator>(0, NUM_NPUH_MEP_ENTRIES_PER_DEVICE);

    // This respresents the number of BFD sessions remote and local in the system. For now limit this
    // to the same number per host.
    m_index_generators.bfd_session_ids = make_shared<ranged_index_generator>(0, NUM_NPUH_MEP_ENTRIES_PER_DEVICE);

    size_t num_oq_drop_counters = (1 << gibraltar::txcgm_counter_set_map_memory::fields::COUNTER_SET_MAP_DATA_WIDTH);
    for (la_slice_id_t i : m_slice_id_manager->get_all_possible_slices()) {
        // allocate from 2-3. id = 0 is saved for all queues, id = 1 is saved for VOQ flush accounting.
        m_index_generators.slice[i].oq_drain_counters = ranged_index_generator(2, num_oq_drop_counters);
    }

    initialize_resolution_index_generators();
    initialize_resolution_configurators();

    m_index_generators.sgacl_ids = ranged_index_generator(2, 255);
}

la_status
la_device_impl::initialize_link_up_vector()
{
    const auto& table(m_tables.link_up_vector);
    npl_link_up_vector_t::key_type key; // key is empty
    npl_link_up_vector_t::value_type value;
    npl_link_up_vector_t::entry_pointer_type dummy_entry;

    value.action = NPL_LINK_UP_VECTOR_ACTION_WRITE;

    // All ports are up in simulation
    for (size_t link = 0; link < 108; link++) {
        value.payloads.link_up_vector_result.link_up[link] = npl_link_state_e::NPL_LINK_STATE_UP;
    }

    la_status status = table->set(key, value, dummy_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_all_reachable_vector()
{
    const auto& table(m_tables.all_reachable_vector);
    npl_all_reachable_vector_t::key_type key; // key is empty
    npl_all_reachable_vector_t::value_type value;
    npl_all_reachable_vector_t::entry_pointer_type dummy_entry;

    value.action = NPL_ALL_REACHABLE_VECTOR_ACTION_WRITE;

    value.unpack(0);

    la_status status = table->set(key, value, dummy_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

size_t
la_device_impl::get_max_devices_based_on_mode() const
{
    return m_is_in_pacific_mode ? MAX_DEVICES : GB_MAX_DEVICES;
}

la_status
la_device_impl::set_fabric_protocols_version()
{
    if (m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_EINVAL;
    }
    gibraltar::frm_frp288_device_mode_reg_register frp_device_mode_reg;
    la_status status = m_ll_device->read_register(m_gb_tree->dmc->frm->frp288_device_mode_reg, frp_device_mode_reg);
    return_on_error(status);
    if (m_is_in_pacific_mode) {
        frp_device_mode_reg.fields.frp288_device_mode = 1;
    } else {
        frp_device_mode_reg.fields.frp288_device_mode = 0;
    }
    status = m_ll_device->write_register(m_gb_tree->dmc->frm->frp288_device_mode_reg, frp_device_mode_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_fe_mode()
{
    bool has_fab_up_slice = false;
    bool has_fab_down_slice = false;

    for (la_slice_id_t sid : get_used_slices()) {
        bool is_down_slice = (m_slice_clos_direction[sid] == la_clos_direction_e::DOWN);
        bool is_up_slice = (m_slice_clos_direction[sid] == la_clos_direction_e::UP);

        if ((is_down_slice == false) && (is_up_slice == false)) {
            return LA_STATUS_ENOTINITIALIZED;
        }

        has_fab_down_slice |= is_down_slice;
        has_fab_up_slice |= is_up_slice;
    }

    if ((has_fab_down_slice == false) && (has_fab_up_slice == true)) {
        log_err(HLD, "A fabric-element device requires at least one CLOS-direction-down slice");
        return LA_STATUS_EINVAL;
    }

    if ((has_fab_down_slice == true) && (has_fab_up_slice == false)) {
        m_fe_mode = fe_mode_e::FE2;
        return LA_STATUS_SUCCESS;
    }

    if ((has_fab_down_slice == true) && (has_fab_up_slice == true)) {
        m_fe_mode = fe_mode_e::FE13;
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_EUNKNOWN;
}

la_status
la_device_impl::configure_fabric_tables()
{
    // Configure the NPL table with the values written in LBRs, until we implement the reversed translator.

    if (m_device_mode == device_mode_e::STANDALONE || !is_simulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    for (la_slice_id_t slice_id : get_used_slices()) {
        const auto& voq_mapping_table(m_tables.filb_voq_mapping[slice_id]);
        npl_filb_voq_mapping_t::key_type k;
        npl_filb_voq_mapping_t::value_type v;
        npl_filb_voq_mapping_t::entry_pointer_type e = nullptr;
        lld_memory_scptr filb_voq_mapping(m_gb_tree->slice[slice_id]->filb->voq_mapping);
        v.action = NPL_FILB_VOQ_MAPPING_ACTION_WRITE;
        // The numbers of lines to update were taken from LBR
        size_t lines_to_update = (is_network_slice(slice_id)) ? 64 : /*fabric*/ 432;
        for (size_t line = 0; line < lines_to_update; line++) {
            bit_vector hw_value;
            la_status status = m_ll_device->read_memory(filb_voq_mapping, line, hw_value);
            return_on_error(status);
            k.rxpdr_output_voq_nr = line;
            v.unpack(hw_value);
            status = voq_mapping_table->insert(k, v, e);
            return_on_error(status);
        }
    }

    for (la_slice_id_t slice_id : get_used_slices()) {
        if (m_slice_mode[slice_id] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        const auto& source_port_to_link_table(m_tables.source_port_to_link_table[slice_id]);
        npl_source_port_to_link_table_t::key_type k;
        npl_source_port_to_link_table_t::value_type v;
        npl_source_port_to_link_table_t::entry_pointer_type e = nullptr;
        lld_memory_scptr source_if2_port_map(
            (*m_gb_tree->slice_pair[slice_id / 2]->rx_pdr->source_if2_port_map_table)[slice_id % 2]);
        for (size_t line = 0; line < source_if2_port_map->get_desc()->entries; line++) {
            bit_vector hw_value;
            la_status status = m_ll_device->read_memory(source_if2_port_map, line, hw_value);
            return_on_error(status);
            k.rxpp_pd_source_if_7_2_ = line;
            v.unpack(hw_value);
            status = source_port_to_link_table->insert(k, v, e);
            return_on_error(status);
        }
    }

    for (la_slice_id_t slice_id : get_used_slices()) {
        if (m_slice_mode[slice_id] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        const auto& ifc_mapping_table(m_tables.pdoq_oq_ifc_mapping[slice_id]);
        npl_pdoq_oq_ifc_mapping_t::key_type k;
        npl_pdoq_oq_ifc_mapping_t::value_type v;
        npl_pdoq_oq_ifc_mapping_t::entry_pointer_type e = nullptr;
        lld_memory_scptr ifc_mapping_hw_memory(m_gb_tree->slice[slice_id]->pdoq->top->oq_ifc_mapping);
        for (size_t line = 0; line < ifc_mapping_hw_memory->get_desc()->entries; line++) {
            bit_vector hw_value;
            la_status status = m_ll_device->read_memory(ifc_mapping_hw_memory, line, hw_value);
            return_on_error(status);
            k.dest_oq = line;
            v.unpack(hw_value);
            status = ifc_mapping_table->insert(k, v, e);
            return_on_error(status);
        }
    }

    // This table is per-slice in HW, but it is configured the same in all slices, so we allocated the NPL table
    // to be per device, hence, we read the values from HW memory of slice 5 and write to the NPL table.
    const auto& fb_link_to_oq_table(m_tables.rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table);
    npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_t::key_type k;
    npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_t::value_type v;
    npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_t::entry_pointer_type e = nullptr;
    auto sp_id = get_used_slice_pairs()[0]; // reading now from slice 1 by default. 3 if 1 is disabled

    lld_memory_scptr link_to_oq_map((*m_gb_tree->slice_pair[sp_id]->rx_pdr->fe_rlb_uc_tx_fb_link_to_oq_map)[1]);
    for (size_t line = 0; line < link_to_oq_map->get_desc()->entries; line++) {
        bit_vector hw_value;
        la_status status = m_ll_device->read_memory(link_to_oq_map, line, hw_value);
        return_on_error(status);
        k.calc_tx_slice_doq_of_fabric_port_context_input_tx_fabric_port_in_device.val = line;
        v.unpack(hw_value);
        status = fb_link_to_oq_table->insert(k, v, e);
        return_on_error(status);
    }

    for (la_slice_id_t slice_id : get_used_slices()) {
        if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
            break;
        }
        const auto& bitmap_oqg_map_table(m_tables.bitmap_oqg_map_table[slice_id]);
        npl_bitmap_oqg_map_table_t::key_type oqg_map_key;
        npl_bitmap_oqg_map_table_t::value_type oqg_map_value;
        npl_bitmap_oqg_map_table_t::entry_pointer_type oqg_map_entry = nullptr;
        oqg_map_value.action = NPL_BITMAP_OQG_MAP_TABLE_ACTION_WRITE;
        lld_memory_scptr bitmap_oqg_map_mem(m_gb_tree->slice[slice_id]->tx->pdr->bitmap_oqg_map);
        for (size_t line = 0; line < bitmap_oqg_map_mem->get_desc()->entries; line++) {
            bit_vector hw_value;
            la_status status = m_ll_device->read_memory(bitmap_oqg_map_mem, line, hw_value);
            return_on_error(status);
            oqg_map_key.bitmap_oqg_map_index_index = line;
            oqg_map_value.unpack(hw_value);
            status = bitmap_oqg_map_table->insert(oqg_map_key, oqg_map_value, oqg_map_entry);
            return_on_error(status);
        }
    }

    la_slice_id_t rep_sid = get_used_slice_pairs()[0];
    const auto& mc_bitmap_base_voq_table(m_tables.mc_bitmap_base_voq_lookup_table);
    npl_mc_bitmap_base_voq_lookup_table_t::key_type mc_bitmap_base_voq_key;
    npl_mc_bitmap_base_voq_lookup_table_t::value_type mc_bitmap_base_voq_value;
    npl_mc_bitmap_base_voq_lookup_table_t::entry_pointer_type mc_bitmap_base_voq_entry = nullptr;
    lld_memory_scptr mc_bitmap_base_voq_mem((*m_gb_tree->slice_pair[rep_sid]->rx_pdr->mc_bitmap_base_voq_lut)[0]);
    for (size_t line = 0; line < mc_bitmap_base_voq_mem->get_desc()->entries; line++) {
        bit_vector hw_value;
        la_status status = m_ll_device->read_memory(mc_bitmap_base_voq_mem, line, hw_value);
        return_on_error(status);
        mc_bitmap_base_voq_key.unpack(line);
        mc_bitmap_base_voq_value.unpack(hw_value);
        status = mc_bitmap_base_voq_table->set(mc_bitmap_base_voq_key, mc_bitmap_base_voq_value, mc_bitmap_base_voq_entry);
        return_on_error(status);
    }

    for (la_slice_id_t slice_id : get_used_slices()) {
        const auto& voq_properties_table(m_tables.pdvoq_slice_voq_properties_table[slice_id]);
        lld_memory_scptr voq_properties_mem(m_gb_tree->slice[slice_id]->pdvoq->voq_properties);
        size_t items_num_in_hw_line = gibraltar::pdvoq_slice_voq_properties_memory::fields::get_profile_array_size(); // 16
        // The numbers of lines to update were taken from LBR
        size_t lines_to_update = (is_network_slice(slice_id)) ? 4 : /*fabric*/ 27;
        for (size_t line = 0; line < lines_to_update; line++) {
            gibraltar::pdvoq_slice_voq_properties_memory entry;
            la_status status = m_ll_device->read_memory(voq_properties_mem, line, entry);
            return_on_error(status);
            for (size_t item_in_line = 0; item_in_line < items_num_in_hw_line; item_in_line++) {
                npl_pdvoq_slice_voq_properties_table_t::key_type voq_properties_key;
                npl_pdvoq_slice_voq_properties_table_t::value_type voq_properties_value;
                npl_pdvoq_slice_voq_properties_table_t::entry_pointer_type voq_properties_entry = nullptr;
                voq_properties_key.voq_num = (line * items_num_in_hw_line) + item_in_line;
                voq_properties_value.unpack(entry.fields.get_profile(item_in_line));
                status = voq_properties_table->set(voq_properties_key, voq_properties_value, voq_properties_entry);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_npu_host()
{
    la_status status = configure_redirect_npuh_encap(NPU_HOST_BFD_ENCAP_PTR, NPL_FI_MACRO_ID_OAMP, NPL_BFD_RECEIVE_MACRO);
    return_on_error(status);

    status = configure_redirect_npuh_encap(NPU_HOST_PFC_ENCAP_PTR, NPL_FI_MACRO_ID_OAMP, NPL_PFC_AA_RECEIVE_MACRO);
    return_on_error(status);

    {
        npl_pin_start_offset_macros_t::key_type k{};
        npl_pin_start_offset_macros_t::value_type v{};
        npl_pin_start_offset_macros_t::entry_pointer_type e = nullptr;

        v.payloads.select_macros.fi_macro_offset = 1;
        v.payloads.select_macros.npe_macro_offset = 0;

        status = m_tables.pin_start_offset_macros->insert(k, v, e);
        return_on_error(status);
    }
    {
        // Set the cif2npa_c_mps_macro
        npl_cif2npa_c_mps_macro_t::key_type k{};
        npl_cif2npa_c_mps_macro_t::value_type v{};
        npl_cif2npa_c_mps_macro_t::entry_pointer_type e = nullptr;
        v.payloads.next_macro_update_next_macro_id = NPL_NPUH_MP_SCANNER_INJECT;
        status = m_tables.cif2npa_c_mps_macro->insert(k, v, e);
        return_on_error(status);
    }

    {
        npu_host_mp_ccm_timer_register reg{{0}};
        reg.fields.mp_ccm_interval_clocks = 30;
        reg.fields.mp_ccm_cycle_clocks = ccm_interval / m_device_clock_interval;
        reg.fields.mp_ccm_start_index = 0;

        // There are 8K MP entries even though we limit the number of sessions to 4K based on the aux memory size.
        // Make sure that the scanner scans all 8K entries.
        reg.fields.mp_ccm_end_index = (NUM_NPUH_MEP_ENTRIES_PER_DEVICE * 2) - 1;

        reg.fields.mp_ccm_timer_enable = 1;

        status = m_ll_device->write_register(m_gb_tree->npuh->host->mp_ccm_timer, reg);
        return_on_error(status);
    }

    {
        const auto max_detection_clocks = chrono::milliseconds(10) / m_device_clock_interval;

        npu_host_rmep_timer_register reg{{0}};
        reg.fields.rmep_interval_clocks = max_detection_clocks / NUM_NPUH_MEP_ENTRIES_PER_DEVICE;
        reg.fields.rmep_cycle_clocks = max_detection_clocks;
        reg.fields.rmep_start_index = 0;
        reg.fields.rmep_end_index = NUM_NPUH_MEP_ENTRIES_PER_DEVICE - 1;
        reg.fields.rmep_timer_enable = 1;

        status = m_ll_device->write_register(m_gb_tree->npuh->host->rmep_timer, reg);
        return_on_error(status);
    }

    {
        // Program the NPUH LRI (Learn Record In) next macro
        npl_cif2npa_c_lri_macro_t::key_type lrn_key{};
        npl_cif2npa_c_lri_macro_t::value_type lrn_value{};
        npl_cif2npa_c_lri_macro_t::entry_pointer_type lrn_entry = nullptr;
        lrn_value.payloads.next_macro_update_next_macro_id = NPL_MAC_LEARN_PUNT_LRC_RECEIVE_PACKETS;
        status = m_tables.cif2npa_c_lri_macro->insert(lrn_key, lrn_value, lrn_entry);
        return_on_error(status);
    }

    {
        const auto max_time_clocks = chrono::milliseconds(50) / m_device_clock_interval;

        // Program NPUH LRI (Learn Record In) register
        npu_host_cfg_lri_register reg{{0}};
        reg.fields.cfg_npu_host_lri_header = 0; // ASIC default is 6
        reg.fields.cfg_npu_host_lri_max_time = max_time_clocks;
        status = m_ll_device->write_register(m_gb_tree->npuh->host->cfg_lri, reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_learn_manager()
{
    la_status status;

    /// NOTE: need to match on what cem_config::configure_hw is configuring
    npl_inject_mact_ldb_to_output_lr_t::key_type ldb_key{};
    npl_inject_mact_ldb_to_output_lr_t::value_type ldb_value{};
    npl_inject_mact_ldb_to_output_lr_t::entry_pointer_type ldb_entry = nullptr;
    ldb_value.payloads.output_learn_record_mact_ldb = NPL_CENTRAL_EM_LDB_MAC_RELAY_DA;
    status = m_tables.inject_mact_ldb_to_output_lr->insert(ldb_key, ldb_value, ldb_entry);
    return_on_error(status);

    npl_lr_write_ptr_reg_t::key_type lr_wr_ptr_key{};
    npl_lr_write_ptr_reg_t::value_type lr_wr_ptr_value{};
    npl_lr_write_ptr_reg_t::entry_pointer_type lr_wr_ptr_entry = nullptr;
    lr_wr_ptr_value.payloads.learn_record_fifo_vars_write_ptr.address = 0;
    status = m_tables.lr_write_ptr_reg->insert(lr_wr_ptr_key, lr_wr_ptr_value, lr_wr_ptr_entry);
    return_on_error(status);

    npl_lr_filter_write_ptr_reg_t::key_type lr_filter_wr_ptr_key{};
    npl_lr_filter_write_ptr_reg_t::value_type lr_filter_wr_ptr_value{};
    npl_lr_filter_write_ptr_reg_t::entry_pointer_type lr_filter_wr_ptr_entry = nullptr;
    lr_filter_wr_ptr_value.payloads.learn_record_filter_vars_write_ptr.address = 0;
    status = m_tables.lr_filter_write_ptr_reg->insert(lr_filter_wr_ptr_key, lr_filter_wr_ptr_value, lr_filter_wr_ptr_entry);
    return_on_error(status);

    // Default to system learning mode
    status = set_learn_mode(m_learn_mode);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_voq_cgm_drop_profile()
{
    // The VOQ CGM profile for drop purposes configuration currently takes place in several functions/files.
    // TODO - need to move all related config to this function, and consider using an la_voq_cgm_profile to do the config,
    // instead of low-level memory or NPL table access.

    // Configure cgm_profile.counter_id
    const auto& tables(m_tables.voq_cgm_slice_slice_cgm_profile_table);

    // Prepare arguments
    npl_voq_cgm_slice_slice_cgm_profile_table_t::key_type k;
    npl_voq_cgm_slice_slice_cgm_profile_table_t::value_type v;

    k.profile_id.value = la_device_impl::VOQ_CGM_DROP_PROFILE;
    v.action = NPL_VOQ_CGM_SLICE_SLICE_CGM_PROFILE_TABLE_ACTION_WRITE;
    v.payloads.voq_cgm_slice_slice_cgm_profile_result.counter_id = NPL_VOQ_CGM_PD_COUNTER_UC;

    la_status status = per_slice_tables_insert(m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(status);

    // Initialize  VOQ profile 0 (#VOQ_CGM_DROP_PROFILE) which is initialized to 0xFFFFFFFF (drop all).
    const auto& behavior_tables(m_tables.voq_cgm_slice_buffers_consumption_lut_for_enq_table);
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type behavior_key;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type behavior_val;

    // Drop always for every age region
    behavior_val.action = NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    la_uint64_t num_sms_age_regions;
    status = get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    return_on_error(status);

    for (la_quantization_region_t age = 0; age < num_sms_age_regions; age++) {
        behavior_val.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[age].value
            = LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP;
        behavior_val.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[age].value
            = LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP;
    }

    la_uint64_t num_sms_total_bytes_regions;
    status = get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    return_on_error(status);

    la_uint64_t num_sms_voq_bytes_regions;
    status = get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    return_on_error(status);

    behavior_key.profile_id.value = VOQ_CGM_DROP_PROFILE;

    for (size_t buffer_pool_available_level = 0; buffer_pool_available_level < num_sms_total_bytes_regions;
         buffer_pool_available_level++) {
        behavior_key.buffer_pool_available_level = buffer_pool_available_level;
        for (size_t buffer_voq_size_level = 0; buffer_voq_size_level < num_sms_voq_bytes_regions; buffer_voq_size_level++) {
            behavior_key.buffer_voq_size_level = buffer_voq_size_level;
            la_status status = per_slice_tables_insert(
                m_slice_mode, behavior_tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, behavior_key, behavior_val);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_static_voqs()
{
    la_status retval;

    retval = configure_static_invalid_voq();
    return_on_error(retval);

    retval = configure_static_mc_voqs();
    return_on_error(retval);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_static_invalid_voq()
{
    std::set<la_voq_gid_t> invalid_voq_ids;

    size_t invalid_dest_dev = bit_utils::ones(filb_slice_voq_mapping_memory::fields::DEST_DEV_WIDTH);

    for (la_slice_id_t src_slice : get_used_slices()) {
        la_voq_gid_t voqs_per_slice
            = (src_slice < LAST_NETWORK_TYPE_SLICE) ? MAX_VOQS_PER_NETWORK_SLICE : MAX_VOQS_PER_FABRIC_SLICE;
        // The last VOQ is used by the HW for invalid indication.
        la_voq_gid_t invalid_voq_id = voqs_per_slice - 1;

        const auto& table(m_tables.filb_voq_mapping[src_slice]);
        npl_filb_voq_mapping_t::key_type key;
        npl_filb_voq_mapping_t::value_type value;
        npl_filb_voq_mapping_t::entry_pointer_type entry = nullptr;

        key.rxpdr_output_voq_nr = invalid_voq_id;

        value.payloads.filb_voq_mapping_result.dest_dev = invalid_dest_dev;
        value.payloads.filb_voq_mapping_result.dest_slice = src_slice;
        value.payloads.filb_voq_mapping_result.dest_oq = bit_utils::ones(filb_slice_voq_mapping_memory::fields::DEST_OQ_WIDTH);

        la_status status = table->insert(key, value, entry);
        return_on_error(status);

        // User-created VOQ-s are only relevant on network slices.
        // Make sure to only block for these VOQ-s.
        if (is_network_slice(src_slice)) {
            invalid_voq_ids.insert(invalid_voq_id);
        }
    }

    // Mark the invalid_voqs as busy
    for (la_voq_gid_t invalid_voq_id : invalid_voq_ids) {
        // Mark the VOQ as busy. The native_voq_set_desc is used as dummy structure, since the invalid VOQ in each src_slice has
        // a different dest_slice.
        native_voq_set_desc voq_set_desc;
        voq_set_desc.dest_device = invalid_dest_dev;

        // The HW uses only this VOQ-ID in spite it not being a 16-multiple. Still use that voq_id, and rely that
        // native_voq_set_list_add to do correct book-keeping.
        // This book-keeping registration is done just to prevent other SDK VOQ creation on the same range.
        la_voq_gid_t native_base_voq = round_down(invalid_voq_id, NATIVE_VOQ_SET_SIZE);
        size_t offset = invalid_voq_id - native_base_voq;

        la_status status = native_voq_set_list_add(native_base_voq, offset, 1 /*set_size*/, voq_set_desc);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_static_mc_voqs()
{
    if (m_device_mode == device_mode_e::STANDALONE) {
        return configure_standalone_static_mc_voqs();
    }
    if (m_device_mode == device_mode_e::LINECARD) {
        return configure_linecard_static_mc_voqs();
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_standalone_static_mc_voqs()
{
    la_device_id_t dest_device = get_id();
    // Configure VOQs 0-96 to local TXPDR.
    // Using VSCs 0-96 to the each destination slice to describe the ingress VOQ.
    la_vsc_gid_vec_t base_vsc_vec(ASIC_MAX_SLICES_PER_DEVICE_NUM);
    for (la_slice_id_t slice : get_used_slices()) {
        base_vsc_vec[slice] = SA_MC_VSC_RANGE_START + NATIVE_VOQ_SET_SIZE * slice;
    }

    la_voq_cgm_profile_wptr mc_cgm_profile;
    la_status status = do_create_cgm_profile(MC_VOQ_CGM_PROFILE, mc_cgm_profile);
    return_on_error(status);
    m_is_builtin_objects[mc_cgm_profile->oid()] = true;

    for (la_slice_id_t dest_slice : get_used_slices()) {
        la_voq_gid_t base_voq_id = BASE_SA_MC_VOQ + NATIVE_VOQ_SET_SIZE * dest_slice;

        la_voq_set_wptr voq_set;
        la_status status
            = do_create_voq_set(base_voq_id, NUM_SA_MC_VOQS, base_vsc_vec, dest_device, dest_slice, 0 /* dest_ifg */, voq_set);
        return_on_error(status);

        for (size_t voq_offset = 0; voq_offset < NUM_SA_MC_VOQS; voq_offset++) {
            status = voq_set->set_cgm_profile(voq_offset, mc_cgm_profile.get());
            return_on_error(status);
        }

        m_is_builtin_objects[voq_set->oid()] = true; // These VOQs should always exist.

        const auto& voq_set_impl = voq_set.weak_ptr_static_cast<la_voq_set_impl>();
        status = set_egress_multicast_slice_replication_voq_set(dest_slice, voq_set_impl);
        return_on_error(status);

        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            auto ifg_sch = m_ifg_schedulers[dest_slice][ifg];

            la_output_queue_scheduler* oq_sch_hi;
            la_output_queue_scheduler* oq_sch_lo;
            status = ifg_sch->get_txpdr_hp_oqcs(oq_sch_hi);
            return_on_error(status);

            status = ifg_sch->get_txpdr_lp_oqcs(oq_sch_lo);
            return_on_error(status);

            la_output_queue_scheduler_impl* oq_sch_hi_impl = static_cast<la_output_queue_scheduler_impl*>(oq_sch_hi);
            la_output_queue_scheduler_impl* oq_sch_lo_impl = static_cast<la_output_queue_scheduler_impl*>(oq_sch_lo);

            for (la_slice_id_t ingress_slice : get_used_slices()) {
                la_output_queue_scheduler_impl* oq_sch_impl;
                for (la_voq_gid_t voq_offset = 0; voq_offset <= NUM_SA_MC_VOQS; voq_offset++) {
                    if (voq_offset < FIRST_HIGH_PRIORITY_MC_VOQ_OFFSET) {
                        oq_sch_impl = oq_sch_lo_impl;
                    } else {
                        oq_sch_impl = oq_sch_hi_impl;
                    }

                    status = oq_sch_impl->do_attach_vsc(base_vsc_vec[ingress_slice] + voq_offset,
                                                        la_oq_vsc_mapping_e::RR1_RR3,
                                                        dest_device,
                                                        ingress_slice,
                                                        base_voq_id + voq_offset);
                    return_on_error(status);
                }
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_linecard_static_mc_voqs()
{
    auto voq_set = std::make_shared<restricted_voq_set_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(voq_set, oid);
    return_on_error(status);
    status = voq_set->initialize_from_memories(oid, la_device_impl::BASE_LC_FABRIC_MC_VOQ, la_device_impl::NUM_LC_FABRIC_MC_VOQS);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_egress_multicast_fabric_replication_voq_set = voq_set;
    m_is_builtin_objects[m_egress_multicast_fabric_replication_voq_set->oid()] = true;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_network_static_mc_voq(la_slice_id_t slice, const la_voq_set_wptr& voq_set)
{
    if (m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    if (!is_network_slice(slice)) {
        return LA_STATUS_EINVAL;
    }

    if (voq_set == nullptr) {
        return LA_STATUS_EINVAL;
    }

    // In linecard mode, the network slices get setup to send to other network
    // slices, the same as standalone mode. This is required for scaled
    // multicast replication of the local MCID at the egress linecard.
    const auto& voq_set_impl = voq_set.weak_ptr_static_cast<la_voq_set_impl>();
    la_status status = set_egress_multicast_slice_replication_voq_set(slice, voq_set_impl);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_npe2dbc_thread_ready_indication()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_lookup_error_drop_dsp()
{
    // Attach DSP0 to VOQs.
    const auto& table(m_tables.rxpdr_dsp_lookup_table);
    npl_rxpdr_dsp_lookup_table_value_t value;
    npl_rxpdr_dsp_lookup_table_key_t key;
    npl_rxpdr_dsp_lookup_table_entry_t* entry = nullptr;

    bool svl_mode = false;
    get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    if (svl_mode) {
        key.fwd_destination_lsb
            = (LOOKUP_ERROR_SYSTEM_PORT_GID | (m_ll_device->get_device_id() << SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID));
    } else {
        key.fwd_destination_lsb = LOOKUP_ERROR_SYSTEM_PORT_GID; // DSP=0 is reserved for lookup-erorr WA.
    }

    value.payloads.rxpdr_dsp_lookup_table_result.tc_map_profile = DROP_DSP_TC_PROFILE;
    value.payloads.rxpdr_dsp_lookup_table_result.base_voq_num = LOOKUP_ERROR_VOQ_BASE;
    value.payloads.rxpdr_dsp_lookup_table_result.dest_device = 0; // This has meaning only for FLB - currenly unused.

    la_status status = table->insert(key, value, entry);
    return_on_error(status);

    // Set VOQ status to drop-always
    const auto& tables(m_tables.pdvoq_slice_voq_properties_table);

    // Prepare arguments
    npl_pdvoq_slice_voq_properties_table_t::key_type k;
    npl_pdvoq_slice_voq_properties_table_t::value_type v;

    v.action = NPL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE_ACTION_WRITE;
    v.payloads.pdvoq_slice_voq_properties_result.type = NPL_PDVOQ_VOQ_SCHEDULING_TYPE_LOCAL_L;
    v.payloads.pdvoq_slice_voq_properties_result.profile.value = la_device_impl::VOQ_CGM_DROP_PROFILE;

    for (size_t voq_index = 0; voq_index < LOOKUP_ERROR_VOQ_SIZE; voq_index++) {
        k.voq_num = LOOKUP_ERROR_VOQ_BASE + voq_index;

        // Write
        status = per_slice_tables_set(m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
        return_on_error(status);
    }

    // Add counter
    auto counter = std::make_shared<la_counter_set_impl>(shared_from_this());
    la_object_id_t oid;
    status = register_object(counter, oid);
    return_on_error(status);

    // la_voq_set::voq_counter_type_e::BOTH requires 2 counters
    status = counter->initialize(oid, 2);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_is_builtin_objects[counter->oid()] = true; // This counter should be available always.

    status = create_voq_counter_set(la_voq_set::voq_counter_type_e::BOTH,
                                    MAX_VOQ_SET_SIZE /* group size */,
                                    counter.get(),
                                    LOOKUP_ERROR_VOQ_BASE,
                                    LOOKUP_ERROR_VOQ_SIZE);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    counter->set_voq_base(LOOKUP_ERROR_VOQ_BASE);

    m_lookup_error_drop_dsp_counter = counter;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_rx_drop_dsp()
{
    // Attach RX_DROP_SYSTEM_PORT_GID to VOQs.
    const auto& table(m_tables.rxpdr_dsp_lookup_table);
    npl_rxpdr_dsp_lookup_table_value_t value;
    npl_rxpdr_dsp_lookup_table_key_t key;
    npl_rxpdr_dsp_lookup_table_entry_t* entry = nullptr;

    bool svl_mode = false;
    get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    if (svl_mode) {
        key.fwd_destination_lsb
            = (RX_DROP_SYSTEM_PORT_GID | (m_ll_device->get_device_id() << SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID));
    } else {
        key.fwd_destination_lsb = RX_DROP_SYSTEM_PORT_GID; // DSP=0 is reserved for lookup-erorr WA.
    }

    value.payloads.rxpdr_dsp_lookup_table_result.tc_map_profile = DROP_DSP_TC_PROFILE;
    value.payloads.rxpdr_dsp_lookup_table_result.base_voq_num = RX_DROP_VOQ_BASE;
    value.payloads.rxpdr_dsp_lookup_table_result.dest_device = 0; // This has meaning only for FLB - currenly unused.

    la_status status = table->insert(key, value, entry);
    return_on_error(status);

    // Set VOQ status to drop-always
    const auto& tables(m_tables.pdvoq_slice_voq_properties_table);

    // Prepare arguments
    npl_pdvoq_slice_voq_properties_table_t::key_type k;
    npl_pdvoq_slice_voq_properties_table_t::value_type v;

    v.action = NPL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE_ACTION_WRITE;
    v.payloads.pdvoq_slice_voq_properties_result.type = NPL_PDVOQ_VOQ_SCHEDULING_TYPE_LOCAL_L;
    v.payloads.pdvoq_slice_voq_properties_result.profile.value = la_device_impl::VOQ_CGM_DROP_PROFILE;

    for (size_t voq_index = 0; voq_index < RX_DROP_VOQ_SIZE; voq_index++) {
        k.voq_num = RX_DROP_VOQ_BASE + voq_index;

        // Write
        status = per_slice_tables_set(m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
        return_on_error(status);
    }

    // Add counter
    auto counter = std::make_shared<la_counter_set_impl>(shared_from_this());
    la_object_id_t oid;
    status = register_object(counter, oid);
    return_on_error(status);

    // la_voq_set::voq_counter_type_e::BOTH requires 2 counters
    // TODO - This counter should express the number of dropped packets. Technically it can be
    // la_voq_set::voq_counter_type_e::DROPPED, but that type is not supported yet.
    status = counter->initialize(oid, 2);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_is_builtin_objects[counter->oid()] = true; // This counter should be available always.

    status = create_voq_counter_set(
        la_voq_set::voq_counter_type_e::BOTH, MAX_VOQ_SET_SIZE /* group size */, counter.get(), RX_DROP_VOQ_BASE, RX_DROP_VOQ_SIZE);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    counter->set_voq_base(RX_DROP_VOQ_BASE);
    m_rx_drop_dsp_counter = counter;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_rx_not_cnt_drop_dsp()
{
    // Attach RX_NOT_CNT_DROP_SYSTEM_PORT_GID to VOQs.
    const auto& table(m_tables.rxpdr_dsp_lookup_table);
    npl_rxpdr_dsp_lookup_table_value_t value;
    npl_rxpdr_dsp_lookup_table_key_t key;
    npl_rxpdr_dsp_lookup_table_entry_t* entry = nullptr;

    bool svl_mode = false;
    get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    if (svl_mode) {
        key.fwd_destination_lsb
            = (RX_NOT_CNT_DROP_SYSTEM_PORT_GID | (m_ll_device->get_device_id() << SVL_DEVICE_ID_MARKING_BIT_IN_SYS_PORT_GID));
    } else {
        key.fwd_destination_lsb = RX_NOT_CNT_DROP_SYSTEM_PORT_GID; // DSP=0 is reserved for lookup-erorr WA.
    }

    value.payloads.rxpdr_dsp_lookup_table_result.tc_map_profile = DROP_DSP_TC_PROFILE;
    value.payloads.rxpdr_dsp_lookup_table_result.base_voq_num = RX_NOT_CNT_DROP_VOQ_BASE;
    value.payloads.rxpdr_dsp_lookup_table_result.dest_device = 0; // This has meaning only for FLB - currenly unused.

    la_status status = table->insert(key, value, entry);
    return_on_error(status);

    // Set VOQ status to drop-always
    const auto& tables(m_tables.pdvoq_slice_voq_properties_table);

    // Prepare arguments
    npl_pdvoq_slice_voq_properties_table_t::key_type k;
    npl_pdvoq_slice_voq_properties_table_t::value_type v;

    v.action = NPL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE_ACTION_WRITE;
    v.payloads.pdvoq_slice_voq_properties_result.type = NPL_PDVOQ_VOQ_SCHEDULING_TYPE_LOCAL_L;
    v.payloads.pdvoq_slice_voq_properties_result.profile.value = la_device_impl::VOQ_CGM_DROP_PROFILE;

    for (size_t voq_index = 0; voq_index < RX_NOT_CNT_DROP_VOQ_SIZE; voq_index++) {
        k.voq_num = RX_NOT_CNT_DROP_VOQ_BASE + voq_index;

        // Write
        status = per_slice_tables_set(m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_fabric_minimum_links()
{
    bool is_per_device_min_link = false;
    la_status status = get_bool_property(la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS, is_per_device_min_link);
    return_on_error(status);
    // If we are not in per-device minimum links number, then, we write the global threshold to be the threshold of all
    // devices.
    if (!is_per_device_min_link) {
        int global_links_num;
        status = get_int_property(la_device_property_e::MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY, global_links_num);
        return_on_error(status);
        status = set_minimum_fabric_links_for_all_devices((size_t)global_links_num);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::lpm_hbm_collect_stats()
{
    bool lpm_hbm_cache_mode_enabled;
    la_status status = get_bool_property(la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE, lpm_hbm_cache_mode_enabled);
    dassert_crit(status == LA_STATUS_SUCCESS);
    return_on_error(status);

    if (lpm_hbm_cache_mode_enabled) {
        m_resource_manager->lpm_hbm_collect_stats();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::lpm_hbm_do_caching()
{
    bool lpm_hbm_cache_mode_enabled;
    la_status status = get_bool_property(la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE, lpm_hbm_cache_mode_enabled);
    dassert_crit(status == LA_STATUS_SUCCESS);
    return_on_error(status);

    if (lpm_hbm_cache_mode_enabled) {
        m_resource_manager->lpm_hbm_do_caching();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_gibraltar_a1_workarounds()
{
    bit_vector spare_reg;
    la_status status;

    // Fix for: VOQ doesnt get out of HBM when congestion is over
    status = m_ll_device->read_register(m_gb_tree->dram_cgm->spare_reg, spare_reg);
    return_on_error(status, HLD, ERROR, "Failed  enabling fix for VOQ doesnt get out of HBM when congestion is over.");
    spare_reg.set_bits(4, 0, 8);
    status = m_ll_device->write_register(m_gb_tree->dram_cgm->spare_reg, spare_reg);
    return_on_error(status, HLD, ERROR, "Failed  enabling fix for VOQ doesnt get out of HBM when congestion is over.");
    for (la_slice_id_t sid : get_used_slices()) {
        const auto& slice = m_gb_tree->slice[sid];
        status = m_ll_device->read_register(slice->ics->spare_reg, spare_reg);
        return_on_error(status, HLD, ERROR, "Failed  enabling fix for VOQ doesnt get out of HBM when congestion is over.");
        spare_reg.set_bit(0, 1);
        status = m_ll_device->write_register(slice->ics->spare_reg, spare_reg);
        return_on_error(status, HLD, ERROR, "Failed  enabling fix for VOQ doesnt get out of HBM when congestion is over.");
    }

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::periodic_workaround_reset_age_filter_entries()
{
    bool gb_a1_disable_fixes = false;
    get_bool_property(la_device_property_e::GB_A1_DISABLE_FIXES, gb_a1_disable_fixes);

    if (gb_a1_disable_fixes) {
        return;
    }

    bit_vector spare_reg;

    // Fixing issue of age filter not cleaned when number of flows is small:
    // When below two bits are set to zero - learn filter will delete all current entries.
    // To re-enable the learn filter need to set to 1.
    la_status status = m_ll_device->read_register(m_gb_tree->cdb->top->spare_reg, spare_reg);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "Failed triggering age filter entries spare register.");
    } else {
        spare_reg.set_bit(0, 0);
        status = m_ll_device->write_register(m_gb_tree->cdb->top->spare_reg, spare_reg);
        log_on_error(status, HLD, ERROR, "Failed triggering age filter entries spare register.");
        spare_reg.set_bit(0, 1);
        status = m_ll_device->write_register(m_gb_tree->cdb->top->spare_reg, spare_reg);
        log_on_error(status, HLD, ERROR, "Failed triggering age filter entries spare register.");
    }

    for (la_slice_id_t sid : get_used_slices()) {
        const auto& slice = m_gb_tree->slice[sid];
        status = m_ll_device->read_register(slice->npu->rxpp_fwd->top->spare_reg, spare_reg);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "Failed triggering age filter entries spare register.");
            continue;
        }
        spare_reg.set_bit(3, 0);
        status = m_ll_device->write_register(slice->npu->rxpp_fwd->top->spare_reg, spare_reg);
        log_on_error(status, HLD, ERROR, "Failed triggering age filter entries spare register.");
        spare_reg.set_bit(3, 1);
        status = m_ll_device->write_register(slice->npu->rxpp_fwd->top->spare_reg, spare_reg);
        log_on_error(status, HLD, ERROR, "Failed triggering age filter entries spare register.");
    }
}

la_status
la_device_impl::gb_rev_a2_apply_fixes(bool fixes_enabled)
{
    const gibraltar_tree* gb_tree = m_ll_device->get_gibraltar_tree();
    gibraltar::pier_spare_reg_register pier_spare_reg_val{{0}};
    gibraltar::pdoq_shared_mem_spare_reg_register pdoq_shared_mem_spare_reg_val{{0}};
    la_status status = LA_STATUS_SUCCESS;

    status = m_ll_device->read_register(gb_tree->dmc->pier->spare_reg, pier_spare_reg_val);
    return_on_error(status);
    status = m_ll_device->read_register(gb_tree->pdoq_shared_mem->spare_reg, pdoq_shared_mem_spare_reg_val);
    return_on_error(status);

    if (fixes_enabled) {
        pier_spare_reg_val.fields.spare_register_p0 |= 0x2ul;
        pdoq_shared_mem_spare_reg_val.fields.spare_register_p0 |= 0x1ul;
        gibraltar::dics_read_reprt_reg_register dics_read_reprt_reg_val{{0}};
        dics_read_reprt_reg_val.fields.header_size = 0x8ul;
        status = m_ll_device->write_register(gb_tree->dics->read_reprt_reg, dics_read_reprt_reg_val);
        return_on_error(status);
        set_int_property(la_device_property_e::OOB_INJ_CREDITS, 6);
    } else {
        pier_spare_reg_val.fields.spare_register_p0 &= ~0x2ul;
        pdoq_shared_mem_spare_reg_val.fields.spare_register_p0 &= ~0x1ul;
        set_int_property(la_device_property_e::OOB_INJ_CREDITS, 1);
    }

    status = m_ll_device->write_register(gb_tree->dmc->pier->spare_reg, pier_spare_reg_val);
    return_on_error(status);
    status = m_ll_device->write_register(gb_tree->pdoq_shared_mem->spare_reg, pdoq_shared_mem_spare_reg_val);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::register_pollers()
{
    m_notification->register_poll_cb([&]() { poll_mac_ports(); }, hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);

    // No pollers on emulated device
    if (is_emulated_device()) {
        return;
    }

    static_assert(sizeof(m_heartbeat.slow) == (size_t)silicon_one::la_css_memory_layout_e::HEARTBEAT_SLOW_SIZE,
                  "heartbeat size does not fit in CSS memory");
    m_notification->register_poll_cb(
        [&]() {
            ++m_heartbeat.slow;
            m_ll_device->write_memory(*m_gb_tree->sbif->css_mem_even,
                                      CSS_MEMORY_HEARTBEAT_SLOW_BASE,
                                      sizeof(m_heartbeat.slow) / 4 /* count */,
                                      sizeof(m_heartbeat.slow) /* in_val_sz */,
                                      &m_heartbeat.slow);
        },
        hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
    m_notification->register_poll_cb([&]() { ++m_heartbeat.fast; }, hld_notification_base::poll_interval_e::POLL_INTERVAL_FAST);

    if (!is_simulated_device()) {
        m_notification->register_pollers();
    }

    m_notification->register_poll_cb([&]() { logger::instance().flush_if_period_expired(); },
                                     hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);

    bool rtl_simulation_workarounds = false;
    get_bool_property(la_device_property_e::RTL_SIMULATION_WORKAROUNDS, rtl_simulation_workarounds);
    if (rtl_simulation_workarounds) {
        return;
    }

    bool gb_initialization_other = false;
    get_bool_property(la_device_property_e::GB_INITIALIZE_OTHER, gb_initialization_other);
    if (!gb_initialization_other) {
        return;
    }

    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        if (is_simulated_device()) {
            m_notification->register_poll_cb([&]() { poll_npu_host_event_queue(); },
                                             hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
        } else {
            m_notification->register_poll_cb([&]() { poll_npu_host_event_queue(); },
                                             hld_notification_base::poll_interval_e::POLL_INTERVAL_FAST);
        }
        m_notification->register_poll_cb([&]() { poll_npu_host_arm_detection_queue(); },
                                         hld_notification_base::poll_interval_e::POLL_INTERVAL_FAST);

        m_notification->register_poll_cb([&]() { poll_pfc_watchdog(); },
                                         hld_notification_base::poll_interval_e::POLL_INTERVAL_FAST);

        if (!is_simulated_device()) {
            m_notification->register_poll_cb([&]() { lpm_hbm_collect_stats(); },
                                             hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
            m_notification->register_poll_cb([&]() { lpm_hbm_do_caching(); },
                                             hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
            m_notification->register_poll_cb([&]() { m_resource_manager->lpm_unmask_and_clear_l2_ecc_interrupt_registers(); },
                                             hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
        }
    }

    if (!is_simulated_device()) {
        if (m_gb_tree->get_revision() == la_device_revision_e::GIBRALTAR_A1) {
            m_notification->register_poll_cb([&]() { periodic_workaround_reset_age_filter_entries(); },
                                             hld_notification_base::poll_interval_e::POLL_INTERVAL_FAST);
        }

        if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
            m_notification->register_poll_cb([&]() { poll_fe_routing_table(); },
                                             hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
        }

        m_notification->register_poll_cb([&]() { m_pvt_handler->periodic_poll_sensors(); },
                                         hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);

        m_notification->register_poll_cb([&]() { m_resource_manager->update_cem_size(); },
                                         hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
    }
}

la_status
la_device_impl::configure_fabric_tm_headers_table_prefix_lsb_entries(npl_fabric_tm_headers_table_t::key_type key,
                                                                     npl_fabric_tm_headers_table_t::value_type value,
                                                                     uint64_t prefix,
                                                                     uint64_t prefix_len)
{
    const auto& table(m_tables.fabric_tm_headers_table);
    npl_fabric_tm_headers_table_t::entry_pointer_type e = nullptr;

    // Assume that the prefix value represents a left-aligned prefix, of which has prefix_len correct MSBs, and zero in LSBs.
    // So the need iterate over all free LSBs.

    dassert_crit(prefix_len <= FABRIC_TM_HEADERS_TABLE_TX_CUD_PREFIX_LEN);
    size_t num_of_free_bits = FABRIC_TM_HEADERS_TABLE_TX_CUD_PREFIX_LEN - prefix_len;

    for (size_t j = 0; j < (1ULL << num_of_free_bits); j++) {
        // Prepare key
        key.tx_cud_prefix = prefix + j;

        // Update table
        la_status status = table->insert(key, value, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_device_properties_phase_topology()
{
    la_status status = configure_device_bool_properties_phase_topology();
    return_on_error(status);
    status = configure_device_int_properties_phase_topology();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_device_bool_properties_phase_topology()
{
    la_status status = configure_device_bool_property(la_device_property_e::LC_ADVERTISE_DEVICE_ON_FABRIC_MODE);

    return status;
}

la_status
la_device_impl::configure_device_int_properties_phase_topology()
{
    // m_vrfs and m_pcl_gids, based upon  MAX_NUM_PCL_GIDS
    int max_num_pcl_gids;
    la_status status = get_int_property(la_device_property_e::MAX_NUM_PCL_GIDS, max_num_pcl_gids);
    return_on_error(status);
    // If max_num_pcl_gids == 128, pcl range is 0-127
    // If max_num_pcl_gids == 1, pcl range is 127-127
    if (max_num_pcl_gids) {
        m_pcl_gids = ranged_index_generator(MAX_PCL_GIDS - max_num_pcl_gids, MAX_PCL_GIDS);
    }
    m_vrfs.resize(MAX_VRF_GID - max_num_pcl_gids, nullptr);
    m_vrf_redir_dests.resize(MAX_VRF_GID - max_num_pcl_gids, nullptr);
    m_og_lpts_app_ids = ranged_index_generator(0, DEFAULT_MAX_NUM_OG_LPTS_APP_IDS);
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_device_bool_property(la_device_property_e device_property)
{
    bool property_value = m_device_properties[(int)device_property].bool_val;
    la_status status;

    switch (device_property) {
    // Supported properties
    case la_device_property_e::LC_56_FABRIC_PORT_MODE: {
        // This feature is Pacific only.
        return LA_STATUS_EINVAL;
    }

    case la_device_property_e::LC_TYPE_2_4_T: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::LC_ADVERTISE_DEVICE_ON_FABRIC_MODE: {
        status = set_bool_property_lc_advertise_device_on_fabric_mode(property_value);
        return status;
    }

    case la_device_property_e::LC_FORCE_FORWARD_THROUGH_FABRIC_MODE: {
        status = set_bool_property_lc_force_forward_through_fabric_mode(property_value);
        return status;
    }

    case la_device_property_e::ENABLE_NSIM_ACCURATE_SCALE_MODEL: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_HBM: {
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::HBM_MOVE_TO_READ_ON_EMPTY: {
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::HBM_MOVE_TO_WRITE_ON_EMPTY: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION: {
        if (property_value && !m_device_properties[(int)la_device_property_e::ENABLE_HBM].bool_val) {
            return LA_STATUS_EINVAL;
        }
        m_resource_manager->enable_lpm_hbm(property_value);
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE: {
        bool do_enable_hbm_caching = property_value;
        bool is_hbm_route_extension_enabled = m_device_properties[(int)la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION].bool_val;

        if (do_enable_hbm_caching && !is_hbm_route_extension_enabled) {
            return LA_STATUS_EINVAL;
        }

        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS: {
        return set_bool_property_fe_per_device_min_links(property_value);
    }

    case la_device_property_e::ENABLE_LPM_IP_CACHE: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::DISABLE_ELECTRICAL_IDLE_DETECTION: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_MBIST_REPAIR:
    case la_device_property_e::IGNORE_MBIST_ERRORS: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_SERDES_NRZ_FAST_TUNE:
    case la_device_property_e::ENABLE_NETWORK_SERDES_PAM4_FAST_TUNE:
    case la_device_property_e::ENABLE_FABRIC_SERDES_PAM4_FAST_TUNE:
    case la_device_property_e::ENABLE_FABRIC_FEC_RS_KP4:
    case la_device_property_e::DISABLE_SERDES_POST_ANLT_TUNE:
    case la_device_property_e::ENABLE_SERDES_PRE_ICAL_PRIOR_ANLT: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::SERDES_DFE_EID: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_SERDES_TX_REFRESH:
    case la_device_property_e::ENABLE_SERDES_TX_SLIP: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::MAC_PORT_IGNORE_LONG_TUNE: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::MAC_PORT_ENABLE_25G_DFETAP_CHECK:
    case la_device_property_e::MAC_PORT_ENABLE_SER_CHECK: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_MAC_PORT_DEGRADED_SER_NOTIFICATIONS: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_SERDES_LOW_POWER: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::RECONNECT_IGNORE_IN_FLIGHT: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::IGNORE_SBUS_MASTER_MBIST_FAILURE: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_SENSOR_POLL: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS: {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    case la_device_property_e::TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::PROCESS_INTERRUPTS: {
        return set_bool_property_process_interrupts(property_value);
    }

    case la_device_property_e::POLL_MSI:
    case la_device_property_e::RTL_SIMULATION_WORKAROUNDS:
    case la_device_property_e::EMULATED_DEVICE:
    case la_device_property_e::GB_INITIALIZE_CONFIG_MEMORIES:
    case la_device_property_e::GB_INITIALIZE_OTHER:
    case la_device_property_e::GB_A1_DISABLE_FIXES:
    case la_device_property_e::SLEEP_IN_SET_MAX_BURST:
    case la_device_property_e::STATISTICAL_METER_COUNTING:
    case la_device_property_e::ENABLE_ECN_QUEUING:
    case la_device_property_e::ENABLE_POWER_SAVING_MODE:
    case la_device_property_e::FORCE_DISABLE_HBM:
    case la_device_property_e::ENABLE_DUMMY_SERDES_HANDLER:
    case la_device_property_e::ENABLE_BOOT_OPTIMIZATION:
        return LA_STATUS_SUCCESS;
    case la_device_property_e::GB_A2_DISABLE_FIXES:
    case la_device_property_e::USING_LEABA_NIC: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_NARROW_COUNTERS: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_MPLS_SR_ACCOUNTING: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_PBTS: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_CLASS_ID_ACLS: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_PACIFIC_B0_IFG_CHANGES: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_PACIFIC_OOB_INTERLEAVING: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::INSTANTIATE_REMOTE_SYSTEM_PORTS: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_PACIFIC_SW_BASED_PFC: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_PFC_DEVICE_TUNING: {
        return set_pfc_device_tuning_enabled();
    }

    case la_device_property_e::ENABLE_SERDES_LDO_VOLTAGE_REGULATOR: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::ENABLE_SRM_OVERRIDE_PLL_KP_KF: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::IGNORE_COMPONENT_INIT_FAILURES: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::PACIFIC_PFC_HBM_ENABLED: {
        return set_bool_property_pacific_pfc_hbm_enabled(property_value);
    }

    case la_device_property_e::ENABLE_SVL_MODE: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::HBM_SKIP_TRAINING: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::DESTINATION_SYSTEM_PORT_IN_IBM_METADATA: {
        return LA_STATUS_SUCCESS;
    }

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }
}

la_status
la_device_impl::configure_mcid_scale_threshold(int old_value, int new_value)
{

    if (old_value == new_value) {
        return LA_STATUS_SUCCESS;
    }

    if (m_device_mode == device_mode_e::STANDALONE) {
        log_err(HLD, "Multicast scale mode is not valid in standalone mode");
        return LA_STATUS_EINVAL;
    }

    if ((new_value < 0) || (new_value > MAX_MC_LOCAL_MCID)) {
        log_err(HLD, "Multicast scale threshold (%d) is out of range (%d to %d)", new_value, 0, MAX_MC_LOCAL_MCID);
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status status = LA_STATUS_SUCCESS;
    if (old_value == MAX_MC_LOCAL_MCID) {
        // the old value had multicast scale disabled, enable now

        // configure the MCID indexes to be used for scale mode
        m_index_generators.local_mcids = ranged_index_generator(new_value, MAX_MC_LOCAL_MCID);

        status = create_multicast_scale_reserved_groups();

    } else if (new_value == MAX_MC_LOCAL_MCID) {

        // the old value had multicast scale enabled, disable now
        status = destroy_multicast_scale_reserved_groups();

    } else { // old_value != MAX_MC_LOCAL_MCID && new_value != MAX_MC_LOCAL_MCID

        // ensure no multicast groups are configured
        if (is_multicast_groups_configured()) {
            log_err(HLD, "Multicast scale threshold cannot be changed while multicast groups exist.");
            return LA_STATUS_EINVAL;
        }

        // re-configure the MCID indexes to be used for scale mode
        m_index_generators.local_mcids = ranged_index_generator(new_value, MAX_MC_LOCAL_MCID);
    }
    return_on_error(status);

    // configure threshold tables on the slices
    status = configure_multicast_scale_threshold_table(new_value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_device_int_property(la_device_property_e device_property, int old_property_value)
{
    int32_t property_value = m_device_properties[(int)device_property].int_val;
    la_status status;

    switch (device_property) {
    // Supported properties
    case la_device_property_e::HBM_FREQUENCY:
        return LA_STATUS_SUCCESS;

    case la_device_property_e::HBM_READ_CYCLES:
    case la_device_property_e::HBM_WRITE_CYCLES:
    case la_device_property_e::HBM_MIN_MOVE_TO_READ:
    case la_device_property_e::HBM_PHY_T_RDLAT_OFFSET:
        return LA_STATUS_SUCCESS;

    case la_device_property_e::HBM_LPM_FAVOR_MODE: {
        if (property_value < 0 || property_value > 2) {
            return LA_STATUS_EOUTOFRANGE;
        }
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::LPTS_MAX_ENTRY_COUNTERS: {
        bool enabled = false;
        get_bool_property(la_device_property_e::ENABLE_NARROW_COUNTERS, enabled);
        if (property_value < 0 || (enabled && (property_value > DEFAULT_LPTS_MAX_ENTRY_COUNTERS_NARROW_MODE))
            || (!enabled && (property_value > DEFAULT_LPTS_MAX_ENTRY_COUNTERS))) {
            return LA_STATUS_EOUTOFRANGE;
        }
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::MULTICAST_MCID_SCALE_THRESHOLD: {
        return configure_mcid_scale_threshold(old_property_value, property_value);
    }

    case la_device_property_e::MAX_NUM_PCL_GIDS: {
        if (property_value < 0 || property_value > MAX_PCL_GIDS) {
            return LA_STATUS_EOUTOFRANGE;
        }
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::SGACL_MAX_CELL_COUNTERS: {
        if (property_value < 0 || property_value > SGACL_CELL_COUNTER_LIMIT) {
            return LA_STATUS_EOUTOFRANGE;
        }
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::LPM_L2_MAX_SRAM_BUCKETS: {
        if (property_value < 0) {
            return LA_STATUS_EOUTOFRANGE;
        }
        la_status status = m_resource_manager->set_lpm_max_number_of_l2_sram_buckets(property_value);
        return status;
    }

    case la_device_property_e::LPM_TCAM_NUM_BANKSETS: {
        if ((property_value < 0) || (property_value > 2)) {
            return LA_STATUS_EOUTOFRANGE;
        }
        m_resource_manager->set_lpm_tcam_num_banksets(property_value);
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::LPM_TCAM_BANK_SIZE: {
        if ((property_value < 240) || (property_value > 512)) { // must be >= MAX_QUAD_ROWS
            return LA_STATUS_EOUTOFRANGE;
        }
        m_resource_manager->set_lpm_tcam_bank_size(property_value);
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::POLL_INTERVAL_MILLISECONDS:
    case la_device_property_e::POLL_FAST_INTERVAL_MILLISECONDS:
    case la_device_property_e::RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS:
    case la_device_property_e::POLL_NON_WIRED_INTERRUPTS_INTERVAL_MILLISECONDS:
    case la_device_property_e::MSI_DAMPENING_INTERVAL_MILLISECONDS:
    case la_device_property_e::MSI_DAMPENING_THRESHOLD:
    case la_device_property_e::SENSOR_POLL_INTERVAL_MILLISECONDS:
        return LA_STATUS_SUCCESS;

    case la_device_property_e::MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY: {
        status = set_int_property_minimum_fabric_ports_for_connectivity(property_value);
        return status;
    }

    case la_device_property_e::SERDES_FW_REVISION:
    case la_device_property_e::SERDES_FW_BUILD:
    case la_device_property_e::SBUS_MASTER_FW_REVISION:
    case la_device_property_e::SBUS_MASTER_FW_BUILD:
    case la_device_property_e::MAC_PORT_TUNE_TIMEOUT:
    case la_device_property_e::MAC_PORT_PAM4_MAX_TUNE_RETRY:
    case la_device_property_e::MAC_PORT_PAM4_MIN_EYE_HEIGHT:
    case la_device_property_e::MAC_PORT_NRZ_MIN_EYE_HEIGHT:
    case la_device_property_e::MAC_PORT_10G_NRZ_MIN_EYE_HEIGHT:
    case la_device_property_e::MAC_PORT_CDR_LOCK_AFTER_TUNE_TIMEOUT:
    case la_device_property_e::MAC_PORT_PCS_LOCK_TIME:
        return LA_STATUS_SUCCESS;

    case la_device_property_e::MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES: {
        // port state transtion logic requires the current state and the
        // previous state so we need to keep at least 2 port state transition
        // history
        if (property_value < 2 || property_value > MAX_MAC_PORT_SM_CAPTURES) {
            log_err(HLD,
                    "Device property %s only takes values from the range [2-%d].",
                    silicon_one::to_string(la_device_property_e::MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES).c_str(),
                    (int)MAX_MAC_PORT_SM_CAPTURES);
            return LA_STATUS_EOUTOFRANGE;
        }
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS: {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    case la_device_property_e::NETWORK_MAC_PORT_TUNE_AND_PCS_LOCK_ITER:
    case la_device_property_e::FABRIC_MAC_PORT_TUNE_AND_PCS_LOCK_ITER:
    case la_device_property_e::MAC_PORT_AUTO_NEGOTIATION_TIMEOUT:
    case la_device_property_e::MAC_PORT_LINK_TRAINING_TIMEOUT:
    case la_device_property_e::MAC_PORT_NRZ_LINK_TRAINING_TIMEOUT:
    case la_device_property_e::MAC_PORT_PAM4_LINK_TRAINING_TIMEOUT:
    case la_device_property_e::SERDES_RXA_POWER_SEQUENCE_MODE:
    case la_device_property_e::SERDES_CL136_PRESET_TYPE:
    case la_device_property_e::MAX_COUNTER_THRESHOLD:
        return LA_STATUS_SUCCESS;

    case la_device_property_e::LPM_REBALANCE_INTERVAL: {
        if (property_value <= 0) {
            return LA_STATUS_EOUTOFRANGE;
        }
        m_resource_manager->set_lpm_rebalance_interval(property_value);
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::LPM_REBALANCE_START_FAIRNESS_THRESHOLD_PERCENT: {
        if ((property_value < 0) || (property_value > 100)) {
            return LA_STATUS_EOUTOFRANGE;
        }

        double percentage_value = (double)property_value / 100.0;
        m_resource_manager->set_lpm_rebalance_start_fairness_threshold(percentage_value);
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::LPM_REBALANCE_END_FAIRNESS_THRESHOLD_PERCENT: {
        if ((property_value < 0) || (property_value > 100)) {
            return LA_STATUS_EOUTOFRANGE;
        }

        double percentage_value = (double)property_value / 100.0;
        m_resource_manager->set_lpm_rebalance_end_fairness_threshold(percentage_value);
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::LPM_TCAM_SINGLE_WIDTH_KEY_WEIGHT: {
        if (property_value <= 0) {
            return LA_STATUS_EOUTOFRANGE;
        }
        m_resource_manager->set_lpm_tcam_single_width_key_weight(property_value);
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::LPM_TCAM_DOUBLE_WIDTH_KEY_WEIGHT: {
        if (property_value <= 0) {
            return LA_STATUS_EOUTOFRANGE;
        }
        m_resource_manager->set_lpm_tcam_double_width_key_weight(property_value);
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::LPM_TCAM_QUAD_WIDTH_KEY_WEIGHT: {
        if (property_value <= 0) {
            return LA_STATUS_EOUTOFRANGE;
        }
        m_resource_manager->set_lpm_tcam_quad_width_key_weight(property_value);
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::DEVICE_FREQUENCY: {
        if (m_matilda_eFuse_type != matilda_model_e::GIBRALTAR_REGULAR) {
            int new_freq = m_device_properties[(int)la_device_property_e::DEVICE_FREQUENCY].int_val;
            if (new_freq != 900 * 1000) {
                log_err(HLD, " !!!!!!! this is a Matilda Modle device -- optimal DEVICE_FREQUENCY is 900 MHz !!!!!!");
                log_err(HLD, " !!!!!!!  setting DEVICE_FREQUENCY to suboptimal %.2f MHz !!!!!!", new_freq / 1000.0);
            }
        }
        status = set_int_device_frequency(property_value);
        return status;
    }
    case la_device_property_e::TCK_FREQUENCY: {
        status = set_int_tck_frequency(property_value);

        return status;
    }
    case la_device_property_e::RESET_INTERRUPT_COUNTERS_INTERVAL_SECONDS: {
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_1B:
    case la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_2B:
    case la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_PARITY:
    case la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_1B:
    case la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_2B:
    case la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_PARITY:
    case la_device_property_e::INTERRUPT_THRESHOLD_LPM_SRAM_ECC_1B:
    case la_device_property_e::INTERRUPT_THRESHOLD_LPM_SRAM_ECC_2B: {
        set_interrupt_thresholds();

        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::MAX_NUMBER_OF_PERIODIC_SAVE_STATE_FILES: {
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::MATILDA_MODEL_TYPE: {
        if (m_matilda_eFuse_type != matilda_model_e::GIBRALTAR_REGULAR) {
            log_err(HLD,
                    " !!!!!!!!!! eFuse Matilda Model type is %d!=0 -- so cannot override matilda model !!!!!!",
                    (int)m_matilda_eFuse_type);
            m_device_properties[(int)la_device_property_e::MATILDA_MODEL_TYPE].int_val = (int)m_matilda_eFuse_type;
        }
        return LA_STATUS_SUCCESS;
    }
    case la_device_property_e::COUNTERS_SHADOW_AGE_OUT: {
        if (property_value < 0) {
            return LA_STATUS_EOUTOFRANGE;
        }
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::OOB_INJ_CREDITS: {
        if (property_value < 1 || property_value > 6) {
            return LA_STATUS_EOUTOFRANGE;
        }
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::CREDIT_SIZE_IN_BYTES: {
        if (property_value != 1024 && property_value != 2048) {
            log_err(HLD, "Valid values are only 1024 or 2048");
            return LA_STATUS_EINVAL;
        }
        return LA_STATUS_SUCCESS;
    }

    case la_device_property_e::METER_BUCKET_REFILL_POLLING_DELAY: {
        if (property_value < 0) {
            return LA_STATUS_EOUTOFRANGE;
        }
        return LA_STATUS_SUCCESS;
    }

    // Unsupported properties
    default:
        log_info(HLD, "device int property %s is not implemented", silicon_one::to_string(device_property).c_str());
        return LA_STATUS_ENOTIMPLEMENTED;
    }
}

la_status
la_device_impl::configure_device_string_property(la_device_property_e device_property)
{
    std::string property_value = m_device_properties[(int)device_property].string_val;

    switch (device_property) {
    // Supported properties
    case la_device_property_e::SERDES_FW_FILE_NAME:
    case la_device_property_e::SBUS_MASTER_FW_FILE_NAME: {
        la_status status = initialize_fw_filepath();
        return_on_error(status);

        return LA_STATUS_SUCCESS;
    }

    // Unsupported properties
    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }
}

la_status
la_device_impl::set_interrupt_thresholds()
{
    interrupt_tree::thresholds th{
        .mem_config = {[(int)la_mem_protect_error_e::ECC_1B]
                       = (uint32_t)m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_1B].int_val,
                       [(int)la_mem_protect_error_e::ECC_2B]
                       = (uint32_t)m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_2B].int_val,
                       [(int)la_mem_protect_error_e::PARITY]
                       = (uint32_t)m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_PARITY].int_val},

        .mem_volatile
        = {[(int)la_mem_protect_error_e::ECC_1B]
           = (uint32_t)m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_1B].int_val,
           [(int)la_mem_protect_error_e::ECC_2B]
           = (uint32_t)m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_2B].int_val,
           [(int)la_mem_protect_error_e::PARITY]
           = (uint32_t)m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_PARITY].int_val},

        .lpm_sram_ecc = {[(int)la_mem_protect_error_e::ECC_1B]
                         = (uint32_t)m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_LPM_SRAM_ECC_1B].int_val,
                         [(int)la_mem_protect_error_e::ECC_2B]
                         = (uint32_t)m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_LPM_SRAM_ECC_2B].int_val,
                         [(int)la_mem_protect_error_e::PARITY] = 0}};

    m_notification->get_interrupt_tree()->set_thresholds(th);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_bool_property_lc_advertise_device_on_fabric_mode(bool property_value)
{
    // Ensure fabric routing tables are updated prior to re-enabling fabric routing advertising.
    // That also triggers an update of all fabric multi-cast groups, ensuring that all groups are
    // programmed correctly before advertising the device.
    if (property_value == true && m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        if (is_simulated_device()) {
            do_poll_fe_routing_table_npl();
        } else {
            do_poll_fe_routing_table();
        }
    }

    gibraltar::frm_frp_enable_reg_register reg;
    reg.fields.frp_packet_gen_en = property_value;

    la_status status = m_ll_device->write_register(m_gb_tree->dmc->frm->frp_enable_reg, reg);

    return status;
}

la_status
la_device_impl::set_bool_property_process_interrupts(bool enable)
{
    gibraltar::sbif_msi_master_interrupt_reg_mask_register val;

    // On GB, the logic is active low, 0 == enabled.
    // Enable/disable summary bits for CIF interrupts.
    // Summary bits for CSS interrupts stay disabled.
    memset(&val, 0xff, sizeof(val));
    val.fields.msi_blocks0_int_mask = !enable;
    val.fields.msi_blocks1_int_mask = !enable;
    val.fields.msi_blocks2_int_mask = !enable;

    return m_ll_device->write_register(m_gb_tree->sbif->msi_master_interrupt_reg_mask, val);
}

la_status
la_device_impl::set_int_property_minimum_fabric_ports_for_connectivity(int32_t property_value)
{
    log_warning(HLD,
                "MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY is deprecated and will be removed in future SDK release. Please use "
                "#silicon_one::la_device::set_global_minimum_fabric_links instead.");

    if (property_value < 0) {
        return LA_STATUS_EOUTOFRANGE;
    }

    bool is_per_device_min_link = false;
    get_bool_property(la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS, is_per_device_min_link);
    if (is_per_device_min_link) {
        // We need to return SUCCESS, because otherwise, reconnect will fail because it updates all
        // the properties blindly.
        log_debug(HLD, "ENABLE_FE_PER_DEVICE_MIN_LINKS is enabled.");
        return LA_STATUS_SUCCESS;
    }

    la_status status = set_minimum_fabric_links_for_all_devices((size_t)property_value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_minimum_fabric_links_for_all_devices(size_t global_min_links)
{
    if (global_min_links > MAX_MIN_LINKS_THRESHOLD) {
        return LA_STATUS_EOUTOFRANGE;
    }

    gibraltar::frm_min_thr_per_device_id_cfg_table_memory mem_entry;
    lld_memory_scptr min_thr_per_lc_table = m_gb_tree->dmc->frm->min_thr_per_device_id_cfg_table;
    lld_memory_line_value_list_t mem_line_val_list;

    mem_entry.fields.min_thr_per_device_id_cfg_data = global_min_links;

    for (la_device_id_t dev_id = 0; dev_id < min_thr_per_lc_table->get_desc()->entries; dev_id++) {
        mem_line_val_list.push_back({{min_thr_per_lc_table, dev_id}, mem_entry});
    }

    la_status status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    status = trigger_frt_scan();
    return_on_error(status);

    m_global_min_fabric_links_threshold = global_min_links;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_int_device_frequency(int32_t property_value)
{
    dassert_crit(m_init_phase == init_phase_e::CREATED);

    if ((property_value < MIN_DEVICE_FREQUENCY) || (property_value > MAX_DEVICE_FREQUENCY)) {
        log_err(HLD,
                "Attempt to set device frequency outside of range. Range is between %d KHz and %d KHz, value given is: %d KHz",
                MIN_DEVICE_FREQUENCY,
                MAX_DEVICE_FREQUENCY,
                property_value);
        return LA_STATUS_EOUTOFRANGE;
    }

    m_device_frequency_int_khz = property_value;
    m_device_frequency_float_ghz = (float)property_value / 1000000;
    m_device_clock_interval = fp_nanoseconds(1 / m_device_frequency_float_ghz);

    log_info(HLD, "Device frequency set to %d KHz", property_value);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_bool_property_pacific_pfc_hbm_enabled(bool enable)
{
    la_status status;

    if (m_mirror_commands.size() < PFC_MEASUREMENT_MIRROR_GID) {
        return LA_STATUS_SUCCESS;
    }

    auto pfc_measurement_mirror = m_mirror_commands[PFC_MEASUREMENT_MIRROR_GID].weak_ptr_static_cast<la_l2_mirror_command>();

    if (!enable) {
        // If neither of the mirrors are created, return success.
        if (pfc_measurement_mirror == nullptr) {
            return LA_STATUS_SUCCESS;
        }

        status = do_destroy(pfc_measurement_mirror);
        return status;
    }

    // Enable case. If mirror is already created, return success.
    if (pfc_measurement_mirror != nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // Create the PFC measurement mirror
    // get any punt/inject port.
    auto pi_port_list = get_objects(la_object::object_type_e::PUNT_INJECT_PORT);
    if (pi_port_list.empty()) {
        return LA_STATUS_EINVAL;
    }

    double pfc_measurement_probability = 0.0;

    la_punt_inject_port_base_wptr pi_port = get_sptr<la_punt_inject_port_base>(pi_port_list.front());
    status = create_pfc_mirror_command(PFC_MEASUREMENT_MIRROR_GID, pi_port, 0, pfc_measurement_probability, pfc_measurement_mirror);
    return status;
}

la_status
la_device_impl::set_bool_property_lc_force_forward_through_fabric_mode(bool property_value)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_bool_property_fe_per_device_min_links(bool is_enable)
{
    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_SUCCESS;
    }

    if (is_enable) { // do nothing
        return LA_STATUS_SUCCESS;
    }

    // if is_enable=False, then we write the global threshold to all devices.
    la_status status = set_minimum_fabric_links_for_all_devices(m_global_min_fabric_links_threshold);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_bool_property_lpm_cache_enabled(bool is_enable)
{
    gibraltar::cdb_cache_lpm_cache_disable_cache_em_register_register lpm_em_cache_disable_reg{{0}};
    gibraltar::cdb_cache_lpm_cache_disable_cache_tcam_register_register lpm_tcam_cache_disable_reg{{0}};

    // There is a bug in GB-A0 that doens't allow us to use lpm cache (for both em and tcam), but enables splitter cache
    // This is resolved in GB-A1
    if (m_gb_tree->get_revision() == la_device_revision_e::GIBRALTAR_A0) {
        lpm_em_cache_disable_reg.fields.lpm_cache_disable_cache_em = 1;
        lpm_tcam_cache_disable_reg.fields.lpm_cache_disable_cache_tcam = 1;
    } else {
        lpm_em_cache_disable_reg.fields.lpm_cache_disable_cache_em = !is_enable;
        lpm_tcam_cache_disable_reg.fields.lpm_cache_disable_cache_tcam = !is_enable;
    }

    gibraltar::cdb_cache_splitter_cache_disable_cache_em_register_register splitter_em_cache_disable_reg{{0}};
    splitter_em_cache_disable_reg.fields.splitter_cache_disable_cache_em = !is_enable;

    gibraltar::cdb_cache_splitter_cache_disable_cache_tcam_register_register splitter_tcam_cache_disable_reg{{0}};
    splitter_tcam_cache_disable_reg.fields.splitter_cache_disable_cache_tcam = !is_enable;

    for (la_slice_id_t slice : get_used_slices()) {
        la_status status = m_ll_device->write_register(
            m_gb_tree->slice[slice]->npu->rxpp_fwd->cdb_cache->lpm_cache_disable_cache_em_register, lpm_em_cache_disable_reg);
        return_on_error(status);
        status = m_ll_device->write_register(
            m_gb_tree->slice[slice]->npu->rxpp_fwd->cdb_cache->lpm_cache_disable_cache_tcam_register, lpm_tcam_cache_disable_reg);
        return_on_error(status);
        status = m_ll_device->write_register(
            m_gb_tree->slice[slice]->npu->rxpp_fwd->cdb_cache->splitter_cache_disable_cache_em_register,
            splitter_em_cache_disable_reg);
        return_on_error(status);
        status = m_ll_device->write_register(
            m_gb_tree->slice[slice]->npu->rxpp_fwd->cdb_cache->splitter_cache_disable_cache_tcam_register,
            splitter_tcam_cache_disable_reg);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::reset_network_interfaces() const
{
    const std::string nic_reset_file_name("leaba_nic_reset");

    std::string path = m_ll_device->get_device_files_path();
    if (path.empty()) {
        return LA_STATUS_SUCCESS;
    }

    std::string nic_reset_file_path = path + "/" + nic_reset_file_name;

    int fd = open(nic_reset_file_path.c_str(), O_WRONLY);
    if (fd < 0) {
        log_err(LLD, "%s: Failed to open %s, errno = %d", __func__, nic_reset_file_path.c_str(), errno);
        return LA_STATUS_ENOTFOUND;
    }

    const char msg[2] = "R";

    int ret = write(fd, msg, sizeof(msg));
    close(fd);
    if (ret < 0) {
        log_err(LLD, "%s: Failed to write to file errno=%d\n", __func__, errno);
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_network_interface_mac_addr(la_slice_id_t slice, la_mac_addr_t mac_addr) const
{
    std::string path = m_ll_device->get_network_interface_file_name(slice);
    if (path.empty()) {
        return LA_STATUS_SUCCESS;
    }

    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) {
        log_err(LLD, "%s: Failed to open %s, errno = %d", __func__, path.c_str(), errno);
        return LA_STATUS_ENOTFOUND;
    }

    char msg[32];
    snprintf(msg,
             sizeof(msg),
             "mac=%02x:%02x:%02x:%02x:%02x:%02x",
             mac_addr.bytes[5],
             mac_addr.bytes[4],
             mac_addr.bytes[3],
             mac_addr.bytes[2],
             mac_addr.bytes[1],
             mac_addr.bytes[0]);

    const size_t c_msg_size = strlen("mac=00:00:00:00:00:00");
    msg[c_msg_size] = '\0';

    int ret = write(fd, msg, c_msg_size);
    close(fd);
    if (ret < 0) {
        log_err(LLD, "%s: Failed to write to file errno=%d\n", __func__, errno);
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

const hld_notification_base_wptr
la_device_impl::get_notificator()
{
    return m_notification;
}

la_status
la_device_impl::initialize_translator_creator(const translator_creator_sptr& creator)
{
    la_status status;

    std::vector<npl_context_e> npl_context_slices(NUM_SLICES_WITH_NPUH_PER_DEVICE, NPL_NONE_CONTEXT);

    status = get_npl_contexts(npl_context_slices);
    return_on_error(status);

    // Build a map of slice ID's per context
    std::map<npl_context_e, std::vector<size_t> > slices_per_context;

    for (la_slice_id_t sid : get_used_slices()) {
        npl_context_e slice_context = npl_context_slices[sid];

        auto it = slices_per_context.find(slice_context);
        if (it == slices_per_context.end()) {
            // if the npl_context already exist, then add the slice ID to the vector of slices
            slices_per_context[slice_context].push_back(sid);
        } else {
            it->second.push_back(sid);
        }
    }

    std::vector<size_t> npuh_slices({0});
    status = creator->load_microcode(npuh_slices, NPL_HOST_CONTEXT);
    return_on_error(status);

    for (auto it = slices_per_context.begin(); it != slices_per_context.end(); ++it) {
        npl_context_e npl_context = it->first;
        auto microcode_slices = it->second;

        status = creator->load_microcode(microcode_slices, npl_context);
        return_on_error(status);
    }

    acl_key_profile_microcode_writes();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_npl_contexts(std::vector<npl_context_e>& out_npl_context_slices) const
{
    for (la_slice_id_t sid = 0; sid < NUM_SLICES_WITH_NPUH_PER_DEVICE; sid++) {
        out_npl_context_slices[sid] = get_npl_slice_context(sid);
    }

    return LA_STATUS_SUCCESS;
}

npl_context_e
la_device_impl::get_npl_slice_context(la_slice_id_t sid) const
{
    if (sid == ASIC_MAX_SLICES_PER_DEVICE_NUM) {
        return NPL_HOST_CONTEXT;
    }

    if (m_slice_mode[sid] == la_slice_mode_e::UDC) {
        return NPL_UDC_CONTEXT;
    }

    if (m_device_mode == device_mode_e::STANDALONE) {
        return NPL_NETWORK_CONTEXT;
    }

    if (m_device_mode == device_mode_e::LINECARD) {
        if (m_slice_mode[sid] == la_slice_mode_e::NETWORK) {
            return NPL_NETWORK_CONTEXT;
        }

        if (m_slice_mode[sid] == la_slice_mode_e::CARRIER_FABRIC) {
            return NPL_FABRIC_CONTEXT;
        }
    }

    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        return NPL_FABRIC_ELEMENT_CONTEXT;
    }

    dassert_crit(true);
    return (npl_context_e)-1;
}

la_status
la_device_impl::apply_fabric_mac_port_workaround(la_mac_port::fc_mode_e fc_mode)
{
    // WORKAROUND
    // mac_pool_port has "reset all PMA lanes in the MAC pool" workaround that requires a reset to all serdeses of a mac_pool in
    // order to have the PMA changes to get to the port, and activate a new serdes. This resets all the serdeses in the IFG,
    // causing already-working fabric ports to fail.
    // So need to do a preconfigure for all fabric ports, and destroy the ports without clearing the HW config. From that point
    // on, only TX-PMA can bet set/reset to enable/disable a port.

    if (m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    std::vector<std::shared_ptr<la_mac_port_base> > fab_mac_ports_vec;

    device_port_handler_base::fabric_data fabric_data;
    m_device_port_handler->get_fabric_data(fabric_data);
    for (la_slice_id_t slice_id : get_used_slices()) {
        for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
            size_t serdes_count = m_ifg_handlers[slice_id][ifg_id]->get_serdes_count();
            for (la_uint_t serdes = 0; serdes < serdes_count; serdes += fabric_data.num_serdes_per_fabric_port) {
                bool is_fabric_port_supporting_serdes_en = is_fabric_port_supporting_serdes(slice_id, ifg_id, serdes);

                if (is_fabric_port_supporting_serdes_en == false) {
                    continue;
                }

                auto fab_mac_port = std::make_shared<la_mac_port_gibraltar>(shared_from_this());
                la_object_id_t oid;
                la_status status = register_object(fab_mac_port, oid);
                return_on_error(status);
                status = fab_mac_port->initialize_fabric(
                    oid, slice_id, ifg_id, serdes, fabric_data.num_serdes_per_fabric_port, fabric_data.speed, fc_mode);
                if (status != LA_STATUS_SUCCESS) {
                    deregister_object(oid);

                    return status;
                }

                fab_mac_ports_vec.push_back(fab_mac_port);
            }
        }
    }

    // destroy the fabric mac ports
    for (auto& fab_mac_port : fab_mac_ports_vec) {
        la_object_id_t fab_mac_port_oid = fab_mac_port->oid();

        status = fab_mac_port->destroy();
        return_on_error(status);

        deregister_object(fab_mac_port_oid);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::nsim_accurate_scale_model_enabled(bool& out_enabled)
{
    get_bool_property(la_device_property_e::ENABLE_NSIM_ACCURATE_SCALE_MODEL, out_enabled);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::hbm_exists(bool& out_exists) const
{
    bool force_disable_hbm = false;
    get_bool_property(la_device_property_e::FORCE_DISABLE_HBM, force_disable_hbm);
    if (force_disable_hbm) {
        out_exists = false;
        return LA_STATUS_SUCCESS;
    }

    bool gb_initialization_other = false;
    get_bool_property(la_device_property_e::GB_INITIALIZE_OTHER, gb_initialization_other);
    if (!gb_initialization_other) {
        out_exists = false;
        return LA_STATUS_SUCCESS;
    }

    if (m_fuse_userbits.bit(FUSE_BIT_HAS_HBM)) {
        out_exists = true;
    } else {
        // If not w/HBM according to the eFuse, check overwrite with property
        get_bool_property(la_device_property_e::ENABLE_HBM, out_exists);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_temperature(la_temperature_sensor_e sensor, la_temperature_t& out_temperature)
{
    start_api_getter_call("sensor=", sensor);

    return m_pvt_handler->get_temperature(sensor, out_temperature);
}

la_status
la_device_impl::get_voltage(la_voltage_sensor_e sensor, la_voltage_t& out_voltage)
{
    start_api_getter_call("sensor=", sensor);

    return m_pvt_handler->get_voltage(sensor, out_voltage);
}

bool
la_device_impl::is_supported_save_state_option(save_state_options options) const
{
    if (options.include_all) {
        return false;
    }

    if (options.include_volatile) {
        return false;
    }

    return true;
}

la_status
la_device_impl::save_state(save_state_options options, json_t*& out_json) const
{
    // This function should be non-blocking as it is intended to periodically poll stats in background
    // Don't acquire any locks
    if (!is_supported_save_state_option(options)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (options.internal_states.size()) {
        return save_internal_states(options.internal_states, out_json);
    }

    state_writer writer(m_ll_device, options);

    la_status status = writer.fill();
    return_on_error(status);

    out_json = writer.acquire_json_tree();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::save_state(save_state_options options, std::string file_name) const
{
    if (!is_supported_save_state_option(options)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (options.internal_states.size()) {
        return save_internal_states(options.internal_states, file_name);
    }

    state_writer writer(m_ll_device, options);

    la_status status = writer.fill();
    return_on_error(status);

    if (options.include_mac_port_serdes) {
        // Collect port info into another JSON structure
        json_t* ports_json_root = json_object();
        status = save_all_mac_port_state(ports_json_root);
        return_on_error(status);

        // Append ports state to device state, write.fill() "steels" reference to ports_json_root.
        status = writer.fill(ports_json_root, "ports_state");
        return_on_error(status);
    }

    if (options.include_interrupt_counters) {
        json_t* interrupt_counters_json_root = json_object();
        status = m_notification->get_interrupt_tree()->save_state(interrupt_counters_json_root);
        return_on_error(status);

        // Append interrupt_counters state to device state, write.fill() "steels" reference to interrupt_counters_json_root.
        status = writer.fill(interrupt_counters_json_root, "interrupt_counters_state");
        return_on_error(status);
    }

    return (writer.write(file_name));
}

template <class _Table>
la_status
la_device_impl::append_table_properties_to_json(_Table& table, json_t* table_prop_array_json) const
{
    std::string key_str;
    std::string value_str;
    la_uint_t value_num;
    json_t* table_object = json_object();

    key_str = "used";
    value_num = table->size();
    json_object_set_new(table_object, key_str.c_str(), json_integer(value_num));

    key_str = "total";
    value_num = table->max_size();
    json_object_set_new(table_object, key_str.c_str(), json_integer(value_num));

    json_array_append_new(table_prop_array_json, table_object);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_table_allocations(json_t* tables_array_json) const
{
    std::string key_str;
    json_t* table_prop_array_json;
    json_t* table_object;

    table_object = json_object();
    key_str = "ipv4_vrf_dip_em_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.ipv4_vrf_dip_em_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    table_object = json_object();
    key_str = "ipv4_vrf_s_g_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.ipv4_vrf_s_g_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    table_object = json_object();
    key_str = "ipv6_vrf_dip_em_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.ipv6_vrf_dip_em_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    table_object = json_object();
    key_str = "ipv6_vrf_s_g_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.ipv6_vrf_s_g_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    table_object = json_object();
    key_str = "lp_over_lag_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.lp_over_lag_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    table_object = json_object();
    key_str = "mac_forwarding_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.mac_forwarding_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    table_object = json_object();
    key_str = "mac_forwarding_w_metadata_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.mac_forwarding_w_metadata_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    table_object = json_object();
    key_str = "mpls_forwarding_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.mpls_forwarding_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    table_object = json_object();
    key_str = "bfd_rx_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.bfd_rx_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    table_object = json_object();
    key_str = "pfc_destination_table";
    table_prop_array_json = json_array();
    json_object_set_new(table_object, key_str.c_str(), table_prop_array_json);
    append_table_properties_to_json(m_tables.pfc_destination_table, table_prop_array_json);
    json_array_append_new(tables_array_json, table_object);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_counter_allocations(json_t* counters_array_json) const
{
    std::string value_str;
    std::string key_str;
    la_uint_t value_num;
    std::set<const counter_logical_bank*> counter_banks;
    m_counter_bank_manager->get_logical_banks(counter_banks);

    // For all counter banks
    for (auto it = counter_banks.begin(); it != counter_banks.end(); it++) {
        const counter_logical_bank* bank = *it;

        // Create json object.
        json_t* counter_bank_object = json_object();

        // Fill the counter bank object.
        key_str = "first_bank_index";
        value_num = bank->get_first_index();
        json_object_set_new(counter_bank_object, key_str.c_str(), json_integer(value_num));

        key_str = "first_slice";
        value_num = bank->get_first_slice();
        json_object_set_new(counter_bank_object, key_str.c_str(), json_integer(value_num));

        key_str = "num_slices";
        size_t num_slices = bank->get_num_of_slices();
        value_num = num_slices;
        json_object_set_new(counter_bank_object, key_str.c_str(), json_integer(value_num));

        key_str = "allowed_users";
        std::bitset<COUNTER_USER_TYPE_NUM> allowed_users = bank->get_allowed_user_types();
        value_str = "";
        for (size_t bit = 0; bit < COUNTER_USER_TYPE_NUM; bit++) {
            if (!allowed_users.test(bit)) {
                continue;
            }
            value_str += silicon_one::to_string(static_cast<counter_user_type_e>(bit)) + ", ";
        }

        json_object_set_new(counter_bank_object, key_str.c_str(), json_string(value_str.c_str()));

        key_str = "direction";
        value_str = silicon_one::to_string(bank->get_direction());
        json_object_set_new(counter_bank_object, key_str.c_str(), json_string(value_str.c_str()));

        // Get usage for all physical banks in this logical bank.
        vector_alloc<std::array<size_t, COUNTER_USER_TYPE_NUM> > bank_allocations = bank->size();
        key_str = "physical_banks";
        json_t* banks_array = json_array();
        json_object_set_new(counter_bank_object, key_str.c_str(), banks_array);

        for (size_t i = 0; i < num_slices * NUM_IFGS_PER_SLICE; i++) {
            json_t* banks_object = json_object();
            key_str = "total";
            value_num = bank->max_size() / (num_slices * NUM_IFGS_PER_SLICE);
            json_object_set_new(banks_object, key_str.c_str(), json_integer(value_num));

            key_str = "allocations";
            json_t* used_per_user_type_array = json_array();
            json_object_set_new(banks_object, key_str.c_str(), used_per_user_type_array);
            for (size_t bit = 0; bit < COUNTER_USER_TYPE_NUM; bit++) {
                if (!allowed_users.test(bit)) {
                    continue;
                }

                counter_user_type_e user = static_cast<counter_user_type_e>(bit);
                json_t* per_user_usage_object = json_object();
                key_str = "user";
                value_str = silicon_one::to_string(user);
                json_object_set_new(per_user_usage_object, key_str.c_str(), json_string(value_str.c_str()));
                key_str = "used";
                value_num = bank_allocations[i][user];
                json_object_set_new(per_user_usage_object, key_str.c_str(), json_integer(value_num));
                json_array_append_new(used_per_user_type_array, per_user_usage_object);
            }

            json_array_append_new(banks_array, banks_object);
        }

        // Append to Counters array.
        json_array_append_new(counters_array_json, counter_bank_object);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_tcam_allocations(json_t* tcam_array_json) const
{
    std::string value_str;
    std::string key_str;
    la_uint_t value_num;

    json_t* db_array_object = json_object();
    key_str = "V4_LPTS_AND_SEC_ACL_DB";
    json_t* db_array_json = json_array();
    json_object_set_new(db_array_object, key_str.c_str(), db_array_json);
    json_array_append_new(tcam_array_json, db_array_object);

    for (la_slice_id_t slice_id : get_used_slices()) {
        json_t* db_object = json_object();

        key_str = "slice_id";
        value_num = slice_id;
        json_object_set_new(db_object, key_str.c_str(), json_integer(value_num));
        key_str = "used";
        value_num = m_tables.ipv4_lpts_table[slice_id]->size();
        json_object_set_new(db_object, key_str.c_str(), json_integer(value_num));
        key_str = "total";
        value_num = m_tables.ipv4_lpts_table[slice_id]->max_size();
        json_object_set_new(db_object, key_str.c_str(), json_integer(value_num));

        json_array_append_new(db_array_json, db_object);
    }

    db_array_object = json_object();
    key_str = "V6_LPTS_AND_SEC_ACL_DB";
    db_array_json = json_array();
    json_object_set_new(db_array_object, key_str.c_str(), db_array_json);
    json_array_append_new(tcam_array_json, db_array_object);

    for (la_slice_id_t slice_id : get_used_slices()) {
        json_t* db_object = json_object();

        key_str = "slice_id";
        value_num = slice_id;
        json_object_set_new(db_object, key_str.c_str(), json_integer(value_num));
        key_str = "used";
        value_num = m_tables.ipv6_lpts_table[slice_id]->size() + m_tables.ingress_rtf_ipv6_db1_320_f0_table[slice_id]->size();
        json_object_set_new(db_object, key_str.c_str(), json_integer(value_num));
        key_str = "total";
        value_num = m_tables.ipv6_lpts_table[slice_id]->max_size();
        json_object_set_new(db_object, key_str.c_str(), json_integer(value_num));

        json_array_append_new(db_array_json, db_object);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::save_internal_states(std::vector<std::string> internal_states_vec, json_t*& out_json) const
{
    json_t* m_root_json;

    m_root_json = json_object();

    std::string key_str = "internals";
    json_t* internals_array_json = json_array();
    json_object_set_new(m_root_json, key_str.c_str(), internals_array_json);

    for (std::string internal_state : internal_states_vec) {
        if (internal_state.compare("counters") == 0) {
            std::string key_str = "counter_banks";
            json_t* counters_array_json = json_array();
            json_t* counter_banks_object_json = json_object();
            json_object_set_new(counter_banks_object_json, key_str.c_str(), counters_array_json);
            json_array_append_new(internals_array_json, counter_banks_object_json);

            get_counter_allocations(counters_array_json);
        } else if (internal_state.compare("tables") == 0) {
            std::string key_str = "tables";
            json_t* tables_array_json = json_array();
            json_t* tables_object_json = json_object();
            json_object_set_new(tables_object_json, key_str.c_str(), tables_array_json);
            json_array_append_new(internals_array_json, tables_object_json);

            get_table_allocations(tables_array_json);
        } else if (internal_state.compare("tcam") == 0) {
            std::string key_str = "tcam_databases";
            json_t* tcam_array_json = json_array();
            json_t* tcam_object_json = json_object();
            json_object_set_new(tcam_object_json, key_str.c_str(), tcam_array_json);
            json_array_append_new(internals_array_json, tcam_object_json);

            get_tcam_allocations(tcam_array_json);
        }
    }

    if (json_object_size(m_root_json) == 0) {
        return LA_STATUS_EINVAL;
    }

    out_json = m_root_json;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::save_internal_states(std::vector<std::string> internal_states_vec, std::string file_name) const
{
    json_t* m_root_json;
    la_status status;

    status = save_internal_states(internal_states_vec, m_root_json);
    return_on_error(status);

    status = file_utils::write_json_to_file(m_root_json, file_name);

    json_decref(m_root_json);

    return status;
}

la_status
la_device_impl::save_all_mac_port_state(json_t* out_root) const
{
    for (auto it : m_mac_ports) {
        la_status status = it.second->save_state(la_mac_port::port_debug_info_e::ALL, out_root);
        if (status != LA_STATUS_SUCCESS) {
            la_slice_id_t slice_id = it.second->get_slice();
            la_ifg_id_t ifg_id = it.second->get_ifg();
            la_uint_t serdes_base_id = it.second->get_first_serdes_id();
            log_err(MAC_PORT, "Slice/IFG/SerDes %d/%d/%d failed during save_state.", slice_id, ifg_id, serdes_base_id);
        }
    }
    return LA_STATUS_SUCCESS;
}

void
la_device_impl::poll_mac_ports()
{
    for (auto it : m_mac_ports) {
        it.second->poll_link_state();
    }
}

void
la_device_impl::poll_npu_host_event_queue()
{
    auto events = m_npu_host_eventq->collect_npu_host_events();

    for (const bit_vector& event : events) {
        m_npu_host_eventq->handle_npu_host_event(event);
    }
}

void
la_device_impl::add_oam_delay_arm(const la_bfd_session_base_wptr& entry)
{
    m_oam_delay_arm.push_back(entry);
}

void
la_device_impl::remove_oam_delay_arm(const la_bfd_session_base_wptr& entry)
{
    m_oam_delay_arm.remove(entry);
}

void
la_device_impl::poll_npu_host_arm_detection_queue()
{
    std::chrono::milliseconds interval;
    m_notification->get_poll_interval(hld_notification_base::poll_interval_e::POLL_INTERVAL_FAST, interval);

    m_oam_delay_arm.remove_if(
        [=](const la_bfd_session_base_wptr& session) { return session && session->check_arm_detection_timer(interval); });
}

void
la_device_impl::add_pfc_watchdog_poll(const la_mac_port_base_wptr& entry)
{
    m_pfc_watchdog_poll.push_back(entry);
}

void
la_device_impl::remove_pfc_watchdog_poll(const la_mac_port_base_wptr& entry)
{
    m_pfc_watchdog_poll.remove(entry);
}

void
la_device_impl::poll_pfc_watchdog()
{
    std::chrono::milliseconds interval;
    m_notification->get_poll_interval(hld_notification_base::poll_interval_e::POLL_INTERVAL_FAST, interval);

    // Need the polling to be at 25ms interval. Use the fast poller and
    // only loop through the watchdog polling at approx 25ms.
    m_pfc_watchdog_countdown -= interval;
    if (m_pfc_watchdog_countdown > std::chrono::microseconds(0)) {
        return;
    }

    m_pfc_watchdog_countdown = std::chrono::milliseconds(PFC_WATCHDOG_POLL_TIME_MS);

    // The remove_if will loop through list of mac_port, call the check_pfc_watchdog and remove the element
    // the list if it returns true.
    m_pfc_watchdog_poll.remove_if(
        [=](const la_mac_port_base_wptr& mac_port) { return mac_port && mac_port->check_pfc_watchdog(m_pfc_watchdog_countdown); });
}

void
la_device_impl::poll_fe_routing_table()
{
    auto current_time = std::chrono::steady_clock::now();
    if ((current_time - m_fe_routing_table_last_pool_time_point) < std::chrono::seconds(2)) {
        log_debug(HLD, "la_device_impl::poll_fe_routing_table finished without performing poll.");
        return;
    }

    m_fe_routing_table_last_pool_time_point = current_time;

    do_poll_fe_routing_table();
}

void
la_device_impl::do_poll_fe_routing_table()
{
    log_debug(HLD, "la_device_impl::do_poll_fe_routing_table begins.");

    dassert_crit(m_gb_tree->dmc->frm->fabric_routing_table->get_desc()->width_bits == NUM_FABRIC_PORTS_IN_DEVICE);

    const size_t line_width_total = m_gb_tree->dmc->frm->fabric_routing_table->get_desc()->width_total;

    bit_vector tmp_fe_routing_table;

    la_status status = m_ll_device->read_memory(*m_gb_tree->dmc->frm->fabric_routing_table, 0, MAX_DEVICES, tmp_fe_routing_table);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "Memory reading returned error %s, skipping.", status.message().c_str());
        return;
    }

    update_current_links_state_and_handle_link_changes(tmp_fe_routing_table, line_width_total);
}

void
la_device_impl::update_on_fabric_links_changed(const la_device_id_vec_t& changed_devices)
{
    const size_t broadcast_bmp_entries
        = gibraltar::rx_pdr_2_slices_fe_configurations_reg1_register::fields::SLICE_FE_VALID_BROADCAST_BMP_VECTOR_WIDTH;
    configure_fe_broadcast_bmp(broadcast_bmp_entries);
    auto fabric_mc_groups = get_objects(object_type_e::FABRIC_MULTICAST_GROUP);
    for (auto fmcg : fabric_mc_groups) {
        la_fabric_multicast_group_impl* fmcg_impl = static_cast<la_fabric_multicast_group_impl*>(fmcg);
        fmcg_impl->configure_mc_bitmap();
    }
}

la_status
la_device_impl::add_potential_link(la_uint_t fabric_port_num, la_device_id_t dev_id)
{
    la_status status = add_fabric_port_to_bundle(fabric_port_num, dev_id);
    return_on_error(status);

    m_device_to_potential_links[dev_id].push_back(fabric_port_num);
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::remove_potential_link(la_uint_t fabric_port_num, la_device_id_t dev_id)
{
    link_vec_t& potential_links = m_device_to_potential_links[dev_id];
    potential_links.erase(std::remove(potential_links.begin(), potential_links.end(), fabric_port_num), potential_links.end());

    la_status status = remove_fabric_port_from_bundle(fabric_port_num, dev_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::remove_fabric_port_from_bundle(la_uint_t fabric_port_num, la_device_id_t dev_id)
{
    la_slice_id_t rep_sid = get_used_slice_pairs()[0];
    log_debug(HLD, "la_device_impl::remove_fabric_port_from_bundle begins");
    gibraltar::rx_pdr_2_slices_fb_link_to_link_bundle_table_memory link_to_bundle;

    la_status status = m_ll_device->read_memory(
        (*m_gb_tree->slice_pair[rep_sid]->rx_pdr->fb_link_to_link_bundle_table)[0], fabric_port_num, link_to_bundle);
    return_on_error(status);

    if (link_to_bundle.fields.table_bundle_num == INVALID_BUNDLE) {
        return LA_STATUS_SUCCESS;
    }

    for (la_slice_id_t slice : get_used_slices()) {
        status = m_ll_device->write_memory(
            (*m_gb_tree->slice_pair[slice / 2]->rx_pdr->fb_link_to_link_bundle_table)[slice % 2], fabric_port_num, INVALID_BUNDLE);
        return_on_error(status);
    }

    size_t bundle_id = link_to_bundle.fields.table_bundle_num;
    link_vec_t& bundle(m_bundles[bundle_id]);
    bundle.erase(std::remove(bundle.begin(), bundle.end(), fabric_port_num), bundle.end());

    status = configure_bundle(bundle_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::add_fabric_port_to_bundle(la_uint_t fabric_port_num, la_device_id_t dev_id)
{
    la_slice_id_t rep_sid = get_used_slice_pairs()[0];
    log_debug(HLD, "la_device_impl::add_fabric_port_to_bundle begins");
    gibraltar::rx_pdr_2_slices_fb_link_to_link_bundle_table_memory link_to_bundle;
    la_status status;

    status = m_ll_device->read_memory(
        (*m_gb_tree->slice_pair[rep_sid]->rx_pdr->fb_link_to_link_bundle_table)[0], fabric_port_num, link_to_bundle);
    return_on_error(status);

    dassert_crit(link_to_bundle.fields.table_bundle_num == INVALID_BUNDLE);

    link_vec_t links_without_bundle;
    for (size_t link : m_device_to_potential_links[dev_id]) {
        status = m_ll_device->read_memory(
            (*m_gb_tree->slice_pair[rep_sid]->rx_pdr->fb_link_to_link_bundle_table)[0], link, link_to_bundle);
        return_on_error(status);

        if (link_to_bundle.fields.table_bundle_num == INVALID_BUNDLE) {
            links_without_bundle.push_back(link);
            continue;
        }
        size_t bundle_id = link_to_bundle.fields.table_bundle_num;
        if (m_bundles[bundle_id].size() == MAX_LINKS_IN_BUNDLE) {
            continue;
        }

        m_bundles[bundle_id].push_back(fabric_port_num);
        status = configure_bundle(bundle_id);
        return_on_error(status);

        return LA_STATUS_SUCCESS;
    }

    // If there is no space in existing bundles to dev_id,
    // we check if there is link to dev_id which is not in bundle and group links together in a new bundle.
    for (auto link : links_without_bundle) {
        for (int bundle_id = 0; bundle_id < MAX_LINK_BUNDLES_IN_FE_DEVICE; bundle_id++) {
            if (!m_bundles[bundle_id].empty()) {
                continue;
            }

            m_bundles[bundle_id].push_back(link);
            m_bundles[bundle_id].push_back(fabric_port_num);

            status = configure_bundle(bundle_id);
            return_on_error(status);

            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_bundle(size_t bundle_id)
{
    gibraltar::rx_pdr_2_slices_fe_uc_link_bundle_desc_table_memory bundle_desc;
    gibraltar::rx_pdr_2_slices_fb_link_to_link_bundle_table_memory link_to_bundle;
    link_vec_t& bundle(m_bundles[bundle_id]);
    la_status status;

    dassert_crit(bundle.size() > 0);

    // Bundle must contains minimum 2 links.
    bundle_desc.fields.slice_bundle_link0 = bundle.size() >= 2 ? bundle[0] : INVALID_LINK;
    bundle_desc.fields.slice_bundle_link1 = bundle.size() >= 2 ? bundle[1] : INVALID_LINK;
    bundle_desc.fields.slice_bundle_link2 = bundle.size() >= 3 ? bundle[2] : INVALID_LINK;
    bundle_desc.fields.slice_bundle_link3 = bundle.size() >= 4 ? bundle[3] : INVALID_LINK;

    bundle_desc.fields.slice_bundle_link0_bc = 0;
    bundle_desc.fields.slice_bundle_link1_bc = 0;
    bundle_desc.fields.slice_bundle_link2_bc = 0;
    bundle_desc.fields.slice_bundle_link3_bc = 0;

    link_to_bundle.fields.table_bundle_num = bundle_id;

    if (bundle.size() < 2) {

        for (la_slice_id_t slice : get_used_slices()) {
            status = m_ll_device->write_memory(
                (*m_gb_tree->slice_pair[slice / 2]->rx_pdr->fb_link_to_link_bundle_table)[slice % 2], bundle[0], INVALID_BUNDLE);
            return_on_error(status);
        }
        bundle.clear();
    }

    for (la_slice_id_t slice : get_used_slices()) {
        // Order of pushing backs is important.
        // Configuring fb_link_to_link_bundle_table before fe_uc_link_bundle_desc_table can cause packet drops
        // because if there is bundle associated with link, that bundle must be configured.

        // fe_uc_link_bundle_desc_table is a dynamic memory, it may happen that after we write to it, the hardware will
        // update it with incorrect value (if it read the values before our update), so we make sure that what we wrote
        // was saved there and not overridden by HW.
        status = write_bundle_desc_table_and_verify_write(slice, bundle_id, bundle_desc);
        return_on_error(status);

        for (size_t link : bundle) {
            status = m_ll_device->write_memory(
                (*m_gb_tree->slice_pair[slice / 2]->rx_pdr->fb_link_to_link_bundle_table)[slice % 2], link, link_to_bundle);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::write_bundle_desc_table_and_verify_write(
    la_slice_id_t slice,
    size_t bundle_id,
    gibraltar::rx_pdr_2_slices_fe_uc_link_bundle_desc_table_memory& bundle_desc)
{
    gibraltar::rx_pdr_2_slices_fe_uc_link_bundle_desc_table_memory read_bundle_desc;
    bool did_write_succeed = false;
    constexpr size_t MAX_TRIES_NUM = 10;
    for (size_t i = 0; i < MAX_TRIES_NUM; i++) {
        la_status status = m_ll_device->write_memory(
            (*m_gb_tree->slice_pair[slice / 2]->rx_pdr->fe_uc_link_bundle_desc_table)[slice % 2], bundle_id, bundle_desc);
        return_on_error(status);

        status = m_ll_device->read_memory(
            (*m_gb_tree->slice_pair[slice / 2]->rx_pdr->fe_uc_link_bundle_desc_table)[slice % 2], bundle_id, read_bundle_desc);
        return_on_error(status);
        did_write_succeed = ((bundle_desc.fields.slice_bundle_link0 == read_bundle_desc.fields.slice_bundle_link0)
                             && (bundle_desc.fields.slice_bundle_link1 == read_bundle_desc.fields.slice_bundle_link1)
                             && (bundle_desc.fields.slice_bundle_link2 == read_bundle_desc.fields.slice_bundle_link2)
                             && (bundle_desc.fields.slice_bundle_link3 == read_bundle_desc.fields.slice_bundle_link3));
        if (did_write_succeed) {
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_EAGAIN;
}

npl_counter_type_e
la_device_impl::get_counter_bank_type() const
{
    bool enabled = false;
    get_bool_property(la_device_property_e::ENABLE_NARROW_COUNTERS, enabled);
    return (enabled == false) ? NPL_COUNTER_TYPE_PC64_BC64 : NPL_COUNTER_TYPE_PC29_BC35;
}

std::chrono::milliseconds
la_device_impl::get_counter_shadow_duration_until_age_out() const
{
    int duration_till_age_out = 0;
    get_int_property(la_device_property_e::COUNTERS_SHADOW_AGE_OUT, duration_till_age_out);
    return std::chrono::milliseconds(duration_till_age_out);
}

bool
la_device_impl::is_mpls_sr_accounting_enabled() const
{
    bool enabled = false;
    get_bool_property(la_device_property_e::ENABLE_MPLS_SR_ACCOUNTING, enabled);
    return enabled;
}

bool
la_device_impl::is_pbts_enabled() const
{
    bool enabled = false;
    get_bool_property(la_device_property_e::ENABLE_PBTS, enabled);
    return enabled;
}

bool
la_device_impl::is_mc_voq_set(const la_voq_set_wcptr& voq_set) const
{
    bool found = false;
    for (const auto& mc_voq_set : m_egress_multicast_slice_replication_voq_set) {
        if (mc_voq_set == voq_set) {
            found = true;
            break;
        }
    }

    // Is it one of the SA-mode MC-VOQs ?
    if (found) {
        return true;
    }

    // Is it the LC-mode MC-VOQ ?
    if (voq_set == m_egress_multicast_fabric_replication_voq_set.get()) {
        return true;
    }

    return false;
}

la_device_impl::lc_56_fabric_port_info
la_device_impl::get_borrowed_fabric_port_info(la_slice_id_t lender_slice_id,
                                              la_ifg_id_t lender_ifg_id,
                                              size_t lender_serdes_base_id) const
{
    lc_56_fabric_port_info retval = {.is_lc_56_fabric_port = false,
                                     .slice_id = (la_slice_id_t)-1,
                                     .ifg_id = (la_ifg_id_t)-1,
                                     .serdes_base_id = (size_t)-1,
                                     .fabric_port_num = (size_t)-1};

    bool lc_56_fabric_port_mode;
    la_status status = get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, lc_56_fabric_port_mode);
    if (status != LA_STATUS_SUCCESS) {
        dassert_crit(status == LA_STATUS_SUCCESS);
    }

    if (lc_56_fabric_port_mode) {
        if ((lender_slice_id == 0) && (lender_ifg_id == 0) && (lender_serdes_base_id == IFG_LENDED_SERDES_ID)) {
            retval.is_lc_56_fabric_port = true;
            retval.slice_id = 5;
            retval.ifg_id = 1;
            retval.serdes_base_id = IFG_BORROWED_SERDES_ID;
            retval.fabric_port_num = IFG_BORROWED_FABRIC_PORT_NUM;
        }

        if ((lender_slice_id == 2) && (lender_ifg_id == 1) && (lender_serdes_base_id == IFG_LENDED_SERDES_ID)) {
            retval.is_lc_56_fabric_port = true;
            retval.slice_id = 3;
            retval.ifg_id = 0;
            retval.serdes_base_id = IFG_BORROWED_SERDES_ID;
            retval.fabric_port_num = IFG_BORROWED_FABRIC_PORT_NUM;
        }
    }

    return retval;
}

bool
la_device_impl::is_borrower_ifg(la_slice_id_t sid, la_ifg_id_t ifg) const
{
    bool lc_56_fabric_port_mode;

    la_status status = get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, lc_56_fabric_port_mode);
    if (status != LA_STATUS_SUCCESS) {
        dassert_crit(status == LA_STATUS_SUCCESS);
    }

    if (lc_56_fabric_port_mode == false) {
        return false;
    }

    if ((sid == 3) && (ifg == 0)) {
        return true;
    }

    if ((sid == 5) && (ifg == 1)) {
        return true;
    }

    return false;
}

la_status
la_device_impl::flush_rxpdr_mcid_cache(la_slice_id_t slice) const
{
    lld_register_value_list_t reg_val_list;
    auto ptrr = (*m_gb_tree->slice_pair[slice / 2]->rx_pdr->slice_global_configuration)[slice % 2];

    gibraltar::rx_pdr_2_slices_slice_global_configuration_register rr;
    la_status status = m_ll_device->read_register(ptrr, rr);
    return_on_error(status);
    rr.fields.slice_mc_cache_reset_trig = 1;
    reg_val_list.push_back({(ptrr), rr});
    rr.fields.slice_mc_cache_reset_trig = 0;
    reg_val_list.push_back({(ptrr), rr});

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::flush_txpdr_mcid_cache(la_slice_id_t slice) const
{
    lld_register_value_list_t reg_val_list;
    auto pttr = m_gb_tree->slice[slice]->tx->pdr->mcid_cache_configuration;

    gibraltar::txpdr_mcid_cache_configuration_register tr;
    la_status status = m_ll_device->read_register(pttr, tr);
    return_on_error(status);

    tr.fields.cache_reset_trig = 1;
    reg_val_list.push_back({(pttr), tr});
    tr.fields.cache_reset_trig = 0;
    reg_val_list.push_back({(pttr), tr});

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::flush_mcid_cache(la_slice_id_t slice) const
{
    la_status status;
    status = flush_rxpdr_mcid_cache(slice);
    return_on_error(status);

    status = flush_txpdr_mcid_cache(slice);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

bool
la_device_impl::is_lender_ifg(la_slice_id_t sid, la_ifg_id_t ifg) const
{
    bool lc_56_fabric_port_mode;

    la_status status = get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, lc_56_fabric_port_mode);
    if (status != LA_STATUS_SUCCESS) {
        dassert_crit(status == LA_STATUS_SUCCESS);
    }

    if (lc_56_fabric_port_mode == false) {
        return false;
    }

    if ((sid == 0) && (ifg == 0)) {
        return true;
    }

    if ((sid == 2) && (ifg == 1)) {
        return true;
    }

    return false;
}

bool
la_device_impl::is_borrower_slice(la_slice_id_t sid) const
{
    bool lc_56_fabric_port_mode;

    la_status status = get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, lc_56_fabric_port_mode);
    if (status != LA_STATUS_SUCCESS) {
        dassert_crit(status == LA_STATUS_SUCCESS);
    }

    if (lc_56_fabric_port_mode == false) {
        return false;
    }

    if ((sid == 3) || (sid == 5)) {
        return true;
    }

    return false;
}

bool
la_device_impl::is_fabric_port_supporting_serdes(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_uint_t first_serdes_id) const
{
    if (m_slice_mode[slice_id] == la_slice_mode_e::CARRIER_FABRIC) {
        return true;
    }

    bool is_lender_ifg_en = is_lender_ifg(slice_id, ifg_id);
    bool is_potentially_lended_port = (first_serdes_id >= IFG_LENDED_SERDES_ID);

    if ((m_slice_mode[slice_id] == la_slice_mode_e::NETWORK) && (is_lender_ifg_en == true)
        && (is_potentially_lended_port == true)) {
        return true;
    }

    return false;
}

size_t
la_device_impl::num_fabric_ports_in_borrower_ifg(la_slice_id_t sid, la_ifg_id_t ifg) const
{
    size_t num_fabric_ports_in_borrower_ifg
        = is_borrower_ifg(sid, ifg) ? NUM_FABRIC_PORTS_IN_ENHANCED_IFG : NUM_FABRIC_PORTS_IN_NORMAL_IFG;

    return num_fabric_ports_in_borrower_ifg;
}

la_status
la_device_impl::initialize_cud_range_managers()
{
    for (la_slice_id_t slice : get_used_slices()) {
        if (m_slice_mode[slice] == la_slice_mode_e::NETWORK) {
            m_cud_range_manager[slice] = silicon_one::make_unique<cud_range_manager>(shared_from_this(), slice);
            la_status status = m_cud_range_manager[slice]->initialize();
            return_on_error(status);
        } else {
            m_cud_range_manager[slice] = nullptr;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_fe_fabric_reachability_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_EINVAL;
    }

    if (enabled == m_fe_fabric_reachability_enabled) {
        return LA_STATUS_SUCCESS;
    }

    if (enabled) {
        la_status status = hardware_reachability_update();
        return_on_error(status);
    } else {
        la_status status = advertise_empty_reachability();
        return_on_error(status);
    }

    m_fe_fabric_reachability_enabled = enabled;
    m_reconnect_handler->update_fe_fabric_reachability_enabled(enabled);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::hardware_reachability_update()
{
    // Enable the FE to send the correct reachability vector
    la_status status = set_reachable_bitmap_hw_updates_enabled(true);
    return_on_error(status);

    status = trigger_frt_scan();
    return status;
}

la_status
la_device_impl::trigger_frt_scan()
{
    // The sending of the routing table to device blocks is done on pos-egde change of debug_frtm_generate_frt_scan.
    // So write 0, wait (one clock), write 1
    // The triggering should happen after the frm_db_fabric_routing_table has been fully written.
    gibraltar::frm_debug_frtm_debug_reg_register reg;
    bit_vector reachability_bmp;

    // HW would ignore this trigger if recieves FRP. We trigger it 10 times in a row to be sure HW is not igrnoring it.
    // Testing in extreme cases has shown that 10 time should be enough.
    constexpr size_t NUM_OF_TRIES = 10;

    // Read full register
    la_status status = m_ll_device->read_register(m_gb_tree->dmc->frm->debug_frtm_debug_reg, reg);
    return_on_error(status);

    for (size_t i = 0; i < NUM_OF_TRIES; i++) {
        // Write 0
        reg.fields.debug_frtm_generate_frt_scan = 0;
        status = m_ll_device->write_register(m_gb_tree->dmc->frm->debug_frtm_debug_reg, reg);
        return_on_error(status);

        // In RTL simulator, all writes are immediate, so need to indicate a sleep time. One clock sleep is needed, so 10ns is
        // safe enough.
        log_debug(HLD, "command::step_no_response %d", 10);

        // Write 1
        reg.fields.debug_frtm_generate_frt_scan = 1;
        status = m_ll_device->write_register(m_gb_tree->dmc->frm->debug_frtm_debug_reg, reg);
        return_on_error(status);

        status = m_ll_device->read_register(m_gb_tree->dmc->frm->frp_reachable_bitmap12_reg, reachability_bmp);
        return_on_error(status);

        if (!reachability_bmp.is_zero()) {
            break;
        }
    }

    if (reachability_bmp.is_zero()) {
        log_warning(HLD,
                    "%s: After %zu debug_frtm_generate_frt_scan retries, frp_reachable_bitmap12_reg is still empty\n",
                    __func__,
                    NUM_OF_TRIES);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::advertise_empty_reachability()
{
    // Force the FE to send an empty reachability vector
    // Make the HW stop updating the fabric reachability vector
    la_status status = set_reachable_bitmap_hw_updates_enabled(false);
    return_on_error(status);

    // Override the reachability vector that the FE uses to advertise to the LCs.
    status = m_ll_device->write_register(m_gb_tree->dmc->frm->frp_reachable_bitmap12_reg, 0);
    return status;
}

la_status
la_device_impl::set_reachable_bitmap_hw_updates_enabled(bool enabled)
{
    gibraltar::frm_debug_frtm_debug_reg_register frtm_debug_reg;
    la_status status = m_ll_device->read_register(m_gb_tree->dmc->frm->debug_frtm_debug_reg, frtm_debug_reg);
    return_on_error(status);

    if (enabled) {
        frtm_debug_reg.fields.debug_frtm_disable_reachable_bitmap_updates = 0;
    } else {
        frtm_debug_reg.fields.debug_frtm_disable_reachable_bitmap_updates = 1;
    }

    status = m_ll_device->write_register(m_gb_tree->dmc->frm->debug_frtm_debug_reg, frtm_debug_reg);
    return status;
}

la_status
la_device_impl::get_fe_fabric_reachability_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    out_enabled = m_fe_fabric_reachability_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_global_minimum_fabric_links(size_t num_links)
{
    start_api_call("num_links=", num_links);

    if (m_device_mode == device_mode_e::STANDALONE) {
        log_err(HLD, "This API can not be called on Standalone device.");
        return LA_STATUS_EINVAL;
    }

    bool is_per_device_min_link = false;
    get_bool_property(la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS, is_per_device_min_link);
    if (is_per_device_min_link) {
        log_debug(HLD, "set_global_minimum_fabric_links was called while ENABLE_FE_PER_DEVICE_MIN_LINKS is enabled.");
        m_global_min_fabric_links_threshold = num_links;
        return LA_STATUS_SUCCESS;
    }

    la_status status = set_minimum_fabric_links_for_all_devices(num_links);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_global_minimum_fabric_links(size_t& out_num_links) const
{
    start_api_getter_call();

    if (m_device_mode == device_mode_e::STANDALONE) {
        log_err(HLD, "This API can not be called on Standalone device.");
        return LA_STATUS_EINVAL;
    }

    out_num_links = m_global_min_fabric_links_threshold;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_fabric_sch_valid_links_quantization_thresholds(const la_fabric_valid_links_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    auto valid_links_mapping_reg = m_gb_tree->sch_top->frl_valid_links_mapping;
    bit_vector bv(0, gibraltar::sch_top_frl_valid_links_mapping_register::SIZE_IN_BITS);

    // 2 bits for each entry - each entry represents # of valid links
    for (size_t i = 0; i < MAX_FABRIC_PORTS_IN_LINECARD_DEVICE; i++) {
        const size_t bits_per_entry = 2;
        const size_t start = i * bits_per_entry;
        const size_t end = start + bits_per_entry;

        if (i < thresholds.thresholds[0]) {
            bv.set_bits(end, start, 3);
        } else if (i < thresholds.thresholds[1]) {
            bv.set_bits(end, start, 2);
        } else if (i < thresholds.thresholds[2]) {
            bv.set_bits(end, start, 1);
        } else {
            bv.set_bits(end, start, 0);
        }
    }

    la_status status = m_ll_device->write_register(valid_links_mapping_reg, bv);
    return_on_error(status);

    m_valid_links_thresholds = thresholds;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_fabric_sch_valid_links_quantization_thresholds(la_fabric_valid_links_thresholds& out_thresholds)
{
    start_api_getter_call();

    out_thresholds = m_valid_links_thresholds;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_fabric_sch_congested_links_quantization_thresholds(const la_fabric_congested_links_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    auto congested_links_mapping_reg = m_gb_tree->sch_top->frl_congested_links_mapping;
    bit_vector bv(0, gibraltar::sch_top_frl_congested_links_mapping_register::SIZE_IN_BITS);

    // 2 bits for each entry - each entry represents # of valid links
    for (size_t i = 0; i < MAX_FABRIC_PORTS_IN_LINECARD_DEVICE; i++) {
        const size_t bits_per_entry = 2;
        const size_t start = i * bits_per_entry;
        const size_t end = start + bits_per_entry;

        if (i < thresholds.thresholds[0]) {
            bv.set_bits(end, start, 0);
        } else if (i < thresholds.thresholds[1]) {
            bv.set_bits(end, start, 1);
        } else if (i < thresholds.thresholds[2]) {
            bv.set_bits(end, start, 2);
        } else {
            bv.set_bits(end, start, 3);
        }
    }

    la_status status = m_ll_device->write_register(congested_links_mapping_reg, bv);
    return_on_error(status);

    m_congested_links_thresholds = thresholds;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_fabric_sch_congested_links_quantization_thresholds(la_fabric_congested_links_thresholds& out_thresholds)
{
    start_api_getter_call();

    out_thresholds = m_congested_links_thresholds;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_fabric_sch_rate_map_entry(la_uint_t index, la_uint_t rate)
{
    start_api_call("index=", index, "rate=", rate);
    la_slice_id_t rep_sid = first_active_slice_id();
    // 4 possible indices
    const size_t num_indices = 4;
    la_uint_t max_rate
        = bit_utils::ones(gibraltar::sch_top_frl_rate_mapping_register::fields::NUM_LINKS_TO_RATE_MAP_WIDTH / num_indices);
    if (index >= num_indices && rate > max_rate) {
        return LA_STATUS_EINVAL;
    }

    auto rate_mapping_reg = m_gb_tree->sch_top->frl_rate_mapping;
    gibraltar::sch_top_frl_rate_mapping_register reg;

    la_status status = m_ll_device->read_register(rate_mapping_reg, reg);
    return_on_error(status);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    status = m_ll_device->read_register(m_gb_tree->slice[rep_sid]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    // Convert rate to device val - API takes rate in Kbps
    uint32_t dev_rate;
    status = tm_utils::convert_rate_to_device_val(
        ((la_rate_t)rate) * 1000, credits_conf_reg.fields.crdt_in_bytes, m_device_frequency_int_khz, dev_rate);
    return_on_error(status);

    // Round device rate up (conversion rounds it down). This means actual rate is always lower than configured
    dev_rate = dev_rate + 1;

    // Each entry is 14 bits - zero out bits at index, then replace with our rate
    const size_t entry_size_in_bits = 14;
    la_uint64_t link_map = reg.fields.num_links_to_rate_map;
    link_map = link_map & ~(0x3FFFULL << (index * entry_size_in_bits));
    link_map |= ((uint64_t)dev_rate << (index * entry_size_in_bits));
    reg.fields.num_links_to_rate_map = link_map;

    status = m_ll_device->write_register(rate_mapping_reg, reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_fabric_sch_rate_map_entry(la_uint_t index, la_uint_t& out_rate)
{
    start_api_getter_call();

    // 4 possible indices
    const size_t num_indices = 4;
    if (index >= num_indices) {
        return LA_STATUS_EINVAL;
    }

    la_slice_id_t rep_sid = first_active_slice_id();

    auto rate_mapping_reg = m_gb_tree->sch_top->frl_rate_mapping;
    gibraltar::sch_top_frl_rate_mapping_register reg;

    la_status status = m_ll_device->read_register(rate_mapping_reg, reg);
    return_on_error(status);

    // 14 bits per index
    const size_t entry_size_in_bits = 14;
    la_uint_t value = reg.fields.num_links_to_rate_map;
    value = value >> (index * entry_size_in_bits);
    value = value & bit_utils::ones(entry_size_in_bits);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    status = m_ll_device->read_register(m_gb_tree->slice[rep_sid]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    out_rate
        = tm_utils::convert_rate_from_device_val(value * 1000, credits_conf_reg.fields.crdt_in_bytes, m_device_frequency_int_khz);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_fabric_sch_links_map_entry(la_uint_t valid_link_status,
                                               la_uint_t congested_link_status,
                                               la_uint_t rate_map_index)
{
    start_api_call("valid_link_status=",
                   valid_link_status,
                   "congested_link_status=",
                   congested_link_status,
                   "rate_map_index=",
                   rate_map_index);

    const size_t valid_link_regions = 4;
    const size_t congested_link_regions = 4;
    const size_t rate_map_indices = 4;

    if (valid_link_status >= valid_link_regions || congested_link_status >= congested_link_regions
        || rate_map_index >= rate_map_indices) {
        return LA_STATUS_EINVAL;
    }

    // Valid link and congested link statuses are 2 bits each - entry number is (valid links | congested links)
    la_uint_t entry = (valid_link_status << 2) | congested_link_status;

    auto rate_mapping_reg = m_gb_tree->sch_top->frl_rate_mapping;
    bit_vector bv;

    la_status status = m_ll_device->read_register(rate_mapping_reg, bv);
    return_on_error(status);

    // EligibleLinksMap is bits 1:32, 2 bits per entry
    const size_t links_map_base = 1;
    const size_t entry_size_in_bits = 2;
    bv.set_bits(links_map_base + (entry * entry_size_in_bits) + entry_size_in_bits,
                links_map_base + (entry * entry_size_in_bits),
                rate_map_index);

    status = m_ll_device->write_register(rate_mapping_reg, bv);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_fabric_sch_links_map_entry(la_uint_t valid_link_status,
                                               la_uint_t congested_link_status,
                                               la_uint_t& out_rate_map_index)
{
    start_api_getter_call();

    const size_t valid_link_regions = 4;
    const size_t congested_link_regions = 4;

    if (valid_link_status >= valid_link_regions || congested_link_status >= congested_link_regions) {
        return LA_STATUS_EINVAL;
    }

    auto rate_mapping_reg = m_gb_tree->sch_top->frl_rate_mapping;
    gibraltar::sch_top_frl_rate_mapping_register reg;

    la_status status = m_ll_device->read_register(rate_mapping_reg, reg);
    return_on_error(status);

    // 2 bits per entry - entry is (valid links | congested links)
    const size_t entry_size_in_bits = 2;
    la_uint_t entry = (valid_link_status << 2) | congested_link_status;
    la_uint_t value = reg.fields.eligible_links_map;
    value = value >> (entry * entry_size_in_bits);
    value = value & 0x3;

    out_rate_map_index = value;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_minimum_fabric_links_per_lc(la_device_id_t device_id, size_t num_links)
{
    start_api_call("device_id=", device_id, "num_links=", num_links);

    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        log_err(HLD, "not an FE device");
        return LA_STATUS_EINVAL;
    }

    bool is_per_device_min_links_mode = false;
    la_status status = get_bool_property(la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS, is_per_device_min_links_mode);
    return_on_error(status);
    if (!is_per_device_min_links_mode) {
        log_err(HLD, "ENABLE_FE_PER_DEVICE_MIN_LINKS is not enabled");
        return LA_STATUS_EINVAL;
    }

    if (device_id >= get_max_devices_based_on_mode()) {
        log_err(HLD, "device_id=%d is out of range", device_id);
        return LA_STATUS_EOUTOFRANGE;
    }

    if (num_links > MAX_MIN_LINKS_THRESHOLD) {
        return LA_STATUS_EOUTOFRANGE;
    }

    gibraltar::frm_min_thr_per_device_id_cfg_table_memory mem_entry;
    mem_entry.fields.min_thr_per_device_id_cfg_data = num_links;
    status = m_ll_device->write_memory(m_gb_tree->dmc->frm->min_thr_per_device_id_cfg_table, device_id, mem_entry);
    return_on_error(status);

    status = trigger_frt_scan();
    return_on_error(status);

    m_reconnect_handler->update_minimum_fabric_links_per_lc(device_id, num_links);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_minimum_fabric_links_per_lc(la_device_id_t device_id, size_t& out_num_links) const
{
    start_api_getter_call();

    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        log_err(HLD, "not an FE device");
        return LA_STATUS_EINVAL;
    }

    bool is_per_device_min_links_mode = false;
    la_status status = get_bool_property(la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS, is_per_device_min_links_mode);
    return_on_error(status);
    if (!is_per_device_min_links_mode) {
        log_err(HLD, "ENABLE_FE_PER_DEVICE_MIN_LINKS is not enabled");
        return LA_STATUS_EINVAL;
    }

    if (device_id >= get_max_devices_based_on_mode()) {
        log_err(HLD, "device_id=%d is out of range", device_id);
        return LA_STATUS_EOUTOFRANGE;
    }

    gibraltar::frm_min_thr_per_device_id_cfg_table_memory mem_entry;
    status = m_ll_device->read_memory(m_gb_tree->dmc->frm->min_thr_per_device_id_cfg_table, device_id, mem_entry);
    return_on_error(status);
    out_num_links = mem_entry.fields.min_thr_per_device_id_cfg_data;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_fe_configurations_reg1(size_t num_valid_entries)
{
    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_SUCCESS;
    }

    lld_register_value_list_t reg_val_list;
    gibraltar::rx_pdr_2_slices_fe_configurations_reg1_register reg;
    constexpr size_t broadcast_bmp_vector_width = reg.fields.SLICE_FE_VALID_BROADCAST_BMP_VECTOR_WIDTH;

    auto valid_entries = bit_vector::ones_range(num_valid_entries - 1 /*msb*/, 0 /*lsb*/, broadcast_bmp_vector_width /*width*/);
    reg.fields.set_slice_fe_valid_broadcast_bmp_vector((const uint64_t*)valid_entries.byte_array());
    // We don't support two levels of FE, so none of the links is FE1.
    reg.fields.slice_src_link_is_fe1 = 0;

    for (la_slice_id_t slice : get_used_slices()) {
        reg_val_list.push_back({(*m_gb_tree->slice_pair[slice / 2]->rx_pdr->fe_configurations_reg1)[slice % 2], reg});
    }

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status, HLD, ERROR, "Failed to write register.");
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_mac_aging_interval(la_mac_aging_time_t& aging_interval)
{
    aging_interval = m_mac_aging_interval;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_mac_aging_interval(la_mac_aging_time_t aging_interval)
{
    start_api_call("aging_interval=", aging_interval);

    uint64_t conversion = aging_interval * LA_MAC_AGING_TIMER_TICKS_PER_SECOND;

    if (conversion > 0xFFFFFFFFULL && aging_interval != LA_MAC_AGING_TIME_NEVER) {
        log_err(HLD, "input out of range");
        return LA_STATUS_EOUTOFRANGE;
    }

    cem em(m_ll_device);

    // Input unit is in milliseconds
    // ARC timer tick is on 100ms intervals, conversion required
    la_status status = em.set_mac_aging_interval((aging_interval == LA_MAC_AGING_TIME_NEVER) ? ARC_MAC_AGING_INTERVAL_DISABLE
                                                                                             : (uint32_t)conversion);
    return_on_error(status, HLD, ERROR, "%s: failed to set MAC aging interval", __func__);

    m_mac_aging_interval = aging_interval;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_learn_mode(learn_mode_e learn_mode)
{
    start_api_call("learn_mode=", learn_mode);

    npl_learn_manager_cfg_max_learn_type_reg_t::key_type learn_type_key{};
    npl_learn_manager_cfg_max_learn_type_reg_t::value_type learn_type_value{};
    npl_learn_manager_cfg_max_learn_type_reg_t::entry_pointer_type learn_type_entry = nullptr;
    learn_type_value.payloads.learn_manager_cfg_max_learn_type.lr_type
        = (learn_mode == learn_mode_e::SYSTEM) ? NPL_LEARN_TYPE_SYSTEM : NPL_LEARN_TYPE_LOCAL;
    la_status status = m_tables.learn_manager_cfg_max_learn_type_reg->set(learn_type_key, learn_type_value, learn_type_entry);
    return_on_error(status);

    // The above NPL table is not mapped to HW, so we write for both: NPL and HW.
    cdb_top_learn_manager_cfg_max_learn_type_register reg = {.u8 = {0}};
    if (learn_mode == learn_mode_e::SYSTEM) {
        reg.fields.system_learning = 1;
    } else {
        reg.fields.local_learning = 1;
    }
    status = m_ll_device->write_register(m_gb_tree->cdb->top->learn_manager_cfg_max_learn_type, reg);
    return_on_error(status);

    cem em(m_ll_device);

    status = (learn_mode == learn_mode_e::SYSTEM) ? em.set_arc_system_mac_learning_features()
                                                  : em.set_arc_local_mac_learning_features();
    return_on_error(status, HLD, ERROR, "failed to set MAC learning features");

    m_learn_mode = learn_mode;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_learn_mode(learn_mode_e& out_learn_mode)
{
    out_learn_mode = m_learn_mode;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::add_to_mc_copy_id_table(const la_l3_ac_port_impl_wcptr& ac_port,
                                        const la_system_port_wcptr& dsp,
                                        uint64_t mc_copy_id)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::add_to_mc_copy_id_table(const la_l2_service_port_base_wcptr& ac_port, const la_system_port_wcptr& dsp)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::add_to_mc_copy_id_table(la_slice_id_t slice, uint64_t mc_copy_id, size_t bank_id)
{
    npl_mc_copy_id_map_key_t key;
    npl_mc_copy_id_map_value_t value;

    key.cud_mapping_local_vars_mc_copy_id_17_12_ = bit_utils::get_bits(mc_copy_id, 17, 12);
    value.action = NPL_MC_COPY_ID_MAP_ACTION_UPDATE;
    value.payloads.update.mc_copy_id_msbs = (bank_id & 0xfe)                      // 8 bits: 7b bank_id
                                            | bit_utils::get_bit(mc_copy_id, 12); //  LSB is the counter-offset MSB
    value.payloads.update.encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_PWE_OR_MC_ACCOUNTING;

    return do_add_to_mc_copy_id_table(slice, key, value);
}

la_status
la_device_impl::remove_from_mc_copy_id_table(const la_l2_service_port_base_wcptr& ac_port, const la_system_port_wcptr& dsp)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::remove_from_mc_copy_id_table(const la_l3_ac_port_impl_wcptr& ac_port,
                                             const la_system_port_wcptr& dsp,
                                             uint64_t mc_copy_id)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::release_ipv6_compressed_sip(la_ipv6_addr_t sip)
{
    // Find in map
    auto it = m_ipv6_compressed_sip_map.find(sip.s_addr);
    if (it == m_ipv6_compressed_sip_map.end()) {
        return LA_STATUS_EUNKNOWN;
    }

    // Decrement use count
    auto& desc = it->second;
    dassert_crit(desc.use_count > 0);
    desc.use_count--;
    if (desc.use_count > 0) {
        return LA_STATUS_SUCCESS;
    }

    // Entry is no longer needed

    // Remove from NPL table
    const auto& table(m_tables.ipv6_sip_compression_table);
    npl_ipv6_sip_compression_table_key_t key;
    npl_ipv6_sip_compression_table_key_t mask;

    key.ipv6_sip[0] = sip.q_addr[0];
    key.ipv6_sip[1] = sip.q_addr[1];
    mask.ipv6_sip[0] = 0xffffffffffffffff;
    mask.ipv6_sip[1] = 0xffffffffffffffff;

    la_status status = table->pop(desc.npl_table_entry->line());
    return_on_error(status);

    // Release the code
    m_index_generators.ipv6_compressed_sips.release(desc.code);

    // Remove from map
    m_ipv6_compressed_sip_map.erase(it);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::allocate_ipv6_compressed_sip(la_ipv6_addr_t sip, uint64_t& out_code)
{
    // Find in map
    auto it = m_ipv6_compressed_sip_map.find(sip.s_addr);
    if (it != m_ipv6_compressed_sip_map.end()) {
        // Increment use count and return
        auto& desc = it->second;
        desc.use_count++;
        out_code = desc.code;

        return LA_STATUS_SUCCESS;
    }

    // SIP is not in map

    // Allocate a new code
    uint64_t code;
    bool success = m_index_generators.ipv6_compressed_sips.allocate(code);
    if (!success) {
        log_err(HLD, "%s: Allocation of IPv6 SIP compression code failed", __func__);
        return LA_STATUS_ERESOURCE;
    }

    // Insert to NPL table
    const auto& table(m_tables.ipv6_sip_compression_table);
    npl_ipv6_sip_compression_table_key_t key;
    npl_ipv6_sip_compression_table_key_t mask;
    npl_ipv6_sip_compression_table_value_t value;
    npl_ipv6_sip_compression_table_entry_wptr_t entry;

    key.ipv6_sip[0] = sip.q_addr[0];
    key.ipv6_sip[1] = sip.q_addr[1];
    mask.ipv6_sip[0] = 0xffffffffffffffff;
    mask.ipv6_sip[1] = 0xffffffffffffffff;
    value.payloads.compressed_sip = code;

    size_t location = m_ipv6_compressed_sip_map.size();
    la_status status = table->insert(location, key, mask, value, entry);
    return_on_error(status);

    // Insert to map
    ipv6_compressed_sip_desc desc = {.use_count = 1, .code = code, .npl_table_entry = entry};
    m_ipv6_compressed_sip_map[sip.s_addr] = desc;

    out_code = code;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_reachable_devices(bit_vector& out_reachable_dev_bv)
{
    if (m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_ll_device->read_register(m_gb_tree->dmc->frm->frp_reachable_bitmap12_reg, out_reachable_dev_bv);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

bool
la_device_impl::is_simulated_device() const
{
    return m_ll_device->is_simulated_device();
}

la_status
la_device_impl::set_interrupt_enabled(const lld_register_scptr& reg, size_t bit_i, bool enabled)
{
    start_api_call("reg=", reg ? reg->get_name().c_str() : "nullptr", "bit_i=", bit_i, "enabled=", enabled);

    if (!reg) {
        return LA_STATUS_EINVAL;
    }

    return m_notification->get_interrupt_tree()->set_interrupt_enabled(reg, bit_i, enabled, false /* clear */);
}

la_status
la_device_impl::get_interrupt_enabled(const lld_register_scptr& reg, size_t bit_i, bool& out_enabled)
{
    start_api_getter_call();

    if (!reg) {
        return LA_STATUS_EINVAL;
    }

    return m_notification->get_interrupt_tree()->get_interrupt_enabled(reg, bit_i, out_enabled);
}

la_status
la_device_impl::set_interrupt_enabled(const lld_memory_scptr& mem, bool enabled)
{
    start_api_call("mem=", mem ? mem->get_name().c_str() : "nullptr", "enabled=", enabled);

    if (!mem) {
        return LA_STATUS_EINVAL;
    }

    return m_notification->get_interrupt_tree()->set_interrupt_enabled(mem, enabled, false /* clear */);
}

la_status
la_device_impl::get_interrupt_enabled(const lld_memory_scptr& mem, bool& out_enabled)
{
    start_api_getter_call();

    if (!mem) {
        return LA_STATUS_EINVAL;
    }

    return m_notification->get_interrupt_tree()->get_interrupt_enabled(mem, out_enabled);
}

la_status
la_device_impl::set_ecmp_hash_seed(la_uint16_t ecmp_lb_seed)
{
    start_api_call("ecmp_lb_seed=", ecmp_lb_seed);
    if (ecmp_lb_seed == m_ecmp_hash_seed) {
        return LA_STATUS_SUCCESS;
    }

    m_ecmp_hash_seed = ecmp_lb_seed;

    update_rxpp_lb();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_ecmp_hash_seed(la_uint16_t& out_ecmp_lb_seed) const
{
    start_api_getter_call();
    out_ecmp_lb_seed = m_ecmp_hash_seed;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_spa_hash_seed(la_uint16_t spa_lb_seed)
{
    start_api_call("spa_lb_seed=", spa_lb_seed);
    if (spa_lb_seed == m_spa_hash_seed) {
        return LA_STATUS_SUCCESS;
    }

    m_spa_hash_seed = spa_lb_seed;

    update_rxpp_lb();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_spa_hash_seed(la_uint16_t& out_spa_lb_seed) const
{
    start_api_getter_call();
    out_spa_lb_seed = m_spa_hash_seed;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_load_balancing_node_id(size_t load_balancing_node_id)
{
    start_api_call("load_balancing_node_id=", load_balancing_node_id);

    if (load_balancing_node_id == m_load_balancing_node_id) {
        return LA_STATUS_SUCCESS;
    }

    m_load_balancing_node_id = load_balancing_node_id;

    update_rxpp_lb();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_load_balancing_node_id(size_t& out_load_balancing_node_id) const
{
    start_api_getter_call();
    out_load_balancing_node_id = m_load_balancing_node_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_lb_hash_shift_amount(la_uint16_t& out_shift_amount) const
{
    out_shift_amount = m_load_balancing_node_id % NUMBER_OF_RXPP_LB_KEYS;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::update_rxpp_lb() const
{
    lld_register_value_list_t reg_val_list;
    gibraltar::rxpp_fwd_resolution_load_balancing_field_size_conf_register field_size_conf_val;
    gibraltar::rxpp_fwd_res_lb_key_const_config_reg_register hardwired_lb_key_const_config_val;
    la_status status;
    auto nw_slices = get_slices(shared_from_this(), la_slice_mode_e::NETWORK);

    // Place spa hash seed so that after barrel shifing in HW, the seed value will land in res_lb_key_crc_3_init_key
    la_uint16_t shift_amount;
    get_lb_hash_shift_amount(shift_amount);
    std::vector<la_uint16_t> preset_seed(6, m_ecmp_hash_seed);
    preset_seed[3] = m_spa_hash_seed;
    std::rotate(preset_seed.begin(), preset_seed.begin() + preset_seed.size() - shift_amount, preset_seed.end());

    for (auto slice : nw_slices) {
        status = m_ll_device->read_register(m_gb_tree->slice[slice]->npu->rxpp_fwd->top->res_lb_key_const_config_reg,
                                            hardwired_lb_key_const_config_val);
        return_on_error(status);

        hardwired_lb_key_const_config_val.fields.res_lb_key_crc_0_init_key = preset_seed[0];
        hardwired_lb_key_const_config_val.fields.res_lb_key_crc_1_init_key = preset_seed[1];
        hardwired_lb_key_const_config_val.fields.res_lb_key_crc_2_init_key = preset_seed[2];
        hardwired_lb_key_const_config_val.fields.res_lb_key_crc_3_init_key = preset_seed[3]; // DSPA
        hardwired_lb_key_const_config_val.fields.res_lb_key_crc_4_init_key = preset_seed[4];
        hardwired_lb_key_const_config_val.fields.res_lb_key_crc_5_init_key = preset_seed[5];
        hardwired_lb_key_const_config_val.fields.res_lb_key_hash_shift = shift_amount;
        reg_val_list.push_back(
            {m_gb_tree->slice[slice]->npu->rxpp_fwd->top->res_lb_key_const_config_reg, hardwired_lb_key_const_config_val});

        status = m_ll_device->read_register(m_gb_tree->slice[slice]->npu->rxpp_fwd->top->resolution_load_balancing_field_size_conf,
                                            field_size_conf_val);
        return_on_error(status);

        field_size_conf_val.fields.field_size_is_16b = 1;
        // lb_key_crc_3_init_key is used for spa hashing.
        field_size_conf_val.fields.lb_key_crc_0_init_key = m_ecmp_hash_seed;
        field_size_conf_val.fields.lb_key_crc_1_init_key = m_ecmp_hash_seed;
        field_size_conf_val.fields.lb_key_crc_2_init_key = m_ecmp_hash_seed;
        field_size_conf_val.fields.lb_key_crc_3_init_key = m_spa_hash_seed;
        field_size_conf_val.fields.lb_key_crc_4_init_key = m_ecmp_hash_seed;
        field_size_conf_val.fields.lb_key_crc_5_init_key = m_ecmp_hash_seed;
        reg_val_list.push_back(
            {m_gb_tree->slice[slice]->npu->rxpp_fwd->top->resolution_load_balancing_field_size_conf, field_size_conf_val});
    }
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_forwarding_load_balance_stage(const la_object* forwarding_object,
                                                  const la_lb_pak_fields_vec& lb_vec,
                                                  size_t& out_member_id,
                                                  const la_object*& out_resolved_object) const
{
    start_api_getter_call();

    if (forwarding_object == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_object::object_type_e type = forwarding_object->type();
    switch (type) {
    case la_object::object_type_e::ECMP_GROUP: {
        const la_ecmp_group_impl* group = static_cast<const la_ecmp_group_impl*>(forwarding_object);
        return group->get_lb_resolution(lb_vec, out_member_id, out_resolved_object);
    }
    case la_object::object_type_e::NEXT_HOP: {
        const la_next_hop_base* hop = static_cast<const la_next_hop_base*>(forwarding_object);
        return hop->get_lb_resolution(lb_vec, out_member_id, out_resolved_object);
    }
    case la_object::object_type_e::SPA_PORT: {
        const la_spa_port_base* port = static_cast<const la_spa_port_base*>(forwarding_object);
        return port->get_lb_resolution(lb_vec, out_member_id, out_resolved_object);
    }
    case la_object::object_type_e::TE_TUNNEL: {
        const la_te_tunnel_impl* dest = static_cast<const la_te_tunnel_impl*>(forwarding_object);
        return dest->get_lb_resolution(lb_vec, out_member_id, out_resolved_object);
    }
    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    return LA_STATUS_EINVAL;
}

la_status
la_device_impl::get_forwarding_load_balance_chain(const la_object* forwarding_object,
                                                  const la_lb_pak_fields_vec& lb_vec,
                                                  std::vector<const la_object*>& out_resolution_chain) const
{
    start_api_getter_call();
    la_status status = LA_STATUS_SUCCESS;
    std::vector<const la_object*> lb_chain;
    const la_object* current_object = forwarding_object;
    const la_object* next_object = nullptr;
    uint8_t elems = 0;

    while (true) {
        size_t member = 0;
        status = get_forwarding_load_balance_stage(current_object, lb_vec, member, next_object);
        if ((status == LA_STATUS_SUCCESS) && next_object) {
            lb_chain.push_back(next_object);
            current_object = next_object;
            next_object = nullptr;
            elems++;
        } else {
            break;
        }
    }
    out_resolution_chain = lb_chain;
    if (elems && status == LA_STATUS_ENOTIMPLEMENTED) {
        return LA_STATUS_SUCCESS;
    }
    return status;
}

bool
la_device_impl::is_network_slice(la_slice_id_t slice) const
{
    return (m_slice_mode[slice] == la_slice_mode_e::NETWORK || m_slice_mode[slice] == la_slice_mode_e::UDC);
}

la_status
la_device_impl::do_read_persistent_token(la_user_data_t& out_token) const
{
    la_status status;

    status = m_ll_device->read_memory(
        *m_gb_tree->sbif->css_mem_even, CSS_MEMORY_PERSISTENT_TOKEN_BASE, sizeof(out_token) >> 2, sizeof(out_token), &out_token);

    return_on_error(status, HLD, ERROR, "Failed reading persistent token!");

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::read_persistent_token(la_user_data_t& out_token) const
{
    start_api_getter_call();

    la_status status;

    status = do_read_persistent_token(out_token);

    return status;
}

la_status
la_device_impl::do_write_persistent_token(la_user_data_t token)
{
    la_status status;

    uint32_t* in_token = (uint32_t*)&token;

    status = m_ll_device->write_memory(
        *m_gb_tree->sbif->css_mem_even, CSS_MEMORY_PERSISTENT_TOKEN_BASE, sizeof(token) >> 2, sizeof(token), in_token);

    return_on_error(status, HLD, ERROR, "Failed writing persistent token!");

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::write_persistent_token(la_user_data_t token)
{
    start_api_call("token=", token);
    la_status status;

    status = do_write_persistent_token(token);

    return status;
}

la_status
la_device_impl::get_lowest_mtu_sibling_port_of_this_slice(const la_system_port* sys_port, const la_system_port*& sibling_port) const
{
    la_mtu_t lowest_mtu = LA_MTU_MAX;
    la_system_port_base_wcptr sys_port_impl = get_sptr<const la_system_port_base>(sys_port);
    sibling_port = nullptr;
    for (const auto& system_port : m_system_ports) {
        if (system_port == nullptr) {
            continue;
        }
        if ((sys_port_impl != system_port) && (system_port->get_slice() == sys_port_impl->get_slice())
            && (system_port->get_mtu() < lowest_mtu)) {
            lowest_mtu = system_port->get_mtu();
            sibling_port = system_port.get();
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_resolution_set_next_macro_table()
{
    la_status status;

    npl_resolution_set_next_macro_table_t::key_type k{};
    npl_resolution_set_next_macro_table_t::value_type v{};
    npl_resolution_set_next_macro_table_t::entry_pointer_type e = nullptr;

    v.payloads.resolution_set_next_macro.pl_inc = NPL_PL_INC_NONE;
    v.payloads.resolution_set_next_macro.macro_id = NPL_FORWARDING_DONE;
    v.payloads.resolution_set_next_macro.next_is_fwd_done = 1;
    k.is_inject_up.val = NPL_FALSE_VALUE;
    for (uint64_t ix = 0; ix < 2; ix++) {
        k.is_pfc_enable = ix;
        status = m_tables.resolution_set_next_macro_table->set(k, v, e);
        return_on_error(status);
    }

    k.is_inject_up.val = NPL_TRUE_VALUE;
    v.payloads.resolution_set_next_macro.macro_id = NPL_RX_INJECT_POST_PROCESS_MACRO;
    v.payloads.resolution_set_next_macro.next_is_fwd_done = 0;
    for (uint64_t ix = 0; ix < 2; ix++) {
        k.is_pfc_enable = ix;
        status = m_tables.resolution_set_next_macro_table->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_pfc_device_tuning_enabled()
{
    // Apply system tuning configuration for PFC. Values recommended by ASIC team
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;
    la_status status;

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    // Tuning should only apply on LC and FE currently
    if (m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    // Bool is used to indicate to other initialization that PFC parameters should be used (i.e. fabric init)
    m_pfc_tuning_enabled = true;

    // Per-slice register configuration for all devices
    for (la_slice_id_t slice : get_used_slices()) {
        if (is_network_slice(slice)) {
            continue;
        }

        // Set OQG profile thresholds for fabric slices to max.
        gibraltar::txcgm_uc_oqg_profile_memory uc_oqg_profile;
        uc_oqg_profile.fields.flow_control_buffers_th = bit_utils::ones(uc_oqg_profile.fields.FLOW_CONTROL_BUFFERS_TH_WIDTH);
        uc_oqg_profile.fields.flow_control_pds_th = bit_utils::ones(uc_oqg_profile.fields.FLOW_CONTROL_PDS_TH_WIDTH);
        uc_oqg_profile.fields.flow_control_bytes_th = bit_utils::ones(uc_oqg_profile.fields.FLOW_CONTROL_BYTES_TH_WIDTH);
        uc_oqg_profile.fields.drop_pds_th = bit_utils::ones(uc_oqg_profile.fields.DROP_PDS_TH_WIDTH);
        uc_oqg_profile.fields.drop_bytes_th = bit_utils::ones(uc_oqg_profile.fields.DROP_BYTES_TH_WIDTH);
        uc_oqg_profile.fields.drop_buffers_th = bit_utils::ones(uc_oqg_profile.fields.DROP_BUFFERS_TH_WIDTH);
        uc_oqg_profile.fields.fcn_bytes_th = bit_utils::ones(uc_oqg_profile.fields.FCN_BYTES_TH_WIDTH);

        if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
            // Derived from previous initial value
            uc_oqg_profile.fields.fcn_buffers_th = 341;
            uc_oqg_profile.fields.fcn_pds_th = 341;
        } else {
            uc_oqg_profile.fields.fcn_buffers_th = bit_utils::ones(uc_oqg_profile.fields.FCN_BUFFERS_TH_WIDTH);
            uc_oqg_profile.fields.fcn_pds_th = bit_utils::ones(uc_oqg_profile.fields.FCN_PDS_TH_WIDTH);
        }

        mem_val_list.push_back({m_gb_tree->slice[slice]->tx->cgm->uc_oqg_profile, uc_oqg_profile});

        // Set OQ profile thresholds for fabric slices to max
        gibraltar::txcgm_uc_oq_profile_memory uc_oq_profile;
        uc_oq_profile.fields.flow_control_bytes_th = bit_utils::ones(uc_oq_profile.fields.FLOW_CONTROL_BYTES_TH_WIDTH);
        uc_oq_profile.fields.flow_control_buffers_th = bit_utils::ones(uc_oq_profile.fields.FLOW_CONTROL_BUFFERS_TH_WIDTH);
        uc_oq_profile.fields.flow_control_pds_th = bit_utils::ones(uc_oq_profile.fields.FLOW_CONTROL_PDS_TH_WIDTH);
        uc_oq_profile.fields.fcn_bytes_th = bit_utils::ones(uc_oq_profile.fields.FCN_BYTES_TH_WIDTH);
        uc_oq_profile.fields.drop_bytes_th = bit_utils::ones(uc_oq_profile.fields.DROP_BYTES_TH_WIDTH);
        uc_oq_profile.fields.drop_buffers_th = bit_utils::ones(uc_oq_profile.fields.DROP_BUFFERS_TH_WIDTH);
        uc_oq_profile.fields.drop_pds_th = bit_utils::ones(uc_oq_profile.fields.DROP_PDS_TH_WIDTH);

        if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
            // Derived from previous initial value
            uc_oq_profile.fields.fcn_buffers_th = 341;
            uc_oq_profile.fields.fcn_pds_th = 341;
            uc_oq_profile.fields.pd_counter_type = 0;
        } else {
            uc_oq_profile.fields.fcn_buffers_th = bit_utils::ones(uc_oq_profile.fields.FCN_BUFFERS_TH_WIDTH);
            uc_oq_profile.fields.fcn_pds_th = bit_utils::ones(uc_oq_profile.fields.FCN_PDS_TH_WIDTH);
            uc_oq_profile.fields.pd_counter_type = 2;
        }

        mem_val_list.push_back({m_gb_tree->slice[slice]->tx->cgm->uc_oq_profile, uc_oq_profile});
    }

    // For non-FE devices only
    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        // Set PDVOQ UC CGM thresholds to 64k
        gibraltar::pdvoq_shared_mma_cgm_thresholds_register cgm_thresholds;
        la_status status = m_ll_device->read_register(m_gb_tree->pdvoq_shared_mma->cgm_thresholds, cgm_thresholds);
        return_on_error(status);

        cgm_thresholds.fields.uc_th = 64 * UNITS_IN_KIBI;
        cgm_thresholds.fields.ms_uc_th = 64 * UNITS_IN_KIBI;

        reg_val_list.push_back({m_gb_tree->pdvoq_shared_mma->cgm_thresholds, cgm_thresholds});

        // Set total MS PDs VOQ/OQ drop thresholds to max
        gibraltar::txcgm_top_total_ms_pd_th_register total_ms_pd_th;
        status = m_ll_device->read_register(m_gb_tree->tx_cgm_top->total_ms_pd_th, total_ms_pd_th);
        return_on_error(status);

        total_ms_pd_th.fields.total_ms_voq_ms_oq_pds_drop_th
            = bit_utils::ones(total_ms_pd_th.fields.TOTAL_MS_VOQ_MS_OQ_PDS_DROP_TH_WIDTH);

        reg_val_list.push_back({m_gb_tree->tx_cgm_top->total_ms_pd_th, total_ms_pd_th});

        // Disable DRAM meter
        gibraltar::ics_top_dram_write_meter_register dram_write_meter_reg;
        status = m_ll_device->read_register(m_gb_tree->ics_top->dram_write_meter, dram_write_meter_reg);
        return_on_error(status);

        dram_write_meter_reg.fields.dram_write_meter_inc_value = 0xFFFF;

        reg_val_list.push_back({m_gb_tree->ics_top->dram_write_meter, dram_write_meter_reg});

        // Set device FC threshold
        gibraltar::txcgm_top_total_sch_uc_buffers_th_register total_sch_uc_buffers_th;
        status = m_ll_device->read_register(m_gb_tree->tx_cgm_top->total_sch_uc_buffers_th, total_sch_uc_buffers_th);
        return_on_error(status);

        total_sch_uc_buffers_th.fields.total_sch_uc_buffers_fc_th = 84600;
        total_sch_uc_buffers_th.fields.total_sch_uc_buffers_drop_th
            = bit_utils::ones(total_sch_uc_buffers_th.fields.TOTAL_SCH_UC_BUFFERS_DROP_TH_WIDTH);
        total_sch_uc_buffers_th.fields.remote_sch_uc_buffers_drop_th
            = bit_utils::ones(total_sch_uc_buffers_th.fields.REMOTE_SCH_UC_BUFFERS_DROP_TH_WIDTH);

        gibraltar::txcgm_top_total_sch_uc_pd_th_register total_sch_uc_pd_th;
        status = m_ll_device->read_register(m_gb_tree->tx_cgm_top->total_sch_uc_pd_th, total_sch_uc_pd_th);
        return_on_error(status);

        total_sch_uc_pd_th.fields.total_sch_uc_pds_fc_th = bit_utils::ones(total_sch_uc_pd_th.fields.TOTAL_SCH_UC_PDS_FC_TH_WIDTH);
        total_sch_uc_pd_th.fields.total_sch_uc_pds_drop_th
            = bit_utils::ones(total_sch_uc_pd_th.fields.TOTAL_SCH_UC_PDS_DROP_TH_WIDTH);

        reg_val_list.push_back({m_gb_tree->tx_cgm_top->total_sch_uc_buffers_th, total_sch_uc_buffers_th});
        reg_val_list.push_back({m_gb_tree->tx_cgm_top->total_sch_uc_pd_th, total_sch_uc_pd_th});

        // Per-slice registers
        for (la_slice_id_t slice : get_used_slices()) {
            if (is_network_slice(slice)) {
                // Set IFG credit generator rate on network slices
                for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
                    gibraltar::sch_ifse_general_configuration_register ifse_general_cfg_reg;

                    la_status status = m_ll_device->read_register(
                        m_gb_tree->slice[slice]->ifg[ifg]->sch->ifse_general_configuration, ifse_general_cfg_reg);
                    return_on_error(status);

                    // Set total IFG BW to 900G (800G NW + 100G extra)
                    // (Credit size * 8 * Freq / Rate) * 16 -> 306
                    ifse_general_cfg_reg.fields.ifg_credit_generator_rate = 306;

                    reg_val_list.push_back(
                        {m_gb_tree->slice[slice]->ifg[ifg]->sch->ifse_general_configuration, ifse_general_cfg_reg});
                }

                // Set ICS credit return
                gibraltar::ics_slice_credits_conf_reg_register credits_reg;
                status = m_ll_device->read_register(m_gb_tree->slice[slice]->ics->credits_conf_reg, credits_reg);
                return_on_error(status);

                int credit_in_bytes;
                status = get_int_property(la_device_property_e::CREDIT_SIZE_IN_BYTES, credit_in_bytes);
                return_on_error(status);

                credits_reg.fields.return_credits_th = credit_in_bytes - 1;

                reg_val_list.push_back({m_gb_tree->slice[slice]->ics->credits_conf_reg, credits_reg});

                // Set dram eligible threshold
                gibraltar::ics_slice_dram_list_param_reg_register ics_dram_list;
                status = m_ll_device->read_register(m_gb_tree->slice[slice]->ics->dram_list_param_reg, ics_dram_list);
                return_on_error(status);

                ics_dram_list.fields.dram_eligible_th_empty = 1024;

                reg_val_list.push_back({m_gb_tree->slice[slice]->ics->dram_list_param_reg, ics_dram_list});

                // Set pre-packet credit balance threshold to 0
                gibraltar::ics_slice_read_pipe_param_reg_register read_pipe_param_reg;
                status = m_ll_device->read_register(m_gb_tree->slice[slice]->ics->read_pipe_param_reg, read_pipe_param_reg);
                return_on_error(status);

                read_pipe_param_reg.fields.pre_pkt_cb_th = 0;

                reg_val_list.push_back({m_gb_tree->slice[slice]->ics->read_pipe_param_reg, read_pipe_param_reg});
            }
        }
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_sw_fc_pause_threshold(la_traffic_class_t tc, std::chrono::microseconds latency)
{
    start_api_call("tc=", tc, "latency=", latency);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::get_sw_fc_pause_threshold(la_traffic_class_t tc, std::chrono::microseconds& out_latency) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::set_sw_pfc_destination(la_system_port_gid_t gid, la_npu_host_destination* npu_dest)
{
    start_api_call("gid=", gid, "npu_dest=", npu_dest);

    npl_pfc_destination_table_t::key_type k;
    npl_pfc_destination_table_t::value_type v;
    npl_pfc_destination_table_t::entry_pointer_type e = nullptr;

    k.ssp1 = gid;
    k.ssp2 = gid;
    k.redirect1 = NPL_REDIRECT_CODE_PFC_MEASUREMENT;
    k.redirect2 = NPL_REDIRECT_CODE_PFC_MEASUREMENT;
    auto dest = get_destination_id(npu_dest, RESOLUTION_STEP_FIRST);
    v.payloads.pfc_em_lookup_result.destination = dest.val;

    return (m_tables.pfc_destination_table->set(k, v, e));
}

la_status
la_device_impl::set_pfc_watchdog_filter(la_system_port_gid_t gid, la_traffic_class_t tc, uint32_t slice, bool enable)
{
    const auto& table(m_tables.pfc_filter_wd_table[slice]);
    npl_pfc_filter_wd_table_t::key_type k;
    npl_pfc_filter_wd_table_t::key_type m;
    npl_pfc_filter_wd_table_t::value_type v;
    npl_pfc_filter_wd_table_t::entry_pointer_type e = nullptr;
    bool found = false;
    size_t location = 0;

    k.tc = tc;
    m.tc = bit_utils::get_lsb_mask(3);

    k.dsp = gid;
    m.dsp = bit_utils::get_lsb_mask(12);

    v.payloads.pfc_filter_wd_action.destination = RX_NOT_CNT_DROP_DSP.val;

    la_status status = table->find(k, m, e, location);
    if (status == LA_STATUS_SUCCESS) {
        found = true;
    }

    if (enable) {
        if (found) {
            return LA_STATUS_SUCCESS;
        }

        location = 0;
        status = table->locate_first_free_entry(location);
        return_on_error(status);
        status = table->insert(location, k, m, v, e);
        return status;
    } else {
        if (found) {
            status = table->erase(location);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_sw_pfc_congestion_state(la_system_port_gid_t gid, la_traffic_class_t tc)
{
    start_api_call("gid=", gid, "tc=", tc);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::attach_synce_output(synce_clock_sel_e prim_sec_clock,
                                    la_slice_id_t slice_id,
                                    la_ifg_id_t ifg_id,
                                    la_uint_t serdes_id,
                                    uint32_t divider,
                                    uint32_t& out_synce_pin)
{
    uint32_t sid;
    uint32_t ifg;
    la_status status;

    out_synce_pin = (m_slice_id_manager->slice_ifg_2_global_ifg(slice_id, ifg_id)) / NUM_IFGS_PER_SYNCE_GROUP;

    uint32_t start_ifg = out_synce_pin * NUM_IFGS_PER_SYNCE_GROUP;

    for (int ii = 0; ii < NUM_IFGS_PER_SYNCE_GROUP; ii++) {
        auto s_ifg = m_slice_id_manager->global_ifg_2_slice_ifg(start_ifg + ii);
        sid = s_ifg.slice;
        ifg = s_ifg.ifg;
        log_debug(HLD,
                  "Attaching %s recover clock %d/%d/%d to IFG %d/%d.\n",
                  silicon_one::to_string(prim_sec_clock).c_str(),
                  slice_id,
                  ifg_id,
                  serdes_id,
                  sid,
                  ifg);
        status = m_ifg_handlers[sid][ifg]->attach_synce_output(prim_sec_clock, slice_id, ifg_id, serdes_id, divider);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_synce_output(synce_clock_sel_e prim_sec_clock,
                                 uint32_t synce_pin,
                                 la_slice_id_t& out_slice_id,
                                 la_ifg_id_t& out_ifg_id,
                                 la_uint_t& out_serdes_id,
                                 uint32_t& out_divider) const
{
    if (synce_pin >= SYNCE_REF_CLOCK_MAX_PIN) {
        return LA_STATUS_EINVAL;
    }

    uint32_t start_ifg = synce_pin * NUM_IFGS_PER_SYNCE_GROUP;

    auto s_ifg = m_slice_id_manager->global_ifg_2_slice_ifg(start_ifg);
    la_status status = m_ifg_handlers[s_ifg.slice][s_ifg.ifg]->get_synce_output(
        prim_sec_clock, synce_pin, out_slice_id, out_ifg_id, out_serdes_id, out_divider);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::detach_synce_output(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin)
{
    uint32_t sid;
    uint32_t ifg_id;
    la_status status;

    if (synce_pin >= SYNCE_REF_CLOCK_MAX_PIN) {
        return LA_STATUS_EINVAL;
    }

    uint32_t start_ifg = synce_pin * NUM_IFGS_PER_SYNCE_GROUP;

    for (int ii = 0; ii < NUM_IFGS_PER_SYNCE_GROUP; ii++) {
        auto s_ifg = m_slice_id_manager->global_ifg_2_slice_ifg(start_ifg + ii);
        sid = s_ifg.slice;
        ifg_id = s_ifg.ifg;
        log_debug(HLD,
                  "Detaching %s recover clock to pin %d - %d/%d.\n",
                  silicon_one::to_string(prim_sec_clock).c_str(),
                  synce_pin,
                  sid,
                  ifg_id);
        status = m_ifg_handlers[sid][ifg_id]->detach_synce_output(prim_sec_clock, synce_pin);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_synce_squelch_lock(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin)
{
    uint32_t sid;
    uint32_t ifg;
    la_status status;

    if (synce_pin >= SYNCE_REF_CLOCK_MAX_PIN) {
        return LA_STATUS_EINVAL;
    }

    uint32_t start_ifg = synce_pin * NUM_IFGS_PER_SYNCE_GROUP;

    for (int ii = 0; ii < NUM_IFGS_PER_SYNCE_GROUP; ii++) {
        auto s_ifg = m_slice_id_manager->global_ifg_2_slice_ifg(start_ifg + ii);
        sid = s_ifg.slice;
        ifg = s_ifg.ifg;
        log_debug(HLD,
                  "Clear %s unlock recover clock status to pin %d - %d/%d.\n",
                  silicon_one::to_string(prim_sec_clock).c_str(),
                  synce_pin,
                  sid,
                  ifg);
        status = m_ifg_handlers[sid][ifg]->clear_synce_squelch_lock(prim_sec_clock);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_synce_auto_squelch(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin, bool squelch_enable)
{
    uint32_t sid;
    uint32_t ifg;
    la_status status;

    if (synce_pin >= SYNCE_REF_CLOCK_MAX_PIN) {
        return LA_STATUS_EINVAL;
    }

    uint32_t start_ifg = synce_pin * NUM_IFGS_PER_SYNCE_GROUP;

    for (int ii = 0; ii < NUM_IFGS_PER_SYNCE_GROUP; ii++) {
        auto s_ifg = m_slice_id_manager->global_ifg_2_slice_ifg(start_ifg + ii);
        sid = s_ifg.slice;
        ifg = s_ifg.ifg;
        log_debug(HLD,
                  "%s %s SyncE auto squelch to pin %d - %d/%d.\n",
                  squelch_enable ? "Enable" : "Disable",
                  silicon_one::to_string(prim_sec_clock).c_str(),
                  synce_pin,
                  sid,
                  ifg);
        status = m_ifg_handlers[sid][ifg]->set_synce_auto_squelch(prim_sec_clock, squelch_enable);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_synce_auto_squelch(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin, bool& out_squelch_enable) const
{
    if (synce_pin >= SYNCE_REF_CLOCK_MAX_PIN) {
        return LA_STATUS_EINVAL;
    }

    uint32_t start_ifg = synce_pin * NUM_IFGS_PER_SYNCE_GROUP;

    auto s_ifg = m_slice_id_manager->global_ifg_2_slice_ifg(start_ifg);
    la_status status = m_ifg_handlers[s_ifg.slice][s_ifg.ifg]->get_synce_auto_squelch(prim_sec_clock, out_squelch_enable);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_cdb_core_lpm_index(lld_register_scptr lpm_shared_sram_interrupt_reg, size_t& out_lpm_index) const
{
    // Figure out the 'lpm_index' by looking for a matching address among these interrupt registers:
    //   cdb.core[].lpm_shared_sram_{1,2}_err_int_reg[lpm_index]
    //
    // Register addresses are identical in all cores, hence the hard-coded core[0].
    la_entry_addr_t addr = lpm_shared_sram_interrupt_reg->get_desc()->addr;

    const lld_register_array_container& ecc_1b = *m_gb_tree->cdb->core[0]->lpm_shared_sram_1b_err_int_reg;
    const lld_register_array_container& ecc_2b = *m_gb_tree->cdb->core[0]->lpm_shared_sram_2b_err_int_reg;

    for (size_t i = 0; i < ecc_1b.size(); ++i) {
        if (addr == ecc_1b[i]->get_desc()->addr || addr == ecc_2b[i]->get_desc()->addr) {
            out_lpm_index = i;
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
la_device_impl::lpm_sram_mem_protect_handler(const lld_block& cdb_core, lpm_sram_mem_protect info)
{
    log_debug(HLD,
              "%s: %s, lpm=%d, mem_error=%s",
              __func__,
              cdb_core.get_name().c_str(),
              info.lpm_index,
              silicon_one::to_string(info.error).c_str());

    // TODO: re-write LPM SRAM content

    return LA_STATUS_SUCCESS;
}

static void
populate_error_handling_table_key(npl_rx_term_error_handling_counter_table_key_t& key, la_uint_t pif, bool is_ser)
{
    key.ser = is_ser ? 1 : 0;
    key.pd_source_if_pif = pif;
}

static void
populate_error_handling_table_key(npl_rx_fwd_error_handling_counter_table_key_t& key, la_uint_t pif, bool is_ser)
{
    key.ser = is_ser ? 1 : 0;
    key.pd_source_if_pif = pif;
}

static void
populate_error_handling_table_key(npl_tx_error_handling_counter_table_key_t& key, la_uint_t pif, bool is_ser)
{
    key.ser = is_ser ? 1 : 0;
    key.dest_pif = pif;
}

template <class _TableType>
la_status
la_device_impl::init_single_internal_error_counter(std::shared_ptr<_TableType> (&table)[ASIC_MAX_SLICES_PER_DEVICE_NUM],
                                                   internal_error_type_e type,
                                                   internal_error_stage_e stage)
{
    // Create counter object
    auto counter = std::make_shared<la_counter_set_impl>(shared_from_this());
    la_object_id_t oid;
    auto status = register_object(counter, oid);
    return_on_error(status);
    // Counter set size == number of PIFs in IFG
    status = counter->initialize(oid, tm_utils::TM_IFG_SYSTEM_PORT_SCHEDULERS);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // Allocate physical counter
    counter_direction_e direction
        = (stage == internal_error_stage_e::TRANSMIT) ? COUNTER_DIRECTION_EGRESS : COUNTER_DIRECTION_INGRESS;
    status = counter->add_internal_error_counter(direction);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // Mark as internal - prevent removal by user
    m_is_builtin_objects[counter->oid()] = true;

    // Add to internal-error counters map
    internal_error_counter_map_key_t map_key = std::make_tuple(stage, type);
    m_internal_error_counters[map_key] = counter;

    // Per-slice table
    for (la_slice_id_t slice : get_used_slices()) {
        for (size_t pif = 0; pif < counter->get_set_size(); pif++) {
            typename _TableType::key_type key;
            typename _TableType::value_type value;
            typename _TableType::entry_pointer_type entry = nullptr;

            populate_error_handling_table_key(key, pif, (type == internal_error_type_e::SER));

            value.payloads.update_result.counter = populate_counter_ptr_slice_with_offset(counter, slice, direction, pif);
            status = table[slice]->insert(key, value, entry);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: insert failed table=%s slice=%u pif=%lu", __func__, table[slice]->get_name().c_str(), slice, pif);
                deregister_object(oid);
                return status;
            }
        }
    }
    return status;
}

la_status
la_device_impl::init_internal_error_counters()
{
    for (auto type : {internal_error_type_e::SER, internal_error_type_e::OTHER}) {
        // Termination
        la_status status = init_single_internal_error_counter(
            m_tables.rx_term_error_handling_counter_table, type, internal_error_stage_e::TERMINATION);
        return_on_error(status);
        // Forwarding
        status = init_single_internal_error_counter(
            m_tables.rx_fwd_error_handling_counter_table, type, internal_error_stage_e::FORWARDING);
        return_on_error(status);
        // Transmit
        status
            = init_single_internal_error_counter(m_tables.tx_error_handling_counter_table, type, internal_error_stage_e::TRANSMIT);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_internal_error_handling()
{
    la_status status = LA_STATUS_SUCCESS;

    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        // Internal error counters cannot be allocated at device creation in FE
        // because memories might not be writable during rpfo/reconnect
        status = init_internal_error_counters();
    }

    return status;
}

la_status
la_device_impl::get_internal_error_counter(internal_error_stage_e stage,
                                           internal_error_type_e type,
                                           la_counter_set*& out_counter) const
{
    start_api_getter_call();
    auto it = m_internal_error_counters.find(std::make_tuple(stage, type));
    if (it == m_internal_error_counters.end()) {
        return LA_STATUS_EUNKNOWN;
    }

    out_counter = (it->second).get();

    return LA_STATUS_SUCCESS;
}

npl_tunnel_type_e
la_device_impl::ip_tunnel_type_to_npl_type(la_ip_tunnel_type_e type) const
{
    switch (type) {
    case la_ip_tunnel_type_e::IP_IN_IP:
        return npl_tunnel_type_e::NPL_IP_TUNNEL_IP_IN_IP;
    case la_ip_tunnel_type_e::GRE:
        return npl_tunnel_type_e::NPL_IP_TUNNEL_GRE;
    case la_ip_tunnel_type_e::VXLAN:
        return npl_tunnel_type_e::NPL_IP_TUNNEL_VXLAN;
    case la_ip_tunnel_type_e::GUE:
        return npl_tunnel_type_e::NPL_IP_TUNNEL_GUE;
    case la_ip_tunnel_type_e::NVGRE:
        return npl_tunnel_type_e::NPL_IP_TUNNEL_NVGRE;
    default:
        return npl_tunnel_type_e::NPL_IP_TUNNEL_NONE;
    }
}

la_status
la_device_impl::set_decap_ttl_decrement_enabled(la_ip_tunnel_type_e type, bool enabled)
{
    start_api_call("type=", type, "enabled=", enabled);

    set_decap_ttl_decrement_enabled_in_l3_termination_classify_ip_tunnels_table(type, enabled);

    if (m_ttl_decrement_enabled[(int)type] == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_ttl_decrement_enabled[(int)type] = enabled;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_decap_ttl_decrement_enabled_in_l3_termination_classify_ip_tunnels_table(la_ip_tunnel_type_e type, bool enabled)
{
    npl_tunnel_type_e npl_tunnel_type = ip_tunnel_type_to_npl_type(type);
    // Scan table entries to find table value matching the 'la_ip_tunnel_type_e type', then modify ttl_decrement bit :
    npl_l3_termination_classify_ip_tunnels_table_key_value_t table_key_value;
    for (unsigned int i = 0;
         i < sizeof(m_l3_termination_classify_ip_tunnels_table) / sizeof(m_l3_termination_classify_ip_tunnels_table[0]);
         i = i + 1) // init loop
    {
        table_key_value = m_l3_termination_classify_ip_tunnels_table[i]; // npl_l3_termination_classify_ip_tunnels_table_key_value_t
                                                                         // key_mask_value // la_device_impl.h array element
        if (table_key_value.value.payloads.tunnel_type.tunnel_type
            == npl_tunnel_type) // found entry with the lookup type in the value
        {
            if (table_key_value.value.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.force_pipe_ttl == enabled) // Differ
            {
                table_key_value.value.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.force_pipe_ttl = !enabled;
                m_l3_termination_classify_ip_tunnels_table[i]
                    .value.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_info.force_pipe_ttl
                    = !enabled;

                table_key_value.value.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_null.force_pipe_ttl = !enabled;
                m_l3_termination_classify_ip_tunnels_table[i]
                    .value.payloads.tunnel_type.force_pipe_ttl_ingress_ptp_null.force_pipe_ttl
                    = !enabled;

                set_l3_termination_classify_ip_tunnels_table(
                    i,                // entry linein table
                    table_key_value); // As key is not changed, we modify same entry in the TCAM
            }
        }
    }                         // for
    return LA_STATUS_SUCCESS; // LA_STATUS_ENOTFOUND; Sucess when init and no entries yet
}

la_status
la_device_impl::set_l3_termination_classify_ip_tunnels_table(
    unsigned int entry_line,
    npl_l3_termination_classify_ip_tunnels_table_key_value_t key_mask_value // la_device_impl.h array element
    )
{
    start_api_call("key=", key_mask_value.key, "value=", key_mask_value.value);

    npl_l3_termination_classify_ip_tunnels_table_t::key_type k;
    npl_l3_termination_classify_ip_tunnels_table_t::key_type m;
    npl_l3_termination_classify_ip_tunnels_table_t::value_type v;
    npl_l3_termination_classify_ip_tunnels_table_t::entry_pointer_type entry_ptr = nullptr;

    k = key_mask_value.key;
    m = key_mask_value.mask;

    v.payloads = key_mask_value.value.payloads;

    v.action = NPL_L3_TERMINATION_CLASSIFY_IP_TUNNELS_TABLE_ACTION_WRITE;

    transaction txn;
    for (la_slice_id_t sid : get_used_slices()) {
        const auto& table(m_tables.l3_termination_classify_ip_tunnels_table[sid]);
        txn.on_fail([&]() {
            // v.payloads.force_pipe_ttl = m_ttl_decrement_enabled[(int)type];
            // table->set((size_t)type, k, m, v, entry_ptr);
        });
        txn.status = table->set((size_t)entry_line, k, m, v, entry_ptr); // {(size_t aka long unsigned int}
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_decap_ttl_decrement_enabled(la_ip_tunnel_type_e type, bool& out_enabled) const
{
    start_api_getter_call("type=", type);

    out_enabled = m_ttl_decrement_enabled[(int)type];
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_vrf_port_common(const la_l3_port_wptr& parent, std::shared_ptr<la_vrf_port_common_base>& out_vrf_port_common)
{
    out_vrf_port_common = std::make_shared<la_vrf_port_common_gibraltar>(shared_from_this(), parent);
    return LA_STATUS_SUCCESS;
}

// TODO There needs to be a HW read API for all the NPL tables. Until that is
// implemented this code is taken from mc_fe_links_bmp_sram_base.cpp. All the
// hardcoded values are taken from there.
la_status
la_device_impl::read_mc_fe_links_bmp_sram(size_t multicast_gid, bit_vector& out_links_bmp)
{
    // the address is bits 14:1
    uint64_t address = bit_utils::get_bits(multicast_gid, 16 - 2, 1);
    // the shared database number is the LSBit
    uint64_t shared_db_num = bit_utils::get_bit(multicast_gid, 0);
    // shared_db_verifier_mem_num = 2 * MCID[15]
    uint64_t shared_db_verifier_mem_num = 2 * bit_utils::get_bit(multicast_gid, 16 - 1);

    // The MC FE bitmap is spread across 2 memories.
    lld_memory_scptr first_mem = (*m_gb_tree->rx_pdr_mc_db[shared_db_num]->shared_db_verifier)[shared_db_verifier_mem_num];
    lld_memory_scptr second_mem = (*m_gb_tree->rx_pdr_mc_db[shared_db_num]->shared_db_verifier)[shared_db_verifier_mem_num + 1];

    // The entries contain 91 usable bits plus 8 ECC bits
    // see mc_fe_links_bmp_sram_base.cpp for constants
    bit_vector entry1(0, 91 + 8);
    bit_vector entry2(0, 91 + 8);

    la_status status = m_ll_device->read_memory(first_mem, address, entry1);
    return_on_error(status);

    status = m_ll_device->read_memory(second_mem, address, entry2);
    return_on_error(status);

    // save the results from both entries into a single bitvector
    // see mc_fe_links_bmp_sram_base.cpp for constants
    out_links_bmp.set_bits(90, 0, entry1.bits(90, 0));
    out_links_bmp.set_bits(108, 91, entry2.bits(17, 0));

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::restore_fe_smcid_to_mcid_mapping()
{
    transaction txn;

    // return if not fabric element
    if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_SUCCESS;
    }

    // return if scale mode is not used
    int mc_mcid_scale_threshold;
    get_int_property(la_device_property_e::MULTICAST_MCID_SCALE_THRESHOLD, mc_mcid_scale_threshold);
    if (mc_mcid_scale_threshold == MAX_MC_LOCAL_MCID) {
        // multicast scale mode is not enabled
        return LA_STATUS_SUCCESS;
    }

    // read the SMCID to MCID mapping table from hardware for all SMCIDs
    for (la_multicast_group_gid_t smcid = mc_mcid_scale_threshold; smcid < MAX_MC_GROUP_GID;
         smcid += NPL_MULTICAST_NUM_MCIDS_PER_ENTRY) {
        npl_fe_smcid_to_mcid_table_t::key_type key;
        npl_fe_smcid_to_mcid_table_t::value_type value;
        npl_fe_smcid_to_mcid_table_t::entry_pointer_type entry_ptr = nullptr;
        bool found = false;

        key.system_mcid_17_3 = bit_utils::get_bits(smcid, 17 /*msb*/, 3 /*lsb*/);

        // read this line of the memory for the npl_fe_smcid_to_mcid_table_t
        la_slice_pair_id_t first_p = get_used_slice_pairs()[0];
        lld_memory_scptr mac_lp_table = m_gb_tree->slice_pair[first_p]->idb->macdb->lp_table;
        bit_vector line;
        m_ll_device->read_memory(mac_lp_table, key.system_mcid_17_3, line);

        size_t entry_idx;
        for (entry_idx = 0; entry_idx < NPL_MULTICAST_NUM_MCIDS_PER_ENTRY; entry_idx++) {
            la_multicast_group_gid_t local_mcid;

            // get the local MCID for this index, each MCID is 16 bits
            local_mcid = line.bits(((entry_idx + 1) * 16) - 1, (entry_idx * 16)).get_value();

            // populate the value for this local MCID
            value.payloads.mcid_array.mcid[entry_idx].id = local_mcid;

            if (local_mcid == NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE) {
                // no need to set mapping for unused entries
                continue;
            }

            // restore the mapping for this system MCID to local MCID
            m_mc_smcid_to_local_mcid[smcid + entry_idx] = local_mcid;

            // set as found such that the table gets updated below
            found = true;
            auto it = m_mcid_to_links_bitmap.find(local_mcid);
            if (it != m_mcid_to_links_bitmap.end()) {
                // this local MCID has already been mapped to the links bitmap
                continue;
            }

            bit_vector links_vector(0, 128);
            uint64_t links_bitmap[2];

            // read the links bitmap for this local mcid
            txn.status = read_mc_fe_links_bmp_sram(local_mcid, links_vector);
            return_on_error(txn.status);

            // save the bit_vector as two uint64_t values
            links_bitmap[0] = links_vector.bits(63, 0).get_value();
            links_bitmap[1] = links_vector.bits(127, 64).get_value();

            // allocate this MCID from the generator
            uint64_t allocator_mcid = local_mcid;
            m_index_generators.local_mcids.allocate(allocator_mcid, allocator_mcid);

            // update the MCID to links bitmap mapping
            auto links_key = mc_links_key_t(links_bitmap[0], links_bitmap[1]);
            m_mcid_to_links_bitmap[local_mcid] = links_key;

            // update links bitmap to allocated MCID mapping
            auto allocated_mcid = std::make_shared<mc_allocated_mcid>();
            txn.on_fail([&]() { allocated_mcid.reset(); });

            // in_use will get updated when the new fabric multicast group creates come in after reconnect
            allocated_mcid->in_use = 0;
            allocated_mcid->mcid = local_mcid;

            m_links_bitmap_to_allocated_mcid[links_key] = allocated_mcid;
            txn.on_fail([&]() { m_links_bitmap_to_allocated_mcid[links_key] = nullptr; });
        }

        if (found) {
            // A valid local MCID was found, re-program this whole entry
            for (la_slice_pair_id_t slice_pair : get_used_slice_pairs()) {
                const auto& table(m_tables.fe_smcid_to_mcid_table[slice_pair]);
                txn.status = table->set(key, value, entry_ptr);
                return_on_error(txn.status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::restore_bundles()
{
    la_status status;

    // These non-volatile memories are used for link bundling.
    std::vector<lld_memory_scptr> non_volatile_memories;
    for (la_slice_pair_id_t pair_idx : get_used_slice_pairs()) {
        for (auto idx = 0; idx < 2; idx++) {
            non_volatile_memories.push_back((*m_gb_tree->slice_pair[pair_idx]->rx_pdr->fb_link_to_link_bundle_table)[idx]);
            non_volatile_memories.push_back((*m_gb_tree->slice_pair[pair_idx]->rx_pdr->fe_uc_link_bundle_desc_table)[idx]);
        }
    }

    // Repopulating tree shadow from HW.
    for (const auto& mem : non_volatile_memories) {
        bit_vector bv;
        status = m_ll_device->read_memory(*mem, 0, mem->get_desc()->entries, bv);
        return_on_error(status);
    }

    std::set<size_t> bundles_in_use;
    gibraltar::rx_pdr_2_slices_fb_link_to_link_bundle_table_memory link_to_bundle;

    la_slice_id_t rep_sid = get_used_slice_pairs()[0];
    for (size_t fabric_port = 0; fabric_port < NUM_FABRIC_PORTS_IN_DEVICE; fabric_port++) {
        status = m_ll_device->read_memory(
            (*m_gb_tree->slice_pair[rep_sid]->rx_pdr->fb_link_to_link_bundle_table)[0], fabric_port, link_to_bundle);
        return_on_error(status);

        if (link_to_bundle.fields.table_bundle_num != INVALID_BUNDLE) {
            bundles_in_use.insert(link_to_bundle.fields.table_bundle_num);
        }
    }

    for (size_t bundle_id : bundles_in_use) {
        gibraltar::rx_pdr_2_slices_fe_uc_link_bundle_desc_table_memory bundle_desc;

        status = m_ll_device->read_memory(
            (*m_gb_tree->slice_pair[rep_sid]->rx_pdr->fe_uc_link_bundle_desc_table)[0], bundle_id, bundle_desc);
        return_on_error(status);

        if (bundle_desc.fields.slice_bundle_link0 != INVALID_LINK) {
            m_bundles[bundle_id].push_back(bundle_desc.fields.slice_bundle_link0);
        }

        if (bundle_desc.fields.slice_bundle_link1 != INVALID_LINK) {
            m_bundles[bundle_id].push_back(bundle_desc.fields.slice_bundle_link1);
        }

        if (bundle_desc.fields.slice_bundle_link2 != INVALID_LINK) {
            m_bundles[bundle_id].push_back(bundle_desc.fields.slice_bundle_link2);
        }

        if (bundle_desc.fields.slice_bundle_link3 != INVALID_LINK) {
            m_bundles[bundle_id].push_back(bundle_desc.fields.slice_bundle_link3);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_system_port_scheduler(la_slice_id_t slice,
                                             la_ifg_id_t ifg,
                                             la_system_port_scheduler_id_t sp_sch_id,
                                             la_interface_scheduler_wptr interface_scheduler,
                                             la_system_port_scheduler_impl_sptr& out_scheduler)
{
    auto scheduler = std::make_shared<la_system_port_scheduler_impl>(shared_from_this(), slice, ifg, sp_sch_id);

    la_object_id_t oid;
    la_status status = register_object(scheduler, oid);
    return_on_error(status);

    status = scheduler->initialize(oid, interface_scheduler);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_scheduler = scheduler;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_logical_port_scheduler(la_slice_id_t slice_id,
                                              la_ifg_id_t ifg_id,
                                              la_system_port_scheduler_id_t tid,
                                              la_rate_t port_speed,
                                              la_logical_port_scheduler_impl_sptr& out_scheduler)
{
    auto scheduler = std::make_shared<la_logical_port_scheduler_impl>(shared_from_this(), slice_id, ifg_id, tid, port_speed);

    la_object_id_t oid;
    la_status status = register_object(scheduler, oid);
    return_on_error(status);

    status = scheduler->initialize(oid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_scheduler = scheduler;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_create_output_queue_scheduler(la_slice_id_t slice_id,
                                                 la_ifg_id_t ifg_id,
                                                 index_handle index,
                                                 la_output_queue_scheduler::scheduling_mode_e mode,
                                                 la_output_queue_scheduler_impl_sptr& out_scheduler)
{
    auto scheduler = std::make_shared<la_output_queue_scheduler_impl>(shared_from_this(), slice_id, ifg_id, std::move(index));

    la_object_id_t oid;
    la_status status = register_object(scheduler, oid);
    return_on_error(status);

    status = scheduler->initialize(oid, mode);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_scheduler = scheduler;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_fabric_port_scheduler(la_slice_id_t slice_id,
                                             la_ifg_id_t ifg_id,
                                             la_uint_t fab_intf_id,
                                             la_fabric_port_scheduler_impl_sptr& out_scheduler)
{
    auto scheduler = std::make_shared<la_fabric_port_scheduler_impl>(shared_from_this(), slice_id, ifg_id, fab_intf_id);

    la_object_id_t oid;
    la_status status = register_object(scheduler, oid);
    return_on_error(status);

    status = scheduler->initialize(oid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_scheduler = scheduler;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_interface_scheduler(la_slice_id_t slice,
                                           la_ifg_id_t ifg,
                                           la_uint_t pif_base,
                                           la_mac_port::port_speed_e speed,
                                           bool is_fabric,
                                           la_interface_scheduler_impl_sptr& out_scheduler)
{
    auto scheduler = std::make_shared<la_interface_scheduler_impl>(shared_from_this(), slice, ifg, pif_base, speed, is_fabric);

    la_object_id_t oid;
    la_status status = register_object(scheduler, oid);
    return_on_error(status);

    status = scheduler->initialize(oid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_scheduler = scheduler;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_mpls_vpn_decap(la_mpls_label label, const la_vrf_wcptr& vrf, la_mpls_vpn_decap_impl_wptr& out_decap)
{
    auto decap = std::make_shared<la_mpls_vpn_decap_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(decap, oid);
    return_on_error(status);

    status = decap->initialize(oid, label, vrf);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_decap = decap;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_mldp_terminate(la_mpls_label label,
                                      const la_vrf_wcptr& vrf,
                                      la_uint_t rpfid,
                                      bool bud_node,
                                      la_mldp_vpn_decap_impl_wptr& out_decap)
{
    auto decap = std::make_shared<la_mldp_vpn_decap_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(decap, oid);
    return_on_error(status);

    if (vrf == nullptr) {
        log_err(API, "%s: VRF ID NULL", __func__);
        return LA_STATUS_EINVAL;
    }

    status = decap->initialize(oid, label, vrf, rpfid, bud_node);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_decap = decap;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::modify_mldp_terminate(la_mpls_label label,
                                      const la_vrf_wcptr& vrf,
                                      la_uint_t rpfid,
                                      bool bud_node,
                                      la_mldp_vpn_decap_impl* vpn_decap)
{
    if (vpn_decap == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (vrf == nullptr) {
        log_err(API, "%s: VRF ID NULL", __func__);
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vpn_decap, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = vpn_decap->update_mldp_termination_table(label, vrf, rpfid, bud_node);
    return status;
}

la_status
la_device_impl::create_system_port(la_system_port_gid_t gid,
                                   la_npu_host_port_base_wptr npu_host_port,
                                   const la_voq_set_wptr& voq_set,
                                   const la_tc_profile_wcptr& tc_profile,
                                   la_system_port_base_sptr& out_port)
{
    auto port = std::make_shared<la_system_port_gibraltar>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(port, oid);
    return_on_error(status);

    status = port->initialize(oid, npu_host_port, gid, voq_set, tc_profile);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_port = std::static_pointer_cast<la_system_port_base>(port);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_sms_total_packet_counts(la_slice_id_t slice_id,
                                            la_ifg_id_t ifg,
                                            bool clear_on_read,
                                            la_sms_packet_counts& out_packet_count)
{
    la_status status = m_slice_id_manager->is_slice_ifg_valid(slice_id, ifg);
    return_on_error(status);

    la_uint_t gifg = m_slice_id_manager->slice_ifg_2_global_ifg(slice_id, ifg);
    gibraltar::sms_main_sms_total_write_pkts_reg_register write_reg;
    gibraltar::sms_main_sms_total_read_pkts_reg_register read_reg;

    if (clear_on_read) {
        status = m_ll_device->read_register((*m_gb_tree->sms_main->sms_total_write_pkts_reg)[gifg], write_reg);
        return_on_error(status);
        status = m_ll_device->read_register((*m_gb_tree->sms_main->sms_total_read_pkts_reg)[gifg], read_reg);
        return_on_error(status);
    } else {
        status = m_ll_device->peek_register((*m_gb_tree->sms_main->sms_total_write_pkts_reg)[gifg], write_reg);
        return_on_error(status);
        status = m_ll_device->peek_register((*m_gb_tree->sms_main->sms_total_read_pkts_reg)[gifg], read_reg);
        return_on_error(status);
    }

    out_packet_count.sms_write_packet_count = write_reg.fields.sms_total_write_pkts;
    out_packet_count.sms_read_packet_count = read_reg.fields.sms_total_read_pkts;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_sms_error_counts(bool clear_on_read, la_sms_error_counts& out_error_count)
{
    gibraltar::sms_main_sms_total_write_error_reg_register total_write_error_reg;
    gibraltar::sms_main_sms_cgm_write_error_reg_register cgm_write_error_reg;
    gibraltar::sms_main_sms_out_of_bank_write_error_reg_register oob_write_error_reg;
    gibraltar::sms_main_sms_read_error_debug_reg_register sms_read_error_reg;
    la_status status;

    if (clear_on_read) {
        status = m_ll_device->read_register(*m_gb_tree->sms_main->sms_total_write_error_reg, total_write_error_reg);
        return_on_error(status);
        status = m_ll_device->read_register(*m_gb_tree->sms_main->sms_cgm_write_error_reg, cgm_write_error_reg);
        return_on_error(status);
        status = m_ll_device->read_register(*m_gb_tree->sms_main->sms_out_of_bank_write_error_reg, oob_write_error_reg);
        return_on_error(status);
        status = m_ll_device->read_register(*m_gb_tree->sms_main->sms_read_error_debug_reg, sms_read_error_reg);
        return_on_error(status);
    } else {
        status = m_ll_device->peek_register(*m_gb_tree->sms_main->sms_total_write_error_reg, total_write_error_reg);
        return_on_error(status);
        status = m_ll_device->peek_register(*m_gb_tree->sms_main->sms_cgm_write_error_reg, cgm_write_error_reg);
        return_on_error(status);
        status = m_ll_device->peek_register(*m_gb_tree->sms_main->sms_out_of_bank_write_error_reg, oob_write_error_reg);
        return_on_error(status);
        status = m_ll_device->peek_register(*m_gb_tree->sms_main->sms_read_error_debug_reg, sms_read_error_reg);
        return_on_error(status);
    }

    out_error_count.total_write_error_count = total_write_error_reg.fields.sms_total_write_error;
    out_error_count.cgm_write_error_count = cgm_write_error_reg.fields.sms_cgm_write_error;
    out_error_count.dram_slice_cgm_write_error_count = cgm_write_error_reg.fields.sms_dram_slice_cgm_write_error;
    out_error_count.out_of_bank_write_error_count = oob_write_error_reg.fields.sms_out_of_bank_write_error;
    out_error_count.read_error_count = sms_read_error_reg.fields.sms_read_crc_error;
    out_error_count.read_dont_transmit_count = sms_read_error_reg.fields.sms_read_dont_transmit;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_sms_total_free_buffer_summary(bool clear_on_read, la_uint64_t& out_free_buffer_count)
{
    gibraltar::sms_main_sms_total_free_buff_sum_status_reg_register reg;
    la_status status;

    if (clear_on_read) {
        status = m_ll_device->read_register(*m_gb_tree->sms_main->sms_total_free_buff_sum_status_reg, reg);
    } else {
        status = m_ll_device->peek_register(*m_gb_tree->sms_main->sms_total_free_buff_sum_status_reg, reg);
    }
    return_on_error(status);

    out_free_buffer_count = reg.fields.sms_total_free_buff_sum_status;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_tx_cgm_port_oq_profile_thresholds(la_slice_id_t slice,
                                                      la_mac_port::port_speed_e port_speed,
                                                      const la_tx_cgm_oq_profile_thresholds& thresholds)
{
    start_api_call("slice=", slice, "port_speed=", port_speed, "thresholds=", thresholds);

    auto uc_oq_profile_mem = m_gb_tree->slice[slice]->tx->cgm->uc_oq_profile;
    gibraltar::txcgm_uc_oq_profile_memory mem;

    la_uint_t max_bytes_thr = bit_utils::ones(mem.fields.FLOW_CONTROL_BYTES_TH_WIDTH);
    la_uint_t max_buffers_thr = bit_utils::ones(mem.fields.FLOW_CONTROL_BUFFERS_TH_WIDTH);
    la_uint_t max_pds_thr = bit_utils::ones(mem.fields.FLOW_CONTROL_PDS_TH_WIDTH);

    if (thresholds.fc_bytes_threshold > max_bytes_thr || thresholds.drop_bytes_threshold > max_bytes_thr) {
        return LA_STATUS_EINVAL;
    }
    if (thresholds.fc_buffers_threshold > max_buffers_thr || thresholds.drop_buffers_threshold > max_buffers_thr) {
        return LA_STATUS_EINVAL;
    }
    if (thresholds.fc_pds_threshold > max_pds_thr || thresholds.drop_pds_threshold > max_pds_thr) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t oqg_profile = la_interface_scheduler_impl::TX_CGM_PROFILE_MAP.at(port_speed);

    la_status status = m_ll_device->read_memory(uc_oq_profile_mem, oqg_profile, mem);
    return_on_error(status);

    mem.fields.flow_control_bytes_th = thresholds.fc_bytes_threshold;
    mem.fields.flow_control_buffers_th = thresholds.fc_buffers_threshold;
    mem.fields.flow_control_pds_th = thresholds.fc_pds_threshold;
    mem.fields.drop_bytes_th = thresholds.drop_bytes_threshold;
    mem.fields.drop_buffers_th = thresholds.drop_buffers_threshold;
    mem.fields.drop_pds_th = thresholds.drop_pds_threshold;

    status = m_ll_device->write_memory(uc_oq_profile_mem, oqg_profile, mem);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_tx_cgm_port_oq_profile_thresholds(la_slice_id_t slice,
                                                      la_mac_port::port_speed_e port_speed,
                                                      la_tx_cgm_oq_profile_thresholds& out_thresholds)
{
    start_api_getter_call();

    auto uc_oq_profile_mem = m_gb_tree->slice[slice]->tx->cgm->uc_oq_profile;
    gibraltar::txcgm_uc_oq_profile_memory mem;

    la_uint_t oqg_profile = la_interface_scheduler_impl::TX_CGM_PROFILE_MAP.at(port_speed);

    la_status status = m_ll_device->read_memory(uc_oq_profile_mem, oqg_profile, mem);
    return_on_error(status);

    out_thresholds.fc_bytes_threshold = mem.fields.flow_control_bytes_th;
    out_thresholds.fc_buffers_threshold = mem.fields.flow_control_buffers_th;
    out_thresholds.fc_pds_threshold = mem.fields.flow_control_pds_th;
    out_thresholds.drop_bytes_threshold = mem.fields.drop_bytes_th;
    out_thresholds.drop_buffers_threshold = mem.fields.drop_buffers_th;
    out_thresholds.drop_pds_threshold = mem.fields.drop_pds_th;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_tx_cgm_pfc_port_oq_profile_thresholds(la_slice_id_t slice,
                                                          la_mac_port::port_speed_e port_speed,
                                                          const la_tx_cgm_oq_profile_thresholds& thresholds)
{
    start_api_call("slice=", slice, "port_speed=", port_speed, "thresholds=", thresholds);

    auto uc_oq_profile_mem = m_gb_tree->slice[slice]->tx->cgm->uc_oq_profile;
    gibraltar::txcgm_uc_oq_profile_memory mem;

    la_uint_t max_bytes_thr = bit_utils::ones(mem.fields.FLOW_CONTROL_BYTES_TH_WIDTH);
    la_uint_t max_buffers_thr = bit_utils::ones(mem.fields.FLOW_CONTROL_BUFFERS_TH_WIDTH);
    la_uint_t max_pds_thr = bit_utils::ones(mem.fields.FLOW_CONTROL_PDS_TH_WIDTH);

    if (thresholds.fc_bytes_threshold > max_bytes_thr || thresholds.drop_bytes_threshold > max_bytes_thr) {
        return LA_STATUS_EINVAL;
    }
    if (thresholds.fc_buffers_threshold > max_buffers_thr || thresholds.drop_buffers_threshold > max_buffers_thr) {
        return LA_STATUS_EINVAL;
    }
    if (thresholds.fc_pds_threshold > max_pds_thr || thresholds.drop_pds_threshold > max_pds_thr) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t oqg_profile = la_interface_scheduler_impl::TX_CGM_PROFILE_MAP_PFC.at(port_speed);

    la_status status = m_ll_device->read_memory(uc_oq_profile_mem, oqg_profile, mem);
    return_on_error(status);

    mem.fields.flow_control_bytes_th = thresholds.fc_bytes_threshold;
    mem.fields.flow_control_buffers_th = thresholds.fc_buffers_threshold;
    mem.fields.flow_control_pds_th = thresholds.fc_pds_threshold;
    mem.fields.drop_bytes_th = thresholds.drop_bytes_threshold;
    mem.fields.drop_buffers_th = thresholds.drop_buffers_threshold;
    mem.fields.drop_pds_th = thresholds.drop_pds_threshold;

    status = m_ll_device->write_memory(uc_oq_profile_mem, oqg_profile, mem);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_tx_cgm_pfc_port_oq_profile_thresholds(la_slice_id_t slice,
                                                          la_mac_port::port_speed_e port_speed,
                                                          la_tx_cgm_oq_profile_thresholds& out_thresholds)
{
    start_api_getter_call();

    auto uc_oq_profile_mem = m_gb_tree->slice[slice]->tx->cgm->uc_oq_profile;
    gibraltar::txcgm_uc_oq_profile_memory mem;

    la_uint_t oqg_profile = la_interface_scheduler_impl::TX_CGM_PROFILE_MAP_PFC.at(port_speed);

    la_status status = m_ll_device->read_memory(uc_oq_profile_mem, oqg_profile, mem);
    return_on_error(status);

    out_thresholds.fc_bytes_threshold = mem.fields.flow_control_bytes_th;
    out_thresholds.fc_buffers_threshold = mem.fields.flow_control_buffers_th;
    out_thresholds.fc_pds_threshold = mem.fields.flow_control_pds_th;
    out_thresholds.drop_bytes_threshold = mem.fields.drop_bytes_th;
    out_thresholds.drop_buffers_threshold = mem.fields.drop_buffers_th;
    out_thresholds.drop_pds_threshold = mem.fields.drop_pds_th;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_pfc_additional_link_tuning(bool use_long_links)
{
    start_api_call("use_long_links=", use_long_links);

    lld_register_value_list_t reg_val_list;

    gibraltar::rx_cgm_statistic_cgm_configurations_register statistic_cgm_configurations;
    gibraltar::rx_cgm_global_configuration_register global_configuration;
    gibraltar::ics_slice_rx_cgm_count_mode_cfg_register count_mode_cfg;
    gibraltar::pdvoq_slice_general_conf_register general_conf;

    // For long link usage, configure SQ counting of HBM packets, otherwise configure for SMS usage
    for (la_slice_id_t slice : get_used_slices()) {
        if (use_long_links) {
            statistic_cgm_configurations.fields.slice_statistic_update_rate_mask = 0;
            reg_val_list.push_back({(*m_gb_tree->rx_cgm->statistic_cgm_configurations)[slice], statistic_cgm_configurations});

            la_status status = m_ll_device->read_register((*m_gb_tree->rx_cgm->global_configuration)[slice], global_configuration);
            return_on_error(status);
            global_configuration.fields.slice_count_dram_buffers = 1;
            reg_val_list.push_back({(*m_gb_tree->rx_cgm->global_configuration)[slice], global_configuration});

            status = m_ll_device->read_register((*m_gb_tree->slice[slice]->ics->rx_cgm_count_mode_cfg), count_mode_cfg);
            return_on_error(status);
            count_mode_cfg.fields.rx_cgm_count_mode = 1;
            reg_val_list.push_back({(m_gb_tree->slice[slice]->ics->rx_cgm_count_mode_cfg), count_mode_cfg});

            if (is_network_slice(slice)) {

                status = m_ll_device->read_register((*m_gb_tree->slice[slice]->pdvoq->general_conf), general_conf);
                return_on_error(status);
                general_conf.fields.ucdv_discard_en = 1;
                reg_val_list.push_back({(m_gb_tree->slice[slice]->pdvoq->general_conf), general_conf});

                // Set max PDs per HBM block
                gibraltar::ics_slice_packing_configuration_register packing_config;
                status = m_ll_device->read_register(m_gb_tree->slice[slice]->ics->packing_configuration, packing_config);
                return_on_error(status);

                packing_config.fields.max_pds_in_pack = 12;
                packing_config.fields.dram_burst_size = 13;

                reg_val_list.push_back({m_gb_tree->slice[slice]->ics->packing_configuration, packing_config});
            }
        } else {
            statistic_cgm_configurations.fields.slice_statistic_update_rate_mask = 7;
            reg_val_list.push_back({(*m_gb_tree->rx_cgm->statistic_cgm_configurations)[slice], statistic_cgm_configurations});

            la_status status = m_ll_device->read_register((*m_gb_tree->rx_cgm->global_configuration)[slice], global_configuration);
            return_on_error(status);
            global_configuration.fields.slice_count_dram_buffers = 0;
            reg_val_list.push_back({(*m_gb_tree->rx_cgm->global_configuration)[slice], global_configuration});

            status = m_ll_device->read_register((*m_gb_tree->slice[slice]->ics->rx_cgm_count_mode_cfg), count_mode_cfg);
            return_on_error(status);
            count_mode_cfg.fields.rx_cgm_count_mode = 0;
            reg_val_list.push_back({(m_gb_tree->slice[slice]->ics->rx_cgm_count_mode_cfg), count_mode_cfg});
        }
    }

    if (use_long_links) {
        // Disable DRAM rate limiter
        ics_top_dram_write_eligible_meter_register dram_write_eligible_meter_reg;
        la_status status = m_ll_device->read_register(m_gb_tree->ics_top->dram_write_eligible_meter, dram_write_eligible_meter_reg);
        return_on_error(status);

        dram_write_eligible_meter_reg.fields.dram_write_elig_meter_inc_value = 0xFFFF;

        reg_val_list.push_back({m_gb_tree->ics_top->dram_write_eligible_meter, dram_write_eligible_meter_reg});
    }

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_voq_max_negative_credit_balance(la_uint_t balance)
{
    start_api_call("balance=", balance);

    gibraltar::ics_slice_read_pipe_param_reg_register reg;

    la_uint_t max_val = bit_utils::ones(reg.fields.MAX_NEGATIVE_CB_WIDTH);
    if (balance > max_val) {
        return LA_STATUS_EINVAL;
    }

    for (la_slice_id_t slice : get_used_slices()) {
        auto read_pipe_param_reg = m_gb_tree->slice[slice]->ics->read_pipe_param_reg;

        // Write read_pipe_param_reg
        la_status status = m_ll_device->read_register(read_pipe_param_reg, reg);
        return_on_error(status);

        reg.fields.max_negative_cb = balance;

        status = m_ll_device->write_register(read_pipe_param_reg, reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_voq_max_negative_credit_balance(la_uint_t& out_balance)
{
    start_api_getter_call();
    la_slice_id_t rep_sid = first_active_slice_id();
    auto read_pipe_param_reg = m_gb_tree->slice[rep_sid]->ics->read_pipe_param_reg;
    gibraltar::ics_slice_read_pipe_param_reg_register reg;

    la_status status = m_ll_device->read_register(read_pipe_param_reg, reg);
    return_on_error(status);

    out_balance = reg.fields.max_negative_cb;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_cgm_watermarks(la_cgm_watermarks& out_watermarks)
{
    gibraltar::pdvoq_shared_mma_cgm_counter_wmk_register reg;
    la_status status;

    status = m_ll_device->read_register(*m_gb_tree->pdvoq_shared_mma->cgm_counter_wmk, reg);
    return_on_error(status);
    out_watermarks.uc_wmk = reg.fields.counter_uc_wmk;
    out_watermarks.mc_wmk = reg.fields.counter_mc_wmk;
    out_watermarks.ms_uc_wmk = reg.fields.counter_ms_uc_wmk;
    out_watermarks.ms_mc_wmk = reg.fields.counter_ms_mc_wmk;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_acl_command_profile(uint32_t profile_index, const la_acl_command_def_vec_t& acl_command_profile)
{
    m_acl_command_profiles[profile_index] = acl_command_profile;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_acl_command_profile(uint32_t profile_index, la_acl_command_def_vec_t& out_acl_command_profile) const
{
    out_acl_command_profile = m_acl_command_profiles[profile_index];
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_ip_tunnel_transit_counter(la_counter_set* counter)
{
    start_api_call("counter", counter);
    if (counter == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(counter, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto counter_impl = get_sptr<la_counter_set_impl>(counter);

    la_status status = counter_impl->add_ip_tunnel_transit_counter();
    return_on_error(status);

    m_ip_tunnel_transit_counter = counter_impl;
    npl_ip_rx_global_counter_table_t::key_type key;
    npl_ip_rx_global_counter_table_t::value_type val;
    npl_ip_rx_global_counter_table_t::value_type rollback_val;
    npl_ip_rx_global_counter_table_t::entry_pointer_type entry_ptr = nullptr;

    transaction txn;
    txn.on_fail([&]() { counter_impl->remove_ip_tunnel_transit_counter(); });
    for (la_slice_id_t slice : get_used_slices()) {
        const auto& table(m_tables.ip_rx_global_counter_table[slice]);
        val.payloads.global_counter.tunnel_transit_counter_p
            = populate_counter_ptr_slice(counter_impl, slice, COUNTER_DIRECTION_INGRESS);
        txn.status = table->set(key, val, entry_ptr);
        return_on_error(txn.status);
        txn.on_fail([&]() { table->set(key, rollback_val, entry_ptr); });
    }
    add_object_dependency(counter_impl, this);
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_ip_tunnel_transit_counter(la_counter_set*& out_counter) const
{
    start_api_getter_call();
    out_counter = m_ip_tunnel_transit_counter.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::register_object(const la_object_sptr& new_object, la_object_id_t& oid)
{
    bool is_success = m_index_generators.oids.allocate(oid);
    if (!is_success) {
        return LA_STATUS_ERESOURCE;
    }

    m_objects[oid] = new_object;
    log_debug(API,
              "%s: new_object=%p type=%s oid=%lu",
              __func__,
              new_object.get(),
              la_object_type_to_string(new_object->type()).c_str(),
              oid);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::warm_boot_disconnect()
{
#if ENABLE_SERIALIZATION
    {
        // lock device inside a block to avoid deadloacks in the following m_notification->stop()
        start_api_call_allow_warm_boot("");

        if (m_warm_boot_disconnected) {
            log_err(API, "%s: device is already disconnected", __func__);
            return LA_STATUS_EINVAL;
        }

        if (m_init_phase != init_phase_e::TOPOLOGY) {
            log_err(API,
                    "%s: Warm-boot can't be invoked prior to completing topology initialization phase (%s)",
                    __func__,
                    silicon_one::to_string(m_init_phase).c_str());
            return LA_STATUS_ENOTINITIALIZED;
        }

        m_warm_boot_disconnected = true;
    }

    // Stop task_scheduler and interrupt worker threads
    m_notification->stop();

    // Temporary code, when serialization is enabled this is uneccessary
    // as the object is getting destroyed anyway
    m_notification->unregister_all_poll_cbs();

    // Close FDs
    m_notification->close_notification_pipes();

    // TODO disconnect nsim_simulator_client
    //

    return LA_STATUS_SUCCESS;
#else
    return LA_STATUS_ENOTIMPLEMENTED;
#endif
}

la_status
la_device_impl::warm_boot_save_and_destroy(const std::string& warm_boot_file, bool free_objects, la_uint32_t target_wb_revision)
{
#ifdef ENABLE_SERIALIZATION
    la_status status;
    start_api_call_allow_warm_boot("warm_boot_file=", warm_boot_file);

    if (!m_warm_boot_disconnected) {
        log_err(API, "%s: device must be disconnected first", __func__);
        return LA_STATUS_EINVAL;
    }

    // Apply rollback patches if target wb_revision is older than current
    if (target_wb_revision < WB_REVISION) {
        status = warm_boot_apply_rollback_patches(target_wb_revision);
        return_on_error(status);
    }

    // Perfrom manual serializations.
    status = warm_boot_pre_save();
    return_on_error(status);

    // Serialize la_device_imp (as la_device_sptr) the given file
    std::ofstream dev_state_file(warm_boot_file, CEREAL_OUTPUT_STREAM_MODE_FLAGS);
    CEREAL_UTILS_CREATE_OUTPUT_ARCHIVE(archive, dev_state_file);

    // Set the serialization version for all SDK components
    warm_boot_set_serialization_version(target_wb_revision);

    // Serialize WB version and revision separatly so we can access them
    // later on in the deserialize phase without the need of deserializing la_device.
    archive(std::string(WB_VERSION));
    m_base_wb_revision = target_wb_revision;
    archive(m_base_wb_revision);

    // TODO: For now up-cast to la_device to workaround Cereal polymorphism issue
    archive(static_pointer_cast<la_device>(m_objects[0]));

    // Disable writes to device
    m_ll_device->set_write_to_device(false /*en*/);

    // Close simulator connection
    // m_ll_device->set_device_simulator(nullptr);

    if (free_objects) {
        m_objects[0].reset();
    }

    return LA_STATUS_SUCCESS;
#else
    return LA_STATUS_ENOTIMPLEMENTED;
#endif
}

la_status
la_device_impl::warm_boot_reconnect()
{
#if ENABLE_SERIALIZATION
    start_api_call_allow_warm_boot("");

    if (!m_warm_boot_disconnected) {
        log_err(API, "%s: device is already connected", __func__);
        return LA_STATUS_EINVAL;
    }

    // TODO create_nsim_simulator_client()
    //

    // TODO call post-deserialization() for objects requiring that (e.g. ll_device, pci_ports, punt_inject_ports,...)
    //
    auto status = reconnect_pci_ports_after_warm_boot();
    return_on_error(status);

    // Restart task_scheduler and interrupt worker threads
    // TODO A better idea is to call start_notifications(), however it needs serialization
    register_pollers();
    if (m_save_state_runt.task_handle != task_scheduler::INVALID_TASK_HANDLE) {
        set_periodic_save_state_period(m_save_state_runt.period);
    }
    m_notification->start();

    // handle pending MSI interrupts to unblock new interrupts
    m_notification->handle_pending_msi_interrupts();

    m_warm_boot_disconnected = false;

    return LA_STATUS_SUCCESS;
#else
    return LA_STATUS_ENOTIMPLEMENTED;
#endif
}

static la_status
check_if_interface_is_enabled(std::string nw_interface_file_name, bool& out_is_enabled)
{
    std::ifstream nw_interface_file(nw_interface_file_name);
    char buf[1024] = {'\0'};
    nw_interface_file.getline(buf, sizeof(buf) - 1);
    std::string first_line(buf);
    if (first_line.size() == 0) {
        log_err(HLD, "%s: failed to read from network-interface-file '%s'", __func__, nw_interface_file_name.c_str());
        return LA_STATUS_ENODEV;
    }

    bool not_enabled = first_line.find("is not enabled") != string::npos;

    out_is_enabled = !not_enabled;

    return LA_STATUS_SUCCESS;
}

static la_status
was_kernel_module_unloaded(const la_device_impl_wptr& la_dev, std::vector<la_object*> pci_ports_objs, bool& out_is_unloaded)
{
    // If a PCI port exists then the correspoinding network-interface should be enabled
    // if it's not enabled then it means that the kernel module was unloaded
    std::vector<la_slice_id_t> enabled_slices;
    std::vector<la_slice_id_t> disabled_slices;
    dassert_crit(pci_ports_objs.size() > 0);
    for (auto ppo : pci_ports_objs) {
        auto pci_port = static_cast<la_pci_port_base*>(ppo);
        auto slice = pci_port->get_slice();
        auto nw_interface_file_name = la_dev->m_ll_device->get_network_interface_file_name(slice);
        bool is_enabled = false; // without the initialization, Werror yell for no apparent reason
        auto status = check_if_interface_is_enabled(nw_interface_file_name, is_enabled);
        return_on_error(status);
        if (is_enabled) {
            enabled_slices.push_back(slice);
        } else {
            disabled_slices.push_back(slice);
        }
    }

    bool is_unloaded = (disabled_slices.size() > 0);

    if (is_unloaded && enabled_slices.size() > 0) {
        log_warning(
            HLD,
            "%s: inconsistent state of PCI ports. Network interfaces are enabled on slices '%s' and disabled on slices '%s'",
            __func__,
            to_string(enabled_slices).c_str(),
            to_string(disabled_slices).c_str());
    }

    out_is_unloaded = is_unloaded;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::reconnect_pci_ports_after_warm_boot()
{
    if (is_simulated_device()) {
        // Nothing to do
        return LA_STATUS_SUCCESS;
    }

    auto pci_ports_objs = get_objects(la_object::object_type_e::PCI_PORT);
    if (pci_ports_objs.size() == 0) {
        // Nothing to do
        return LA_STATUS_SUCCESS;
    }

    bool is_unloaded = false;
    auto status = was_kernel_module_unloaded(shared_from_this(), pci_ports_objs, is_unloaded);
    return_on_error(status);
    if (!is_unloaded) {
        // Nothing to do
        return LA_STATUS_SUCCESS;
    }

    // Reset the pointers that the packet-dma HW holds, since they are not sync'ed with kernel module
    status = init_packet_dma();
    return_on_error(status);

    // Enable all PCI ports and activate if needed
    for (auto o : pci_ports_objs) {
        auto pci_port = static_cast<la_pci_port_base*>(o);
        status = pci_port->enable();
        return_on_error(status);

        if (pci_port->is_active()) {
            status = pci_port->do_activate();
            return_on_error(status);
        }
    }

    // Restore MAC addresses of network interfaces
    auto punt_inject_ports_objs = get_objects(la_object::object_type_e::PUNT_INJECT_PORT);
    for (auto o : punt_inject_ports_objs) {
        auto punt_inject_port = static_cast<const la_punt_inject_port_base*>(o);
        auto sys_port_api = punt_inject_port->get_system_port();
        auto sys_port = static_cast<const la_system_port_base*>(sys_port_api);
        auto sys_port_type = sys_port->get_port_type();
        if (sys_port_type != la_system_port_base::port_type_e::PCI) {
            continue;
        }

        la_mac_addr_t mac_addr;
        status = punt_inject_port->get_mac(mac_addr);
        return_on_error(status);
        auto slice = sys_port->get_slice();
        status = set_network_interface_mac_addr(slice, mac_addr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::warm_boot_restore(const std::string& device_path, const silicon_one::la_platform_cbs& platform_cbs)
{
    start_api_call_allow_warm_boot("device_path=", device_path, "platform_cbs=", platform_cbs);

    if (!m_warm_boot_disconnected) {
        log_err(API, "%s: device must be disconnected first", __func__);
        return LA_STATUS_EINVAL;
    }

    // Restore simulator client if needed
    device_simulator* sim = nullptr;
    auto status = create_nsim_simulator_client(device_path, sim);
    return_on_error(status);

    if (sim) {
        status = m_ll_device->set_device_simulator(sim);
        return_on_error(status);
    }

    // Revive ll_device
    status = m_ll_device->post_restore(device_path.c_str(), platform_cbs);
    return_on_error(status);

    // Invoke per-device post restoration
    status = warm_boot_post_restore();
    return_on_error(status);

    // Invoke WB upgrade patches
    if (m_base_wb_revision < WB_REVISION) {
        warm_boot_apply_upgrade_patches(m_base_wb_revision);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_component_health(la_component_health_vec_t& out_component_health) const
{
    la_status stat = LA_STATUS_SUCCESS;

    // Don't allow API call before device is initialized.
    if (m_init_phase == init_phase_e::CREATED) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    out_component_health.resize(0);
    la_component_health_vec_t die_health;
    m_serdes_device_handler->get_component_health(die_health);

    out_component_health.insert(out_component_health.end(), die_health.begin(), die_health.end());

    return stat;
}

la_status
la_device_impl::create_multicast_group_common(std::shared_ptr<la_multicast_group_common_base>& out_multicast_group_common)
{
    out_multicast_group_common = std::make_shared<la_multicast_group_common_gibraltar>(shared_from_this());
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_forus_destination(la_uint_t bincode, la_forus_destination*& out_destination)
{
    start_api_call("bincode=", bincode);
    auto forus_destination = std::make_shared<la_forus_destination_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(forus_destination, oid);
    return_on_error(status);

    status = forus_destination->initialize(oid, bincode);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);

        return status;
    }

    out_destination = forus_destination.get();

    return LA_STATUS_SUCCESS;
}

la_uint64_t
la_device_impl::allocate_security_group_acl_id()
{
    uint64_t sgacl_id = 0;
    bool is_success = m_index_generators.sgacl_ids.allocate(sgacl_id);
    if (!is_success) {
        return 0;
    }

    return sgacl_id;
}

la_status
la_device_impl::release_security_group_acl_id(la_uint64_t sgacl_id)
{
    if (sgacl_id) {
        m_index_generators.sgacl_ids.release(sgacl_id);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_dedicated_oq_for_mcg_counter()
{
    if ((m_device_mode != device_mode_e::LINECARD) && (m_device_mode != device_mode_e::STANDALONE)) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = do_create_tc_profile(m_mcg_counter_tc_profile);
    return_on_error(status);

    for (la_traffic_class_t tc = 0; tc < NUM_TC_CLASSES; tc++) {
        status = m_mcg_counter_tc_profile->set_mapping(tc, tc);
        return_on_error(status);
    }

    m_is_builtin_objects[m_mcg_counter_tc_profile->oid()] = true;

    la_rate_t port_speed = (la_2_port_speed(NPU_HOST_PORT_DEFAULT_SPEED)) * UNITS_IN_GIGA;
    for (auto si : m_valid_ifgs_for_mcg_counters) {
        auto sid = si.slice;
        auto ifg_id = si.ifg;

        auto npu_host_port = std::make_shared<la_npu_host_port_gibraltar>(shared_from_this());
        la_object_id_t oid;
        status = register_object(npu_host_port, oid);
        return_on_error(status);
        status = npu_host_port->initialize_resources(sid, ifg_id, oid);
        return_on_error(status);

        m_is_builtin_objects[npu_host_port->oid()] = true;
        m_mcg_tx_npu_host_ports[sid][ifg_id] = npu_host_port;

        la_interface_scheduler_impl* intf_sch = static_cast<la_interface_scheduler_impl*>(npu_host_port->get_scheduler());
        status = intf_sch->set_transmit_cir(port_speed);
        return_on_error(status);
        status = intf_sch->set_transmit_eir_or_pir(port_speed, false /* is_eir */);
        return_on_error(status);

        // Following code is based on la_system_port_scheduler_impl::set_transmit_pir()
        lld_memory_sptr cfg_mem = (*m_gb_tree->slice[sid]->pdoq->top->oq_pir_token_bucket_cfg)[ifg_id];
        lld_memory_sptr dynamic_mem = (*m_gb_tree->slice[sid]->pdoq->top->oq_pir_token_bucket)[ifg_id];
        lld_register_sptr shaper_update_reg = (*m_gb_tree->slice[sid]->pdoq->top->tpse_pir_shaper_update)[ifg_id];
        la_rate_t ifg_rate = 0;
        status = m_ifg_schedulers[sid][ifg_id]->get_transmit_pir(ifg_rate);
        return_on_error(status);
        la_rate_t requested_oqcs_rate = port_speed * 1.2;
        for (la_oq_id_t oq = 0; oq < tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH; oq++) {
            size_t mem_line = HOST_SERDES_ID * tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH + oq;
            status = tm_utils::set_oqcs_rate(shared_from_this(),
                                             cfg_mem,
                                             dynamic_mem,
                                             mem_line,
                                             shaper_update_reg,
                                             requested_oqcs_rate,
                                             requested_oqcs_rate,
                                             ifg_rate,
                                             tm_utils::DEFAULT_TRANSMIT_BUCKET_SIZE);
            return_on_error(status);
        }

        // Following code is based on la_system_port_scheduler_impl::set_priority_group_transmit_cir()
        cfg_mem = (*m_gb_tree->slice[sid]->pdoq->top->oqpg_cir_token_bucket_cfg)[ifg_id];
        dynamic_mem = (*m_gb_tree->slice[sid]->pdoq->top->oqpg_cir_token_bucket)[ifg_id];
        for (size_t pg = 0; pg < (size_t)la_system_port_scheduler::priority_group_e::NONE; pg++) {
            size_t mem_line = HOST_SERDES_ID * (size_t)la_system_port_scheduler::priority_group_e::NONE + pg;
            status = tm_utils::set_oqcs_rate(shared_from_this(),
                                             cfg_mem,
                                             dynamic_mem,
                                             mem_line,
                                             shaper_update_reg,
                                             requested_oqcs_rate,
                                             requested_oqcs_rate,
                                             ifg_rate,
                                             tm_utils::DEFAULT_TRANSMIT_BUCKET_SIZE);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(la_uint_t level, float probability)
{
    start_api_call("level=", level, "probability =", probability);
    la_status status = m_voq_cgm_handler->set_cgm_ecn_probability(level, probability);

    return status;
}

la_status
la_device_impl::get_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(la_uint_t level, float& out_probability)
{
    start_api_call("level=", level);
    la_status status = m_voq_cgm_handler->get_cgm_ecn_probability(level, out_probability);

    return status;
}

la_status
la_device_impl::clear_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(la_uint_t level)
{
    start_api_call("level=", level);
    la_status status = m_voq_cgm_handler->clear_cgm_ecn_probability(level);

    return status;
}

la_status
la_device_impl::create_vrf_redirect_destination(const la_vrf* vrf, la_vrf_redirect_destination*& out_vrf_redirect_dest)
{
    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (vrf->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_vrf_gid_t vrf_gid = vrf->get_gid();

    if (m_vrf_redir_dests[vrf_gid] != nullptr) {
        return LA_STATUS_EBUSY;
    }

    // Create and initialize L3 vrf redirect destination
    auto vrf_redirect_dest = std::make_shared<la_vrf_redirect_destination_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(vrf_redirect_dest, oid);
    return_on_error(status);

    status = vrf_redirect_dest->initialize(oid, vrf);

    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // Update mappings
    m_vrf_redir_dests[vrf_gid] = vrf_redirect_dest;
    out_vrf_redirect_dest = vrf_redirect_dest.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_vrf_redirect_destination(const la_vrf_redirect_destination_impl_wptr& vrf_redirect_dest)
{
    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    // Check arguments
    if (vrf_redirect_dest == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf_redirect_dest, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const la_vrf* vrf = vrf_redirect_dest->get_vrf();
    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_vrf_gid_t vrf_gid = vrf->get_gid();

    status = vrf_redirect_dest->destroy();
    return_on_error(status);

    m_vrf_redir_dests[vrf_gid] = nullptr;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_vrf_redirect_destination_by_id(la_vrf_gid_t vrf_gid, const la_l3_destination*& out_vrf_redir_dest) const
{
    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    if (vrf_gid >= max_vrf_gids) {
        return LA_STATUS_EINVAL;
    }

    la_vrf_redirect_destination_wptr vrf_redir_dest = m_vrf_redir_dests[vrf_gid];
    if (vrf_redir_dest == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_vrf_redir_dest = vrf_redir_dest.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_vrf_redirect_destination(const la_vrf* vrf, la_vrf_redirect_destination*& out_vrf_redir_dest) const
{
    start_api_getter_call();
    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (vrf->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_vrf_gid_t vrf_gid = vrf->get_gid();

    la_vrf_redirect_destination_wptr vrf_redir_dest = m_vrf_redir_dests[vrf_gid];
    if (vrf_redir_dest == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    out_vrf_redir_dest = vrf_redir_dest.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_mac_entries_count(la_uint32_t& out_count)
{
    start_api_getter_call();
    out_count = m_tables.mac_forwarding_table->size();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_mac_entries(la_mac_entry_vec& out_mac_entries)
{
    start_api_getter_call();
    size_t entries_total = m_tables.mac_forwarding_table->size();
    vector_alloc<npl_mac_forwarding_table_t::entry_pointer_type> entries(entries_total, nullptr);
    size_t entries_num = m_tables.mac_forwarding_table->get_entries(&entries[0], entries_total);
    dassert_ncrit(entries_num <= entries_total);

    for (size_t i = 0; i < entries_num; i++) {
        npl_mac_forwarding_table_t::key_type k(entries[i]->key());
        npl_mac_forwarding_table_t::value_type v(entries[i]->value());
        la_mac_entry_t record{};

        record.slp_gid = v.payloads.mact_result.destination.val;
        record.relay_gid = k.mac_forwarding_key.relay_id.id;
        record.addr.flat = k.mac_forwarding_key.mac_address.mac_address;
        out_mac_entries.push_back(record);
    }
    return LA_STATUS_SUCCESS;
}

la_uint32_t
la_device_impl::get_pbts_start_id()
{
    // PrefixObject GID range is (1<<16).
    // Start PBTS at (1<<15) if feature is enabled.
    // return invalid start if PBTS is disabled.
    return is_pbts_enabled() ? (1 << 15) : (1 << 17);
}

la_status
la_device_impl::get_mldp_bud_refcnt(la_slice_id_t slice_id, la_uint_t& out_refcnt)
{
    out_refcnt = m_mldp_bud_info[slice_id].recycle_mldp_bud_refcnt;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::incr_mldp_bud_refcnt(la_slice_id_t slice_id)
{
    m_mldp_bud_info[slice_id].recycle_mldp_bud_refcnt++;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::decr_mldp_bud_refcnt(la_slice_id_t slice_id)
{
    dassert_crit(m_mldp_bud_info[slice_id].recycle_mldp_bud_refcnt > 0);
    m_mldp_bud_info[slice_id].recycle_mldp_bud_refcnt--;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_mldp_bud_mpls_mc_copy_id(la_slice_id_t slice_id, uint64_t& mpls_mc_copy_id)
{
    mpls_mc_copy_id = m_mldp_bud_info[slice_id].mpls_mc_copy_id;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_mldp_bud_mpls_mc_copy_id(la_slice_id_t slice_id, uint64_t mpls_mc_copy_id)
{
    m_mldp_bud_info[slice_id].mpls_mc_copy_id = mpls_mc_copy_id;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::flush_mac_entries(bool dynamic_only, la_mac_entry_vec& out_mac_entries)
{
    start_api_call("dynamic_only=", dynamic_only);
    out_mac_entries.clear();
    la_mac_entry_vec sw_mac_entries;

    for (auto sw : m_switches) {
        la_switch* sw_ptr = sw.get();
        if (sw_ptr == nullptr) {
            continue;
        }
        la_status status = sw_ptr->flush_mac_entries(dynamic_only, sw_mac_entries);
        return_on_error(status);
    }
    out_mac_entries.insert(out_mac_entries.end(), sw_mac_entries.begin(), sw_mac_entries.end());
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::trigger_mem_protect_error(la_mem_protect_error_e error_type)
{
    start_api_call("error_type=", error_type);
    la_status status(LA_STATUS_SUCCESS);
    bit_vector mem_result;
    if (error_type == la_mem_protect_error_e::ECC_2B) {
        gibraltar::npu_host_ecc_2b_err_initiate_register_register ecc_reg;
        status = m_ll_device->read_register(m_gb_tree->npuh->host->ecc_2b_err_initiate_register, ecc_reg);
        return_on_error(status);

        ecc_reg.fields.mp_data_table_ecc_2b_err_initiate = 1;
        status = m_ll_device->write_register(m_gb_tree->npuh->host->ecc_2b_err_initiate_register, ecc_reg);
        return_on_error(status);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        status = m_ll_device->read_memory(m_gb_tree->npuh->host->mp_data_table, 0, mem_result);
        return_on_error(status);

        ecc_reg.fields.mp_data_table_ecc_2b_err_initiate = 0;
        status = m_ll_device->write_register(m_gb_tree->npuh->host->ecc_2b_err_initiate_register, ecc_reg);
        return_on_error(status);
    } else if (error_type == la_mem_protect_error_e::ECC_1B) {
        gibraltar::npu_host_ecc_1b_err_initiate_register_register ecc_reg;
        status = m_ll_device->read_register(m_gb_tree->npuh->host->ecc_1b_err_initiate_register, ecc_reg);
        return_on_error(status);

        ecc_reg.fields.mp_data_table_ecc_1b_err_initiate = 1;
        status = m_ll_device->write_register(m_gb_tree->npuh->host->ecc_1b_err_initiate_register, ecc_reg);
        return_on_error(status);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        status = m_ll_device->read_memory(m_gb_tree->npuh->host->mp_data_table, 0, mem_result);
        return_on_error(status);

        ecc_reg.fields.mp_data_table_ecc_1b_err_initiate = 0;
        status = m_ll_device->write_register(m_gb_tree->npuh->host->ecc_1b_err_initiate_register, ecc_reg);
        return_on_error(status);
    } else {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    return status;
}

static void
populate_ip_inactivity_table_key(la_vrf_gid_t vrf_gid,
                                 la_ipv4_addr_t ip_addr,
                                 uint32_t length,
                                 npl_ip_inactivity_check_table_key_t& out_key)
{
    out_key.ip_version = NPL_IP_VERSION_IPV4;
    out_key.vrf_id = vrf_gid;
    out_key.ip_address_msb = ((ip_addr.s_addr >> 12) & 0xfffff);
}

static void
populate_ip_inactivity_table_key(la_vrf_gid_t vrf_gid,
                                 la_ipv6_addr_t ip_addr,
                                 uint32_t length,
                                 npl_ip_inactivity_check_table_key_t& out_key)
{
    out_key.ip_version = NPL_IP_VERSION_IPV6;
    out_key.vrf_id = vrf_gid;
    out_key.ip_address_msb = ((ip_addr.q_addr[1] >> 44) & 0xfffff);
}

template <class _PrefixType>
la_status
la_device_impl::configure_ip_inactivity_entry(la_vrf_gid_t vrf_gid, _PrefixType prefix, bool add)
{
    const auto& table(m_tables.ip_inactivity_check_table);
    npl_ip_inactivity_check_table_t::key_type k;
    npl_ip_inactivity_check_table_t::key_type m;
    npl_ip_inactivity_check_table_t::value_type v;
    npl_ip_inactivity_check_table_t::entry_pointer_type e = nullptr;
    uint32_t mask;

    memset(&m, 0xff, sizeof(m));

    v.payloads.ip_inactivity_punt = add ? 1 : 0;
    populate_ip_inactivity_table_key(vrf_gid, prefix.addr, prefix.length, k);

    // Monitoring max 20 bits from the IP (MSB).
    mask = ~((1 << (20 - prefix.length)) - 1);
    m.ip_address_msb &= mask;

    v.action = NPL_IP_INACTIVITY_CHECK_TABLE_ACTION_WRITE;

    la_status status;
    size_t location = 0;
    bool found = false;

    status = table->find(k, m, e, location);
    if (status == LA_STATUS_SUCCESS) {
        found = true;
    }

    if (add) {
        if (found) {
            return LA_STATUS_SUCCESS;
        }

        location = 0;
        status = table->locate_first_free_entry(location);
        return_on_error(status);
        status = table->insert(location, k, m, v, e);
        return status;
    } else {
        if (found) {
            status = table->erase(location);
            return_on_error(status);
        }
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::add_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv4_prefix_t prefix)
{
    start_api_call("vrf=", vrf, "prefix=", prefix);

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (prefix.length > 20) {
        return LA_STATUS_EINVAL;
    }

    return configure_ip_inactivity_entry(vrf->get_gid(), prefix, true);
}

la_status
la_device_impl::remove_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv4_prefix_t prefix)
{
    start_api_call("vrf=", vrf, "prefix=", prefix);

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (prefix.length > 20) {
        return LA_STATUS_EINVAL;
    }

    return configure_ip_inactivity_entry(vrf->get_gid(), prefix, false);
}

la_status
la_device_impl::add_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv6_prefix_t prefix)
{
    start_api_call("vrf=", vrf, "prefix=", prefix);

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (prefix.length > 20) {
        return LA_STATUS_EINVAL;
    }

    return configure_ip_inactivity_entry(vrf->get_gid(), prefix, true);
}

la_status
la_device_impl::remove_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv6_prefix_t prefix)
{
    start_api_call("vrf=", vrf, "prefix=", prefix);

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (prefix.length > 20) {
        return LA_STATUS_EINVAL;
    }

    return configure_ip_inactivity_entry(vrf->get_gid(), prefix, false);
}

la_status
la_device_impl::get_source_ip_snooping_prefixes(la_ip_snooping_entry_vec_t& out_ip_snooping_prefixes)
{
    start_api_getter_call();
    size_t entries_total = m_tables.ip_inactivity_check_table->size();
    vector_alloc<npl_ip_inactivity_check_table_t::entry_pointer_type> entries(entries_total, nullptr);
    size_t entries_num = m_tables.ip_inactivity_check_table->get_entries(&entries[0], entries_total);
    dassert_ncrit(entries_num <= entries_total);

    for (size_t i = 0; i < entries_num; i++) {
        npl_ip_inactivity_check_table_t::key_type k(entries[i]->key());
        npl_ip_inactivity_check_table_t::value_type v(entries[i]->value());
        la_ip_snooping_entry_t record{};

        record.ip_inactivity_punt = v.payloads.ip_inactivity_punt;
        record.vrf_gid = k.vrf_id;
        if (k.ip_version == NPL_IP_VERSION_IPV4) {
            record.ip_version = la_ip_version_e::IPV4;
            record.prefix.ipv4.addr.s_addr = k.ip_address_msb;
        } else {
            record.ip_version = la_ip_version_e::IPV6;
            record.prefix.ipv6.addr.s_addr = k.ip_address_msb;
        }

        out_ip_snooping_prefixes.push_back(record);
    }
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one

extern std::recursive_mutex m_device_creation_mutex;

static la_status
do_warm_boot_restore(const char* device_path,
                     const char* warm_boot_file,
                     const silicon_one::la_platform_cbs& platform_cbs,
                     silicon_one::la_device*& out_device)
{
#if ENABLE_SERIALIZATION
    if (device_path == nullptr) {
        log_err(API, "%s: NULL device.", __func__);
        return LA_STATUS_EINVAL;
    }

    if (warm_boot_file == nullptr) {
        log_err(API, "%s NULL state file path.", __func__);
        return LA_STATUS_EINVAL;
    }

    // don't allow unbound input strings
    char tmp_s[FILENAME_MAX];
    strncpy(tmp_s, warm_boot_file, sizeof(tmp_s) - 1);
    tmp_s[sizeof(tmp_s) - 1] = '\0';
    std::string dev_state_path(tmp_s);

    strncpy(tmp_s, device_path, sizeof(tmp_s) - 1);
    tmp_s[sizeof(tmp_s) - 1] = '\0';
    std::string dev_path(tmp_s);

    log_debug(API,
              "%s(device_path='%s' warm_boot_file='%s' cbs=%s) #SDK version is %s#",
              __func__,
              dev_path.c_str(),
              dev_state_path.c_str(),
              get_value_string(platform_cbs).c_str(),
              la_get_version_string());

    // TODO: For now serialize as base class (la_device) to workaround Cereal polymorphism issue
    silicon_one::la_device_sptr base_device;
    std::ifstream dev_state_file(warm_boot_file, CEREAL_INPUT_STREAM_MODE_FLAGS);
    cereal_input_archive_class archive(dev_state_file);

    // Before deserializing la_device (and all SDK objects) validate WB compatibility
    std::string base_wb_version;
    la_uint32_t base_wb_revision;
    archive(base_wb_version);
    archive(base_wb_revision);

    if (base_wb_version != silicon_one::WB_VERSION) {
        log_err(API,
                "%s: WB versions are incompatible, base WB version %s, current WB version: %s",
                __func__,
                base_wb_version.c_str(),
                silicon_one::WB_VERSION);
        return LA_STATUS_ENOTINITIALIZED;
    }

    if (base_wb_revision > silicon_one::WB_REVISION) {
        log_err(API,
                "%s: Base WB revision (%u) is newer than current SDK WB revision (%u)",
                __func__,
                base_wb_revision,
                silicon_one::WB_REVISION);
        return LA_STATUS_ENOTINITIALIZED;
    }

    if (base_wb_revision < silicon_one::WB_MIN_REVISION) {
        log_err(
            API,
            "%s: Current SDK WB revision (%u) is not upgradable from base SDK WB revision (%u), minimum supported revision is: %u",
            __func__,
            silicon_one::WB_REVISION,
            base_wb_revision,
            silicon_one::WB_MIN_REVISION);
        return LA_STATUS_ENOTINITIALIZED;
    }

    // Set the serialization version for all SDK components
    silicon_one::warm_boot_set_serialization_version(base_wb_revision);

    // Deserialize la_device
    archive(base_device);
    if (!base_device) {
        return LA_STATUS_ENODEV;
    }

    silicon_one::la_device_impl_sptr device = static_pointer_cast<silicon_one::la_device_impl>(base_device);
    la_status rc = device->warm_boot_restore(dev_path, platform_cbs);
    if (rc != LA_STATUS_SUCCESS) {
        return rc;
    }

    auto dev_id = device->get_id();
    silicon_one::la_lock_guard<std::recursive_mutex> lock(m_device_creation_mutex, dev_id);

    if (dev_id >= silicon_one::la_device_impl::MAX_DEVICES) {
        return LA_STATUS_EUNKNOWN;
    }

    if (m_devices[dev_id] != nullptr) {
        return LA_STATUS_EEXIST;
    }
    m_devices[dev_id] = device;
    out_device = device.get();

    return LA_STATUS_SUCCESS;
#else
    return LA_STATUS_ENOTIMPLEMENTED;
#endif
}

la_status
la_warm_boot_restore(const char* device_path,
                     const char* warm_boot_file,
                     const silicon_one::la_platform_cbs& platform_cbs,
                     silicon_one::la_device*& out_device)
{
    la_status rc = do_warm_boot_restore(device_path, warm_boot_file, platform_cbs, out_device);

    if (rc != LA_STATUS_SUCCESS) {
        // log flushing mechanism might have not been started.
        silicon_one::la_flush_log();
    }

    return rc;
}

la_status
la_warm_boot_restore(const char* device_path, const char* warm_boot_file, silicon_one::la_device*& out_device)
{
    silicon_one::la_platform_cbs cbs = {.user_data = 0,
                                        .i2c_register_access = nullptr,
                                        .dma_alloc = nullptr,
                                        .dma_free = nullptr,
                                        .open_device = nullptr,
                                        .close_device = nullptr};

    la_status rc = do_warm_boot_restore(device_path, warm_boot_file, cbs, out_device);

    if (rc != LA_STATUS_SUCCESS) {
        // log flushing mechanism might have not been started.
        silicon_one::la_flush_log();
    }

    return rc;
}

static la_status
do_warm_boot_save_and_destroy(silicon_one::la_device* device,
                              la_uint32_t target_wb_revision,
                              const char* warm_boot_file,
                              bool free_objects)

{
#if ENABLE_SERIALIZATION
    if (!device) {
        log_err(API, "%s: NULL device.", __func__);
        return LA_STATUS_EINVAL;
    }

    if (!warm_boot_file) {
        log_err(API, "%s: NULL state file path.", __func__);
        return LA_STATUS_EINVAL;
    }

    la_device_id_t dev_id = device->get_id();

    silicon_one::la_lock_guard<std::recursive_mutex> lock(m_device_creation_mutex, dev_id);

    log_debug(API, "%s(device= %s)#dev_id=%u#", __func__, get_value_string(device).c_str(), dev_id);

    auto la_device_impl = static_cast<silicon_one::la_device_impl*>(device);

    // don't allow unbound input strings
    char tmp_s[FILENAME_MAX];
    strncpy(tmp_s, warm_boot_file, sizeof(tmp_s) - 1);
    tmp_s[sizeof(tmp_s) - 1] = '\0';
    std::string dev_state_path(tmp_s);

    la_status rc = la_device_impl->warm_boot_save_and_destroy(dev_state_path, free_objects, target_wb_revision);
    if (rc != LA_STATUS_SUCCESS) {
        return rc;
    }

    if (free_objects) {
        m_devices[dev_id].reset();
    }

    // Log flushing task is stopped, need to flush expicitly.
    silicon_one::la_flush_log();

    return LA_STATUS_SUCCESS;
#else
    return LA_STATUS_ENOTIMPLEMENTED;
#endif
}

la_status
la_warm_boot_save_and_destroy(silicon_one::la_device* device, const char* warm_boot_file, bool free_objects)
{
    return do_warm_boot_save_and_destroy(device, silicon_one::WB_REVISION, warm_boot_file, free_objects);
}

la_status
la_warm_boot_rollback_save_and_destroy(silicon_one::la_device* device,
                                       std::string target_sdk_version,
                                       const char* warm_boot_file,
                                       bool free_objects)
{
    la_uint32_t target_wb_revision;

    if (target_sdk_version == la_get_version_string()) {
        log_err(API,
                "%s: Can't rollback from SDK version %s to itself, please use 'la_warm_boot_save_and_destroy()' instead",
                __func__,
                target_sdk_version.c_str());
        return LA_STATUS_EINVAL;
    }

    la_status status = silicon_one::sdk_version_to_wb_revision(target_sdk_version, target_wb_revision);
    if (status != LA_STATUS_SUCCESS) {
        log_err(API,
                "%s: Can't rollback to SDK version: %s, it is not WB compatible with current SDK version.",
                __func__,
                target_sdk_version.c_str());
        return LA_STATUS_EINVAL;
    }

    if (target_wb_revision >= silicon_one::WB_REVISION) {
        log_err(API,
                "%s: Can't rollback to a newer WB revision, current WB revision: %u, target WB revision: %u.",
                __func__,
                silicon_one::WB_REVISION,
                target_wb_revision);
        return LA_STATUS_EINVAL;
    }

    status = do_warm_boot_save_and_destroy(device, target_wb_revision, warm_boot_file, free_objects);
    return status;
}
