#define AUTO_SERIALIZE_CODE
#include "common/cereal_utils.h"

#ifdef CEREAL_DISABLE_OPTIMIZATION
// Disable optimizations as clang, GCC choke on this file in -O3 mode.
#ifdef __GNUC__
    #ifdef __clang__
        #pragma clang optimize off
    #else
        #pragma GCC optimize ("O0")
    #endif
#endif
#endif
#if CEREAL_MODE == CEREAL_MODE_BINARY
#include <cereal/archives/binary.hpp>
#elif CEREAL_MODE == CEREAL_MODE_JSON
#include <cereal/archives/json.hpp>
#elif CEREAL_MODE == CEREAL_MODE_XML
#include <cereal/archives/xml.hpp>
#endif
#include <cereal/types/array.hpp>
#include <cereal/types/atomic.hpp>
#include <cereal/types/base_class.hpp>
#include <cereal/types/bitset.hpp>
#include <cereal/types/chrono.hpp>
#include <cereal/types/forward_list.hpp>
#include <cereal/types/functional.hpp>
#include <cereal/types/list.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/polymorphic.hpp>
#include <cereal/types/queue.hpp>
#include <cereal/types/set.hpp>
#include <cereal/types/stack.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/tuple.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/unordered_set.hpp>
#include <cereal/types/utility.hpp>
#include <cereal/types/vector.hpp>

#include "hld/runtime_flexibility_library.h"
#include "hld/runtime_flexibility_types.h"
#include "cgm/la_rx_cgm_sq_profile_impl.h"
#include "cgm/la_voq_cgm_profile_impl.h"
#include "cgm/rx_cgm_handler.h"
#include "cgm/voq_cgm_handler.h"
#include "hld_serialization.h"
#include "hld_types.h"
#include "ifg_use_count.h"
#include "npu/ipv4_sip_index_manager.h"
#include "npu/ipv4_tunnel_ep_manager.h"
#include "npu/la_ac_port_common.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_acl_delegate.h"
#include "npu/la_acl_egress_sec_ipv4.h"
#include "npu/la_acl_egress_sec_ipv6.h"
#include "npu/la_acl_generic.h"
#include "npu/la_acl_impl.h"
#include "npu/la_acl_scaled_delegate.h"
#include "npu/la_acl_scaled_impl.h"
#include "npu/la_asbr_lsp_impl.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_destination_pe_impl.h"
#include "npu/la_ecmp_group_impl.h"
#include "npu/la_fabric_multicast_group_impl.h"
#include "npu/la_filter_group_impl.h"
#include "npu/la_forus_destination_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_gue_port_impl.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_ip_tunnel_destination_impl.h"
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
#include "npu/la_next_hop_impl_common.h"
#include "npu/la_og_lpts_application_impl.h"
#include "npu/la_pbts_group_impl.h"
#include "npu/la_pcl_impl.h"
#include "npu/la_protection_monitor_impl.h"
#include "npu/la_switch_impl.h"
#include "npu/la_te_tunnel_impl.h"
#include "npu/la_vrf_impl.h"
#include "npu/mac_address_manager.h"
#include "npu/mc_copy_id_manager.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_action_profile_impl.h"
#include "qos/la_meter_markdown_profile_impl.h"
#include "qos/la_meter_profile_impl.h"
#include "qos/la_meter_set_exact_impl.h"
#include "qos/la_meter_set_impl.h"
#include "qos/la_meter_set_statistical_impl.h"
#include "system/arc_handler_pacific.h"
#include "system/counter_allocation.h"
#include "system/counter_bank_utils.h"
#include "system/counter_logical_bank.h"
#include "system/counter_manager.h"
#include "system/cud_range_manager.h"
#include "system/fabric_init_handler.h"
#include "system/la_device_impl.h"
#include "system/la_fabric_port_impl.h"
#include "system/la_hbm_handler_impl.h"
#include "system/la_l2_punt_destination_impl.h"
#include "system/la_npu_host_destination_impl.h"
#include "system/la_pbts_map_profile_impl.h"
#include "system/la_remote_port_impl.h"
#include "system/mac_pool2_port.h"
#include "system/mac_pool8_port.h"
#include "system/mac_pool_port.h"
#include "system/npu_static_config.h"
#include "system/pacific_mac_pool.h"
#include "system/pacific_pvt_handler.h"
#include "system/pvt_handler.h"
#include "system/ranged_sequential_indices_generator.h"
#include "system/reconnect_handler.h"
#include "system/reconnect_metadata.h"
#include "system/resource_handler.h"
#include "system/serdes_device_handler.h"
#include "tm/la_fabric_port_scheduler_impl.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/la_logical_port_scheduler_impl.h"
#include "tm/la_output_queue_scheduler_impl.h"
#include "tm/la_system_port_scheduler_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/la_voq_set_impl.h"
#include "tm/tm_utils.h"
#include "tm/voq_counter_set.h"
#include "../device_context/la_slice_mapper_base.h"
#include "npu/copc_protocol_manager_base.h"
#include "npu/copc_protocol_manager_pacific.h"
#include "npu/la_acl_command_profile_base.h"
#include "npu/la_acl_group_base.h"
#include "npu/la_acl_group_pacific.h"
#include "npu/la_acl_key_profile_base.h"
#include "npu/la_acl_key_profile_pacific.h"
#include "npu/la_bfd_session_base.h"
#include "npu/la_bfd_session_pacific.h"
#include "npu/la_copc_base.h"
#include "npu/la_copc_pacific.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ethernet_port_pacific.h"
#include "npu/la_ip_multicast_group_base.h"
#include "npu/la_ip_multicast_group_pacific.h"
#include "npu/la_l2_multicast_group_base.h"
#include "npu/la_l2_multicast_group_pacific.h"
#include "npu/la_l2_protection_group_base.h"
#include "npu/la_l2_protection_group_pacific.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l2_service_port_pacgb.h"
#include "npu/la_l2_service_port_pacific.h"
#include "npu/la_multicast_group_common_base.h"
#include "npu/la_multicast_group_common_pacific.h"
#include "npu/la_multicast_protection_group_base.h"
#include "npu/la_multicast_protection_monitor_base.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_next_hop_pacgb.h"
#include "npu/la_next_hop_pacific.h"
#include "npu/la_prefix_object_base.h"
#include "npu/la_prefix_object_pacific.h"
#include "npu/la_rate_limiter_set_base.h"
#include "npu/la_rate_limiter_set_pacific.h"
#include "npu/la_security_group_cell_base.h"
#include "npu/la_security_group_cell_pacific.h"
#include "npu/la_stack_port_base.h"
#include "npu/la_stack_port_pacific.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_svi_port_pacific.h"
#include "npu/la_vrf_port_common_base.h"
#include "npu/la_vrf_port_common_pacgb.h"
#include "npu/la_vrf_port_common_pacific.h"
#include "npu/la_vxlan_next_hop_base.h"
#include "npu/la_vxlan_next_hop_pacific.h"
#include "qos/la_meter_set_base.h"
#include "system/arc_handler_base.h"
#include "system/device_configurator_base.h"
#include "system/device_port_handler_base.h"
#include "system/device_port_handler_pacific.h"
#include "system/dummy_serdes_device_handler_base.h"
#include "system/dummy_serdes_handler_base.h"
#include "system/hld_notification_base.h"
#include "system/hld_notification_pacific.h"
#include "system/ifg_handler.h"
#include "system/ifg_handler_base.h"
#include "system/ifg_handler_ifg.h"
#include "system/ifg_handler_pacific.h"
#include "system/init_performance_helper_base.h"
#include "system/la_device_impl_base.h"
#include "system/la_erspan_mirror_command_base.h"
#include "system/la_erspan_mirror_command_pacific.h"
#include "system/la_l2_mirror_command_base.h"
#include "system/la_l2_mirror_command_pacgb.h"
#include "system/la_l2_mirror_command_pacific.h"
#include "system/la_mac_port_base.h"
#include "system/la_mac_port_pacgb.h"
#include "system/la_mac_port_pacific.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_npu_host_port_pacific.h"
#include "system/la_pci_port_base.h"
#include "system/la_pci_port_pacific.h"
#include "system/la_ptp_handler_base.h"
#include "system/la_ptp_handler_pacific.h"
#include "system/la_punt_inject_port_base.h"
#include "system/la_punt_inject_port_pacgb.h"
#include "system/la_punt_inject_port_pacific.h"
#include "system/la_recycle_port_base.h"
#include "system/la_recycle_port_pacific.h"
#include "system/la_remote_device_base.h"
#include "system/la_spa_port_base.h"
#include "system/la_spa_port_pacgb.h"
#include "system/la_spa_port_pacific.h"
#include "system/la_system_port_base.h"
#include "system/la_system_port_pacgb.h"
#include "system/la_system_port_pacific.h"
#include "system/npu_host_event_queue_base.h"
#include "system/npu_host_event_queue_pacific.h"
#include "system/serdes_handler.h"
#include "system/slice_id_manager_base.h"
#include "system/slice_manager_smart_ptr_base.h"
#include "system/slice_mapping_base.h"
#include "tm/la_voq_set_base.h"

template <class T>
static T&
cereal_gen_remove_const(const T& t)
{
    return const_cast<T&>(t);
}

#define CEREAL_GEN_COPY_ARRAY(from, to, size) \
for (size_t i = 0; i < size; ++i) {\
    to[i] = from[i];\
}

#define CEREAL_GEN_COMMA() ,
namespace cereal {
    template <class Archive, class T>
    struct specialize<Archive, silicon_one::fixed_deque<T>, specialization::member_serialize> {};
}
#include "api/tm/la_unicast_tc_profile.h"
#include "apb/apb.h"
#include "cpu2jtag/cpu2jtag.h"
#include "system/cud_range_manager.h"
#include "system/reconnect_handler.h"
#include "system/resource_handler.h"
#include "system/counter_allocation.h"
#include "cgm/voq_cgm_handler.h"
#include "ra/resource_manager.h"
#include "api/tm/la_unicast_tc_profile.h"
#include "apb/apb.h"
// Manulal registration of polymorphic templates, not supported by the tool
namespace cereal {
template <class Archive> void save(Archive&, const silicon_one::delayed_ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::delayed_ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::bfd_packet_intervals&);
template <class Archive> void load(Archive&, silicon_one::bfd_packet_intervals&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const bfd_rx_entry_data_t&);
template <class Archive> void load(Archive&, bfd_rx_entry_data_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl::oam_encap_info_t&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl::oam_encap_info_t&);

template <class Archive> void save(Archive&, const npl_lpts_payload_t&);
template <class Archive> void load(Archive&, npl_lpts_payload_t&);

template <class Archive> void save(Archive&, const l2_slp_acl_info_t&);
template <class Archive> void load(Archive&, l2_slp_acl_info_t&);

template <class Archive> void save(Archive&, const silicon_one::acl_group_info_t&);
template <class Archive> void load(Archive&, silicon_one::acl_group_info_t&);

}

CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::ipv4_sip_index_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::l3vxlan_smac_msb_index_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::npu_host_max_ccm_counters_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::npu_host_packet_intervals_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::bfd_local_ipv6_addresses_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::npu_host_detection_times_profile_allocator)
// The tool does generate a proper registration for profile_allocators::lpts_meters_profile_allocator
//CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::lpts_meters_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::lpts_em_entries_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::bfd_rx_entries_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::oam_punt_encap_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::l2_slp_acl_indices_profile_allocator)
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::acl_group_entries_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_ipv4_prefix_t>,
			             silicon_one::la_device_impl::profile_allocators::ipv4_sip_index_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<la_uint32_t>,
                                     silicon_one::la_device_impl::profile_allocators::l3vxlan_smac_msb_index_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<std::chrono::microseconds>,
                                     silicon_one::la_device_impl::profile_allocators::npu_host_max_ccm_counters_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::bfd_packet_intervals>,
                                     silicon_one::la_device_impl::profile_allocators::npu_host_packet_intervals_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_ipv6_addr_t>,
                                     silicon_one::la_device_impl::profile_allocators::bfd_local_ipv6_addresses_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<std::chrono::microseconds>,
                                     silicon_one::la_device_impl::profile_allocators::npu_host_detection_times_profile_allocator)
//CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_meter_set_wcptr>,
//                                     silicon_one::la_device_impl::profile_allocators::lpts_meters_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_device_impl::profile_allocators::lpts_em_entry_data>,
                                     silicon_one::la_device_impl::profile_allocators::lpts_em_entries_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<bfd_rx_entry_data_t>,
                                     silicon_one::la_device_impl::profile_allocators::bfd_rx_entries_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::la_device_impl::oam_encap_info_t>,
                                     silicon_one::la_device_impl::profile_allocators::oam_punt_encap_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<l2_slp_acl_info_t>,
                                     silicon_one::la_device_impl::profile_allocators::l2_slp_acl_indices_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::acl_group_info_t>,
                                     silicon_one::la_device_impl::profile_allocators::acl_group_entries_profile_allocator)
#include "hld/hld_serialized_fwd_declarations.h"

namespace cereal {

extern unsigned g_hld_serialization_version;

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::ll_device&);
template <class Archive> void load(Archive&, silicon_one::ll_device&);

template <class Archive> void save(Archive&, const silicon_one::lld_memory&);
template <class Archive> void load(Archive&, silicon_one::lld_memory&);

template <class Archive> void save(Archive&, const silicon_one::lld_register&);
template <class Archive> void load(Archive&, silicon_one::lld_register&);

template <class Archive> void save(Archive&, const silicon_one::lld_register_array_container&);
template <class Archive> void load(Archive&, silicon_one::lld_register_array_container&);

template <class Archive> void save(Archive&, const silicon_one::mac_pool_port&);
template <class Archive> void load(Archive&, silicon_one::mac_pool_port&);

template <class Archive> void save(Archive&, const silicon_one::pacific_tree&);
template <class Archive> void load(Archive&, silicon_one::pacific_tree&);

template <class Archive> void save(Archive&, const std::chrono::_V2::steady_clock&);
template <class Archive> void load(Archive&, std::chrono::_V2::steady_clock&);

template<>
class serializer_class<silicon_one::mac_pool_port::fec_engine_config_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::mac_pool_port::fec_engine_config_data& m) {
            archive(::cereal::make_nvp("fec_lane_per_engine", m.fec_lane_per_engine));
            archive(::cereal::make_nvp("fec_engine_count", m.fec_engine_count));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::mac_pool_port::fec_engine_config_data& m) {
            archive(::cereal::make_nvp("fec_lane_per_engine", m.fec_lane_per_engine));
            archive(::cereal::make_nvp("fec_engine_count", m.fec_engine_count));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::mac_pool_port::fec_engine_config_data& m)
{
    serializer_class<silicon_one::mac_pool_port::fec_engine_config_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mac_pool_port::fec_engine_config_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::mac_pool_port::fec_engine_config_data& m)
{
    serializer_class<silicon_one::mac_pool_port::fec_engine_config_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mac_pool_port::fec_engine_config_data&);



template<>
class serializer_class<silicon_one::mac_pool_port::serdes_param_setting> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::mac_pool_port::serdes_param_setting& m) {
            archive(::cereal::make_nvp("mode", m.mode));
            archive(::cereal::make_nvp("value", m.value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::mac_pool_port::serdes_param_setting& m) {
            archive(::cereal::make_nvp("mode", m.mode));
            archive(::cereal::make_nvp("value", m.value));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::mac_pool_port::serdes_param_setting& m)
{
    serializer_class<silicon_one::mac_pool_port::serdes_param_setting>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mac_pool_port::serdes_param_setting&);

template <class Archive>
void
load(Archive& archive, silicon_one::mac_pool_port::serdes_param_setting& m)
{
    serializer_class<silicon_one::mac_pool_port::serdes_param_setting>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mac_pool_port::serdes_param_setting&);



template<>
class serializer_class<silicon_one::mac_pool_port::sm_state_transition> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::mac_pool_port::sm_state_transition& m) {
            archive(::cereal::make_nvp("new_state", m.new_state));
            archive(::cereal::make_nvp("timestamp", m.timestamp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::mac_pool_port::sm_state_transition& m) {
            archive(::cereal::make_nvp("new_state", m.new_state));
            archive(::cereal::make_nvp("timestamp", m.timestamp));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::mac_pool_port::sm_state_transition& m)
{
    serializer_class<silicon_one::mac_pool_port::sm_state_transition>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::mac_pool_port::sm_state_transition&);

template <class Archive>
void
load(Archive& archive, silicon_one::mac_pool_port::sm_state_transition& m)
{
    serializer_class<silicon_one::mac_pool_port::sm_state_transition>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::mac_pool_port::sm_state_transition&);



template<>
class serializer_class<silicon_one::npu_static_config> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::npu_static_config& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_slice_config", m.m_slice_config));
            archive(::cereal::make_nvp("m_reg_vals", m.m_reg_vals));
            archive(::cereal::make_nvp("m_mem_vals", m.m_mem_vals));
            archive(::cereal::make_nvp("m_mem_line_vals", m.m_mem_line_vals));
            archive(::cereal::make_nvp("m_tcam_line_vals", m.m_tcam_line_vals));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_tree", m.m_tree));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::npu_static_config& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_slice_config", m.m_slice_config));
            archive(::cereal::make_nvp("m_reg_vals", m.m_reg_vals));
            archive(::cereal::make_nvp("m_mem_vals", m.m_mem_vals));
            archive(::cereal::make_nvp("m_mem_line_vals", m.m_mem_line_vals));
            archive(::cereal::make_nvp("m_tcam_line_vals", m.m_tcam_line_vals));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_tree", m.m_tree));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::npu_static_config& m)
{
    serializer_class<silicon_one::npu_static_config>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::npu_static_config&);

template <class Archive>
void
load(Archive& archive, silicon_one::npu_static_config& m)
{
    serializer_class<silicon_one::npu_static_config>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::npu_static_config&);



template<>
class serializer_class<silicon_one::npu_static_config::slice_config> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::npu_static_config::slice_config& m) {
            archive(::cereal::make_nvp("slice_mode", m.slice_mode));
            archive(::cereal::make_nvp("sna_slice_mode", m.sna_slice_mode));
            archive(::cereal::make_nvp("is_slb_enabled", m.is_slb_enabled));
            archive(::cereal::make_nvp("is_egress_tor", m.is_egress_tor));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::npu_static_config::slice_config& m) {
            archive(::cereal::make_nvp("slice_mode", m.slice_mode));
            archive(::cereal::make_nvp("sna_slice_mode", m.sna_slice_mode));
            archive(::cereal::make_nvp("is_slb_enabled", m.is_slb_enabled));
            archive(::cereal::make_nvp("is_egress_tor", m.is_egress_tor));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::npu_static_config::slice_config& m)
{
    serializer_class<silicon_one::npu_static_config::slice_config>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::npu_static_config::slice_config&);

template <class Archive>
void
load(Archive& archive, silicon_one::npu_static_config::slice_config& m)
{
    serializer_class<silicon_one::npu_static_config::slice_config>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::npu_static_config::slice_config&);



template<>
class serializer_class<silicon_one::pacific_mac_pool> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::pacific_mac_pool& m) {
            archive(::cereal::make_nvp("m_mac_pool_regs", m.m_mac_pool_regs));
            archive(::cereal::make_nvp("m_mac_pool_counters", m.m_mac_pool_counters));
            archive(::cereal::make_nvp("m_mac_pool_interrupt_regs", m.m_mac_pool_interrupt_regs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::pacific_mac_pool& m) {
            archive(::cereal::make_nvp("m_mac_pool_regs", m.m_mac_pool_regs));
            archive(::cereal::make_nvp("m_mac_pool_counters", m.m_mac_pool_counters));
            archive(::cereal::make_nvp("m_mac_pool_interrupt_regs", m.m_mac_pool_interrupt_regs));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::pacific_mac_pool& m)
{
    archive(cereal::base_class<silicon_one::mac_pool_port>(&m));
    serializer_class<silicon_one::pacific_mac_pool>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::pacific_mac_pool&);

template <class Archive>
void
load(Archive& archive, silicon_one::pacific_mac_pool& m)
{
    archive(cereal::base_class<silicon_one::mac_pool_port>(&m));
    serializer_class<silicon_one::pacific_mac_pool>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::pacific_mac_pool&);



template<>
class serializer_class<silicon_one::pacific_mac_pool::_mac_pool_regs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::pacific_mac_pool::_mac_pool_regs_t& m) {
            archive(::cereal::make_nvp("counter_timer", m.counter_timer));
            archive(::cereal::make_nvp("counter_timer_trigger_reg", m.counter_timer_trigger_reg));
            archive(::cereal::make_nvp("rsf_ck_cycles_per_1ms_reg", m.rsf_ck_cycles_per_1ms_reg));
            archive(::cereal::make_nvp("am_cfg", m.am_cfg));
            archive(::cereal::make_nvp("mac_lanes_loopback_register", m.mac_lanes_loopback_register));
            archive(::cereal::make_nvp("pma_loopback_register", m.pma_loopback_register));
            archive(::cereal::make_nvp("rsf_degraded_ser_cfg0", m.rsf_degraded_ser_cfg0));
            archive(::cereal::make_nvp("rx_ber_fsm_cfg", m.rx_ber_fsm_cfg));
            archive(::cereal::make_nvp("rx_cfg0", m.rx_cfg0));
            archive(::cereal::make_nvp("rx_high_ser_fsm_cfg", m.rx_high_ser_fsm_cfg));
            archive(::cereal::make_nvp("rx_krf_status", m.rx_krf_status));
            archive(::cereal::make_nvp("rx_krf_cfg", m.rx_krf_cfg));
            archive(::cereal::make_nvp("rx_mac_cfg0", m.rx_mac_cfg0));
            archive(::cereal::make_nvp("rx_mac_cfg1", m.rx_mac_cfg1));
            archive(::cereal::make_nvp("rx_pcs_test_cfg0", m.rx_pcs_test_cfg0));
            archive(::cereal::make_nvp("rx_pma_test_cfg0", m.rx_pma_test_cfg0));
            archive(::cereal::make_nvp("rx_rsf_cfg0", m.rx_rsf_cfg0));
            archive(::cereal::make_nvp("rx_status_register", m.rx_status_register));
            archive(::cereal::make_nvp("rx_status_lane_mapping", m.rx_status_lane_mapping));
            archive(::cereal::make_nvp("tx_cfg0", m.tx_cfg0));
            archive(::cereal::make_nvp("tx_mac_cfg0", m.tx_mac_cfg0));
            archive(::cereal::make_nvp("tx_mac_ctrl_sa", m.tx_mac_ctrl_sa));
            archive(::cereal::make_nvp("tx_mac_cfg_ipg", m.tx_mac_cfg_ipg));
            archive(::cereal::make_nvp("tx_mac_fc_per_xoff_timer", m.tx_mac_fc_per_xoff_timer));
            archive(::cereal::make_nvp("tx_mac_fc_xoff_timer", m.tx_mac_fc_xoff_timer));
            archive(::cereal::make_nvp("tx_mac_fc_per_xon_timer", m.tx_mac_fc_per_xon_timer));
            archive(::cereal::make_nvp("tx_mac_fc_xon_timer", m.tx_mac_fc_xon_timer));
            archive(::cereal::make_nvp("tx_pcs_test_cfg0", m.tx_pcs_test_cfg0));
            archive(::cereal::make_nvp("tx_pma_test_cfg0", m.tx_pma_test_cfg0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::pacific_mac_pool::_mac_pool_regs_t& m) {
            archive(::cereal::make_nvp("counter_timer", m.counter_timer));
            archive(::cereal::make_nvp("counter_timer_trigger_reg", m.counter_timer_trigger_reg));
            archive(::cereal::make_nvp("rsf_ck_cycles_per_1ms_reg", m.rsf_ck_cycles_per_1ms_reg));
            archive(::cereal::make_nvp("am_cfg", m.am_cfg));
            archive(::cereal::make_nvp("mac_lanes_loopback_register", m.mac_lanes_loopback_register));
            archive(::cereal::make_nvp("pma_loopback_register", m.pma_loopback_register));
            archive(::cereal::make_nvp("rsf_degraded_ser_cfg0", m.rsf_degraded_ser_cfg0));
            archive(::cereal::make_nvp("rx_ber_fsm_cfg", m.rx_ber_fsm_cfg));
            archive(::cereal::make_nvp("rx_cfg0", m.rx_cfg0));
            archive(::cereal::make_nvp("rx_high_ser_fsm_cfg", m.rx_high_ser_fsm_cfg));
            archive(::cereal::make_nvp("rx_krf_status", m.rx_krf_status));
            archive(::cereal::make_nvp("rx_krf_cfg", m.rx_krf_cfg));
            archive(::cereal::make_nvp("rx_mac_cfg0", m.rx_mac_cfg0));
            archive(::cereal::make_nvp("rx_mac_cfg1", m.rx_mac_cfg1));
            archive(::cereal::make_nvp("rx_pcs_test_cfg0", m.rx_pcs_test_cfg0));
            archive(::cereal::make_nvp("rx_pma_test_cfg0", m.rx_pma_test_cfg0));
            archive(::cereal::make_nvp("rx_rsf_cfg0", m.rx_rsf_cfg0));
            archive(::cereal::make_nvp("rx_status_register", m.rx_status_register));
            archive(::cereal::make_nvp("rx_status_lane_mapping", m.rx_status_lane_mapping));
            archive(::cereal::make_nvp("tx_cfg0", m.tx_cfg0));
            archive(::cereal::make_nvp("tx_mac_cfg0", m.tx_mac_cfg0));
            archive(::cereal::make_nvp("tx_mac_ctrl_sa", m.tx_mac_ctrl_sa));
            archive(::cereal::make_nvp("tx_mac_cfg_ipg", m.tx_mac_cfg_ipg));
            archive(::cereal::make_nvp("tx_mac_fc_per_xoff_timer", m.tx_mac_fc_per_xoff_timer));
            archive(::cereal::make_nvp("tx_mac_fc_xoff_timer", m.tx_mac_fc_xoff_timer));
            archive(::cereal::make_nvp("tx_mac_fc_per_xon_timer", m.tx_mac_fc_per_xon_timer));
            archive(::cereal::make_nvp("tx_mac_fc_xon_timer", m.tx_mac_fc_xon_timer));
            archive(::cereal::make_nvp("tx_pcs_test_cfg0", m.tx_pcs_test_cfg0));
            archive(::cereal::make_nvp("tx_pma_test_cfg0", m.tx_pma_test_cfg0));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::pacific_mac_pool::_mac_pool_regs_t& m)
{
    serializer_class<silicon_one::pacific_mac_pool::_mac_pool_regs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::pacific_mac_pool::_mac_pool_regs_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::pacific_mac_pool::_mac_pool_regs_t& m)
{
    serializer_class<silicon_one::pacific_mac_pool::_mac_pool_regs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::pacific_mac_pool::_mac_pool_regs_t&);



template<>
class serializer_class<silicon_one::pacific_mac_pool::_mac_pool_counters_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::pacific_mac_pool::_mac_pool_counters_t& m) {
            archive(::cereal::make_nvp("rx_ber", m.rx_ber));
            archive(::cereal::make_nvp("rx_errored_blocks", m.rx_errored_blocks));
            archive(::cereal::make_nvp("port_mib", m.port_mib));
            archive(::cereal::make_nvp("pcs_test", m.pcs_test));
            archive(::cereal::make_nvp("pma_read", m.pma_read));
            archive(::cereal::make_nvp("pma_write", m.pma_write));
            archive(::cereal::make_nvp("pma_test", m.pma_test));
            archive(::cereal::make_nvp("krf_cor", m.krf_cor));
            archive(::cereal::make_nvp("krf_uncor", m.krf_uncor));
            archive(::cereal::make_nvp("rsf_cor", m.rsf_cor));
            archive(::cereal::make_nvp("rsf_uncor", m.rsf_uncor));
            archive(::cereal::make_nvp("rx_symb_err_lane_regs", m.rx_symb_err_lane_regs));
            archive(::cereal::make_nvp("rsf_debug", m.rsf_debug));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::pacific_mac_pool::_mac_pool_counters_t& m) {
            archive(::cereal::make_nvp("rx_ber", m.rx_ber));
            archive(::cereal::make_nvp("rx_errored_blocks", m.rx_errored_blocks));
            archive(::cereal::make_nvp("port_mib", m.port_mib));
            archive(::cereal::make_nvp("pcs_test", m.pcs_test));
            archive(::cereal::make_nvp("pma_read", m.pma_read));
            archive(::cereal::make_nvp("pma_write", m.pma_write));
            archive(::cereal::make_nvp("pma_test", m.pma_test));
            archive(::cereal::make_nvp("krf_cor", m.krf_cor));
            archive(::cereal::make_nvp("krf_uncor", m.krf_uncor));
            archive(::cereal::make_nvp("rsf_cor", m.rsf_cor));
            archive(::cereal::make_nvp("rsf_uncor", m.rsf_uncor));
            archive(::cereal::make_nvp("rx_symb_err_lane_regs", m.rx_symb_err_lane_regs));
            archive(::cereal::make_nvp("rsf_debug", m.rsf_debug));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::pacific_mac_pool::_mac_pool_counters_t& m)
{
    serializer_class<silicon_one::pacific_mac_pool::_mac_pool_counters_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::pacific_mac_pool::_mac_pool_counters_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::pacific_mac_pool::_mac_pool_counters_t& m)
{
    serializer_class<silicon_one::pacific_mac_pool::_mac_pool_counters_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::pacific_mac_pool::_mac_pool_counters_t&);



template<>
class serializer_class<silicon_one::pacific_mac_pool::_mac_pool_interrupt_regs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::pacific_mac_pool::_mac_pool_interrupt_regs_t& m) {
            archive(::cereal::make_nvp("rx_link_status_down", m.rx_link_status_down));
            archive(::cereal::make_nvp("rx_link_status_down_mask", m.rx_link_status_down_mask));
            archive(::cereal::make_nvp("rx_pcs_link_status_down", m.rx_pcs_link_status_down));
            archive(::cereal::make_nvp("rx_pcs_link_status_down_mask", m.rx_pcs_link_status_down_mask));
            archive(::cereal::make_nvp("rx_pcs_align_status_down", m.rx_pcs_align_status_down));
            archive(::cereal::make_nvp("rx_pcs_hi_ber_up", m.rx_pcs_hi_ber_up));
            archive(::cereal::make_nvp("rx_pma_sig_ok_loss_interrupt_register", m.rx_pma_sig_ok_loss_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_high_ser_interrupt_register", m.rsf_rx_high_ser_interrupt_register));
            archive(::cereal::make_nvp("rx_desk_fif_ovf_interrupt_register", m.rx_desk_fif_ovf_interrupt_register));
            archive(::cereal::make_nvp("rx_code_err_interrupt_register", m.rx_code_err_interrupt_register));
            archive(::cereal::make_nvp("rx_crc_err_interrupt_register", m.rx_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_invert_crc_err_interrupt_register", m.rx_invert_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_oob_invert_crc_err_interrupt_register", m.rx_oob_invert_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_oversize_err_interrupt_register", m.rx_oversize_err_interrupt_register));
            archive(::cereal::make_nvp("rx_undersize_err_interrupt_register", m.rx_undersize_err_interrupt_register));
            archive(::cereal::make_nvp("tx_crc_err_interrupt_register", m.tx_crc_err_interrupt_register));
            archive(::cereal::make_nvp("tx_underrun_err_interrupt_register", m.tx_underrun_err_interrupt_register));
            archive(::cereal::make_nvp("tx_missing_eop_err_interrupt_register", m.tx_missing_eop_err_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_degraded_ser_interrupt_register", m.rsf_rx_degraded_ser_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_rm_degraded_ser_interrupt_register", m.rsf_rx_rm_degraded_ser_interrupt_register));
            archive(::cereal::make_nvp("device_time_override_interrupt_register", m.device_time_override_interrupt_register));
            archive(::cereal::make_nvp("rx_code_err_interrupt_register_mask", m.rx_code_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_crc_err_interrupt_register_mask", m.rx_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_invert_crc_err_interrupt_register_mask", m.rx_invert_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_oob_invert_crc_err_interrupt_register_mask", m.rx_oob_invert_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_oversize_err_interrupt_register_mask", m.rx_oversize_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_undersize_err_interrupt_register_mask", m.rx_undersize_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_crc_err_interrupt_register_mask", m.tx_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_underrun_err_interrupt_register_mask", m.tx_underrun_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_missing_eop_err_interrupt_register_mask", m.tx_missing_eop_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rsf_rx_degraded_ser_interrupt_register_mask", m.rsf_rx_degraded_ser_interrupt_register_mask));
            archive(::cereal::make_nvp("rsf_rx_rm_degraded_ser_interrupt_register_mask", m.rsf_rx_rm_degraded_ser_interrupt_register_mask));
            archive(::cereal::make_nvp("device_time_override_interrupt_register_mask", m.device_time_override_interrupt_register_mask));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::pacific_mac_pool::_mac_pool_interrupt_regs_t& m) {
            archive(::cereal::make_nvp("rx_link_status_down", m.rx_link_status_down));
            archive(::cereal::make_nvp("rx_link_status_down_mask", m.rx_link_status_down_mask));
            archive(::cereal::make_nvp("rx_pcs_link_status_down", m.rx_pcs_link_status_down));
            archive(::cereal::make_nvp("rx_pcs_link_status_down_mask", m.rx_pcs_link_status_down_mask));
            archive(::cereal::make_nvp("rx_pcs_align_status_down", m.rx_pcs_align_status_down));
            archive(::cereal::make_nvp("rx_pcs_hi_ber_up", m.rx_pcs_hi_ber_up));
            archive(::cereal::make_nvp("rx_pma_sig_ok_loss_interrupt_register", m.rx_pma_sig_ok_loss_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_high_ser_interrupt_register", m.rsf_rx_high_ser_interrupt_register));
            archive(::cereal::make_nvp("rx_desk_fif_ovf_interrupt_register", m.rx_desk_fif_ovf_interrupt_register));
            archive(::cereal::make_nvp("rx_code_err_interrupt_register", m.rx_code_err_interrupt_register));
            archive(::cereal::make_nvp("rx_crc_err_interrupt_register", m.rx_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_invert_crc_err_interrupt_register", m.rx_invert_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_oob_invert_crc_err_interrupt_register", m.rx_oob_invert_crc_err_interrupt_register));
            archive(::cereal::make_nvp("rx_oversize_err_interrupt_register", m.rx_oversize_err_interrupt_register));
            archive(::cereal::make_nvp("rx_undersize_err_interrupt_register", m.rx_undersize_err_interrupt_register));
            archive(::cereal::make_nvp("tx_crc_err_interrupt_register", m.tx_crc_err_interrupt_register));
            archive(::cereal::make_nvp("tx_underrun_err_interrupt_register", m.tx_underrun_err_interrupt_register));
            archive(::cereal::make_nvp("tx_missing_eop_err_interrupt_register", m.tx_missing_eop_err_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_degraded_ser_interrupt_register", m.rsf_rx_degraded_ser_interrupt_register));
            archive(::cereal::make_nvp("rsf_rx_rm_degraded_ser_interrupt_register", m.rsf_rx_rm_degraded_ser_interrupt_register));
            archive(::cereal::make_nvp("device_time_override_interrupt_register", m.device_time_override_interrupt_register));
            archive(::cereal::make_nvp("rx_code_err_interrupt_register_mask", m.rx_code_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_crc_err_interrupt_register_mask", m.rx_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_invert_crc_err_interrupt_register_mask", m.rx_invert_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_oob_invert_crc_err_interrupt_register_mask", m.rx_oob_invert_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_oversize_err_interrupt_register_mask", m.rx_oversize_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rx_undersize_err_interrupt_register_mask", m.rx_undersize_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_crc_err_interrupt_register_mask", m.tx_crc_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_underrun_err_interrupt_register_mask", m.tx_underrun_err_interrupt_register_mask));
            archive(::cereal::make_nvp("tx_missing_eop_err_interrupt_register_mask", m.tx_missing_eop_err_interrupt_register_mask));
            archive(::cereal::make_nvp("rsf_rx_degraded_ser_interrupt_register_mask", m.rsf_rx_degraded_ser_interrupt_register_mask));
            archive(::cereal::make_nvp("rsf_rx_rm_degraded_ser_interrupt_register_mask", m.rsf_rx_rm_degraded_ser_interrupt_register_mask));
            archive(::cereal::make_nvp("device_time_override_interrupt_register_mask", m.device_time_override_interrupt_register_mask));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::pacific_mac_pool::_mac_pool_interrupt_regs_t& m)
{
    serializer_class<silicon_one::pacific_mac_pool::_mac_pool_interrupt_regs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::pacific_mac_pool::_mac_pool_interrupt_regs_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::pacific_mac_pool::_mac_pool_interrupt_regs_t& m)
{
    serializer_class<silicon_one::pacific_mac_pool::_mac_pool_interrupt_regs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::pacific_mac_pool::_mac_pool_interrupt_regs_t&);



template<>
class serializer_class<silicon_one::pacific_pvt_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::pacific_pvt_handler& m) {
            archive(::cereal::make_nvp("m_next_poll_time", m.m_next_poll_time));
            archive(::cereal::make_nvp("m_fail_temp_time", m.m_fail_temp_time));
            archive(::cereal::make_nvp("m_cached_temp_sensor", m.m_cached_temp_sensor));
            archive(::cereal::make_nvp("m_cached_volt_sensor", m.m_cached_volt_sensor));
            archive(::cereal::make_nvp("m_sensor_poll_time", m.m_sensor_poll_time));
            archive(::cereal::make_nvp("m_sensor_stage", m.m_sensor_stage));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::pacific_pvt_handler& m) {
            archive(::cereal::make_nvp("m_next_poll_time", m.m_next_poll_time));
            archive(::cereal::make_nvp("m_fail_temp_time", m.m_fail_temp_time));
            archive(::cereal::make_nvp("m_cached_temp_sensor", m.m_cached_temp_sensor));
            archive(::cereal::make_nvp("m_cached_volt_sensor", m.m_cached_volt_sensor));
            archive(::cereal::make_nvp("m_sensor_poll_time", m.m_sensor_poll_time));
            archive(::cereal::make_nvp("m_sensor_stage", m.m_sensor_stage));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::pacific_pvt_handler& m)
{
    archive(cereal::base_class<silicon_one::pvt_handler>(&m));
    serializer_class<silicon_one::pacific_pvt_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::pacific_pvt_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::pacific_pvt_handler& m)
{
    archive(cereal::base_class<silicon_one::pvt_handler>(&m));
    serializer_class<silicon_one::pacific_pvt_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::pacific_pvt_handler&);



template<>
class serializer_class<silicon_one::pvt_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::pvt_handler& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::pvt_handler& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::pvt_handler& m)
{
    serializer_class<silicon_one::pvt_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::pvt_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::pvt_handler& m)
{
    serializer_class<silicon_one::pvt_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::pvt_handler&);



template<>
class serializer_class<silicon_one::ranged_sequential_indices_generator> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ranged_sequential_indices_generator& m) {
            archive(::cereal::make_nvp("m_lower_bound", m.m_lower_bound));
            archive(::cereal::make_nvp("m_upper_bound", m.m_upper_bound));
            archive(::cereal::make_nvp("m_range_length", m.m_range_length));
            archive(::cereal::make_nvp("m_indices_usage", m.m_indices_usage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ranged_sequential_indices_generator& m) {
            archive(::cereal::make_nvp("m_lower_bound", m.m_lower_bound));
            archive(::cereal::make_nvp("m_upper_bound", m.m_upper_bound));
            archive(::cereal::make_nvp("m_range_length", m.m_range_length));
            archive(::cereal::make_nvp("m_indices_usage", m.m_indices_usage));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ranged_sequential_indices_generator& m)
{
    serializer_class<silicon_one::ranged_sequential_indices_generator>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ranged_sequential_indices_generator&);

template <class Archive>
void
load(Archive& archive, silicon_one::ranged_sequential_indices_generator& m)
{
    serializer_class<silicon_one::ranged_sequential_indices_generator>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ranged_sequential_indices_generator&);



template<>
class serializer_class<silicon_one::reconnect_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_handler& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_css_memory", m.m_css_memory));
            archive(::cereal::make_nvp("m_metadata", m.m_metadata));
            archive(::cereal::make_nvp("m_serdes_parameters", m.m_serdes_parameters));
            archive(::cereal::make_nvp("m_in_flight_nesting_level", m.m_in_flight_nesting_level));
            archive(::cereal::make_nvp("m_reconnect_in_progress", m.m_reconnect_in_progress));
            archive(::cereal::make_nvp("m_store_to_device_enabled", m.m_store_to_device_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_handler& m) {
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_css_memory", m.m_css_memory));
            archive(::cereal::make_nvp("m_metadata", m.m_metadata));
            archive(::cereal::make_nvp("m_serdes_parameters", m.m_serdes_parameters));
            archive(::cereal::make_nvp("m_in_flight_nesting_level", m.m_in_flight_nesting_level));
            archive(::cereal::make_nvp("m_reconnect_in_progress", m.m_reconnect_in_progress));
            archive(::cereal::make_nvp("m_store_to_device_enabled", m.m_store_to_device_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_handler& m)
{
    serializer_class<silicon_one::reconnect_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_handler& m)
{
    serializer_class<silicon_one::reconnect_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_handler&);



template<>
class serializer_class<silicon_one::reconnect_metadata> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_metadata& m) {
            archive(::cereal::make_nvp("in_flight", m.in_flight));
            archive(::cereal::make_nvp("magic_start", m.magic_start));
            archive(::cereal::make_nvp("device_id", m.device_id));
            archive(::cereal::make_nvp("init_phase", m.init_phase));
            archive(::cereal::make_nvp("fe_fabric_reachability_enabled", m.fe_fabric_reachability_enabled));
            archive(::cereal::make_nvp("lc_to_min_links", m.lc_to_min_links));
            archive(::cereal::make_nvp("bool_device_properties", m.bool_device_properties));
            archive(::cereal::make_nvp("int_device_properties", m.int_device_properties));
            archive(::cereal::make_nvp("fabric_mac_ports", m.fabric_mac_ports));
            archive(::cereal::make_nvp("ifg_serdes_info", m.ifg_serdes_info));
            archive(::cereal::make_nvp("sdk_version", m.sdk_version));
            archive(::cereal::make_nvp("serdes_parameters_n", m.serdes_parameters_n));
            archive(::cereal::make_nvp("magic_end", m.magic_end));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_metadata& m) {
            archive(::cereal::make_nvp("in_flight", m.in_flight));
            archive(::cereal::make_nvp("magic_start", m.magic_start));
            archive(::cereal::make_nvp("device_id", m.device_id));
            archive(::cereal::make_nvp("init_phase", m.init_phase));
            archive(::cereal::make_nvp("fe_fabric_reachability_enabled", m.fe_fabric_reachability_enabled));
            archive(::cereal::make_nvp("lc_to_min_links", m.lc_to_min_links));
            archive(::cereal::make_nvp("bool_device_properties", m.bool_device_properties));
            archive(::cereal::make_nvp("int_device_properties", m.int_device_properties));
            archive(::cereal::make_nvp("fabric_mac_ports", m.fabric_mac_ports));
            archive(::cereal::make_nvp("ifg_serdes_info", m.ifg_serdes_info));
            archive(::cereal::make_nvp("sdk_version", m.sdk_version));
            archive(::cereal::make_nvp("serdes_parameters_n", m.serdes_parameters_n));
            archive(::cereal::make_nvp("magic_end", m.magic_end));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_metadata& m)
{
    serializer_class<silicon_one::reconnect_metadata>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_metadata&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_metadata& m)
{
    serializer_class<silicon_one::reconnect_metadata>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_metadata&);



template<>
class serializer_class<silicon_one::reconnect_metadata::in_flight_s> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_metadata::in_flight_s& m) {
            archive(::cereal::make_nvp("magic", m.magic));
            archive(::cereal::make_nvp("name", m.name));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_metadata::in_flight_s& m) {
            archive(::cereal::make_nvp("magic", m.magic));
            archive(::cereal::make_nvp("name", m.name));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_metadata::in_flight_s& m)
{
    serializer_class<silicon_one::reconnect_metadata::in_flight_s>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_metadata::in_flight_s&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_metadata::in_flight_s& m)
{
    serializer_class<silicon_one::reconnect_metadata::in_flight_s>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_metadata::in_flight_s&);



template<>
class serializer_class<silicon_one::reconnect_metadata::fe_fabric_reachability_enabled_s> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_metadata::fe_fabric_reachability_enabled_s& m) {
        uint32_t m_value = m.value;
        uint32_t m_is_set = m.is_set;
            archive(::cereal::make_nvp("value", m_value));
            archive(::cereal::make_nvp("is_set", m_is_set));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_metadata::fe_fabric_reachability_enabled_s& m) {
        uint32_t m_value;
        uint32_t m_is_set;
            archive(::cereal::make_nvp("value", m_value));
            archive(::cereal::make_nvp("is_set", m_is_set));
        m.value = m_value;
        m.is_set = m_is_set;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_metadata::fe_fabric_reachability_enabled_s& m)
{
    serializer_class<silicon_one::reconnect_metadata::fe_fabric_reachability_enabled_s>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_metadata::fe_fabric_reachability_enabled_s&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_metadata::fe_fabric_reachability_enabled_s& m)
{
    serializer_class<silicon_one::reconnect_metadata::fe_fabric_reachability_enabled_s>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_metadata::fe_fabric_reachability_enabled_s&);



template<>
class serializer_class<silicon_one::reconnect_metadata::lc_to_min_links_s> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_metadata::lc_to_min_links_s& m) {
        uint8_t m_value = m.value;
        uint8_t m_is_set = m.is_set;
            archive(::cereal::make_nvp("value", m_value));
            archive(::cereal::make_nvp("is_set", m_is_set));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_metadata::lc_to_min_links_s& m) {
        uint8_t m_value;
        uint8_t m_is_set;
            archive(::cereal::make_nvp("value", m_value));
            archive(::cereal::make_nvp("is_set", m_is_set));
        m.value = m_value;
        m.is_set = m_is_set;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_metadata::lc_to_min_links_s& m)
{
    serializer_class<silicon_one::reconnect_metadata::lc_to_min_links_s>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_metadata::lc_to_min_links_s&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_metadata::lc_to_min_links_s& m)
{
    serializer_class<silicon_one::reconnect_metadata::lc_to_min_links_s>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_metadata::lc_to_min_links_s&);



template<>
class serializer_class<silicon_one::reconnect_metadata::fabric_mac_port> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_metadata::fabric_mac_port& m) {
            archive(::cereal::make_nvp("create_args", m.create_args));
            archive(::cereal::make_nvp("is_attr_set", m.is_attr_set));
            archive(::cereal::make_nvp("attr", m.attr));
            archive(::cereal::make_nvp("state", m.state));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_metadata::fabric_mac_port& m) {
            archive(::cereal::make_nvp("create_args", m.create_args));
            archive(::cereal::make_nvp("is_attr_set", m.is_attr_set));
            archive(::cereal::make_nvp("attr", m.attr));
            archive(::cereal::make_nvp("state", m.state));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_metadata::fabric_mac_port& m)
{
    serializer_class<silicon_one::reconnect_metadata::fabric_mac_port>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_metadata::fabric_mac_port&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_metadata::fabric_mac_port& m)
{
    serializer_class<silicon_one::reconnect_metadata::fabric_mac_port>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_metadata::fabric_mac_port&);



template<>
class serializer_class<silicon_one::reconnect_metadata::fabric_mac_port::create_args_s> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_metadata::fabric_mac_port::create_args_s& m) {
        uint32_t m_valid = m.valid;
        uint32_t m_slice_id = m.slice_id;
        uint32_t m_ifg_id = m.ifg_id;
        uint32_t m_first_serdes_id = m.first_serdes_id;
        uint32_t m_last_serdes_id = m.last_serdes_id;
        uint32_t m_speed = m.speed;
        uint32_t m_rx_fc_mode = m.rx_fc_mode;
        uint32_t m_tx_fc_mode = m.tx_fc_mode;
        uint32_t m_has_fabric_port = m.has_fabric_port;
            archive(::cereal::make_nvp("valid", m_valid));
            archive(::cereal::make_nvp("slice_id", m_slice_id));
            archive(::cereal::make_nvp("ifg_id", m_ifg_id));
            archive(::cereal::make_nvp("first_serdes_id", m_first_serdes_id));
            archive(::cereal::make_nvp("last_serdes_id", m_last_serdes_id));
            archive(::cereal::make_nvp("speed", m_speed));
            archive(::cereal::make_nvp("rx_fc_mode", m_rx_fc_mode));
            archive(::cereal::make_nvp("tx_fc_mode", m_tx_fc_mode));
            archive(::cereal::make_nvp("has_fabric_port", m_has_fabric_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_metadata::fabric_mac_port::create_args_s& m) {
        uint32_t m_valid;
        uint32_t m_slice_id;
        uint32_t m_ifg_id;
        uint32_t m_first_serdes_id;
        uint32_t m_last_serdes_id;
        uint32_t m_speed;
        uint32_t m_rx_fc_mode;
        uint32_t m_tx_fc_mode;
        uint32_t m_has_fabric_port;
            archive(::cereal::make_nvp("valid", m_valid));
            archive(::cereal::make_nvp("slice_id", m_slice_id));
            archive(::cereal::make_nvp("ifg_id", m_ifg_id));
            archive(::cereal::make_nvp("first_serdes_id", m_first_serdes_id));
            archive(::cereal::make_nvp("last_serdes_id", m_last_serdes_id));
            archive(::cereal::make_nvp("speed", m_speed));
            archive(::cereal::make_nvp("rx_fc_mode", m_rx_fc_mode));
            archive(::cereal::make_nvp("tx_fc_mode", m_tx_fc_mode));
            archive(::cereal::make_nvp("has_fabric_port", m_has_fabric_port));
        m.valid = m_valid;
        m.slice_id = m_slice_id;
        m.ifg_id = m_ifg_id;
        m.first_serdes_id = m_first_serdes_id;
        m.last_serdes_id = m_last_serdes_id;
        m.speed = m_speed;
        m.rx_fc_mode = m_rx_fc_mode;
        m.tx_fc_mode = m_tx_fc_mode;
        m.has_fabric_port = m_has_fabric_port;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_metadata::fabric_mac_port::create_args_s& m)
{
    serializer_class<silicon_one::reconnect_metadata::fabric_mac_port::create_args_s>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_metadata::fabric_mac_port::create_args_s&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_metadata::fabric_mac_port::create_args_s& m)
{
    serializer_class<silicon_one::reconnect_metadata::fabric_mac_port::create_args_s>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_metadata::fabric_mac_port::create_args_s&);



template<>
class serializer_class<silicon_one::reconnect_metadata::ifg_serdes_info_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_metadata::ifg_serdes_info_desc& m) {
        uint8_t m_is_rx_source_set = m.is_rx_source_set;
        uint8_t m_is_anlt_order_set = m.is_anlt_order_set;
            archive(::cereal::make_nvp("is_rx_source_set", m_is_rx_source_set));
            archive(::cereal::make_nvp("is_anlt_order_set", m_is_anlt_order_set));
            archive(::cereal::make_nvp("serdes_info", m.serdes_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_metadata::ifg_serdes_info_desc& m) {
        uint8_t m_is_rx_source_set;
        uint8_t m_is_anlt_order_set;
            archive(::cereal::make_nvp("is_rx_source_set", m_is_rx_source_set));
            archive(::cereal::make_nvp("is_anlt_order_set", m_is_anlt_order_set));
            archive(::cereal::make_nvp("serdes_info", m.serdes_info));
        m.is_rx_source_set = m_is_rx_source_set;
        m.is_anlt_order_set = m_is_anlt_order_set;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_metadata::ifg_serdes_info_desc& m)
{
    serializer_class<silicon_one::reconnect_metadata::ifg_serdes_info_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_metadata::ifg_serdes_info_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_metadata::ifg_serdes_info_desc& m)
{
    serializer_class<silicon_one::reconnect_metadata::ifg_serdes_info_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_metadata::ifg_serdes_info_desc&);



template<>
class serializer_class<silicon_one::reconnect_metadata::ifg_serdes_info_desc::serdes_info_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_metadata::ifg_serdes_info_desc::serdes_info_desc& m) {
        uint16_t m_rx_source = m.rx_source;
        uint16_t m_anlt_order = m.anlt_order;
        uint16_t m_rx_polarity_inversion = m.rx_polarity_inversion;
        uint16_t m_is_rx_polarity_inversion_set = m.is_rx_polarity_inversion_set;
        uint16_t m_tx_polarity_inversion = m.tx_polarity_inversion;
        uint16_t m_is_tx_polarity_inversion_set = m.is_tx_polarity_inversion_set;
            archive(::cereal::make_nvp("rx_source", m_rx_source));
            archive(::cereal::make_nvp("anlt_order", m_anlt_order));
            archive(::cereal::make_nvp("rx_polarity_inversion", m_rx_polarity_inversion));
            archive(::cereal::make_nvp("is_rx_polarity_inversion_set", m_is_rx_polarity_inversion_set));
            archive(::cereal::make_nvp("tx_polarity_inversion", m_tx_polarity_inversion));
            archive(::cereal::make_nvp("is_tx_polarity_inversion_set", m_is_tx_polarity_inversion_set));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_metadata::ifg_serdes_info_desc::serdes_info_desc& m) {
        uint16_t m_rx_source;
        uint16_t m_anlt_order;
        uint16_t m_rx_polarity_inversion;
        uint16_t m_is_rx_polarity_inversion_set;
        uint16_t m_tx_polarity_inversion;
        uint16_t m_is_tx_polarity_inversion_set;
            archive(::cereal::make_nvp("rx_source", m_rx_source));
            archive(::cereal::make_nvp("anlt_order", m_anlt_order));
            archive(::cereal::make_nvp("rx_polarity_inversion", m_rx_polarity_inversion));
            archive(::cereal::make_nvp("is_rx_polarity_inversion_set", m_is_rx_polarity_inversion_set));
            archive(::cereal::make_nvp("tx_polarity_inversion", m_tx_polarity_inversion));
            archive(::cereal::make_nvp("is_tx_polarity_inversion_set", m_is_tx_polarity_inversion_set));
        m.rx_source = m_rx_source;
        m.anlt_order = m_anlt_order;
        m.rx_polarity_inversion = m_rx_polarity_inversion;
        m.is_rx_polarity_inversion_set = m_is_rx_polarity_inversion_set;
        m.tx_polarity_inversion = m_tx_polarity_inversion;
        m.is_tx_polarity_inversion_set = m_is_tx_polarity_inversion_set;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_metadata::ifg_serdes_info_desc::serdes_info_desc& m)
{
    serializer_class<silicon_one::reconnect_metadata::ifg_serdes_info_desc::serdes_info_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_metadata::ifg_serdes_info_desc::serdes_info_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_metadata::ifg_serdes_info_desc::serdes_info_desc& m)
{
    serializer_class<silicon_one::reconnect_metadata::ifg_serdes_info_desc::serdes_info_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_metadata::ifg_serdes_info_desc::serdes_info_desc&);



template<>
class serializer_class<silicon_one::reconnect_metadata::serdes_parameter> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::reconnect_metadata::serdes_parameter& m) {
        uint32_t m_slice_id = m.slice_id;
        uint32_t m_ifg_id = m.ifg_id;
        uint32_t m_first_serdes_id = m.first_serdes_id;
        uint32_t m_serdes_idx = m.serdes_idx;
        uint32_t m_stage = m.stage;
        uint32_t m_parameter = m.parameter;
        uint32_t m_mode = m.mode;
        uint32_t m_is_set = m.is_set;
        uint32_t m_reserved = m.reserved;
            archive(::cereal::make_nvp("slice_id", m_slice_id));
            archive(::cereal::make_nvp("ifg_id", m_ifg_id));
            archive(::cereal::make_nvp("first_serdes_id", m_first_serdes_id));
            archive(::cereal::make_nvp("serdes_idx", m_serdes_idx));
            archive(::cereal::make_nvp("stage", m_stage));
            archive(::cereal::make_nvp("parameter", m_parameter));
            archive(::cereal::make_nvp("mode", m_mode));
            archive(::cereal::make_nvp("is_set", m_is_set));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("value", m.value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::reconnect_metadata::serdes_parameter& m) {
        uint32_t m_slice_id;
        uint32_t m_ifg_id;
        uint32_t m_first_serdes_id;
        uint32_t m_serdes_idx;
        uint32_t m_stage;
        uint32_t m_parameter;
        uint32_t m_mode;
        uint32_t m_is_set;
        uint32_t m_reserved;
            archive(::cereal::make_nvp("slice_id", m_slice_id));
            archive(::cereal::make_nvp("ifg_id", m_ifg_id));
            archive(::cereal::make_nvp("first_serdes_id", m_first_serdes_id));
            archive(::cereal::make_nvp("serdes_idx", m_serdes_idx));
            archive(::cereal::make_nvp("stage", m_stage));
            archive(::cereal::make_nvp("parameter", m_parameter));
            archive(::cereal::make_nvp("mode", m_mode));
            archive(::cereal::make_nvp("is_set", m_is_set));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("value", m.value));
        m.slice_id = m_slice_id;
        m.ifg_id = m_ifg_id;
        m.first_serdes_id = m_first_serdes_id;
        m.serdes_idx = m_serdes_idx;
        m.stage = m_stage;
        m.parameter = m_parameter;
        m.mode = m_mode;
        m.is_set = m_is_set;
        m.reserved = m_reserved;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::reconnect_metadata::serdes_parameter& m)
{
    serializer_class<silicon_one::reconnect_metadata::serdes_parameter>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::reconnect_metadata::serdes_parameter&);

template <class Archive>
void
load(Archive& archive, silicon_one::reconnect_metadata::serdes_parameter& m)
{
    serializer_class<silicon_one::reconnect_metadata::serdes_parameter>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::reconnect_metadata::serdes_parameter&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::pacific_pvt_handler var0;
    ar(var0);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::pacific_mac_pool);
CEREAL_REGISTER_TYPE(silicon_one::pacific_pvt_handler);
CEREAL_REGISTER_TYPE(silicon_one::pvt_handler);

#pragma GCC diagnostic pop

