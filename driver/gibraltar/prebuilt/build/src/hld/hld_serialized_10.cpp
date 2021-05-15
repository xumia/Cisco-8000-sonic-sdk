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
#include "cgm/la_voq_cgm_evicted_profile_impl.h"
#include "cgm/la_voq_cgm_profile_impl.h"
#include "cgm/rx_cgm_handler.h"
#include "hld_serialization.h"
#include "hld_types.h"
#include "npu/la_ac_port_common.h"
#include "npu/la_acl_delegate.h"
#include "npu/la_acl_generic.h"
#include "npu/la_acl_security_group.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_destination_pe_impl.h"
#include "npu/la_ecmp_group_impl.h"
#include "npu/la_ip_tunnel_destination_impl.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_l3_protection_group_impl.h"
#include "npu/la_mldp_vpn_decap_impl.h"
#include "npu/la_mpls_vpn_decap_impl.h"
#include "npu/la_protection_monitor_impl.h"
#include "npu/la_vrf_impl.h"
#include "npu/la_vrf_redirect_destination_impl.h"
#include "npu/mc_copy_id_manager.h"
#include "npu/resolution_configurator.h"
#include "npu/resolution_configurator_impl.h"
#include "qos/la_meter_profile_impl.h"
#include "qos/la_meter_set_impl.h"
#include "qos/la_meter_set_statistical_impl.h"
#include "system/arc_handler_gibraltar.h"
#include "system/counter_bank_utils.h"
#include "system/counter_logical_bank.h"
#include "system/counter_manager.h"
#include "system/gibraltar_mac_pool.h"
#include "system/gibraltar_pvt_handler.h"
#include "system/la_device_impl.h"
#include "system/la_fabric_port_impl.h"
#include "system/la_flow_cache_handler_impl.h"
#include "system/la_hbm_handler_impl.h"
#include "system/mac_pool8_port.h"
#include "system/npu_static_config.h"
#include "system/srm_serdes_device_handler.h"
#include "system/srm_serdes_handler.h"
#include "tm/la_logical_port_scheduler_impl.h"
#include "tm/la_output_queue_scheduler_impl.h"
#include "tm/la_system_port_scheduler_impl.h"
#include "tm/la_voq_set_impl.h"
#include "tm/restricted_voq_set_impl.h"
#include "tm/tm_utils.h"
#include "cgm/la_rx_cgm_sq_profile_impl.h"
#include "cgm/voq_cgm_handler.h"
#include "ifg_use_count.h"
#include "npu/ipv4_sip_index_manager.h"
#include "npu/ipv4_tunnel_ep_manager.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_acl_egress_sec_ipv4.h"
#include "npu/la_acl_egress_sec_ipv6.h"
#include "npu/la_acl_impl.h"
#include "npu/la_acl_scaled_delegate.h"
#include "npu/la_acl_scaled_impl.h"
#include "npu/la_asbr_lsp_impl.h"
#include "npu/la_fabric_multicast_group_impl.h"
#include "npu/la_filter_group_impl.h"
#include "npu/la_forus_destination_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_gue_port_impl.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_lpts_impl.h"
#include "npu/la_lsr_impl.h"
#include "npu/la_mpls_label_destination_impl.h"
#include "npu/la_mpls_multicast_group_impl.h"
#include "npu/la_mpls_nhlfe_impl.h"
#include "npu/la_mpls_vpn_encap_impl.h"
#include "npu/la_next_hop_impl_common.h"
#include "npu/la_og_lpts_application_impl.h"
#include "npu/la_pbts_group_impl.h"
#include "npu/la_pcl_impl.h"
#include "npu/la_switch_impl.h"
#include "npu/la_te_tunnel_impl.h"
#include "npu/mac_address_manager.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_action_profile_impl.h"
#include "qos/la_meter_markdown_profile_impl.h"
#include "qos/la_meter_set_exact_impl.h"
#include "system/counter_allocation.h"
#include "system/cud_range_manager.h"
#include "system/la_l2_punt_destination_impl.h"
#include "system/la_npu_host_destination_impl.h"
#include "system/la_pbts_map_profile_impl.h"
#include "system/la_remote_port_impl.h"
#include "system/mac_pool_port.h"
#include "system/pvt_handler.h"
#include "system/ranged_sequential_indices_generator.h"
#include "system/reconnect_handler.h"
#include "system/reconnect_metadata.h"
#include "system/resource_handler.h"
#include "system/serdes_device_handler.h"
#include "tm/la_fabric_port_scheduler_impl.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/voq_counter_set.h"
#include "../device_context/la_slice_mapper_base.h"
#include "npu/copc_protocol_manager_base.h"
#include "npu/copc_protocol_manager_gibraltar.h"
#include "npu/la_acl_command_profile_base.h"
#include "npu/la_acl_group_base.h"
#include "npu/la_acl_group_gibraltar.h"
#include "npu/la_acl_key_profile_base.h"
#include "npu/la_acl_key_profile_gibraltar.h"
#include "npu/la_bfd_session_base.h"
#include "npu/la_bfd_session_gibraltar.h"
#include "npu/la_copc_base.h"
#include "npu/la_copc_gibraltar.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ethernet_port_gibraltar.h"
#include "npu/la_ip_multicast_group_base.h"
#include "npu/la_ip_multicast_group_gibraltar.h"
#include "npu/la_l2_multicast_group_base.h"
#include "npu/la_l2_multicast_group_gibraltar.h"
#include "npu/la_l2_protection_group_base.h"
#include "npu/la_l2_protection_group_gibraltar.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l2_service_port_gibraltar.h"
#include "npu/la_l2_service_port_pacgb.h"
#include "npu/la_multicast_group_common_base.h"
#include "npu/la_multicast_group_common_gibraltar.h"
#include "npu/la_multicast_protection_group_base.h"
#include "npu/la_multicast_protection_monitor_base.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_next_hop_gibraltar.h"
#include "npu/la_next_hop_pacgb.h"
#include "npu/la_prefix_object_base.h"
#include "npu/la_prefix_object_gibraltar.h"
#include "npu/la_rate_limiter_set_base.h"
#include "npu/la_rate_limiter_set_gibraltar.h"
#include "npu/la_security_group_cell_base.h"
#include "npu/la_security_group_cell_gibraltar.h"
#include "npu/la_stack_port_base.h"
#include "npu/la_stack_port_gibraltar.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_svi_port_gibraltar.h"
#include "npu/la_vrf_port_common_base.h"
#include "npu/la_vrf_port_common_gibraltar.h"
#include "npu/la_vrf_port_common_pacgb.h"
#include "npu/la_vxlan_next_hop_base.h"
#include "npu/la_vxlan_next_hop_gibraltar.h"
#include "qos/la_meter_set_base.h"
#include "system/arc_handler_base.h"
#include "system/device_configurator_base.h"
#include "system/device_port_handler_base.h"
#include "system/device_port_handler_gibraltar.h"
#include "system/dummy_serdes_device_handler_base.h"
#include "system/dummy_serdes_handler_base.h"
#include "system/hld_notification_base.h"
#include "system/hld_notification_gibraltar.h"
#include "system/ifg_handler.h"
#include "system/ifg_handler_base.h"
#include "system/ifg_handler_gibraltar.h"
#include "system/ifg_handler_ifg.h"
#include "system/init_performance_helper_base.h"
#include "system/la_device_impl_base.h"
#include "system/la_erspan_mirror_command_base.h"
#include "system/la_erspan_mirror_command_gibraltar.h"
#include "system/la_l2_mirror_command_base.h"
#include "system/la_l2_mirror_command_gibraltar.h"
#include "system/la_l2_mirror_command_pacgb.h"
#include "system/la_mac_port_base.h"
#include "system/la_mac_port_gibraltar.h"
#include "system/la_mac_port_pacgb.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_npu_host_port_gibraltar.h"
#include "system/la_pci_port_base.h"
#include "system/la_pci_port_gibraltar.h"
#include "system/la_ptp_handler_base.h"
#include "system/la_ptp_handler_gibraltar.h"
#include "system/la_punt_inject_port_base.h"
#include "system/la_punt_inject_port_gibraltar.h"
#include "system/la_punt_inject_port_pacgb.h"
#include "system/la_recycle_port_base.h"
#include "system/la_recycle_port_gibraltar.h"
#include "system/la_remote_device_base.h"
#include "system/la_spa_port_base.h"
#include "system/la_spa_port_gibraltar.h"
#include "system/la_spa_port_pacgb.h"
#include "system/la_system_port_base.h"
#include "system/la_system_port_gibraltar.h"
#include "system/la_system_port_pacgb.h"
#include "system/npu_host_event_queue_base.h"
#include "system/npu_host_event_queue_gibraltar.h"
#include "system/serdes_handler.h"
#include "system/slice_id_manager_base.h"
#include "system/slice_id_manager_gibraltar.h"
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
#include "npu/mc_copy_id_manager.h"
#include "cgm/voq_cgm_handler.h"
#include "ra/resource_manager.h"
#include "cgm/la_voq_cgm_evicted_profile_impl.h"
#include "lld/pacific_tree.h"
#include <cereal/types/boost_variant.hpp> // needed for supporting serialization of boost::variant
namespace cereal {
    template <class Archive> static void save(Archive&, const boost::blank&) {}
    template <class Archive> static void load(Archive&, boost::blank&) {}
}
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
CEREAL_REGISTER_TYPE(silicon_one::la_device_impl::profile_allocators::voq_probability_profile_profile_allocator)
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
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<double>,
                                     silicon_one::la_device_impl::profile_allocators::voq_probability_profile_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<l2_slp_acl_info_t>,
                                     silicon_one::la_device_impl::profile_allocators::l2_slp_acl_indices_profile_allocator)
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<silicon_one::acl_group_info_t>,
                                     silicon_one::la_device_impl::profile_allocators::acl_group_entries_profile_allocator)
#include "hld/hld_serialized_fwd_declarations.h"

namespace cereal {

extern unsigned g_hld_serialization_version;

template <class Archive> void save(Archive&, const la_status&);
template <class Archive> void load(Archive&, la_status&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_fabric_port_scheduler&);
template <class Archive> void load(Archive&, silicon_one::la_fabric_port_scheduler&);

template <class Archive> void save(Archive&, const silicon_one::la_ifg_scheduler&);
template <class Archive> void load(Archive&, silicon_one::la_ifg_scheduler&);

template <class Archive> void save(Archive&, const silicon_one::la_interface_scheduler&);
template <class Archive> void load(Archive&, silicon_one::la_interface_scheduler&);

template <class Archive> void save(Archive&, const silicon_one::la_output_queue_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_output_queue_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_resource_descriptor&);
template <class Archive> void load(Archive&, silicon_one::la_resource_descriptor&);

template <class Archive> void save(Archive&, const silicon_one::ll_device&);
template <class Archive> void load(Archive&, silicon_one::ll_device&);

template <class Archive> void save(Archive&, const silicon_one::lld_memory&);
template <class Archive> void load(Archive&, silicon_one::lld_memory&);

template <class Archive> void save(Archive&, const silicon_one::lld_register&);
template <class Archive> void load(Archive&, silicon_one::lld_register&);

template <class Archive> void save(Archive&, const silicon_one::lld_register_array_container&);
template <class Archive> void load(Archive&, silicon_one::lld_register_array_container&);

template <class Archive> void save(Archive&, const silicon_one::resource_monitor&);
template <class Archive> void load(Archive&, silicon_one::resource_monitor&);

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



template<>
class serializer_class<silicon_one::resource_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resource_handler& m) {
            archive(::cereal::make_nvp("m_resource_monitors", m.m_resource_monitors));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resource_handler& m) {
            archive(::cereal::make_nvp("m_resource_monitors", m.m_resource_monitors));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resource_handler& m)
{
    serializer_class<silicon_one::resource_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resource_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::resource_handler& m)
{
    serializer_class<silicon_one::resource_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resource_handler&);



template<>
class serializer_class<silicon_one::resource_handler::res_monitor_action_cb> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resource_handler::res_monitor_action_cb& m) {
            archive(::cereal::make_nvp("m_res_desc", m.m_res_desc));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resource_handler::res_monitor_action_cb& m) {
            archive(::cereal::make_nvp("m_res_desc", m.m_res_desc));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resource_handler::res_monitor_action_cb& m)
{
    archive(cereal::base_class<silicon_one::la_function<class la_status (unsigned long, unsigned long, unsigned long)>>(&m));
    serializer_class<silicon_one::resource_handler::res_monitor_action_cb>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resource_handler::res_monitor_action_cb&);

template <class Archive>
void
load(Archive& archive, silicon_one::resource_handler::res_monitor_action_cb& m)
{
    archive(cereal::base_class<silicon_one::la_function<class la_status (unsigned long, unsigned long, unsigned long)>>(&m));
    serializer_class<silicon_one::resource_handler::res_monitor_action_cb>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resource_handler::res_monitor_action_cb&);



template<>
class serializer_class<silicon_one::resource_handler::resource_monitor_entry> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resource_handler::resource_monitor_entry& m) {
            archive(::cereal::make_nvp("monitors", m.monitors));
            archive(::cereal::make_nvp("granularity", m.granularity));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resource_handler::resource_monitor_entry& m) {
            archive(::cereal::make_nvp("monitors", m.monitors));
            archive(::cereal::make_nvp("granularity", m.granularity));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resource_handler::resource_monitor_entry& m)
{
    serializer_class<silicon_one::resource_handler::resource_monitor_entry>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resource_handler::resource_monitor_entry&);

template <class Archive>
void
load(Archive& archive, silicon_one::resource_handler::resource_monitor_entry& m)
{
    serializer_class<silicon_one::resource_handler::resource_monitor_entry>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resource_handler::resource_monitor_entry&);



template<>
class serializer_class<silicon_one::serdes_device_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::serdes_device_handler& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::serdes_device_handler& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::serdes_device_handler& m)
{
    serializer_class<silicon_one::serdes_device_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::serdes_device_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::serdes_device_handler& m)
{
    serializer_class<silicon_one::serdes_device_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::serdes_device_handler&);



template<>
class serializer_class<silicon_one::la_fabric_port_scheduler_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_fabric_port_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_fab_intf_id", m.m_fab_intf_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_fabric_port_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_fab_intf_id", m.m_fab_intf_id));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_fabric_port_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_fabric_port_scheduler>(&m));
    serializer_class<silicon_one::la_fabric_port_scheduler_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_fabric_port_scheduler_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_fabric_port_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_fabric_port_scheduler>(&m));
    serializer_class<silicon_one::la_fabric_port_scheduler_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_fabric_port_scheduler_impl&);



template<>
class serializer_class<silicon_one::la_ifg_scheduler_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ifg_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_max_transmit_rate", m.m_max_transmit_rate));
            archive(::cereal::make_nvp("m_max_rx_shaper_burst", m.m_max_rx_shaper_burst));
            archive(::cereal::make_nvp("m_sch_soft_reset_configuration", m.m_sch_soft_reset_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_general_configuration", m.m_sch_ifse_general_configuration));
            archive(::cereal::make_nvp("m_sch_slow_rate_configuration", m.m_sch_slow_rate_configuration));
            archive(::cereal::make_nvp("m_sch_lpse_shaper_configuration", m.m_sch_lpse_shaper_configuration));
            archive(::cereal::make_nvp("m_sch_oqse_shaper_configuration", m.m_sch_oqse_shaper_configuration));
            archive(::cereal::make_nvp("m_sch_tpse_shaper_configuration", m.m_sch_tpse_shaper_configuration));
            archive(::cereal::make_nvp("m_sch_spare_reg", m.m_sch_spare_reg));
            archive(::cereal::make_nvp("m_sch_ifse_cir_shaper_rate_configuration", m.m_sch_ifse_cir_shaper_rate_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_cir_shaper_max_bucket_configuration", m.m_sch_ifse_cir_shaper_max_bucket_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_pir_shaper_configuration", m.m_sch_ifse_pir_shaper_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_pir_shaper_max_bucket_configuration", m.m_sch_ifse_pir_shaper_max_bucket_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_wfq_cir_weights", m.m_sch_ifse_wfq_cir_weights));
            archive(::cereal::make_nvp("m_sch_ifse_wfq_eir_weights", m.m_sch_ifse_wfq_eir_weights));
            archive(::cereal::make_nvp("m_sch_vsc_token_bucket_cfg", m.m_sch_vsc_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oq_pir_token_bucket_cfg", m.m_sch_oq_pir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oqpg_cir_token_bucket_cfg", m.m_sch_oqpg_cir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oqse_cir_token_bucket_cfg", m.m_sch_oqse_cir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oqse_eir_token_bucket_cfg", m.m_sch_oqse_eir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_lpse_wfq_weight_map", m.m_sch_lpse_wfq_weight_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_txpdr_hp", m.m_txpdr_hp));
            archive(::cereal::make_nvp("m_txpdr_lp", m.m_txpdr_lp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ifg_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_max_transmit_rate", m.m_max_transmit_rate));
            archive(::cereal::make_nvp("m_max_rx_shaper_burst", m.m_max_rx_shaper_burst));
            archive(::cereal::make_nvp("m_sch_soft_reset_configuration", m.m_sch_soft_reset_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_general_configuration", m.m_sch_ifse_general_configuration));
            archive(::cereal::make_nvp("m_sch_slow_rate_configuration", m.m_sch_slow_rate_configuration));
            archive(::cereal::make_nvp("m_sch_lpse_shaper_configuration", m.m_sch_lpse_shaper_configuration));
            archive(::cereal::make_nvp("m_sch_oqse_shaper_configuration", m.m_sch_oqse_shaper_configuration));
            archive(::cereal::make_nvp("m_sch_tpse_shaper_configuration", m.m_sch_tpse_shaper_configuration));
            archive(::cereal::make_nvp("m_sch_spare_reg", m.m_sch_spare_reg));
            archive(::cereal::make_nvp("m_sch_ifse_cir_shaper_rate_configuration", m.m_sch_ifse_cir_shaper_rate_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_cir_shaper_max_bucket_configuration", m.m_sch_ifse_cir_shaper_max_bucket_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_pir_shaper_configuration", m.m_sch_ifse_pir_shaper_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_pir_shaper_max_bucket_configuration", m.m_sch_ifse_pir_shaper_max_bucket_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_wfq_cir_weights", m.m_sch_ifse_wfq_cir_weights));
            archive(::cereal::make_nvp("m_sch_ifse_wfq_eir_weights", m.m_sch_ifse_wfq_eir_weights));
            archive(::cereal::make_nvp("m_sch_vsc_token_bucket_cfg", m.m_sch_vsc_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oq_pir_token_bucket_cfg", m.m_sch_oq_pir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oqpg_cir_token_bucket_cfg", m.m_sch_oqpg_cir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oqse_cir_token_bucket_cfg", m.m_sch_oqse_cir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_oqse_eir_token_bucket_cfg", m.m_sch_oqse_eir_token_bucket_cfg));
            archive(::cereal::make_nvp("m_sch_lpse_wfq_weight_map", m.m_sch_lpse_wfq_weight_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_txpdr_hp", m.m_txpdr_hp));
            archive(::cereal::make_nvp("m_txpdr_lp", m.m_txpdr_lp));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ifg_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ifg_scheduler>(&m));
    serializer_class<silicon_one::la_ifg_scheduler_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ifg_scheduler_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ifg_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ifg_scheduler>(&m));
    serializer_class<silicon_one::la_ifg_scheduler_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ifg_scheduler_impl&);



template<>
class serializer_class<silicon_one::la_interface_scheduler_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_interface_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_sch_ifse_general_configuration", m.m_sch_ifse_general_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_wfq_cir_weights", m.m_sch_ifse_wfq_cir_weights));
            archive(::cereal::make_nvp("m_sch_ifse_wfq_eir_weights", m.m_sch_ifse_wfq_eir_weights));
            archive(::cereal::make_nvp("m_sch_ifse_cir_shaper_rate_configuration", m.m_sch_ifse_cir_shaper_rate_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_pir_shaper_configuration", m.m_sch_ifse_pir_shaper_configuration));
            archive(::cereal::make_nvp("m_pif_base", m.m_pif_base));
            archive(::cereal::make_nvp("m_slice_pif_base", m.m_slice_pif_base));
            archive(::cereal::make_nvp("m_tm_port_id", m.m_tm_port_id));
            archive(::cereal::make_nvp("m_slice_tm_port_id", m.m_slice_tm_port_id));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_is_fabric", m.m_is_fabric));
            archive(::cereal::make_nvp("m_pfc", m.m_pfc));
            archive(::cereal::make_nvp("m_pfc_tc_bitmap", m.m_pfc_tc_bitmap));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_interface_scheduler_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_sch_ifse_general_configuration", m.m_sch_ifse_general_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_wfq_cir_weights", m.m_sch_ifse_wfq_cir_weights));
            archive(::cereal::make_nvp("m_sch_ifse_wfq_eir_weights", m.m_sch_ifse_wfq_eir_weights));
            archive(::cereal::make_nvp("m_sch_ifse_cir_shaper_rate_configuration", m.m_sch_ifse_cir_shaper_rate_configuration));
            archive(::cereal::make_nvp("m_sch_ifse_pir_shaper_configuration", m.m_sch_ifse_pir_shaper_configuration));
            archive(::cereal::make_nvp("m_pif_base", m.m_pif_base));
            archive(::cereal::make_nvp("m_slice_pif_base", m.m_slice_pif_base));
            archive(::cereal::make_nvp("m_tm_port_id", m.m_tm_port_id));
            archive(::cereal::make_nvp("m_slice_tm_port_id", m.m_slice_tm_port_id));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_is_fabric", m.m_is_fabric));
            archive(::cereal::make_nvp("m_pfc", m.m_pfc));
            archive(::cereal::make_nvp("m_pfc_tc_bitmap", m.m_pfc_tc_bitmap));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_interface_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_interface_scheduler>(&m));
    serializer_class<silicon_one::la_interface_scheduler_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_interface_scheduler_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_interface_scheduler_impl& m)
{
    archive(cereal::base_class<silicon_one::la_interface_scheduler>(&m));
    serializer_class<silicon_one::la_interface_scheduler_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_interface_scheduler_impl&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::resource_handler::res_monitor_action_cb var0;
    ar(var0);
    silicon_one::la_fabric_port_scheduler_impl var1;
    ar(var1);
    silicon_one::la_ifg_scheduler_impl var2;
    ar(var2);
    silicon_one::la_interface_scheduler_impl var3;
    ar(var3);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::pvt_handler);
CEREAL_REGISTER_TYPE(silicon_one::resource_handler::res_monitor_action_cb);
CEREAL_REGISTER_TYPE(silicon_one::la_function<class la_status (unsigned long, unsigned long, unsigned long)>);
CEREAL_REGISTER_TYPE(silicon_one::serdes_device_handler);
CEREAL_REGISTER_TYPE(silicon_one::la_fabric_port_scheduler_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_ifg_scheduler_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_interface_scheduler_impl);

#pragma GCC diagnostic pop

