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

template <class Archive> void save(Archive&, const silicon_one::acl_entry_desc&);
template <class Archive> void load(Archive&, silicon_one::acl_entry_desc&);

template <class Archive> void save(Archive&, const silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait&);
template <class Archive> void load(Archive&, silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait&);

template <class Archive> void save(Archive&, const silicon_one::la_ac_profile&);
template <class Archive> void load(Archive&, silicon_one::la_ac_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_acl&);
template <class Archive> void load(Archive&, silicon_one::la_acl&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_command_profile_base&);
template <class Archive> void load(Archive&, silicon_one::la_acl_command_profile_base&);

template <class Archive> void save(Archive&, const silicon_one::la_acl_key_profile_base&);
template <class Archive> void load(Archive&, silicon_one::la_acl_key_profile_base&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_ethernet_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_ethernet_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_object&);
template <class Archive> void load(Archive&, silicon_one::la_object&);

template <class Archive> void save(Archive&, const silicon_one::la_pcl&);
template <class Archive> void load(Archive&, silicon_one::la_pcl&);

template <class Archive> void save(Archive&, const silicon_one::la_switch&);
template <class Archive> void load(Archive&, silicon_one::la_switch&);

template <class Archive> void save(Archive&, const silicon_one::slice_manager_smart_ptr&);
template <class Archive> void load(Archive&, silicon_one::slice_manager_smart_ptr&);

template<>
class serializer_class<silicon_one::voq_cgm_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::voq_cgm_handler& m) {
            archive(::cereal::make_nvp("m_evicted_buffers_default_behavior", m.m_evicted_buffers_default_behavior));
            archive(::cereal::make_nvp("m_sms_voqs_age_time_ns", m.m_sms_voqs_age_time_ns));
            archive(::cereal::make_nvp("ecn_level_prob_map", m.ecn_level_prob_map));
            archive(::cereal::make_nvp("cgm_ecn_num_levels", m.cgm_ecn_num_levels));
            archive(::cereal::make_nvp("cgm_ecn_num_probability", m.cgm_ecn_num_probability));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::voq_cgm_handler& m) {
            archive(::cereal::make_nvp("m_evicted_buffers_default_behavior", m.m_evicted_buffers_default_behavior));
            archive(::cereal::make_nvp("m_sms_voqs_age_time_ns", m.m_sms_voqs_age_time_ns));
            archive(::cereal::make_nvp("ecn_level_prob_map", m.ecn_level_prob_map));
            archive(::cereal::make_nvp("cgm_ecn_num_levels", m.cgm_ecn_num_levels));
            archive(::cereal::make_nvp("cgm_ecn_num_probability", m.cgm_ecn_num_probability));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::voq_cgm_handler& m)
{
    serializer_class<silicon_one::voq_cgm_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::voq_cgm_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::voq_cgm_handler& m)
{
    serializer_class<silicon_one::voq_cgm_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::voq_cgm_handler&);



template<>
class serializer_class<silicon_one::all_acl_generic_types> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::all_acl_generic_types& m) {
            archive(::cereal::make_nvp("_acl_ingress_rtf_eth_db1_160_f0", m._acl_ingress_rtf_eth_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_eth_db2_160_f0", m._acl_ingress_rtf_eth_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db1_160_f0", m._acl_ingress_rtf_ipv4_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db2_160_f0", m._acl_ingress_rtf_ipv4_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db3_160_f0", m._acl_ingress_rtf_ipv4_db3_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db4_160_f0", m._acl_ingress_rtf_ipv4_db4_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db1_320_f0", m._acl_ingress_rtf_ipv4_db1_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db2_320_f0", m._acl_ingress_rtf_ipv4_db2_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db3_320_f0", m._acl_ingress_rtf_ipv4_db3_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db4_320_f0", m._acl_ingress_rtf_ipv4_db4_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db1_160_f0", m._acl_ingress_rtf_ipv6_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db2_160_f0", m._acl_ingress_rtf_ipv6_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db3_160_f0", m._acl_ingress_rtf_ipv6_db3_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db4_160_f0", m._acl_ingress_rtf_ipv6_db4_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db1_320_f0", m._acl_ingress_rtf_ipv6_db1_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db2_320_f0", m._acl_ingress_rtf_ipv6_db2_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db3_320_f0", m._acl_ingress_rtf_ipv6_db3_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db4_320_f0", m._acl_ingress_rtf_ipv6_db4_320_f0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::all_acl_generic_types& m) {
            archive(::cereal::make_nvp("_acl_ingress_rtf_eth_db1_160_f0", m._acl_ingress_rtf_eth_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_eth_db2_160_f0", m._acl_ingress_rtf_eth_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db1_160_f0", m._acl_ingress_rtf_ipv4_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db2_160_f0", m._acl_ingress_rtf_ipv4_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db3_160_f0", m._acl_ingress_rtf_ipv4_db3_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db4_160_f0", m._acl_ingress_rtf_ipv4_db4_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db1_320_f0", m._acl_ingress_rtf_ipv4_db1_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db2_320_f0", m._acl_ingress_rtf_ipv4_db2_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db3_320_f0", m._acl_ingress_rtf_ipv4_db3_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv4_db4_320_f0", m._acl_ingress_rtf_ipv4_db4_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db1_160_f0", m._acl_ingress_rtf_ipv6_db1_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db2_160_f0", m._acl_ingress_rtf_ipv6_db2_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db3_160_f0", m._acl_ingress_rtf_ipv6_db3_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db4_160_f0", m._acl_ingress_rtf_ipv6_db4_160_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db1_320_f0", m._acl_ingress_rtf_ipv6_db1_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db2_320_f0", m._acl_ingress_rtf_ipv6_db2_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db3_320_f0", m._acl_ingress_rtf_ipv6_db3_320_f0));
            archive(::cereal::make_nvp("_acl_ingress_rtf_ipv6_db4_320_f0", m._acl_ingress_rtf_ipv6_db4_320_f0));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::all_acl_generic_types& m)
{
    serializer_class<silicon_one::all_acl_generic_types>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::all_acl_generic_types&);

template <class Archive>
void
load(Archive& archive, silicon_one::all_acl_generic_types& m)
{
    serializer_class<silicon_one::all_acl_generic_types>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::all_acl_generic_types&);



template<>
class serializer_class<silicon_one::destination_id> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::destination_id& m) {
        la_uint32_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::destination_id& m) {
        la_uint32_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::destination_id& m)
{
    serializer_class<silicon_one::destination_id>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::destination_id&);

template <class Archive>
void
load(Archive& archive, silicon_one::destination_id& m)
{
    serializer_class<silicon_one::destination_id>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::destination_id&);



template<>
class serializer_class<silicon_one::lpm_destination_id> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::lpm_destination_id& m) {
        la_uint32_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::lpm_destination_id& m) {
        la_uint32_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::lpm_destination_id& m)
{
    serializer_class<silicon_one::lpm_destination_id>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::lpm_destination_id&);

template <class Archive>
void
load(Archive& archive, silicon_one::lpm_destination_id& m)
{
    serializer_class<silicon_one::lpm_destination_id>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::lpm_destination_id&);



template<>
class serializer_class<silicon_one::resolution_table_index> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::resolution_table_index& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::resolution_table_index& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::resolution_table_index& m)
{
    serializer_class<silicon_one::resolution_table_index>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::resolution_table_index&);

template <class Archive>
void
load(Archive& archive, silicon_one::resolution_table_index& m)
{
    serializer_class<silicon_one::resolution_table_index>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::resolution_table_index&);



template<>
class serializer_class<silicon_one::dependency_listener> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::dependency_listener& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::dependency_listener& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::dependency_listener& m)
{
    serializer_class<silicon_one::dependency_listener>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::dependency_listener&);

template <class Archive>
void
load(Archive& archive, silicon_one::dependency_listener& m)
{
    serializer_class<silicon_one::dependency_listener>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::dependency_listener&);



template<>
class serializer_class<silicon_one::bfd_packet_intervals> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::bfd_packet_intervals& m) {
            archive(::cereal::make_nvp("desired_min_tx_interval", m.desired_min_tx_interval));
            archive(::cereal::make_nvp("required_min_rx_interval", m.required_min_rx_interval));
            archive(::cereal::make_nvp("detection_time_multiplier", m.detection_time_multiplier));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::bfd_packet_intervals& m) {
            archive(::cereal::make_nvp("desired_min_tx_interval", m.desired_min_tx_interval));
            archive(::cereal::make_nvp("required_min_rx_interval", m.required_min_rx_interval));
            archive(::cereal::make_nvp("detection_time_multiplier", m.detection_time_multiplier));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::bfd_packet_intervals& m)
{
    serializer_class<silicon_one::bfd_packet_intervals>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::bfd_packet_intervals&);

template <class Archive>
void
load(Archive& archive, silicon_one::bfd_packet_intervals& m)
{
    serializer_class<silicon_one::bfd_packet_intervals>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::bfd_packet_intervals&);



template<>
class serializer_class<silicon_one::ifg_use_count> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_use_count& m) {
            archive(::cereal::make_nvp("m_ifgs", m.m_ifgs));
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_use_count& m) {
            archive(::cereal::make_nvp("m_ifgs", m.m_ifgs));
            archive(::cereal::make_nvp("m_slice_id_manager", m.m_slice_id_manager));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_use_count& m)
{
    serializer_class<silicon_one::ifg_use_count>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_use_count&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_use_count& m)
{
    serializer_class<silicon_one::ifg_use_count>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_use_count&);



template<>
class serializer_class<silicon_one::ipv4_sip_index_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ipv4_sip_index_manager& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ipv4_sip_index_manager& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ipv4_sip_index_manager& m)
{
    serializer_class<silicon_one::ipv4_sip_index_manager>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ipv4_sip_index_manager&);

template <class Archive>
void
load(Archive& archive, silicon_one::ipv4_sip_index_manager& m)
{
    serializer_class<silicon_one::ipv4_sip_index_manager>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ipv4_sip_index_manager&);



template<>
class serializer_class<silicon_one::ipv4_tunnel_ep_manager> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager& m) {
            archive(::cereal::make_nvp("m_ipv4_tunnel_ep_map", m.m_ipv4_tunnel_ep_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager& m) {
            archive(::cereal::make_nvp("m_ipv4_tunnel_ep_map", m.m_ipv4_tunnel_ep_map));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ipv4_tunnel_ep_manager&);

template <class Archive>
void
load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ipv4_tunnel_ep_manager&);



template<>
class serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("ipv4_prefix", m.ipv4_prefix));
            archive(::cereal::make_nvp("l4_protocol_sel", m.l4_protocol_sel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("ipv4_prefix", m.ipv4_prefix));
            archive(::cereal::make_nvp("l4_protocol_sel", m.l4_protocol_sel));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s&);

template <class Archive>
void
load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_ep_t_s&);



template<>
class serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t& m) {
            archive(::cereal::make_nvp("loc", m.loc));
            archive(::cereal::make_nvp("ref_cnt", m.ref_cnt));
            archive(::cereal::make_nvp("sip_index", m.sip_index));
            archive(::cereal::make_nvp("sip_index_or_local_slp_id", m.sip_index_or_local_slp_id));
            archive(::cereal::make_nvp("db", m.db));
            archive(::cereal::make_nvp("entry", m.entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t& m) {
            archive(::cereal::make_nvp("loc", m.loc));
            archive(::cereal::make_nvp("ref_cnt", m.ref_cnt));
            archive(::cereal::make_nvp("sip_index", m.sip_index));
            archive(::cereal::make_nvp("sip_index_or_local_slp_id", m.sip_index_or_local_slp_id));
            archive(::cereal::make_nvp("db", m.db));
            archive(::cereal::make_nvp("entry", m.entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t& m)
{
    serializer_class<silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ipv4_tunnel_ep_manager::ipv4_tunnel_entry_t&);



template<>
class serializer_class<silicon_one::la_ac_port_common> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ac_port_common& m) {
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_vid1", m.m_vid1));
            archive(::cereal::make_nvp("m_vid2", m.m_vid2));
            archive(::cereal::make_nvp("m_attached_p2p_pwe", m.m_attached_p2p_pwe));
            archive(::cereal::make_nvp("m_attached_p2p_pwe_gid", m.m_attached_p2p_pwe_gid));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_mapped_vids", m.m_mapped_vids));
            archive(::cereal::make_nvp("m_port_state", m.m_port_state));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_eth_port", m.m_eth_port));
            archive(::cereal::make_nvp("m_attached_switch", m.m_attached_switch));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ac_port_common& m) {
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_vid1", m.m_vid1));
            archive(::cereal::make_nvp("m_vid2", m.m_vid2));
            archive(::cereal::make_nvp("m_attached_p2p_pwe", m.m_attached_p2p_pwe));
            archive(::cereal::make_nvp("m_attached_p2p_pwe_gid", m.m_attached_p2p_pwe_gid));
            archive(::cereal::make_nvp("m_slice_data", m.m_slice_data));
            archive(::cereal::make_nvp("m_mapped_vids", m.m_mapped_vids));
            archive(::cereal::make_nvp("m_port_state", m.m_port_state));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_eth_port", m.m_eth_port));
            archive(::cereal::make_nvp("m_attached_switch", m.m_attached_switch));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ac_port_common& m)
{
    serializer_class<silicon_one::la_ac_port_common>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ac_port_common&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ac_port_common& m)
{
    serializer_class<silicon_one::la_ac_port_common>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ac_port_common&);



template<>
class serializer_class<silicon_one::la_ac_port_common::slice_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ac_port_common::slice_data& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
            archive(::cereal::make_nvp("em0_ac_entry", m.em0_ac_entry));
            archive(::cereal::make_nvp("em0_ac_tag_entry", m.em0_ac_tag_entry));
            archive(::cereal::make_nvp("em0_ac_tag_tag_entry", m.em0_ac_tag_tag_entry));
            archive(::cereal::make_nvp("em1_ac_tag_entry", m.em1_ac_tag_entry));
            archive(::cereal::make_nvp("tcam_ac_entry", m.tcam_ac_entry));
            archive(::cereal::make_nvp("tcam_ac_tag_entry", m.tcam_ac_tag_entry));
            archive(::cereal::make_nvp("tcam_ac_tag_tag_entry", m.tcam_ac_tag_tag_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ac_port_common::slice_data& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
            archive(::cereal::make_nvp("em0_ac_entry", m.em0_ac_entry));
            archive(::cereal::make_nvp("em0_ac_tag_entry", m.em0_ac_tag_entry));
            archive(::cereal::make_nvp("em0_ac_tag_tag_entry", m.em0_ac_tag_tag_entry));
            archive(::cereal::make_nvp("em1_ac_tag_entry", m.em1_ac_tag_entry));
            archive(::cereal::make_nvp("tcam_ac_entry", m.tcam_ac_entry));
            archive(::cereal::make_nvp("tcam_ac_tag_entry", m.tcam_ac_tag_entry));
            archive(::cereal::make_nvp("tcam_ac_tag_tag_entry", m.tcam_ac_tag_tag_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ac_port_common::slice_data& m)
{
    serializer_class<silicon_one::la_ac_port_common::slice_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ac_port_common::slice_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ac_port_common::slice_data& m)
{
    serializer_class<silicon_one::la_ac_port_common::slice_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ac_port_common::slice_data&);



template<>
class serializer_class<silicon_one::la_ac_profile_impl> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ac_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_need_fallback", m.m_need_fallback));
            archive(::cereal::make_nvp("m_selector_type_pvlan_enabled", m.m_selector_type_pvlan_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ac_profile_impl& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_index", m.m_index));
            archive(::cereal::make_nvp("m_need_fallback", m.m_need_fallback));
            archive(::cereal::make_nvp("m_selector_type_pvlan_enabled", m.m_selector_type_pvlan_enabled));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ac_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ac_profile>(&m));
    serializer_class<silicon_one::la_ac_profile_impl>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ac_profile_impl&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ac_profile_impl& m)
{
    archive(cereal::base_class<silicon_one::la_ac_profile>(&m));
    serializer_class<silicon_one::la_ac_profile_impl>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ac_profile_impl&);



template<>
class serializer_class<silicon_one::la_acl_delegate> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_delegate& m) {
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_stage", m.m_stage));
            archive(::cereal::make_nvp("m_acl_type", m.m_acl_type));
            archive(::cereal::make_nvp("m_qos_cmd_count", m.m_qos_cmd_count));
            archive(::cereal::make_nvp("m_aces", m.m_aces));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_acl_key_profile", m.m_acl_key_profile));
            archive(::cereal::make_nvp("m_acl_command_profile", m.m_acl_command_profile));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
            archive(::cereal::make_nvp("m_src_pcl", m.m_src_pcl));
            archive(::cereal::make_nvp("m_dst_pcl", m.m_dst_pcl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_delegate& m) {
            archive(::cereal::make_nvp("m_slice_pair_data", m.m_slice_pair_data));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_stage", m.m_stage));
            archive(::cereal::make_nvp("m_acl_type", m.m_acl_type));
            archive(::cereal::make_nvp("m_qos_cmd_count", m.m_qos_cmd_count));
            archive(::cereal::make_nvp("m_aces", m.m_aces));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_acl_key_profile", m.m_acl_key_profile));
            archive(::cereal::make_nvp("m_acl_command_profile", m.m_acl_command_profile));
            archive(::cereal::make_nvp("m_parent", m.m_parent));
            archive(::cereal::make_nvp("m_src_pcl", m.m_src_pcl));
            archive(::cereal::make_nvp("m_dst_pcl", m.m_dst_pcl));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_delegate& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_acl_delegate>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_delegate&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_delegate& m)
{
    archive(cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_acl_delegate>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_delegate&);



template<>
class serializer_class<silicon_one::la_acl_delegate::slice_pair_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_delegate::slice_pair_data& m) {
            archive(::cereal::make_nvp("acl_id", m.acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_delegate::slice_pair_data& m) {
            archive(::cereal::make_nvp("acl_id", m.acl_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_delegate::slice_pair_data& m)
{
    serializer_class<silicon_one::la_acl_delegate::slice_pair_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_delegate::slice_pair_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_delegate::slice_pair_data& m)
{
    serializer_class<silicon_one::la_acl_delegate::slice_pair_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_delegate::slice_pair_data&);



template<>
class serializer_class<silicon_one::la_acl_egress_sec_ipv4> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_egress_sec_ipv4& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_egress_sec_ipv4& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_egress_sec_ipv4& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_egress_sec_ipv4>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_egress_sec_ipv4&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_egress_sec_ipv4& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_egress_sec_ipv4>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_egress_sec_ipv4&);



template<>
class serializer_class<silicon_one::la_acl_egress_sec_ipv6> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_acl_egress_sec_ipv6& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_acl_egress_sec_ipv6& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_acl_egress_sec_ipv6& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_egress_sec_ipv6>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_acl_egress_sec_ipv6&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_acl_egress_sec_ipv6& m)
{
    archive(cereal::base_class<silicon_one::la_acl_delegate>(&m));
    serializer_class<silicon_one::la_acl_egress_sec_ipv6>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_acl_egress_sec_ipv6&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait&);



template<>
class serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait&);

template <class Archive>
void
load(Archive& archive, silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait& m)
{
    serializer_class<silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait> var0;
    ar(var0);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait> var1;
    ar(var1);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait> var2;
    ar(var2);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait> var3;
    ar(var3);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait> var4;
    ar(var4);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait> var5;
    ar(var5);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait> var6;
    ar(var6);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait> var7;
    ar(var7);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait> var8;
    ar(var8);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait> var9;
    ar(var9);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait> var10;
    ar(var10);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait> var11;
    ar(var11);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait> var12;
    ar(var12);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait> var13;
    ar(var13);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait> var14;
    ar(var14);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait> var15;
    ar(var15);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait> var16;
    ar(var16);
    silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait> var17;
    ar(var17);
    silicon_one::la_ac_profile_impl var18;
    ar(var18);
    silicon_one::la_acl_egress_sec_ipv4 var19;
    ar(var19);
    silicon_one::la_acl_egress_sec_ipv6 var20;
    ar(var20);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait>);
CEREAL_REGISTER_TYPE(silicon_one::dependency_listener);
CEREAL_REGISTER_TYPE(silicon_one::la_ac_profile_impl);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_delegate);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_egress_sec_ipv4);
CEREAL_REGISTER_TYPE(silicon_one::la_acl_egress_sec_ipv6);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db1_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_eth_db2_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db1_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db2_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db3_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv4_db4_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_160_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db1_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db2_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db3_320_f0_trait>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::la_acl_delegate, silicon_one::la_acl_generic<struct silicon_one::acl_ingress_rtf_ipv6_db4_320_f0_trait>);

#pragma GCC diagnostic pop

