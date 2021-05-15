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

template <class Archive> void save(Archive&, const la_mac_addr_t&);
template <class Archive> void load(Archive&, la_mac_addr_t&);

template <class Archive> void save(Archive&, const la_slice_ifg&);
template <class Archive> void load(Archive&, la_slice_ifg&);

template <class Archive> void save(Archive&, const npl_mac_af_npp_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_af_npp_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_source_pif_hw_table_value_t&);
template <class Archive> void load(Archive&, npl_source_pif_hw_table_value_t&);

template <class Archive> void save(Archive&, const silicon_one::dependency_listener&);
template <class Archive> void load(Archive&, silicon_one::dependency_listener&);

template <class Archive> void save(Archive&, const silicon_one::ifg_use_count&);
template <class Archive> void load(Archive&, silicon_one::ifg_use_count&);

template <class Archive> void save(Archive&, const silicon_one::la_device_impl&);
template <class Archive> void load(Archive&, silicon_one::la_device_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_interface_scheduler&);
template <class Archive> void load(Archive&, silicon_one::la_interface_scheduler&);

template <class Archive> void save(Archive&, const silicon_one::la_interface_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_interface_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_mac_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_mac_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_npu_host_port_base&);
template <class Archive> void load(Archive&, silicon_one::la_npu_host_port_base&);

template <class Archive> void save(Archive&, const silicon_one::la_pci_port&);
template <class Archive> void load(Archive&, silicon_one::la_pci_port&);

template <class Archive> void save(Archive&, const silicon_one::la_ptp_handler&);
template <class Archive> void load(Archive&, silicon_one::la_ptp_handler&);

template <class Archive> void save(Archive&, const silicon_one::la_punt_inject_port&);
template <class Archive> void load(Archive&, silicon_one::la_punt_inject_port&);

template <class Archive> void save(Archive&, const silicon_one::la_recycle_port&);
template <class Archive> void load(Archive&, silicon_one::la_recycle_port&);

template <class Archive> void save(Archive&, const silicon_one::la_remote_device&);
template <class Archive> void load(Archive&, silicon_one::la_remote_device&);

template <class Archive> void save(Archive&, const silicon_one::la_remote_port_impl&);
template <class Archive> void load(Archive&, silicon_one::la_remote_port_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_slice_mapper_base&);
template <class Archive> void load(Archive&, silicon_one::la_slice_mapper_base&);

template <class Archive> void save(Archive&, const silicon_one::la_spa_port&);
template <class Archive> void load(Archive&, silicon_one::la_spa_port&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port&);
template <class Archive> void load(Archive&, silicon_one::la_system_port&);

template <class Archive> void save(Archive&, const silicon_one::la_system_port_scheduler_impl&);
template <class Archive> void load(Archive&, silicon_one::la_system_port_scheduler_impl&);

template <class Archive> void save(Archive&, const silicon_one::la_tc_profile&);
template <class Archive> void load(Archive&, silicon_one::la_tc_profile&);

template <class Archive> void save(Archive&, const silicon_one::la_voq_set&);
template <class Archive> void load(Archive&, silicon_one::la_voq_set&);

template <class Archive> void save(Archive&, const silicon_one::ll_device&);
template <class Archive> void load(Archive&, silicon_one::ll_device&);

template <class Archive> void save(Archive&, const silicon_one::pacific_tree&);
template <class Archive> void load(Archive&, silicon_one::pacific_tree&);

template<>
class serializer_class<silicon_one::la_pci_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_pci_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice", m.m_slice));
            archive(::cereal::make_nvp("m_ifg", m.m_ifg));
            archive(::cereal::make_nvp("m_is_active", m.m_is_active));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_skip_kernel_driver", m.m_skip_kernel_driver));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_pci_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice", m.m_slice));
            archive(::cereal::make_nvp("m_ifg", m.m_ifg));
            archive(::cereal::make_nvp("m_is_active", m.m_is_active));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_skip_kernel_driver", m.m_skip_kernel_driver));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_pci_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_pci_port>(&m));
    serializer_class<silicon_one::la_pci_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_pci_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_pci_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_pci_port>(&m));
    serializer_class<silicon_one::la_pci_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_pci_port_base&);



template<>
class serializer_class<silicon_one::la_pci_port_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_pci_port_pacific& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_pci_port_pacific& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_pci_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_pci_port_base>(&m));
    serializer_class<silicon_one::la_pci_port_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_pci_port_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_pci_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_pci_port_base>(&m));
    serializer_class<silicon_one::la_pci_port_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_pci_port_pacific&);



template<>
class serializer_class<silicon_one::la_ptp_handler_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ptp_handler_base& m) {
            archive(::cereal::make_nvp("m_use_debug_device_time_load", m.m_use_debug_device_time_load));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ptp_handler_base& m) {
            archive(::cereal::make_nvp("m_use_debug_device_time_load", m.m_use_debug_device_time_load));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_ll_device", m.m_ll_device));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ptp_handler_base& m)
{
    archive(cereal::base_class<silicon_one::la_ptp_handler>(&m));
    serializer_class<silicon_one::la_ptp_handler_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ptp_handler_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ptp_handler_base& m)
{
    archive(cereal::base_class<silicon_one::la_ptp_handler>(&m));
    serializer_class<silicon_one::la_ptp_handler_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ptp_handler_base&);



template<>
class serializer_class<silicon_one::la_ptp_handler_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_ptp_handler_pacific& m) {
            archive(::cereal::make_nvp("m_pc_tree", m.m_pc_tree));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_ptp_handler_pacific& m) {
            archive(::cereal::make_nvp("m_pc_tree", m.m_pc_tree));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_ptp_handler_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_ptp_handler_base>(&m));
    serializer_class<silicon_one::la_ptp_handler_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_ptp_handler_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_ptp_handler_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_ptp_handler_base>(&m));
    serializer_class<silicon_one::la_ptp_handler_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_ptp_handler_pacific&);



template<>
class serializer_class<silicon_one::la_punt_inject_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_punt_inject_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_punt_inject_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_mac_addr", m.m_mac_addr));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_system_port", m.m_system_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_punt_inject_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_punt_inject_port>(&m));
    serializer_class<silicon_one::la_punt_inject_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_punt_inject_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_punt_inject_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_punt_inject_port>(&m));
    serializer_class<silicon_one::la_punt_inject_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_punt_inject_port_base&);



template<>
class serializer_class<silicon_one::la_punt_inject_port_pacgb> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_punt_inject_port_pacgb& m) {
            archive(::cereal::make_nvp("m_system_recycle_port", m.m_system_recycle_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_punt_inject_port_pacgb& m) {
            archive(::cereal::make_nvp("m_system_recycle_port", m.m_system_recycle_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_punt_inject_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_punt_inject_port_base>(&m));
    serializer_class<silicon_one::la_punt_inject_port_pacgb>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_punt_inject_port_pacgb&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_punt_inject_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_punt_inject_port_base>(&m));
    serializer_class<silicon_one::la_punt_inject_port_pacgb>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_punt_inject_port_pacgb&);



template<>
class serializer_class<silicon_one::la_punt_inject_port_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_punt_inject_port_pacific& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_punt_inject_port_pacific& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_punt_inject_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_punt_inject_port_pacgb>(&m));
    serializer_class<silicon_one::la_punt_inject_port_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_punt_inject_port_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_punt_inject_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_punt_inject_port_pacgb>(&m));
    serializer_class<silicon_one::la_punt_inject_port_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_punt_inject_port_pacific&);



template<>
class serializer_class<silicon_one::la_recycle_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_recycle_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice", m.m_slice));
            archive(::cereal::make_nvp("m_ifg", m.m_ifg));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_recycle_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_slice", m.m_slice));
            archive(::cereal::make_nvp("m_ifg", m.m_ifg));
            archive(::cereal::make_nvp("m_speed", m.m_speed));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_recycle_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_recycle_port>(&m));
    serializer_class<silicon_one::la_recycle_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_recycle_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_recycle_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_recycle_port>(&m));
    serializer_class<silicon_one::la_recycle_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_recycle_port_base&);



template<>
class serializer_class<silicon_one::la_recycle_port_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_recycle_port_pacific& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_recycle_port_pacific& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_recycle_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_recycle_port_base>(&m));
    serializer_class<silicon_one::la_recycle_port_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_recycle_port_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_recycle_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_recycle_port_base>(&m));
    serializer_class<silicon_one::la_recycle_port_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_recycle_port_pacific&);



template<>
class serializer_class<silicon_one::la_remote_device_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_remote_device_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_remote_device_id", m.m_remote_device_id));
            archive(::cereal::make_nvp("m_remote_device_revision", m.m_remote_device_revision));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_remote_device_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_remote_device_id", m.m_remote_device_id));
            archive(::cereal::make_nvp("m_remote_device_revision", m.m_remote_device_revision));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_remote_device_base& m)
{
    archive(cereal::base_class<silicon_one::la_remote_device>(&m));
    serializer_class<silicon_one::la_remote_device_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_remote_device_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_remote_device_base& m)
{
    archive(cereal::base_class<silicon_one::la_remote_device>(&m));
    serializer_class<silicon_one::la_remote_device_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_remote_device_base&);



template<>
class serializer_class<silicon_one::la_spa_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_spa_port_base& m) {
            archive(::cereal::make_nvp("m_mac_af_npp_attributes_table_value", m.m_mac_af_npp_attributes_table_value));
            archive(::cereal::make_nvp("m_mac_af_npp_attributes_table_value_valid", m.m_mac_af_npp_attributes_table_value_valid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mtu", m.m_mtu));
            archive(::cereal::make_nvp("m_qu", m.m_qu));
            archive(::cereal::make_nvp("m_mask_eve", m.m_mask_eve));
            archive(::cereal::make_nvp("m_system_ports_data", m.m_system_ports_data));
            archive(::cereal::make_nvp("m_decrement_ttl", m.m_decrement_ttl));
            archive(::cereal::make_nvp("m_stack_prune", m.m_stack_prune));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_index_to_system_port", m.m_index_to_system_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_spa_port_base& m) {
            archive(::cereal::make_nvp("m_mac_af_npp_attributes_table_value", m.m_mac_af_npp_attributes_table_value));
            archive(::cereal::make_nvp("m_mac_af_npp_attributes_table_value_valid", m.m_mac_af_npp_attributes_table_value_valid));
            archive(::cereal::make_nvp("m_ifg_use_count", m.m_ifg_use_count));
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_mtu", m.m_mtu));
            archive(::cereal::make_nvp("m_qu", m.m_qu));
            archive(::cereal::make_nvp("m_mask_eve", m.m_mask_eve));
            archive(::cereal::make_nvp("m_system_ports_data", m.m_system_ports_data));
            archive(::cereal::make_nvp("m_decrement_ttl", m.m_decrement_ttl));
            archive(::cereal::make_nvp("m_stack_prune", m.m_stack_prune));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_index_to_system_port", m.m_index_to_system_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_spa_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_spa_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_spa_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_spa_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_spa_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_spa_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_spa_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_spa_port_base&);



template<>
class serializer_class<silicon_one::la_spa_port_base::system_port_base_data> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_spa_port_base::system_port_base_data& m) {
            archive(::cereal::make_nvp("num_of_dspa_table_entries", m.num_of_dspa_table_entries));
            archive(::cereal::make_nvp("underlying_port_speed", m.underlying_port_speed));
            archive(::cereal::make_nvp("is_active", m.is_active));
            archive(::cereal::make_nvp("is_receive_enabled", m.is_receive_enabled));
            archive(::cereal::make_nvp("system_port", m.system_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_spa_port_base::system_port_base_data& m) {
            archive(::cereal::make_nvp("num_of_dspa_table_entries", m.num_of_dspa_table_entries));
            archive(::cereal::make_nvp("underlying_port_speed", m.underlying_port_speed));
            archive(::cereal::make_nvp("is_active", m.is_active));
            archive(::cereal::make_nvp("is_receive_enabled", m.is_receive_enabled));
            archive(::cereal::make_nvp("system_port", m.system_port));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_spa_port_base::system_port_base_data& m)
{
    serializer_class<silicon_one::la_spa_port_base::system_port_base_data>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_spa_port_base::system_port_base_data&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_spa_port_base::system_port_base_data& m)
{
    serializer_class<silicon_one::la_spa_port_base::system_port_base_data>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_spa_port_base::system_port_base_data&);



template<>
class serializer_class<silicon_one::la_spa_port_pacgb> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_spa_port_pacgb& m) {
            archive(::cereal::make_nvp("m_source_pif_hw_table_value", m.m_source_pif_hw_table_value));
            archive(::cereal::make_nvp("m_source_pif_hw_table_value_valid", m.m_source_pif_hw_table_value_valid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_spa_port_pacgb& m) {
            archive(::cereal::make_nvp("m_source_pif_hw_table_value", m.m_source_pif_hw_table_value));
            archive(::cereal::make_nvp("m_source_pif_hw_table_value_valid", m.m_source_pif_hw_table_value_valid));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_spa_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_spa_port_base>(&m));
    serializer_class<silicon_one::la_spa_port_pacgb>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_spa_port_pacgb&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_spa_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_spa_port_base>(&m));
    serializer_class<silicon_one::la_spa_port_pacgb>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_spa_port_pacgb&);



template<>
class serializer_class<silicon_one::la_spa_port_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_spa_port_pacific& m) {
            archive(::cereal::make_nvp("m_size_table_entry", m.m_size_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_spa_port_pacific& m) {
            archive(::cereal::make_nvp("m_size_table_entry", m.m_size_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_spa_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_spa_port_pacgb>(&m));
    serializer_class<silicon_one::la_spa_port_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_spa_port_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_spa_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_spa_port_pacgb>(&m));
    serializer_class<silicon_one::la_spa_port_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_spa_port_pacific&);



template<>
class serializer_class<silicon_one::la_system_port_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_system_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_port_type", m.m_port_type));
            archive(::cereal::make_nvp("m_destination_device_id", m.m_destination_device_id));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_source_group_offset", m.m_source_group_offset));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base", m.m_serdes_base));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_pif_base", m.m_pif_base));
            archive(::cereal::make_nvp("m_pif_count", m.m_pif_count));
            archive(::cereal::make_nvp("m_npp_attributes_index", m.m_npp_attributes_index));
            archive(::cereal::make_nvp("m_mc_pruning_high", m.m_mc_pruning_high));
            archive(::cereal::make_nvp("m_mc_pruning_low", m.m_mc_pruning_low));
            archive(::cereal::make_nvp("m_ttl_inheritance_mode", m.m_ttl_inheritance_mode));
            archive(::cereal::make_nvp("m_mtu", m.m_mtu));
            archive(::cereal::make_nvp("m_port_extender_vid", m.m_port_extender_vid));
            archive(::cereal::make_nvp("m_oq_pair_mac_id", m.m_oq_pair_mac_id));
            archive(::cereal::make_nvp("m_mask_eve", m.m_mask_eve));
            archive(::cereal::make_nvp("m_pfc_enabled", m.m_pfc_enabled));
            archive(::cereal::make_nvp("m_decrement_ttl", m.m_decrement_ttl));
            archive(::cereal::make_nvp("m_stack_prune", m.m_stack_prune));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_mac_port", m.m_mac_port));
            archive(::cereal::make_nvp("m_npu_host_port", m.m_npu_host_port));
            archive(::cereal::make_nvp("m_pci_port", m.m_pci_port));
            archive(::cereal::make_nvp("m_punt_recycle_port", m.m_punt_recycle_port));
            archive(::cereal::make_nvp("m_recycle_port", m.m_recycle_port));
            archive(::cereal::make_nvp("m_remote_port", m.m_remote_port));
            archive(::cereal::make_nvp("m_intf_scheduler", m.m_intf_scheduler));
            archive(::cereal::make_nvp("m_voq_set", m.m_voq_set));
            archive(::cereal::make_nvp("m_ect_voq_set", m.m_ect_voq_set));
            archive(::cereal::make_nvp("m_tc_profile", m.m_tc_profile));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_system_port_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_gid", m.m_gid));
            archive(::cereal::make_nvp("m_port_type", m.m_port_type));
            archive(::cereal::make_nvp("m_destination_device_id", m.m_destination_device_id));
            archive(::cereal::make_nvp("m_slice_id", m.m_slice_id));
            archive(::cereal::make_nvp("m_source_group_offset", m.m_source_group_offset));
            archive(::cereal::make_nvp("m_ifg_id", m.m_ifg_id));
            archive(::cereal::make_nvp("m_serdes_base", m.m_serdes_base));
            archive(::cereal::make_nvp("m_serdes_count", m.m_serdes_count));
            archive(::cereal::make_nvp("m_pif_base", m.m_pif_base));
            archive(::cereal::make_nvp("m_pif_count", m.m_pif_count));
            archive(::cereal::make_nvp("m_npp_attributes_index", m.m_npp_attributes_index));
            archive(::cereal::make_nvp("m_mc_pruning_high", m.m_mc_pruning_high));
            archive(::cereal::make_nvp("m_mc_pruning_low", m.m_mc_pruning_low));
            archive(::cereal::make_nvp("m_ttl_inheritance_mode", m.m_ttl_inheritance_mode));
            archive(::cereal::make_nvp("m_mtu", m.m_mtu));
            archive(::cereal::make_nvp("m_port_extender_vid", m.m_port_extender_vid));
            archive(::cereal::make_nvp("m_oq_pair_mac_id", m.m_oq_pair_mac_id));
            archive(::cereal::make_nvp("m_mask_eve", m.m_mask_eve));
            archive(::cereal::make_nvp("m_pfc_enabled", m.m_pfc_enabled));
            archive(::cereal::make_nvp("m_decrement_ttl", m.m_decrement_ttl));
            archive(::cereal::make_nvp("m_stack_prune", m.m_stack_prune));
            archive(::cereal::make_nvp("m_device", m.m_device));
            archive(::cereal::make_nvp("m_mac_port", m.m_mac_port));
            archive(::cereal::make_nvp("m_npu_host_port", m.m_npu_host_port));
            archive(::cereal::make_nvp("m_pci_port", m.m_pci_port));
            archive(::cereal::make_nvp("m_punt_recycle_port", m.m_punt_recycle_port));
            archive(::cereal::make_nvp("m_recycle_port", m.m_recycle_port));
            archive(::cereal::make_nvp("m_remote_port", m.m_remote_port));
            archive(::cereal::make_nvp("m_intf_scheduler", m.m_intf_scheduler));
            archive(::cereal::make_nvp("m_voq_set", m.m_voq_set));
            archive(::cereal::make_nvp("m_ect_voq_set", m.m_ect_voq_set));
            archive(::cereal::make_nvp("m_tc_profile", m.m_tc_profile));
            archive(::cereal::make_nvp("m_scheduler", m.m_scheduler));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_system_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_system_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_system_port_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_system_port_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_system_port_base& m)
{
    archive(cereal::base_class<silicon_one::la_system_port>(&m),
            cereal::base_class<silicon_one::dependency_listener>(&m));
    serializer_class<silicon_one::la_system_port_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_system_port_base&);



template<>
class serializer_class<silicon_one::la_system_port_pacgb> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_system_port_pacgb& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_system_port_pacgb& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_system_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_system_port_base>(&m));
    serializer_class<silicon_one::la_system_port_pacgb>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_system_port_pacgb&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_system_port_pacgb& m)
{
    archive(cereal::base_class<silicon_one::la_system_port_base>(&m));
    serializer_class<silicon_one::la_system_port_pacgb>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_system_port_pacgb&);



template<>
class serializer_class<silicon_one::la_system_port_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_system_port_pacific& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_system_port_pacific& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_system_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_system_port_pacgb>(&m));
    serializer_class<silicon_one::la_system_port_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_system_port_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_system_port_pacific& m)
{
    archive(cereal::base_class<silicon_one::la_system_port_pacgb>(&m));
    serializer_class<silicon_one::la_system_port_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_system_port_pacific&);



template<>
class serializer_class<silicon_one::npu_host_event_queue_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::npu_host_event_queue_base& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::npu_host_event_queue_base& m) {
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::npu_host_event_queue_base& m)
{
    serializer_class<silicon_one::npu_host_event_queue_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::npu_host_event_queue_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::npu_host_event_queue_base& m)
{
    serializer_class<silicon_one::npu_host_event_queue_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::npu_host_event_queue_base&);



template<>
class serializer_class<silicon_one::npu_host_event_queue_pacific> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::npu_host_event_queue_pacific& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::npu_host_event_queue_pacific& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::npu_host_event_queue_pacific& m)
{
    archive(cereal::base_class<silicon_one::npu_host_event_queue_base>(&m));
    serializer_class<silicon_one::npu_host_event_queue_pacific>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::npu_host_event_queue_pacific&);

template <class Archive>
void
load(Archive& archive, silicon_one::npu_host_event_queue_pacific& m)
{
    archive(cereal::base_class<silicon_one::npu_host_event_queue_base>(&m));
    serializer_class<silicon_one::npu_host_event_queue_pacific>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::npu_host_event_queue_pacific&);



template<>
class serializer_class<silicon_one::serdes_handler> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::serdes_handler& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::serdes_handler& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::serdes_handler& m)
{
    serializer_class<silicon_one::serdes_handler>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::serdes_handler&);

template <class Archive>
void
load(Archive& archive, silicon_one::serdes_handler& m)
{
    serializer_class<silicon_one::serdes_handler>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::serdes_handler&);



template<>
class serializer_class<silicon_one::slice_id_manager_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::slice_id_manager_base& m) {
            archive(::cereal::make_nvp("m_FIRST_HW_FABRIC_SLICE", m.m_FIRST_HW_FABRIC_SLICE));
            archive(::cereal::make_nvp("m_first_possible_fabric_slice", m.m_first_possible_fabric_slice));
            archive(::cereal::make_nvp("m_enabled_slices", m.m_enabled_slices));
            archive(::cereal::make_nvp("m_enabled_slice_pairs", m.m_enabled_slice_pairs));
            archive(::cereal::make_nvp("m_enabled_slices_logical", m.m_enabled_slices_logical));
            archive(::cereal::make_nvp("m_enabled_slice_pairs_logical", m.m_enabled_slice_pairs_logical));
            archive(::cereal::make_nvp("m_enabled_ifgs", m.m_enabled_ifgs));
            archive(::cereal::make_nvp("m_is_gifg_enabled", m.m_is_gifg_enabled));
            archive(::cereal::make_nvp("m_initialized", m.m_initialized));
            archive(::cereal::make_nvp("m_designated_fabric_slices", m.m_designated_fabric_slices));
            archive(::cereal::make_nvp("m_designated_nonfabric_slices", m.m_designated_nonfabric_slices));
            archive(::cereal::make_nvp("m_fabric_hw_slices", m.m_fabric_hw_slices));
            archive(::cereal::make_nvp("m_nonfabric_hw_slices", m.m_nonfabric_hw_slices));
            archive(::cereal::make_nvp("m_slice_mapper", m.m_slice_mapper));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::slice_id_manager_base& m) {
            archive(::cereal::make_nvp("m_FIRST_HW_FABRIC_SLICE", m.m_FIRST_HW_FABRIC_SLICE));
            archive(::cereal::make_nvp("m_first_possible_fabric_slice", m.m_first_possible_fabric_slice));
            archive(::cereal::make_nvp("m_enabled_slices", m.m_enabled_slices));
            archive(::cereal::make_nvp("m_enabled_slice_pairs", m.m_enabled_slice_pairs));
            archive(::cereal::make_nvp("m_enabled_slices_logical", m.m_enabled_slices_logical));
            archive(::cereal::make_nvp("m_enabled_slice_pairs_logical", m.m_enabled_slice_pairs_logical));
            archive(::cereal::make_nvp("m_enabled_ifgs", m.m_enabled_ifgs));
            archive(::cereal::make_nvp("m_is_gifg_enabled", m.m_is_gifg_enabled));
            archive(::cereal::make_nvp("m_initialized", m.m_initialized));
            archive(::cereal::make_nvp("m_designated_fabric_slices", m.m_designated_fabric_slices));
            archive(::cereal::make_nvp("m_designated_nonfabric_slices", m.m_designated_nonfabric_slices));
            archive(::cereal::make_nvp("m_fabric_hw_slices", m.m_fabric_hw_slices));
            archive(::cereal::make_nvp("m_nonfabric_hw_slices", m.m_nonfabric_hw_slices));
            archive(::cereal::make_nvp("m_slice_mapper", m.m_slice_mapper));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::slice_id_manager_base& m)
{
    serializer_class<silicon_one::slice_id_manager_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::slice_id_manager_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::slice_id_manager_base& m)
{
    serializer_class<silicon_one::slice_id_manager_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::slice_id_manager_base&);



template<>
class serializer_class<silicon_one::slice_manager_smart_ptr> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::slice_manager_smart_ptr& m) {
            archive(::cereal::make_nvp("m_initialized", m.m_initialized));
            archive(::cereal::make_nvp("m_holder", m.m_holder));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::slice_manager_smart_ptr& m) {
            archive(::cereal::make_nvp("m_initialized", m.m_initialized));
            archive(::cereal::make_nvp("m_holder", m.m_holder));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::slice_manager_smart_ptr& m)
{
    serializer_class<silicon_one::slice_manager_smart_ptr>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::slice_manager_smart_ptr&);

template <class Archive>
void
load(Archive& archive, silicon_one::slice_manager_smart_ptr& m)
{
    serializer_class<silicon_one::slice_manager_smart_ptr>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::slice_manager_smart_ptr&);



template<>
class serializer_class<silicon_one::slice_manager_smart_ptr::centralized_ptr> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::slice_manager_smart_ptr::centralized_ptr& m) {
            archive(::cereal::make_nvp("m_sid_mgr", m.m_sid_mgr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::slice_manager_smart_ptr::centralized_ptr& m) {
            archive(::cereal::make_nvp("m_sid_mgr", m.m_sid_mgr));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::slice_manager_smart_ptr::centralized_ptr& m)
{
    serializer_class<silicon_one::slice_manager_smart_ptr::centralized_ptr>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::slice_manager_smart_ptr::centralized_ptr&);

template <class Archive>
void
load(Archive& archive, silicon_one::slice_manager_smart_ptr::centralized_ptr& m)
{
    serializer_class<silicon_one::slice_manager_smart_ptr::centralized_ptr>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::slice_manager_smart_ptr::centralized_ptr&);



template<>
class serializer_class<silicon_one::slice_manager_smart_ptr_owner> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::slice_manager_smart_ptr_owner& m) {
            archive(::cereal::make_nvp("m_owned_holder", m.m_owned_holder));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::slice_manager_smart_ptr_owner& m) {
            archive(::cereal::make_nvp("m_owned_holder", m.m_owned_holder));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::slice_manager_smart_ptr_owner& m)
{
    archive(cereal::base_class<silicon_one::slice_manager_smart_ptr>(&m));
    serializer_class<silicon_one::slice_manager_smart_ptr_owner>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::slice_manager_smart_ptr_owner&);

template <class Archive>
void
load(Archive& archive, silicon_one::slice_manager_smart_ptr_owner& m)
{
    archive(cereal::base_class<silicon_one::slice_manager_smart_ptr>(&m));
    serializer_class<silicon_one::slice_manager_smart_ptr_owner>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::slice_manager_smart_ptr_owner&);



template<>
class serializer_class<silicon_one::single_idx_mapping> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::single_idx_mapping& m) {
            archive(::cereal::make_nvp("_from", m._from));
            archive(::cereal::make_nvp("_to", m._to));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::single_idx_mapping& m) {
            archive(::cereal::make_nvp("_from", m._from));
            archive(::cereal::make_nvp("_to", m._to));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::single_idx_mapping& m)
{
    serializer_class<silicon_one::single_idx_mapping>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::single_idx_mapping&);

template <class Archive>
void
load(Archive& archive, silicon_one::single_idx_mapping& m)
{
    serializer_class<silicon_one::single_idx_mapping>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::single_idx_mapping&);



template<>
class serializer_class<silicon_one::ifg_mapping> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ifg_mapping& m) {
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("serdes_map", m.serdes_map));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ifg_mapping& m) {
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("serdes_map", m.serdes_map));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ifg_mapping& m)
{
    serializer_class<silicon_one::ifg_mapping>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ifg_mapping&);

template <class Archive>
void
load(Archive& archive, silicon_one::ifg_mapping& m)
{
    serializer_class<silicon_one::ifg_mapping>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ifg_mapping&);



template<>
class serializer_class<silicon_one::slice_mapping> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::slice_mapping& m) {
            archive(::cereal::make_nvp("slice", m.slice));
            archive(::cereal::make_nvp("ifg_map", m.ifg_map));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::slice_mapping& m) {
            archive(::cereal::make_nvp("slice", m.slice));
            archive(::cereal::make_nvp("ifg_map", m.ifg_map));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::slice_mapping& m)
{
    serializer_class<silicon_one::slice_mapping>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::slice_mapping&);

template <class Archive>
void
load(Archive& archive, silicon_one::slice_mapping& m)
{
    serializer_class<silicon_one::slice_mapping>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::slice_mapping&);



template<>
class serializer_class<silicon_one::la_voq_set_base> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_voq_set_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_base_voq", m.m_base_voq));
            archive(::cereal::make_nvp("m_set_size", m.m_set_size));
            archive(::cereal::make_nvp("m_dest_device", m.m_dest_device));
            archive(::cereal::make_nvp("m_dest_slice", m.m_dest_slice));
            archive(::cereal::make_nvp("m_dest_ifg", m.m_dest_ifg));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_voq_set_base& m) {
            archive(::cereal::make_nvp("m_oid", m.m_oid));
            archive(::cereal::make_nvp("m_base_voq", m.m_base_voq));
            archive(::cereal::make_nvp("m_set_size", m.m_set_size));
            archive(::cereal::make_nvp("m_dest_device", m.m_dest_device));
            archive(::cereal::make_nvp("m_dest_slice", m.m_dest_slice));
            archive(::cereal::make_nvp("m_dest_ifg", m.m_dest_ifg));
            archive(::cereal::make_nvp("m_device", m.m_device));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_voq_set_base& m)
{
    archive(cereal::base_class<silicon_one::la_voq_set>(&m));
    serializer_class<silicon_one::la_voq_set_base>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_voq_set_base&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_voq_set_base& m)
{
    archive(cereal::base_class<silicon_one::la_voq_set>(&m));
    serializer_class<silicon_one::la_voq_set_base>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_voq_set_base&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::la_pci_port_pacific var0;
    ar(var0);
    silicon_one::la_ptp_handler_base var1;
    ar(var1);
    silicon_one::la_ptp_handler_pacific var2;
    ar(var2);
    silicon_one::la_punt_inject_port_pacific var3;
    ar(var3);
    silicon_one::la_recycle_port_pacific var4;
    ar(var4);
    silicon_one::la_remote_device_base var5;
    ar(var5);
    silicon_one::la_spa_port_pacific var6;
    ar(var6);
    silicon_one::la_system_port_pacific var7;
    ar(var7);
    silicon_one::npu_host_event_queue_pacific var8;
    ar(var8);
    silicon_one::slice_id_manager_base var9;
    ar(var9);
    silicon_one::slice_manager_smart_ptr var10;
    ar(var10);
    silicon_one::slice_manager_smart_ptr_owner var11;
    ar(var11);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::la_pci_port_base);
CEREAL_REGISTER_TYPE(silicon_one::la_pci_port_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_ptp_handler_base);
CEREAL_REGISTER_TYPE(silicon_one::la_ptp_handler_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_punt_inject_port_base);
CEREAL_REGISTER_TYPE(silicon_one::la_punt_inject_port_pacgb);
CEREAL_REGISTER_TYPE(silicon_one::la_punt_inject_port_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_recycle_port_base);
CEREAL_REGISTER_TYPE(silicon_one::la_recycle_port_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_remote_device_base);
CEREAL_REGISTER_TYPE(silicon_one::la_spa_port_base);
CEREAL_REGISTER_TYPE(silicon_one::la_spa_port_pacgb);
CEREAL_REGISTER_TYPE(silicon_one::la_spa_port_pacific);
CEREAL_REGISTER_TYPE(silicon_one::la_system_port_base);
CEREAL_REGISTER_TYPE(silicon_one::la_system_port_pacgb);
CEREAL_REGISTER_TYPE(silicon_one::la_system_port_pacific);
CEREAL_REGISTER_TYPE(silicon_one::npu_host_event_queue_base);
CEREAL_REGISTER_TYPE(silicon_one::npu_host_event_queue_pacific);
CEREAL_REGISTER_TYPE(silicon_one::serdes_handler);
CEREAL_REGISTER_TYPE(silicon_one::slice_id_manager_base);
CEREAL_REGISTER_TYPE(silicon_one::slice_manager_smart_ptr);
CEREAL_REGISTER_TYPE(silicon_one::slice_manager_smart_ptr_owner);
CEREAL_REGISTER_TYPE(silicon_one::la_voq_set_base);

#pragma GCC diagnostic pop

