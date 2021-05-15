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

template <class Archive> void save(Archive&, const bfd_rx_entry_data_t&);
template <class Archive> void load(Archive&, bfd_rx_entry_data_t&);

template <class Archive> void save(Archive&, const l2_slp_acl_info_t&);
template <class Archive> void load(Archive&, l2_slp_acl_info_t&);

template <class Archive> void save(Archive&, const la_mac_addr_t&);
template <class Archive> void load(Archive&, la_mac_addr_t&);

template <class Archive> void save(Archive&, const la_vlan_tag_tci_t&);
template <class Archive> void load(Archive&, la_vlan_tag_tci_t&);

template <class Archive> void save(Archive&, const npl_lpts_payload_t&);
template <class Archive> void load(Archive&, npl_lpts_payload_t&);

template <class Archive> void save(Archive&, const silicon_one::acl_group_info_t&);
template <class Archive> void load(Archive&, silicon_one::acl_group_info_t&);

template <class Archive> void save(Archive&, const silicon_one::bfd_packet_intervals&);
template <class Archive> void load(Archive&, silicon_one::bfd_packet_intervals&);

template <class Archive> void save(Archive&, const silicon_one::delayed_ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::delayed_ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv4_prefix_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv4_prefix_t&);

template <class Archive> void save(Archive&, const silicon_one::la_ipv6_addr_t&);
template <class Archive> void load(Archive&, silicon_one::la_ipv6_addr_t&);

template <class Archive> void save(Archive&, const silicon_one::la_meter_set&);
template <class Archive> void load(Archive&, silicon_one::la_meter_set&);

template <class Archive> void save(Archive&, const silicon_one::ranged_index_generator&);
template <class Archive> void load(Archive&, silicon_one::ranged_index_generator&);

template <class Archive> void save(Archive&, const silicon_one::ranged_sequential_indices_generator&);
template <class Archive> void load(Archive&, silicon_one::ranged_sequential_indices_generator&);

template<>
class serializer_class<silicon_one::la_device_impl::oam_encap_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::oam_encap_info_t& m) {
            archive(::cereal::make_nvp("da_addr", m.da_addr));
            archive(::cereal::make_nvp("sa_addr", m.sa_addr));
            archive(::cereal::make_nvp("vlan_tag", m.vlan_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::oam_encap_info_t& m) {
            archive(::cereal::make_nvp("da_addr", m.da_addr));
            archive(::cereal::make_nvp("sa_addr", m.sa_addr));
            archive(::cereal::make_nvp("vlan_tag", m.vlan_tag));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::oam_encap_info_t& m)
{
    serializer_class<silicon_one::la_device_impl::oam_encap_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::oam_encap_info_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::oam_encap_info_t& m)
{
    serializer_class<silicon_one::la_device_impl::oam_encap_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::oam_encap_info_t&);



template<>
class serializer_class<silicon_one::la_device_impl::profile_allocators> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::profile_allocators& m) {
            archive(::cereal::make_nvp("ipv4_sip_index", m.ipv4_sip_index));
            archive(::cereal::make_nvp("l3vxlan_smac_msb_index", m.l3vxlan_smac_msb_index));
            archive(::cereal::make_nvp("npu_host_max_ccm_counters", m.npu_host_max_ccm_counters));
            archive(::cereal::make_nvp("npu_host_packet_intervals", m.npu_host_packet_intervals));
            archive(::cereal::make_nvp("bfd_local_ipv6_addresses", m.bfd_local_ipv6_addresses));
            archive(::cereal::make_nvp("npu_host_detection_times", m.npu_host_detection_times));
            archive(::cereal::make_nvp("lpts_em_entries", m.lpts_em_entries));
            archive(::cereal::make_nvp("bfd_rx_entries", m.bfd_rx_entries));
            archive(::cereal::make_nvp("oam_punt_encap", m.oam_punt_encap));
            archive(::cereal::make_nvp("l2_slp_acl_indices", m.l2_slp_acl_indices));
            archive(::cereal::make_nvp("acl_group_entries", m.acl_group_entries));
            archive(::cereal::make_nvp("lpts_meters", m.lpts_meters));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::profile_allocators& m) {
            archive(::cereal::make_nvp("ipv4_sip_index", m.ipv4_sip_index));
            archive(::cereal::make_nvp("l3vxlan_smac_msb_index", m.l3vxlan_smac_msb_index));
            archive(::cereal::make_nvp("npu_host_max_ccm_counters", m.npu_host_max_ccm_counters));
            archive(::cereal::make_nvp("npu_host_packet_intervals", m.npu_host_packet_intervals));
            archive(::cereal::make_nvp("bfd_local_ipv6_addresses", m.bfd_local_ipv6_addresses));
            archive(::cereal::make_nvp("npu_host_detection_times", m.npu_host_detection_times));
            archive(::cereal::make_nvp("lpts_em_entries", m.lpts_em_entries));
            archive(::cereal::make_nvp("bfd_rx_entries", m.bfd_rx_entries));
            archive(::cereal::make_nvp("oam_punt_encap", m.oam_punt_encap));
            archive(::cereal::make_nvp("l2_slp_acl_indices", m.l2_slp_acl_indices));
            archive(::cereal::make_nvp("acl_group_entries", m.acl_group_entries));
            archive(::cereal::make_nvp("lpts_meters", m.lpts_meters));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::profile_allocators& m)
{
    serializer_class<silicon_one::la_device_impl::profile_allocators>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::profile_allocators&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::profile_allocators& m)
{
    serializer_class<silicon_one::la_device_impl::profile_allocators>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::profile_allocators&);



template<>
class serializer_class<silicon_one::la_device_impl::serdes_info_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::serdes_info_desc& m) {
            archive(::cereal::make_nvp("rx_source", m.rx_source));
            archive(::cereal::make_nvp("anlt_order", m.anlt_order));
            archive(::cereal::make_nvp("rx_polarity_inversion", m.rx_polarity_inversion));
            archive(::cereal::make_nvp("tx_polarity_inversion", m.tx_polarity_inversion));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::serdes_info_desc& m) {
            archive(::cereal::make_nvp("rx_source", m.rx_source));
            archive(::cereal::make_nvp("anlt_order", m.anlt_order));
            archive(::cereal::make_nvp("rx_polarity_inversion", m.rx_polarity_inversion));
            archive(::cereal::make_nvp("tx_polarity_inversion", m.tx_polarity_inversion));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::serdes_info_desc& m)
{
    serializer_class<silicon_one::la_device_impl::serdes_info_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::serdes_info_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::serdes_info_desc& m)
{
    serializer_class<silicon_one::la_device_impl::serdes_info_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::serdes_info_desc&);



template<>
class serializer_class<silicon_one::la_device_impl::serdes_status> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::serdes_status& m) {
            archive(::cereal::make_nvp("rx_enabled", m.rx_enabled));
            archive(::cereal::make_nvp("tx_enabled", m.tx_enabled));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::serdes_status& m) {
            archive(::cereal::make_nvp("rx_enabled", m.rx_enabled));
            archive(::cereal::make_nvp("tx_enabled", m.tx_enabled));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::serdes_status& m)
{
    serializer_class<silicon_one::la_device_impl::serdes_status>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::serdes_status&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::serdes_status& m)
{
    serializer_class<silicon_one::la_device_impl::serdes_status>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::serdes_status&);



template<>
class serializer_class<silicon_one::la_device_impl::pwe_tagged_local_label_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::pwe_tagged_local_label_desc& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("slp_id", m.slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::pwe_tagged_local_label_desc& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("slp_id", m.slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::pwe_tagged_local_label_desc& m)
{
    serializer_class<silicon_one::la_device_impl::pwe_tagged_local_label_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::pwe_tagged_local_label_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::pwe_tagged_local_label_desc& m)
{
    serializer_class<silicon_one::la_device_impl::pwe_tagged_local_label_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::pwe_tagged_local_label_desc&);



template<>
class serializer_class<silicon_one::la_device_impl::ipv4_tunnel_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::ipv4_tunnel_id_t& m) {
            archive(::cereal::make_nvp("local_ip_prefix", m.local_ip_prefix));
            archive(::cereal::make_nvp("remote_ip_prefix", m.remote_ip_prefix));
            archive(::cereal::make_nvp("vrf_gid", m.vrf_gid));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::ipv4_tunnel_id_t& m) {
            archive(::cereal::make_nvp("local_ip_prefix", m.local_ip_prefix));
            archive(::cereal::make_nvp("remote_ip_prefix", m.remote_ip_prefix));
            archive(::cereal::make_nvp("vrf_gid", m.vrf_gid));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::ipv4_tunnel_id_t& m)
{
    serializer_class<silicon_one::la_device_impl::ipv4_tunnel_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::ipv4_tunnel_id_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::ipv4_tunnel_id_t& m)
{
    serializer_class<silicon_one::la_device_impl::ipv4_tunnel_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::ipv4_tunnel_id_t&);



template<>
class serializer_class<silicon_one::la_device_impl::vxlan_vni_profile> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::vxlan_vni_profile& m) {
            archive(::cereal::make_nvp("refcount", m.refcount));
            archive(::cereal::make_nvp("index", m.index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::vxlan_vni_profile& m) {
            archive(::cereal::make_nvp("refcount", m.refcount));
            archive(::cereal::make_nvp("index", m.index));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::vxlan_vni_profile& m)
{
    serializer_class<silicon_one::la_device_impl::vxlan_vni_profile>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::vxlan_vni_profile&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::vxlan_vni_profile& m)
{
    serializer_class<silicon_one::la_device_impl::vxlan_vni_profile>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::vxlan_vni_profile&);



template<>
class serializer_class<silicon_one::la_device_impl::vxlan_nh_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::vxlan_nh_t& m) {
            archive(::cereal::make_nvp("l3_port_id", m.l3_port_id));
            archive(::cereal::make_nvp("vxlan_port_id", m.vxlan_port_id));
            archive(::cereal::make_nvp("dmac", m.dmac));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::vxlan_nh_t& m) {
            archive(::cereal::make_nvp("l3_port_id", m.l3_port_id));
            archive(::cereal::make_nvp("vxlan_port_id", m.vxlan_port_id));
            archive(::cereal::make_nvp("dmac", m.dmac));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::vxlan_nh_t& m)
{
    serializer_class<silicon_one::la_device_impl::vxlan_nh_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::vxlan_nh_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::vxlan_nh_t& m)
{
    serializer_class<silicon_one::la_device_impl::vxlan_nh_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::vxlan_nh_t&);



template<>
class serializer_class<silicon_one::la_device_impl::_index_generators> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::_index_generators& m) {
            archive(::cereal::make_nvp("oids", m.oids));
            archive(::cereal::make_nvp("ethernet_ports", m.ethernet_ports));
            archive(::cereal::make_nvp("tc_profiles", m.tc_profiles));
            archive(::cereal::make_nvp("ac_profiles", m.ac_profiles));
            archive(::cereal::make_nvp("filter_groups", m.filter_groups));
            archive(::cereal::make_nvp("voq_cgm_profiles", m.voq_cgm_profiles));
            archive(::cereal::make_nvp("ipv6_compressed_sips", m.ipv6_compressed_sips));
            archive(::cereal::make_nvp("vxlan_compressed_dlp_id", m.vxlan_compressed_dlp_id));
            archive(::cereal::make_nvp("rtf_eth_f0_160_table_id", m.rtf_eth_f0_160_table_id));
            archive(::cereal::make_nvp("rtf_ipv4_f0_160_table_id", m.rtf_ipv4_f0_160_table_id));
            archive(::cereal::make_nvp("rtf_ipv4_f0_320_table_id", m.rtf_ipv4_f0_320_table_id));
            archive(::cereal::make_nvp("rtf_ipv6_f0_160_table_id", m.rtf_ipv6_f0_160_table_id));
            archive(::cereal::make_nvp("rtf_ipv6_f0_320_table_id", m.rtf_ipv6_f0_320_table_id));
            archive(::cereal::make_nvp("multicast_protection_monitors", m.multicast_protection_monitors));
            archive(::cereal::make_nvp("slice", m.slice));
            archive(::cereal::make_nvp("slice_pair", m.slice_pair));
            archive(::cereal::make_nvp("exact_meter_action_profile_id", m.exact_meter_action_profile_id));
            archive(::cereal::make_nvp("exact_meter_profile_id", m.exact_meter_profile_id));
            archive(::cereal::make_nvp("statistical_meter_id", m.statistical_meter_id));
            archive(::cereal::make_nvp("statistical_meter_action_profile_id", m.statistical_meter_action_profile_id));
            archive(::cereal::make_nvp("statistical_meter_profile_id", m.statistical_meter_profile_id));
            archive(::cereal::make_nvp("fecs", m.fecs));
            archive(::cereal::make_nvp("mpls_label_destinations", m.mpls_label_destinations));
            archive(::cereal::make_nvp("protection_monitors", m.protection_monitors));
            archive(::cereal::make_nvp("ecmp_groups", m.ecmp_groups));
            archive(::cereal::make_nvp("output_queue_scheduler", m.output_queue_scheduler));
            archive(::cereal::make_nvp("sr_extended_policies", m.sr_extended_policies));
            archive(::cereal::make_nvp("npuh_mep_ids", m.npuh_mep_ids));
            archive(::cereal::make_nvp("bfd_session_ids", m.bfd_session_ids));
            archive(::cereal::make_nvp("local_mcids", m.local_mcids));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::_index_generators& m) {
            archive(::cereal::make_nvp("oids", m.oids));
            archive(::cereal::make_nvp("ethernet_ports", m.ethernet_ports));
            archive(::cereal::make_nvp("tc_profiles", m.tc_profiles));
            archive(::cereal::make_nvp("ac_profiles", m.ac_profiles));
            archive(::cereal::make_nvp("filter_groups", m.filter_groups));
            archive(::cereal::make_nvp("voq_cgm_profiles", m.voq_cgm_profiles));
            archive(::cereal::make_nvp("ipv6_compressed_sips", m.ipv6_compressed_sips));
            archive(::cereal::make_nvp("vxlan_compressed_dlp_id", m.vxlan_compressed_dlp_id));
            archive(::cereal::make_nvp("rtf_eth_f0_160_table_id", m.rtf_eth_f0_160_table_id));
            archive(::cereal::make_nvp("rtf_ipv4_f0_160_table_id", m.rtf_ipv4_f0_160_table_id));
            archive(::cereal::make_nvp("rtf_ipv4_f0_320_table_id", m.rtf_ipv4_f0_320_table_id));
            archive(::cereal::make_nvp("rtf_ipv6_f0_160_table_id", m.rtf_ipv6_f0_160_table_id));
            archive(::cereal::make_nvp("rtf_ipv6_f0_320_table_id", m.rtf_ipv6_f0_320_table_id));
            archive(::cereal::make_nvp("multicast_protection_monitors", m.multicast_protection_monitors));
            archive(::cereal::make_nvp("slice", m.slice));
            archive(::cereal::make_nvp("slice_pair", m.slice_pair));
            archive(::cereal::make_nvp("exact_meter_action_profile_id", m.exact_meter_action_profile_id));
            archive(::cereal::make_nvp("exact_meter_profile_id", m.exact_meter_profile_id));
            archive(::cereal::make_nvp("statistical_meter_id", m.statistical_meter_id));
            archive(::cereal::make_nvp("statistical_meter_action_profile_id", m.statistical_meter_action_profile_id));
            archive(::cereal::make_nvp("statistical_meter_profile_id", m.statistical_meter_profile_id));
            archive(::cereal::make_nvp("fecs", m.fecs));
            archive(::cereal::make_nvp("mpls_label_destinations", m.mpls_label_destinations));
            archive(::cereal::make_nvp("protection_monitors", m.protection_monitors));
            archive(::cereal::make_nvp("ecmp_groups", m.ecmp_groups));
            archive(::cereal::make_nvp("output_queue_scheduler", m.output_queue_scheduler));
            archive(::cereal::make_nvp("sr_extended_policies", m.sr_extended_policies));
            archive(::cereal::make_nvp("npuh_mep_ids", m.npuh_mep_ids));
            archive(::cereal::make_nvp("bfd_session_ids", m.bfd_session_ids));
            archive(::cereal::make_nvp("local_mcids", m.local_mcids));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::_index_generators& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::_index_generators&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::_index_generators& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::_index_generators&);



template<>
class serializer_class<silicon_one::la_device_impl::_index_generators::_slice> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::_index_generators::_slice& m) {
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("oq_drain_counters", m.oq_drain_counters));
            archive(::cereal::make_nvp("my_ipv4_table_id", m.my_ipv4_table_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::_index_generators::_slice& m) {
            archive(::cereal::make_nvp("npp_attributes", m.npp_attributes));
            archive(::cereal::make_nvp("oq_drain_counters", m.oq_drain_counters));
            archive(::cereal::make_nvp("my_ipv4_table_id", m.my_ipv4_table_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::_index_generators::_slice& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators::_slice>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::_index_generators::_slice&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::_index_generators::_slice& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators::_slice>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::_index_generators::_slice&);



template<>
class serializer_class<silicon_one::la_device_impl::_index_generators::_slice_pair> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::_index_generators::_slice_pair& m) {
            archive(::cereal::make_nvp("service_port_slps", m.service_port_slps));
            archive(::cereal::make_nvp("ingress_eth_db1_160_f0_acl_ids", m.ingress_eth_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_eth_db2_160_f0_acl_ids", m.ingress_eth_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db1_160_f0_acl_ids", m.ingress_ipv4_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db2_160_f0_acl_ids", m.ingress_ipv4_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db3_160_f0_acl_ids", m.ingress_ipv4_db3_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db4_160_f0_acl_ids", m.ingress_ipv4_db4_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db1_320_f0_acl_ids", m.ingress_ipv4_db1_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db2_320_f0_acl_ids", m.ingress_ipv4_db2_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db3_320_f0_acl_ids", m.ingress_ipv4_db3_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db4_320_f0_acl_ids", m.ingress_ipv4_db4_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db1_160_f0_acl_ids", m.ingress_ipv6_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db2_160_f0_acl_ids", m.ingress_ipv6_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db3_160_f0_acl_ids", m.ingress_ipv6_db3_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db4_160_f0_acl_ids", m.ingress_ipv6_db4_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db1_320_f0_acl_ids", m.ingress_ipv6_db1_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db2_320_f0_acl_ids", m.ingress_ipv6_db2_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db3_320_f0_acl_ids", m.ingress_ipv6_db3_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db4_320_f0_acl_ids", m.ingress_ipv6_db4_320_f0_acl_ids));
            archive(::cereal::make_nvp("service_port_pwe", m.service_port_pwe));
            archive(::cereal::make_nvp("ingress_ipv4_mirror_acl_ids", m.ingress_ipv4_mirror_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_mirror_acl_ids", m.ingress_ipv6_mirror_acl_ids));
            archive(::cereal::make_nvp("egress_ipv4_acl_ids", m.egress_ipv4_acl_ids));
            archive(::cereal::make_nvp("egress_ipv6_acl_ids", m.egress_ipv6_acl_ids));
            archive(::cereal::make_nvp("ingress_qos_profiles", m.ingress_qos_profiles));
            archive(::cereal::make_nvp("egress_qos_profiles", m.egress_qos_profiles));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::_index_generators::_slice_pair& m) {
            archive(::cereal::make_nvp("service_port_slps", m.service_port_slps));
            archive(::cereal::make_nvp("ingress_eth_db1_160_f0_acl_ids", m.ingress_eth_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_eth_db2_160_f0_acl_ids", m.ingress_eth_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db1_160_f0_acl_ids", m.ingress_ipv4_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db2_160_f0_acl_ids", m.ingress_ipv4_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db3_160_f0_acl_ids", m.ingress_ipv4_db3_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db4_160_f0_acl_ids", m.ingress_ipv4_db4_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db1_320_f0_acl_ids", m.ingress_ipv4_db1_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db2_320_f0_acl_ids", m.ingress_ipv4_db2_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db3_320_f0_acl_ids", m.ingress_ipv4_db3_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv4_db4_320_f0_acl_ids", m.ingress_ipv4_db4_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db1_160_f0_acl_ids", m.ingress_ipv6_db1_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db2_160_f0_acl_ids", m.ingress_ipv6_db2_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db3_160_f0_acl_ids", m.ingress_ipv6_db3_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db4_160_f0_acl_ids", m.ingress_ipv6_db4_160_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db1_320_f0_acl_ids", m.ingress_ipv6_db1_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db2_320_f0_acl_ids", m.ingress_ipv6_db2_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db3_320_f0_acl_ids", m.ingress_ipv6_db3_320_f0_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_db4_320_f0_acl_ids", m.ingress_ipv6_db4_320_f0_acl_ids));
            archive(::cereal::make_nvp("service_port_pwe", m.service_port_pwe));
            archive(::cereal::make_nvp("ingress_ipv4_mirror_acl_ids", m.ingress_ipv4_mirror_acl_ids));
            archive(::cereal::make_nvp("ingress_ipv6_mirror_acl_ids", m.ingress_ipv6_mirror_acl_ids));
            archive(::cereal::make_nvp("egress_ipv4_acl_ids", m.egress_ipv4_acl_ids));
            archive(::cereal::make_nvp("egress_ipv6_acl_ids", m.egress_ipv6_acl_ids));
            archive(::cereal::make_nvp("ingress_qos_profiles", m.ingress_qos_profiles));
            archive(::cereal::make_nvp("egress_qos_profiles", m.egress_qos_profiles));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::_index_generators::_slice_pair& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators::_slice_pair>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::_index_generators::_slice_pair&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::_index_generators::_slice_pair& m)
{
    serializer_class<silicon_one::la_device_impl::_index_generators::_slice_pair>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::_index_generators::_slice_pair&);



template<>
class serializer_class<silicon_one::la_device_impl::aapl_firmware_info> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::aapl_firmware_info& m) {
            archive(::cereal::make_nvp("revision", m.revision));
            archive(::cereal::make_nvp("build_id", m.build_id));
            archive(::cereal::make_nvp("filename", m.filename));
            archive(::cereal::make_nvp("filepath", m.filepath));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::aapl_firmware_info& m) {
            archive(::cereal::make_nvp("revision", m.revision));
            archive(::cereal::make_nvp("build_id", m.build_id));
            archive(::cereal::make_nvp("filename", m.filename));
            archive(::cereal::make_nvp("filepath", m.filepath));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::aapl_firmware_info& m)
{
    serializer_class<silicon_one::la_device_impl::aapl_firmware_info>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::aapl_firmware_info&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::aapl_firmware_info& m)
{
    serializer_class<silicon_one::la_device_impl::aapl_firmware_info>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::aapl_firmware_info&);



template<>
class serializer_class<silicon_one::la_device_impl::device_property_val> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::device_property_val& m) {
            archive(::cereal::make_nvp("bool_val", m.bool_val));
            archive(::cereal::make_nvp("int_val", m.int_val));
            archive(::cereal::make_nvp("string_val", m.string_val));
            archive(::cereal::make_nvp("supported", m.supported));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::device_property_val& m) {
            archive(::cereal::make_nvp("bool_val", m.bool_val));
            archive(::cereal::make_nvp("int_val", m.int_val));
            archive(::cereal::make_nvp("string_val", m.string_val));
            archive(::cereal::make_nvp("supported", m.supported));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::device_property_val& m)
{
    serializer_class<silicon_one::la_device_impl::device_property_val>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::device_property_val&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::device_property_val& m)
{
    serializer_class<silicon_one::la_device_impl::device_property_val>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::device_property_val&);



template<>
class serializer_class<silicon_one::la_device_impl::ipv6_compressed_sip_desc> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::la_device_impl::ipv6_compressed_sip_desc& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("code", m.code));
            archive(::cereal::make_nvp("npl_table_entry", m.npl_table_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::la_device_impl::ipv6_compressed_sip_desc& m) {
            archive(::cereal::make_nvp("use_count", m.use_count));
            archive(::cereal::make_nvp("code", m.code));
            archive(::cereal::make_nvp("npl_table_entry", m.npl_table_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::la_device_impl::ipv6_compressed_sip_desc& m)
{
    serializer_class<silicon_one::la_device_impl::ipv6_compressed_sip_desc>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::la_device_impl::ipv6_compressed_sip_desc&);

template <class Archive>
void
load(Archive& archive, silicon_one::la_device_impl::ipv6_compressed_sip_desc& m)
{
    serializer_class<silicon_one::la_device_impl::ipv6_compressed_sip_desc>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::la_device_impl::ipv6_compressed_sip_desc&);



template<class Archive>
static void
force_serialization(Archive& ar)
{
    silicon_one::profile_allocator<class silicon_one::weak_ptr_unsafe<const class silicon_one::la_meter_set>, struct std::less<class silicon_one::weak_ptr_unsafe<const class silicon_one::la_meter_set> >, class silicon_one::ranged_index_generator> var0;
    ar(var0);
}
template void force_serialization<cereal_input_archive_class>(cereal_input_archive_class&);
template void force_serialization<cereal_output_archive_class>(cereal_output_archive_class&);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CEREAL_REGISTER_TYPE(silicon_one::profile_allocator<class silicon_one::weak_ptr_unsafe<const class silicon_one::la_meter_set>, struct std::less<class silicon_one::weak_ptr_unsafe<const class silicon_one::la_meter_set> >, class silicon_one::ranged_index_generator>);
CEREAL_REGISTER_TYPE(silicon_one::profile_allocator_base<class silicon_one::weak_ptr_unsafe<const class silicon_one::la_meter_set> >);
CEREAL_REGISTER_POLYMORPHIC_RELATION(silicon_one::profile_allocator_base<class silicon_one::weak_ptr_unsafe<const class silicon_one::la_meter_set> >, silicon_one::profile_allocator<class silicon_one::weak_ptr_unsafe<const class silicon_one::la_meter_set> CEREAL_GEN_COMMA()  struct std::less<class silicon_one::weak_ptr_unsafe<const class silicon_one::la_meter_set> > CEREAL_GEN_COMMA()  class silicon_one::ranged_index_generator>);

#pragma GCC diagnostic pop

