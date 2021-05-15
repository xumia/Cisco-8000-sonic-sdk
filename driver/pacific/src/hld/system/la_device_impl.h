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

#ifndef __LA_DEVICE_IMPL_H__
#define __LA_DEVICE_IMPL_H__

#include "api/system/la_css_memory_layout.h"
#include "api/system/la_device.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_lb_types.h"
#include "common/delayed_ranged_index_generator.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "common/profile_allocator.h"
#include "common/ranged_index_generator.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_reg_structs.h"
#include "nplapi/device_tables.h"
#include "nplapi/npl_constants.h"
#include "nplapi/nplapi_fwd.h"
#include "nplapi/nplapi_tables.h"
#include "nplapi/translator_creator.h"
#include "npu/copc_protocol_manager_base.h"
#include "npu/ipv4_sip_index_manager.h"
#include "npu/ipv4_tunnel_ep_manager.h"
#include "npu/la_copc_base.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/mac_address_manager.h"
#include "pacific_pvt_handler.h"
#include "ra/ra_fwd.h"
#include "ranged_sequential_indices_generator.h"
#include "system/device_port_handler_base.h"
#include "system/hld_notification_base.h"
#include "system/ifg_handler_pacific.h"
#include "system/init_performance_helper_base.h"
#include "system/la_device_impl_base.h"
#include "system/la_mac_port_base.h"
#include "system/la_ptp_handler_pacific.h"

#include "runtime_flexibility_library.h"
#include "serdes_device_handler.h"

// multicast links bitmap representing all links to all devices
typedef std::tuple<uint64_t, uint64_t> mc_links_key_t;

// rx entry
struct bfd_rx_entry_data_t {
    uint16_t local_discr_msb;
    uint16_t udp_port;
    la_l3_protocol_e protocol;
    uint32_t destination;
};

struct l2_slp_acl_info_t {
    la_object_id_t v4_acl_oid;
    la_object_id_t v6_acl_oid;
    la_object_id_t mac_acl_oid;
};

class la_aapl_user_hbm;
class la_aapl_user_pci;

namespace silicon_one
{

class arc_handler_pacific;
class counter_manager;
class counter_allocation;
class cud_range_manager;
class mc_copy_id_manager;
class ifg_handler;
class pvt_handler;
class fabric_init_handler;
class la_vrf_port_common_base;
class rx_cgm_handler;

class voq_cgm_handler;
class reconnect_handler;
class resource_manager;
class device_configurator_base;
class device_port_handler;
class la_multicast_group_common_base;
class npu_host_event_queue_base;
class la_pbts_map_profile;
class la_pbts_group;
class init_performance_helper_base;

union tsms_tsms_fifo_th_configuration_register;
union tsms_tsms_delete_fifo_th_configuration_register;

using fp_nanoseconds = std::chrono::duration<double, std::chrono::nanoseconds::period>;

using link_vec_t = std::vector<size_t>;
using bundle_vec_t = std::vector<link_vec_t>;
using la_acl_wptr_vec_t = std::vector<la_acl_wptr>;
// acl group entry
struct acl_group_info_t {
    la_uint16_t ethernet_acls_size;
    la_uint16_t ipv4_acls_size;
    la_uint16_t ipv6_acls_size;
    la_acl_wptr_vec_t ethernet_acls;
    la_acl_wptr_vec_t ipv4_acls;
    la_acl_wptr_vec_t ipv6_acls;
};

class la_device_impl : public la_device_impl_base, public std::enable_shared_from_this<la_device_impl>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_device_impl() = default;

public:
    explicit la_device_impl(ll_device_sptr ldevice);

    // Disallow default and copy c'tors
    explicit la_device_impl(la_device_impl&) = delete;

    ~la_device_impl() override;

    // To support serialization we need the shared pointer of la_device in creating some of the objects that should
    // be created before device phase init (i.e. in constructor).
    // However, we can't use shared pointer of a class in its constructor, so we make la_device_impl's constructor empty
    // and move all its logic to this function.
    la_status pre_initialize();
    la_status initialize_first_ifgs() override;

    // Life-cycle - Public API
    la_status initialize(init_phase_e phase) override;
    la_status reconnect() override;
    void disconnect() override;

    // Warm boot API - Public API
    la_status warm_boot_disconnect() override;
    la_status warm_boot_reconnect() override;

    // Warm boot API, not public API thru la_device but thru the global API functions:
    // la_warm_boot_save_and_destroy() and la_warm_boot_restore
    la_status warm_boot_save_and_destroy(const std::string& warm_boot_file, bool free_objects);
    la_status warm_boot_restore(const std::string& device_path,
                                const std::string& warm_boot_file,
                                const silicon_one::la_platform_cbs& platform_cbs);

    la_status apply_pacific_b0_post_initialize_workarounds() override;

    la_status destroy();
    la_status destroy(la_object* object) override;
    la_status do_destroy(const la_object_wptr& object);

    // Temporary: needed for warm-boot early-testing (until we have full serialization support).
    std::string get_device_path()
    {
        return m_ll_device->get_device_path();
    }

    static la_status create_nsim_simulator_client(std::string device_path, device_simulator*& out_sim);

    // la_device implementation
    std::vector<la_object*> get_objects() const override;
    std::vector<la_object*> get_objects(object_type_e type) const override;
    std::vector<la_object*> get_dependent_objects(const la_object* dependee) const override;
    la_uint_t get_dependent_objects_count(const la_object* dependee) const override;
    la_object* get_object(la_object_id_t oid) const override;
    ll_device* get_ll_device() const override;
    const device_tables* get_device_tables() const override;

    template <class T>
    std::shared_ptr<T> get_sptr(const la_object* o) const
    {
        if (!o) {
            return nullptr;
        }

        auto oid = o->oid();
        dassert_crit(oid < MAX_OIDS);
        if (!of_same_device(o, this)) {
            dassert_ncrit(false, "la_object* o belongs to different device");
            return nullptr;
        }
        auto obj = m_objects[oid];
        return std::static_pointer_cast<T>(obj);
    }

    template <class T>
    std::shared_ptr<T> get_sptr(T* o) const
    {
        return get_sptr<T>(static_cast<const la_object*>(o));
    }

    ll_device_sptr get_ll_device_sptr() const;

    la_status get_device_information(la_device_info_t& out_dev_info) const override;

    const la_slice_id_vec_t& get_used_slices() const override;
    const la_slice_pair_id_vec_t& get_used_slice_pairs() const override;
    la_status get_slice_mode(la_slice_id_t slice_id, la_slice_mode_e& out_slice_mode) const override;
    la_status set_slice_mode(la_slice_id_t slice_id, la_slice_mode_e slice_mode) override;

    la_status get_fabric_mac_ports_mode(fabric_mac_ports_mode_e& out_fabric_mac_ports_mode) const override;
    la_status set_fabric_mac_ports_mode(fabric_mac_ports_mode_e fabric_mac_ports_mode) override;

    la_status set_fabric_slice_clos_direction(la_slice_id_t slice_id, la_clos_direction_e clos_direction) override;
    la_status get_fabric_slice_clos_direction(la_slice_id_t slice_id, la_clos_direction_e& out_clos_direction) const override;
    la_status set_is_fabric_time_master(bool is_master) override;
    la_status get_fabric_time_sync_status(bool& out_sync_status) const override;
    la_status set_fe_fabric_reachability_enabled(bool enabled) override;
    la_status get_fe_fabric_reachability_enabled(bool& out_enabled) const override;
    la_status set_global_minimum_fabric_links(size_t num_links) override;
    la_status get_global_minimum_fabric_links(size_t& out_num_links) const override;
    la_status set_minimum_fabric_links_per_lc(la_device_id_t device_id, size_t num_links) override;
    la_status get_minimum_fabric_links_per_lc(la_device_id_t device_id, size_t& out_num_links) const override;

    la_status get_num_of_serdes(la_slice_id_t slice_id, la_ifg_id_t ifg_id, size_t& out_num_of_serdes) const override;
    la_status get_serdes_source(la_slice_id_t slice_id,
                                la_ifg_id_t ifg_id,
                                std::vector<la_uint_t>& out_serdes_mapping_vec) const override;
    la_status get_serdes_source(la_slice_id_t slice_id,
                                la_ifg_id_t ifg_id,
                                la_uint_t serdes_index,
                                la_uint_t& out_serdes) const override;
    la_status set_serdes_source(la_slice_id_t slice_id, la_ifg_id_t ifg_id, std::vector<la_uint_t> serdes_mapping_vec) override;
    la_status get_serdes_anlt_order(la_slice_id_t slice_id,
                                    la_ifg_id_t ifg_id,
                                    std::vector<la_uint_t>& out_serdes_mapping_vec) const override;
    la_status set_serdes_anlt_order(la_slice_id_t slice_id, la_ifg_id_t ifg_id, std::vector<la_uint_t> serdes_mapping_vec) override;
    la_status get_serdes_polarity_inversion(la_slice_id_t slice_id,
                                            la_ifg_id_t ifg_id,
                                            la_uint_t serdes_id,
                                            la_serdes_direction_e direction,
                                            bool& out_invert) const override;
    la_status set_serdes_polarity_inversion(la_slice_id_t slice_id,
                                            la_ifg_id_t ifg_id,
                                            la_uint_t serdes_id,
                                            la_serdes_direction_e direction,
                                            bool invert) override;
    la_status get_serdes_addr(la_slice_id_t slice,
                              la_ifg_id_t ifg,
                              la_uint_t serdes_idx,
                              la_serdes_direction_e direction,
                              la_uint_t& out_serdes_addr) override;

    la_status create_filter_group(la_filter_group*& out_filter_group) override;
    la_uint_t get_available_filter_groups() const override;

    la_status get_accounted_packet_overhead(int& out_overhead) const override;
    la_status set_accounted_packet_overhead(int overhead) override;

    la_status get_ifg_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) override;
    la_status get_native_sbus_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) override;
    la_status get_pci_aapl_handler(Aapl_t*& out_aapl) override;
    la_status get_hbm_aapl_handler(size_t hbm_interface, Aapl_t*& out_aapl) override;

    la_status destroy_aapl_handlers();

    la_status get_hbm_handler(la_hbm_handler*& out_hbm) override;
    la_status get_apb_handler(apb_interface_type_e interface_type, apb*& out_apb) override;
    la_status get_cpu2jtag_handler(cpu2jtag*& out_cpu2jtag) override;
    la_status get_info_phy_handler(la_info_phy_handler*& out_info_phy) override;

    la_status get_ptp_handler(la_ptp_handler*& out_ptp) override;
    la_status get_flow_cache_handler(la_flow_cache_handler*& out_flow_cache_handler) override;

    la_status get_valid_mac_port_configs(la_mac_port::mac_config_vec& out_config_vec) const override;

    la_status create_mac_port(la_slice_id_t slice_id,
                              la_ifg_id_t ifg_id,
                              la_uint_t first_serdes_id,
                              la_uint_t last_serdes_id,
                              la_mac_port::port_speed_e speed,
                              la_mac_port::fc_mode_e fc_mode,
                              la_mac_port::fec_mode_e fec_mode,
                              la_mac_port*& out_mac_port) override;

    la_status get_mac_port(la_slice_id_t slice_id,
                           la_ifg_id_t ifg_id,
                           la_uint_t serdes_id,
                           la_mac_port*& out_mac_port) const override;

    la_status create_channelized_mac_port(la_slice_id_t slice_id,
                                          la_ifg_id_t ifg_id,
                                          la_uint_t first_serdes_id,
                                          la_uint_t last_serdes_id,
                                          la_mac_port::port_speed_e speed,
                                          la_mac_port::fc_mode_e fc_mode,
                                          la_mac_port::fec_mode_e fec_mode,
                                          la_mac_port*& out_mac_port) override;

    la_status create_fabric_mac_port(la_slice_id_t slice_id,
                                     la_ifg_id_t ifg_id,
                                     la_uint_t first_serdes_id,
                                     la_uint_t last_serdes_id,
                                     la_mac_port::port_speed_e speed,
                                     la_mac_port::fc_mode_e fc_mode,
                                     la_mac_port*& out_mac_port) override;

    la_status create_fabric_port(la_mac_port* fabric_mac_port, la_fabric_port*& out_fabric_port) override;

    la_status create_pci_port(la_slice_id_t slice_id,
                              la_ifg_id_t ifg_id,
                              bool skip_kernel_driver,
                              la_pci_port*& out_pci_port) override;

    la_status create_recycle_port(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_recycle_port*& out_recycle_port) override;

    la_status create_remote_device(la_device_id_t remote_device_id,
                                   la_device_revision_e remote_device_revision,
                                   la_remote_device*& out_remote_device) override;

    la_status create_remote_port(la_remote_device* remote_device,
                                 la_slice_id_t remote_slice_id,
                                 la_ifg_id_t remote_ifg_id,
                                 la_uint_t remote_first_serdes_id,
                                 la_uint_t remote_last_serdes_id,
                                 la_mac_port::port_speed_e remote_port_speed,
                                 la_remote_port*& out_remote_port) override;

    la_status create_system_port(la_system_port_gid_t system_port_gid,
                                 la_mac_port* mac_port,
                                 la_voq_set* voq_set,
                                 const la_tc_profile* tc_profile,
                                 la_system_port*& out_system_port) override;
    la_status create_system_port(la_system_port_gid_t system_port_gid,
                                 la_port_extender_vid_t port_extender_vid,
                                 la_mac_port* mac_port,
                                 la_voq_set* voq_set,
                                 const la_tc_profile* tc_profile,
                                 la_system_port*& out_system_port) override;
    la_status create_system_port(la_system_port_gid_t system_port_gid,
                                 la_recycle_port* recycle_port,
                                 la_voq_set* voq_set,
                                 const la_tc_profile* tc_profile,
                                 la_system_port*& out_system_port) override;
    la_status create_system_port(la_system_port_gid_t system_port_gid,
                                 la_pci_port* pci_port,
                                 la_voq_set* voq_set,
                                 const la_tc_profile* tc_profile,
                                 la_system_port*& out_system_port) override;
    la_status create_system_port(la_system_port_gid_t system_port_gid,
                                 la_remote_port* remote_port,
                                 la_voq_set* voq_set,
                                 const la_tc_profile* tc_profile,
                                 la_system_port*& out_system_port) override;

    la_status create_spa_port(la_spa_port_gid_t spa_port_gid, la_spa_port*& out_spa_port) override;

    la_status create_punt_inject_port(la_system_port* system_port,
                                      la_mac_addr_t mac_addr,
                                      la_punt_inject_port*& out_punt_inject_port) override;

    la_status create_l2_punt_destination(la_l2_punt_destination_gid_t gid,
                                         la_punt_inject_port* pi_port,
                                         la_mac_addr_t mac_addr,
                                         la_vlan_tag_tci_t vlan_tag,
                                         la_l2_punt_destination*& out_punt_dest) override;

    la_status create_l2_punt_destination(la_l2_punt_destination_gid_t gid,
                                         la_stack_port* stack_port,
                                         la_mac_addr_t mac_addr,
                                         la_vlan_tag_tci_t vlan_tag,
                                         la_l2_punt_destination*& out_punt_dest) override;

    la_status get_l2_punt_destination_by_gid(la_l2_punt_destination_gid_t gid,
                                             la_l2_punt_destination*& out_punt_dest) const override;

    la_status create_npu_host_port(la_remote_device* remote_device,
                                   la_system_port_gid_t system_port_gid,
                                   la_voq_set* voq_set,
                                   const la_tc_profile* tc_profile,
                                   la_npu_host_port*& out_npu_host_port) override;

    la_status create_npu_host_destination(la_npu_host_port* system_port,
                                          la_npu_host_destination*& out_npu_host_destination) override;

    la_status create_erspan_mirror_command(la_mirror_gid_t mirror_gid,
                                           la_erspan_mirror_command::ipv4_encapsulation encap_data,
                                           la_uint_t voq_offset,
                                           const la_system_port* dsp,
                                           float probability,
                                           la_erspan_mirror_command*& out_mirror_cmd) override;

    la_status create_erspan_mirror_command(la_mirror_gid_t mirror_gid,
                                           la_erspan_mirror_command::ipv6_encapsulation encap_data,
                                           la_uint_t voq_offset,
                                           const la_system_port* dsp,
                                           float probability,
                                           la_erspan_mirror_command*& out_mirror_cmd) override;

    la_status do_create_l2_mirror_command(la_mirror_gid_t mirror_gid,
                                          la_punt_inject_port* punt_inject_port,
                                          la_system_port* system_port,
                                          la_mac_addr_t mac_addr,
                                          la_vlan_tag_tci_t vlan_tag,
                                          la_uint_t voq_offset,
                                          const la_meter_set* meter,
                                          float probability,
                                          la_l2_mirror_command*& out_mirror_cmd);

    la_status create_l2_mirror_command(la_mirror_gid_t mirror_gid,
                                       la_punt_inject_port* punt_inject_port,
                                       la_mac_addr_t mac_addr,
                                       la_vlan_tag_tci_t vlan_tag,
                                       la_uint_t voq_offset,
                                       const la_meter_set* meter,
                                       float probability,
                                       la_l2_mirror_command*& out_mirror_cmd) override;

    la_status create_mc_lpts_mirror_command(la_mirror_gid_t mirror_gid,
                                            la_system_port* system_port,
                                            la_l2_mirror_command*& out_mirror_cmd) override;

    la_status create_l2_mirror_command(la_mirror_gid_t mirror_gid,
                                       la_ethernet_port* eth_port,
                                       la_system_port* system_port,
                                       la_uint_t voq_offset,
                                       float probability,
                                       la_l2_mirror_command*& out_mirror_cmd) override;

    la_status get_trap_configuration(la_event_e trap,
                                     la_trap_priority_t& out_priority,
                                     la_counter_or_meter_set*& out_counter_or_meter,
                                     const la_punt_destination*& out_destination,
                                     bool& out_skip_inject_up_packets,
                                     bool& out_skip_p2p_packets,
                                     bool& out_overwrite_phb,
                                     la_traffic_class_t& out_tc) override;
    la_status set_trap_configuration(la_event_e trap,
                                     la_trap_priority_t priority,
                                     la_counter_or_meter_set* counter_or_meter,
                                     const la_punt_destination* destination,
                                     bool skip_inject_up_packets,
                                     bool skip_p2p_packets,
                                     bool overwrite_phb,
                                     la_traffic_class_t tc) override;
    la_status do_clear_trap_configuration(la_event_e trap);
    la_status clear_trap_configuration(la_event_e trap) override;
    la_status get_snoop_configuration(la_event_e snoop,
                                      la_snoop_priority_t& out_priority,
                                      const la_mirror_command*& out_mirror_cmd) override;
    la_status do_set_snoop_configuration(la_event_e snoop,
                                         la_snoop_priority_t priority,
                                         bool skip_inject_up_packets,
                                         bool skip_p2p_packets,
                                         const la_mirror_command* mirror_cmd);
    la_status set_snoop_configuration(la_event_e snoop,
                                      la_snoop_priority_t priority,
                                      bool skip_inject_up_packets,
                                      bool skip_p2p_packets,
                                      const la_mirror_command* mirror_cmd) override;
    la_status set_mc_lpts_snoop_configuration(la_snoop_priority_t priority,
                                              bool skip_inject_up_packets,
                                              bool skip_p2p_packets,
                                              const la_mirror_command* mirror_cmd) override;
    la_status clear_snoop_configuration(la_event_e snoop) override;

    la_status create_ethernet_port(la_system_port* system_port,
                                   la_ethernet_port::port_type_e type,
                                   la_ethernet_port*& out_ethernet_port) override;

    la_status create_ethernet_port(la_spa_port* spa_port,
                                   la_ethernet_port::port_type_e type,
                                   la_ethernet_port*& out_ethernet_port) override;

    la_status create_ac_l2_service_port(la_l2_port_gid_t port_gid,
                                        const la_ethernet_port* ethernet_port,
                                        la_vlan_id_t vid1,
                                        la_vlan_id_t vid2,
                                        const la_filter_group* filter_group,
                                        la_ingress_qos_profile* ingress_qos_profile,
                                        la_egress_qos_profile* egress_qos_profile,
                                        la_l2_service_port*& out_l2_service_port) override;

    la_status create_pwe_l2_service_port(la_l2_port_gid_t port_gid,
                                         la_mpls_label local_label,
                                         la_mpls_label remote_label,
                                         la_pwe_gid_t pwe_gid,
                                         la_l3_destination* destination,
                                         la_ingress_qos_profile* ingress_qos_profile,
                                         la_egress_qos_profile* egress_qos_profile,
                                         la_l2_service_port*& out_l2_service_port) override;

    la_status create_pwe_tagged_l2_service_port(la_l2_port_gid_t port_gid,
                                                la_mpls_label local_label,
                                                la_mpls_label remote_label,
                                                la_l3_destination* destination,
                                                la_vlan_id_t vid1,
                                                la_ingress_qos_profile* ingress_qos_profile,
                                                la_egress_qos_profile* egress_qos_profile,
                                                la_l2_service_port*& out_l2_service_port) override;

    la_status create_vxlan_l2_service_port(la_l2_port_gid_t port_gid,
                                           la_ipv4_addr_t local_ip_addr,
                                           la_ipv4_addr_t remote_ip_addr,
                                           la_vrf* vrf,
                                           la_l2_service_port*& out_l2_service_port) override;

    la_status create_vxlan_l2_service_port(la_l2_port_gid_t port_gid,
                                           la_ip_tunnel_mode_e tunnel_mode,
                                           la_ipv4_prefix_t local_ip_prefix,
                                           la_ipv4_addr_t remote_ip_addr,
                                           la_vrf* vrf,
                                           la_l2_service_port*& out_l2_service_port) override;

    la_status create_stack_port(la_system_port* system_port, la_stack_port*& out_stack_port) override;
    la_status create_stack_port(la_spa_port* spa_port, la_stack_port*& out_stack_port) override;

    la_status create_protection_monitor(la_protection_monitor*& out_protection_monitor) override;
    la_status create_multicast_protection_monitor(la_multicast_protection_monitor*& out_protection_monitor) override;

    la_status create_l2_protection_group(la_l2_port_gid_t group_gid,
                                         la_l2_destination* primary_destination,
                                         la_l2_destination* protecting_destination,
                                         la_protection_monitor* protection_monitor,
                                         la_l2_protection_group*& out_l2_protection_group) override;
    la_status get_l2_protection_group_by_id(la_l2_port_gid_t group_gid,
                                            la_l2_protection_group*& out_l2_protection_group) const override;
    la_status create_l3_protection_group(la_l3_protection_group_gid_t group_gid,
                                         la_l3_destination* primary_destination,
                                         la_l3_destination* protecting_destination,
                                         la_protection_monitor* protection_monitor,
                                         la_l3_protection_group*& out_l3_protection_group) override;
    la_status create_multicast_protection_group(la_next_hop* primary_destination,
                                                la_system_port* primary_system_port,
                                                la_next_hop* protecting_destination,
                                                la_system_port* protecting_system_port,
                                                la_multicast_protection_monitor* protection_monitor,
                                                la_multicast_protection_group*& out_multicast_protection_group) override;
    la_status get_l3_protection_group_by_id(la_l3_protection_group_gid_t group_gid,
                                            la_l3_protection_group*& out_l3_protection_group) const override;

    // Bridge API-s
    la_status create_switch(la_switch_gid_t switch_gid, la_switch*& out_switch) override;

    la_switch* get_switch_by_id(la_switch_gid_t sw_gid) override;

    la_status create_ac_profile(la_ac_profile*& out_ac_profile) override;
    size_t get_num_of_available_ac_profiles() const override;

    // Multicast API-s
    la_status create_l2_multicast_group(la_multicast_group_gid_t multicast_gid,
                                        la_replication_paradigm_e rep_paradigm,
                                        la_l2_multicast_group*& out_group) override;

    la_status do_create_ip_multicast_group(la_multicast_group_gid_t multicast_gid,
                                           la_replication_paradigm_e rep_paradigm,
                                           la_ip_multicast_group_pacific_wptr& out_group);

    la_status create_ip_multicast_group(la_multicast_group_gid_t multicast_gid,
                                        la_replication_paradigm_e rep_paradigm,
                                        la_ip_multicast_group*& out_group) override;

    la_status create_fabric_multicast_group(la_multicast_group_gid_t multicast_gid,
                                            la_replication_paradigm_e rep_paradigm,
                                            la_fabric_multicast_group*& out_fabric_multicast_group) override;

    la_status create_mpls_multicast_group(la_multicast_group_gid_t multicast_gid,
                                          la_replication_paradigm_e rep_paradigm,
                                          la_mpls_multicast_group*& out_group) override;
    la_status get_l2_multicast_group(la_multicast_group_gid_t multicast_gid,
                                     la_l2_multicast_group*& out_l2_multicast_group) const override;
    la_status get_ip_multicast_group(la_multicast_group_gid_t multicast_gid,
                                     la_ip_multicast_group*& out_ip_multicast_group) const override;
    la_status get_mpls_multicast_group(la_multicast_group_gid_t multicast_gid,
                                       la_mpls_multicast_group*& out_mpls_multicast_group) const override;
    la_status get_fabric_multicast_group(la_multicast_group_gid_t multicast_gid,
                                         la_fabric_multicast_group*& out_fabric_multicast_group) const override;

    la_status create_mpls_label_destination(la_l3_destination_gid_t gid,
                                            la_mpls_label label,
                                            la_l3_destination* destination,
                                            la_mpls_label_destination*& out_mpls_label_destination) override;

    la_status create_mpls_vpn_encap(la_mpls_vpn_encap_gid_t gid, la_mpls_vpn_encap*& out_mpls_vpn_encap) override;

    la_status get_mpls_vpn_encap_by_gid(la_mpls_vpn_encap_gid_t gid, la_mpls_vpn_encap*& out_mpls_vpn_encap) const override;
    la_status create_prefix_object(la_l3_destination_gid_t gid,
                                   const la_l3_destination* destination,
                                   la_prefix_object::prefix_type_e type,
                                   la_prefix_object*& out_prefix) override;

    la_status get_prefix_object_by_id(la_l3_destination_gid_t gid, la_prefix_object*& out_prefix) const override;

    la_status create_ip_tunnel_destination(la_l3_destination_gid_t gid,
                                           const la_l3_port* ip_tunnel_port,
                                           const la_l3_destination* underlay_destination,
                                           la_ip_tunnel_destination*& out_ip_tunnel_destination) override;

    la_status get_ip_tunnel_destination_by_gid(la_l3_destination_gid_t gid,
                                               la_ip_tunnel_destination*& out_ip_tunnel_destination) const override;

    la_status create_destination_pe(la_l3_destination_gid_t destination_pe_gid,
                                    const la_l3_destination* destination,
                                    la_destination_pe*& out_destination_pe) override;
    la_status create_asbr_lsp(const la_prefix_object* asbr,
                              const la_l3_destination* destination,
                              la_asbr_lsp*& out_asbr_lsp) override;
    la_status get_asbr_lsp(const la_prefix_object* asbr, const la_l3_destination* destination, la_asbr_lsp*& out_asbr_lsp) override;

    la_status create_te_tunnel(la_te_tunnel_gid_t gid,
                               const la_l3_destination* destination,
                               la_te_tunnel::tunnel_type_e type,
                               la_te_tunnel*& out_te_tunnel) override;

    la_status create_pbts_map_profile(la_pbts_map_profile::level_e level,
                                      la_pbts_destination_offset max_offset,
                                      la_pbts_map_profile*& out_pbts_map_profile) override;

    la_status create_pbts_group(la_pbts_map_profile* profile, la_pbts_group*& out_pbts_group) override;

    la_status create_mpls_swap_nhlfe(const la_next_hop* next_hop, la_mpls_label label, la_mpls_nhlfe*& out_nhlfe) override;
    la_status create_mpls_php_nhlfe(const la_next_hop* next_hop, la_mpls_nhlfe*& out_nhlfe) override;
    la_status create_mpls_tunnel_protection_nhlfe(const la_l3_protection_group* l3_protection_group,
                                                  la_mpls_label te_label,
                                                  la_mpls_label mp_label,
                                                  la_mpls_nhlfe*& out_nhlfe) override;
    la_status create_mpls_l2_adjacency_nhlfe(const la_prefix_object* prefix,
                                             const la_system_port* dsp,
                                             la_mpls_nhlfe*& out_nhlfe) override;

    la_status get_lsr(la_lsr*& out_lsr) override;
    la_status set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode) override;
    la_mpls_ttl_inheritance_mode_e get_ttl_inheritance_mode() const override;

    la_status get_forus_destination(la_forus_destination*& out_forus_destination) override;

    // TM API-s
    la_status set_fabric_mode(la_fabric_mode_e mode) override;

    la_status set_slb_fabric_delay(la_float_t delay) override;

    la_status set_ifg_maximum_pps_utilization(la_float_t max_pps_percent) override;
    la_status get_ifg_maximum_pps_utilization(la_float_t& out_max_pps_percent) const override;

    la_status get_ifg_scheduler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_ifg_scheduler*& out_sch) const override;

    la_status create_output_queue_scheduler(la_slice_id_t slice_id,
                                            la_ifg_id_t ifg_id,
                                            la_output_queue_scheduler::scheduling_mode_e mode,
                                            la_output_queue_scheduler*& out_oq_sch) override;

    la_status set_fabric_sch_valid_links_quantization_thresholds(const la_fabric_valid_links_thresholds& thresholds) override;
    la_status get_fabric_sch_valid_links_quantization_thresholds(la_fabric_valid_links_thresholds& out_thresholds) override;
    la_status set_fabric_sch_congested_links_quantization_thresholds(
        const la_fabric_congested_links_thresholds& thresholds) override;
    la_status get_fabric_sch_congested_links_quantization_thresholds(la_fabric_congested_links_thresholds& out_thresholds) override;
    la_status set_fabric_sch_rate_map_entry(la_uint_t index, la_uint_t rate) override;
    la_status get_fabric_sch_rate_map_entry(la_uint_t index, la_uint_t& out_rate) override;
    la_status set_fabric_sch_links_map_entry(la_uint_t valid_link_status,
                                             la_uint_t congested_link_status,
                                             la_uint_t rate_map_index) override;
    la_status get_fabric_sch_links_map_entry(la_uint_t valid_link_status,
                                             la_uint_t congested_link_status,
                                             la_uint_t& out_rate_map_index) override;

    // VOQ API-s
    la_status create_voq_set(la_voq_gid_t base_voq_id,
                             size_t set_size,
                             const la_vsc_gid_vec_t& base_vsc_vec,
                             la_device_id_t dest_device,
                             la_slice_id_t dest_slice,
                             la_ifg_id_t dest_ifg,
                             la_voq_set*& out_voq_set) override;

    la_status create_voq_counter_set(la_voq_set::voq_counter_type_e type,
                                     size_t group_size,
                                     la_counter_set* counter,
                                     la_voq_gid_t base_voq_id,
                                     size_t voq_set_size);

    la_status destroy_voq_counter_set(la_voq_gid_t base_voq_id, size_t voq_set_size);

    la_status get_npu_error_counter(la_counter_set*& out_counter) override;
    la_status get_forwarding_drop_counter(la_counter_set*& out_counter) override;

    // Traffic class API-s
    la_status create_tc_profile(la_tc_profile*& out_tc_profile) override;

    // MC VOQ functions

    la_status get_egress_multicast_slice_replication_voq_set(la_slice_id_t dest_slice, la_voq_set*& out_voq_set) const override;
    la_status set_egress_multicast_slice_replication_tc_mapping(la_traffic_class_t tc, la_uint_t voq_offset) override;

    la_status get_egress_multicast_fabric_replication_voq_set(la_voq_set*& out_voq_set) const override;

    // Security Group API-s
    la_status set_sda_mode(bool mode) override;
    la_status get_sda_mode(bool& out_mode) const override;
    la_status create_security_group_cell(la_sgt_t sgt,
                                         la_dgt_t dgt,
                                         la_ip_version_e ip_version,
                                         la_security_group_cell*& out_security_group_cell) override;

    /// @brief   Set per-slice VOQ-set for egress replication.
    ///
    /// @note Provided VOQ set should have 2 members: one for high-priority traffic (offset 0),
    /// and one for low-priority traffic (offset 1).
    /// @note VSCs must be in multicast VSCs reserved range [#SA_MC_VSC_RANGE_START, #SA_MC_VSC_RANGE_END].
    ///
    /// @param[in]  dest_slice          Destination slice ID.
    /// @param[in]  voq_set             VOQ set.
    ///
    /// @retval     LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval     LA_STATUS_EBUSY          The given VOQ set is already in use.
    /// @retval     LA_STATUS_EINVAL         Invalid VOQ set.
    /// @retval     LA_STATUS_EINVAL         Invalid VOQ set size.
    /// @retval     LA_STATUS_EOUTOFRANGE    VSCs out of range.
    /// @retval     LA_STATUS_EUNKNOWN       An unknown error occurred.
    la_status set_egress_multicast_slice_replication_voq_set(la_slice_id_t dest_slice, const la_voq_set_impl_wptr& voq_set);

    /// @brief   Clear per-slice VOQ-set for egress replication.
    ///
    /// @param[in]  dest_slice          Destination slice ID.
    ///
    /// @retval     LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND      No VOQ set on slice.
    /// @retval     LA_STATUS_EUNKNOWN       An unknown error occurred.
    la_status clear_egress_multicast_slice_replication_voq_set(la_slice_id_t dest_slice);

    la_status get_mc_bitmap_base_lookup_table_values(la_slice_id_t dest_slice,
                                                     uint64_t& out_tc_mac_profile,
                                                     uint64_t& out_base_voq);

    // IP Prefix inactivity Functions
    la_status add_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv4_prefix_t prefix) override;
    la_status remove_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv4_prefix_t prefix) override;
    la_status add_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv6_prefix_t prefix) override;
    la_status remove_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv6_prefix_t prefix) override;
    la_status get_source_ip_snooping_prefixes(la_ip_snooping_entry_vec_t& out_ip_snooping_prefixes) override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Resolution API-s
    la_status create_l3_fec_wrapper(const la_l3_destination_wptr& destination, la_l3_fec_impl_sptr& out_fec);
    la_status create_l3_fec_wrapper(const la_l2_destination_wptr& destination, la_l3_fec_impl_sptr& out_fec);
    la_status destroy_l3_fec_wrapper(const la_l3_fec_impl_wptr& fec);

    la_status set_ipv6_ext_header_trap_enabled(la_ipv6_extension_header_t ext_hdr_id, bool enabled) override;
    la_status create_vrf(la_vrf_gid_t vrf_gid, la_vrf*& out_vrf) override;
    la_status get_vrf_by_id(la_vrf_gid_t vrf_gid, la_vrf*& out_vrf) const override;
    la_status get_next_hop_by_id(la_next_hop_gid_t nh_gid, la_next_hop*& out_next_hop) const override;
    la_status create_next_hop(la_next_hop_gid_t nh_gid,
                              la_mac_addr_t nh_mac_addr,
                              la_l3_port* port,
                              la_next_hop::nh_type_e nh_type,
                              la_next_hop*& out_next_hop) override;
    la_status create_vxlan_next_hop(la_mac_addr_t nh_mac_addr,
                                    la_l3_port* port,
                                    la_l2_service_port* vxlan_port,
                                    la_vxlan_next_hop*& out_vxlan_next_hop) override;
    la_status create_l3_fec(la_l3_destination* destination, la_l3_fec*& out_fec) override;
    la_status create_l3_ac_port(la_l3_port_gid_t port_gid,
                                const la_ethernet_port* ethernet_port,
                                la_vlan_id_t vid1,
                                la_vlan_id_t vid2,
                                la_mac_addr_t mac_addr,
                                la_vrf* vrf,
                                la_ingress_qos_profile* ingress_qos_profile,
                                la_egress_qos_profile* egress_qos_profile,
                                la_l3_ac_port*& out_l3_ac_port) override;

    la_status create_svi_port(la_l3_port_gid_t gid,
                              const la_switch* sw,
                              const la_vrf* vrf,
                              la_mac_addr_t mac_addr,
                              la_ingress_qos_profile* ingress_qos_profile,
                              la_egress_qos_profile* egress_qos_profile,
                              la_svi_port*& out_svi_port) override;

    la_status create_ip_over_ip_tunnel_port(la_l3_port_gid_t port_gid,
                                            la_vrf* underlay_vrf,
                                            la_ipv4_prefix_t prefix,
                                            la_ipv4_addr_t ip_addr,
                                            la_vrf* vrf,
                                            la_ingress_qos_profile* ingress_qos_profile,
                                            la_egress_qos_profile* egress_qos_profile,
                                            la_ip_over_ip_tunnel_port*& out_ip_over_ip_tunnel_port) override;

    la_status create_ip_over_ip_tunnel_port(la_l3_port_gid_t port_gid,
                                            la_ip_tunnel_mode_e tunnel_mode,
                                            la_vrf* underlay_vrf,
                                            la_ipv4_prefix_t prefix,
                                            la_ipv4_addr_t ip_addr,
                                            la_vrf* vrf,
                                            la_ingress_qos_profile* ingress_qos_profile,
                                            la_egress_qos_profile* egress_qos_profile,
                                            la_ip_over_ip_tunnel_port*& out_ip_over_ip_tunnel_port) override;

    la_status create_gue_port(la_l3_port_gid_t port_gid,
                              la_ip_tunnel_mode_e tunnel_mode,
                              la_vrf* underlay_vrf,
                              la_ipv4_prefix_t local_prefix,
                              la_ipv4_addr_t remote_ip_addr,
                              la_vrf* overlay_vrf,
                              la_ingress_qos_profile* ingress_qos_profile,
                              la_egress_qos_profile* egress_qos_profile,
                              la_gue_port*& out_gue_port) override;

    la_status create_gre_port(la_l3_port_gid_t port_gid,
                              const la_vrf* underlay_vrf,
                              la_ipv4_addr_t local_ip_addr,
                              la_ipv4_addr_t remote_ip_addr,
                              const la_vrf* overlay_vrf,
                              la_ingress_qos_profile* ingress_qos_profile,
                              la_egress_qos_profile* egress_qos_profile,
                              la_gre_port*& out_gre_port) override;

    la_status create_gre_port(la_l3_port_gid_t port_gid,
                              la_ip_tunnel_mode_e tunnel_mode,
                              const la_vrf* underlay_vrf,
                              la_ipv4_addr_t local_ip_addr,
                              la_ipv4_addr_t remote_ip_addr,
                              const la_vrf* overlay_vrf,
                              la_ingress_qos_profile* ingress_qos_profile,
                              la_egress_qos_profile* egress_qos_profile,
                              la_gre_port*& out_gre_port) override;

    la_status get_gre_port_by_gid(la_l3_port_gid_t port_gid, la_gre_port*& out_gre_port) const override;

    la_status create_ecmp_group(la_ecmp_group::level_e level, la_ecmp_group*& out_ecmp_group) override;

    la_status set_acl_scaled_enabled(bool enabled) override;
    la_status get_acl_scaled_enabled(bool& out_enabled) override;

    la_status set_acl_scaled_enabled(la_slice_pair_id_t slice, la_acl_id_t acl_id, bool enabled);
    la_status get_acl_scaled_enabled(la_slice_pair_id_t slice, la_acl_id_t acl_id, bool& out_enabled);

    la_status create_acl_key_profile(la_acl_key_type_e key_type,
                                     la_acl_direction_e dir,
                                     const la_acl_key_def_vec_t& key_def,
                                     la_acl_tcam_pool_id_t tcam_pool_id,
                                     la_acl_key_profile*& out_acl_key_profile) override;

    la_status create_acl_command_profile(const la_acl_command_def_vec_t& command_def,
                                         la_acl_command_profile*& out_acl_command_profile) override;

    la_status create_acl(const la_acl_key_profile* acl_key_profile,
                         const la_acl_command_profile* acl_command_profile,
                         la_acl*& out_acl) override;

    la_status create_acl(const la_acl_key_profile* acl_key_profile,
                         const la_acl_command_profile* acl_command_profile,
                         la_pcl* src_pcl,
                         la_pcl* dst_pcl,
                         la_acl*& out_acl) override;

    la_status create_acl_internal(const la_acl_key_profile* acl_key_profile,
                                  const la_acl_command_profile* acl_command_profile,
                                  la_pcl* src_pcl,
                                  la_pcl* dst_pcl,
                                  la_acl*& out_acl);

    la_status create_acl_group(la_acl_group*& out_acl_group) override;
    la_status reserve_acl(la_acl* acl) override;

    la_status set_acl_range(la_acl::stage_e stage,
                            la_acl::range_type_e range,
                            la_uint_t idx,
                            la_uint16_t rstart,
                            la_uint16_t rend) override;

    la_status create_pcl(const la_pcl_v4_vec_t& prefixes, const pcl_feature_type_e& feature, la_pcl*& out_pcl) override;
    la_status create_pcl(const la_pcl_v6_vec_t& prefixes, const pcl_feature_type_e& feature, la_pcl*& out_pcl) override;
    la_status create_lpts(lpts_type_e type, silicon_one::la_lpts*& out_lpts) override;
    la_status create_copc(la_control_plane_classifier::type_e type, la_control_plane_classifier*& out_copc) override;
    la_status create_og_lpts_app(const la_lpts_app_properties& properties,
                                 la_pcl* src_pcl,
                                 la_og_lpts_application*& out_lpts_app) override;

    la_status create_voq_cgm_evicted_profile(la_voq_cgm_evicted_profile*& out_evicted_profile) override;
    la_status get_voq_cgm_default_evicted_profile(const la_voq_cgm_evicted_profile*& out_evicted_profile) const override;
    la_status set_rx_pdr_sms_bytes_drop_thresholds(const la_rx_pdr_sms_bytes_drop_thresholds& thresholds) override;
    la_status get_rx_pdr_sms_bytes_drop_thresholds(la_rx_pdr_sms_bytes_drop_thresholds& out_thresholds) override;

    la_status set_rx_cgm_sms_bytes_quantization(const la_rx_cgm_sms_bytes_quantization_thresholds& thresholds) override;
    la_status get_rx_cgm_sms_bytes_quantization(la_rx_cgm_sms_bytes_quantization_thresholds& out_thresholds) override;
    la_status set_rx_cgm_sqg_thresholds(la_uint_t group_index, const la_rx_cgm_sqg_thresholds& thresholds) override;
    la_status get_rx_cgm_sqg_thresholds(la_uint_t group_index, la_rx_cgm_sqg_thresholds& out_thresholds) override;
    la_status create_rx_cgm_sq_profile(la_rx_cgm_sq_profile*& out_rx_cgm_sq_profile) override;
    la_status get_default_rx_cgm_sq_profile(la_rx_cgm_sq_profile*& out_default_rx_cgm_sq_profile) override;
    la_status set_pfc_headroom_mode(la_rx_cgm_headroom_mode_e mode) override;
    la_status get_pfc_headroom_mode(la_rx_cgm_headroom_mode_e& out_mode) override;
    la_status read_rx_cgm_drop_counter(la_slice_id_t slice, la_uint_t counter_index, la_uint_t& out_packets) override;

    la_status set_tx_cgm_port_oq_profile_thresholds(la_slice_id_t slice,
                                                    la_mac_port::port_speed_e port_speed,
                                                    const la_tx_cgm_oq_profile_thresholds& thresholds) override;
    la_status get_tx_cgm_port_oq_profile_thresholds(la_slice_id_t slice,
                                                    la_mac_port::port_speed_e port_speed,
                                                    la_tx_cgm_oq_profile_thresholds& out_thresholds) override;
    la_status set_tx_cgm_pfc_port_oq_profile_thresholds(la_slice_id_t slice,
                                                        la_mac_port::port_speed_e port_speed,
                                                        const la_tx_cgm_oq_profile_thresholds& thresholds) override;
    la_status get_tx_cgm_pfc_port_oq_profile_thresholds(la_slice_id_t slice,
                                                        la_mac_port::port_speed_e port_speed,
                                                        la_tx_cgm_oq_profile_thresholds& out_thresholds) override;

    la_status set_pfc_additional_link_tuning(bool use_long_links) override;

    la_status set_voq_max_negative_credit_balance(la_uint_t balance) override;
    la_status get_voq_max_negative_credit_balance(la_uint_t& out_balance) override;

    la_status create_voq_cgm_profile(la_voq_cgm_profile*& out_profile) override;
    la_status set_cgm_sms_voqs_bytes_quantization(const la_cgm_sms_bytes_quantization_thresholds& thresholds) override;
    la_status get_cgm_sms_voqs_bytes_quantization(la_cgm_sms_bytes_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_sms_voqs_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_cgm_sms_voqs_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_sms_voqs_packets_quantization(const la_cgm_sms_packets_quantization_thresholds& thresholds) override;
    la_status get_cgm_sms_voqs_packets_quantization(la_cgm_sms_packets_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_sms_voqs_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_cgm_sms_voqs_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_sms_evicted_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_cgm_sms_evicted_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_hbm_number_of_voqs_quantization(const la_cgm_hbm_number_of_voqs_quantization_thresholds& thresholds) override;
    la_status get_cgm_hbm_number_of_voqs_quantization(
        la_cgm_hbm_number_of_voqs_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_hbm_number_of_voqs_quantization(const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_cgm_hbm_number_of_voqs_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const override;
    la_status set_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float threshold) override;
    la_status get_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float& out_threshold) const override;
    la_status set_cgm_hbm_pool_free_blocks_quantization(
        la_cgm_hbm_pool_id_t hbm_pool_id,
        const la_cgm_hbm_pool_free_blocks_quantization_thresholds& thresholds) override;
    la_status get_cgm_hbm_pool_free_blocks_quantization(
        la_cgm_hbm_pool_id_t hbm_pool_id,
        la_cgm_hbm_pool_free_blocks_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                        const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                        la_voq_cgm_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_hbm_voq_age_quantization(const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_cgm_hbm_voq_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_hbm_blocks_by_voq_quantization(const la_cgm_hbm_blocks_by_voq_quantization_thresholds& thresholds) override;
    la_status get_cgm_hbm_blocks_by_voq_quantization(
        la_cgm_hbm_blocks_by_voq_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_hbm_blocks_by_voq_quantization(const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_cgm_hbm_blocks_by_voq_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const override;
    la_status set_cgm_sms_voqs_age_time_granularity(la_cgm_sms_voqs_age_time_units_t sms_voqs_age_time_units) override;
    la_status get_cgm_sms_voqs_age_time_granularity(la_cgm_sms_voqs_age_time_units_t& out_sms_voqs_age_time_units) const override;
    la_status create_counter(size_t set_size, la_counter_set*& out_counter) override;

    la_status create_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) override;
    la_status create_egress_qos_profile(la_egress_qos_marking_source_e marking_source,
                                        la_egress_qos_profile*& out_egress_qos_profile) override;
    la_status get_limit(limit_type_e limit_type, la_uint64_t& out_limit) const override;
    la_status get_precision(la_precision_type_e precision_type, double& out_precision) const override;

    la_status is_property_supported(la_device_property_e device_property, bool& supported) const override;
    la_status set_bool_property(la_device_property_e device_property, bool property_value) override;
    la_status get_bool_property(la_device_property_e device_property, bool& out_property_value) const override;
    la_status set_int_property(la_device_property_e device_property, int property_value) override;
    la_status get_int_property(la_device_property_e device_property, int& out_property_value) const override;
    la_status set_string_property(la_device_property_e device_property, std::string property_value) override;
    la_status get_string_property(la_device_property_e device_property, std::string& out_property_value) const override;

    la_status create_meter(la_meter_set::type_e set_type, size_t set_size, la_meter_set*& out_meter) override;
    la_status create_rate_limiter(la_system_port* system_port, la_rate_limiter_set*& out_rate_limiter_set) override;
    la_status create_meter_profile(la_meter_profile::type_e profile_type,
                                   la_meter_profile::meter_measure_mode_e meter_measure_mode,
                                   la_meter_profile::meter_rate_mode_e meter_rate_mode,
                                   la_meter_profile::color_awareness_mode_e color_awareness_mode,
                                   la_meter_profile*& out_meter_profile) override;
    la_status create_meter_action_profile(la_meter_action_profile*& out_meter_action_profile) override;
    la_status create_meter_markdown_profile(la_meter_markdown_gid_t meter_markdown_gid,
                                            la_meter_markdown_profile*& out_meter_markdown_profile) override;
    la_status get_meter_markdown_profile_by_id(la_meter_markdown_gid_t meter_markdown_gid,
                                               la_meter_markdown_profile*& out_meter_markdown_profile) const override;

    la_status open_notification_fds(int mask, int& out_fd_critical, int& out_fd_normal) override;
    la_status close_notification_fds() override;

    la_status diagnostics_test(test_feature_e feature) override;

    la_status get_granularity(la_resource_descriptor::type_e resource_type,
                              la_resource_granularity& out_granularity) const override;
    la_status get_resource_usage(la_resource_usage_descriptor_vec& out_descriptor) const override;
    la_status get_resource_usage(la_resource_descriptor::type_e resource_type,
                                 la_resource_usage_descriptor_vec& out_descriptors) const override;
    la_status get_resource_usage(const la_resource_descriptor& resource_descriptor,
                                 la_resource_usage_descriptor& out_descriptors) const override;
    la_status set_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                   const std::vector<la_resource_thresholds>& thresholds_vec) override;
    la_status get_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                   std::vector<la_resource_thresholds>& out_thresholds_vec) const override;

    la_status flush() const override;

    la_status get_temperature(la_temperature_sensor_e sensor, la_temperature_t& out_temperature) override;

    la_status save_state(save_state_options options, std::string file_name) const override;
    la_status save_state(save_state_options options, json_t*& out_json) const override;
    la_status set_periodic_save_state_period(const std::chrono::milliseconds period) override;
    la_status set_periodic_save_state_parameters(const save_state_options& options, const std::string& file_name_prefix) override;
    la_status get_periodic_save_state_period(std::chrono::milliseconds& out_period) const override;
    la_status get_periodic_save_state_parameters(save_state_options& out_options, std::string& out_file_name_prefix) const override;
    la_status save_internal_states(std::vector<std::string> internal_states_vec, std::string file_name) const;
    la_status save_internal_states(std::vector<std::string> internal_states_vec, json_t*& out_json) const;

    template <class _Table>
    la_status append_table_properties_to_json(_Table& table, json_t* table_prop_array_json) const;
    la_status get_table_allocations(json_t* tables_array_json) const;
    la_status get_counter_allocations(json_t* counters_array_json) const;
    la_status get_tcam_allocations(json_t* tcam_array_json) const;

    la_status save_all_mac_port_state(json_t* out_root) const;

    la_status get_voltage(la_voltage_sensor_e sensor, la_voltage_t& out_voltage) override;

    // VLAN editing API-s
    la_status get_npl_vlan_edit_command(const la_vlan_edit_command& edit_command, npl_ive_profile_and_data_t& npl_edit_command);
    la_status get_la_vlan_edit_command(const npl_ive_profile_and_data_t& npl_edit_command, la_vlan_edit_command& out_edit_command);

    // Trap get/set body
    la_status do_get_trap_configuration(la_event_e trap,
                                        la_trap_priority_t& out_priority,
                                        la_counter_or_meter_set*& out_counter_or_meter,
                                        const la_punt_destination*& out_destination,
                                        bool& out_skip_inject_up_packets,
                                        bool& out_skip_p2p_packets,
                                        bool& out_overwrite_phb,
                                        la_traffic_class_t& out_tc);
    la_status check_trap_skip_p2p_packets(la_event_e trap, bool skip_p2p_packets);
    la_status do_set_trap_configuration(la_event_e trap,
                                        la_trap_priority_t priority,
                                        la_counter_or_meter_set* counter_or_meter,
                                        const la_punt_destination* destination,
                                        bool skip_inject_up_packets,
                                        bool skip_p2p_packets,
                                        bool overwrite_phb,
                                        la_traffic_class_t tc);

    // Clear snoop function
    enum snoop_skip_attribute_e {
        NO_SKIP,
        SKIP_INJECT_UP,
        SKIP_P2P,
        SKIP_ALL,
        SKIP_LAST,
    };

    la_status clear_entry_from_snoop_table(la_event_e trap, snoop_skip_attribute_e attribute);

    // BFD API-s
    la_status create_bfd_session(la_bfd_discriminator local_discriminator,
                                 la_bfd_session::type_e session_type,
                                 la_l3_protocol_e protocol,
                                 const la_punt_destination* punt_destination,
                                 la_bfd_session*& out_bfd_session) override;

    la_status set_bfd_inject_up_mac_address(la_mac_addr_t mac_addr) override;
    la_status get_bfd_inject_up_mac_address(la_mac_addr_t& out_mac_addr) const override;

    // Soft reset while traffic is on
    la_status soft_reset() override;

    // Helper functions for configuring TM tables
    la_status add_to_mc_copy_id_table(const la_l2_service_port_base_wcptr& ac_port, const la_system_port_wcptr& dsp);
    la_status remove_from_mc_copy_id_table(const la_l2_service_port_base_wcptr& ac_port, const la_system_port_wcptr& dsp);
    la_status add_to_mc_copy_id_table(la_slice_id_t slice, uint64_t mc_copy_id);
    la_status remove_from_mc_copy_id_table(la_slice_id_t slice, uint64_t mc_copy_id);
    la_status add_to_mc_copy_id_table(la_slice_id_t slice, uint64_t mc_copy_id, size_t bank_id);

    // Management of IPv6 SIP compression
    la_status release_ipv6_compressed_sip(la_ipv6_addr_t sip);
    la_status allocate_ipv6_compressed_sip(la_ipv6_addr_t sip, uint64_t& out_code);

    // Get all remote devices reachable from this device
    la_status get_reachable_devices(bit_vector& out_reachable_dev_bv) override;

    la_status add_potential_link(la_uint_t fabric_port_num, la_device_id_t dev_id);
    la_status remove_potential_link(la_uint_t fabric_port_num, la_device_id_t dev_id);
    // Reset DMC OOB inject credits on Specific Fabric Port
    la_status reset_oob_inj_credits(size_t link);

    la_status set_ip_tunnel_transit_counter(la_counter_set* counter) override;
    la_status get_ip_tunnel_transit_counter(la_counter_set*& out_counter) const override;
    la_status get_component_health(la_component_health_vec_t& out_component_health) const override;

    la_status set_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(la_uint_t level, float probability) override;
    la_status get_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(la_uint_t level, float& out_probability) override;
    la_status clear_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(la_uint_t level) override;

public:
    /// @brief Global limits of the device
    enum {
        MAX_SWITCH_GID = (1 << 14),
        MAX_L2_DESTINATION_GID = (1 << 20),
        MAX_L3_DESTINATION_GID = (1 << 20),
        MAX_L3_DESTINATION_LPM_GID = (1 << 19),
        NUM_OF_PREFIX_TABLE_ENTRIES = (1 << 16),
        MAX_PREFIX_OBJECT_GIDS = (1 << 16),
        MAX_TE_TUNNEL_GIDS = (1 << 14),
        MAX_MPLS_VPN_ENCAP_GIDS = (1 << 17),
        MAX_L2_SERVICE_PORT_GID = (3 * (1 << 16)) - (1 << 14) - (1 << 13) /*168K*/ - NUM_OF_PREFIX_TABLE_ENTRIES,
        MAX_L2_SERVICE_PORT_PROTECTED_GIDS = (1 << 13) /*8K*/,
        MAX_PWE_SERVICE_PORT_GID = (1 << 14),
        MAX_L3_PROTECTED_GIDS = (1 << 12) /*4K*/,
        L3_PORT_GID_NAMESPACE_WIDTH = 12,
        L3_PORT_GID_NAMESPACE_EXTENSION_WIDTH = 1,
        MAX_L3_PORT_GID = (1 << (L3_PORT_GID_NAMESPACE_WIDTH + L3_PORT_GID_NAMESPACE_EXTENSION_WIDTH)),
        L3_PORT_GID_PROPERTIES_WIDTH = 4,
        L3_PORT_GID_EXTENSION_OFFSET_ON_PROPERTIES = 2,
        MAX_SYSTEM_PORT_GID = (1 << 12),
        MAX_MIRROR_GID = (1 << 6),
        MIRROR_GID_INGRESS_OFFSET = (1 << 5),
        MIRROR_GID_EGRESS_OFFSET = 0,
        MAX_INGRESS_MIRROR_GID = (1 << 6) - 1,
        MIN_INGRESS_MIRROR_GID = (1 << 5),
        MAX_EGRESS_MIRROR_GID = (1 << 5) - 1,
        MIN_EGRESS_MIRROR_GID = (0),
        DEFAULT_MAX_NUM_OG_LPTS_APP_IDS = (1 << 4),
        MAX_PCL_GIDS = (1 << 5),
        DEFAULT_NUM_PCL_GIDS = (0),
        MAX_VRF_GID
        = (1 << 11)
          - 1 /* VRF is 11 bits. Due to HW bug in the LPM related to V4/V6 distributor classification we can't use VRF=0x7ff */,
        MAX_MC_GROUP_GID = (1 << 18),  /* 256K */
        MAX_MC_LOCAL_MCID = (1 << 16), /* 64k */
        NUM_RESERVED_MCIDS = 7,
        MAX_MC_GROUP_CONFIGURABLE = MAX_MC_LOCAL_MCID - 1,
        MAX_MC_SCALE_GROUP_CONFIGURABLE = MAX_MC_GROUP_GID - NUM_RESERVED_MCIDS,
        MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE = MAX_MC_GROUP_GID - 1,
        MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_0 = MAX_MC_GROUP_GID - 2,
        MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_0_IFG_1 = MAX_MC_GROUP_GID - 3,
        MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_0 = MAX_MC_GROUP_GID - 4,
        MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_1_IFG_1 = MAX_MC_GROUP_GID - 5,
        MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_0 = MAX_MC_GROUP_GID - 6,
        MULTICAST_RESERVED_SMCID_TO_NETWORK_SLICE_2_IFG_1 = MAX_MC_GROUP_GID - 7,
        MAX_L2_PUNT_DESTINATION_GID = 254,
        NUM_FILTER_GROUPS_PER_DEVICE = (1 << 4),
        NUM_TPID_PROFILES = 4,
        MAX_OIDS = 400000,
        NUM_TC_PROFILES = (1 << 3),
        NUM_IPV6_COMPRESSED_SIPS = (1 << 16),
        NUM_IPV4_SIP_INDEX = (1 << 4),
        NUM_MY_IPV4_TABLE_INDEX = 64,
        NUM_L3VXLAN_SMAC_MSB_INDEX = (1 << 4),
        NUM_RTF_CONF_SET = (1 << 8),
        NUM_MULTICAST_PROTECTION_MONITORS = (1 << 9),

        NUM_AC_PROFILE_PER_DEVICE = (1 << 4),
        NUM_NPP_ATTRIBUTES_PER_DEVICE = (1 << 8),
        NUM_VOQ_CGM_PROFILES_PER_DEVICE = (1 << 5),
        VOQ_CGM_DROP_PROFILE = 0,

        MAX_DEVICES = 288,    ///< Maximum number of devices in a system.
        MAX_REMOTE_SLICE = 4, ///< Maximum number of remote slices.

        // TODO: this parameter is configurable and should match service_lp_attributes table allocation per-slice.
        // Currently setting to smallest configuration.
        MAX_SLPS_PER_SLICE = (1 << 14),

        MAX_PWE_PER_SLICE = 15000,

        // Standalone device max number of VOQs and VSCs
        MAX_VOQS_PER_FABRIC_SLICE
        = 24576, // Maximum VOQs in a HW fabric-type slice (in Pacific slices 4..5), regardless of the actual slice mode
        MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE = MAX_VOQS_PER_FABRIC_SLICE, // In a standalone-mode device there is no need for 40K
                                                                             // VOQs in network-type slices and 24k in fabric-type
        // slices. So the maximum for all slices is capped at the fabric-type capacity.
        MAX_VSCS_PER_IFG_IN_STANDALONE_DEVICE
        = MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE / 2, // There's the same number of VSCs per slice as there
                                                       // are VOQs. But - the HW appends 1 bit to the VSC ID to
                                                       // denote the source IFG. So the name space which is
                                                       // exposed to the user is cut by half.

        // Linecard device max number of VOQs and VSCs
        MAX_VOQS_PER_NETWORK_SLICE
        = 40960, // Maximum VOQs in a HW network-type slice (in Pacific slices 0..3), regardless of the actual slice mode
        MAX_VOQS_PER_SLICE_IN_LINECARD_DEVICE
        = MAX_VOQS_PER_NETWORK_SLICE, // In a linecard-mode device all network-mode slice will have 40K VOQs.
        MAX_VSCS_PER_IFG_IN_LINECARD_DEVICE
        = MAX_VOQS_PER_SLICE_IN_LINECARD_DEVICE / 2, // There's the same number of VSCs per slice as there
                                                     // are VOQs. But - the HW appends 1 bit to the VSC ID to
                                                     // denote the source IFG. So the name space which is
                                                     // exposed to the user is cut by half.
        // Maximum VSCs in HW network-type (Pacific slices 0..3) and fabric-type (Pacific slices 4..5)
        MAX_VSCS_PER_IFG_IN_NETWORK_SLICE = MAX_VOQS_PER_NETWORK_SLICE / 2,
        MAX_VSCS_PER_IFG_IN_FABRIC_SLICE = MAX_VOQS_PER_FABRIC_SLICE / 2,

        IPV4_MC_VRF_GID_RANGE_LIMIT = (MAX_VRF_GID),
        IPV6_VRF_GID_RANGE_LIMIT = (MAX_VRF_GID),
        EGRESS_DIRECT0_TABLE_SIZE = 3 * 1024,

        MAX_ETHERNET_PORT_ID = (1 << 16), // local_slp_id

        NUM_INGRESS_QOS_PROFILES_PER_SLICE_PAIR = (1 << 4),
        NUM_EGRESS_QOS_PROFILES_PER_SLICE_PAIR = (1 << 4),

        NUM_NPUH_MEP_ENTRIES_PER_DEVICE = (1 << 12),

        NUM_SR_EXTENDED_POLICIES = (1 << 12), // Number of SR policies that support 4 or more outgoing labels

        MAX_ERSPAN_SESSION_ID = (1 << 10),

        SPA_LB_KEY_RANGE_SIZE = (1 << 16),

        SMS_BLOCK_SIZE_IN_BYTES = 384, // size of block in bytes in the SMS.

        MAX_COUNTER_OFFSET = 7,
        MAX_PIF_COUNTER_OFFSET = 26,

        MAX_VOQ_SET_SIZE = 8,

        MAX_ROUTE_STATS_SET_SIZE = 1, // counter_set of max size 1 is allowed for route stats.

        // Static VSC details. Used to grant credits during VOQ flush.
        LC_VOQ_FLUSH_VSC_SLICE_ID = 3, // Need to use fabric slice so the OQs are available for granting credits. Slice #3 is used
                                       // as it has the physical architecture of a network slice thus has access to full VOQ range
        LC_VOQ_FLUSH_VSC_IFG_ID = 0,
        SA_VOQ_FLUSH_VSC_SLICE_ID = 0, // Slice 0, serdes 19 is available as recycle port (i.e. 19) exists only on odd slices.
        SA_VOQ_FLUSH_VSC_IFG_ID = 0,

        DELETE_FIFO_SIZE = 300,
        DELETE_FIFO_GUARD_BUFFER = 6,
        NUM_OAMP_TRAP_ENCAP_ENTRIES_PER_DEVICE = 4,

        MAX_MAC_PORT_SM_CAPTURES = 50,
        MAX_SERDES_DEBUG_CAPTURES = 10,

        INVALID_RPF_ID = 0, // use for rpf enabled but still to drop packet
        // RPF ID range for MLDP
        MLDP_MIN_RPF_ID = 4096,  // MLDP lowest rpf id
        MLDP_MAX_RPF_ID = 32767, // MLDP highest rpf id
        SGACL_CELL_COUNTER_LIMIT = ((1 << 12) - 1)
    };

    /// @brief Limits of object IDs in resolution tables
    enum {
        MAX_ECMP_GROUP_NATIVE_LB_ID = (1 << 13),
        MAX_ECMP_GROUP_STAGE2_LB_ID = (1 << 13),
        MAX_ECMP_GROUP_STAGE3_LB_ID = (1 << 13),
        MAX_SPA_PORT_GID = (1 << 13),
        MAX_NEXT_HOP_GID = (1 << 12),
        MAX_VXLAN_OVL_NH = (1 << 10),
        MAX_FEC_GID = (1 << 12),
        MAX_PROTECTION_MONITOR_GID = (1 << 13),
        MAX_NATIVE_LP_TABLE_ENTRIES = (3 * (1 << 16)),
        MAX_ASBR_GID = (1 << 15),
        MAX_ASBR_LSP_DESTINATION_GID = (1 << 11),
    };

    /// @brief Global constants of the device
    enum {
        LOOKUP_ERROR_SYSTEM_PORT_GID = NPL_LOOKUP_ERROR_SYSTEM_PORT_GID, /// DSP=0 is reserved for Lookup error WA.
        RX_DROP_SYSTEM_PORT_GID
        = NPL_RX_DROP_SYSTEM_PORT_GID, ///< System port allocated for drop purposes. Drops on this DSP are counted.
        RX_NOT_CNT_DROP_SYSTEM_PORT_GID
        = NPL_RX_NOT_CNT_DROP_SYSTEM_PORT_GID, ///< System port allocated for drop purposes. Drops on this DSP are not counted.
        MIN_SYSTEM_PORT_GID = RX_NOT_CNT_DROP_SYSTEM_PORT_GID + 1, //=3

        RTF_CONF_SET_INVALID_ID = 0,
        ACL_INVALID_ID = 0, ///< ACL ID that will result in no ACL check
        ACL_SELECT_TABLE_SIZE = 16,
        INGRESS_ACL_ID_TABLE_SIZE = 128,
        SECOND_ACL_SELECT_TABLE_SIZE = 4,
        RX_SILENT_DROP_DESTINATION
        = 0xfffff, ///< Special destination encoding that results with packet drop in the Rx, without any counting.
        LPM_RX_DROP_TRAP = (1 << 5),     ///< Drop TRAP indicator in LPTS
        LPM_ILLEGAL_DIP_TRAP = (1 << 1), ///< Illegal DIP Trap indicator in LPTS
        LPTS_EM_SIZE = (1 << 5),         ///< LPTS 2nd EM size - restriction is because of index size from TCAM
        LPTS_METER_SIZE = (1 << 8),      ///< LPTS meter table size - restriction is because of index size from TCAM
        LPTS_METER_INDEX_LSB = 7,        ///< LPTS meter split index lsb bits
        DEFAULT_LPTS_MAX_ENTRY_COUNTERS
        = (1 << 8), ///< In PC64_BC64 counter mode, only 1K meter entries are available. Each Entry meter
                    /// consumes 2 indices. So support a max of only 256 LPTS Entry counters.
        DEFAULT_LPTS_MAX_ENTRY_COUNTERS_NARROW_MODE = (1 << 9), ///< In narrow counter mode 512 LPTS Entry Counters are supported.
                                                                ///< Redirect code consists of mirror commands and afterwards
        NPU_HOST_PFC_ENCAP_PTR = 253,
        NPU_HOST_BFD_ENCAP_PTR = 254,
        SERDES_PERFORM_SPICO_RAM_BIST = 1,
        LPM_CATCH_ALL_DROP_DESTINATION = NPL_LPM_COMPRESSED_DESTINATION_LPTS_MASK_DEFAULT | LPM_RX_DROP_TRAP,
        LPM_ILLEGAL_DIP_DESTINATION = NPL_LPM_COMPRESSED_DESTINATION_LPTS_MASK_DEFAULT | LPM_ILLEGAL_DIP_TRAP,
        PACIFIC_PART_NUMBER = 0x451,
        CRC_HEADER_SIZE = 4,
        ETHERNET_OVERHEAD = 20 + CRC_HEADER_SIZE, ///< Ethernet Premble (8) + InterPacketGap(12) + CRC (4).
        NPU_HEADER_SIZE = 40,                     ///< NPU header size.
        FABRIC_HEADER_SIZE = 52,
        INVALID_FABRIC_PORT_NUM = INT_MAX,
        MAX_MIN_LINKS_THRESHOLD = (1 << frm_min_links_threshold_reg_register::SIZE_IN_BITS) - 1,
        DEFAULT_MIN_LINKS_THRESHOLD = 1,

        ECN_WA_IN_LC_STATISTICAL_METER_OFFSET = 0, // The offset of the statistical meter used in LC for the ECN WA.

        MAX_COPC_ETHERNET_PROFILES = ((1 << 8) - 1),
        MAX_COPC_SWITCH_PROFILES = ((1 << 6) - 1),
        MAX_COPC_L2_SERVICE_PORT_PROFILES = ((1 << 2) - 1),
    };

    /// @brief Various constants
    enum {
        MC_SLICE_REPLICATION_TC_PROFILE = 0,
        IBM_TC_PROFILE = 0,
        NUM_LC_FABRIC_MC_VOQS = MAX_VOQ_SET_SIZE,
        NUM_LC_NETWORK_MC_VOQS = MAX_VOQ_SET_SIZE,
        NUM_SA_MC_VOQS = MAX_VOQ_SET_SIZE,
        BASE_LC_MC_VOQ = 0,
        BASE_LC_NETWORK_MC_VOQ = BASE_LC_MC_VOQ,
        LAST_LC_NETWORK_MC_VOQ = BASE_LC_MC_VOQ + (3 * NATIVE_VOQ_SET_SIZE),
        BASE_LC_FABRIC_MC_VOQ = LAST_LC_NETWORK_MC_VOQ,
        LAST_LC_FABRIC_MC_VOQ = BASE_LC_FABRIC_MC_VOQ + (3 * NATIVE_VOQ_SET_SIZE),

        BASE_SA_MC_VOQ = 0,
        FIRST_HIGH_PRIORITY_MC_VOQ_OFFSET = 6,

        // Value that ensures packet is not counted in PDVOQ if VoQ set doesn't have attached VoQ counter.
        // 127 can't be used because the HW uses bank_id for IFG0 & bank_id+1==128 for IFG1.
        COUNTERS_VOQ_BLOCK_MAP_TABLE_INVALID_BANK_ID = 126,
    };

    enum class resolution_lp_table_format_e {
        NONE,
        NARROW,
        WIDE,
    };
    enum class acl_key_profile_type_e {
        DEFAULT,
        UDK_160,
        UDK_320,
    };

    enum class tm_slice_mode_e {
        LC_CRF_TS_NETWORK = 0x0,
        LC_CRF_SN_NETWORK = 0x1,
        LC_CRF_TS_FABRIC = 0x2,
        LC_CRF_SN_FABRIC = 0x3,
        TOR_NETWORK = 0x4,
        TOR_FABRIC = 0x5,
        FABRIC_TS = 0x6,
        FABRIC_SN = 0x7,
        STANDALONE = 0x8,
        DRAM = 0x9,
    };

    /// @brief NPU host scanner interval
    const std::chrono::microseconds ccm_interval{300};

    destination_id get_actual_destination_id(destination_id dest_id);
    la_status get_stack_port_from_remote_sys_port_gid(la_system_port_gid_t remote_sys_port_gid,
                                                      const la_stack_port*& out_stack_port);
    destination_id get_stack_remote_resolution_destination_id() const;

    /// @brief Full destination of a system port allocated for drop purposes
    const destination_id RX_DROP_DSP{NPL_DESTINATION_MASK_DSP | RX_DROP_SYSTEM_PORT_GID};

    /// @brief Full destination of a system port allocated for drop purposes without counting
    const destination_id RX_NOT_CNT_DROP_DSP{NPL_DESTINATION_MASK_DSP | RX_NOT_CNT_DROP_SYSTEM_PORT_GID};

    static constexpr int INVALID_CREDIT_SIZE = -1;

    static constexpr size_t INVALID_BUNDLE
        = (1 << rx_pdr_2_slices_fb_link_to_link_bundle_table_memory::fields::TABLE_BUNDLE_NUM_WIDTH) - 1;

    static constexpr size_t INVALID_LINK
        = (1 << rx_pdr_2_slices_fe_uc_link_bundle_desc_table_memory::fields::SLICE_BUNDLE_LINK0_WIDTH) - 1;

    la_status validate_destination_gid_format_match(const resolution_lp_table_format_e format,
                                                    const la_l3_destination_gid_t gid,
                                                    bool is_init);
    la_status update_destination_gid_format(const resolution_lp_table_format_e format, const la_l3_destination_gid_t gid);
    la_status clear_destination_gid_format(const la_l3_destination_gid_t gid);

    /// @brief Manage the ASBR LSP entries
    la_status check_asbr_lsps(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination);
    la_status update_asbr_lsp(const la_prefix_object_wcptr& asbr,
                              const la_l3_destination_wcptr& destination,
                              const la_asbr_lsp_wptr& asbr_lsp);
    la_status clear_asbr_lsp(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination);

    /// Manage LPTS meters
    la_status assign_lpts_counter_allocation(la_slice_pair_id_t pair_idx, counter_allocation& out_allocation);
    la_status release_lpts_counter_allocation(la_slice_pair_id_t pair_idx, counter_allocation& out_allocation);

    /// Manage SGACL counters
    la_status assign_sgacl_counter_allocation(la_slice_pair_id_t pair_idx, counter_allocation& out_allocation);
    la_status release_sgacl_counter_allocation(la_slice_pair_id_t pair_idx, counter_allocation& out_allocation);

    /// @brief Check if given slice ID supports remote destination/source.
    ///
    /// @param[in]  slice_id        Slice ID to be queried.
    ///
    /// @return     True in case the given slice ID supports remote destination/source, false otherwise.
    static bool is_multi_device_aware_slice(la_slice_id_t slice_id);

    /// @brief Check if given VOQ ID is in valid range for the given slice ID.
    ///
    /// @param[in]  slice_id        Slice ID to be queried.
    /// @param[in]  voq_id          VOQ ID to be queried.
    ///
    /// @return     True in case the given VOQ ID is in supported range of the given slice ID, false otherwise.
    static bool is_voq_id_in_range(la_slice_id_t slice_id, la_voq_gid_t voq_id);

    /// @brief Check if given system port GID is in valid range.
    ///
    /// @param[in]  system_port_gid      System port GID to be queried.
    ///
    /// @return     True in case the given VSC ID is in supported range of the given slice ID, false otherwise.
    static bool is_dsp_in_range(la_system_port_gid_t system_port_gid);

    /// @brief Check if given VSC ID is in valid range for the given slice ID.
    ///
    /// @param[in]  slice_id        Slice ID to be queried.
    /// @param[in]  vsc_id          VSC ID to be queried.
    ///
    /// @return     True in case the given VSC ID is in supported range of the given slice ID, false otherwise.
    bool is_vsc_id_in_range(la_slice_id_t slice_id, la_vsc_gid_t vsc_id);

    /// @brief Returns the L2-destination GID of a given L2-destination object
    ///
    /// @param[in]  l2_destination      L2-destination object.
    ///
    /// @return     GID of the L2-destination object. In case that the L2-destination is still unsupported returns
    /// LA_L2_DESTINATION_GID_INVALID.
    la_l2_destination_gid_t get_l2_destination_gid(const la_l2_destination_wcptr& l2_dest) const;

    /// @brief Returns the L2-destination object for a given L2-destination GID
    ///
    /// @param[in]  l2_destination_gid      GID of an L2-destination object.
    ///
    /// @return     L2-destination object. In case that the GID is invalid returns nullptr.
    la_l2_destination_wptr get_l2_destination_by_gid(la_l2_destination_gid_t l2_destination_gid) const;

    /// @brief Returns the L3-destination GID of a given L3-destination object
    ///
    /// @param[in]  l3_destination      L3-destination object.
    /// @param[in]  is_lpm_format       If TRUE, return GID with NPL LPM mask, non-LPM otherwise.
    ///
    /// @return    GID of the L3-destination object. In case that the L3-destination is still unsupported returns
    /// LA_L3_DESTINATION_GID_INVALID.
    la_l3_destination_gid_t get_l3_destination_gid(const la_l3_destination_wcptr& l3_destination, bool is_lpm_format) const;

    /// @brief Returns the L3-destination object for a given L3-destination GID
    ///
    /// @param[in]  l3_destination_gid      GID of an L3-destination object.
    ///
    /// @return     L3-destination object. In case that the GID is invalid returns nullptr.
    la_l3_destination_wptr get_l3_destination_by_gid(la_l3_destination_gid_t l3_destination_gid) const;

    /// @brief Returns the mirror command object for a given mirror GID
    ///
    /// @param[in]  mirror_gid          GID of an mirror command object.
    ///
    /// @return     Mirror command object. In case that the GID is invalid returns nullptr.
    la_mirror_command_wptr get_mirror_command_by_gid(la_mirror_gid_t mirror_gid) const;

    /// @brief Add object dependency.
    ///
    /// An object that is being depndent on should not be deleted while the dependent object uses it.
    ///
    /// @param    dependee     Object being dependent on.
    /// @param    dependent    Depending object.
    void add_object_dependency(const la_object* dependee, const la_object* dependent);
    void add_object_dependency(const la_object_wcptr& dependee, const la_object* dependent);
    void add_object_dependency(const la_object* dependee, const la_object_wcptr& dependent);
    void add_object_dependency(const la_object_wcptr& dependee, const la_object_wcptr& dependent);

    /// @brief Remove object dependency.
    ///
    /// @param    dependee     Object being dependent on.
    /// @param    dependent    Object that depends on the 'dependee'.
    void remove_object_dependency(const la_object* dependee, const la_object* dependent);
    void remove_object_dependency(const la_object_wcptr& dependee, const la_object* dependent);
    void remove_object_dependency(const la_object* dependee, const la_object_wcptr& dependent);
    void remove_object_dependency(const la_object_wcptr& dependee, const la_object_wcptr& dependent);

    /// @brief Notify dependent objects dependee object changed attribute.
    ///
    /// @param    dependee              Object being dependent on.
    /// @param    attribute             Attribute change descriptor
    /// @param    undo                  callback for undo
    ///
    ///@retval    LA_STATUS_SUCCESS     Operation completed successfully.
    ///@retval    LA_STATUS_EUNKNOWN    Internal error.
    la_status notify_attribute_changed(const la_object* dependee,
                                       attribute_management_details& attribute,
                                       const la_amd_undo_callback_funct_t& undo);

    /// @brief Add IFG dependency.
    ///
    /// Dependent objects will be notified when requested attributes of dependee change.
    ///
    /// @param    dependee     Object being dependent on.
    /// @param    dependent    Object that depends on the 'dependee'.
    ///
    /// Dependent must implement dependent->notify_change(dependency_management_op op)
    void add_ifg_dependency(const la_object* dependee, dependency_listener* dependent);
    void add_ifg_dependency(const la_object_wcptr& dependee, dependency_listener* dependent);
    void add_ifg_dependency(const la_object* dependee, const dependency_listener_wptr& dependent);
    void add_ifg_dependency(const la_object_wcptr& dependee, const dependency_listener_wptr& dependent);

    /// @brief Remove IFG dependency.
    ///
    /// @param    dependee     Object being dependent on.
    /// @param    dependent    Object that depends on the 'dependee'.
    void remove_ifg_dependency(const la_object* dependee, dependency_listener* dependent);
    void remove_ifg_dependency(const la_object_wcptr& dependee, dependency_listener* dependent);
    void remove_ifg_dependency(const la_object* dependee, const dependency_listener_wptr& dependent);
    void remove_ifg_dependency(const la_object_wcptr& dependee, const dependency_listener_wptr& dependent);

    /// @brief Add attribute dependency.
    ///
    /// An object that is being dependent on should notify all the objects depending on it of
    /// any change in attribute change.
    ///
    /// @param    dependee     Object being dependent on.
    /// @param    dependent    Object that depends on the 'dependee'.
    /// @param    attributes   Changes dependent object should be notified about.
    ///
    /// Dependent must implement dependent->notify_change(dependency_management_op op)
    void add_attribute_dependency(const la_object* dependee, dependency_listener* dependent, bit_vector attributes);
    void add_attribute_dependency(const la_object_wcptr& dependee, dependency_listener* dependent, bit_vector attributes);
    void add_attribute_dependency(const la_object* dependee, const dependency_listener_wptr& dependent, bit_vector attributes);
    void add_attribute_dependency(const la_object_wcptr& dependee,
                                  const dependency_listener_wptr& dependent,
                                  bit_vector attributes);

    /// @brief Remove attribute dependency.
    ///
    /// @param    dependee     Object being dependent on.
    /// @param    dependent    Object that depends on the 'dependee'.
    /// @param    attributes   Attributes to remove from dependency management.
    void remove_attribute_dependency(const la_object* dependee, dependency_listener* dependent, bit_vector attributes);
    void remove_attribute_dependency(const la_object_wcptr& dependee, dependency_listener* dependent, bit_vector attributes);
    void remove_attribute_dependency(const la_object* dependee, const dependency_listener_wptr& dependent, bit_vector attributes);
    void remove_attribute_dependency(const la_object_wcptr& dependee,
                                     const dependency_listener_wptr& dependent,
                                     bit_vector attributes);

    /// @brief  Check whether the given object is being dependent on (object-dependency).
    ///
    /// @param    dependee     Object being dependent on.
    ///
    /// @retval   True iff the given object is being dependent on.
    bool is_in_use(const la_object* obj);
    bool is_in_use(const la_object_wcptr& obj);

    /// @brief   Notify all the objects that depend on the given object that it was added to a IFG.
    ///
    /// @param    dependee     Object being dependent on.
    ///
    /// @retval  LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval  LA_STATUS_EUNKNOWN    Internal error.
    la_status notify_ifg_added(const la_object* dependee, la_slice_ifg ifg);
    la_status notify_ifg_added(const la_object_wcptr& dependee, la_slice_ifg ifg);

    /// @brief   Notify all the objects that depend on the given object that it was removed from a IFG.
    ///
    /// @param    dependee     Object being dependent on.
    ///
    /// @retval  LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval  LA_STATUS_EUNKNOWN    Internal error.
    la_status notify_ifg_removed(const la_object* dependee, la_slice_ifg ifg);
    la_status notify_ifg_removed(const la_object_wcptr& dependee, la_slice_ifg ifg);

    void create_resource_manager(ll_device_sptr ldevice);
    resource_manager_wcptr get_resource_manager() const;
    counter_manager_wcptr get_counter_bank_manager() const;

    /// @brief Set the MAC address of the network interface in the given slice.
    ///
    /// @param[in]  slice       Slice.
    /// @param[in]  mac_addr    MAC address of the network interface in the given slice.
    ///
    /// @return LA_STATUS_SUCCESS     Operation completed successfully.
    /// @return LA_STATUS_ENOTFOUND   No interface exist for the given IFG.
    /// @return LA_STATUS_EUNKNOWN    Internal errror.
    la_status set_network_interface_mac_addr(la_slice_id_t slice, la_mac_addr_t mac_addr) const;

    /// @brief Return the type of the counter bank used in the device.
    ///
    /// @return The type of the counter bank used in the device.
    npl_counter_type_e get_counter_bank_type() const;

    /// @brief Return a list of all enabled IFGs.
    const slice_ifg_vec_t& get_used_ifgs() const;

    /// @brief Check if this a VOQ set is a MC VOQ created by the SDK.
    ///
    /// @return True if this VOQ set is a MC VOQ created by the SDK, false otherwise.
    bool is_mc_voq_set(const la_voq_set_wcptr& voq_set) const;

    /// @brief Return true is slice is a network slice.
    ///
    /// @return true is slice is a la_slice_mode_e::NETWORK/la_slice_mode_e::UDC slice.
    bool is_network_slice(la_slice_id_t slice) const;

    /// @brief Return true is slice is a fabric slice.
    ///
    /// @return true is slice a la_slice_mode_e::CARRIER_FABRIC/la_slice_mode_e::DC_FABRIC slice.
    bool is_fabric_slice(la_slice_id_t slice) const;

    /// @brief Return true if this slice can be used for FABRIC conection
    bool is_fabric_capable_slice(la_slice_id_t slice) const;

    /// @brief Returns the next available IFG for MCG counter allocation.
    ///
    /// @param[out] out_slice_ifg           slice_ifg_struct containing the next available IFG.
    ///
    /// @retval     LA_STATUS_SUCCESS       next available IFG returned successfully.
    la_status get_next_ifg_for_mcg_counter(la_slice_ifg& out_slice_ifg);

public:
    /// Whether device access is disconnected.
    bool m_disconnected = false;

    /// Warm-boot state
    bool m_warm_boot_disconnected = false;

    // Revision
    la_device_revision_e m_revision;

    struct oam_encap_info_t {
        la_mac_addr_t da_addr;
        la_mac_addr_t sa_addr;
        la_vlan_tag_tci_t vlan_tag;
    };

    // Profile allocators needs to be above m_objects because order of destruction is important.
    // Some objects in their destructor dependence on existence of profile allocators (e.g. lpts).
    struct profile_allocators {
        struct compare_v4_prefix {
            bool operator()(const la_ipv4_prefix_t& lhs, const la_ipv4_prefix_t& rhs)
            {
                if (lhs.addr.s_addr != rhs.addr.s_addr) {
                    return (lhs.addr.s_addr < rhs.addr.s_addr);
                } else {
                    return (lhs.length < rhs.length);
                }
            }
        };

        using ipv4_sip_index_profile_allocator = profile_allocator<la_ipv4_prefix_t, compare_v4_prefix>;
        std::shared_ptr<ipv4_sip_index_profile_allocator> ipv4_sip_index;

        using l3vxlan_smac_msb_index_profile_allocator = profile_allocator<la_uint32_t>;
        std::shared_ptr<l3vxlan_smac_msb_index_profile_allocator> l3vxlan_smac_msb_index;

        // ccm counter profile requires a delayed release generator.
        using npu_host_max_ccm_counters_profile_allocator
            = profile_allocator<std::chrono::microseconds, std::less<std::chrono::microseconds>, delayed_ranged_index_generator>;
        std::shared_ptr<npu_host_max_ccm_counters_profile_allocator> npu_host_max_ccm_counters;

        using npu_host_packet_intervals_profile_allocator = profile_allocator<bfd_packet_intervals>;
        std::shared_ptr<npu_host_packet_intervals_profile_allocator> npu_host_packet_intervals;

        struct compare_v6_addr {
            bool operator()(const la_ipv6_addr_t& lhs, const la_ipv6_addr_t& rhs)
            {
                return (lhs.s_addr < rhs.s_addr);
            }
        };

        using bfd_local_ipv6_addresses_profile_allocator = profile_allocator<la_ipv6_addr_t, compare_v6_addr>;
        std::shared_ptr<bfd_local_ipv6_addresses_profile_allocator> bfd_local_ipv6_addresses;

        using npu_host_detection_times_profile_allocator = profile_allocator<std::chrono::microseconds>;
        std::shared_ptr<npu_host_detection_times_profile_allocator> npu_host_detection_times;

        using lpts_compressed_meter_profile = profile_allocator<la_meter_set_wcptr>::profile_ptr;
        using lpts_em_entry_data = npl_lpts_payload_t;

        using lpts_meters_profile_allocator = profile_allocator<la_meter_set_wcptr>;
        std::shared_ptr<lpts_meters_profile_allocator> lpts_meters;

        struct compare_lpts_em_entry {
            bool operator()(const lpts_em_entry_data& lhs, const lpts_em_entry_data& rhs)
            {
                return (std::tie(lhs.destination, lhs.phb.tc, lhs.phb.dp) < std::tie(rhs.destination, rhs.phb.tc, rhs.phb.dp));
            }
        };
        using lpts_em_entries_profile_allocator = profile_allocator<lpts_em_entry_data, compare_lpts_em_entry>;
        std::shared_ptr<lpts_em_entries_profile_allocator> lpts_em_entries;

        struct compare_bfd_rx_entry {
            bool operator()(const bfd_rx_entry_data_t& lhs, const bfd_rx_entry_data_t& rhs)
            {
                return (std::tie(lhs.local_discr_msb, lhs.udp_port, lhs.protocol)
                        < std::tie(rhs.local_discr_msb, rhs.udp_port, rhs.protocol));
            }
        };
        using bfd_rx_entries_profile_allocator = profile_allocator<bfd_rx_entry_data_t, compare_bfd_rx_entry>;
        std::shared_ptr<bfd_rx_entries_profile_allocator> bfd_rx_entries;

        struct compare_oam_encap_entry {
            bool operator()(const oam_encap_info_t& lhs, const oam_encap_info_t& rhs)
            {
                return (std::tie(lhs.da_addr.flat, lhs.sa_addr.flat, lhs.vlan_tag.raw)
                        < std::tie(rhs.da_addr.flat, rhs.sa_addr.flat, rhs.vlan_tag.raw));
            }
        };
        using oam_punt_encap_profile_allocator = profile_allocator<oam_encap_info_t, compare_oam_encap_entry>;
        std::shared_ptr<oam_punt_encap_profile_allocator> oam_punt_encap;

        struct compare_l2_slp_acl_entry {
            bool operator()(const l2_slp_acl_info_t& lhs, const l2_slp_acl_info_t& rhs)
            {
                return (std::tie(lhs.v4_acl_oid, lhs.v6_acl_oid, lhs.mac_acl_oid)
                        < std::tie(rhs.v4_acl_oid, rhs.v6_acl_oid, rhs.mac_acl_oid));
            }
        };

        using l2_slp_acl_indices_profile_allocator = profile_allocator<l2_slp_acl_info_t, compare_l2_slp_acl_entry>;
        std::shared_ptr<l2_slp_acl_indices_profile_allocator> l2_slp_acl_indices;

        struct compare_acl_group_entry {
            bool operator()(const acl_group_info_t& lhs, const acl_group_info_t& rhs)
            {
                if (lhs.ethernet_acls_size != rhs.ethernet_acls_size) {
                    return (lhs.ethernet_acls_size < rhs.ethernet_acls_size);
                }
                if (lhs.ipv4_acls_size != rhs.ipv4_acls_size) {
                    return (lhs.ipv4_acls_size < rhs.ipv4_acls_size);
                }
                if (lhs.ipv6_acls_size != rhs.ipv6_acls_size) {
                    return (lhs.ipv6_acls_size < rhs.ipv6_acls_size);
                }
                la_acl_wptr_vec_t lhs_all_acls;
                la_acl_wptr_vec_t rhs_all_acls;
                lhs_all_acls.reserve(lhs.ethernet_acls.size() + lhs.ipv4_acls.size() + lhs.ipv6_acls.size());
                rhs_all_acls.reserve(rhs.ethernet_acls.size() + rhs.ipv4_acls.size() + rhs.ipv6_acls.size());
                lhs_all_acls.insert(lhs_all_acls.end(), lhs.ethernet_acls.begin(), lhs.ethernet_acls.end());
                lhs_all_acls.insert(lhs_all_acls.end(), lhs.ipv4_acls.begin(), lhs.ipv4_acls.end());
                lhs_all_acls.insert(lhs_all_acls.end(), lhs.ipv6_acls.begin(), lhs.ipv6_acls.end());
                rhs_all_acls.insert(rhs_all_acls.end(), rhs.ethernet_acls.begin(), rhs.ethernet_acls.end());
                rhs_all_acls.insert(rhs_all_acls.end(), rhs.ipv4_acls.begin(), rhs.ipv4_acls.end());
                rhs_all_acls.insert(rhs_all_acls.end(), rhs.ipv6_acls.begin(), rhs.ipv6_acls.end());
                for (la_uint16_t index = 0; index < lhs_all_acls.size(); index++) {
                    if (std::tie(lhs_all_acls[index]) != std::tie(rhs_all_acls[index])) {
                        return (std::tie(lhs_all_acls[index]) < std::tie(rhs_all_acls[index]));
                    }
                }
                return false;
            }
        };
        using acl_group_entries_profile_allocator = profile_allocator<acl_group_info_t, compare_acl_group_entry>;
        std::shared_ptr<acl_group_entries_profile_allocator> acl_group_entries;
    } m_profile_allocators;

    std::vector<bool> m_is_builtin_objects;

    std::array<la_slice_mode_e, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_slice_mode;

    // HBM handlers
    std::shared_ptr<la_hbm_handler_impl> m_hbm_handler;

    // PTP handler
    std::shared_ptr<la_ptp_handler_pacific> m_ptp_handler;

    // Process-Voltage-Temperature (PVT) handler
    std::unique_ptr<pvt_handler> m_pvt_handler;

    // CPU2JTAG handler
    std::unique_ptr<cpu2jtag> m_cpu2jtag_handler;

    // IFG block handler.
    using ifg_slice_handlers = std::array<std::unique_ptr<ifg_handler>, NUM_IFGS_PER_SLICE>;
    using ifg_device_handlers = std::array<ifg_slice_handlers, ASIC_MAX_SLICES_PER_DEVICE_NUM>;
    ifg_device_handlers m_ifg_handlers;

    // System objects
    // SerDes information
    struct serdes_info_desc {
        la_uint_t rx_source;        // SerDes Rx source
        la_uint_t anlt_order;       // SerDes ANLT order
        bool rx_polarity_inversion; // Polarity inversion - Rx
        bool tx_polarity_inversion; // Polarity inversion - Tx
    };

    using ifg_serdes_info = std::vector<serdes_info_desc>;
    using slice_serdes_info = std::vector<ifg_serdes_info>;
    std::vector<slice_serdes_info> m_serdes_info;

    // Bit set for each [slice][ifg], each bit indicates if the specific SerDes is in use by some MAC port.
    using ifg_serdes_bitset = std::bitset<NUM_SERDES_PER_IFG>;
    using slice_serdes_bitset = std::vector<ifg_serdes_bitset>;
    std::vector<slice_serdes_bitset> m_serdes_inuse;

    // SerDes status - if SerDes is enabled
    struct serdes_status {
        bool rx_enabled = false; // Rx enabled
        bool tx_enabled = false; // Tx enabled
    };

    using ifg_serdes_status = std::vector<serdes_status>;
    using slice_serdes_status = std::vector<ifg_serdes_status>;
    std::vector<slice_serdes_status> m_serdes_status;

    std::array<std::bitset<MAX_PORT_EXTENDER_VIDS_PER_SLICE>, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_extended_port_vid_bitset;
    std::vector<la_mirror_command_wptr> m_mirror_commands;

    ranged_index_generator m_pcl_gids;
    int m_pcl_ids_allocated;
    ranged_index_generator m_og_lpts_app_ids;
    int m_og_lpts_app_ids_allocated;
    std::vector<la_l3_destination_wptr>
        m_l3_destinations; // Holds destinations from the SW point of view, e.g. a next-hop object will
                           // have the index of its hardware implementation - fec id.
    typedef std::map<std::pair<la_prefix_object_wcptr, la_l3_destination_wcptr>, la_asbr_lsp_wptr> asbr_lsp_map_t;
    asbr_lsp_map_t m_asbr_lsp_map;

    std::vector<std::pair<resolution_lp_table_format_e, size_t> > m_native_lp_table_format;

    std::vector<la_bfd_session_base_wptr> m_bfd_sessions;
    std::vector<la_system_port_pacific_wptr> m_system_ports;
    std::vector<la_spa_port_pacific_wptr> m_spa_ports;

    // TM objects
    std::vector<std::vector<la_ifg_scheduler_impl_sptr> > m_ifg_schedulers;
    std::vector<la_voq_set_impl_wptr> m_voq_sets;
    std::vector<voq_counter_set_sptr> m_voq_counter_sets;

    // CGM objects
    std::vector<la_voq_cgm_profile_wptr> m_voq_cgm_profiles;

    // Meter markdown profile tables

    // Data used for management of local-labels of PWE-tagged ports.
    struct pwe_tagged_local_label_desc {
        size_t use_count;                            // Number of ports defined with this local-label.
        uint64_t slp_id[NUM_SLICE_PAIRS_PER_DEVICE]; // The source-logical port ID with which to enter the service mapping.
    };
    std::map<la_uint32_t, pwe_tagged_local_label_desc> m_pwe_tagged_local_labels_map;

    struct ipv4_tunnel_id_t {
        la_ipv4_prefix_t local_ip_prefix;
        la_ipv4_prefix_t remote_ip_prefix;
        la_vrf_gid_t vrf_gid;
        npl_tunnel_type_e tunnel_type;
    };

    struct ipv4_tunnel_id_lt {
        bool operator()(const ipv4_tunnel_id_t& tun1, const ipv4_tunnel_id_t& tun2) const
        {
            return (std::tie(tun1.remote_ip_prefix.addr.s_addr,
                             tun1.remote_ip_prefix.length,
                             tun1.local_ip_prefix.addr.s_addr,
                             tun1.local_ip_prefix.length,
                             tun1.vrf_gid,
                             tun1.tunnel_type)
                    < std::tie(tun2.remote_ip_prefix.addr.s_addr,
                               tun2.remote_ip_prefix.length,
                               tun2.local_ip_prefix.addr.s_addr,
                               tun2.local_ip_prefix.length,
                               tun2.vrf_gid,
                               tun2.tunnel_type));
        }
    };

    struct vxlan_vni_profile {
        int refcount = 0;
        uint64_t index = 0;
    };

    struct vxlan_nh_t {
        la_l3_port_gid_t l3_port_id;
        la_l2_port_gid_t vxlan_port_id;
        la_mac_addr_t dmac;
    };

    struct vxlan_nh_t_lt {
        bool operator()(const vxlan_nh_t& nh1, const vxlan_nh_t& nh2) const
        {
            return (std::tie(nh1.l3_port_id, nh1.vxlan_port_id, nh1.dmac.flat)
                    < std::tie(nh2.l3_port_id, nh2.vxlan_port_id, nh2.dmac.flat));
        }
    };

    std::map<ipv4_tunnel_id_t, la_l3_port_wptr, ipv4_tunnel_id_lt> m_ipv4_tunnel_map;
    std::map<ipv4_tunnel_id_t, la_l2_service_port_wptr, ipv4_tunnel_id_lt> m_vxlan_port_map;
    std::map<la_vni_t, la_object_wptr> m_vxlan_vni_map;
    std::vector<vxlan_vni_profile> m_vxlan_vni_profile;
    std::map<vxlan_nh_t, la_vxlan_next_hop_wptr, vxlan_nh_t_lt> m_vxlan_nh_map;

    // NPL tables
    device_tables m_tables;

    resource_manager_sptr m_resource_manager;

    // Index generators
    struct _index_generators {
        ranged_index_generator oids;
        ranged_index_generator ethernet_ports;
        ranged_index_generator tc_profiles;
        ranged_index_generator ac_profiles;
        ranged_index_generator filter_groups;
        ranged_index_generator voq_cgm_profiles;
        ranged_index_generator ipv6_compressed_sips;
        ranged_index_generator vxlan_compressed_dlp_id;
        ranged_index_generator rtf_eth_f0_160_table_id;
        ranged_index_generator rtf_ipv4_f0_160_table_id;
        ranged_index_generator rtf_ipv4_f0_320_table_id;
        ranged_index_generator rtf_ipv6_f0_160_table_id;
        ranged_index_generator rtf_ipv6_f0_320_table_id;
        ranged_index_generator multicast_protection_monitors;

        struct _slice {
            ranged_index_generator npp_attributes;
            ranged_index_generator oq_drain_counters;
            ranged_index_generator my_ipv4_table_id;
        } slice[ASIC_MAX_SLICES_PER_DEVICE_NUM];

        struct _slice_pair {
            ranged_index_generator service_port_slps;
            ranged_index_generator ingress_eth_db1_160_f0_acl_ids;
            ranged_index_generator ingress_eth_db2_160_f0_acl_ids;
            ranged_index_generator ingress_ipv4_db1_160_f0_acl_ids;
            ranged_index_generator ingress_ipv4_db2_160_f0_acl_ids;
            ranged_index_generator ingress_ipv4_db3_160_f0_acl_ids;
            ranged_index_generator ingress_ipv4_db4_160_f0_acl_ids;
            ranged_index_generator ingress_ipv4_db1_320_f0_acl_ids;
            ranged_index_generator ingress_ipv4_db2_320_f0_acl_ids;
            ranged_index_generator ingress_ipv4_db3_320_f0_acl_ids;
            ranged_index_generator ingress_ipv4_db4_320_f0_acl_ids;
            ranged_index_generator ingress_ipv6_db1_160_f0_acl_ids;
            ranged_index_generator ingress_ipv6_db2_160_f0_acl_ids;
            ranged_index_generator ingress_ipv6_db3_160_f0_acl_ids;
            ranged_index_generator ingress_ipv6_db4_160_f0_acl_ids;
            ranged_index_generator ingress_ipv6_db1_320_f0_acl_ids;
            ranged_index_generator ingress_ipv6_db2_320_f0_acl_ids;
            ranged_index_generator ingress_ipv6_db3_320_f0_acl_ids;
            ranged_index_generator ingress_ipv6_db4_320_f0_acl_ids;
            ranged_index_generator service_port_pwe;
            ranged_index_generator ingress_ipv4_mirror_acl_ids;
            ranged_index_generator ingress_ipv6_mirror_acl_ids;
            ranged_index_generator egress_ipv4_acl_ids;
            ranged_index_generator egress_ipv6_acl_ids;
            ranged_index_generator ingress_qos_profiles;
            ranged_index_generator egress_qos_profiles;
        } slice_pair[NUM_SLICE_PAIRS_PER_DEVICE];

        // Meter profile and action profile index generator
        ranged_index_generator exact_meter_action_profile_id[NUM_IFGS_PER_DEVICE];
        ranged_index_generator exact_meter_profile_id[NUM_IFGS_PER_DEVICE];
        ranged_sequential_indices_generator statistical_meter_id[NUM_STATISTICAL_METER_BANKS];
        ranged_index_generator statistical_meter_action_profile_id;
        ranged_index_generator statistical_meter_profile_id;

        // Resolution tables ID generators
        ranged_index_generator fecs;
        ranged_index_generator mpls_label_destinations;
        ranged_index_generator protection_monitors;
        ranged_index_generator ecmp_groups[RESOLUTION_STEP_LAST];

        // TM scheduler ID generators
        ranged_index_generator_sptr output_queue_scheduler[ASIC_MAX_SLICES_PER_DEVICE_NUM][NUM_IFGS_PER_SLICE];

        // SR Extended policies ID generators
        ranged_index_generator sr_extended_policies;

        // NPU host ID generators
        ranged_index_generator_sptr npuh_mep_ids;
        ranged_index_generator_sptr bfd_session_ids;

        // Local-MCID generator for scaled multicast
        ranged_index_generator local_mcids;
    } m_index_generators;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Low level objects

    // AAPL handlers
    struct aapl_firmware_info {
        int revision;
        int build_id;
        std::string filename;
        std::string filepath;
    };

    aapl_firmware_info m_hbm_fw_info;
    aapl_firmware_info m_hbm_mbist_fw_info;

    /// Registers and memories tree
    pacific_tree_wcptr m_pacific_tree;
    gibraltar_tree_wcptr m_gb_tree;

    /// Reconnect handler
    std::unique_ptr<reconnect_handler> m_reconnect_handler;

    /// Possible speed up of device initialization helper
    std::unique_ptr<init_performance_helper_base> m_init_performance_helper;

    /// VOQ cgm configuration handler
    std::unique_ptr<voq_cgm_handler> m_voq_cgm_handler;

    /// RX cgm configuration handler
    std::unique_ptr<rx_cgm_handler> m_rx_cgm_handler;

    /// manager of MAC addresses, which are a limited resource in the device
    std::unique_ptr<mac_address_manager> m_mac_addr_manager;

    /// manager of l2 lpts protocol table, which are a limited resource in the device
    std::unique_ptr<copc_protocol_manager_base> m_copc_protocol_manager;

    /// manager of IPv4 tunnel endpoint addresses, which are shared among different type of IPv4 tunnels
    std::unique_ptr<ipv4_tunnel_ep_manager> m_ipv4_tunnel_ep_manager;

    /// manager of IPv4 SIP, which are shared among different type of IPv4 tunnels
    std::unique_ptr<ipv4_sip_index_manager> m_ipv4_sip_index_manager;

    /// Physical counter allocator
    std::shared_ptr<counter_manager> m_counter_bank_manager;

    /// CUD range manager
    std::array<std::unique_ptr<cud_range_manager>, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_cud_range_manager;

    /// LSR
    std::shared_ptr<la_lsr_impl> m_lsr;
    la_status create_lsr();

    /// TTL Inheritance Mode
    la_mpls_ttl_inheritance_mode_e m_ttl_inheritance_mode;

    /// for-us destination
    std::shared_ptr<la_forus_destination_impl> m_forus_destination;

    /// ACL global settings
    bool m_acl_scaled_enabled;

    /// L2PT trap settings
    bool m_l2pt_trap_enabled;

    /// UDK library
    std::unique_ptr<runtime_flexibility_library> m_udk_library;

    // List of system ports that use PIF 19
    std::array<la_system_port_base_wcptr, NUM_IFGS_PER_DEVICE> m_per_ifg_recycle_sp; // PACKET-DMA-WA

    /// API lock
    std::recursive_mutex m_mutex;

    /// AAPL lock
    std::recursive_mutex m_aapl_mutex;

    // Inject up Mac address
    la_mac_addr_t m_inject_up_mac;

    /// IFGB's initialized in Fabric mode
    bool m_fabric_ports_initialized;

    la_mac_port::fc_mode_e m_fabric_fc_mode;

    la_uint16_t m_ecmp_hash_seed;
    la_uint16_t m_spa_hash_seed;

    size_t m_load_balancing_node_id;

    size_t m_device_frequency_int_khz;
    float m_device_frequency_float_ghz;

    // Device clock interval value which is directly calculated from the device frequency
    fp_nanoseconds m_device_clock_interval;

    // JTAG TAP clock frequency
    size_t m_tck_frequency_mhz;

    // Meters shaper rate configuration. The meters rate limit calculation will be derived from this value.
    float m_meter_shaper_rate;

    float m_rate_limiters_shaper_rate;

    // PFC tuning enabled
    bool m_pfc_tuning_enabled;

    struct device_property_val {
        std::atomic<bool> bool_val;
        std::atomic<int32_t> int_val;
        std::string string_val;
        std::atomic<bool> supported;

        device_property_val()
        {
            bool_val.store(false);
            int_val.store(0);
            supported.store(true);
        };
    };
    std::array<device_property_val, (int)la_device_property_e::LAST + 1> m_device_properties;

    // Management of IPv6 SIP compression
    struct ipv6_compressed_sip_desc {
        size_t use_count;
        uint64_t code;
        npl_ipv6_sip_compression_table_entry_wptr_t npl_table_entry;
    };

    // IPv6 compressed SIP map
    std::map<la_uint128_t, ipv6_compressed_sip_desc> m_ipv6_compressed_sip_map;

    serdes_device_handler_sptr m_serdes_device_handler;
    device_port_handler_base_sptr m_device_port_handler;

    // VSC ownership
    struct vsc_ownership_map_key {
        la_slice_id_t slice;
        la_ifg_id_t ifg;
        la_vsc_gid_t vsc;

        vsc_ownership_map_key(la_slice_id_t _slice, la_ifg_id_t _ifg, la_vsc_gid_t _vsc) : slice(_slice), ifg(_ifg), vsc(_vsc)
        {
        }

        vsc_ownership_map_key() = default; // Needed for cereal

        bool operator<(const vsc_ownership_map_key& other) const
        {
            return std::tie(slice, ifg, vsc) < std::tie(other.slice, other.ifg, other.vsc);
        }
    };

    struct vsc_ownership_map_val {
        la_device_id_t device_id;
        la_output_queue_scheduler_impl_wptr oqs;
    };

    std::map<vsc_ownership_map_key, vsc_ownership_map_val> m_vsc_ownership_map;

    // Output queue scheduler for credit grant during voq flush
    std::shared_ptr<la_output_queue_scheduler_impl> m_voq_flush_oq_sch;

    // Redirect helper functions
    /// @brief Return redirect destination code for given trap
    uint64_t get_drop_redirect_destination(la_event_e trap);

    la_trap_priority_t get_default_trap_priority(la_event_e trap);

    la_status configure_redirect_eth_encap(uint64_t encap_ptr, la_mac_addr_t da, la_mac_addr_t sa, la_vlan_tag_tci_t vlan_tag);
    la_status configure_oamp_punt_eth_hdr_table(const la_punt_destination_wcptr& destination,
                                                profile_allocator<oam_encap_info_t>::profile_ptr& oam_encap);

    la_status clear_redirect_eth_encap(uint64_t encap_ptr);

    la_status configure_redirect_npuh_encap(uint64_t redirect_code, uint32_t fi_macro, uint32_t npuh_macro);

    la_status configure_redirect_code(uint64_t redirect_code,
                                      bool disable_snoop,
                                      bool is_l3_trap,
                                      const la_counter_or_meter_set_wptr& counter_or_meter,
                                      const destination_id& redirect_dest,
                                      npl_punt_nw_encap_type_e redirect_type,
                                      la_uint_t encap_ptr,
                                      bool overwrite_phb,
                                      la_traffic_class_t tc);
    la_status clear_redirect_code(uint64_t redirect_code);

    la_status configure_rx_obm_punt_src_and_code(uint64_t punt_code,
                                                 uint64_t punt_source,
                                                 la_traffic_class_t tc,
                                                 uint8_t dp,
                                                 const la_meter_set_wptr& meter,
                                                 const la_meter_set_wptr& counter,
                                                 la_voq_gid_t voq_gid);
    la_status clear_rx_obm_punt_src_and_code(uint64_t punt_code, uint64_t punt_source);

    la_status event_to_trap_struct(la_event_e trap_event,
                                   npl_traps_t& trap_struct,
                                   npl_trap_conditions_t& trap_conditions_struct,
                                   bool skip_inject_up_packets,
                                   bool skip_p2p_packets);
    la_status configure_event_to_redirect_code(la_event_e trap,
                                               size_t location,
                                               uint64_t redirect_code,
                                               bool skip_inject_up_packets,
                                               bool skip_p2p_packets,
                                               bool is_overwrite);
    la_status clear_event_to_redirect_code(size_t location);

    la_status configure_snoop_code_to_ibm(uint64_t code, la_uint_t ibm_cmd);
    la_status clear_snoop_code_to_ibm(uint64_t code);

    la_status configure_mirror_code_to_ibm(uint64_t code, la_uint_t ibm_cmd);
    la_status clear_mirror_code_to_ibm(uint64_t code);

    la_status configure_event_to_snoop_code(la_event_e trap,
                                            size_t location,
                                            uint64_t code,
                                            bool skip_inject_up_packets,
                                            bool skip_p2p_packets);
    la_status clear_event_to_snoop_code(la_event_e trap);

    la_status configure_recycle_override_table();
    la_status configure_recycle_override_table_sa_lc();
    la_status configure_recycle_override_table_sa_lc_network_slices();
    la_status configure_recycle_override_table_lc_fabric_slices();
    la_status configure_recycle_override_table_fe();
    la_status configure_recycle_override_network_slices_entry(uint64_t key_recycle_code,
                                                              uint64_t key_recycle_data,
                                                              uint64_t key_sched_rcy,
                                                              bool override_src,
                                                              npl_macro_e np_macro,
                                                              npl_fi_macro_ids_e fi_macro);

    la_status get_max_vrf_gids(la_uint_t& max_vrf_gids) const;
    la_status remove_network_slices_entry_from_recycle_override_table(uint64_t key_recycle_code,
                                                                      uint64_t key_recycle_data,
                                                                      uint64_t key_sched_rcy);

    /// @brief Get the TPIDs for vlan_edit_command by its tpid_profile and the amount of tags to populate.
    ///
    /// @param[in]  tpid_profile            TPID profile.
    /// @param[out] out_edit_command        la_vlan_edit_command with initialized num_tags_to_push.
    ///
    /// @retval     LA_STATUS_SUCCESS       TPIDs were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    la_status populate_vlan_edit_command_tpids(size_t tpid_profile, la_vlan_edit_command& out_edit_command);

    la_status nsim_accurate_scale_model_enabled(bool& out_enabled);

    la_status hbm_exists(bool& out_exists) const override;

    /// @brief Get the internal notification object
    ///
    /// @return A pointer to notification object
    weak_ptr_unsafe<hld_notification_base> get_notificator();

    la_status do_flush() const;

    /// @brief LC_56_FABRIC_PORT_MODE fabric port helper struct
    struct lc_56_fabric_port_info {
        bool is_lc_56_fabric_port;
        la_slice_id_t slice_id;
        la_ifg_id_t ifg_id;
        size_t serdes_base_id;
        size_t fabric_port_num;
    };

    la_status get_fuse_userbits(std::vector<uint32_t>& out_fuse_userbits) const override;

    /// @brief Get the current state of the hearteat.
    ///
    /// @param[out]   out_heartbeat  Struct containing the heartbeat information.
    ///
    /// @return LA_STATUS_SUCCESS  operation as successfull.
    la_status get_heartbeat(la_heartbeat_t& out_heartbeat) const override;

    /// @brief Returns the borrowed port for a LC_56_FABRIC_PORT_MODE port.
    lc_56_fabric_port_info get_borrowed_fabric_port_info(la_slice_id_t lender_slice_id,
                                                         la_ifg_id_t lender_ifg_id,
                                                         size_t lender_serdes_base_id) const;

    struct mc_links_key_hash {
        std::size_t operator()(const mc_links_key_t& k) const
        {
            return std::get<0>(k) ^ std::get<1>(k);
        }
    };

    struct mc_links_key_equal {
        bool operator()(const mc_links_key_t& a, const mc_links_key_t& b) const
        {
            return ((std::get<0>(a) == std::get<0>(b)) && (std::get<1>(a) == std::get<1>(b)));
        }
    };

    struct mc_allocated_mcid {
        uint16_t in_use;
        uint16_t mcid;
    };

    /// @brief Map the System MCID to the local MCID
    std::unordered_map<la_multicast_group_gid_t, la_multicast_group_gid_t> m_mc_smcid_to_local_mcid;

    /// @brief Map the devices bitmap to the allocated MCIDs
    std::unordered_map<mc_links_key_t, std::shared_ptr<mc_allocated_mcid>, mc_links_key_hash, mc_links_key_equal>
        m_links_bitmap_to_allocated_mcid;

    /// @brief Reverse map for MCID to devices bitmap
    std::unordered_map<la_multicast_group_gid_t, mc_links_key_t> m_mcid_to_links_bitmap;

    /// @brief Returns the number of fabric ports for a LC_56_FABRIC_PORT_MODE borrower IFG.
    size_t num_fabric_ports_in_borrower_ifg(la_slice_id_t sid, la_ifg_id_t ifg) const;

    la_status flush_mcid_cache(la_slice_id_t slice) const;
    la_status flush_rxpdr_mcid_cache(la_slice_id_t slice) const;
    la_status flush_txpdr_mcid_cache(la_slice_id_t slice) const;

    /// @brief Indicates whether the slice or slice/IFG is a borrowing a fabric port in LC_56_FABRIC_PORT_MODE.
    bool is_borrower_ifg(la_slice_id_t sid, la_ifg_id_t ifg) const;
    bool is_lender_ifg(la_slice_id_t sid, la_ifg_id_t ifg) const;
    bool is_borrower_slice(la_slice_id_t sid) const;

    // Core function to create voq_set
    la_status do_create_voq_set(la_voq_gid_t base_voq_id,
                                size_t set_size,
                                const la_vsc_gid_vec_t& base_vsc_vec,
                                la_device_id_t dest_device,
                                la_slice_id_t dest_slice,
                                la_ifg_id_t dest_ifg,
                                la_voq_set_wptr& out_voq_set);

    std::array<std::vector<size_t>, MAX_DEVICES> m_device_to_links;
    std::array<std::vector<size_t>, MAX_DEVICES> m_device_to_potential_links;
    std::array<std::vector<size_t>, MAX_LINK_BUNDLES_IN_FE_DEVICE> m_bundles;

    la_status init_fuse_userbits();

    la_status init_sbif_interrupts();
    la_status init_interrupts();
    la_status init_npe2dbc_thread_ready_indication();

    /// @brief Get the configured MAC aging check interval.
    ///
    /// @param[out] aging_interval          in seconds
    ///
    /// @retval     LA_STATUS_SUCCESS       aging_interval were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    la_status get_mac_aging_interval(la_mac_aging_time_t& aging_interval) override;

    /// @brief Set the configured MAC aging check interval.
    ///
    /// @param[in]  aging_interval          in seconds, to disable use
    ///                                     LA_MAC_AGING_TIME_NEVER
    ///
    /// @retval     LA_STATUS_SUCCESS       aging_interval were set successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   interval is too long
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    la_status set_mac_aging_interval(la_mac_aging_time_t aging_interval) override;

    void remove_oam_delay_arm(const la_bfd_session_base_wptr& entry);
    void add_oam_delay_arm(const la_bfd_session_base_wptr& entry);

    la_status set_learn_mode(learn_mode_e learn_mode) override;
    la_status get_learn_mode(learn_mode_e& out_learn_mode) override;

    bool is_simulated_device() const;
    bool is_emulated_device() const;
    bool is_simulated_or_emulated_device() const;

    la_status get_lb_hash_shift_amount(la_uint16_t& out_shift_amount) const;

    la_status set_interrupt_enabled(const lld_register_scptr& reg, size_t bit_i, bool enabled) override;
    la_status get_interrupt_enabled(const lld_register_scptr& reg, size_t bit_i, bool& out_enabled) override;
    la_status set_interrupt_enabled(const lld_memory_scptr& mem, bool enabled) override;
    la_status get_interrupt_enabled(const lld_memory_scptr& mem, bool& out_enabled) override;
    la_status get_forwarding_load_balance_stage(const la_object* forwarding_object,
                                                const la_lb_pak_fields_vec& lb_vec,
                                                size_t& out_member_id,
                                                const la_object*& out_resolved_object) const override;
    la_status get_forwarding_load_balance_chain(const la_object* forwarding_object,
                                                const la_lb_pak_fields_vec& lb_vec,
                                                std::vector<const la_object*>& out_resolution_chain) const override;
    la_status set_ecmp_hash_seed(la_uint16_t ecmp_lb_seed) override;
    la_status get_ecmp_hash_seed(la_uint16_t& out_ecmp_lb_seed) const override;
    la_status set_spa_hash_seed(la_uint16_t spa_lb_seed) override;
    la_status get_spa_hash_seed(la_uint16_t& out_spa_lb_seed) const override;
    la_status set_load_balancing_node_id(size_t load_balancing_node_id) override;
    la_status get_load_balancing_node_id(size_t& out_load_balancing_node_id) const override;
    la_status acquire_device_lock(bool blocking) override;
    void release_device_lock() override;
    la_status get_lowest_mtu_sibling_port_of_this_slice(const la_system_port* sys_port,
                                                        const la_system_port*& out_sys_port) const override;
    void get_acl_key_profile_types(acl_key_profile_type_e& out_ipv4_type, acl_key_profile_type_e& out_ipv6_type);
    /// @brief Function that initializes poll feature
    void initialize_poll_sensors();

    la_status set_sw_fc_pause_threshold(la_traffic_class_t tc, std::chrono::microseconds latency) override;
    la_status get_sw_fc_pause_threshold(la_traffic_class_t tc, std::chrono::microseconds& out_latency) const override;
    void get_acl_key_profile_translation_info(std::vector<udk_translation_info_sptr>& trans_info);
    void get_acl_key_profile_udf_types(la_udf_profile_type_e& ipv4_acl, la_udf_profile_type_e& ipv6_acl);
    void acl_key_profile_microcode_writes();
    la_status set_sw_pfc_destination(la_system_port_gid_t gid, la_npu_host_destination* npu_dest) override;
    la_status clear_sw_pfc_congestion_state(la_system_port_gid_t gid, la_traffic_class_t tc) override;
    void remove_pfc_watchdog_poll(const la_mac_port_base_wptr& entry);
    void add_pfc_watchdog_poll(const la_mac_port_base_wptr& entry);
    la_status set_pfc_watchdog_filter(la_system_port_gid_t gid, la_traffic_class_t tc, uint32_t slice, bool enable);
    la_status attach_synce_output(synce_clock_sel_e prim_sec_clock,
                                  la_slice_id_t slice_id,
                                  la_ifg_id_t ifg_id,
                                  la_uint_t serdes_id,
                                  uint32_t divider,
                                  uint32_t& out_synce_pin) override;
    la_status get_synce_output(synce_clock_sel_e prim_sec_clock,
                               uint32_t synce_pin,
                               la_slice_id_t& out_slice_id,
                               la_ifg_id_t& out_ifg_id,
                               la_uint_t& out_serdes_id,
                               uint32_t& out_divider) const override;
    la_status detach_synce_output(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin) override;
    la_status clear_synce_squelch_lock(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin) override;
    la_status set_synce_auto_squelch(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin, bool squelch_enable) override;
    la_status get_synce_auto_squelch(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin, bool& out_squelch_enable) const override;

    // Given an interrupt register return the corresponding LPM index (0 or 1).
    la_status get_cdb_core_lpm_index(lld_register_scptr lpm_shared_sram_interrupt_reg, size_t& out_lpm_index) const;

    // Handle LPM shared-sram ECC interrupt.
    la_status lpm_sram_mem_protect_handler(const lld_block& cdb_core, lpm_sram_mem_protect info);

    la_status write_persistent_token(la_user_data_t token) override;
    la_status read_persistent_token(la_user_data_t& out_token) const override;

    la_status do_write_persistent_token(la_user_data_t token);
    la_status do_read_persistent_token(la_user_data_t& out_token) const;

    // Exact meter as counter configuration
    la_meter_profile_impl_wptr m_exact_meter_profile;
    la_meter_action_profile_wptr m_exact_meter_action_profile;
    la_status create_exact_meter_as_counter_profiles();
    la_status do_create_meter(la_meter_set::type_e set_type, size_t set_size, la_meter_set_impl_wptr& out_meter);

    la_status get_internal_error_counter(internal_error_stage_e stage,
                                         internal_error_type_e type,
                                         la_counter_set*& out_counter) const override;

    bool is_multicast_scale_mode_configured() const;
    bool is_reserved_smcid(const la_multicast_group_gid_t mcid) const;
    bool is_scale_mode_smcid(const la_multicast_group_gid_t mcid) const;
    la_status multicast_reserved_smcid_fabric_slice_bitmap(la_multicast_group_gid_t smcid, uint32_t& out_slice_bitmap);
    la_status multicast_reserved_smcid_to_local_mcid(la_multicast_group_gid_t smcid, la_multicast_group_gid_t& out_local_mcid);
    la_status configure_network_static_mc_voq(la_slice_id_t slice, const la_voq_set_wptr& voq_set);

    la_status get_system_recycle_port(la_multicast_group_gid_t smcid, la_system_port_wcptr& recycle_port);

    la_status allocate_vni_profile(la_switch::vxlan_termination_mode_e vni_profile, uint64_t& index);
    la_status release_vni_profile(la_switch::vxlan_termination_mode_e vni_profile);

    la_status set_l2pt_trap_enabled(bool enabled) override;
    la_status get_l2pt_trap_enabled(bool& out_enabled) override;
    la_status get_decap_ttl_decrement_enabled(la_ip_tunnel_type_e type, bool& out_enabled) const override;
    la_status set_decap_ttl_decrement_enabled(la_ip_tunnel_type_e type, bool enabled) override;
    std::array<la_acl_command_def_vec_t, NUM_ACL_COMMAND_PROFILES> m_acl_command_profiles{{}};
    la_status get_sms_total_packet_counts(la_slice_id_t slice_id,
                                          la_ifg_id_t ifg,
                                          bool clear_on_read,
                                          la_sms_packet_counts& out_packet_count) override;
    la_status get_sms_error_counts(bool clear_on_read, la_sms_error_counts& out_error_count) override;
    la_status get_sms_total_free_buffer_summary(bool clear_on_read, la_uint64_t& out_free_buffer_count) override;
    la_status get_cgm_watermarks(la_cgm_watermarks& out_watermarks) override;
    la_status create_forus_destination(la_uint_t bincode, la_forus_destination*& out_destination) override;

    la_status set_acl_command_profile(uint32_t profile_index, const la_acl_command_def_vec_t& acl_command_profile);
    la_status get_acl_command_profile(uint32_t profile_index, la_acl_command_def_vec_t& out_acl_command_profile) const;
    la_status create_vrf_port_common(const la_l3_port_wptr& parent, std::shared_ptr<la_vrf_port_common_base>& out_vrf_port_common);

    la_tc_profile_impl_wptr m_mcg_counter_tc_profile;
    la_npu_host_port_base_wptr m_mcg_tx_npu_host_ports[ASIC_MAX_SLICES_PER_DEVICE_NUM][NUM_IFGS_PER_SLICE];

    la_status restore_fe_smcid_to_mcid_mapping();

    la_status restore_bundles();

    la_status create_system_port_scheduler(la_slice_id_t slice,
                                           la_ifg_id_t ifg,
                                           la_system_port_scheduler_id_t sp_sch_id,
                                           la_interface_scheduler_wptr interface_scheduler,
                                           la_system_port_scheduler_impl_sptr& out_scheduler);
    la_status create_logical_port_scheduler(la_slice_id_t slice_id,
                                            la_ifg_id_t ifg_id,
                                            la_system_port_scheduler_id_t tid,
                                            la_rate_t port_speed,
                                            la_logical_port_scheduler_impl_sptr& out_scheduler);
    la_status do_create_output_queue_scheduler(la_slice_id_t slice_id,
                                               la_ifg_id_t ifg_id,
                                               index_handle index,
                                               la_output_queue_scheduler::scheduling_mode_e mode,
                                               la_output_queue_scheduler_impl_sptr& out_scheduler);
    la_status create_fabric_port_scheduler(la_slice_id_t slice_id,
                                           la_ifg_id_t ifg_id,
                                           la_uint_t fab_intf_id,
                                           la_fabric_port_scheduler_impl_sptr& out_scheduler);
    la_status create_interface_scheduler(la_slice_id_t slice,
                                         la_ifg_id_t ifg,
                                         la_uint_t pif_base,
                                         la_mac_port::port_speed_e speed,
                                         bool is_fabric,
                                         la_interface_scheduler_impl_sptr& out_scheduler);
    la_status create_mpls_vpn_decap(la_mpls_label label, const la_vrf_wcptr& vrf, la_mpls_vpn_decap_impl_wptr& out_decap);
    la_status create_mldp_terminate(la_mpls_label label,
                                    const la_vrf_wcptr& vrf,
                                    la_uint_t rpfid,
                                    bool bud_node,
                                    la_mldp_vpn_decap_impl_wptr& out_decap);
    la_status modify_mldp_terminate(la_mpls_label label,
                                    const la_vrf_wcptr& vrf,
                                    la_uint_t rpfid,
                                    bool bud_node,
                                    la_mldp_vpn_decap_impl* vpn_decap);

    la_status create_system_port(la_system_port_gid_t gid,
                                 la_npu_host_port_base_wptr npu_host_port,
                                 const la_voq_set_wptr& voq_set,
                                 const la_tc_profile_wcptr& tc_profile,
                                 la_system_port_base_sptr& out_port);
    la_status create_multicast_group_common(std::shared_ptr<la_multicast_group_common_base>& out_multicast_group_common);

    la_status trigger_frt_scan();

    la_status get_mldp_bud_refcnt(la_slice_id_t slice_id, la_uint_t& out_refcnt);
    la_status incr_mldp_bud_refcnt(la_slice_id_t slice_id);
    la_status decr_mldp_bud_refcnt(la_slice_id_t slice_id);
    la_status get_mldp_bud_mpls_mc_copy_id(la_slice_id_t slice_id, uint64_t& out_mpls_mc_copy_id);
    la_status set_mldp_bud_mpls_mc_copy_id(la_slice_id_t slice_id, uint64_t mpls_mc_copy_id);
    size_t get_meter_cir_eir_factor(la_meter_set::type_e type) const;

    /// Whether acl was create.
    bool m_acl_created = false;

    la_status create_vrf_redirect_destination(const la_vrf* vrf, la_vrf_redirect_destination*& out_vrf_redirect_dest) override;
    la_status get_vrf_redirect_destination(const la_vrf* vrf, la_vrf_redirect_destination*& out_vrf_redirect_dest) const override;
    la_status get_vrf_redirect_destination_by_id(la_vrf_gid_t vrf_gid, const la_l3_destination*& out_vrf_redirect_dest) const;

    // helper-funcs for rcy ports
    la_system_port_base_wcptr allocate_punt_recycle_port(const la_system_port_base_wcptr& target_port);
    void release_punt_recycle_port(const la_system_port_base_wcptr& target_port);

    la_status get_mac_entries_count(la_uint32_t& out_count) override;
    la_status get_mac_entries(la_mac_entry_vec& out_mac_entries) override;
    la_status flush_mac_entries(bool dynamic_only, la_mac_entry_vec& out_mac_entries) override;
    la_status trigger_mem_protect_error(la_mem_protect_error_e error_type) override;

    /// @brief Set resource monitor for a given resource_type
    ///
    /// @param[in]  resource_monitor           Resource monitor to attach.
    la_status set_resource_monitor(la_resource_descriptor::type_e resource_type, const resource_monitor_sptr& monitor);

    /// @brief Get resource monitor of a given resource.
    ///
    /// @param[out]  out_resource_monitor           Resource monitor.
    la_status get_resource_monitor(la_resource_descriptor::type_e resource_type, resource_monitor_sptr& out_monitor) const;

    // device resource monitors
    struct resource_monitors {
        resource_monitor_sptr next_hop_resource_monitor;
    };

    la_uint32_t get_pbts_start_id();

private:
    /// @brief Static tables constants
    enum {
        /// Resolution tables constants
        RESOLUTION_ENCODING_PREFIX_MAX_LEN = 5,
        RESOLUTION_DESTINATION_LEN = 20,
        NATIVE_FEC_TYPE_DECODING_TABLE_KEY_LEN = 4,
        NATIVE_LB_TYPE_DECODING_TABLE_KEY_LEN = 4,
        NATIVE_LP_TYPE_DECODING_TABLE_KEY_LEN = 4,
        PORT_DSPA_TYPE_DECODING_TABLE_KEY_LEN = 1,

        /// Other table constants
        CALC_CHECKSUM_ENABLE_TABLE_KEY_LEN = 4,
        CUD_IS_MULTICAST_BITMAP_TX_CUD_PREFIX_LEN = 4,
        FABRIC_TM_HEADERS_TABLE_TX_CUD_PREFIX_LEN = 4,
        TERMINATION_TO_FORWARDING_FI_HARDWIRED_TABLE_KEY_LEN = 5,
        FWD_TYPE_TO_IVE_ENABLE_TABLE_KEY_LEN = 4,
        RECYCLE_OVERRIDE_TABLE_KEY_LEN = 6,
    };

    /// @brief Pacific header format sizes
    enum {
        /// Fabric headers field sizes
        FABRIC_HEADER_COMMON_FIELDS_SIZE = 1, // Header-type, Link FC, FCN, Reserved (PLB-context,...)
        FABRIC_HEADER_TS1_FIELD_SIZE = 3,     // Single time-stamp
        FABRIC_HEADER_TS3_FIELD_SIZE = 3 * 3, // Three time-stamps
        /// Fabric load-balancing header sizes
        FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET_SIZE = 6,  // = 1+(1*TS)+2     TS=3
        FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS_SIZE = 7, // = 1+(1*TS)+2+1   TS=3
        FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET_SIZE = 12,    // = 1+(3*TS)+2     TS=3
        FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS_SIZE = 13,   // = 1+(3*TS)+2+1   TS=3
        FABRIC_HEADER_TYPE_SN_TS_PLB_KEEPALIVE_SIZE = 10,   // = 1+9
        FABRIC_HEADER_TYPE_FLB_SIZE = 3,
        FABRIC_HEADER_TYPE_PEER_DELAY_REQUEST_SIZE = 12,      // = 1+4+4+2+1;
        FABRIC_HEADER_TYPE_PEER_DELAY_REPLY_SIZE = 12,        // = 1+4+4+2+1;
        FABRIC_HEADER_TYPE_FABRIC_TIME_SYNC_SIZE = 9,         // = 1+4+4
        FABRIC_HEADER_TYPE_CREDIT_SCHEDULER_CONTROL_SIZE = 3, // = 3;
        FABRIC_HEADER_TYPE_FABRIC_ROUTING_PROTOCOL_SIZE = 38, // = 1+1+36;
        FABRIC_HEADER_TYPE_SOURCE_ROUTED_SIZE = 5,            // = 1+4

        /// TM header sizes
        TM_HEADER_TYPE_UNICAST_OR_MUU_PLB_SIZE = 4,
        TM_HEADER_TYPE_UNICAST_FLB_SIZE = 3,
        TM_HEADER_TYPE_MMM_PLB_OR_FLB_SIZE = 3,
        TM_HEADER_TYPE_MUM_PLB_SIZE = 5,

        /// NPU header size
        NPU_HEADER_TX_FABRIC_SIZE = 32,
    };

    /// @brief Various constants
    enum {
        COMPRESSED_DESTINATION_PREFIX_LENGTH = 6,
        NUM_REDIRECT_CODES = 256,
        DUMMY_REDIRECT_ENCAP_PTR = 0xFF, ///< Ethernet encapsulation dummy pointer - used for dropped packet.
        MC_OQ_ID_LO_PRIORITY = 320,
        MC_OQ_ID_HI_PRIORITY = 321,

        /// Init related constants
        TSMS_RLB_UCH_FIFO_SIZE
        = 16, ///< PLB UC-High fifo size for TX slice, for FE fabric -> fabric, or, LC fabric -> network topologies
        TSMS_RLB_UCL_FIFO_SIZE
        = 16, ///< PLB UC-Low fifo size for TX slice, for FE fabric -> fabric, or, LC fabric -> network topologies
        TSMS_RLB_MC_FIFO_SIZE = 16, ///< PLB MC fifo size for TX slice, for FE fabric -> fabric, or, LC fabric -> network topologies
        NUMBER_OF_FUSE_REGISTERS = 4, ///< number of fuse user bits registers

        NUMBER_OF_RXPP_LB_KEYS = 6,
        B1_STAT_METER_FACTOR = 8, ///< configured shaper value over actual shaper value
    };

    /// @brief Scaffold tables constants
    enum {
        NP_MACRO_ID_LENGTH = 6,
    };

    enum {
        // There are two SBus rings - one connected through slice2/ifg0 and the second through slice3/ifg1
        SBUS_RING1_SLICE = 2,
        SBUS_RING1_IFG = 0,
        SBUS_RING2_SLICE = 3,
        SBUS_RING2_IFG = 1,
    };

    /// @brief Fabric-element mode.
    ///
    /// Pacific supports two types of Clos topologies:
    /// - Single level of fabric-elements.
    ///     _FE_
    ///    |    |
    ///   LC    LC
    /// A packet flow in this topology is seen as: LC --> FE --> LC
    ///
    /// - Two levels of fabric-elements.
    ///       _FE_
    ///      |    |
    ///    _FE    FE_
    ///   |          |
    ///  LC          LC
    /// A packet flow in this topology is seen as LC --> FE --> FE --> FE --> LC
    ///
    /// In the two-level-FEs topology the behavior of the FE depends on its level. An FE-mode differentiates this behavior. For
    /// each topology the modes of the FEs are:
    /// - Single level: LC --> FE2 --> LC
    /// - Two levels: LC --> FE13 --> FE2 --> FE13 --> LC
    enum class fe_mode_e {
        NONE, ///< Not a fabric-element device.
        FE2,  ///< Top-level fabric-element device.
        FE13, ///< Intermediate-level fabric-element device.
    };

    struct save_state_runtime {
        // The handle of the task inside the task scheduler that calls save_state.
        task_scheduler::task_handle task_handle{task_scheduler::INVALID_TASK_HANDLE};

        // Saving state period.
        std::chrono::milliseconds period{0};

        // Are the paremeters initialized.
        bool param_initialized = false;

        // Options to pass to save state on each call.
        la_device::save_state_options options;

        // File name prefix.
        std::string file_name_prefix{"./"};

        // Contains all the old file names, so that they can be removed as needed.
        std::deque<std::string> old_file_names;

        // Status from last save_state_thread
        la_status save_state_status;

        // save_state_thread
        std::thread worker_thread;

        // Is save_state_thread currently running
        std::atomic<bool> thread_running;

        save_state_runtime();
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(save_state_runtime);

    la_device_impl_base_sptr get_sptr() override;

    /// @brief Keeps all the data relevant to periodic save state cb.
    save_state_runtime m_save_state_runt;

    enum { CSS_MEMORY_PERSISTENT_TOKEN_BASE = (size_t)la_css_memory_layout_e::PERSISTENT_TOKEN / 4 };

    static constexpr la_trap_priority_t LAST_USER_ALLOWED_PRIORITY = std::numeric_limits<la_trap_priority_t>::max() - 3;

    // @brief Life-cycle helper functions
    la_status clear_meter_block_memories();
    la_status initialize_fw_filepath();
    la_status initialize_phase_device_core();
    la_status initialize_phase_device();
    la_status initialize_phase_topology(const translator_creator_sptr& creator);
    la_status initialize_serdes();
    la_status start_notifications();

    /// @brief Helper functions that initialize la_device fields
    void initialize_resolution_index_generators();

    la_status initialize_device_mode();

    /// @brief Helper functions that initializes containers and index generators.
    ///
    /// This function must run after #silicon_one::la_device::initialize_device_mode as it contains lazy initializations dependent
    /// on device mode.
    void device_mode_optimized_storage_initialization();

    /// @brief Initialize reconnect handler
    la_status initialize_reconnect_handler();

    /// @brief Poll on relevant blocks to wait hard reset is done.
    la_status poll_init_done();

    /// @brief Take all blocks out of soft reset state.
    la_status init_time_soft_reset(la_uint_t reset_val);

    /// @brief Fix problems of hard reset initialization.
    la_status apply_init_workarounds();

    /// @brief Write device mode into its table. For simulator only.
    la_status initialize_device_mode_table();

    /// @brief Initialize link_up_vector to all ones. For simulator only.
    la_status initialize_link_up_vector();

    /// @brief Initialize all_reachable_vector to zeros. For simulator only.
    la_status initialize_all_reachable_vector();

    /// @brief Iniliazie bitmap_oqg_map_table for simulator.
    la_status initialize_bitmap_oqg_map_table();

    // @brief Function that initializes device handlers in fabric mode
    la_status initialize_fabric_ifgb(la_mac_port::fc_mode_e fc_mode);

    /// @brief Functions that initialize device handlers
    la_status initialize_ifg();

    /// @brief Functions that initialize device tables
    la_status initialize_slice_modes();
    la_status initialize_traps();
    la_status initialize_internal_traps();
    la_status initialize_qos_mapping_tables();
    la_status initialize_dscp_to_qos_tag_table();
    la_status initialize_txpp_fwd_qos_mapping_table();
    la_status initialize_txpp_encap_qos_mapping_table();
    la_status initialize_native_lp_is_pbts_prefix_default_values();
    la_status initialize_path_lp_is_pbts_prefix_default_values();
    la_status initialize_fwd_type_to_ive_enable_default_values();
    la_status initialize_fwd_type_to_ive_enable_default_values_sa_lc();
    la_status initialize_fwd_type_to_ive_enable_default_values_fe();
    la_status initialize_bvn_tc_map_default_values();
    la_status initialize_rewrite_sa_prefix_index_table();
    la_status initialize_scaffolds();
    la_status initialize_scaffold_vlan_edit_tables();
    la_status initialize_scaffold_encap_qos_tag_table();
    la_status initialize_cud_range_managers();
    la_status initialize_mac_da_table();
    la_status initialize_lpts_counter_tables();
    la_status initialize_counters_voq_block_map_table();
    la_status initialize_lpts_allocation_cache();
    la_status release_lpts_allocation_cache();

    /// @brief Functions that configure copc protocol table
    la_status initialize_copc_protocol_table();
    la_status add_copc_protocol_entry(la_control_plane_classifier::protocol_table_data& entry);
    la_status remove_copc_protocol_entry(la_control_plane_classifier::protocol_table_data& entry);
    la_status get_copc_protocol_entries(la_control_plane_classifier::protocol_table_data_vec& out_entries);
    la_status clear_copc_protocol_entries();

    la_status post_topology_p4_overrides();
    la_status post_topology_p4_overrides_network();
    la_status set_pac_b1_padding(la_slice_id_t slice_id);

    /// @brief Functions called after la_device_impl serialize and deserialize
    ///        to serialize manual fields
    la_status warm_boot_post_save();
    la_status warm_boot_post_restore();

    /// @brief Functions that configure the static device tables
    la_status configure_static_tables();
    la_status configure_static_resolution_tables();
    la_status configure_static_resolution_destination_decoding_table();

    /// @brief Diagnostic functions
    la_status mbist_run();
    la_status mbist_run_cycle(bool repair, bool report_failures, bool& mbist_result);
    la_status mbist_activate(bool repair);
    la_status mbist_activate_write(bit_vector block_mbist_val, bit_vector sbm_mbist_val, bit_vector sms_mbist_val);
    la_status mbist_clear();
    la_status mbist_read_result(bool report_failures, size_t& total_tested, size_t& total_failed);
    la_status mbist_check_pass_fail_registers(bool report_failures,
                                              lld_register_scptr pass_reg,
                                              lld_register_scptr fail_reg,
                                              size_t& pass,
                                              size_t& fail);
    la_status mbist_check_status_register(bool report_failures, lld_register_scptr stat_reg, size_t& pass, size_t& fail);

    la_status mbist_hbm_run();

    /// @brief Functions that destroy different kinds of la_object
    la_status destroy_security_group_cell(const la_security_group_cell_base_wptr& sg_cell);
    la_status destroy_copc(const la_copc_base_wptr& copc);
    la_status destroy_remote_device(const la_remote_device_base_wptr& remote_device);
    la_status destroy_filter_group(const la_filter_group_impl_wptr& filter_group);
    la_status destroy_mac_port(const la_mac_port_base_wptr& port);
    la_status destroy_fabric_port(const la_fabric_port_impl_wptr& fabric_port);
    la_status destroy_pci_port(const la_pci_port_base_wptr& port);
    la_status destroy_recycle_port(const la_recycle_port_base_wptr& recycle_port);
    la_status destroy_remote_port(const la_remote_port_impl_wptr& remote_port);
    la_status destroy_system_port(const la_system_port_base_wptr& system_port);
    la_status destroy_spa_port(const la_spa_port_base_wptr& spa_port);
    la_status destroy_stack_port(const la_stack_port_base_wptr& spa_port);
    la_status destroy_punt_inject_port(const la_punt_inject_port_base_wptr& pi_port);
    la_status destroy_l2_punt_destination(const la_l2_punt_destination_impl_wptr& punt_dest);
    la_status destroy_npu_host_port(const la_npu_host_port_base_wptr& npu_host_port);
    la_status destroy_npu_host_destination(const la_npu_host_destination_impl_wptr& npu_host_dest);
    la_status destroy_erspan_mirror_command(const la_erspan_mirror_command_base_wptr& mirror_cmd);
    la_status destroy_l2_mirror_command(const la_l2_mirror_command_base_wptr& mirror_cmd);
    la_status destroy_ethernet_port(const la_ethernet_port_pacific_wptr& ethernet_port);
    la_status destroy_l2_service_port(const la_l2_service_port_pacific_wptr& port);
    la_status destroy_protection_monitor(const la_protection_monitor_impl_wptr& protection_monitor);
    la_status destroy_l2_protection_group(const la_l2_protection_group_base_wptr& l2_protection_group);
    la_status destroy_l3_protection_group(const la_l3_protection_group_impl_wptr& l3_protection_group);
    la_status destroy_switch(const la_switch_impl_wptr& sw);
    la_status destroy_ac_profile(const la_ac_profile_impl_wptr& profile);
    la_status destroy_l2_multicast_group(const la_l2_multicast_group_base_wptr& group);
    la_status destroy_ip_multicast_group(const la_ip_multicast_group_base_wptr& group);
    la_status destroy_fabric_multicast_group(const la_fabric_multicast_group_impl_wptr& group);
    la_status destroy_mpls_label_destination(const la_mpls_label_destination_impl_wptr& tunnel);
    la_status destroy_prefix_object(const la_prefix_object_base_wptr& prefix_object);
    la_status destroy_ip_tunnel_destination(const la_ip_tunnel_destination_impl_wptr& ip_tunnel_destination);
    la_status destroy_destination_pe(const la_destination_pe_impl_wptr& destination_pe);
    la_status destroy_asbr_lsp(const la_asbr_lsp_impl_wptr& asbr_lsp);
    la_status destroy_mpls_nhlfe(const la_mpls_nhlfe_impl_wptr& nhlfe);
    la_status destroy_mpls_vpn_decap(const la_mpls_vpn_decap_impl_wptr& vpn_decap);
    la_status destroy_mpls_vpn_encap(const la_mpls_vpn_encap_impl_wptr& vpn_encap);
    la_status destroy_mldp_vpn_decap(const la_mldp_vpn_decap_impl_wptr& vpn_decap);
    la_status destroy_mpls_multicast_group(const la_mpls_multicast_group_impl_wptr& group);
    la_status destroy_og_lpts_app(const la_og_lpts_application_impl_wptr& lpts_app);
    la_status destroy_output_queue_scheduler(const la_output_queue_scheduler_impl_wptr& oq_sch);
    la_status destroy_voq_set(const la_voq_set_impl_wptr& voq_set, bool ignore_active_not_empty);
    la_status destroy_voq_cgm_profile(const la_voq_cgm_profile_impl_wptr& profile);
    la_status destroy_te_tunnel(const la_te_tunnel_impl_wptr& te_tunnel);
    la_status destroy_tc_profile(const la_tc_profile_impl_wptr& profile);
    la_status destroy_l3_fec(const la_l3_fec_impl_wptr& fec);
    la_status destroy_vrf(const la_vrf_impl_wptr& vrf);
    la_status destroy_next_hop(const la_next_hop_base_wptr& next_hop);
    la_status destroy_vxlan_next_hop(const la_vxlan_next_hop_pacific_wptr& vxlan_next_hop);
    la_status destroy_l3_ac_port(const la_l3_ac_port_impl_wptr& port);
    la_status destroy_svi_port(const la_svi_port_base_wptr& port);
    la_status destroy_ip_over_ip_tunnel_port(const la_ip_over_ip_tunnel_port_impl_wptr& port);
    la_status destroy_gre_port(const la_gre_port_impl_wptr& port);
    la_status destroy_gue_port(const la_gue_port_impl_wptr& port);
    la_status destroy_ecmp_group(const la_ecmp_group_impl_wptr& ecmp_group);
    la_status destroy_acl_key_profile(const la_acl_key_profile_wptr& acl_key_profile);
    la_status destroy_acl_command_profile(const la_acl_command_profile_wptr& acl_command_profile);
    la_status destroy_acl_group(const la_acl_group_wptr& acl_group);
    la_status destroy_pcl(const la_pcl_impl_wptr& pcl);
    la_status destroy_lpts(const la_lpts_impl_wptr& lpts);
    la_status destroy_acl(const la_acl_impl_wptr& acl);
    la_status destroy_acl_scaled(const la_acl_scaled_impl_wptr& acl);
    la_status destroy_counter(const la_counter_set_impl_wptr& counter);
    la_status destroy_meter(const la_meter_set_impl_wptr& meter);
    la_status destroy_ingress_qos_profile(const la_ingress_qos_profile_impl_wptr& ingress_qos_profile);
    la_status destroy_egress_qos_profile(const la_egress_qos_profile_impl_wptr& egress_qos_profile);
    la_status destroy_meter_profile(const la_meter_profile_impl_wptr& meter_profile);
    la_status destroy_meter_action_profile(const la_meter_action_profile_impl_wptr& meter_action_profile);
    la_status destroy_bfd_session(const la_bfd_session_base_wptr& bfd_session);
    la_status destroy_rate_limiters(const la_rate_limiter_set_base_wptr& rate_limiter_set);
    la_status destroy_meter_markdown_profile(const la_meter_markdown_profile_impl_wptr& meter_markdown_profile);
    la_status destroy_multicast_protection_monitor(const la_multicast_protection_monitor_base_wptr& multicast_protection_monitor);
    la_status destroy_multicast_protection_group(const la_multicast_protection_group_base_wptr& multicast_protection_group);
    la_status destroy_rx_cgm_sq_profile(const la_rx_cgm_sq_profile_impl_wptr& profile);
    la_status destroy_vrf_redirect_destination(const la_vrf_redirect_destination_impl_wptr& vrf_redirect_dest);
    la_status destroy_pbts_map_profile(const la_pbts_map_profile_impl_wptr& profile);
    la_status destroy_pbts_group(const la_pbts_group_impl_wptr& group);

    /// @brief Helper functions that provide the entries for the static tables
    npl_destination_decoding_table_result_t get_resolution_destination_decoding_value(uint64_t destination_encoding);
    npl_destination_type_e get_resolution_destination_type(uint64_t destination_encoding);
    bool does_encoding_match_prefix(uint64_t destination_encoding, uint64_t prefix, uint64_t prefix_len);

    la_status do_set_lpm_destination_prefix_map(uint64_t compressed_prefix,
                                                size_t compressed_prefix_len,
                                                uint64_t prefix,
                                                size_t prefix_len,
                                                bool is_default);

    la_status set_lpm_destination_prefix_map(uint64_t compressed_prefix,
                                             size_t compressed_prefix_len,
                                             uint64_t prefix,
                                             size_t prefix_len,
                                             bool non_default_only,
                                             bool default_only);

    la_status configure_termination_to_forwarding_fi_hardwired_table();
    la_status configure_termination_to_forwarding_fi_hardwired_table_network();
    la_status configure_termination_to_forwarding_fi_hardwired_table_fabric();
    la_status configure_termination_to_forwarding_fi_hardwired_table_network_entry(npl_protocol_type_e header_type,
                                                                                   npl_fi_hardwired_type_e hw_type);

    la_status configure_cud_is_multicast_bitmap_table();
    la_status configure_cud_is_multicast_bitmap_entry(uint8_t bitmap, size_t prefix_len, bool is_mc);

    la_status configure_default_rx_cgm_sq_profile();
    la_rx_cgm_sq_profile_wptr m_default_rx_cgm_sq_profile;

    la_status configure_lpm_destination_prefix_map_table();
    la_status configure_nhlfe_type_mapping_table();
    la_status configure_rpf_fec_access_map_table();
    la_status configure_tunnel_dlp_p_counter_offset_table();
    la_status configure_l3_dlp_p_counter_offset_table();
    la_status configure_te_headend_lsp_counter_offset_table();
    la_status configure_pdoq_oq_ifc_mapping();
    la_status configure_pdoq_oq_ifc_mapping_network(la_slice_id_t sid, la_ifg_id_t ifg);
    la_status configure_pdoq_oq_ifc_mapping_fabric(la_slice_id_t sid, la_ifg_id_t ifg);
    la_status configure_reassembly_source_port_map_table();
    la_status configure_rx_npu_to_tm_dest_table();
    la_status configure_rx_npu_to_tm_dest_table_rx_network_slices();
    la_status configure_rx_npu_to_tm_dest_table_rx_fabric_slices();

    la_status configure_fabric_tm_headers_table();
    la_status configure_fabric_tm_headers_table_prefix_lsb_entries(npl_fabric_tm_headers_table_t::key_type key,
                                                                   npl_fabric_tm_headers_table_t::value_type value,
                                                                   uint64_t prefix,
                                                                   uint64_t prefix_len);
    la_status configure_fabric_headers_type_table();
    la_status configure_fabric_out_color_map_table();
    la_status configure_fabric_header_ene_macro_table();
    la_status configure_set_ene_macro_and_bytes_to_remove_table();
    la_status configure_set_ene_macro_and_bytes_to_remove_table_entry(npl_fabric_header_type_e fabric_header_type,
                                                                      npl_plb_header_type_e plb_header_type);
    la_status configure_fabric_filb_voq_mapping();
    la_status configure_npu_host();
    la_status configure_static_voqs();
    la_status configure_static_invalid_voq();
    la_status configure_static_mc_voqs();
    la_status configure_voq_cgm_drop_profile();
    la_status configure_lookup_error_drop_dsp();
    la_status configure_rx_drop_dsp();
    la_status configure_rx_not_cnt_drop_dsp();
    la_status init_lookup_error_macros_ids();
    la_status configure_meters_for_ecn_workaround_in_lc();
    void register_pollers();

    /// @brief Helper function that provide constant configuration of hardwired resolution LB keys calculation
    la_status update_rxpp_lb() const;

    la_status configure_learn_manager();

    /// @brief Update the TPID table with the profile of a given VLAn edit command
    ///
    /// @return status
    /// @retval     LA_STATUS_SUCCESS       TPID profile updated to the table.
    ///                                     if TPID profile already in table return success also
    /// @retval     LA_STATUS_ERESOURCE     Table is full, unable to insert new TPID profile.
    la_status update_tpid_table(const la_vlan_edit_command& edit_command, size_t& out_tpid_profile);

    // Resolution API-s
    la_status create_forus_destination();
    la_status create_l3_fec_common(const la_l3_destination_wptr& destination,
                                   bool is_internal_wrapper,
                                   la_l3_fec_impl_sptr& out_fec_impl);
    la_status create_l3_fec_common(const la_l2_destination_wptr& destination,
                                   bool is_internal_wrapper,
                                   la_l3_fec_impl_sptr& out_fec_impl);
    la_status destroy_l3_fec_common(const la_l3_fec_impl_wptr& fec_impl);

    /// @brief Called periodically to save state of the device.
    /// When invoked creates a separate thread of execution to do the actual saving.
    ///
    /// @note If period of execution is lower than the amount of time that the save state
    /// needs to finish, then the excess calls will be filtered out.
    void periodic_save_state();

    la_status save_state_thread();

    size_t num_vlan_format_tags(const npl_vlan_format_table_t::key_type& key) const;
    la_status update_vlan_format_table(la_switch::vxlan_termination_mode_e vni_profile, uint64_t& index);

    // Trap counters/meters
    std::array<la_counter_or_meter_set_wptr, NUM_REDIRECT_CODES> m_trap_counters_or_meters;

    // NPU objects
    std::vector<la_l2_destination_wptr> m_l2_destinations;

    std::vector<la_l2_punt_destination_wptr> m_l2_punt_destinations;

    // Trap configuration helper functions
    bool skip_trap_init(la_event_e trap);
    bool is_event_type_disabled(la_event_e trap);

    // Trap configuration entry
    struct la_trap_config_entry {
        la_event_e trap;                               ///< Trap type.
        la_trap_priority_t priority;                   ///< Trap priority.
        la_counter_or_meter_set_wptr counter_or_meter; ///< Counter associated with the trap.
        la_punt_destination_wcptr punt_dest;           ///< Punt destination of the trap.
        bool skip_inject_up_packets;                   ///< True if requested trap should not occur for inject up packets.
        bool skip_p2p_packets;                         ///< True if requested trap should not occur for p2p packets.
        bool overwrite_phb;                            ///< True if trap phb should be obtained from the trap configuration.
        la_traffic_class_t tc;                         ///< Trap traffic control.
        // Used only for OAM traps
        profile_allocator<oam_encap_info_t>::profile_ptr oam_encap; ///< OAM encap info.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(la_trap_config_entry);

    // Trap configuration ordered by priority
    std::vector<la_trap_config_entry> m_trap_entries;

    // Snoop configuration entry
    struct la_snoop_config_entry {
        la_event_e snoop;                   ///< Snoop type.
        la_trap_priority_t priority;        ///< Snoop priority.
        la_mirror_command_wcptr mirror_cmd; ///< Mirror command.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(la_snoop_config_entry);

    // Physical meter descriptors, mapped by slice-pair-id
    using slice_pair_lpts_counter_allocation = std::vector<counter_allocation>;
    std::vector<slice_pair_lpts_counter_allocation> m_lpts_allocation_cache;
    std::map<la_meter_set_wcptr, counter_allocation> m_lpts_meter_map[NUM_SLICE_PAIRS_PER_DEVICE];

    // Snoop configuration ordered by priority
    std::vector<la_snoop_config_entry> m_snoop_entries;

    // AAPL handlers
    struct hbm_aapl_desc {
        std::shared_ptr<la_aapl_user_hbm> user;
        Aapl_t* handler; // TODO wait for 3rd party serialization
        hbm_aapl_desc() : handler(nullptr)
        {
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(hbm_aapl_desc);
    std::vector<hbm_aapl_desc> m_hbm_aapl_handlers;

    struct pci_aapl_desc {
        std::shared_ptr<la_aapl_user_pci> user;
        Aapl_t* handler; // TODO wait for 3rd party serialization
        pci_aapl_desc() : handler(nullptr)
        {
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(pci_aapl_desc);
    pci_aapl_desc m_pci_aapl_handler;

    // Supported TPID-s
    std::vector<std::pair<la_tpid_t, la_tpid_t> > m_supported_tpid_pairs;

    // Dependencies

    // Object dependencies
    using la_object_multiset = std::multiset<la_object_wptr>;
    using la_object_dependency_list = std::map<la_object_wcptr, la_object_multiset>;
    la_object_dependency_list m_object_dependencies;

    // Slice management
    la_status do_dependency_management_op(dependency_management_op op); // used also for attribute dependencies

    using la_dependent_multiset = std::multiset<dependency_listener_wptr>;
    using la_notification_dependency_list = std::map<la_object_wcptr, la_dependent_multiset>;
    la_notification_dependency_list m_ifg_dependencies;

    la_status undo_ifg_dependency_management_op(dependency_management_op op, const dependency_listener_wptr& last_node);

    // Atrribute dependencies
    using la_refcount_multimap = std::multimap<dependency_listener_wptr, size_t>;
    using la_attribute_map = std::map<attribute_management_op, la_refcount_multimap>;
    using la_attribute_dependency = std::map<la_object_wcptr, la_attribute_map>;
    la_attribute_dependency m_attribute_dependencies;

    la_status undo_attribute_management_op(dependency_management_op op, const dependency_listener_wptr& last_node);

    // Trap counters
    la_status add_trap_counter_or_meter(uint64_t redirect_code, const la_counter_or_meter_set_wptr& counter_or_meter);
    la_status remove_trap_counter_or_meter(uint64_t redirect_code);

    // Details of native VOQ set
    struct native_voq_set_desc {
        la_device_id_t dest_device = -1;
        la_slice_id_t dest_slice = -1;
        la_ifg_id_t dest_ifg = -1;
        la_vsc_gid_vec_t base_vsc_vec = la_vsc_gid_vec_t(ASIC_MAX_SLICES_PER_DEVICE_NUM, LA_VSC_GID_INVALID);
        std::bitset<NATIVE_VOQ_SET_SIZE> is_busy{0};

        native_voq_set_desc();
        native_voq_set_desc(const native_voq_set_desc& ref);
        native_voq_set_desc(const la_vsc_gid_vec_t& vsc_vec, la_device_id_t device, la_slice_id_t slice, la_ifg_id_t ifg);

        bool operator==(const native_voq_set_desc& ref) const;
        bool operator!=(const native_voq_set_desc& ref) const;
        native_voq_set_desc& operator=(const native_voq_set_desc& ref);
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(native_voq_set_desc);

    // Map a native base-voq-id to the attributes of the set.
    std::vector<native_voq_set_desc> m_native_voq_sets;

    // Add/remove a VOQ-set to the native-sets list
    la_status native_voq_set_and_vsc_is_busy_list_add(la_voq_gid_t base_voq_id,
                                                      size_t set_size,
                                                      const native_voq_set_desc& voq_set_desc);
    void native_voq_set_and_vsc_is_busy_list_remove(const la_voq_set_wcptr& voq_set);
    la_status native_voq_set_list_add(la_voq_gid_t base_voq_id,
                                      size_t offset,
                                      size_t set_size,
                                      const native_voq_set_desc& voq_set_desc);

    // VSCs is-busy indicator. The uniqueness is per destination device:slice.
    // A standalone device should keep track of ASIC_MAX_SLICES_PER_DEVICE_NUM dest slices, NUM_IFGS_PER_SLICE ifgs,
    // MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE voqs.
    // A linecard   device should keep track of MAX_REMOTE_SLICE      dest slices, NUM_IFGS_PER_SLICE ifgs,
    // MAX_VSCS_PER_IFG_IN_LINECARD_DEVICE     voqs.
    // The same structure is used both for SA and LC, hence max is used.
    using vsc_ifg_usage_t
        = std::bitset<constexpr_max((int)MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE, (int)MAX_VSCS_PER_IFG_IN_LINECARD_DEVICE)>;
    using vsc_slice_usage_t = std::array<vsc_ifg_usage_t, NUM_IFGS_PER_SLICE>;
    using vsc_device_usage_t
        = std::array<vsc_slice_usage_t, constexpr_max((int)ASIC_MAX_SLICES_PER_DEVICE_NUM, (int)MAX_REMOTE_SLICE)>;
    using vsc_system_usage_t = std::array<std::unique_ptr<vsc_device_usage_t>, MAX_DEVICES>;
    vsc_system_usage_t m_vsc_is_busy;
    // Check whether the VSC is in the TXRQ duplication range
    bool check_vxrq_dup_range(la_slice_id_t dest_slice, const la_voq_set_wcptr& voq_set);

    la_uint_t m_tm_slice_mode[ASIC_MAX_SLICES_PER_DEVICE_NUM];

    // Get the index to the native VOQ sets list
    size_t get_native_voq_sets_index(la_voq_gid_t base_voq_id) const;

    // Iterate over the vsc_is_busy list
    bool check_and_set_vsc_is_busy_list(const native_voq_set_desc& voq_set_desc, size_t set_size, bool check_only, bool value);

    la_status init_config_memories();
    la_status init_config_memory(lld_memory_scptr mem,
                                 const std::map<lld_memory_scptr, bit_vector, lld_memory_scptr_ops>& mem_init_values);
    la_status disable_tcam_parity_scanners();
    la_status init_packet_dma();
    la_status init_hbm();

    la_status verify_topology_configuration();
    la_status init_txpp_time_offsets();
    la_status init_em_per_bank_reg();
    la_uint_t get_pif_from_serdes(la_uint_t serdes_idx);
    la_status init_tm();
    la_status init_tm_filb();
    la_status init_tm_ics();
    la_status init_tm_pdoq_fdoq();
    la_status init_tm_pdoq_top();
    la_status init_tm_pdvoq();
    la_status init_tm_reorder();
    la_status init_tm_rxcgm();
    la_status init_tm_rxpdr();
    la_status populate_rxpdr_device_mode(la_uint64_t& rxpdr_device_mode);
    la_status init_tm_rxpdr_mc_db();
    la_status init_tm_txcgm();
    la_status prepare_tx_cgm_uc_ifg_profile(lld_memory_value_list_t& mem_val_list, la_slice_id_t slice);
    la_status prepare_tx_cgm_uc_oq_profile(lld_memory_value_list_t& mem_val_list,
                                           lld_memory_line_value_list_t& mem_line_val_list,
                                           la_slice_id_t slice,
                                           bool is_lc_type_2_4_t,
                                           std::map<la_mac_port::port_speed_e, uint64_t>& out_fc_bytes_th_arr);
    la_status prepare_tx_cgm_uc_oqg_profile(lld_memory_value_list_t& mem_val_list,
                                            lld_memory_line_value_list_t& mem_line_val_list,
                                            la_slice_id_t slice,
                                            bool is_lc_type_2_4_t,
                                            const std::map<la_mac_port::port_speed_e, uint64_t>& fc_bytes_th_arr);
    la_status prepare_tx_cgm_mc_oq_profile(lld_memory_value_list_t& mem_val_list,
                                           lld_memory_line_value_list_t& mem_line_val_list,
                                           la_slice_id_t slice);
    la_status prepare_tx_cgm_mc_oq_profile_per_speed(lld_memory_value_list_t& mem_val_list,
                                                     lld_memory_line_value_list_t& mem_line_val_list,
                                                     la_slice_id_t slice,
                                                     size_t profile);
    la_status prepare_tx_cgm_mc_byte_pd_drop_resolutions(lld_memory_value_list_t& mem_val_list,
                                                         lld_memory_line_value_list_t& mem_line_val_list,
                                                         la_slice_id_t slice);
    la_status init_tm_txpdr();
    la_status init_tm_ts_ms();
    la_status prepare_tm_ts_ms_tsms_th_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t tx_slice);
    la_status populate_tm_ts_ms_tsms_th_configuration_reg(la_slice_id_t tx_slice,
                                                          la_slice_id_t rx_slice,
                                                          tsms_tsms_fifo_th_configuration_register& fifo_reg,
                                                          tsms_tsms_delete_fifo_th_configuration_register& delete_fifo_reg);
    la_status prepare_tm_ts_ms_rate_meter_cfg(lld_register_value_list_t& reg_val_list, la_slice_id_t tx_slice);
    la_status prepare_tm_ts_ms_rlb_fifo_start_addr(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t tx_slice);
    la_status prepare_tm_ts_ms_tsmon_valid_slice_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t tx_slice);
    la_status prepare_tm_ts_ms_keepalive_gen_cfg(lld_register_value_list_t& reg_val_list, la_slice_id_t tx_slice);
    la_status init_tm_ts_mon();
    la_status prepare_ts_mon_monitor_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t slice);
    la_status init_tm_reassembly();
    la_status init_tm_other();
    la_status init_other();
    la_status init_credit_size();
    la_status init_topology();
    la_status init_topology_tm(la_slice_id_t slice);
    la_status init_meters();
    la_status init_dmc();
    la_status init_dmc_frm();
    la_status init_dmc_fte();
    la_status init_dmc_pier();
    la_status clear_rcy_path();
    la_status init_sms_main();
    la_status disable_ipv4_header_checking();
    la_status init_load_balancing_keys();

    void set_default_cif_masks(lld_register_value_list_t& reg_val_list);
    void override_masks_ts_ms(lld_register_value_list_t& reg_val_list);
    void override_masks_hbm(lld_register_value_list_t& reg_val_list);
    void override_masks_mem_protect(lld_register_value_list_t& reg_val_list);
    void override_masks_npuh(lld_register_value_list_t& reg_val_list);
    void clear_sbif_interrupts(lld_register_value_list_t& reg_val_list);

    la_status retrieve_overhead_accounting(int& out_overhead) const;
    la_status configure_overhead_accounting(int overhead);

    la_status init_dynamic_memories();
    la_status apply_topology_post_soft_reset_workaround();
    la_status apply_topology_post_soft_reset_workaround_ics();
    la_status apply_topology_post_soft_reset_workaround_dics();
    la_status apply_topology_post_soft_reset_workaround_dvoq();
    la_status apply_topology_post_soft_reset_workaround_ifgb();
    la_status apply_topology_post_soft_reset_workaround_reorder();
    la_status apply_topology_post_soft_reset_workaround_tx_cgm();
    la_status apply_fabric_mac_port_workaround(la_mac_port::fc_mode_e fc_mode);
    la_status apply_fe_light_fi_workaround();

    la_status create_flow(translator_creator_sptr& creator);
    la_status initialize_translator_creator(const translator_creator_sptr& creator);

    la_status set_int_device_frequency(int32_t property_value);
    la_status set_int_tck_frequency(int32_t property_value);

    la_status initialize_hbm_max_pool();

    la_status get_npl_contexts(std::vector<npl_context_e>& out_npl_context_slices) const;
    npl_context_e get_npl_slice_context(la_slice_id_t sid) const;

    // Configure default values for multicast slice replication TC mapping
    la_status configure_mc_bitmap_tc_map_table();
    la_status configure_mc_bitmap_tc_map_table_per_tc(la_traffic_class_t tc, la_uint_t voq_offset);

    la_status configure_mc_emdb_tc_map_table();
    la_status configure_mc_emdb_tc_map_table_per_tc(la_traffic_class_t tc, la_uint_t voq_offset);

    // configure mcid threshold register for ingress replication
    la_status configure_tr_lc_sa_configuration_registers();

    // Configure multicast scale MCIDs
    la_status create_multicast_scale_reserved_groups();
    la_status destroy_multicast_scale_reserved_groups();
    la_status configure_multicast_scale_threshold_table(uint16_t threshold);

    // Configure default values for IBM TC mapping
    la_status configure_ibm_tc_map_table();
    la_status configure_mirror_to_dsp_in_npu_soft_header_table();
    la_status configure_snoop_to_dsp_in_npu_soft_header_table(uint64_t snoop_code, uint8_t value);
    la_status clear_snoop_to_dsp_in_npu_soft_header_table(uint64_t snoop_code);

    // Init the resource manager and the required resources
    la_status init_resource_management();

    // Update the MC bitmap tables
    la_status update_mc_bitmap_base_voq_lookup_table(la_slice_id_t dest_slice);

    // Update the FILB table with the MC slice replication VOQs
    la_status add_egress_multicast_slice_replication_voq_set_to_filb_table(la_slice_id_t dest_slice);
    la_status remove_egress_multicast_slice_replication_voq_set_from_filb_table(la_slice_id_t dest_slice);

    // Helper function to check SerDes mapping validity
    la_status check_serdes_mapping(la_slice_id_t slice_id,
                                   la_ifg_id_t ifg_id,
                                   la_serdes_direction_e direction,
                                   std::vector<la_uint_t> serdes_mapping_vec);

    // Update fabric tables
    la_status configure_fabric_init_cfg_table();

    // Diagnostics test
    la_status do_diagnostics_test(test_feature_e feature);

    // Notifications
    std::shared_ptr<hld_notification_base> m_notification;

    // fuse registers values
    bit_vector m_fuse_userbits;

    struct la_heartbeat_t m_heartbeat;

    void initialize_device_properties();
    void initialize_device_bool_properties();
    void initialize_device_int_properties();
    void initialize_device_string_properties();
    la_status configure_device_properties_phase_topology();
    la_status configure_device_bool_properties_phase_topology();
    la_status configure_device_int_properties_phase_topology();
    la_status configure_device_bool_property(la_device_property_e device_property);
    la_status configure_device_int_property(la_device_property_e device_property, int old_property_value);
    la_status configure_device_string_property(la_device_property_e device_property);
    bool is_allow_modify_property_at_phase(la_device_property_e device_property) const;
    la_status set_bool_property_lc_advertise_device_on_fabric_mode(bool property_value);
    la_status set_bool_property_lc_force_forward_through_fabric_mode(bool property_value);
    la_status set_bool_property_fe_per_device_min_links(bool property_value);
    la_status set_int_property_minimum_fabric_ports_for_connectivity(int32_t property_value);
    la_status set_bool_property_lpm_cache_enabled(bool enable);
    la_status set_bool_property_process_interrupts(bool enable);
    la_status set_interrupt_thresholds();
    bool is_mpls_sr_accounting_enabled() const;
    bool is_pbts_enabled() const;

    /// @brief Indicates whether the slice/IFG/serdes if a fabric port
    bool is_fabric_port_supporting_serdes(la_slice_id_t sid, la_ifg_id_t ifg, la_uint_t serdes) const;

    std::unique_ptr<fabric_init_handler> m_fabric_init_handler;

    fe_mode_e m_fe_mode;
    std::array<la_clos_direction_e, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_slice_clos_direction;
    bool m_fe_fabric_reachability_enabled;

    la_status initialize_fe_mode();

    void poll_mac_ports();

    struct mac_port_location_less {
        bool operator()(const la_mac_port_base::location& lhs, const la_mac_port_base::location& rhs) const
        {
            return std::tie(lhs.slice_id, lhs.ifg_id, lhs.first_serdes_id)
                   < std::tie(rhs.slice_id, rhs.ifg_id, rhs.first_serdes_id);
        }
    };
    std::map<la_mac_port_base::location, la_mac_port_base_wptr, mac_port_location_less> m_mac_ports;

    void poll_npu_host_event_queue();
    void poll_npu_host_arm_detection_queue();

    // Disable all network interfaces
    la_status reset_network_interfaces() const;

    std::vector<la_l2_multicast_group_pacific_wptr> m_l2_multicast_groups;
    std::vector<la_ip_multicast_group_pacific_wptr> m_ip_multicast_groups;
    std::vector<la_mpls_multicast_group_impl_wptr> m_mpls_multicast_groups;
    std::vector<la_fabric_multicast_group_impl_wptr> m_fabric_multicast_groups;

    // Lookup error WA counter.
    la_counter_set_impl_sptr m_lookup_error_drop_dsp_counter;

    // RX drop destination counter.
    la_counter_set_impl_sptr m_rx_drop_dsp_counter;

    // IP tunnel transit counter
    la_counter_set_impl_wptr m_ip_tunnel_transit_counter;

    // fe links poller
    void poll_fe_routing_table();
    void do_poll_fe_routing_table();
    void do_poll_fe_routing_table_npl();
    void update_current_links_state_and_handle_link_changes(const bit_vector& tmp_fe_routing_table, const size_t line_width_total);
    void update_on_fabric_links_changed(const la_device_id_vec_t& changed_devices);
    // TODO(ibogosav) Remove this once fe routing table pooling is fast enough
    std::chrono::time_point<std::chrono::steady_clock> m_fe_routing_table_last_pool_time_point;

    la_status remove_fabric_port_from_bundle(la_uint_t fabric_port_num, la_device_id_t dev_id);
    la_status add_fabric_port_to_bundle(la_uint_t fabric_port_num, la_device_id_t dev_id);
    la_status configure_bundle(size_t bundle_id);
    bool is_allowed_to_bundle_links(size_t first_link_in_bundle, size_t new_link) const;
    la_status write_bundle_desc_table_and_verify_write(la_slice_id_t slice,
                                                       size_t bundle_id,
                                                       rx_pdr_2_slices_fe_uc_link_bundle_desc_table_memory& bundle_desc);

    la_status configure_fe_broadcast_bmp(const size_t fe_broadcast_bmp_entries);
    la_status configure_fe_configurations_reg1(size_t num_valid_entries);

    la_status configure_reachability_of_lcs(la_device_id_vec_t devices);
    std::vector<size_t> m_lc_to_min_links;

    la_fabric_valid_links_thresholds m_valid_links_thresholds;
    la_fabric_congested_links_thresholds m_congested_links_thresholds;

    // Control enabling/disabling advertising fabric reachability.
    la_status update_fe_fabric_reachability_advertisement(bool is_fe_fabric_reachability_enabled,
                                                          bool is_per_device_min_links_mode);
    la_status software_reachability_update();
    la_status hardware_reachability_update();
    la_status advertise_empty_reachability();
    la_status set_reachable_bitmap_hw_updates_enabled(bool enabled);

    bool is_supported_save_state_option(save_state_options options) const;

    // LPM HBM caching
    la_status lpm_hbm_collect_stats();
    la_status lpm_hbm_do_caching();

    // Learn mananager related config
    learn_mode_e m_learn_mode;

    // Periodic reset of ICS delete fifo credits
    void periodic_workaround_reset_ics_delete_credits();

    // Periodic reset of age filter
    void periodic_workaround_reset_age_filter_entries();

    la_status configure_mcid_scale_threshold(int old_value, int new_value);

    la_status read_mc_fe_links_bmp_sram(size_t multicast_gid, bit_vector& out_links_bmp);

    la_mac_aging_time_t m_mac_aging_interval;

    // MC copy ID table use count
    using mc_copy_id_table_use_count_t = std::map<uint64_t, size_t>;
    std::array<mc_copy_id_table_use_count_t, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_mc_copy_id_table_use_count;
    la_status do_remove_from_mc_copy_id_table(la_slice_id_t slice, npl_mc_copy_id_map_key_t key);
    la_status do_add_to_mc_copy_id_table(la_slice_id_t slice, npl_mc_copy_id_map_key_t key, npl_mc_copy_id_map_value_t value);

    std::list<la_bfd_session_base_wptr> m_oam_delay_arm;
    la_status reset_bfd_session_timeout();

    bool m_lpts_allocation_cache_initialized;

    // Internal error counters and destination
    using internal_error_counter_map_key_t = std::tuple<internal_error_stage_e, internal_error_type_e>;
    std::map<internal_error_counter_map_key_t, la_counter_set_impl_wptr> m_internal_error_counters;
    template <class _TableType>
    la_status init_single_internal_error_counter(std::shared_ptr<_TableType> (&table)[ASIC_MAX_SLICES_PER_DEVICE_NUM],
                                                 internal_error_type_e type,
                                                 internal_error_stage_e stage);
    la_status init_internal_error_counters();
    la_status init_internal_error_handling();

    // Live soft-reset helper functions
    la_status exact_match_wa();

    std::array<std::chrono::microseconds, LA_NUM_EGRESS_TRAFFIC_CLASSES> m_pfc_tc_latency;
    std::list<la_mac_port_base_wptr> m_pfc_watchdog_poll;
    static constexpr size_t PFC_WATCHDOG_POLL_TIME_MS = 25; // Set polling to 25ms
    std::chrono::milliseconds m_pfc_watchdog_countdown{PFC_WATCHDOG_POLL_TIME_MS};
    void poll_pfc_watchdog();

    la_status prepare_dedicated_vsc_for_voq_flush();

    la_status prepare_dedicated_oq_for_mcg_counter();

    std::vector<la_slice_ifg> m_valid_ifgs_for_mcg_counters;
    size_t m_valid_ifg_for_mcg_counter_ptr;
    void init_valid_ifgs_for_mcg_counters();

    // Read fuse value:
    //
    // read_fuse()
    //     Read the full fuse value.
    //     Also, reload the 4k-bit-buffer. As a result, the lower 4 dwords of the fuse value can be fetched
    //     through sbif.efuse_userbits_reg0,1,2,3.
    //
    // read_fuse_no_reload()
    //     Read the full fuse value - a faster version.
    //     Don't reload the 4k-bit-buffer. As a result, sbif.efuse_userbits_reg0,1,2,3 are invalid.
    //
    // reload_fuse_userbits()
    //     Reload the 4k-bit-buffer. As a result, the lower 4 dwords of the fuse value can be fetched
    //     through sbif.efuse_userbits_reg0,1,2,3.
    //
    // read_fuse_userbits()
    //      Read sbif.efuse_userbits_reg0,1,2,3.
    //      If the 4k-bit-buffer was reloaded, this read will fetch the lower 4 dwords of the fuse value
    la_status read_fuse(bit_vector& out_bv);
    la_status read_fuse_no_reload(bit_vector& out_bv);
    la_status reload_fuse_userbits(bit_vector& out_bv);
    la_status read_fuse_userbits(bit_vector& out_bv);

    // fuse helpers
    la_status setup_tap_for_fuse_access(const bit_vector& test_reg_value_in, bit_vector& test_reg_value_out);
    la_status configure_tck_on_fuse_read(bit_vector& test_reg_value, bool enable_tck);
    la_status write_fuse_4k_bit_buffer(const bit_vector& write_data_in);
    la_status read_fuse_into_4k_bit_buffer();
    la_status read_fuse_4k_bit_buffer(const bit_vector& write_data_in, bit_vector& fuse_data_out);
    la_status do_read_fuse(bool reload, bit_vector& out_bv);
    int get_refclk_from_fuse(bit_vector& bv) const;

    npl_tunnel_type_e ip_tunnel_type_to_npl_type(la_ip_tunnel_type_e type) const;
    la_status initialize_ip_tunnel_inner_ttl_decrement_config_table();

    bool m_ttl_decrement_enabled[npl_tunnel_type_e::NPL_IP_TUNNEL_NONE] = {false};

    struct npl_l3_termination_classify_ip_tunnels_table_key_value_t {
        struct npl_l3_termination_classify_ip_tunnels_table_key_t key;     // from npl_table_types.h based on NPL
        struct npl_l3_termination_classify_ip_tunnels_table_key_t mask;    // from npl_table_types.h based on NPL
        struct npl_l3_termination_classify_ip_tunnels_table_value_t value; // npl_table_types.h
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(npl_l3_termination_classify_ip_tunnels_table_key_value_t)

    std::array<npl_l3_termination_classify_ip_tunnels_table_key_value_t, 10> m_l3_termination_classify_ip_tunnels_table;

    la_status initialize_l3_termination_classify_ip_tunnels_table();
    la_status set_l3_termination_classify_ip_tunnels_table(
        unsigned int entry_line,
        npl_l3_termination_classify_ip_tunnels_table_key_value_t key_mask_value // la_device_impl.h array element
        );
    la_status // called by set_decap_ttl_decrement_enabled
        set_decap_ttl_decrement_enabled_in_l3_termination_classify_ip_tunnels_table(la_ip_tunnel_type_e type, bool enabled);

    la_status do_set_global_minimum_fabric_links(size_t num_links);
    size_t m_global_min_fabric_links_threshold;

    la_status configure_oamp_redirect_code(uint64_t redirect_code,
                                           const la_counter_or_meter_set_wptr& counter_or_meter,
                                           const destination_id& redirect_dest,
                                           la_traffic_class_t tc,
                                           la_uint_t encap_ptr);
    la_status clear_oamp_redirect_code(uint64_t redirect_code);
    la_status set_trap_configuration_for_npu_host(la_event_e trap,
                                                  la_trap_priority_t priority,
                                                  const la_counter_or_meter_set_wptr& counter_or_meter,
                                                  const la_punt_destination_wcptr& destination,
                                                  la_traffic_class_t tc);
    // Trap get/set body
    la_status do_get_trap_configuration(la_event_e trap,
                                        la_trap_priority_t& out_priority,
                                        la_counter_or_meter_set_wptr& out_counter_or_meter,
                                        la_punt_destination_wcptr& out_destination,
                                        bool& out_skip_inject_up_packets,
                                        bool& out_skip_p2p_packets,
                                        bool& out_overwrite_phb,
                                        la_traffic_class_t& out_tc);
    la_status do_set_trap_configuration(la_event_e trap,
                                        la_trap_priority_t priority,
                                        const la_counter_or_meter_set_wptr& counter_or_meter,
                                        const la_punt_destination_wcptr& destination,
                                        bool skip_inject_up_packets,
                                        bool skip_p2p_packets,
                                        bool overwrite_phb,
                                        la_traffic_class_t tc);
    la_status do_create_tc_profile(la_tc_profile_impl_wptr& out_tc_profile);

    template <class T>
    la_status register_object(std::shared_ptr<T> new_object, la_object_id_t& oid)
    {
        bool is_success = m_index_generators.oids.allocate(oid);
        if (!is_success) {
            return LA_STATUS_ERESOURCE;
        }

        m_objects[oid] = std::static_pointer_cast<la_object>(new_object);
        log_debug(API,
                  "%s: new_object=%p type=%s oid=%lu",
                  __func__,
                  new_object.get(),
                  la_object_type_to_string(new_object->type()).c_str(),
                  oid);

        return LA_STATUS_SUCCESS;
    }
    void deregister_object(la_object_id_t oid);
    std::vector<la_object_wptr> get_objects_wptr(object_type_e type) const;

    // NPU objects
    std::vector<la_pci_port_base_wptr> m_pci_ports;
    std::vector<la_recycle_port_pacific_wptr> m_recycle_ports;
    std::vector<la_system_port_pacific_wptr> m_rcy_system_ports;
    std::vector<la_fabric_port_impl_wptr> m_fabric_ports;
    std::vector<la_ac_profile_impl_wptr> m_ac_profiles;
    std::vector<la_filter_group_impl_wptr> m_filter_groups;
    std::vector<la_ingress_qos_profile_impl_wptr> m_ingress_qos_profiles;
    std::vector<la_egress_qos_profile_impl_wptr> m_egress_qos_profiles;
    std::vector<la_vrf_impl_wptr> m_vrfs;
    std::vector<la_switch_impl_wptr> m_switches;
    std::vector<la_l2_destination_wptr> m_l2_ports;
    std::vector<la_l2_destination_wptr> m_pwe_ports;
    std::vector<la_next_hop_base_wptr> m_next_hops;
    std::vector<la_l3_port_wptr> m_l3_ports;
    std::vector<la_protection_monitor_wptr> m_protection_monitors;
    std::vector<la_l3_protection_group_wptr> m_l3_protected_entries;
    std::vector<la_l3_destination_wptr> m_prefix_objects;
    std::vector<la_mpls_vpn_encap_wptr> m_mpls_vpn_encap;
    std::vector<la_destination_pe_wptr> m_destination_pes;
    std::vector<la_te_tunnel_wptr> m_te_tunnels;
    std::vector<la_meter_markdown_profile_wptr> m_meter_markdown_profiles;
    std::vector<la_vrf_redirect_destination_wptr> m_vrf_redir_dests;

    template <class _PrefixType>
    la_status do_create_pcl(const _PrefixType& prefixes, const pcl_feature_type_e& feature, la_pcl_wptr& out_pcl);

    bool is_multicast_groups_configured() const;

    std::array<la_voq_set_impl_wptr, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_egress_multicast_slice_replication_voq_set;
    la_voq_set_wptr m_egress_multicast_fabric_replication_voq_set;

    // Device tuning specific for SW PFC
    la_status set_sw_pfc_device_tuning_enabled();
    // Device tuning for both SW/HW PFC
    la_status set_pfc_device_tuning_enabled();

    la_status set_int_device_pfc_pilot_probability(int32_t property_value);
    la_status set_int_device_pfc_measurement_probability(int32_t property_value);
    la_status set_bool_property_pacific_pfc_hbm_enabled(bool enable);
    la_status create_pfc_mirror_command(la_mirror_gid_t mirror_gid,
                                        const la_punt_inject_port_base_wptr& punt_inject_port,
                                        la_uint_t voq_offset,
                                        float probability,
                                        la_l2_mirror_command_wptr& out_mirror_cmd);
    la_status create_l2_mirror_command(la_mirror_gid_t mirror_gid,
                                       const la_npu_host_port_base_wptr& npu_host_port,
                                       la_uint_t voq_offset,
                                       float probability,
                                       la_l2_mirror_command_wptr& out_mirror_cmd);

    la_status init_pfc_sw_tables();
    la_status init_resolution_set_next_macro_table();

    std::unique_ptr<arc_handler_pacific> m_arc_hdlr;

    la_status reconnect_pci_ports_after_warm_boot();
    std::unique_ptr<npu_host_event_queue_base> m_npu_host_eventq;
    bool m_cpu_eventq_polling;

    std::array<bool, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_punt_recycle_port_exist;

    // All objects created by this device
    std::vector<la_object_sptr> m_objects; // Keep as the last field in the class

    struct mldp_bud_info {
        // number of mldp bud labels using the recycle port
        la_uint_t recycle_mldp_bud_refcnt;

        // copy_id to be used by mldp labels using this port
        uint64_t mpls_mc_copy_id;
    } m_mldp_bud_info[ASIC_MAX_SLICES_PER_DEVICE_NUM];

    CEREAL_SUPPORT_PRIVATE_CLASS(mldp_bud_info);

    // device resource monitors
    resource_monitors m_resource_monitors;

}; // class la_device_impl

} // namespace silicon_one

#endif // __LA_DEVICE_IMPL_H__
