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

#ifndef __LA_FABRIC_PORT_IMPL_H__
#define __LA_FABRIC_PORT_IMPL_H__

#include "api/system/la_fabric_port.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "lld/pacific_mem_structs.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_fabric_port_impl : public la_fabric_port, public dependency_listener
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_fabric_port_impl() = default;
    //////////////////////////////
public:
    explicit la_fabric_port_impl(const la_device_impl_wptr& device);
    ~la_fabric_port_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_mac_port* fabric_mac_port);
    la_status destroy();
    la_status restore_state();

    // Inherited API-s
    la_status get_adjacent_peer_info(adjacent_peer_info& out_adjacent_peer_info) const override;
    la_status set_reachable_lc_devices(const la_device_id_vec_t& device_id_vec) override;
    la_status get_reachable_lc_devices(la_device_id_vec_t& out_device_id_vec) const override;
    la_fabric_port_scheduler* get_scheduler() const override;
    la_status activate(link_protocol_e link_protocol) override;
    la_status deactivate(link_protocol_e link_protocol) override;
    la_status get_link_keepalive_activated(bool& out_activated) const override;
    la_status get_status(port_status& out_port_status) const override;
    const la_mac_port* get_mac_port() const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    /// Returns the device-level fabric port num (agnostic to LC_56_FABRIC_PORT_MODE)
    la_uint_t get_fabric_port_num() const;

private:
    /// @brief Fabric mac port constants.
    enum {
        NUM_FABRIC_PORT_PER_NORMAL_SLICE
        = NUM_IFGS_PER_SLICE * NUM_FABRIC_PORTS_IN_NORMAL_IFG, /// Number of fabric ports in a "normal" slice.
        BORROWED_FABRIC_PORT_TSMS_TSMON_ID = 18,               /// The fabric-port number of the borrowed port in TSMS and TSMON
    };

    la_status activate_peer_discovery();
    la_status activate_link_keepalive();

    la_status deactivate_peer_discovery();
    la_status deactivate_link_keepalive();

    la_status configure_frm_db_fabric_routing_table(const la_device_id_vec_t& device_id_vec);
    la_status configure_frm_db_fabric_routing_table_npl(const la_device_id_vec_t& device_id_vec);
    la_status configure_frm_db_fabric_routing_table_hardware(const la_device_id_vec_t& device_id_vec);
    la_status configure_frm_db_rev_fabric_routing_table(const la_device_id_vec_t& device_id_vec);

    la_status configure_source_pif_hw_table();
    la_status erase_source_pif_hw_table();

    la_status configure_all_reachable_vector(bool all_reachable);

    /// Returns the slice-level fabric port num (dependent of LC_56_FABRIC_PORT_MODE)
    la_uint_t get_tsms_tsmon_fabric_port_num_in_slice() const;
    la_status set_fabric_link_down_transition(bool enable_link);
    la_status get_fabric_link_down_transition(bool& out_enabled) const;
    la_status do_peer_delay_measurement();
    la_status clear_peer_delay_measurement();
    la_status get_peer_delay_mem_entry(fte_peer_delay_mem_memory& out_peer_delay_mem_entry) const;
    la_status set_keepalive_generation(bool enable);
    la_status get_keepalive_generation(bool& out_enabled) const;
    la_status do_set_reachable_lc_devices(const la_device_id_vec_t& device_id_vec);

    la_status restore_non_volatile();

    void register_dependency(const la_mac_port_base* fabric_mac_port);
    void unregister_dependency(const la_mac_port_base* fabric_mac_port);

    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);
    la_status update_mac_port_link_state_down();

    // Device this port object is created on
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Fabric MAC port servicing this fabric port
    la_mac_port_base_wptr m_mac_port;

    // Logical slice ID
    la_slice_id_t m_slice_id;

    // Logical interface group ID
    la_ifg_id_t m_ifg_id;

    // Logical first serdes (within the IFG)
    la_uint_t m_serdes_base;

    // Logical first pif (within the IFG)
    la_uint_t m_pif_base;

    // Indicates whether this is a LC_56_FABRIC_PORT_MODE ports
    bool m_is_lc_56_fabric_port;

    // Fabric port scheduler
    la_fabric_port_scheduler_impl_wptr m_scheduler;

    la_device_id_t m_peer_dev_id;
};
}

/// @}

#endif
