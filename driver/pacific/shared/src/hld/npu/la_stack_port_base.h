// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_STACK_PORT_BASE_H__
#define __LA_STACK_PORT_BASE_H__

#include "api/npu/la_stack_port.h"
#include "api/types/la_common_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"
#include "npu/resolution_utils.h"

#include "api_tracer.h"

#include <vector>

namespace silicon_one
{

class la_stack_port_base : public la_stack_port, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_stack_port_base(const la_device_impl_wptr& device);
    ~la_stack_port_base() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, const la_system_port_base_wptr& system_port);
    la_status initialize(la_object_id_t oid, const la_spa_port_base_wptr& spa_port);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    la_status add_ifg(la_slice_ifg ifg);

    la_status remove_ifg(la_slice_ifg ifg);

    slice_ifg_vec_t get_ifgs() const;

    bool is_member(const la_system_port_wcptr& system_port) const;

    bool is_aggregate() const;

    la_object* get_underlying_port() const;

    // la_stack_port API-s

    const la_system_port* get_system_port() const override;
    const la_spa_port* get_spa_port() const override;
    la_status set_local_punt_system_port(la_system_port* system_port) override;
    la_status set_remote_punt_system_port(la_system_port* system_port) override;
    la_status set_remote_punt_src_mac(la_mac_addr_t mac_addr) override;
    const la_system_port* get_remote_punt_system_port() const;

    la_status get_remote_punt_mac(la_mac_addr_t& out_mac_addr) const;

    destination_id get_destination_id(resolution_step_e prev_step) const;

    la_status set_peer_device_id(la_device_id_t peer_device_id) override;
    la_device_id_t get_peer_device_id() override;
    la_status set_control_traffic_queueing(la_system_port* system_port, la_voq_set* voq_set) override;
    uint32_t get_control_traffic_destination_id(la_system_port* system_port, la_uint_t voq_offset) override;
    la_status erase_control_traffic_queueing(const la_system_port_wcptr& system_port);

protected:
    la_stack_port_base() = default; // For serialization purposes only
    using system_port_base_vec = std::vector<la_system_port_base_wptr>;
    using control_traffic_voq_map_t = std::map<la_system_port_wcptr, la_voq_set_wptr>;

    la_status initialize_common();
    la_status destroy_common();

    virtual la_status set_source_pif_entry() = 0;
    la_status erase_source_pif_entry();

    la_status set_rx_obm_code_table_entry(la_slice_id_t slice);
    la_status erase_rx_obm_code_table_entry(la_slice_id_t slice);

    virtual npl_initial_pd_nw_rx_data_t populate_initial_pd_nw_rx_data() const = 0;

    la_device_impl_wptr m_device;

    ifg_use_count_uptr m_ifg_use_count;

    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    la_system_port_base_wptr m_system_port;

    la_spa_port_base_wptr m_spa_port;

    la_system_port_base_wptr m_remote_punt_system_port;
    la_system_port_base_wptr m_local_punt_system_port;

    la_mac_addr_t m_remote_punt_mac;

    la_device_id_t m_peer_device_id;

    control_traffic_voq_map_t m_control_traffic_voq_map;
    control_traffic_voq_map_t::const_iterator find_in_voq_map(const la_system_port_wcptr& sys_port) const;

    virtual la_status set_peer_device_reachable_stack_port_destination() = 0;
};
}
/// @}

#endif
