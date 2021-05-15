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

#include "la_next_hop_impl_common.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_switch.h"
#include "api/types/la_common_types.h"
#include "common/defines.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_l3_ac_port_impl.h"
#include "la_switch_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_svi_port_base.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_next_hop_impl_common::la_next_hop_impl_common(const la_device_impl_wptr& device) : m_device(device), m_gid(0)
{
}

la_next_hop_impl_common::~la_next_hop_impl_common()
{
}

la_next_hop_gid_t
la_next_hop_impl_common::get_gid() const
{
    return m_gid;
}

la_status
la_next_hop_impl_common::add_ifg(la_slice_ifg ifg)
{
    transaction txn;

    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    // If IFG is already configured, bail
    if (!ifg_added) {
        return LA_STATUS_SUCCESS;
    }

    if (m_next_hop != nullptr && slice_added) {
        txn.status = m_next_hop->configure_per_slice_tx_tables(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([&]() { m_next_hop->teardown_per_slice_tx_tables(ifg.slice); });
    }

    // Notify users
    txn.status = m_device->notify_ifg_added(m_next_hop, ifg);
    return txn.status;
}

la_status
la_next_hop_impl_common::remove_ifg(la_slice_ifg ifg)
{
    transaction txn;

    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->add_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (!ifg_removed) {
        return LA_STATUS_SUCCESS;
    }

    txn.status = m_device->notify_ifg_removed(m_next_hop, ifg);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_device->notify_ifg_added(m_next_hop, ifg); });

    if (m_next_hop != nullptr && slice_removed) {
        txn.status = m_next_hop->teardown_per_slice_tx_tables(ifg.slice);
    }

    return txn.status;
}

la_status
la_next_hop_impl_common::initialize(const la_object_wptr& parent,
                                    la_next_hop_gid_t nh_gid,
                                    la_mac_addr_t nh_mac_addr,
                                    const la_l3_port_wptr& port)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_gid = nh_gid;
    m_mac_addr = nh_mac_addr;
    m_l3_port = port;

    la_object::object_type_e parent_type = parent->type();
    switch (parent_type) {
    case la_object::object_type_e::NEXT_HOP:
        m_next_hop = parent.weak_ptr_static_cast<la_next_hop_base>();
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    if (m_next_hop != nullptr) {
        la_status status = m_next_hop->configure_global_tx_tables();
        return_on_error(status);
    }

    slice_ifg_vec_t ifgs;

    if (port != nullptr) {
        ifgs = silicon_one::get_ifgs(port);

        for (auto ifg : ifgs) {
            la_status status = add_ifg(ifg);
            if (status != LA_STATUS_SUCCESS) {
                destroy();
                return status;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_impl_common::update_next_hop_mac_addr(la_mac_addr_t nh_mac_addr)
{
    if (m_l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (m_next_hop == nullptr) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_object::object_type_e l3_port_type = m_l3_port->type();
    if (l3_port_type == la_object::object_type_e::L3_AC_PORT) {
        la_status status = m_next_hop->update_global_tx_tables();
        return_on_error(status);
        m_mac_addr = nh_mac_addr;
    } else if (l3_port_type == la_object::object_type_e::SVI_PORT) {
        // global tx tables are updated in la_next_hop_base class
        m_mac_addr = nh_mac_addr;
    } else {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_impl_common::clear_port_dependencies()
{
    if (m_l3_port == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    auto ifgs = m_ifg_use_count->get_ifgs();

    for (la_slice_ifg ifg : ifgs) {
        la_status status = remove_ifg(ifg);
        return_on_error(status);
    }

    m_l3_port = nullptr;
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_impl_common::destroy()
{
    auto ifgs = m_ifg_use_count->get_ifgs();

    for (la_slice_ifg ifg : ifgs) {
        la_status status = remove_ifg(ifg);
        return_on_error(status);
    }

    la_status status = LA_STATUS_SUCCESS;
    if (m_next_hop != nullptr) {
        status = m_next_hop->teardown_global_tx_tables();
    }

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_impl_common::get_mac(la_mac_addr_t& out_mac_addr) const
{
    out_mac_addr = m_mac_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_impl_common::get_router_port(la_l3_port_wptr& out_port) const
{
    out_port = m_l3_port;

    return LA_STATUS_SUCCESS;
}

const la_device*
la_next_hop_impl_common::get_device() const
{
    return m_device.get();
}

slice_ifg_vec_t
la_next_hop_impl_common::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_status
la_next_hop_impl_common::get_nh_l2_destination(la_l2_destination_wptr& out_l2_dest) const
{
    if (m_l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_l2_destination_wcptr l2_dest;
    la_status status = get_l2_destination(m_l3_port, m_mac_addr, l2_dest);
    return_on_error(status);

    out_l2_dest = l2_dest.weak_ptr_const_cast<la_l2_destination>();

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_impl_common::get_dsp_or_dspa(la_l2_port_gid_t& out_npp_gid, bool& out_is_aggregate) const
{
    la_l2_destination_wptr l2_dest = nullptr;
    la_status status = get_nh_l2_destination(l2_dest);

    if (status == LA_STATUS_SUCCESS) {
        status = silicon_one::get_dsp_or_dspa(m_device, l2_dest, out_npp_gid, out_is_aggregate);
        return_on_error(status);
    } else if (status == LA_STATUS_ENOTFOUND) {
        if (m_l3_port->type() == la_object::object_type_e::SVI_PORT) {
            out_is_aggregate = false;
            auto svi = m_l3_port.weak_ptr_static_cast<la_svi_port_base>();
            status = svi->get_inject_up_source_port_dsp(out_npp_gid);
            return_on_error(status);
        }
    } else {
        return_on_error(status);
    }

    return status;
}

la_status
la_next_hop_impl_common::get_l3_port_mac(la_mac_addr_t& out_sa) const
{
    if (m_l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_object::object_type_e l3_port_type = m_l3_port->type();

    switch (l3_port_type) {
    case la_object::object_type_e::SVI_PORT: {
        auto svi = m_l3_port.weak_ptr_static_cast<la_svi_port_base>();
        return svi->get_mac(out_sa);
    }

    break;

    case la_object::object_type_e::L3_AC_PORT: {
        auto l3_ac = m_l3_port.weak_ptr_static_cast<la_l3_ac_port_impl>();
        return l3_ac->get_mac(out_sa);
    }

    break;

    default:

        return LA_STATUS_ENOTFOUND;
    }
}

const la_l3_port_wptr
la_next_hop_impl_common::get_l3_port() const
{
    return m_l3_port;
}

la_slice_id_vec_t
la_next_hop_impl_common::get_slices() const
{
    return m_ifg_use_count->get_slices();
}

std::vector<la_slice_pair_id_t>
la_next_hop_impl_common::get_slice_pairs() const
{
    return m_ifg_use_count->get_slice_pairs();
}

} // namespace silicon_one
