// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __PORT_HELPER_H__
#define __PORT_HELPER_H__

#include "api/types/la_limit_types.h"
#include "api/system/la_system_port.h"
#include "api/tm/la_voq_set.h"
#include "api/system/la_device.h"
#include "sai_constants.h"
#include "sai_device.h"
#include "sai_port.h"
#include "sai_logger.h"
#include "sai_leaba.h"

namespace silicon_one
{
namespace sai
{

class lsai_device;

la_status port_scheduler_default_config(std::shared_ptr<lsai_device> sdev,
                                        port_entry& port_entry,
                                        la_interface_scheduler* ifc_sch,
                                        uint64_t port_mbps,
                                        la_vsc_gid_vec_t vsc_vec);

template <typename base_port_t>
la_status
setup_la_system_port(const base_port_t& base_port,
                     la_uint_t vsc_offset,
                     uint64_t port_mbps,
                     port_entry* pentry,
                     std::shared_ptr<lsai_device> sdev,
                     transaction& txn,
                     const la_system_port_gid_t* sp_gid_ptr = nullptr)
{
    la_voq_set* voq_set = nullptr;
    // create another set of voqs
    la_voq_set* voq_set_ecn = nullptr;
    la_vsc_gid_vec_t vsc_vec(sdev->m_dev_params.slices_per_dev);
    la_vsc_gid_vec_t vsc_vec_ecn(sdev->m_dev_params.slices_per_dev);
    la_system_port* system_port;

    lsai_object la_port(pentry->oid);

    if (sp_gid_ptr != nullptr) {
        // Override the pentry's default SP GID with the provided GID
        la_uint64_t min_sp_gid;
        txn.status = sdev->m_dev->get_limit(limit_type_e::DEVICE__MIN_SYSTEM_PORT_GID, min_sp_gid);
        la_return_on_error(txn.status);
        pentry->sp_gid = (*sp_gid_ptr) + min_sp_gid;
    }

    // Update System Port GID -> Port mapping
    sdev->set_la2sai_port(pentry->sp_gid, pentry->oid);

    txn.status = sdev->setup_sp_voq_and_cgm(vsc_offset, pentry, vsc_vec, vsc_vec_ecn, voq_set, voq_set_ecn, txn);
    la_return_on_error(txn.status);

    txn.status = sdev->m_dev->create_system_port(
        pentry->sp_gid, base_port, voq_set, sdev->m_qos_handler->get_default_tc_profile(), system_port);
    la_return_on_error(txn.status, "Failed creating system port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(system_port); });

    // Retrieve port index, then update entry
    pentry->sys_port = system_port;

    // set the ecn capable transport to the other voq set
    // set_ect_voq_set() currently implemented only for the gb hw
    if (sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR && pentry->type == port_entry_type_e::MAC) {
        txn.status = pentry->sys_port->set_ect_voq_set(voq_set_ecn);
        la_return_on_error(txn.status, "Failed setting ecn capable transport to voq set, %s", txn.status.message().c_str());
    }

    txn.status = sdev->setup_sp_tm_defaults(voq_set, voq_set_ecn, vsc_vec, port_mbps, pentry, base_port->get_scheduler(), txn);

    return txn.status;
}

inline la_status
setup_sai_system_port(uint32_t lane, const sai_system_port_config_t& sp_config, shared_ptr<lsai_device> sdev, transaction& txn)
{
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    sai_object_id_t sai_port_id;
    txn.status = sdev->get_lane_to_port(lane, sai_port_id);

    sai_system_port_api_t* sp_api;
    txn.status = to_la_status(sai_api_query(SAI_API_SYSTEM_PORT, (void**)(&sp_api)));
    la_return_on_error(txn.status, "Fail to get api, \"SAI_API_SYSTEM_PORT\".");

    vector<sai_attribute_t> sp_attrs;
    sai_attribute_t sp_attr{};
    sp_attr.id = SAI_SYSTEM_PORT_ATTR_CONFIG_INFO;

    sp_attr.value.sysportconfig = sp_config;
    sp_attrs.push_back(sp_attr);

    sai_object_id_t sai_sp_id;
    txn.status = to_la_status(sp_api->create_system_port(&sai_sp_id, sdev->m_switch_id, sp_attrs.size(), sp_attrs.data()));
    la_return_on_error(txn.status, "Failed create_system_port.");
#endif
    return LA_STATUS_SUCCESS;
}

inline la_status
setup_sai_system_port(uint32_t lane, shared_ptr<lsai_device> sdev, transaction& txn)
{
    sai_system_port_config_t sp_config;
    txn.status = sdev->m_voq_cfg_manager->get_sp_cfg_from_lane(lane, sp_config);
    la_return_on_error(txn.status);

    return setup_sai_system_port(lane, sp_config, sdev, txn);
}

inline la_status
setup_sai_system_port(la_slice_id_t slice_id, la_ifg_id_t ifg_id, uint32_t pif, shared_ptr<lsai_device> sdev, transaction& txn)
{
    uint32_t lane = to_sai_lane(slice_id, ifg_id, pif);
    return setup_sai_system_port(lane, sdev, txn);
}

// Setup internal system port. Internal SPs have a unique usage since
// they are not created by a direct SAI layer call.
template <typename base_port_t>
la_status
setup_internal_system_port(const base_port_t& base_port,
                           uint32_t pif,
                           la_uint_t vsc_offset,
                           uint64_t port_mbps,
                           port_entry* pentry,
                           std::shared_ptr<lsai_device> sdev,
                           transaction& txn)
{
    if (sdev->m_voq_cfg_manager->is_npu_switch()) {
        // In NPU mode, create system ports without using the SAI API
        // create_system_port.
        txn.status = setup_la_system_port(base_port, vsc_offset, port_mbps, pentry, sdev, txn);
        la_return_on_error(txn.status);
    } else if (sdev->m_voq_cfg_manager->is_voq_switch()) {
        txn.status = setup_sai_system_port(pentry->slice_id, pentry->ifg_id, pif, sdev, txn);
        la_return_on_error(txn.status);
    }
    return LA_STATUS_SUCCESS;
}
}
}
#endif
