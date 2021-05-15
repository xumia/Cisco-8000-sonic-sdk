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

#ifndef __LA_FABRIC_PORT_SCHEDULER_IMPL_H__
#define __LA_FABRIC_PORT_SCHEDULER_IMPL_H__

#include "api/tm/la_fabric_port_scheduler.h"
#include "common/bit_vector.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_fabric_port_scheduler_impl : public la_fabric_port_scheduler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum fabric_oq_pg_e {
        PLB_UC_HIGH = 7,
        PLB_UC_LOW = 6,
        PLB_MC = 0,
    };

    explicit la_fabric_port_scheduler_impl(const la_device_impl_wptr& device,
                                           la_slice_id_t slice_id,
                                           la_ifg_id_t ifg_id,
                                           la_uint_t fab_intf_id);
    ~la_fabric_port_scheduler_impl() override;
    la_status initialize(la_object_id_t oid);
    la_status destroy();

    // la_fabric_port_scheduler API-s
    la_status get_output_queue_weight(fabric_ouput_queue_e oq, la_wfq_weight_t& out_weight) const override;
    la_status set_output_queue_weight(fabric_ouput_queue_e oq, la_wfq_weight_t weight) override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

private:
    enum {
        WFQ_WEIGHT_WIDTH = 6, ///< Width of a single 'weight' field in pdoq.tpse_wfq_cfg memory line
    };

    static constexpr size_t INVALID_PG = (size_t)-1;
    size_t get_oq2pg(fabric_ouput_queue_e oq) const;

    // Device this scheduler belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Slice ID
    la_slice_id_t m_slice_id;

    // IFG ID
    la_ifg_id_t m_ifg_id;

    // Fabric interface ID (within the IFG) - a sequential number (and not base_serdes as other ports)
    la_uint_t m_fab_intf_id;

    la_fabric_port_scheduler_impl() = default; // For serialization purposes only.
};                                             // class la_fabric_port_scheduler

} // namespace silicon_one

/// @}

#endif // __LA_FABRIC_PORT_SCHEDULER_IMPL_H__
