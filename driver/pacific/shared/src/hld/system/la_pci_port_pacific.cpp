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

#include "system/la_pci_port_pacific.h"
#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "system/la_device_impl.h"
#include "system/la_recycle_port_base.h"

namespace silicon_one
{

la_pci_port_pacific::la_pci_port_pacific(const la_device_impl_wptr& device, bool skip_kernel_driver)
    : la_pci_port_base(device, skip_kernel_driver)
{
}

la_pci_port_pacific::~la_pci_port_pacific()
{
}

static la_recycle_port_base_wcptr
get_rcy_port_on_slice(const la_device_impl_wptr& device, la_slice_id_t slice)
{
    auto rcy_ports = device->get_objects(la_object::object_type_e::RECYCLE_PORT);
    for (const auto& rp : rcy_ports) {
        auto rpb = device->get_sptr<const la_recycle_port_base>(rp);
        auto rp_slice = rpb->get_slice();
        if (rp_slice == slice) {
            return rpb;
        }
    }

    return nullptr;
}

la_status
la_pci_port_pacific::initialize(la_object_id_t oid, la_slice_id_t slice, la_ifg_id_t ifg)
{
    if (ifg != 0) {
        // PACKET-DMA-WA
        log_err(HLD, "la_pci_port_base::%s: Cannot create PCI port on IFG other than 0.", __func__);

        return LA_STATUS_EINVAL;
    }

    bool pacific_B0_changes_en;
    auto status = m_device->get_bool_property(la_device_property_e::ENABLE_PACIFIC_B0_IFG_CHANGES, pacific_B0_changes_en);
    return_on_error(status);

    // don't return error to allow sdk unit-testing to run on pacific A0
    bool allow_rcy_on_all_slices;
    status
        = m_device->get_bool_property(la_device_property_e::TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES, allow_rcy_on_all_slices);
    return_on_error(status);

    if ((m_device->m_pacific_tree->get_revision() == la_device_revision_e::PACIFIC_A0 || pacific_B0_changes_en == false)
        && (slice & 1) == 1) {
        auto rcy_port_on_slice = get_rcy_port_on_slice(m_device, slice);
        if (rcy_port_on_slice != nullptr) {
            log_err(HLD,
                    "%s: RCY port %s already exist in this slice. PCI port cannot be created on same slice as RCY port.",
                    __func__,
                    rcy_port_on_slice->to_string().c_str());

            if (!allow_rcy_on_all_slices) {
                return LA_STATUS_EINVAL;
            }
        }
    }

    return la_pci_port_base::initialize(oid, slice, ifg);
}

la_status
la_pci_port_pacific::read_punt_counter(bool clear_on_read, la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_uint64_t& out_count)
{
    la_status status;
    ifgb_inbe_pkt_cnt_reg_register ifgb_inbe_pkt_cnt_reg;
    auto& lld = m_device->m_ll_device;

    if (clear_on_read) {
        status = lld->read_register(m_device->m_pacific_tree->slice[slice_id]->ifg[ifg_id]->ifgb->inbe_pkt_cnt_reg,
                                    ifgb_inbe_pkt_cnt_reg);
    } else {
        status = lld->peek_register(m_device->m_pacific_tree->slice[slice_id]->ifg[ifg_id]->ifgb->inbe_pkt_cnt_reg,
                                    ifgb_inbe_pkt_cnt_reg);
    }
    return_on_error(status);

    out_count = ifgb_inbe_pkt_cnt_reg.fields.inbe_pkt_count;

    return LA_STATUS_SUCCESS;
}

la_status
la_pci_port_pacific::read_inject_counter(bool clear_on_read, la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_uint64_t& out_count)
{
    la_status status;
    ifgb_inbi_pkt_cnt_register ifgb_inbi_pkt_cnt_reg;
    auto& lld = m_device->m_ll_device;

    if (clear_on_read) {
        status
            = lld->read_register(m_device->m_pacific_tree->slice[slice_id]->ifg[ifg_id]->ifgb->inbi_pkt_cnt, ifgb_inbi_pkt_cnt_reg);
    } else {
        status
            = lld->peek_register(m_device->m_pacific_tree->slice[slice_id]->ifg[ifg_id]->ifgb->inbi_pkt_cnt, ifgb_inbi_pkt_cnt_reg);
    }
    return_on_error(status);

    out_count = ifgb_inbi_pkt_cnt_reg.fields.inbi_pkt_count;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
