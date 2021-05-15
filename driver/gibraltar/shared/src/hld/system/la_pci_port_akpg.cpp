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

#include "system/la_pci_port_akpg.h"
#include "common/bit_utils.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_pci_port_akpg::la_pci_port_akpg(const la_device_impl_wptr& device, bool skip_kernel_driver)
    : la_pci_port_base(device, skip_kernel_driver)
{
}

la_pci_port_akpg::~la_pci_port_akpg()
{
}

la_status
la_pci_port_akpg::read_punt_counter(bool clear_on_read, la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_uint64_t& out_count)
{
    // TODO:read register for punt packets count
    return LA_STATUS_SUCCESS;
}

la_status
la_pci_port_akpg::read_inject_counter(bool clear_on_read, la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_uint64_t& out_count)
{
    // TODO:read register for inject packets count
    return LA_STATUS_SUCCESS;
}
} // namespace silicon_one
