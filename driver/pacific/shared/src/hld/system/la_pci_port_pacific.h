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

#ifndef __LA_PCI_PORT_PACIFIC_H__
#define __LA_PCI_PORT_PACIFIC_H__

#include "system/la_pci_port_base.h"

namespace silicon_one
{
class la_pci_port_pacific : public la_pci_port_base
{
    /////////SERIALIZATION//////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_pci_port_pacific() = default;
    ////////////////////////////////
public:
    explicit la_pci_port_pacific(const la_device_impl_wptr& device, bool skip_kernel_driver);
    ~la_pci_port_pacific() override;
    la_status initialize(la_object_id_t oid, la_slice_id_t slice, la_ifg_id_t ifg) override;

private:
    la_status read_inject_counter(bool clear_on_read, la_slice_id_t slice, la_ifg_id_t ifg_id, la_uint64_t& out_count) override;
    la_status read_punt_counter(bool clear_on_read, la_slice_id_t slice, la_ifg_id_t ifg_id, la_uint64_t& out_count) override;
};
} // namespace silicon_one

#endif // __LA_PCI_PORT_PACIFIC_H__
