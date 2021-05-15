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

#ifndef __LA_SECURITY_GROUP_CELL_GIBRALTAR_H__
#define __LA_SECURITY_GROUP_CELL_GIBRALTAR_H__

#include "la_security_group_cell_base.h"

namespace silicon_one
{

class la_security_group_cell_gibraltar : public la_security_group_cell_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_security_group_cell_gibraltar(const la_device_impl_wptr& device);
    ~la_security_group_cell_gibraltar() override;

    la_status initialize(la_object_id_t oid,
                         la_sgt_t sgt,
                         la_dgt_t dgt,
                         la_ip_version_e ip_version,
                         const la_counter_set_wptr& counter) override;
    la_status destroy() override;

    la_status set_counter(la_counter_set* counter) override;
    la_status get_counter(la_counter_set*& out_counter) const override;
    la_status set_monitor_mode(bool allow_drop) override;
    la_status get_monitor_mode(bool& out_allow_drop) const override;
    la_status set_acl(la_acl* sgacl) override;
    la_status clear_acl() override;
    la_status get_acl(la_acl*& out_sgacl) const override;
    la_status set_bincode(la_uint32_t bincode) override;
    la_status get_bincode(la_uint32_t& out_bincode) const override;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    // Helper functions
    la_status remove_counter();
    la_status do_set_counter(la_counter_set* counter);
    la_status configure_cell_counter_attribute_tables(la_counter_set* counter);
    la_status update_attributes();

protected:
    la_security_group_cell_gibraltar() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_SECURITY_GROUP_CELL_GIBRALTAR_H__
