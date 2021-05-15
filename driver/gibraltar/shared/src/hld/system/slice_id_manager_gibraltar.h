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

#ifndef __SLICE_ID_MANAGER_GIBRALTAR_H__
#define __SLICE_ID_MANAGER_GIBRALTAR_H__

#include "slice_id_manager_base.h"
namespace silicon_one
{

/// This class is responsible for managing the valid slice Ids. See slice_id_manager_base for more info.
class slice_id_manager_gibraltar : public slice_id_manager_base
{
    // FOR SERIALIZATION PURPOSES//
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    //////////////////////////////
public:
    slice_id_manager_gibraltar();
    virtual ~slice_id_manager_gibraltar();

    /// @brief sets all the lists and data of enabled slices. Based on the device properties
    /// @param[in]    dev            the device of this slice_id_manager, should be the same one used in get_instance
    void initialize(const la_device_impl_base_wptr& dev) override;

    la_slice_pair_id_t map_slice_pair(la_slice_pair_id_t id) const override;
    la_slice_pair_id_t map_back_slice_pair(la_slice_pair_id_t id) const override;

    la_slice_id_t map_slice(la_slice_id_t id) const override;
    la_slice_id_t map_back_slice(la_slice_id_t id) const override;

    la_status map_slice_ifg(la_slice_ifg& ifg) const override;
    la_status map_back_slice_ifg(la_slice_ifg& ifg) const override;

    la_status map_serdices(la_slice_serdices& map_this) const override;
    la_status map_back_serdices(la_slice_serdices& map_this) const override;

    la_status map_pif(la_slice_pif& map_this) const override;
    la_status map_back_pif(la_slice_pif& map_this) const override;

protected:
    bool m_use_mapping;
};

} // namespace silicon_one

#endif // __SLICE_ID_MANAGER_GIBRALTAR_H__
