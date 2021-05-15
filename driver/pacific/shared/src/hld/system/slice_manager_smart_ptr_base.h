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

#ifndef __SLICE_MANAGER_SMART_PTR_BASE_H__
#define __SLICE_MANAGER_SMART_PTR_BASE_H__

#include "api/types/la_common_types.h"
#include "hld_types_fwd.h"

#include <memory>

namespace silicon_one
{

class la_device_impl_base;
class la_device_impl;

class slice_manager_smart_ptr
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    class centralized_ptr : public std::enable_shared_from_this<centralized_ptr>
    {
    public:
        centralized_ptr() = default;
        slice_id_manager_base_sptr m_sid_mgr;
    };

public:
    slice_manager_smart_ptr(const slice_manager_smart_ptr&);
    slice_manager_smart_ptr();
    virtual ~slice_manager_smart_ptr();

    slice_id_manager_base_scptr operator->() const;
    slice_manager_smart_ptr& operator=(const slice_manager_smart_ptr&);

protected:
    bool m_initialized;
    std::shared_ptr<const centralized_ptr> m_holder;
};

class slice_manager_smart_ptr_owner : public slice_manager_smart_ptr
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    friend la_device_impl_base;
    friend la_device_impl;
    virtual ~slice_manager_smart_ptr_owner();
    slice_id_manager_base_sptr& get_mgr();

protected:
    void initialize(const slice_id_manager_base_sptr& ptr);
    slice_manager_smart_ptr_owner();
    std::shared_ptr<slice_manager_smart_ptr::centralized_ptr> m_owned_holder;
};

} // namespace silicon_one

#endif // __SLICE_MANAGER_SMART_PTR_BASE_H__
