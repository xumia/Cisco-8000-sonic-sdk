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

#include "system/slice_manager_smart_ptr_base.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "system/la_device_impl.h"
#include "system/la_device_impl_base.h"
#include "system/slice_id_manager_base.h"

namespace silicon_one
{

slice_manager_smart_ptr::slice_manager_smart_ptr(const slice_manager_smart_ptr& parent) : m_initialized(true), m_holder(nullptr)
{
    m_initialized = true;
    dassert_crit(parent.m_holder != nullptr, "slice_manager_smart_ptr::copy_cnstruct, no holder found");
    m_holder = parent.m_holder;
}
slice_manager_smart_ptr::slice_manager_smart_ptr() : m_initialized(false), m_holder(nullptr)
{
}
slice_manager_smart_ptr::~slice_manager_smart_ptr()
{
}

slice_id_manager_base_scptr slice_manager_smart_ptr::operator->() const
{
    dassert_crit(m_initialized, "slice_manager_smart_ptr instance has not not initialized");
    dassert_crit(m_holder != nullptr, "m_holder == nullptr");
    dassert_crit(m_holder->m_sid_mgr != nullptr, "m_parent->m_sid_mgr == nullptr, probably has been destroyed");

    return m_holder->m_sid_mgr;
}
slice_manager_smart_ptr&
slice_manager_smart_ptr::operator=(const slice_manager_smart_ptr& rhs)
{
    m_initialized = true;
    dassert_crit(rhs.m_holder != nullptr, "slice_manager_smart_ptr::operator= , no holder found");
    m_holder = rhs.m_holder;
    return *this;
}

// -----------protected-----------
slice_manager_smart_ptr_owner::slice_manager_smart_ptr_owner() : slice_manager_smart_ptr()
{
    m_owned_holder = std::make_shared<slice_manager_smart_ptr::centralized_ptr>();
    m_holder = m_owned_holder;
}
void
slice_manager_smart_ptr_owner::initialize(const slice_id_manager_base_sptr& mgr)
{
    m_initialized = true;
    m_owned_holder->m_sid_mgr = mgr;
}

slice_manager_smart_ptr_owner::~slice_manager_smart_ptr_owner()
{
    slice_id_manager_base_sptr ptr;
    m_owned_holder->m_sid_mgr.swap(ptr);
    // now ptr is going out of scope, and the slice_id_manager_base and the ptr should be destroyed
}
slice_id_manager_base_sptr&
slice_manager_smart_ptr_owner::get_mgr()
{
    return m_owned_holder->m_sid_mgr;
}

} // namespace silicon_one
