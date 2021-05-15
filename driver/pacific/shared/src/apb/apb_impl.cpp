// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "apb_impl.h"
#include "apb_impl_gibraltar.h"
#include "common/gen_utils.h"
#include "common/logger.h"

#include <chrono>
#include <thread>

using namespace std;

namespace silicon_one
{

apb*
apb::create(ll_device_sptr ldev, apb_interface_type_e type)
{
    if (!ldev) {
        return nullptr;
    }

    if (!ldev->is_gibraltar()) {
        log_err(APB, "%s: APB is not supported for dev_id=%d", __func__, ldev->get_device_id());
        return nullptr;
    }

    apb* obj;
    if (ldev->is_simulated_device()) {
        obj = new apb_impl_simulated(ldev, type);
    } else if (ldev->is_gibraltar()) {
        obj = apb_impl::create_gibraltar(ldev, type);
    } else {
        obj = nullptr;
    }

    return obj;
}

apb*
apb_impl::create_gibraltar(ll_device_sptr ldev, apb_interface_type_e type)
{
    apb* obj;

    if (type == apb_interface_type_e::PCIE) {
        obj = new apb_impl_pcie_gibraltar(ldev);
    } else if (type == apb_interface_type_e::SERDES) {
        obj = new apb_impl_serdes_gibraltar(ldev);
    } else if (type == apb_interface_type_e::HBM) {
        obj = new apb_impl_hbm_gibraltar(ldev);
    } else {
        obj = nullptr;
    }

    return obj;
}

apb*
apb_impl::create_asic3(ll_device_sptr ldev, apb_interface_type_e type)
{
    return nullptr;
}

apb*
apb_impl::create_asic4(ll_device_sptr ldev, apb_interface_type_e type)
{
    return nullptr;
}

la_status
apb::encode_apb_select(ll_device_sptr ll_device, uint slice, uint ifg, uint serdes_package, uint32_t& apb_select)
{
    return LA_STATUS_EINVAL;
}

apb_impl::apb_impl(ll_device_sptr ldev, apb_interface_type_e interface_type) : m_ll_device(ldev), m_interface_type(interface_type)
{
}

apb_impl::apb_impl() : m_interface_type()
{
}

apb_impl_simulated::apb_impl_simulated(ll_device_sptr ldev, apb_interface_type_e type) : apb_impl(ldev, type)
{
}

la_device_id_t
apb_impl::get_device_id() const
{
    return m_ll_device->get_device_id();
}

std::recursive_mutex&
apb_impl::get_lock() const
{
    return m_mutex;
}

apb_interface_type_e
apb_impl::get_interface_type() const
{
    return m_interface_type;
}

/// @brief Simulator PCIe/MAC port/HBM SerDes implementations
la_status
apb_impl_simulated::configure(uint32_t clk_div)
{
    return LA_STATUS_SUCCESS;
}

la_status
apb_impl_simulated::write(uint32_t apb_select, uint32_t addr, const bit_vector& in_bv)
{
    start_apb_call("%s: apb_select=0x%x, addr=0x%x, in_bv=0x%s", __func__, apb_select, addr, in_bv.to_string().c_str());

    return LA_STATUS_SUCCESS;
}

la_status
apb_impl_simulated::read(uint32_t apb_select, uint32_t addr, bit_vector& out_bv)
{
    start_apb_call("%s: apb_select=0x%x, addr=0x%x", __func__, apb_select, addr);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
