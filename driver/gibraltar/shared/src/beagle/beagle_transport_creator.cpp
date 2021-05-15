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

#include "beagle/beagle_transport_creator.h"

namespace silicon_one
{

std::shared_ptr<beagle::beagle_transport>
beagle_transport_creator::create(ll_device_sptr ldev, apb* apb, uint32_t apb_select)
{
    if (!apb) {
        return nullptr;
    }

    if (!ldev->is_asic3() && !ldev->is_asic7()) {
        return nullptr;
    }

    // TODO- make a factory for all devices

    return std::make_shared<beagle_transport_asic3>(apb, apb_select, ldev->is_simulated_device(), ldev->get_device_id());
}
};
