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

#ifndef __LEABA_SRM_H__
#define __LEABA_SRM_H__

#include "apb/apb.h"

namespace silicon_one
{

class srm
{
public:
    /// @brief Set APB interface to use for SRM operations.
    ///
    /// @param[in]  apb        APB interface of type apb_interface_type_e::SERDES.
    ///
    /// @return LA_STATUS_SUCCESS   Successfully initialized SRM with APB interface.
    /// @return LA_STATUS_EEXIST    SRM has already been initialized with this APB interface.
    /// @return LA_STATUS_EUNKNOWN  Unknown error.
    static la_status set_apb(apb* apb);

    /// @brief Get APB interface of type apb_interface_type_e::SERDES for a given device.
    ///
    /// @param[in]  dev_id      ID of low-level device.
    ///
    /// @retval                 Pointer to APB object.
    static apb* get_apb(la_device_id_t device_id);

    /// @brief Clear APB interface.
    ///
    /// @param[in]  apb        APB interface of type apb_interface_type_e::SERDES.
    static void clear_apb(apb* apb);
};

} // namespace silicon_one

#endif
