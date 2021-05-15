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

#ifndef __LA_PCI_PORT_H__
#define __LA_PCI_PORT_H__

/// @file
/// @brief Leaba PCI Port API-s.
///
/// Defines API-s for managing and using PCI port.
///

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @addtogroup PORT
/// @{

namespace silicon_one
{

/// @brief A PCI port is defined above one specific IFG and used to send/receive packets over PCI interface.
///
class la_pci_port : public la_object
{
public:
    /// @brief Activate the PCI port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port activated successfully.
    /// @retval     LA_STATUS_EBUSY     Port is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status activate() = 0;

    /// @brief Stop host port.
    ///
    /// Change port state to inactive.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port state changed successfully.
    /// @retval     LA_STATUS_EINVAL    Port is inactive.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status stop() = 0;

    /// @brief Get active state.
    ///
    /// @retval True iff port is active.
    virtual bool is_active() const = 0;

    /// @brief Get slice used by this host port.
    ///
    /// @return #la_slice_id_t.
    virtual la_slice_id_t get_slice() const = 0;

    /// @brief Get IFG used by this host port.
    ///
    /// @return #la_ifg_id_t.
    virtual la_ifg_id_t get_ifg() const = 0;

    /// @brief Return interface scheduler for this PCI port.
    ///
    /// @return Interface scheduler object.
    virtual la_interface_scheduler* get_scheduler() const = 0;

    /// @brief Return the number of inject packets
    ///
    /// @param[in]  clear_on_read           Clear counters after read.
    /// @param[out] out_inject_count    inject packet count
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_inject_count(bool clear_on_read, la_uint64_t& out_inject_count) = 0;

    /// @brief Return the number of punt packets
    ///
    /// @param[in]  clear_on_read           Clear counters after read.
    /// @param[out] out_punt_count      punt packet count
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_punt_count(bool clear_on_read, la_uint64_t& out_punt_count) = 0;

protected:
    ~la_pci_port() override = default;
};
}

/// @}

#endif // __LA_PCI_PORT_H__
