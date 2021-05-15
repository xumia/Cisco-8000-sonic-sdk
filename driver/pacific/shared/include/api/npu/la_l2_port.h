// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_L2_PORT_H__
#define __LA_L2_PORT_H__

#include "api/npu/la_acl.h"
#include "api/npu/la_acl_group.h"
#include "api/npu/la_counter_set.h"
#include "api/npu/la_l2_destination.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_qos_types.h"

/// @file
/// @brief Leaba Layer 2 Port API-s.
///
/// Layer 2 port acts as the superclass of all Layer 2 ports.

namespace silicon_one
{
/// @addtogroup L2PORT
/// @{

/// @brief      Layer 2 port base class.
///
/// @details    A layer 2 port serves as a base class for L2 ports.\n
///             It is used for QoS and ACL setting configuration.
class la_l2_port : public la_l2_destination
{
public:
    /// @}
    /// @name QoS
    /// @{

    /// @brief Set port's ingress QoS profile.
    ///
    /// @param[in]  ingress_qos_profile     Ingress QoS profile to set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Ingress QoS profile is nullptr.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile) = 0;

    /// @brief Get port's ingress QoS profile.
    ///
    /// @param[out] out_ingress_qos_profile     Ingress QoS profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         No ingress QoS profile is set.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const = 0;

    /// @brief Set port's egress QoS profile.
    ///
    /// @param[in]  egress_qos_profile      Egress QoS profile to set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Egress QoS profile is nullptr.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile) = 0;

    /// @brief Get port's egress QoS profile.
    ///
    /// @param[out] out_egress_qos_profile  Egress QoS profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     No egress QoS profile is set.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const = 0;

    /// @}
    /// @name ACL
    /// @{

    /// @brief Set ACL group for the port.
    ///
    /// @param[in]  dir                 Direction (ingress or egress)
    /// @param[in]  acl_group           ACL group to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACLs set successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid ACLs.
    /// @retval     LA_STATUS_ERESOURCE No resources to attach the ACL.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group) = 0;

    /// @brief Get the ACL group for the port.
    ///
    /// @param[in]  dir                 Direction (ingress or egress)
    ///
    /// @param[out] out_acl_group       ACL group.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const = 0;

    /// @brief Clear ACL group for the port.
    ///
    /// @param[in]  dir                 Direction (ingress or egress)
    ///
    /// @retval     LA_STATUS_SUCCESS   ACLs set successfully.
    /// @retval     LA_STATUS_ENOTFOUND No ACL is currently set.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_acl_group(la_acl_direction_e dir) = 0;

    /// @}
    /// @name Metering
    /// @{

    /// @brief Attach a meter to the port.
    ///
    /// Attaches a meter to the port. The #silicon_one::la_ingress_qos_profile attached to this port or an ACL rule is needed to
    /// determine the meter offset; it is the user's responsibility to ensure the #silicon_one::la_ingress_qos_profile's
    /// offsets and ACL rule's offsets are in range for the meter. Passing a nullptr meter removes an existing meter if there's
    /// one, and has no effect if there's none.
    ///
    /// A #silicon_one::la_meter_set::type_e::EXACT meter can be a attached only to a single #silicon_one::la_l2_port of type
    /// #silicon_one::la_l2_service_port::port_type_e::AC that accepts ingress traffic from a single #silicon_one::la_system_port.
    /// The
    /// aforementioned L2-AC port can be attached only with a #silicon_one::la_meter_set::type_e::EXACT or a
    /// #silicon_one::la_meter_set::type_e::STATISTICAL meter types.
    ///
    /// @param[in]  meter               Meter object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    The meter type is invalid for this port.
    /// @retval     LA_STATUS_EBUSY     An exact meter is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  Internal error.
    virtual la_status set_meter(const la_meter_set* meter) = 0;

    /// @brief Get the attached meter to the port.
    ///
    /// @param[out] out_meter           Meter to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  Internal error.
    virtual la_status get_meter(const la_meter_set*& out_meter) const = 0;

    /// @brief Set ingress mirror command.
    ///
    /// @param[in]  mirror_cmd                  Mirror command. If nullptr, mirroring will be disabled on this port.
    /// @param[in]  is_acl_conditioned          Indicating whether mirror command is always active,
    ///                                         or only when a relevant ACL command is matching the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    /// @retval     LA_STATUS_ENOTINITIALIZED   Table object was not initialized.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS   output queue scheduler is on a different device.
    virtual la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) = 0;

    /// @brief Get ingress mirror command.
    ///
    /// @param[out]  out_mirror_cmd             Mirror command.
    /// @param[out]  out_is_acl_conditioned     Indicating whether mirror command is always active,
    ///                                         or only when a relevant ACL command is matching the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    virtual la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const = 0;

    /// @brief Set egress mirror command.
    ///
    /// @param[in]  mirror_cmd                  Mirror command. If nullptr, mirroring will be disabled on this port.
    /// @param[in]  is_acl_conditioned          Indicating whether mirror command is always active,
    ///                                         or only when a relevant ACL command is matching the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    /// @retval     LA_STATUS_ENOTINITIALIZED   Table object was not initialized.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS   output queue scheduler is on a different device.
    virtual la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) = 0;

    /// @brief Get egress mirror command.
    ///
    /// @param[out]  out_mirror_cmd             Mirror command.
    /// @param[out]  out_is_acl_conditioned     Indicating whether mirror command is always active,
    ///                                         or only when a relevant ACL command is matching the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    virtual la_status get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const = 0;

    /// @}
    /// @name Port and QoS Counters
    /// @{

    /// @brief Set port's QoS/Port ingress counter.
    ///
    /// For port counters, supported set sizes are 1 (aggregate all traffic in a single counter), or 8 (count traffic per PCP
    /// value).\n
    /// For QoS counters, supported set sizes are 1-32. An ACL rule is needed to determine counter offset; it is the user's
    /// responsibility to ensure the ACL rule's offsets are in-range for the counter set.
    /// Passing NULL counter removes an existing counter if there's one, and has no effect if there's none.
    /// If there's a counter already associated with this port then it is replaced by this function.
    ///
    /// @param[in]  counter             Counter object.
    /// @param[in]  type                Counter type.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Counter type is other than QOS or PORT.
    /// @retval     LA_STATUS_EINVAL    Invalid set size.
    /// @retval     LA_STATUS_EEXIST    A counter of this type is already associated with this port/direction.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter) = 0;

    /// @brief Get port's QoS/Port ingress counter.
    ///
    /// @param[in]  type                Counter type.
    /// @param[out] out_counter         Counter object to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_counter countains the QoS/Port ingress counter.
    /// @retval     LA_STATUS_EINVAL    Counter type is other than QOS or PORT.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const = 0;

    /// @brief Set port's QoS/Port egress counter.
    ///
    /// For port counters, supported set sizes are 1 (aggregate all traffic in a single counter), or 8 (count traffic per PCP
    /// value).\n
    /// For QoS counters, supported set sizes are 1-8. An ACL rule is needed to determine counter offset; it is the user's
    /// responsibility to ensure the ACL rule's offsets are in-range for the counter set.
    /// Passing NULL counter removes an existing counter if there's one, and has no effect if there's none.
    /// If there's a counter already associated with this port then it is replaced by this function.
    ///
    /// @param[in]  counter             Counter object.
    /// @param[in]  type                Counter type.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Counter type is other than QOS or PORT.
    /// @retval     LA_STATUS_EINVAL    Invalid set size.
    /// @retval     LA_STATUS_EEXIST    A counter of this type is already associated with this port/direction.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_egress_counter(la_counter_set::type_e type, la_counter_set* counter) = 0;

    /// @brief Get port's QoS/Port egress counter.
    ///
    /// @param[in]  type                Counter type.
    /// @param[out] out_counter         Counter object to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_counter countains the QoS/Port egress counter.
    /// @retval     LA_STATUS_EUNKNOWN  Counter type is other than QOS or PORT.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const = 0;

    /// @}

protected:
    ~la_l2_port() override = default;
};
}

/// @}

#endif // __LA_L2_PORT_H__
