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

#ifndef __RESOLUTION_UTILS_H__
#define __RESOLUTION_UTILS_H__

#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_next_hop.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_lb_types.h"
#include "api/types/la_object.h"
#include "api/types/la_system_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/npl_types.h"

namespace silicon_one
{

// Number of bits in NPL destination
enum { NUM_OF_BITS_IN_DESTINATION = 20 };

// Type of destination.
enum destination_type_e {
    DESTINATION_TYPE_UNKNOWN, ///< Unknown destination type.
    DESTINATION_TYPE_L2,      ///< L2 destination.
    DESTINATION_TYPE_L3,      ///< L3 destination.
};

class la_device_impl;

/// @brief Check if the port is an aggregate port (for example SVI/SPA)
///
/// @param[in]  l3_port                    The given L3 port.
///
/// @retval     true iff the given port is an aggregate port
bool is_aggregate_port(const la_l3_port_wcptr& port);

/// @brief Check if the Next-hop is an aggregate next-hop
///
/// @param[in]  next_hop                    The given next-hop.
///
/// @retval     true iff the given next-hop has an associated aggregate port
bool is_aggregate_nh(const la_next_hop* next_hop); // TODO remove when all classes are refactored
bool is_aggregate_nh(const la_next_hop_wcptr& next_hop);

/// @brief Retrieve the L2 destination object attached to the given L3 port/MAC address.
///
/// @param[in]  l3_port                    The given L3 port.
/// @param[in]  mac_addr                   The given MAC address.
/// @param[out] out_l2_destination         Returns the L2 destination object.
///
/// @retval    LA_STATUS_SUCCESS           Operation completed successfully.
/// @retval    LA_STATUS_EUNKNOWN          L3 port type is not known.
la_status get_l2_destination(const la_l3_port_wcptr& l3_port, la_mac_addr_t mac_addr, la_l2_destination_wcptr& out_l2_destination);

/// @brief Retrieve the ethernet port underlying the give L2 destination.
///
/// @param[in]  l2_dest                    The given L2 destination.
/// @param[out] out_ethernet_port          Returns the ethernet port.
///
/// @retval    LA_STATUS_SUCCESS           Operation completed successfully.
la_status get_underlying_ethernet_port(const la_l2_destination_wcptr& l2_dest, la_ethernet_port_wcptr& out_ethernet_port);

/// @brief Return a system port or spa GID of the given L2 destination (sp-gid and spa-gid are the same type).
///
/// @param[in]  l2_dest                    The given L2 destination.
/// @param[out] out_gid                    Returns the destination GID.
/// @param[out] out_is_aggregate           Returns if the destination is Agggregate Port
///
/// @retval    LA_STATUS_SUCCESS           Operation completed successfully.
/// @retval    LA_STATUS_EUNKNOWN          L2 destination type is not known.
la_status get_dsp_or_dspa(const la_device_impl_wptr& device,
                          const la_l2_destination_wcptr& l2_dest,
                          la_l2_destination_gid_t& out_gid,
                          bool& out_is_aggregate);

/// @brief Check whether the given LPM destination is of a L3 destination.
///
/// @param[in]  lpm_dest    The ID to query.
///
/// @retval     true iff the given LPM-ID is of a L3 destination (at NPL level, not the API)
bool is_l3_lpm_destination(lpm_destination_id lpm_dest);

/// @brief Return the type of the given destination.
///
/// @param[in]  dest_id                 The ID to query.
///
/// @retval The destination type.
destination_type_e get_destination_type(destination_id dest_id);

/// @brief Returns the destination ID of a given destination object after the specified resolution step.
///
/// @param[in]  dest_object         Destination object.
/// @param[in]  prev_step           Resolution step.
///
/// @return     ID of the destination object. In case that the destination is still unsupported returns DESTINATION_ID_INVALID.
destination_id get_destination_id(const la_object* dest_object, resolution_step_e prev_step);
destination_id get_destination_id(const la_object_wcptr& dest_object_wptr, resolution_step_e prev_step);

/// @brief Returns #la_l3_port for given destination object.
///
/// @param[in]  dest_object                  Destination object.
/// @param[out] out_l3_port                  Returns L3 Port Object.
///
/// @retval     LA_STATUS_SUCCESSS           Operation completed successfully.
/// @retval     LA_STATUS_ENOTIMPLEMENTED    Destination type not implemented.
la_status get_l3_port(const la_l3_destination* dest_object, la_l3_port*& out_l3_port);
la_status get_l3_port(const la_l3_destination_wcptr& dest_object, la_l3_port_wptr& out_l3_port);

/// @brief Returns the LPM destination ID of a given destination object after the specified resolution step.
///
/// @param[in]  dest_object         Destination object.
/// @param[in]  prev_step           Resolution step.
///
/// @return     LPM ID of the destination object. In case that the destination is still unsupported returns
/// LPM_DESTINATION_ID_INVALID.
lpm_destination_id get_lpm_destination_id(const la_object_wcptr& dest_object, resolution_step_e prev_step);

/// @brief Calls the instantiation of an object after the specified resolution step.
///
/// @param[in]  obj                 Object.
/// @param[in]  prev_step           Resolution step.
///
/// @retval    LA_STATUS_SUCCESS    Operation completed successfully
/// @retval    LA_STATUS_ERESOURCE  Table is full, unable to instantiate the objects that it relies on.
la_status instantiate_resolution_object(const la_object_wcptr& obj, resolution_step_e prev_step);

/// @brief Calls the instantiation of an object after the specified resolution step and dependent object.
///
/// @param[in]  obj                 Object.
/// @param[in]  prev_step           Resolution step.
/// @param[in]  prev_obj            The dependent object which instantiates obj.
///
/// @retval    LA_STATUS_SUCCESS    Operation completed successfully
/// @retval    LA_STATUS_ERESOURCE  Table is full, unable to instantiate the objects that it relies on.
la_status instantiate_resolution_object(const la_object_wcptr& obj, resolution_step_e prev_step, const la_object_wcptr& prev_obj);
la_status instantiate_resolution_object(const la_object_wcptr& obj, resolution_step_e prev_step, const la_object* prev_obj);

/// @brief Calls the uninstantiation of an object after the specified resolution step.
///
/// @param[in]  obj                 Object.
/// @param[in]  prev_step           Resolution step.
///
/// @retval    LA_STATUS_SUCCESS    Operation completed successfully
la_status uninstantiate_resolution_object(const la_object_wcptr& obj, resolution_step_e prev_step);

/// @brief Convert a destination ID to LPM destination ID.
///
/// @param[in]  id  Destination ID.
///
/// @retval The LPM destination ID.
lpm_destination_id l3_destination_gid_2_lpm_destination_id(la_l3_destination_gid_t id);

/// @brief Check whether the prefix of the given destination is the same as the given prefix.
///
/// @param[in]  destination                Destination.
/// @param[in]  prefix                     Prefix.
/// @param[in]  prefix_len                 Prefix length in bits.
///
/// @retval True iff the prefix of the given destination is the same as the given prefix.
bool does_destination_match_prefix(uint64_t destination, uint64_t prefix, uint64_t prefix_len);

/// @brief Return the actual system port used as DSP. PACKET-DMA-WA
///
/// Packet-DMA workaround requires the recycle-port instead of PCI port.
///
/// @param[in] dsp   System port.
///
/// @retval The RCY port corresponding to the given PCI system port.
const la_system_port_base_wcptr get_actual_dsp(const la_system_port_wcptr& dsp);

/// @brief Return the slice on which the actual system port resides.
///
/// @param[in] dsp   System port.
///
/// @retval The slice on which the actual system port resides.
la_slice_id_t get_actual_dsp_slice(const la_system_port_wcptr& dsp);

/// @brief Return the resolution stage index where the given
/// resolution step is mapped to
///
/// @param[in] res_step Resolution step
///
/// @retval The resolution stage on which the res_step is mapped
/// to.
int res_step_to_stage(resolution_step_e res_step);

/// @brief Resolve load balance for the given stage and determine the member of lb group.
///
/// @param[in]  lb_vector    	        The load balance field vector.
/// @param[in]  group_size   	        The load balance group size.
/// @param[in]  consistency  	        The load balance consistency mode.
/// @param[in]  step         	        The resolution stage.
/// @param[in]  seed         	        Load balance hash seed.
/// @param[in]  shift_amount            Six LB keys are calculated and barrel shifted according to this value. This allows for
///                                     different CRC functions.
/// @param[out] out_member_id       	The resolved member id from the load balance group.
///
/// @retval LA_STATUS_SUCCESS   LB Resolution Success.
la_status do_lb_resolution(const la_lb_pak_fields_vec& lb_vector,
                           size_t group_size,
                           npl_lb_consistency_mode_e consistency_mode,
                           resolution_step_e step,
                           uint16_t seed,
                           uint16_t shift_amount,
                           size_t& out_member_id);
} // namespace silicon_one

#endif // __RESOLUTION_UTILS_H__
