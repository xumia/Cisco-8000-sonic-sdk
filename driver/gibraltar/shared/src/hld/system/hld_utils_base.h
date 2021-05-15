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

#ifndef __HLD_UTILS_BASE_H__
#define __HLD_UTILS_BASE_H__

#include <bitset>
#include <climits>
#include <cxxabi.h>
#include <typeinfo>
#include <vector>

#include "common/common_strings.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "la_strings.h"

#include "api/cgm/la_voq_cgm_profile.h"
#include "api/npu/la_acl.h"
#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l3_destination.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_protection_monitor.h"
#include "api/qos/la_meter_markdown_profile.h"
#include "api/qos/la_meter_profile.h"
#include "api/system/la_device.h"
#include "api/system/la_mac_port.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_qos_types.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_enums.h"

namespace silicon_one
{

class la_object;

/// @brief Apply a mask with the given length to an IPv6 address.
void apply_prefix_mask(la_ipv6_addr_t& addr, size_t prefix_length);

/// @brief Return the ACL delegate object used by the given ACL.
const la_acl_delegate_wptr get_delegate(const la_acl_wptr& acl);

/// @brief Vector of IFG details structure.
using slice_ifg_vec_t = std::vector<la_slice_ifg>;
/// @brief Get all IFGs where an object is configured.
slice_ifg_vec_t get_ifgs_base(const la_object_wcptr& obj);

/// @brief Populate Tx to Rx recycle data
bool is_recycle_ac(const la_l3_ac_port_impl_wcptr& ac_port);
bool is_recycle_ac(const la_l2_service_port_base_wcptr& ac_port);

/// @brief Convert Ethernet Type to protocol type.
///
/// @param[in]  ethtype         Ethernet type to translate.
///
/// @return #npl_protocol_type_e representing Ethernet type.
npl_protocol_type_e ethtype_to_npl_protocol_type(uint16_t ethtype);

/// @brief Convert NPL protocol type to ether-type.
///
/// @param[in]  protocol_type         NPL protocol type.
///
/// @return ether-type.
uint16_t npl_protocol_type_to_ethtype(npl_protocol_type_e protocol_type);

/// @brief Convert L4 protocol to compressed NPL L4 protocol type.
///
/// @param[in]  l4proto         L4 protocol type to translate.
///
/// @return #npl_protocol_type_e representing Ethernet type.
npl_lpts_l4_protocol_compress_e l4_protocol_to_npl_protocol_type(la_l4_protocol_e l4proto);

/// @brief Convert Protection Monitor state to NPL Protection selector type.
///
/// @param[in]  monitor_state         Protection Monitor state to translate.
///
/// @return #npl_resolution_protection_selector_e representing Protection selector type.
npl_resolution_protection_selector_e monitor_state_to_npl_protection_selector(la_protection_monitor::monitor_state_e state);

npl_lb_profile_enum_e la_2_npl_lb_profile(la_l3_port::lb_profile_e la_lb_profile);

la_l3_port::lb_profile_e npl_2_la_lb_profile(npl_lb_profile_enum_e npl_lb_profile);

/// @brief Convert IP protocol to protocol type.
///
/// @param[in]  ipproto         IP protocol type to translate.
///
/// @return #npl_protocol_type_e representing Ethernet type.
npl_protocol_type_e ip_protocol_to_npl_protocol_type(uint8_t ipproto);

/// @brief Validate quantization thresholds against specified limits.
///
/// @param[in]  device                  pointer to la_device_impl.
/// @param[in]  thresholds              vector of thresholds.
/// @param[in]  num_thresholds_limit    number of configurable thresholds Limit.
/// @param[in]  max_threshold_limit     max threshold value limit.
///
/// @return status  LA_STATUS_SUCCESS       comare succeeded.
///                 LA_STATUS_EOUTOFRANGE   compare failed.
///                 LA_STATUS_EINVAL        thresholds is not sorted.
la_status validate_quantization_thresholds(const la_device_impl_wcptr& device,
                                           const std::vector<la_uint_t>& thresholds,
                                           limit_type_e num_thresholds_limit,
                                           limit_type_e max_threshold_limit);

/// @brief Convert VOQ age time-units in nanoseconds to device time-units in microseconds.
///
/// Useable time unit values are 1000 [nanosecond] and 2000 [nanosecond].
///
/// @param[in]  sms_voqs_age_time_units         VOQ-in-SMS age time units in nanoseconds.
///
/// @return Device time-units in microseconds.
la_uint_t user_age_time_units_to_device_units(la_cgm_sms_voqs_age_time_units_t sms_voqs_age_time_units);

/// @brief Convert device enqueue time-units code to user age time units in nanoseconds.
///
/// In Gibraltar, device EnqTimeUnits is 1 bit code. 0 - 1us, 1 - 2us.
///
/// @param[in]  device_enq_time_units         Device time-units code.
//
/// @return VOQ-in-SMS age time units in nanoseconds.
la_cgm_sms_voqs_age_time_units_t device_enq_time_units_to_user_units(la_uint_t device_enq_time_units);

/// @brief add all the ifgs (currentlo IFG=0 and IFG=1) of the given slice to the vector
void add_all_slice_ifgs_to_vect(la_slice_id_t slice, slice_ifg_vec_t& vect);

/// returnes a the name of this type, as a string
std::string get_value_type(unsigned long long value);
std::string get_value_type(unsigned long int value);
std::string get_value_type(unsigned int value);
std::string get_value_type(unsigned char value);
std::string get_value_type(char const* value);
std::string get_value_type(unsigned short value);
std::string get_value_type(bool value);
std::string get_value_type(float value);
std::string get_value_type(double value);
std::string get_value_type(int value);
std::string get_value_type(std::string value);

/// @brief Get a vector that contains all slices matching the given mode.
///
/// @param[in]  device         Device of the requested slices.
/// @param[in]  slice_mode     Filter only slices from this slice_mode.
///
/// @return Vector contains all slices in the given mode.
la_slice_id_vec_t get_slices(const la_device_impl_wcptr& device, la_slice_mode_e slice_mode);

/// @brief Get a vector that contains all slices matching the given modes.
///
/// @param[in]  device         Device of the requested slices.
/// @param[in]  slice_modes    Filter only slices from these slice_mode-s.
///
/// @return Vector contains all slices in the given modes.
la_slice_id_vec_t get_slices(const la_device_impl_wcptr& device, const vector_alloc<la_slice_mode_e>& slice_modes);

/// @brief Get a vector that contains all slice pairs matching the given mode.
///
/// @param[in]  device         Device of the requested slices.
/// @param[in]  slice_mode     Filter only slice-pairs from this slice_mode.
///
/// @return Vector contains all slice pairs in the given mode.
la_slice_pair_id_vec_t get_slice_pairs(const la_device_impl_wcptr& device, la_slice_mode_e slice_mode);

/// @brief Get a vector that contains all network IFGs.
slice_ifg_vec_t get_all_network_ifgs(const la_device_impl_wcptr& device);

// Get a list of slices out of a list of IFGs
std::vector<la_slice_id_t> get_slices_from_ifgs(slice_ifg_vec_t ifgs);

/// @brief Verify an ethertype value and mask is representable in npl
la_status validate_ethtype_key_mask(uint16_t key, uint16_t mask);

/// @brief Verify a L4 protocol mask is representable in npl
la_status validate_l4_protocol_mask(uint16_t mask);

/// @brief Check if slice mode is a network slice mode.
///
/// @param[in]  mode                  Slice mode.
///
/// @return true if network slice (la_slice_mode_e::NETWORK or la_slice_mode_e::UDC), false otherwise.
bool is_network_slice(la_slice_mode_e mode);

/// @brief Return the recycle port associated with the given slice.
const la_system_port_base_wcptr get_rcy_system_port_for_pci_sys_port(const la_device_impl_wcptr& la_dev_impl,
                                                                     la_slice_id_t port_slice);

std::string find_resource_file(const char* file_env, const char* default_file);

/// @brief Get the minimum TCAM entries covering range [min, max].
///
/// @param[in]      min_value       Low edge.
/// @param[in]      max_value       High edge.
///
/// @return         Vector of pairs <key,mask> covering all range.
std::vector<std::pair<uint64_t, uint64_t> > tcam_expand_range(uint64_t min_value, uint64_t max_value, size_t key_width);

/// @brief Compare two MAC addresses until a prefix.
///
/// @param[in]      addr1             MAC address 1.
/// @param[in]      addr2             MAC address 2.
/// @param[in]      bytes_from_msb    Number of bytes from msb to compare.
///
/// @return         True if MAC addresses are equal up to bytes_from_msb. False if not.
bool is_equal_mac_addr_prefix(la_mac_addr_t addr1, la_mac_addr_t addr2, size_t bytes_from_msb);

/// @brief Ensure param is less than or equal to the specified limit.
///
/// @param[in]  device      pointer to la_device_impl.
/// @param[in]  param       parameter value to test.
/// @param[in]  limit_type  Limit type to compare with.
///
/// @return status  LA_STATUS_SUCCESS       comare succeeded.
///                 LA_STATUS_EOUTOFRANGE   compare failed.
la_status ensure_limit_le(const la_device_impl_wcptr& device, la_uint64_t param, limit_type_e limit_type);

/// @brief Ensure param is equal to the specified limit.
///
/// @param[in]  device      pointer to la_device_impl.
/// @param[in]  param       parameter value to test.
/// @param[in]  limit_type  Limit type to compare with.
///
/// @return status  LA_STATUS_SUCCESS       comare succeeded.
///                 LA_STATUS_EOUTOFRANGE   compare failed.
la_status ensure_limit_eq(const la_device_impl_wcptr& device, la_uint64_t param, limit_type_e limit_type);

///////////////////////////////////////////////////////////////////////
/// Short and trivial functions that can be inlined.
///////////////////////////////////////////////////////////////////////

// Return true iff both objects belong to same device
static inline bool
of_same_device(const la_object* a, const la_object* b)
{
    return (a->get_device() == b->get_device());
}

inline bool
of_same_device(const la_object* a, const la_object_wcptr& b)
{
    return of_same_device(a, b.get());
}

inline bool
of_same_device(const la_object_wcptr& a, const la_object* b)
{
    return of_same_device(a.get(), b);
}

inline bool
of_same_device(const la_object_wcptr& a, const la_object_wcptr& b)
{
    return of_same_device(a.get(), b.get());
}

// Return true iff the given IFG is valid
static inline bool
is_valid_ifg(la_ifg_id_t ifg)
{
    return (ifg <= NUM_IFGS_PER_DEVICE);
}

// Return true iff the given VLAN tags are equal
static inline bool
is_vlan_tag_eq(const la_vlan_tag_t& a, const la_vlan_tag_t& b)
{
    return ((a.tpid == b.tpid) && (a.tci.raw == b.tci.raw));
}

// Apply prefix mask to the given IP address
static inline void
apply_prefix_mask(la_ipv4_addr_t& addr, size_t prefix_length)
{
    uint32_t mask = ~((1llu << (CHAR_BIT * sizeof(uint32_t) - prefix_length)) - 1);
    addr.s_addr &= mask;
}

// NPL/LA value conversion
static inline npl_rpf_mode_e
la_2_npl_urpf_mode(la_l3_port::urpf_mode_e la_mode)
{
    switch (la_mode) {
    case la_l3_port::urpf_mode_e::LOOSE:
        return NPL_RPF_MODE_LOOSE;
    case la_l3_port::urpf_mode_e::STRICT:
        return NPL_RPF_MODE_STRICT;
    default:
        return NPL_RPF_MODE_NONE;
    }
}

static inline la_l3_port::urpf_mode_e
npl_2_la_urpf_mode(npl_rpf_mode_e npl_mode)
{
    switch (npl_mode) {
    case NPL_RPF_MODE_LOOSE:
        return la_l3_port::urpf_mode_e::LOOSE;
    case NPL_RPF_MODE_STRICT:
        return la_l3_port::urpf_mode_e::STRICT;
    default:
        return la_l3_port::urpf_mode_e::NONE;
    }
}

static inline npl_ttl_mode_e
la_2_npl_ttl_inheritance_mode(la_ttl_inheritance_mode_e la_mode)
{
    if (la_mode == la_ttl_inheritance_mode_e::UNIFORM) {
        return NPL_TTL_MODE_UNIFORM;
    }

    return NPL_TTL_MODE_PIPE;
}

static inline npl_ttl_mode_e
la_2_npl_mpls_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e la_mode)
{
    if (la_mode == la_mpls_ttl_inheritance_mode_e::UNIFORM) {
        return NPL_TTL_MODE_UNIFORM;
    }

    return NPL_TTL_MODE_PIPE;
}

static inline npl_qos_type_e
la_2_npl_mpls_qos_inheritance_mode(la_mpls_qos_inheritance_mode_e la_mode)
{
    if (la_mode == la_mpls_qos_inheritance_mode_e::UNIFORM) {
        return NPL_QOS_TYPE_UNIFORM;
    }

    return NPL_QOS_TYPE_PIPE;
}

static inline la_mpls_ttl_inheritance_mode_e
npl_2_la_mpls_ttl_inheritance_mode(npl_ttl_mode_e npl_mode)
{
    if (npl_mode == NPL_TTL_MODE_UNIFORM) {
        return la_mpls_ttl_inheritance_mode_e::UNIFORM;
    }

    return la_mpls_ttl_inheritance_mode_e::PIPE;
}

static inline la_mpls_qos_inheritance_mode_e
npl_2_la_mpls_qos_inheritance_mode(npl_qos_type_e npl_mode)
{
    if (npl_mode == NPL_QOS_TYPE_UNIFORM) {
        return la_mpls_qos_inheritance_mode_e::UNIFORM;
    }

    return la_mpls_qos_inheritance_mode_e::PIPE;
}

static inline npl_nh_type_e
la_2_npl_nh_type(la_next_hop::nh_type_e nh_type)
{
    switch (nh_type) {
    case la_next_hop::nh_type_e::GLEAN:
        return npl_nh_type_e::NPL_NH_TYPE_GLEAN;
    case la_next_hop::nh_type_e::DROP:
        return npl_nh_type_e::NPL_NH_TYPE_DROP;
    case la_next_hop::nh_type_e::NULL_:
        return npl_nh_type_e::NPL_NH_TYPE_NULL;
    case la_next_hop::nh_type_e::USER_TRAP1:
        return npl_nh_type_e::NPL_NH_TYPE_USER_TRAP1;
    case la_next_hop::nh_type_e::USER_TRAP2:
        return npl_nh_type_e::NPL_NH_TYPE_USER_TRAP2;
    default:
        dassert_crit(!"Unknown NH type");
        return static_cast<npl_nh_type_e>(0);
    }
}

static inline la_next_hop::nh_type_e
npl_2_la_nh_type(npl_trapped_nh_types_e nh_type)
{
    switch (nh_type) {
    case NPL_TRAP_NH_IS_GLEAN:
        return la_next_hop::nh_type_e::GLEAN;
    case NPL_TRAP_NH_IS_NULL:
        return la_next_hop::nh_type_e::NULL_;
    case NPL_TRAP_NH_IS_DROP:
        return la_next_hop::nh_type_e::DROP;
    case NPL_TRAP_NH_IS_USER_TRAP1:
        return la_next_hop::nh_type_e::USER_TRAP1;
    case NPL_TRAP_NH_IS_USER_TRAP2:
        return la_next_hop::nh_type_e::USER_TRAP2;
    default:
        return la_next_hop::nh_type_e::NORMAL;
    }
}

static inline bool
is_destination_unicast(const la_l2_destination_wptr& l2_dest)
{
    return l2_dest->type() != la_object::object_type_e::L2_MULTICAST_GROUP;
}

static inline bool
is_destination_unicast(const la_l3_destination_wptr& l3_dest)
{
    return l3_dest->type() != la_object::object_type_e::IP_MULTICAST_GROUP;
}

/// @brief Return the packed value of MPLS Traffic-Class and Bottom-of-Stack fields.
static inline la_uint8_t
get_packed_mpls_tc_bos_bit(la_mpls_tc mpls_tc, bool is_bos)
{
    return ((mpls_tc.value << 1) + (is_bos ? 1 : 0));
}

/// @brief Return the MPLS Traffic-Class and Bottom-of-Stack fields from the packed value.
static inline la_uint8_t
get_mpls_tc_from_packed_value(la_uint8_t packed_value)
{
    return packed_value >> 1;
}

static inline npl_qos_remark_mapping_key_type_e
la_2_npl_qos_remark_profile_type(la_egress_qos_marking_source_e egress_qos_marking_source)
{
    switch (egress_qos_marking_source) {
    case la_egress_qos_marking_source_e::QOS_GROUP:
        return NPL_QOS_REMARK_USE_QOS_GROUP;
    case la_egress_qos_marking_source_e::QOS_TAG:
        return NPL_QOS_REMARK_USE_QOS_TAG;
    }

    // Shouldn't reach here
    return NPL_QOS_REMARK_USE_QOS_TAG;
}

static inline la_egress_qos_marking_source_e
npl_2_la_qos_remark_profile_type(npl_qos_remark_mapping_key_type_e egress_qos_marking_source)
{
    switch (egress_qos_marking_source) {
    case NPL_QOS_REMARK_USE_QOS_GROUP:
        return la_egress_qos_marking_source_e::QOS_GROUP;
    case NPL_QOS_REMARK_USE_QOS_TAG:
        return la_egress_qos_marking_source_e::QOS_TAG;
    }

    // Shouldn't reach here
    return la_egress_qos_marking_source_e::QOS_TAG;
}

static inline size_t
la_2_pbh_dp(la_qos_color_e color)
{
    return (size_t)color;
}

static inline size_t
la_2_meter_color(la_qos_color_e color)
{
    return (size_t)color;
}

static inline size_t
la_2_meter_measure_mode(la_meter_profile::meter_measure_mode_e meter_measure_mode)
{
    return (size_t)meter_measure_mode;
}

static inline size_t
la_2_meter_color_aware_mode(la_meter_profile::color_awareness_mode_e meter_color_awareness_mode)
{
    return (size_t)meter_color_awareness_mode;
}

static inline size_t
la_2_meter_coupling_mode(la_meter_set::coupling_mode_e meter_coupling_mode)
{
    return (size_t)meter_coupling_mode;
}

static inline size_t
la_2_meter_cascade_mode(la_meter_profile::cascade_mode_e meter_cascade_mode)
{
    return (size_t)meter_cascade_mode;
}
static inline size_t
la_2_meter_rate_mode(la_meter_profile::meter_rate_mode_e meter_rate_mode)
{
    return (size_t)meter_rate_mode;
}

static inline size_t
la_2_port_speed(la_mac_port::port_speed_e speed)
{
    switch (speed) {
    case la_mac_port::port_speed_e::E_MGIG:
        return 1;
    case la_mac_port::port_speed_e::E_10G:
        return 10;
    case la_mac_port::port_speed_e::E_20G:
        return 20;
    case la_mac_port::port_speed_e::E_25G:
        return 25;
    case la_mac_port::port_speed_e::E_40G:
        return 40;
    case la_mac_port::port_speed_e::E_50G:
        return 50;
    case la_mac_port::port_speed_e::E_100G:
        return 100;
    case la_mac_port::port_speed_e::E_200G:
        return 200;
    case la_mac_port::port_speed_e::E_400G:
        return 400;
    case la_mac_port::port_speed_e::E_800G:
        return 800;
    case la_mac_port::port_speed_e::E_1200G:
        return 1200;
    case la_mac_port::port_speed_e::E_1600G:
        return 1600;
    }

    // Shouldn't reach here.
    return 0;
}

static inline la_qos_color_e
npl_2_la_qos_color(la_uint8_t dp)
{
    switch (dp) {
    case 0:
        return la_qos_color_e::GREEN;
    case 1:
        return la_qos_color_e::YELLOW;
    case 2:
        return la_qos_color_e::RED;
    }

    // Shouldn't reach here.
    return la_qos_color_e::NONE;
}

/// @brief Return the prefixed QoS field value of (PCP,DEI)
static inline la_uint8_t
get_prefixed_qos_field(la_vlan_pcpdei pcpdei)
{
    return (PCPDEI_KEY_PREFIX | pcpdei.flat);
}

/// @brief Return the prefixed QoS field value of DSCP
static inline la_uint8_t
get_prefixed_qos_field(la_ip_dscp dscp)
{
    return (DSCP_KEY_PREFIX | dscp.value);
}

/// @brief Return the prefixed QoS field value of MPLS Traffic-Class
static inline la_uint8_t
get_prefixed_qos_field(la_mpls_tc mpls_tc)
{
    return (MPLS_TC_KEY_PREFIX | mpls_tc.value);
}

/// @brief Return the prefixed mpls exp QoS field value of MPLS Traffic-Class
static inline la_uint8_t
get_prefixed_mpls_exp_field(la_mpls_tc mpls_tc)
{
    return (MAX_MPLS_TC_VALUE | mpls_tc.value);
}

/// @brief Convert SDK device mode type to coresponding NPL constant.
///
/// @param[in]  device_mode         Device mode.
///
/// @return NPL device mode constant value.
static inline uint64_t
device_mode_2_npl_dev_mode(device_mode_e device_mode)
{
    switch (device_mode) {
    case device_mode_e::STANDALONE:
        return NPL_DEV_MODE_SA;
    case device_mode_e::LINECARD:
        return NPL_DEV_MODE_LC;
    case device_mode_e::FABRIC_ELEMENT:
        return NPL_DEV_MODE_FE;
    default:
        dassert_crit(!"Unknown device mode");
        return -1;
    }
}

/// @brief Convert NPL protocol type to ether-type.
///
/// @param[in]  protocol_type         NPL protocol type.
///
/// @return ether-type.
static inline npl_slice_mode_e
la_2_npl_slice_mode(la_slice_mode_e slice_mode)
{
    switch (slice_mode) {
    case la_slice_mode_e::CARRIER_FABRIC:
        return NPL_SLICE_MODE_FABRIC;

    case la_slice_mode_e::UDC:
    case la_slice_mode_e::NETWORK:
        return NPL_SLICE_MODE_NETWORK;

    case la_slice_mode_e::DC_FABRIC:
        dassert_crit(!"Unsupported slice mode");
        return npl_slice_mode_e(0);

    default:
        // Shouldn't reach here
        dassert_crit(!"Unknown slice mode");
        return static_cast<npl_slice_mode_e>(0);
    }
}

/// @brief Performs a set action to a table in all slices of a specified mode
template <typename _TableType, size_t _SIZE>
static inline la_status
per_slice_tables_set(const std::array<la_slice_mode_e, ASIC_MAX_SLICES_PER_DEVICE_NUM>& slice_modes,
                     const std::shared_ptr<_TableType> (&table_arr)[_SIZE],
                     const vector_alloc<la_slice_mode_e>& requested_modes,
                     const typename _TableType::key_type& key,
                     const typename _TableType::value_type& value)
{
    static_assert(_SIZE == ASIC_MAX_SLICES_PER_DEVICE_NUM, "table array does not define a per-slice table");
    std::bitset<(size_t)la_slice_mode_e::NUM_SLICE_MODES> active_modes;

    for (auto mode : requested_modes) {
        active_modes.set(to_utype(mode));
    }

    typename _TableType::entry_pointer_type entry_ptr = nullptr;
    for (la_slice_id_t sid = 0; sid < slice_modes.size(); sid++) {
        if (!active_modes.test(to_utype(slice_modes[sid]))) {
            continue;
        }

        la_status status = table_arr[sid]->set(key, value, entry_ptr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

/// @brief Performs an insert action to a table in all slices of a specified mode
template <typename _TableType, size_t _SIZE>
static inline la_status
per_slice_tables_insert(const std::array<la_slice_mode_e, ASIC_MAX_SLICES_PER_DEVICE_NUM>& slice_modes,
                        const std::shared_ptr<_TableType> (&table_arr)[_SIZE],
                        const vector_alloc<la_slice_mode_e>& requested_modes,
                        const typename _TableType::key_type& key,
                        const typename _TableType::value_type& value)
{
    static_assert(_SIZE == ASIC_MAX_SLICES_PER_DEVICE_NUM, "table array does not define a per-slice table");
    std::bitset<(size_t)la_slice_mode_e::NUM_SLICE_MODES> active_modes;

    for (auto mode : requested_modes) {
        active_modes.set(to_utype(mode));
    }

    typename _TableType::entry_pointer_type entry_ptr = nullptr;
    for (la_slice_id_t sid = 0; sid < slice_modes.size(); sid++) {
        if (!active_modes.test(to_utype(slice_modes[sid]))) {
            continue;
        }

        la_status status = table_arr[sid]->insert(key, value, entry_ptr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

/// @brief Performs an erase action to a table in all slices of a specified mode
template <typename _TableType, size_t _SIZE>
static inline la_status
per_slice_tables_erase(const std::array<la_slice_mode_e, ASIC_MAX_SLICES_PER_DEVICE_NUM>& slice_modes,
                       const std::shared_ptr<_TableType> (&table_arr)[_SIZE],
                       const vector_alloc<la_slice_mode_e>& requested_modes,
                       const typename _TableType::key_type& key)
{
    static_assert(_SIZE == ASIC_MAX_SLICES_PER_DEVICE_NUM, "table array does not define a per-slice table");
    std::bitset<(size_t)la_slice_mode_e::NUM_SLICE_MODES> active_modes;

    for (auto mode : requested_modes) {
        active_modes.set(to_utype(mode));
    }

    for (la_slice_id_t sid = 0; sid < slice_modes.size(); sid++) {
        if (!active_modes.test(to_utype(slice_modes[sid]))) {
            continue;
        }

        la_status status = table_arr[sid]->erase(key);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

/// @brief Populate Tx to Rx recycle data
class la_mirror_command;
void populate_rcy_data_mirror_command(const la_mirror_command_wcptr& mirror_cmd,
                                      bool is_recycle_ac,
                                      npl_tx_to_rx_rcy_data_t& rcy_data);
la_status populate_rcy_data(const la_device_impl_wcptr& device,
                            const la_mirror_command_wcptr& mirror_cmd,
                            bool is_recycle_ac,
                            npl_tx_to_rx_rcy_data_t& rcy_data);

/// @brief Populate L3 DLP Id
npl_npu_encap_header_l3_dlp_t get_l3_dlp_encap(la_l3_port_gid_t gid);
npl_l3_dlp_id_t get_l3_dlp_id(la_l3_port_gid_t gid);

/// @brief L3 DLP from GID
uint32_t get_l3_dlp_value_from_gid(la_l3_port_gid_t gid);

static inline uint32_t
get_l3_lp_lsb(la_l3_port_gid_t gid)
{
    return bit_utils::get_bits(gid, 11, 0);
}

static inline uint32_t
get_l3_lp_msb(la_l3_port_gid_t gid)
{
    return bit_utils::get_bits(gid, 15, 12);
}
//  ------------------------------------------------------------end of inline

} // namespace silicon_one

#endif // __HLD_UTILS_BASE_H__
