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

#include "hld_utils_base.h"
#include "hld_utils.h"

#include "common/logger.h"
#include "npu/la_acl_delegate.h"
#include "npu/la_acl_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_gue_port_impl.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_lpts_impl.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_vrf_impl.h"
#include "npu/la_vxlan_next_hop_base.h"
#include "system/la_device_impl.h"
#include "system/la_l2_mirror_command_base.h"
#include "system/slice_id_manager_base.h"

#include "npu/la_acl_impl.h"
#include <sstream>

namespace silicon_one
{

static const char DEFAULT_BASE_OUTPUT_DIR[] = "out/noopt-debug";
static const char BASE_OUTPUT_DIR_ENVVAR[] = "BASE_OUTPUT_DIR";

void
apply_prefix_mask(la_ipv6_addr_t& addr, size_t prefix_length)
{
    size_t num_of_lsbits_to_clear = sizeof(addr) * CHAR_BIT - prefix_length;
    for (size_t ai = 0; num_of_lsbits_to_clear > 0; ai++) {
        if (num_of_lsbits_to_clear >= CHAR_BIT) {
            addr.b_addr[ai] = 0;
            num_of_lsbits_to_clear -= CHAR_BIT;
        } else {
            la_uint8_t mask = ~((1 << num_of_lsbits_to_clear) - 1);
            addr.b_addr[ai] &= mask;
            num_of_lsbits_to_clear = 0;
        }
    }
}

const la_acl_delegate_wptr
get_delegate(const la_acl_wptr& acl)
{

    if (acl == nullptr) {
        return la_acl_delegate_wptr{};
    }

    la_object::object_type_e t = acl->type();

    if (t == la_object::object_type_e::ACL) {
        auto acl_impl = acl.weak_ptr_static_cast<const la_acl_impl>();
        return acl_impl->get_delegate();
    }

    return la_acl_delegate_wptr{};
}

slice_ifg_vec_t
get_ifgs_base(const la_object_wcptr& obj)
{
    la_object::object_type_e object_type = obj->type();

    switch (object_type) {
    case la_object::object_type_e::L2_SERVICE_PORT: {
        const auto& port = obj.weak_ptr_static_cast<const la_l2_service_port_base>();
        return port->get_ifgs();
    }

    break;
    case la_object::object_type_e::L3_AC_PORT: {
        const auto& port = obj.weak_ptr_static_cast<const la_l3_ac_port_impl>();
        return port->get_ifgs();
    }

    break;
    case la_object::object_type_e::NEXT_HOP: {
        const auto& next_hop = obj.weak_ptr_static_cast<const la_next_hop_base>();
        return next_hop->get_ifgs();
    }

    break;
    case la_object::object_type_e::VXLAN_NEXT_HOP: {
        const auto& vxlan_next_hop = obj.weak_ptr_static_cast<const la_vxlan_next_hop_base>();
        return vxlan_next_hop->get_ifgs();
    }

    break;
    case la_object::object_type_e::SVI_PORT: {
        const auto& port = obj.weak_ptr_static_cast<const la_svi_port_base>();
        return port->get_ifgs();
    }

    case la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT: {
        const auto& port = obj.weak_ptr_static_cast<const la_ip_over_ip_tunnel_port_impl>();
        return port->get_ifgs();
    }

    break;
    case la_object::object_type_e::GRE_PORT: {
        const auto& port = obj.weak_ptr_static_cast<const la_gre_port_impl>();
        return port->get_ifgs();
    }

    break;
    case la_object::object_type_e::GUE_PORT: {
        const auto& port = obj.weak_ptr_static_cast<const la_gue_port_impl>();
        return port->get_ifgs();
    }

    break;
    case la_object::object_type_e::VRF: {
        const auto& vrf = obj.weak_ptr_static_cast<const la_vrf_impl>();
        return vrf->get_ifgs();
    }

    case la_object::object_type_e::LPTS: {
        const auto& lpts = obj.weak_ptr_static_cast<const la_lpts_impl>();
        return lpts->get_ifgs();
    }

    break;

    case la_object::object_type_e::L2_MIRROR_COMMAND: {
        const auto& l2_mirror_command = obj.weak_ptr_static_cast<const la_l2_mirror_command_base>();
        return l2_mirror_command->get_ifgs();
    }

    break;

    case la_object::object_type_e::MAC_PORT: {
        const auto& port = obj.weak_ptr_static_cast<const la_mac_port_base>();
        return port->get_pfc_counter_ifgs();
    }

    break;

    case la_object::object_type_e::ACL: {
        auto acl = obj.weak_ptr_static_cast<const la_acl_impl>();
        la_acl::type_e type;
        acl->get_type(type);
        if (type == la_acl::type_e::PBR) {
            return acl->get_delegate()->get_ifgs();
        }

        return slice_ifg_vec_t();
    }

    break;

    default:
        return slice_ifg_vec_t();
    }
}

bool
is_recycle_ac(const la_l3_ac_port_impl_wcptr& ac_port)
{
    auto ether_port = ac_port->get_ethernet_port();
    auto ether_impl = static_cast<const la_ethernet_port_base*>(ether_port);
    if (ether_impl->get_underlying_port_type() == la_object::object_type_e::RECYCLE_PORT) {
        return true;
    }
    return false;
}

bool
is_recycle_ac(const la_l2_service_port_base_wcptr& ac_port)
{
    auto ether_port = ac_port->get_ethernet_port();
    auto ether_impl = ether_port.weak_ptr_static_cast<const la_ethernet_port_base>();
    if (ether_impl->get_underlying_port_type() == la_object::object_type_e::RECYCLE_PORT) {
        return true;
    }
    return false;
}

npl_protocol_type_e
ethtype_to_npl_protocol_type(uint16_t ethtype)
{
    switch (ethtype) {
    case 0x0800:
        return NPL_PROTOCOL_TYPE_IPV4;
    case 0x86DD:
        return NPL_PROTOCOL_TYPE_IPV6;
    case 0x8808: // PFC
        return NPL_PROTOCOL_TYPE_PFC;
    case 0x8847: // MPLS unicast
    case 0x8848: // MPLS multicast
        return NPL_PROTOCOL_TYPE_MPLS;
    case 0x8809: // LACP
    case 0x88cc:
    case 0x8902: // CFM
        return NPL_PROTOCOL_TYPE_PUNT;
    case 0x0806:
        return NPL_PROTOCOL_TYPE_ARP;
    case 0x8100:
        return NPL_PROTOCOL_TYPE_VLAN_0;
    case 0x9100:
    case 0x88a8:
        return NPL_PROTOCOL_TYPE_VLAN_1;
    default:
        return NPL_PROTOCOL_TYPE_UNKNOWN;
    }
}

uint16_t
npl_protocol_type_to_ethtype(npl_protocol_type_e protocol_type)
{
    switch (protocol_type) {
    case NPL_PROTOCOL_TYPE_PFC:
        return 0x8808;
    case NPL_PROTOCOL_TYPE_IPV4:
        return 0x0800;
    case NPL_PROTOCOL_TYPE_IPV6:
        return 0x86DD;
    case NPL_PROTOCOL_TYPE_MPLS:
        return 0x8847;
    case NPL_PROTOCOL_TYPE_ARP:
        return 0x0806;
    case NPL_PROTOCOL_TYPE_VLAN_0:
        return 0x8100;
    case NPL_PROTOCOL_TYPE_VLAN_1:
        return 0x9100;
    default:
        return 0;
    }
}

npl_lpts_l4_protocol_compress_e
l4_protocol_to_npl_protocol_type(la_l4_protocol_e l4proto)
{
    switch (l4proto) {
    case la_l4_protocol_e::ICMP:
        return NPL_ICMP;
    case la_l4_protocol_e::HOP_BY_HOP:
        return NPL_ICMP;
    case la_l4_protocol_e::IGMP:
        return NPL_IGMP;
    case la_l4_protocol_e::TCP:
        return NPL_TCP;
    case la_l4_protocol_e::UDP:
        return NPL_UDP;
    case la_l4_protocol_e::RSVP:
        return NPL_RSVP;
    case la_l4_protocol_e::GRE:
        return NPL_GRE;
    case la_l4_protocol_e::IPV6_ICMP:
        return NPL_IPV6_ICMP;
    case la_l4_protocol_e::EIGRP:
        return NPL_EIGRP;
    case la_l4_protocol_e::OSPF:
        return NPL_OSPF;
    case la_l4_protocol_e::PIM:
        return NPL_PIM;
    case la_l4_protocol_e::VRRP:
        return NPL_VRRP;
    case la_l4_protocol_e::L2TP:
        return NPL_L2TPV3;
    case la_l4_protocol_e::IPV6_FRAGMENT:
        return NPL_FRAGMENT;
    default:
        return NPL_OTHER_L4_PROTOCOL;
    }
}

npl_resolution_protection_selector_e
monitor_state_to_npl_protection_selector(la_protection_monitor::monitor_state_e state)
{
    if (state == la_protection_monitor::monitor_state_e::TRIGGERED) {
        return NPL_PROTECTION_SELECTOR_PROTECT;
    } else {
        return NPL_PROTECTION_SELECTOR_PRIMARY;
    }
}

npl_lb_profile_enum_e
la_2_npl_lb_profile(la_l3_port::lb_profile_e la_lb_profile)
{
    switch (la_lb_profile) {
    case la_l3_port::lb_profile_e::IP:
        return NPL_LB_PROFILE_IP;
    case la_l3_port::lb_profile_e::EL_ELI:
        return NPL_LB_PROFILE_EL_ELI;
    default:
        return NPL_LB_PROFILE_MPLS;
    }
}

la_l3_port::lb_profile_e
npl_2_la_lb_profile(npl_lb_profile_enum_e npl_lb_profile)
{
    switch (npl_lb_profile) {
    case NPL_LB_PROFILE_IP:
        return la_l3_port::lb_profile_e::IP;
    case NPL_LB_PROFILE_EL_ELI:
        return la_l3_port::lb_profile_e::EL_ELI;
    default:
        return la_l3_port::lb_profile_e::MPLS;
    }
}

npl_protocol_type_e
ip_protocol_to_npl_protocol_type(uint8_t ipproto)
{
    switch (ipproto) {
    /*
    case 6:
        return NPL_PROTOCOL_TYPE_TCP;*/
    case 17:
        return NPL_PROTOCOL_TYPE_UDP;
    case 47:
        return NPL_PROTOCOL_TYPE_GRE;
    default:
        return NPL_PROTOCOL_TYPE_UNKNOWN;
    }
}

la_status
validate_quantization_thresholds(const la_device_impl_wcptr& device,
                                 const std::vector<la_uint_t>& thresholds,
                                 limit_type_e num_thresholds_limit,
                                 limit_type_e max_threshold_limit)
{
    la_status status;

    status = ensure_limit_eq(device, thresholds.size(), num_thresholds_limit);
    return_on_error(status);

    if (!is_sorted(thresholds.begin(), thresholds.end())) {
        return LA_STATUS_EINVAL;
    }

    status = ensure_limit_le(device, thresholds.back(), max_threshold_limit);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_uint_t
user_age_time_units_to_device_units(la_cgm_sms_voqs_age_time_units_t sms_voqs_age_time_units)
{
    switch (sms_voqs_age_time_units) {
    case 1000:
        return 1;
    case 2000:
        return 2;
    default:
        // Unsupported value
        return 0;
    }
}

la_cgm_sms_voqs_age_time_units_t
device_enq_time_units_to_user_units(la_uint_t device_enq_time_units)
{
    switch (device_enq_time_units) {
    case 0:
        return 1000; // 1000ns
    case 1:
        return 2000; // 2000ns
    default:
        return 0;
    }
}

void
add_all_slice_ifgs_to_vect(la_slice_id_t slice, slice_ifg_vec_t& vect)
{
    for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
        vect.push_back({.slice = slice, .ifg = ifg_id});
    }
}

std::string
get_value_type(unsigned long long value)
{
    return {};
}

std::string
get_value_type(unsigned long int value)
{
    return {};
}

std::string
get_value_type(unsigned int value)
{
    return {};
}

std::string
get_value_type(unsigned char value)
{
    return {};
}

std::string
get_value_type(char const* value)
{
    return {};
}

std::string
get_value_type(unsigned short value)
{
    return {};
}

std::string
get_value_type(bool value)
{
    return {};
}

std::string
get_value_type(float value)
{
    return {};
}

std::string
get_value_type(double value)
{
    return {};
}

std::string
get_value_type(int value)
{
    return {};
}

std::string
get_value_type(std::string value)
{
    return {};
}

la_slice_id_vec_t
get_slices(const la_device_impl_wcptr& device, la_slice_mode_e slice_mode)
{
    return get_slices(device, vector_alloc<la_slice_mode_e>({slice_mode}));
}

la_slice_id_vec_t
get_slices(const la_device_impl_wcptr& device, const vector_alloc<la_slice_mode_e>& slice_modes)
{
    la_slice_id_vec_t slices;
    size_t num_slices_including_disabled = device->get_slice_id_manager()->num_slices_per_device();
    for (la_slice_id_t slice = 0; slice < num_slices_including_disabled; slice++) {
        auto it = std::find(slice_modes.begin(), slice_modes.end(), device->m_slice_mode[slice]);
        if (it != slice_modes.end()) {
            slices.push_back(slice);
        }
    }

    return slices;
}

la_slice_pair_id_vec_t
get_slice_pairs(const la_device_impl_wcptr& device, la_slice_mode_e slice_mode)
{
    la_slice_pair_id_vec_t slice_pairs;

    la_slice_id_vec_t slices = get_slices(device, slice_mode);
    for (la_slice_id_t slice : slices) {
        // Compare with last slice pair in vector as slices in vector are in ascending order.
        if (!contains(slice_pairs, slice / 2)) {
            slice_pairs.push_back(slice / 2);
        }
    }

    return slice_pairs;
}

slice_ifg_vec_t
get_all_network_ifgs(const la_device_impl_wcptr& device)
{
    slice_ifg_vec_t all_network_ifgs;

    for (la_slice_id_t slice : get_slices(device, la_slice_mode_e::NETWORK)) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            la_slice_ifg slice_ifg = {.slice = slice, .ifg = ifg};
            all_network_ifgs.push_back(slice_ifg);
        }
    }

    return all_network_ifgs;
}

la_status
validate_ethtype_key_mask(uint16_t key, uint16_t mask)
{
    if (mask == 0x0) {
        return LA_STATUS_SUCCESS;
    }
    if (mask != 0xffff) {
        log_err(HLD, "Ethertype mask must be 0x0 or 0xffff but was %x", mask);
        return LA_STATUS_EINVAL;
    }
    if (ethtype_to_npl_protocol_type(key) == NPL_PROTOCOL_TYPE_UNKNOWN) {
        log_err(HLD, "Ethertype value %x is unsupported", key);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
validate_l4_protocol_mask(uint16_t mask)
{
    if (mask == 0) {
        return LA_STATUS_SUCCESS;
    }
    if (mask != 0xff) {
        log_err(HLD, "L4 protocol mask must be 0x0 or 0xff but was %x", mask);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

std::vector<la_slice_id_t>
get_slices_from_ifgs(slice_ifg_vec_t ifgs)
{
    std::vector<la_slice_id_t> slices;
    std::bitset<ASIC_MAX_SLICES_PER_DEVICE_NUM> slice_covered; // Default initialization to 0

    for (auto ifg : ifgs) {
        la_slice_id_t slice = ifg.slice;
        if (slice_covered[slice]) {
            continue;
        }

        slice_covered[slice] = true;
        slices.push_back(slice);
    }

    return slices;
}

std::string
find_resource_file(const char* file_env, const char* default_file)
{
    std::string filename;

    // take env vars
    const char* filename_env = getenv(file_env);
    const char* base_outdir_env = getenv(BASE_OUTPUT_DIR_ENVVAR);

    if (filename_env != nullptr) {
        // First check if the file was set explicitely.
        filename = filename_env;
    } else if (base_outdir_env != nullptr) {
        // If not, check if build path exists
        std::stringstream ss;
        ss << base_outdir_env << "/" << default_file;
        filename = ss.str();
    } else {
        // Else, take all default
        std::stringstream ss;
        ss << DEFAULT_BASE_OUTPUT_DIR << "/" << default_file;
        filename = ss.str();
    }

    return filename;
}

std::vector<std::pair<uint64_t, uint64_t> >
tcam_expand_range(uint64_t min_value, uint64_t max_value, size_t key_width)
{
    la_uint_t key_width_mask = bit_utils::get_lsb_mask(key_width);
    std::vector<std::pair<uint64_t, uint64_t> > res;
    if (min_value == max_value) {
        res.push_back({(min_value & key_width_mask), ((~0) & key_width_mask)});
        return res;
    }

    // First loop raise min_value until it gets to [max_value & ~get_lsb_mask(n)]
    if (min_value > 0) {
        uint64_t lsb_min = bit_utils::get_lsb(min_value);
        uint64_t msb_xor = bit_utils::get_msb(min_value ^ max_value);
        while (lsb_min < msb_xor) {
            lsb_min = bit_utils::get_lsb(min_value);
            uint64_t mask = ((~bit_utils::get_lsb_mask(lsb_min)) & key_width_mask);
            res.push_back({min_value, mask});
            min_value += (1 << lsb_min);
            lsb_min = bit_utils::get_lsb(min_value);
        }
    }

    // Second loop raise min up to max
    while (min_value < max_value) {
        uint64_t diff = min_value ^ max_value;
        uint64_t msb_diff = bit_utils::get_msb(diff);
        uint64_t lsb_mask = bit_utils::get_lsb_mask(msb_diff);
        uint64_t msb_diff_bit = (uint64_t)1 << msb_diff;
        if (lsb_mask == (lsb_mask & max_value)) { // max_value = *111
            uint64_t mask = (((~lsb_mask) & (~msb_diff_bit)) & key_width_mask);
            res.push_back({min_value, mask});
            return res;
        }

        res.push_back({min_value, ((~lsb_mask) & key_width_mask)});
        min_value |= msb_diff_bit;
    }

    res.push_back({min_value, ((~0) & key_width_mask)});
    return res;
}

bool
is_equal_mac_addr_prefix(la_mac_addr_t addr1, la_mac_addr_t addr2, size_t bytes_from_msb)
{
    for (size_t index = 6; index > (6 - bytes_from_msb); index--) {
        if (addr1.bytes[index - 1] != addr2.bytes[index - 1]) {
            return false;
        }
    }

    return true;
}

// PACKET-DMA-WA
const la_system_port_base_wcptr
get_rcy_system_port_for_pci_sys_port(const la_device_impl_wcptr& device, la_slice_id_t port_slice)
{
    for (la_slice_ifg s_ifg : get_possible_rcy_port_slice(port_slice)) {
        size_t gifg_id = device->get_slice_id_manager()->slice_ifg_2_global_ifg(s_ifg);
        la_system_port_base_wcptr ptr = device->m_per_ifg_recycle_sp[gifg_id];
        if (ptr != nullptr) {
            return ptr.lock();
        }
    }
    return device->get_sptr<const la_system_port_base>(nullptr);
}

bool
is_network_slice(la_slice_mode_e mode)
{
    switch (mode) {
    case la_slice_mode_e::NETWORK:
    case la_slice_mode_e::UDC:
        return true;

    default:
        return false;
    }
}

la_status
ensure_limit_le(const la_device_impl_wcptr& device, la_uint64_t param, limit_type_e limit_type)
{
    la_status status;
    la_uint64_t value_set;
    status = device->get_limit(limit_type, value_set);
    return_on_error(status);
    if (param > value_set) {
        return LA_STATUS_EOUTOFRANGE;
    }
    return LA_STATUS_SUCCESS;
}

la_status
ensure_limit_eq(const la_device_impl_wcptr& device, la_uint64_t param, limit_type_e limit_type)
{
    la_status status;
    la_uint64_t value_set;
    status = device->get_limit(limit_type, value_set);
    return_on_error(status);
    if (param != value_set) {
        return LA_STATUS_EOUTOFRANGE;
    }
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
