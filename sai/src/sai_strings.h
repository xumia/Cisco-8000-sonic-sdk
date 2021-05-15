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

#ifndef __SAI_STRINGS_H__
#define __SAI_STRINGS_H__

extern "C" {
#include <sai.h>
#include "sai_attr_ext.h"
}
#include <sstream>
#include <unordered_map>
#include <string.h>

#include "auto_gen_attr_ext.h"
#include "api/system/la_mac_port.h"

#include "la_sai_board.h"

namespace silicon_one
{

extern std::string to_string(la_device_property_e device_property);
extern std::string to_string(la_mac_port::fc_mode_e fc_mode);
extern std::string to_string(la_mac_port::fec_mode_e fec_mode);
extern std::string to_string(la_mac_port::loopback_mode_e loopback_mode);
extern std::string to_string(la_mac_port::port_speed_e speed);
extern std::string to_string(la_mac_port::serdes_param_e parameter);
extern std::string to_string(la_mac_port::serdes_param_mode_e mode);
extern std::string to_string(la_mac_port::serdes_param_stage_e stage);
extern std::string to_string(la_mac_port::state_e state);
extern std::string to_string(const la_object* object);

namespace sai
{

enum class port_entry_type_e;

typedef std::string (*attr_to_string_fn)(sai_attribute_t& attr);

std::string to_string(const silicon_one::sai::lsai_sw_init_mode_e& value);
std::string to_string(const silicon_one::la_mac_port::serdes_parameter& serdes_prop);
std::string to_string(const silicon_one::sai::lsai_serdes_params_map_key_t& value);
std::string to_string(const silicon_one::sai::lsai_serdes_key_counters_t& value);
std::string to_string(const port_entry_type_e& pentry_type);
std::string to_string(attr_to_string_fn attr_func, unsigned int& value);
std::string to_string(attr_to_string_fn attr_func, const char*& value);
std::string to_string(attr_to_string_fn attr_func, const std::string& value);
std::string to_string(attr_to_string_fn attr_func, const sai_object_id_t& obj_id);
std::string to_string(attr_to_string_fn attr_func, sai_attribute_t& attr);
std::string to_string(attr_to_string_fn attr_func, const sai_fdb_entry_t*& x);
std::string to_string(attr_to_string_fn attr_func, const sai_neighbor_entry_t*& x);
std::string to_string(attr_to_string_fn attr_func, const sai_inseg_entry_t*& x);
std::string to_string(attr_to_string_fn attr_func, const sai_route_entry_t*& x);
std::string to_string(attr_to_string_fn attr_func, std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs);
std::string to_string(const sai_ip_address_t& ipaddr);
std::string to_string(const sai_ip_prefix_t& ipprefix);

std::string to_string(const sai_map_t&);
std::string to_string(const sai_map_list_t&);

std::string to_string(const sai_s8_list_t&);
std::string to_string(const sai_u8_list_t&);
std::string to_string(const sai_acl_capability_t&);
std::string to_string(const sai_acl_resource_list_t&);
std::string to_string(const sai_u32_range_t&);
std::string to_string(const sai_segment_list_t&);
std::string to_string(const sai_tlv_list_t&);
std::string to_string(const sai_qos_map_list_t&);
std::string to_string(const sai_timespec_t&);

std::string to_string(const sai_s32_list_t& s32list);
std::string to_string(const sai_u32_list_t& u32list);
std::string to_string(const sai_mac_t& mac);
std::string to_string(short unsigned int& x);
std::string to_string(unsigned int& x);
std::string to_string(long unsigned int& x);
std::string to_string(const sai_object_list_t& list);
std::string to_string(bool x);

std::string to_string(const sai_ip_address_list_t& list);
std::string to_string(const sai_vlan_list_t& list);
std::string to_string(const sai_s32_list_t& list);
std::string to_string(const sai_ip6_t& ip6);
std::string to_string(const sai_port_lane_eye_values_t& ev);
std::string to_string(const sai_port_eye_values_list_t& evlst);

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 0)
std::string to_string(const sai_macsec_sak_t& sak);
std::string to_string(const sai_macsec_auth_key_t& auth_key);
std::string to_string(const sai_macsec_salt_t& salt);
#endif

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 2)
std::string to_string(const sai_port_err_status_list_t& status_list);
std::string to_string(const sai_fabric_port_reachability_t& reachability);
std::string to_string(const sai_system_port_config_list_t& cfg_list);
std::string to_string(const sai_system_port_config_t& port_cfg);
#endif

std::string to_string(sai_port_serdes_attr_ext_t a, sai_attribute_value_t v);
std::string to_string(const sai_port_serdes_attr_ext_t& x);

template <class ForwardIt, typename Func>
std::string
to_string(ForwardIt first, ForwardIt last, Func func)
{
    std::stringstream ss;
    auto itr = first;
    if (itr != last) {
        ss << func(itr);
        itr++;
    }
    for (; itr != last; itr++) {
        ss << ", " << func(itr);
    }

    return ss.str();
}
}
}

#endif
