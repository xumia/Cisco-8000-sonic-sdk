// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

// Description: SERDES and Board related lsai objects.

#ifndef __LA_SAI_BOARD_H__
#define __LA_SAI_BOARD_H__

#include <string>
#include <map>

#include "api/system/la_device.h"
#include "sai_constants.h"

extern "C" {
#include <sai.h>
}

namespace silicon_one
{
namespace sai
{

// Lanes Settings structure for lane swap, RX/TX lane inversion information
struct lsai_lane_settings_t {
    std::vector<std::vector<unsigned int>> ifg_swap;
    std::vector<std::vector<unsigned int>> rx_inverse;
    std::vector<std::vector<unsigned int>> tx_inverse;
};

// SerDes Key struct and its hash key
struct lsai_serdes_params_map_key_t {
    uint8_t slice_id;
    uint8_t ifg_id;
    uint8_t serdes_id = 0;
    uint16_t serdes_speed;
    lsai_serdes_media_type_e media_type;
};

struct lsai_serdes_params_map_key_comparator_t {
    bool operator()(const lsai_serdes_params_map_key_t& left, const lsai_serdes_params_map_key_t& right) const
    {
        return (std::tie(left.slice_id, left.ifg_id, left.serdes_id, left.serdes_speed, left.media_type)
                > std::tie(right.slice_id, right.ifg_id, right.serdes_id, right.serdes_speed, right.media_type));
    }
};

// SerDes Parameters structure and mapping structure
using lsai_serdes_params_t = std::vector<silicon_one::la_mac_port::serdes_parameter>;
using lsai_serdes_params_map_t
    = std::map<lsai_serdes_params_map_key_t, lsai_serdes_params_t, lsai_serdes_params_map_key_comparator_t>;

// serdes_params/serdes_key counters
struct lsai_serdes_key_counters_t {
    la_uint32_t not_present = 0;
    la_uint32_t copper = 0;
    la_uint32_t optic = 0;
    la_uint32_t chip2chip = 0;
    la_uint32_t loopback = 0;

    la_uint32_t error_cnt = 0;

    void inc(const lsai_serdes_media_type_e& media_type);

    la_uint32_t total();
};

struct lsai_sai_board_cfg_t {
    lsai_lane_settings_t lanes;

    // serdes parameters and serdes properties counters
    lsai_serdes_params_t serdes_default_params;
    lsai_serdes_params_t serdes_default_pll;
    // Storage of All SI parameters, indexing with specific serdes lane and media type
    lsai_serdes_params_map_t serdes_params_map;
    // Default SI parameters for specific IFG.
    lsai_serdes_params_map_t ifg_default_params_map;
    lsai_serdes_key_counters_t serdes_key_counters;
    lsai_serdes_key_counters_t ifg_key_counters;
};

// Port configuration struct for config_parser.cpp
struct lsai_port_cfg_t {
    std::vector<uint32_t> m_pif_lanes;        // PIF lanes of port
    std::vector<sai_attribute_t> m_attrs;     // attribute vector of a port configuration
    sai_object_id_t m_sai_port_id = 0;        // sai port object id
    sai_object_id_t m_sai_bridge_port_id = 0; // sai bridge_port object id
    sai_object_id_t m_sai_vlan_member_id = 0; // sai vlan member object id

    lsai_port_cfg_t(){};
    lsai_port_cfg_t(const uint32_t& pif, const uint32_t& num_of_lanes, std::vector<sai_attribute_t>& attrs);
};

using lsai_port_grp_t = std::vector<lsai_port_cfg_t>; // a group of port configurations

// a map of port configuration groups
using lsai_port_mix_map_t = std::map<std::string, lsai_port_grp_t>;
}
}
#endif
