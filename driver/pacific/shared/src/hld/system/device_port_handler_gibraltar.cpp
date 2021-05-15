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

#include "system/device_port_handler_gibraltar.h"
#include "common/logger.h"
#include "system/la_device_impl.h"
#include "system/mac_pool8_port.h"

namespace silicon_one
{

// valid configurations parameters
// Each entry key is {speed, serdes_count, fec_mode}
// Each entry value is {serdes_speed, serdes_speed_gbps, mac_lanes in use, mac_lanes, pcs_lanes_per_mac_lane,
// alignment_marker_rx,
// alignment_marker_tx}
using valid_configurations_t = device_port_handler_gibraltar::valid_configurations_t;
// this holds all the possible port configurations where the serdes operates at low speed ( speed <= 25Gbit )
valid_configurations_t s_nrz_configurations_GB = {
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_10G, 1, la_mac_port::fec_mode_e::NONE},
        {la_mac_port::port_speed_e::E_10G, 10, 1, 1, 1, 0, 0, serdes_handler::an_capability_code_e::E_10GBASE_KR, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_10G, 1, la_mac_port::fec_mode_e::KR},
        {la_mac_port::port_speed_e::E_10G, 10, 1, 1, 1, 0, 0, serdes_handler::an_capability_code_e::E_10GBASE_KR, 1}),

    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_25G, 1, la_mac_port::fec_mode_e::NONE},
        {la_mac_port::port_speed_e::E_25G, 25, 1, 1, 1, 0, 0, serdes_handler::an_capability_code_e::E_25GBASE_KRCR, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_25G, 1, la_mac_port::fec_mode_e::KR},
        {la_mac_port::port_speed_e::E_25G, 25, 1, 1, 1, 0, 0, serdes_handler::an_capability_code_e::E_25GBASE_KRCR, 4}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_25G, 1, la_mac_port::fec_mode_e::RS_KR4},
        {la_mac_port::port_speed_e::E_25G, 25, 1, 1, 1, 90110, 81913, serdes_handler::an_capability_code_e::E_25GBASE_KRCR, 2}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_25G, 1, la_mac_port::fec_mode_e::RS_KP4},
        {la_mac_port::port_speed_e::E_25G, 26, 1, 1, 1, 93182, 81913, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),

    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_40G, 4, la_mac_port::fec_mode_e::NONE},
        {la_mac_port::port_speed_e::E_10G, 10, 1, 4, 4, 16382, 65529, serdes_handler::an_capability_code_e::E_40GBASE_CR4, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_40G, 4, la_mac_port::fec_mode_e::KR},
        {la_mac_port::port_speed_e::E_10G, 10, 1, 4, 4, 16382, 65529, serdes_handler::an_capability_code_e::E_40GBASE_CR4, 1}),
    // 2x20G, check number of pcs lanes per mac
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_40G, 2, la_mac_port::fec_mode_e::NONE},
        {la_mac_port::port_speed_e::E_25G, 20, 1, 2, 2, 16382, 65529, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),

    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_50G, 2, la_mac_port::fec_mode_e::NONE},
        {la_mac_port::port_speed_e::E_25G, 25, 1, 2, 2, 16382, 65529, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_50G, 2, la_mac_port::fec_mode_e::RS_KR4},
        {la_mac_port::port_speed_e::E_25G, 25, 1, 2, 2, 45053, 81913, serdes_handler::an_capability_code_e::E_50GBASE_KR_CR, 1}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_50G, 2, la_mac_port::fec_mode_e::RS_KP4},
        {la_mac_port::port_speed_e::E_25G, 26, 1, 2, 2, 47101, 81913, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),

    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_100G, 4, la_mac_port::fec_mode_e::NONE},
        {la_mac_port::port_speed_e::E_25G, 25, 2, 4, 10, 16382, 163827, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_100G, 4, la_mac_port::fec_mode_e::RS_KR4},
        {la_mac_port::port_speed_e::E_25G, 25, 2, 4, 2, 90109, 163827, serdes_handler::an_capability_code_e::E_100GBASE_CR4, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_100G, 4, la_mac_port::fec_mode_e::RS_KP4},
        {la_mac_port::port_speed_e::E_25G, 26, 2, 4, 2, 94205, 163827, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),

    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_200G, 8, la_mac_port::fec_mode_e::RS_KP4},
        {la_mac_port::port_speed_e::E_25G, 26, 8, 8, 1, 94205, 163833, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),
};

// this holds all the possible port configurations where the serdes operates at high speed (speed > 25Gbit )
valid_configurations_t s_pam4_configurations_GB = {
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_50G, 1, la_mac_port::fec_mode_e::RS_KR4},
        {la_mac_port::port_speed_e::E_50G, 51, 1, 1, 2, 45053, 81913, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_50G, 1, la_mac_port::fec_mode_e::RS_KP4},
        {la_mac_port::port_speed_e::E_50G, 53, 1, 1, 2, 47101, 81913, serdes_handler::an_capability_code_e::E_50GBASE_KR_CR, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_200G, 4, la_mac_port::fec_mode_e::RS_KP4},
        {la_mac_port::port_speed_e::E_50G, 53, 4, 4, 2, 47101, 81913, serdes_handler::an_capability_code_e::E_200GBASE_KR4_CR4, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_400G, 8, la_mac_port::fec_mode_e::RS_KP4},
        {la_mac_port::port_speed_e::E_50G, 53, 8, 8, 2, 49149, 81913, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),

    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_800G, 16, la_mac_port::fec_mode_e::RS_KP4},
        {la_mac_port::port_speed_e::E_50G, 53, 16, 16, 2, 49149, 81913, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_100G, 2, la_mac_port::fec_mode_e::RS_KR4},
        {la_mac_port::port_speed_e::E_50G, 51, 2, 2, 2, 90109, 163827, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0}),
    valid_configurations_t::value_type({la_mac_port::port_speed_e::E_100G, 2, la_mac_port::fec_mode_e::RS_KP4},
                                       {la_mac_port::port_speed_e::E_50G,
                                        53,
                                        2,
                                        2,
                                        2,
                                        94205,
                                        163827,
                                        serdes_handler::an_capability_code_e::E_100GBASE_KR2_CR2,
                                        0}),
    valid_configurations_t::value_type(
        {la_mac_port::port_speed_e::E_100G, 2, la_mac_port::fec_mode_e::RS_KP4_FI},
        {la_mac_port::port_speed_e::E_50G, 53, 2, 2, 2, 46589, 40947, serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY, 0})};

device_port_handler_gibraltar::device_port_handler_gibraltar(const la_device_impl_wptr& device) : device_port_handler_base(device)
{
}

device_port_handler_gibraltar::~device_port_handler_gibraltar()
{
}

void
device_port_handler_gibraltar::initialize()
{
    // Initialize valid configurations and parameters
    m_valid_configurations = valid_configurations_t(s_nrz_configurations_GB);

    int matildaMod = 0;
    m_device->get_int_property(la_device_property_e::MATILDA_MODEL_TYPE, matildaMod);
    if (matildaMod == matilda_model_e::GIBRALTAR_REGULAR || matildaMod == matilda_model_e::MATILDA_8T_A
        || matildaMod == matilda_model_e::MATILDA_8T_B) {
        m_valid_configurations.insert(s_pam4_configurations_GB.begin(), s_pam4_configurations_GB.end());
    }

    m_serdes_configurations
        = {serdes_configurations_t::value_type(
               {la_mac_port::port_speed_e::E_10G},
               {la_mac_port::port_speed_e::E_10G, pma_data_width_e::E_20, 0, fec_lane_speed_e::E_NONE, 0, false}),
           serdes_configurations_t::value_type(
               {la_mac_port::port_speed_e::E_25G},
               {la_mac_port::port_speed_e::E_25G, pma_data_width_e::E_40, 1, fec_lane_speed_e::E_25G, 0, false}),
           serdes_configurations_t::value_type(
               {la_mac_port::port_speed_e::E_50G},
               {la_mac_port::port_speed_e::E_50G, pma_data_width_e::E_80, 2, fec_lane_speed_e::E_25G, 0, true})};
}

const std::vector<la_mac_port::port_speed_e>
device_port_handler_gibraltar::get_supported_speeds()
{
    static const std::vector<la_mac_port::port_speed_e> supported_speeds = {la_mac_port::port_speed_e::E_10G,
                                                                            la_mac_port::port_speed_e::E_25G,
                                                                            la_mac_port::port_speed_e::E_40G,
                                                                            la_mac_port::port_speed_e::E_50G,
                                                                            la_mac_port::port_speed_e::E_100G,
                                                                            la_mac_port::port_speed_e::E_200G,
                                                                            la_mac_port::port_speed_e::E_400G,
                                                                            la_mac_port::port_speed_e::E_800G};

    return supported_speeds;
}

la_status
device_port_handler_gibraltar::create_mac_pool(size_t serdes_base_id, mac_pool_port_sptr& mac_pool_port)
{
    mac_pool_port = std::make_shared<mac_pool8_port>(m_device);
    return LA_STATUS_SUCCESS;
}

la_status
device_port_handler_gibraltar::set_fabric_mode(la_device::fabric_mac_ports_mode_e fabric_mac_ports_mode)
{
    if (fabric_mac_ports_mode == la_device::fabric_mac_ports_mode_e::E_2x50) {
        m_fabric_data.speed = la_mac_port::port_speed_e::E_100G;
        m_fabric_data.num_serdes_per_fabric_port = 2;
    } else {
        m_fabric_data.speed = la_mac_port::port_speed_e::E_200G;
        m_fabric_data.num_serdes_per_fabric_port = 4;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
