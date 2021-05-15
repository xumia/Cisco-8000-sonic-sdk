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

#include "system/device_port_handler_base.h"

namespace silicon_one
{

device_port_handler_base::device_port_handler_base(const la_device_impl_wptr& device) : m_device(device)
{
    // Initialize Fabric mode to default
    m_fabric_data.speed = la_mac_port::port_speed_e::E_100G;
    m_fabric_data.num_serdes_per_fabric_port = 2;
}

device_port_handler_base::~device_port_handler_base()
{
}

bool
device_port_handler_base::is_valid_config(la_mac_port::port_speed_e speed, size_t serdes_count, la_mac_port::fec_mode_e fec_mode)
{
    return (m_valid_configurations.count({speed, serdes_count, fec_mode}) > 0);
}

la_status
device_port_handler_base::get_mac_port_config(la_mac_port::port_speed_e speed,
                                              size_t serdes_count,
                                              la_mac_port::fec_mode_e fec_mode,
                                              mac_port_config_data& out_config)
{
    valid_configurations_t::const_iterator config = m_valid_configurations.find({speed, serdes_count, fec_mode});

    if (config == m_valid_configurations.end()) {
        return LA_STATUS_EINVAL;
    }

    out_config = config->second;

    return LA_STATUS_SUCCESS;
}

la_status
device_port_handler_base::get_serdes_config(la_mac_port::port_speed_e speed, serdes_config_data& out_config)
{
    serdes_configurations_t::const_iterator config = m_serdes_configurations.find({speed});

    if (config == m_serdes_configurations.end()) {
        return LA_STATUS_EINVAL;
    }

    out_config = config->second;

    return LA_STATUS_SUCCESS;
}

la_status
device_port_handler_base::get_valid_configs(la_mac_port::mac_config_vec& out_config_vec)
{
    out_config_vec.clear();

    // TODO: if infrastructure is enhanced, better to use std::transform.
    for (auto x : m_valid_configurations) {
        bool an_supported = (x.first.speed == la_mac_port::port_speed_e::E_400G
                             || x.second.an_capability != serdes_handler::an_capability_code_e::E_NO_TECHNOLOGY);
        out_config_vec.push_back(la_mac_port::mac_config({x.first.speed, x.first.serdes_count, x.first.fec_mode, an_supported}));
    }

    return LA_STATUS_SUCCESS;
}

la_status
device_port_handler_base::get_fabric_data(fabric_data& out_data) const
{
    out_data = m_fabric_data;
    return LA_STATUS_SUCCESS;
}

// The three method below are common for PA/GB/PL/GR
bool
device_port_handler_base::is_mlp(size_t serdes_count) const
{
    return serdes_count > 8;
}

size_t
device_port_handler_base::get_mac_pool_id(size_t serdes_base_id) const
{
    return serdes_base_id / 8;
}

size_t
device_port_handler_base::get_serdes_id_in_mac_pool(size_t serdes_base_id) const
{
    return serdes_base_id % 8;
}
}
