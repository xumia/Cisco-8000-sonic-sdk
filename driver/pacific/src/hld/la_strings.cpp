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

#include "la_strings.h"
#include <sstream>

namespace silicon_one
{

std::string
to_string(la_temperature_sensor_e sensor)
{
    static constexpr size_t first = (size_t)la_temperature_sensor_e::PACIFIC_FIRST;
    static const char* strs[] = {
            [(size_t)la_temperature_sensor_e::PACIFIC_SENSOR_1 - first] = "TEMPERATURE_SENSOR_1",
            [(size_t)la_temperature_sensor_e::PACIFIC_SENSOR_2 - first] = "TEMPERATURE_SENSOR_2",
            [(size_t)la_temperature_sensor_e::PACIFIC_SENSOR_1_DIRECT - first] = "TEMPERATURE_SENSOR_1_DIRECT",
            [(size_t)la_temperature_sensor_e::PACIFIC_SENSOR_2_DIRECT - first] = "TEMPERATURE_SENSOR_2_DIRECT",
            [(size_t)la_temperature_sensor_e::PACIFIC_HBM_SENSOR_1 - first] = "TEMPERATURE_HBM_SENSOR_1",
            [(size_t)la_temperature_sensor_e::PACIFIC_HBM_SENSOR_2 - first] = "TEMPERATURE_HBM_SENSOR_2",
    };

    static_assert(array_size(strs) == (size_t)la_temperature_sensor_e::PACIFIC_LAST - first + 1, "");

    if ((size_t)sensor - first < array_size(strs)) {
        return strs[(size_t)sensor - first];
    }

    return "Unknown temperature sensor";
}

std::string
to_string(la_voltage_sensor_e sensor)
{
    static constexpr size_t first = (size_t)la_voltage_sensor_e::PACIFIC_FIRST;
    static const char* strs[] = {
            [(size_t)la_voltage_sensor_e::PACIFIC_SENSOR_1_VDD - first] = "VOLTAGE_SENSOR_1_VDD",
            [(size_t)la_voltage_sensor_e::PACIFIC_SENSOR_1_AVDD - first] = "VOLTAGE_SENSOR_1_AVDD",
            [(size_t)la_voltage_sensor_e::PACIFIC_SENSOR_2_VDD - first] = "VOLTAGE_SENSOR_2_VDD",
            [(size_t)la_voltage_sensor_e::PACIFIC_SENSOR_2_AVDD - first] = "VOLTAGE_SENSOR_2_AVDD",
    };

    static_assert(array_size(strs) == (size_t)la_voltage_sensor_e::PACIFIC_LAST - first + 1, "");

    if ((size_t)sensor - first < array_size(strs)) {
        return strs[(size_t)sensor - first];
    }

    return "Unknown voltage sensor";
}

std::string
to_string(resolution_step_e resolution_step)
{
    static const char* strs[] = {
            [(int)resolution_step_e::RESOLUTION_STEP_FORWARD_L2] = "RESOLUTION_STEP_FORWARD_L2",
            [(int)resolution_step_e::RESOLUTION_STEP_FORWARD_L3] = "RESOLUTION_STEP_FORWARD_L3",
            [(int)resolution_step_e::RESOLUTION_STEP_FORWARD_MPLS] = "RESOLUTION_STEP_FORWARD_MPLS",
            [(int)resolution_step_e::RESOLUTION_STEP_STAGE0_PBTS_GROUP] = "RESOLUTION_STEP_STAGE0_PBTS_GROUP",
            [(int)resolution_step_e::RESOLUTION_STEP_NATIVE_FEC] = "RESOLUTION_STEP_NATIVE_FEC",
            [(int)resolution_step_e::RESOLUTION_STEP_NATIVE_LB] = "RESOLUTION_STEP_NATIVE_LB",
            [(int)resolution_step_e::RESOLUTION_STEP_NATIVE_CE_PTR] = "RESOLUTION_STEP_NATIVE_CE_PTR",
            [(int)resolution_step_e::RESOLUTION_STEP_NATIVE_L2_LP] = "RESOLUTION_STEP_NATIVE_L2_LP",
            [(int)resolution_step_e::RESOLUTION_STEP_NATIVE_L3_LP] = "RESOLUTION_STEP_NATIVE_L3_LP",
            [(int)resolution_step_e::RESOLUTION_STEP_NATIVE_FRR] = "RESOLUTION_STEP_NATIVE_FRR",
            [(int)resolution_step_e::RESOLUTION_STEP_STAGE1_PROTECTION] = "RESOLUTION_STEP_STAGE1_PROTECTION",
            [(int)resolution_step_e::RESOLUTION_STEP_STAGE2_LB] = "RESOLUTION_STEP_STAGE2_LB",
            [(int)resolution_step_e::RESOLUTION_STEP_PATH_LP] = "RESOLUTION_STEP_PATH_LP",
            [(int)resolution_step_e::RESOLUTION_STEP_STAGE2_PROTECTION] = "RESOLUTION_STEP_STAGE2_PROTECTION",
            [(int)resolution_step_e::RESOLUTION_STEP_STAGE3_LB] = "RESOLUTION_STEP_STAGE3_LB",
            [(int)resolution_step_e::RESOLUTION_STEP_PORT_NPP_PROTECTION] = "RESOLUTION_STEP_PORT_NPP_PROTECTION",
            [(int)resolution_step_e::RESOLUTION_STEP_PORT_DSPA] = "RESOLUTION_STEP_PORT_DSPA",
    };

    if ((size_t)resolution_step < array_size(strs)) {
        return std::string(strs[(size_t)resolution_step]);
    }

    return std::string("Unknown resolution step");
}

std::string
to_string(la_ip_tunnel_type_e type)
{
    static const char* strs[] = {
            [(int)la_ip_tunnel_type_e::IP_IN_IP] = "IP_IN_IP",
            [(int)la_ip_tunnel_type_e::GRE] = "GRE",
            [(int)la_ip_tunnel_type_e::GUE] = "GUE",
            [(int)la_ip_tunnel_type_e::VXLAN] = "VXLAN",
            [(int)la_ip_tunnel_type_e::NVGRE] = "NVGRE",
    };

    if ((size_t)type < array_size(strs)) {
        return std::string(strs[(size_t)type]);
    }

    return std::string("Unknown IP Tunnel Type");
}

std::string
to_string(la_mep_direction_e mep_dir)
{
    static const char* strs[] = {
            [(int)la_mep_direction_e::DOWN] = "MEP_DIRECTION_DOWN", [(int)la_mep_direction_e::UP] = "MEP_DIRECTION_UP",
    };

    if ((size_t)mep_dir < array_size(strs)) {
        return std::string(strs[(size_t)mep_dir]);
    }

    return std::string("Unknown mep direction");
}

} // namespace silicon_one
