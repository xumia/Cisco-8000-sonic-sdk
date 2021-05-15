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

#ifndef __SAI_TEST_UTILS_H__
#define __SAI_TEST_UTILS_H__

#include <arpa/inet.h>
#include <unordered_map>
#include <sstream>

static char g_config_file_name[100] = "config/sherman_p5.json";
static char g_acl_key_profile_file_name[100] = "config/acl_key_profile.json";

static const char*
profile_get_value(sai_switch_profile_id_t profile_id, const char* variable)
{
    const char DEFAULT_RES_DIR[] = "res/";
    const char RES_OUTPUT_DIR_ENVVAR[] = "RES_OUTPUT_DIR";
    const char* res_outdir_env = getenv(RES_OUTPUT_DIR_ENVVAR);

    std::stringstream config_file_full_path;
    std::stringstream acl_key_profile_full_path;
    if (res_outdir_env) {
        config_file_full_path << res_outdir_env << "/" << g_config_file_name;
        acl_key_profile_full_path << res_outdir_env << "/" << g_acl_key_profile_file_name;
    } else {
        config_file_full_path << DEFAULT_RES_DIR << g_config_file_name;
        acl_key_profile_full_path << DEFAULT_RES_DIR << g_acl_key_profile_file_name;
    }

    using sai_key_t = std::unordered_map<std::string, std::string>;
    sai_key_t sai_key_map{{SAI_KEY_INIT_CONFIG_FILE, config_file_full_path.str()},
                          {SAI_KEY_NUM_QUEUES, "256"},
                          {"ACL_KEY_PROFILE_FILE", acl_key_profile_full_path.str()}};

    return sai_key_map[variable].c_str();
};

struct slice_ifg_pif {
    uint32_t slice;
    uint32_t ifg;
    uint32_t pif;
};

inline slice_ifg_pif
lane_to_slice_ifg_pif(uint32_t lane)
{
    return {(lane >> 8) / 2, (lane >> 8) % 2, lane & 0x00FF};
}

inline uint32_t
lane_from_slice_ifg_pif(uint32_t slice, uint32_t ifg, uint32_t pif)
{
    return (((slice * 2) + ifg) << 8) + (pif & 0x00FF);
}

inline sai_status_t
str_to_ipv4(const char* str, uint32_t& ip)
{
    uint32_t tmp_ip = 0;
    if (inet_pton(AF_INET, str, &tmp_ip) != 1) {
        return SAI_STATUS_FAILURE;
    }
    ip = tmp_ip;
    return SAI_STATUS_SUCCESS;
}

inline sai_status_t
str_to_ipv6(const char* str, uint8_t* ip)
{
    uint8_t tmp_ip[16];
    if (inet_pton(AF_INET6, str, (void*)tmp_ip) != 1) {
        return SAI_STATUS_FAILURE;
    }

    std::copy(std::begin(tmp_ip), std::end(tmp_ip), ip);

    return SAI_STATUS_SUCCESS;
}

inline sai_status_t
str_to_mac(const char* mac_str, sai_mac_t& mac)
{
    uint32_t temp[6];

    if (sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]) != 6) {
        return SAI_STATUS_FAILURE;
    }

    std::copy(std::begin(temp), std::end(temp), std::begin(mac));

    return SAI_STATUS_SUCCESS;
}

inline void
str_to_uint8(const char* str, uint8_t* buf, uint32_t size)
{
    uint32_t i;
    uint8_t a, b;
    for (i = 0; i < size; i++) {
        int j = i * 2;
        if (str[j] >= 'a') {
            a = str[j] - 'a' + 10;
        } else {
            a = str[j] - '0';
        }
        if (str[j + 1] >= 'a') {
            b = str[j + 1] - 'a' + 10;
        } else {
            b = str[j + 1] - '0';
        }
        buf[i] = (a << 4) + b;
    }
}

#endif
