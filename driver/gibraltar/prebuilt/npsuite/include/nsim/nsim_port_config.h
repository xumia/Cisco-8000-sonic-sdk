// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NSIM_PORT_CONFIG_H__
#define __NSIM_PORT_CONFIG_H__

#include "utils/list_macros.h"
#include <string.h>
#include <array>
#include <iostream>

typedef struct nsim_port_info_lane_t_ {
    //
    // FYI default comparisons of structs is only available in c++20 with the "spaceship" operator "<=>"
    // Until then we have to do this:
    //
    bool operator==(const struct nsim_port_info_lane_t_& rhs) const
    {
        return (lane_base == rhs.lane_base) && (lane_size == rhs.lane_size);
    }
    bool operator!=(const struct nsim_port_info_lane_t_& rhs) const
    {
        return (lane_base != rhs.lane_base) || (lane_size != rhs.lane_size);
    }
    friend std::ostream& operator<<(std::ostream& os, const struct nsim_port_info_lane_t_& s);

    //
    // If this PIF is part of a lane bundle, what is the first pif within that bundle.
    // e.g. if pif 2 and 3 are part of a pair, and we query PIF 2 or 3, we will return a
    // lane_base of 2 and lane_size of 2. lane_size is typically 1, 2, 4, or 8.
    //
    size_t lane_base{};
    size_t lane_size{};
} nsim_port_info_lane_t;

inline std::ostream&
operator<<(std::ostream& os, const struct nsim_port_info_lane_t_& s)
{
    return os << "lane_base = " << s.lane_base << " lane_size = " << s.lane_size;
}

struct nsim_port_pif_config_t_;

typedef struct nsim_port_pif_config_t_ {
    //
    // Comparison operators are needed to avoid sending repeat data to the client in notifications.
    //
    bool operator==(const struct nsim_port_pif_config_t_& rhs) const
    {
        return (pif == rhs.pif) && (tx == rhs.tx) && (rx == rhs.rx);
    }
    bool operator!=(const struct nsim_port_pif_config_t_& rhs) const
    {
        return (pif != rhs.pif) || (tx != rhs.tx) || (rx != rhs.rx);
    }
    friend std::ostream& operator<<(std::ostream& os, const struct nsim_port_pif_config_t_& s);

    //
    // Used with get_port_config in python to act as a return code.
    //
    bool valid{};
    //
    // Which PIF is being reported.
    //
    size_t pif{};
    //
    // Config per direction
    //
    nsim_port_info_lane_t tx{};
    nsim_port_info_lane_t rx{};
} nsim_port_pif_config_t;

inline std::ostream&
operator<<(std::ostream& os, const struct nsim_port_pif_config_t_& s)
{
    if (s.valid) {
        return os << "pif = " << s.pif << " tx = {" << s.tx << "}, rx = {" << s.rx << "}";
    }
    return os << "invalid";
}

typedef struct {
    //
    // Which slice and ifg the following port config pertains to. As a change in config
    // for one port will likely result in a change for others, it seems a good idea to
    // send all pif config in one go to minimize change in the client.
    //
    size_t slice;
    size_t ifg;
    std::vector<nsim_port_pif_config_t> pif_config;
} nsim_port_config_t;

#endif
