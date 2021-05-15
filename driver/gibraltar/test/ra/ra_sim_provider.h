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

#ifndef __RA_SIM_PROVIDER_H__
#define __RA_SIM_PROVIDER_H__

#include "sim_provider/sim_provider.h"

namespace silicon_one
{

/// @brief sim_provider interface implementation for RTL simulation.
class ra_sim_provider : public sim_provider
{
public:
    ra_sim_provider() = default;

    // sim_provider API
    bool inject_packet(const sim_packet_info_desc& packet_desc, const sim_initial_metadata_map_t& initial_values = {}) override;
    bool step_packet() override;
    sim_packet_info_desc get_packet() override;
    sim_packet_info_desc_vec_t get_packets() override;

    /// @brief Advance simulator.
    /// Advance simulation time by number of iterations.
    ///
    /// @param[in]  delay           Delay ns.
    /// @param[in]  blocking        Whether call is blocking.
    void step(size_t delay, bool blocking);

    /// @brief Advance simulator till condition is met.
    /// Condition: (read(address) ^ value) & mask == 0.
    ///
    /// @param[in]  address         Absolute address (44 bits 12:block + 32:memory).
    /// @param[in]  value           Up to 16 bits value to compare to.
    /// @param[in]  mask            Up to 16 bits mask - 1 means bit will be checked.
    /// @param[in]  iterations      Number of polling iterations, 500ns each.
    /// @param[in]  blocking        Whether call is blocking.
    void poll(size_t address, size_t val, size_t mask, size_t iterations, bool blocking);

    /// @brief Flush all in-flight instructions.
    void flush();

    /// @brief Runs simulations as long as there is traffic in one of the slices.
    void poll_end_of_traffic();

    /// @brief Stops RTL simulation
    void stop_simulation();

    /// @brief Re-Inject the last packet/s (no new packets configurations)
    void reinject_last_packet();

    /// @brief Pop head of output packets queue
    void pop_packet();

    /// @brief Allow to change reg-access: default (0) / backdoor (1) / frontdoor (2)
    void force_reg_access_method(size_t reg_access_type);

private:
    // forbid copy
    ra_sim_provider(const ra_sim_provider&);
    ra_sim_provider& operator=(const ra_sim_provider&);

private:
    // Queue of result packets
    sim_packet_info_desc_vec_t m_out_packets;
};

} // namespace silicon_one

#endif // __RA_SIM_PROVIDER_H__
