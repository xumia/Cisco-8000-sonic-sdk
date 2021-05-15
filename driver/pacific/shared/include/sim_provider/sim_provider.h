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

#ifndef __SIM_PROVIDER_H__
#define __SIM_PROVIDER_H__

#include <map>
#include <string>
#include <vector>

namespace silicon_one
{

struct sim_packet_info_desc {
    std::string packet; ///< Packet bytes in hex form.
    size_t slice;       ///< Slice packet is ingressing/egressing on.
    size_t ifg;         ///< Physical interface.
    size_t pif;         ///< Port.
};

typedef std::vector<sim_packet_info_desc> sim_packet_info_desc_vec_t;
typedef std::map<std::string /* key=<npl_metadata_name> */, std::string /* val=<value_in_hex_format */> sim_initial_metadata_map_t;

/// @brief Interface of Pacific Simulation Control.
class sim_provider
{
public:
    sim_provider()
    {
    } // For serialization purposes only.
    // D'tor
    virtual ~sim_provider()
    {
    }

    /// @brief Inject packet to simulator.
    ///
    /// Packet is not simulated, but rather stored on the ingress packet queue for the device.
    ///
    /// @param[in]  packet_desc         Packet descriptor.
    /// @param[in]  initial_values      Set initial values to NPL metadata per packet
    ///
    /// @return true if packet injected successfully, false otherwise.
    virtual bool inject_packet(const sim_packet_info_desc& packet_desc, const sim_initial_metadata_map_t& initial_values = {}) = 0;

    /// @brief Step packet through device.
    ///
    /// Steps packet through device, from ingress to egress.
    /// If successful, packet on egress can be acquired using #get_packet or #get_packets.
    ///
    /// @retval true if packet simulated successfully, false otherwise.
    virtual bool step_packet() = 0;

    /// @brief Get single forwarded packet for last simulated packet from output queue.
    ///
    /// @retval Packet descriptor.
    virtual sim_packet_info_desc get_packet() = 0;

    /// @brief Get all forwarded packets for last simulated packets.
    ///
    /// In case of multicast or mirroring, more than one packet will be returned.
    ///
    /// @retval Vector of packet descriptors.
    virtual sim_packet_info_desc_vec_t get_packets() = 0;
};

} // namespace silicon_one

#endif // __SIM_PROVIDER_H__
