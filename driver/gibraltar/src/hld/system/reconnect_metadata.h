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

#ifndef __RECONNECT_METADATA_H__
#define __RECONNECT_METADATA_H__

#include "api/system/la_css_memory_layout.h"
#include "api/system/la_device.h"
#include "api/system/la_mac_port.h"
#include "api/types/la_system_types.h"
#include "hld_types.h"
#include <cstdlib>

namespace silicon_one
{

// This struct is written to PCIe memory at a 64-byte aligned offset.
struct alignas(64) reconnect_metadata
{
    // in_flight is updated more frequently than the other fields.
    // Must be at 64byte-aligned offset and size for optimal PCIe performance.
    enum { API_IN_FLIGHT_MAGIC = 0xFACADE };
    struct in_flight_s {
        // An opertation is in-flight:
        //   magic == API_IN_FLIGHT_MAGIC
        //   name is the 'name' argument of the outermost start_transaction() call.
        // No operation is in-flight:
        //   magic == 0
        uint32_t magic;
        char name[60];
    } in_flight;

    static_assert(sizeof(in_flight) <= 64, "Not PCIe friendly");

    // Metadata entries that are written to device as a single block.
    enum { METADATA_START_MAGIC = 0xCAFECAFE, METADATA_END_MAGIC = 0xBAADA555 };

    uint32_t magic_start;

    // Device ID
    la_device_id_t device_id;

    // Device init phase
    la_device::init_phase_e init_phase;

    // Fabric element reachability, value and "is_set"
    struct fe_fabric_reachability_enabled_s {
        uint32_t value : 1;
        uint32_t is_set : 1;
    } fe_fabric_reachability_enabled;

    // Minimum fabric links per LC
    static constexpr size_t MAX_DEVICES = 288; // la_device_impl::MAX_DEVICES cannot be used because of cyclic include
    struct lc_to_min_links_s {
        uint8_t value : 7;
        uint8_t is_set : 1;
    } lc_to_min_links[MAX_DEVICES];

    // Bool and integer properties
    bool bool_device_properties[(int)la_device_property_e::NUM_BOOLEAN_PROPERTIES];
    uint32_t int_device_properties[(int)la_device_property_e::NUM_INTEGER_PROPERTIES];

    // Mac ports
    struct fabric_mac_port {
        // Arguments for create_fabric_mac_port() and create_fabric_port()
        struct create_args_s {
            uint32_t valid : 1;
            uint32_t slice_id : 3;
            uint32_t ifg_id : 1;
            uint32_t first_serdes_id : 6;
            uint32_t last_serdes_id : 6;
            uint32_t speed : 4;
            uint32_t rx_fc_mode : 2;
            uint32_t tx_fc_mode : 2;
            uint32_t has_fabric_port : 1;
        } create_args;

        // mac_port attributes that were modified after a port was created.
        // The attributes cover all explicit mac_port setters API + the state of mac_port's state machine.
        enum class attr_e {
            SPEED = 0,
            RX_FC_MODE,
            TX_FC_MODE,
            FEC_MODE,
            FEC_BYPASS_MODE,
            SERDES_TUNING_MODE,
            SERDES_CONTINUOUS_TUNING_ENABLED,
            LINK_MANAGEMENT_ENABLED,
            LOOPBACK_MODE,
            PCS_TEST_MODE,
            PMA_TEST_MODE,
            LAST = PMA_TEST_MODE
        };

        uint32_t is_attr_set;

        // 'uint8_t' is large enough to hold any of the attributes.
        using attr_t = uint8_t;
        attr_t attr[(size_t)attr_e::LAST + 1];

        // mac port state
        la_mac_port::state_e state;
    } fabric_mac_ports[NUM_FABRIC_PORTS_IN_DEVICE];

    struct ifg_serdes_info_desc {
        // per IFG
        uint8_t is_rx_source_set : 1;
        uint8_t is_anlt_order_set : 1;

        // per serdes in IFG
        struct serdes_info_desc {
            uint16_t rx_source : 6;
            uint16_t anlt_order : 6;
            uint16_t rx_polarity_inversion : 1;
            uint16_t is_rx_polarity_inversion_set : 1;
            uint16_t tx_polarity_inversion : 1;
            uint16_t is_tx_polarity_inversion_set : 1;
        } serdes_info[MAX_NUM_SERDES_PER_IFG];
    } ifg_serdes_info[ASIC_MAX_SLICES_PER_DEVICE_NUM][NUM_IFGS_PER_SLICE];

    static_assert(sizeof(ifg_serdes_info_desc::serdes_info_desc) == sizeof(uint16_t), "bad size");

    char sdk_version[128];

    uint32_t serdes_parameters_n; // The size of serdes parameters array
    uint32_t magic_end;           // This is the last dword located at fixed offset

    // Base of dynamic array of serdes parameters. Initial size is 0.
    struct serdes_parameter {
        // key - mac port location
        uint32_t slice_id : 3;
        uint32_t ifg_id : 1;
        uint32_t first_serdes_id : 6;

        // key - serdes parameter
        uint32_t serdes_idx : 6;
        uint32_t stage : 4;
        uint32_t parameter : 8;

        // value
        uint32_t mode : 2;
        uint32_t is_set : 1;
        uint32_t reserved : 1;
        int32_t value;
    } serdes_parameters[0];
    static_assert(sizeof(struct serdes_parameter) == 2 * sizeof(uint32_t), "bad size");
};

static_assert(sizeof(reconnect_metadata) <= (size_t)la_css_memory_layout_e::RECONNECT_METADATA_SIZE_MAX,
              "Size does not fit in CSS memory");
static_assert(sizeof(reconnect_metadata) % 4 == 0, "Must be DWORD aligned");
static_assert(sizeof(reconnect_metadata::serdes_parameter) % 4 == 0, "Must be DWORD aligned");
static_assert(NUM_FABRIC_PORTS_IN_DEVICE == 108, "");

static constexpr uint32_t MAX_NUM_SERDES_PARAMETERS = NUM_FABRIC_PORTS_IN_DEVICE * NUM_SERDES_PER_IFG
                                                      * ((uint32_t)la_mac_port::serdes_param_stage_e::LAST + 1)
                                                      * ((uint32_t)la_mac_port::serdes_param_e::LAST + 1);

std::string to_string(const reconnect_metadata& metadata);
std::string to_string(const reconnect_metadata::fabric_mac_port& metadata);
std::string to_string(reconnect_metadata::fabric_mac_port::attr_e attr);
std::string to_string(const reconnect_metadata::serdes_parameter& param);

} // namespace silicon_one
#endif
