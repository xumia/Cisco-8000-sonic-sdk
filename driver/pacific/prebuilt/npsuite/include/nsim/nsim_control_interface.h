// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NSIM_CONTROL_INTERFACE_H__
#define __NSIM_CONTROL_INTERFACE_H__

#include <string>
#include <list>

#include "utils/nsim_bv.h"
#include "nsim_packet_statistics.h"
#include "nsim_port_config.h"

namespace nsim
{

/// nsim_core source location information.
///
/// Provides scope (containing action/control/table), file name and line number for a stack frame.
struct nsim_source_location_info_t {
    std::string m_scope;
    std::string m_file_name;
    unsigned int m_line_number{};
};

#ifndef SWIG // avoid redefinition of 'PyObject* _wrap_to_string(PyObject*, PyObject*)'
static inline std::string
to_string(const nsim_source_location_info_t& s)
{
    return "(scope=" + s.m_scope + ", file=" + s.m_file_name + ", line=" + std::to_string(s.m_line_number) + ")";
}
#endif

typedef enum {
    OVERSUBSCRIBED_INTERFACES_DETECTION_DISABLED = 0,
    OVERSUBSCRIBED_INTERFACES_DETECTION_WARN,
    OVERSUBSCRIBED_INTERFACES_DETECTION_DROP
} oversubscribed_interfaces_detection_mode_e;

typedef void (*port_state_change_cb_t)(size_t /* slice */, size_t /* ifg */, size_t /* pif */, bool /* is_up */, void* opaque);
typedef void (*port_config_change_cb_t)(const nsim_port_config_t, void* opaque);

class packet_statistics_filter_map_t
{
    uint32_t value;

public:
    packet_statistics_filter_map_t(uint32_t v) : value(v)
    {
    }

    void operator|=(const packet_statistics_filter_map_t& other)
    {
        value |= other.value;
    }

    bool operator&(const packet_statistics_filter_map_t& other) const
    {
        return (value & other.value) != 0;
    }

    bool operator!=(const packet_statistics_filter_map_t& other) const
    {
        return value != other.value;
    }
};

const packet_statistics_filter_map_t PACKET_STATISTICS_NO_FILTERS = packet_statistics_filter_map_t(0);
const packet_statistics_filter_map_t PACKET_STATISTICS_INCLUDE_HW_NPL = packet_statistics_filter_map_t(1);
const packet_statistics_filter_map_t PACKET_STATISTICS_INVALID_FILTER = packet_statistics_filter_map_t(1 << 30);

class nsim_control_interface
{
public:
    virtual ~nsim_control_interface()
    {
    }

    /// @brief Check if automatic step mode is enabled
    ///
    /// @return Returns true if automatic step mode is enabled
    virtual bool is_nsim_standalone_mode() = 0;

    /// @brief Step the simulation one cycle forward.
    ///
    /// Evaluates the next statement to be executed, and advances the current statement location.
    ///
    /// @return true if step completed successfully, false otherwise.
    ///
    /// @see step_macro
    virtual bool step() = 0;

    /// @brief Step the simulation one macro forward.
    ///
    /// Evaluates the current macro, stopping one step before end of the macro.
    /// Invoking #step() after #step_macro() will load the next macro.
    ///
    /// @return true if macro completed successfully, false otherwise.
    ///
    /// @see step
    virtual bool step_macro() = 0;

    /// @brief Simulate one packet.
    ///
    /// Evaluates the current packet execution, stopping one step before the packet finishes.
    /// Invoking #step() after #step_macro() will load the next macro.
    ///
    /// @return true if macro completed successfully, false otherwise.
    ///
    /// @see step
    virtual bool step_packet() = 0;

    /// @brief Reset state back to that of the LBR.
    ///
    /// @return true if dump was successful, false otherwise.
    virtual bool reset_state(void) = 0;

    /// @brief Get current packet id value. Not supported in multithreaded mode.
    ///
    /// @return current packet id value, 0 if no packet was injected otherwise.
    virtual unsigned get_current_packet_id() const = 0;

    /// @brief Enable or disable Packet DMA support
    ///
    /// @param[in]  enable              Parameter, true or false
    ///                                 indicating if the packet DMA should be enabled
    virtual void packet_dma_enable(bool enable) = 0;
    /// @brief Check if Packet DMA support is enabled
    ///
    /// @return true Packet DMA support is enabled, false otherwise.
    virtual bool is_packet_dma_enabled() = 0;

    /// @brief Return currently simulated device name
    ///
    /// @return device name string
    virtual std::string get_device_name() = 0;

    /// @brief Return currently simulated device revision
    ///
    /// @return device revision string
    virtual std::string get_device_revision() = 0;

    /// @brief Return current npu_host time in simulated npu_host ticks
    virtual uint32_t get_current_npuh_time() = 0;

    /// @brief Returns the number of jobs currently waiting to be processed.
    /// A job is either a packet, RMEP event, MP event or learning event.
    virtual size_t get_input_queue_size() = 0;
    /// @brief Returns the number of packets in the output queue.
    virtual size_t get_output_queue_size() = 0;

    /// @brief Check if port interface is up for specified slice, ifg and pif.
    ///
    /// @return Returns true if port interface is up.
    virtual bool is_port_up(size_t slice_id, size_t ifg, size_t pif) = 0;

    /// @brief Register user callback to get notifications about port state changes
    ///
    /// @param[in] cb       User callback pointer
    /// @param[in] opaque   Opaque user data
    ///
    /// @return Returns true if successfully registered, false if already registered.
    virtual bool register_port_state_change_cb(port_state_change_cb_t cb, void* opaque = nullptr) = 0;

    /// @brief Unregister user callback
    ///
    /// @param[in] cb       User callback pointer
    /// @param[in] opaque   Opaque user data
    ///
    /// @return Returns true if successfully unregistered, false if not registered a all.
    virtual bool unregister_port_state_change_cb(port_state_change_cb_t cb, void* opaque = nullptr) = 0;

    /// @brief Return miscellaneous port information.
    ///
    /// @return Returns true if port information was found.
    virtual nsim_port_pif_config_t get_port_config(size_t slice_id, size_t ifg, size_t pif) = 0;

    /// @brief Register user callback to get notifications about port config changes
    ///
    /// @param[in] cb       User callback pointer
    /// @param[in] opaque   Opaque user data
    ///
    /// @return Returns true if successfully registered, false if already registered.
    virtual bool register_port_config_change_cb(port_config_change_cb_t cb, void* opaque = nullptr) = 0;

    /// @brief Unregister user callback
    ///
    /// @param[in] cb       User callback pointer
    /// @param[in] opaque   Opaque user data
    ///
    /// @return Returns true if successfully unregistered, false if not registered a all.
    virtual bool unregister_port_config_change_cb(port_config_change_cb_t cb, void* opaque = nullptr) = 0;

};
} // namespace nsim

#endif
