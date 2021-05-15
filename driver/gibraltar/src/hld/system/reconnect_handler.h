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

#ifndef __RECONNECT_HANDLER_H__
#define __RECONNECT_HANDLER_H__

#include "hld_types_fwd.h"
#include "reconnect_metadata.h"
#include "system/la_mac_port_base.h"

/// @file
/// @brief Leaba device reconnect handler.
///
/// Internal implementation of device reconnect.
/// During normal operation, 'reconnect_handler' maintains reconnect metadata which is written to on-device non volatile memory.
/// During reconnect, the reconnect metadata is loaded from device and the state of 'la_device' is restored.
///
/// @note Currently, only reconnect to a FABRIC device is supported.

namespace silicon_one
{

class reconnect_handler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit reconnect_handler(const la_device_impl_wptr& device);
    reconnect_handler() = default;

    la_status pre_initialize_ifgs();

    const la_device_impl* get_device() const;

    /// @brief Write initial metadata to device.
    la_status initialize();

    /// @brief Reconnect to a possibly online device.
    la_status reconnect(bool ignore_in_flight);

    /// @brief Check whether reconnect() is in progress.
    bool is_reconnect_in_progress() const;

    /// @brief Update that an API call is in progress.
    la_status start_transaction(const char* name)
    {
        return (m_store_to_device_enabled ? start_transaction_core(name) : LA_STATUS_SUCCESS);
    }

    la_status start_transaction_core(const char* name);

    /// @brief Update that an API call is completed.
    la_status end_transaction()
    {
        return (m_store_to_device_enabled ? end_transaction_core() : LA_STATUS_SUCCESS);
    }

    la_status end_transaction_core();

    /// @brief Update SDK device id
    la_status update_device_id(la_device_id_t device_id);

    /// @brief Update init phase
    la_status update_init_phase(la_device::init_phase_e init_phase);

    /// @brief Update metadata for a bool or int device properties
    la_status update_device_property(la_device_property_e property, int val);

    /// @brief Add metadata for a fabric mac port.
    ///
    /// Operation succeedes if metadata does not exist and fails if otherwise.
    la_status add_mac_port(const la_mac_port_base_wcptr& fabric_mac_port);

    /// @brief Update an attribute for existing fabric mac port's metadata.
    ///
    /// Operation succeedes if metadata exists and fails if otherwise.
    la_status update_mac_port_attr(const mac_pool_port_wcptr& port, reconnect_metadata::fabric_mac_port::attr_e attr, uint8_t val);

    /// @brief Update an attribute for existing fabric mac port's metadata.
    ///
    /// Operation succeedes if metadata exists and fails if otherwise.
    la_status update_mac_port_state(const mac_pool_port_wcptr& port);

    /// @brief Remove metadata for a fabric mac port.
    la_status remove_mac_port(const la_mac_port_base_wcptr& fabric_mac_port);

    /// @brief Add metadata for a fabric port.
    ///
    /// Operation succeedes if an entry does not exist and fails if otherwise.
    la_status add_fabric_port(const la_fabric_port_wcptr& port);

    /// @brief Remove metadata for a fabric mac port.
    la_status remove_fabric_port(const la_fabric_port_wcptr& port);

    /// @brief Update serdes mapping
    la_status update_serdes_mapping(la_slice_id_t slice_id,
                                    la_ifg_id_t ifg_id,
                                    la_serdes_direction_e direction,
                                    std::vector<la_uint_t> serdes_mapping_vec);

    /// @brief Update serdes polarity inversion.
    la_status update_serdes_polarity_inversion(la_slice_id_t slice_id,
                                               la_ifg_id_t ifg_id,
                                               la_uint_t serdes_id,
                                               la_serdes_direction_e direction,
                                               bool invert);

    /// @brief Add or update serdes parameter
    la_status update_serdes_parameter(const mac_pool_port_wcptr& port,
                                      la_uint_t serdes_idx,
                                      la_mac_port::serdes_param_stage_e stage,
                                      la_mac_port::serdes_param_e param,
                                      la_mac_port::serdes_param_mode_e mode,
                                      int32_t value);

    /// @brief Clear serdes parameter
    la_status clear_serdes_parameter(const mac_pool_port_wcptr& port,
                                     la_uint_t serdes_idx,
                                     la_mac_port::serdes_param_stage_e stage,
                                     la_mac_port::serdes_param_e parameter);

    /// @brief Update whether fe_fabric_reachability is enabled.
    la_status update_fe_fabric_reachability_enabled(bool enabled);

    /// @brief Update the minimum number of links per LC
    la_status update_minimum_fabric_links_per_lc(la_device_id_t device_id, size_t num_links);

    // These can be removed when moving to c++17 since then we get some
    // language support for new on overaligned types. They are here because the
    // embedded reconnect_metadata has 64-byte alignment requirement for pci
    // performance optimization reasons, so this class should be allocated with
    // 64-byte alignment (pre-c++17, the compiler only takes care of the
    // internal padding).
    static void* operator new(size_t nbytes);
    static void operator delete(void* p);

private:
    la_device_impl_wptr m_device;
    ll_device_sptr m_ll_device;

    // Dword offset of metadata in CSS memory
    enum { CSS_MEMORY_METADATA_BASE = (size_t)la_css_memory_layout_e::RECONNECT_METADATA / 4 };
    lld_memory_scptr m_css_memory;

    // Mirror of the fixed size portion of reconnect metadata that is stored on device
    reconnect_metadata m_metadata;

    // Dynamic vector of serdes parameters that is stored to device as a flat array
    // Serdes parameters are either added or updated, never removed. Existing entries are not moved within the vector.
    std::vector<reconnect_metadata::serdes_parameter> m_serdes_parameters;

    size_t m_in_flight_nesting_level;
    bool m_reconnect_in_progress;
    bool m_store_to_device_enabled;

    la_status load_from_device(bool ignore_in_flight);
    la_status store_to_device(const uint32_t* in_val, size_t first_dword, size_t count);

    template <typename field_type>
    la_status store_to_device(const field_type& field)
    {
        uintptr_t off = (uintptr_t)&field - (uintptr_t)&m_metadata;
        if (off >= sizeof(m_metadata)) {
            return LA_STATUS_EOUTOFRANGE; // address is outside of m_metadata
        }
        size_t first_dword = off >> 2;
        size_t last_dword = (off + sizeof(field) - 1) >> 2;
        size_t count = last_dword - first_dword + 1;
        uint32_t* in_val = ((uint32_t*)&m_metadata) + first_dword;

        return store_to_device(in_val, first_dword, count);
    }

    la_status store_to_device(size_t i, const reconnect_metadata::serdes_parameter& param);

    la_status get_fabric_mac_port_index_by_mac_port(const la_mac_port_base_wcptr& port,
                                                    size_t& out_index,
                                                    bool& out_entry_exists) const;
    la_status get_fabric_mac_port_index_by_pool_port(const mac_pool_port_wcptr& port,
                                                     size_t& out_index,
                                                     bool& out_entry_exists) const;
    la_status get_fabric_mac_port_index_by_serdes(la_slice_id_t slice,
                                                  la_ifg_id_t ifg,
                                                  la_uint_t first_serdes,
                                                  size_t& out_index,
                                                  bool& out_entry_exists) const;

    // Restore mac_port attribute, attribute value is taken from 'metadata' argument.
    la_status restore_mac_port_attribute(const la_mac_port_wptr& port,
                                         const reconnect_metadata::fabric_mac_port& metadata,
                                         reconnect_metadata::fabric_mac_port::attr_e attr);

    // top-level restore, called with write-to-HW disabled
    la_status restore();

    la_status restore_device_properties();
    la_status restore_init_phase();
    la_status restore_fabric_mac_ports();
    la_status restore_fabric_mac_port(const reconnect_metadata::fabric_mac_port& metadata);
    la_status restore_fe_fabric_reachability();
    la_status restore_minimum_fabric_links_per_lc();
    la_status restore_serdes_parameters();
    la_status restore_mac_port_regs();

    la_status enable_interrupts();

    void log_metadata();

    la_status do_update_or_clear_serdes_parameter(const mac_pool_port_wcptr& port,
                                                  la_uint_t serdes_idx,
                                                  la_mac_port::serdes_param_stage_e stage,
                                                  la_mac_port::serdes_param_e parameter,
                                                  la_mac_port::serdes_param_mode_e mode,
                                                  int32_t value,
                                                  bool clear);
};

} // namespace silicon_one
#endif
