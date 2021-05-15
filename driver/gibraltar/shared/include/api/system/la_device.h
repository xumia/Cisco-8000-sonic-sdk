// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_DEVICE_H__
#define __LA_DEVICE_H__

#include <memory>
#include <vector>

#include "api/types/la_acl_types.h"
#include "api/types/la_bfd_types.h"
#include "api/types/la_cgm_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_event_types.h"
#include "api/types/la_fe_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_lb_types.h"
#include "api/types/la_limit_types.h"
#include "api/types/la_lpts_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_notification_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"
#include "api/types/la_tunnel_types.h"

#include "api/npu/la_acl.h"
#include "api/npu/la_acl_command_profile.h"
#include "api/npu/la_acl_group.h"
#include "api/npu/la_acl_key_profile.h"
#include "api/npu/la_asbr_lsp.h"
#include "api/npu/la_bfd_session.h"
#include "api/npu/la_copc.h"
#include "api/npu/la_counter_set.h"
#include "api/npu/la_destination_pe.h"
#include "api/npu/la_ecmp_group.h"
#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_forus_destination.h"
#include "api/npu/la_l3_protection_group.h"
#include "api/npu/la_lpts.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_og_lpts_application.h"
#include "api/npu/la_pbts_group.h"
#include "api/npu/la_pcl.h"
#include "api/npu/la_rate_limiter_set.h"
#include "api/npu/la_security_group_cell.h"
#include "api/npu/la_stack_port.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_te_tunnel.h"
#include "api/npu/la_vrf_redirect_destination.h"
#include "api/npu/la_vxlan_next_hop.h"
#include "api/qos/la_meter_markdown_profile.h"
#include "api/qos/la_meter_profile.h"
#include "api/qos/la_meter_set.h"
#include "api/system/la_erspan_mirror_command.h"
#include "api/system/la_mac_port.h"
#include "api/system/la_pbts_map_profile.h"
#include "api/system/la_system_port.h"
#include "api/tm/la_output_queue_scheduler.h"

#include "apb/apb_types.h"

/// @file
/// @brief Leaba device API-s.
///
/// Defines API-s for managing Devices.

/// @addtogroup SYSTEM
/// @{

/// @brief Create a #silicon_one::la_device object.
///
/// This API creates a #silicon_one::la_device, and performs minimal initialization.
/// Following creation, the device is not yet fully initialized, but rather ready to start
/// receiving configurations.
///
/// See #silicon_one::la_device::initialize for more details.
///
///
/// @param[in]  device_path            Path to device.
/// @param[in]  dev_id                 System-wide, unique Device ID to use.
/// @param[out] out_device             #silicon_one::la_device* to populate.
///
/// @retval     LA_STATUS_SUCCESS      Operation completed successfully. out_device contains the created device.
/// @retval     LA_STATUS_EEXIST       Device with given ID already exists.
/// @retval     LA_STATUS_EINVAL       Device ID is out of range.
/// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
la_status la_create_device(const char* device_path, la_device_id_t dev_id, silicon_one::la_device*& out_device);

/// @brief Create a #silicon_one::la_device object.
///
/// This API creates a #silicon_one::la_device, and performs minimal initialization.
/// Following creation, the device is not yet fully initialized, but rather ready to start
/// receiving configurations.
///
/// See #silicon_one::la_device::initialize for more details.
///
///
/// @param[in]  device_path            Path to device.
/// @param[in]  dev_id                 System-wide, unique Device ID to use.
/// @param[in]  platform_cbs           Platform-specific operations.
/// @param[out] out_device             #silicon_one::la_device* to populate.
///
/// @retval     LA_STATUS_SUCCESS      Operation completed successfully. out_device contains the created device.
/// @retval     LA_STATUS_EEXIST       Device with given ID already exists.
/// @retval     LA_STATUS_EINVAL       Device ID is out of range.
/// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
la_status la_create_device(const char* device_path,
                           la_device_id_t dev_id,
                           const silicon_one::la_platform_cbs& platform_cbs,
                           silicon_one::la_device*& out_device);

/// @brief Destroy an existing #silicon_one::la_device object.
///
/// All associated data structures are freed.
/// This function has no effect on the underlying physical device.
/// The given object must not be accessed after this function returns.
///
/// @param[in]  device              Device to be destroyed.
///
/// @retval     LA_STATUS_SUCCESS   Device has been destroyed successfully.
/// @retval     LA_STATUS_EINVAL    Device is corrupt or invalid.
/// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
la_status la_destroy_device(silicon_one::la_device* device);

/// @brief Create a #silicon_one::la_device object by restoring its state from a file.
///
/// This API creates a #silicon_one::la_device and restores its state from a file.
/// This function has no effect on the underlying physical device.
/// Device must be disconnected first, @see #silicon_one::la_device::warm_boot_disconnect
///
/// @param[in]  device_path            Path to device.
/// @param[in]  warm_boot_file         Path to a file where to store the device's state.
/// @param[out] out_device             #silicon_one::la_device* to populate.
///
/// @retval     LA_STATUS_SUCCESS          Operation completed successfully. out_device contains the created device.
/// @retval     LA_STATUS_EINVAL           Device Path and/or Warm Boot File are corrupted, invalid or not existing, or
///                                        incompatible SDK WB versions.
/// @retval     LA_STATUS_EEXIST           Device is already connected.
/// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
la_status la_warm_boot_restore(const char* device_path, const char* warm_boot_file, silicon_one::la_device*& out_device);

/// @brief Create a #silicon_one::la_device object by restoring its state from a file.
///
/// This API creates a #silicon_one::la_device and restores its state from a file.
/// This function has no effect on the underlying physical device.
/// Device must be disconnected first, @see #silicon_one::la_device::warm_boot_disconnect
///
/// @param[in]  device_path            Path to device.
/// @param[in]  warm_boot_file         Path to a file where to store the device's state.
/// @param[in]  platform_cbs           Platform-specific operations.
/// @param[out] out_device             #silicon_one::la_device* to populate.
///
/// @retval     LA_STATUS_SUCCESS      Operation completed successfully. out_device contains the created device.
/// @retval     LA_STATUS_EINVAL       Device Path and/or Warm Boot File are corrupted, invalid or not existing, or
///                                    incompatible SDK WB versions.
/// @retval     LA_STATUS_EEXIST       Device is already connected.
/// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
la_status la_warm_boot_restore(const char* device_path,
                               const char* warm_boot_file,
                               const silicon_one::la_platform_cbs& platform_cbs,
                               silicon_one::la_device*& out_device);

/// @brief Save an existing #silicon_one::la_device object's state to a file and destroy it.
///
/// If asked for all associated data structures are freed.
/// This function has no effect on the underlying physical device.
/// Device shall be reconncted after restoration, @see #silicon_one::la_device::warm_boot_reconnect
///
/// @param[in]  device                 Device to be destroyed.
/// @param[in]  warm_boot_file         Path to a file where to restore the device's state from.
/// @param[in]  free_objects           if true, la_device, its associated data structred and all objects will be freed.
///
/// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
/// @retval     LA_STATUS_EINVAL       Device and/or Warm Boot File are corrupted/invalid or device is still connected.
/// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
la_status la_warm_boot_save_and_destroy(silicon_one::la_device* device, const char* warm_boot_file, bool free_objects);

/// @brief Save an existing #silicon_one::la_device object's state to a file and destroy it.
///        The file is saved in the target SDK warm-boot revision format to allow SDK version rollback.
///
/// If asked for all associated data structures are freed.
/// This function has no effect on the underlying physical device.
/// Device shall be reconncted after restoration, @see #silicon_one::la_device::warm_boot_reconnect
///
/// @param[in]  device                 Device to be destroyed.
/// @param[in]  target_sdk_version     Target rollback SDK version.
/// @param[in]  warm_boot_file         Path to a file where to restore the device's state from.
/// @param[in]  free_objects           if true, la_device, its associated data structred and all objects will be freed.
///
/// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
/// @retval     LA_STATUS_EINVAL       Device and/or Warm Boot File are corrupted/invalid or device is still connected, or
///                                    incompatible SDK WB versions.
/// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
la_status la_warm_boot_rollback_save_and_destroy(silicon_one::la_device* device,
                                                 std::string target_sdk_version,
                                                 const char* warm_boot_file,
                                                 bool free_objects);

/// @brief Get a #silicon_one::la_device based on device ID.
///
/// @param[in]  dev_id              Device ID.
///
/// @return #silicon_one::la_device*, or nullptr if no device with this ID exists.
silicon_one::la_device* la_get_device(la_device_id_t dev_id);

/// @brief Return Leaba SDK version string.
const char* la_get_version_string();

namespace silicon_one
{

class lld_register;
class lld_memory;
class apb;
class cpu2jtag;
class la_info_phy_handler;

using lld_register_scptr = std::shared_ptr<const lld_register>;
using lld_memory_scptr = std::shared_ptr<const lld_memory>;

class la_device : public la_object
{
public:
    /// @name Initialization
    /// @{

    /// @brief Device initialization phase.
    ///
    /// Device bring-up happens in several stages.
    enum class init_phase_e {
        CREATED,  ///< Device has been created but not initialized.
        DEVICE,   ///< Device settings irrespective of topology are applied.
        TOPOLOGY, ///< Topology settings are applied.
    };

    /// @brief Device Fabric Ports mode.
    ///
    /// Device Fabric ports has multiple modes.
    enum class fabric_mac_ports_mode_e {
        E_2x50, ///< 2x50G Fabric Ports.
        E_4x50, ///< 4x50G Fabric Ports.
    };

    /// @brief Set of tests that can be executed by the #diagnostics_test API.
    enum class test_feature_e {
        MEM_BIST,          ///< Memory Built-In Self-Test.
        HBM,               ///< High-Bandwidth Memory.
        MEM_BIST_CHIPLETS, ///< Memory Built-In Self-Test for Chiplets
    };

    /// @brief Set of learn modes.
    enum class learn_mode_e {
        LOCAL,  ///< Local learn.
        SYSTEM, ///< System learn.
    };

    /// @brief SYNC-E recovered clock
    ///
    /// Each SYNC-E output pin has two sources - Primary and Secondary clock to select.
    /// If a primary serdes is not in in sync, the secondary serdes will be used as the recovered clock source.
    enum class synce_clock_sel_e {
        PRIMARY,
        SECONDARY,
    };

    /// @brief Internal error types.
    enum class internal_error_type_e {
        SER,
        OTHER,
    };

    /// @brief Stages in which internal errors can be traced.
    enum class internal_error_stage_e {
        TERMINATION,
        FORWARDING,
        TRANSMIT,
    };

    /// @brief indexes of capabilities values in device capabilities vectors
    enum class device_bool_capability_e { HAS_HBM = 0, LAST = HAS_HBM };

    enum class device_int_capability_e { MATILDA_MODEL = 0, LAST = MATILDA_MODEL };

    enum class device_string_capability_e { LAST = 0 };

    /// @brief Options for #silicon_one::la_device::save_state API.
    ///
    /// Each field selects whether a specific type of register/memory/internal_state should be saved.
    struct save_state_options {
        bool include_all = false;                ///< If set, all memories and registers will be included in the state.
        bool include_config = false;             ///< If set, all config memories and registers will be included in the state.
        bool include_volatile = false;           ///< If set, all volatile memories and registers will be included in the state.
        bool include_counters = false;           ///< If set, all registers that have at least one counter field will be included.
        bool include_status = false;             ///< If set, all registers that have at least one status field will be included.
        bool include_mac_port_serdes = false;    ///< If set, the information will be part of the config option in the state.
        bool include_interrupt_counters = false; ///< if set, interrupt counters will be a included.
        bool reset_on_read
            = false; ///< True is Intrusive. If set, all counters will be reset after read. This flag only affects counters fields.
        bool verbose_subfields = true;            ///< Expands individual fields of each register
        std::vector<std::string> internal_states; ///< Vector of strings representing internal states to store.
                                                  ///< Supported strings:
        ///< "counter" - stores counter_logical_bank usage information.
        ///< "tables"  - stores tables usage information.
        ///< "tcam"    - stores shared tcam db usage information.
    };

    /// @brief Counters for the number of calls to the slow and fast poll functions.
    struct la_heartbeat_t {
        uint64_t slow; ///< Counts the number of calls to the slow poll callbacks.
        uint64_t fast; ///< Counts the number of calls to the fast poll callbacks.
    };

    /// @brief Counters for number of packets written to and read from SMS.
    struct la_sms_packet_counts {
        la_uint_t sms_write_packet_count; ///< Count of packets written to SMS.
        la_uint_t sms_read_packet_count;  ///< Count of packets read from SMS.
    };

    /// @brief Counters for errors in SMS write and Read path.
    struct la_sms_error_counts {
        la_uint64_t total_write_error_count;          ///< Count of errors in SMS write path.
        la_uint64_t cgm_write_error_count;            ///< Count of errors in SMS write path caused by CGM.
        la_uint64_t dram_slice_cgm_write_error_count; ///< Count of errors in SMS write path caused by CGM for DRAM Slice.
        la_uint64_t out_of_bank_write_error_count;    ///< Count of errors due to empty SMS buffer manager.
        la_uint64_t read_error_count;                 ///< Count of read errors or read crc errors
        la_uint64_t read_dont_transmit_count;         ///< Count of read don't transmit.
    };

    /// @brief Watermark values of counters.
    struct la_cgm_watermarks {
        la_uint_t uc_wmk;    ///< Watermark value for unicast counter.
        la_uint_t mc_wmk;    ///< Watermark value for multicast counter.
        la_uint_t ms_uc_wmk; ///< Watermark value for MS-VOQ unicast counter.
        la_uint_t ms_mc_wmk; ///< Watermark value for MS-VOQ multicast counter.
    };

    /// @brief Initialize device up to given phase.
    ///
    /// @param[in]  phase   New initialization phase, see #silicon_one::la_device::init_phase_e
    ///
    /// @return Status code.
    virtual la_status initialize(init_phase_e phase) = 0;

    /// @brief Retrieve the initialization phase of the device.
    ///
    /// @return Initialization phase, see #silicon_one::la_device::init_phase_e.
    virtual init_phase_e get_init_phase() const = 0;

    /// @brief Apply Pacific B0 post-initialize work-arounds.
    ///
    /// This function should only be invoked if instructed so by the SDK team.
    /// It is relevant only for standalone devices, post initialization.
    /// @return #la_status.
    virtual la_status apply_pacific_b0_post_initialize_workarounds() = 0;

    /// @brief Acquire device's master lock.
    ///
    /// @param[in]  blocking  If set, function will block until lock is acquired, otherwise it will give up if lock is already
    /// taken.
    ///
    /// @return #la_status.
    ///
    /// @note Use with care. This API acquires the master device lock manually.
    /// Failure to release this lock in a timely manner (<1ms) may cause system stability issues.
    /// It should only be used for debug purposes, never for production features.
    virtual la_status acquire_device_lock(bool blocking) = 0;

    /// @brief Release device's master lock.
    virtual void release_device_lock() = 0;

    /// @brief Reconnect to an active device.
    ///
    /// During reconnect, all state in la_device is restored.
    ///
    /// @note This API is currently supported only for fabric devices.
    ///
    /// @retval LA_STATUS_SUCCESS   Reconnect completed successfully.
    /// @retval LA_STATUS_ENODEV    Device is not present.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error.
    virtual la_status reconnect() = 0;

    /// @brief Disconnect from an active device.
    ///
    /// Device access is stopped, interrupt handling and internal state machines are stopped as well.
    virtual void disconnect() = 0;

    /// @brief Reconnect a warm-boot restored device.
    ///
    /// Reactivate background activities (i.e. notification, interrupts,..) of a warm-boot restored la_device.
    /// @note This API is currently used for warm-boot, should be invoked after #la_warm_boot_restore
    ///
    /// @retval LA_STATUS_SUCCESS   Reconnect completed successfully.
    /// @retval LA_STATUS_EINVAL    Device is already reconnected.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error.
    virtual la_status warm_boot_reconnect() = 0;

    /// @brief Disconnect from an active device prior warm-boot.
    ///
    /// Deactivate background activities (i.e. notification, interrupts,..)
    /// @note This API is currently used for warm-boot, should be called before #la_warm_boot_save_and_destroy
    ///
    /// @retval LA_STATUS_SUCCESS         Device was disconnected successfully.
    /// @retval LA_STATUS_EINVAL          Device is already disconnected.
    /// @retval LA_STATUS_ENOTINITIALIZED Device did not complete TOPOLOGY initialization phase.
    /// This is a precondtion for #la_warm_boot_save_and_destroy.
    virtual la_status warm_boot_disconnect() = 0;

    /// @brief Retrive the warm boot revision of the base SDK version.
    ///
    /// @note Base SDK is the SDK being upgraded from.
    ///
    /// @retval LA_STATUS_SUCCESS          WB revision retrieved successfully.
    /// @retval LA_STATUS_ENOTINITIALIZED  No warm boot performed.
    /// @retval LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status warm_boot_get_base_revision(la_uint32_t& wb_revision) = 0;

    /// @}
    /// @name General
    /// @{

    /// @brief Return device ID.
    ///
    /// @return Device ID.
    virtual la_device_id_t get_id() const = 0;

    /// @brief Return object attached to this device by oid.
    ///
    /// @param[in]  oid                 object ID of the object queried.
    ///
    /// @return Object queried.
    virtual la_object* get_object(la_object_id_t oid) const = 0;

    /// @brief Return all objects associated with this device.
    ///
    /// @return  vector of all objects.
    virtual std::vector<la_object*> get_objects() const = 0;

    /// @brief Return all objects of given type.
    ///
    /// @param[in]  type                Type of objects to return.
    ///
    /// @return  vector of all objects.
    virtual std::vector<la_object*> get_objects(object_type_e type) const = 0;

    /// @brief Return all objects that depend on the given one.
    ///
    /// This provide a relationship model, returning all objects that use the dependee.
    /// For example, if a #silicon_one::la_l3_ac_port has an #silicon_one::la_counter_set associated
    /// with it, the port is said to depend on the counter.<br>
    /// Objects cannot be destroyed when they have other dependent objects using them.
    ///
    /// @param[in]  dependee     Dependee.
    ///
    /// @return  Vector of all dependent objects.
    virtual std::vector<la_object*> get_dependent_objects(const la_object* dependee) const = 0;

    /// @brief Returns number of objects that depend on the given one.
    ///
    /// @param[in]  dependee     Dependee.
    ///
    /// @return  Returns number of dependent objects.
    virtual la_uint_t get_dependent_objects_count(const la_object* dependee) const = 0;

    /// @brief Return low-level device object.
    ///
    /// @return a low-level device pointer.
    ///
    /// @note Modifying properties through low-level device API-s such as
    ///       register/memory writes, interrupt settings etc should not be done
    ///       on production systems.
    ///       This API is exposed for debug use only.
    virtual ll_device* get_ll_device() const = 0;

    /// @brief Return NPL tables collection.
    ///
    /// @return a device_tables pointer.
    ///
    /// @note Direct access to NPL tables for modification and query
    ///       should not be done on production systems.
    ///       This API is exposed for debug use only.
    virtual const device_tables* get_device_tables() const = 0;

    /// @brief Retrieve device hardware information.
    ///
    /// This includes device revision and part number information.
    ///
    /// @param[out] out_dev_info        Retrieved device information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Device information retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_device_information(la_device_info_t& out_dev_info) const = 0;

    /// @brief Get The Ids of all the Slices which are not DISABLED.
    ///
    /// @retval      slice Id vector.
    virtual const la_slice_id_vec_t& get_used_slices() const = 0;

    /// @brief Get The Ids of all the Slicepairs which are not DISABLED.
    ///
    /// @retval      slice Id vector.
    virtual const la_slice_pair_id_vec_t& get_used_slice_pairs() const = 0;

    /// @brief Get a device's fabric ports mode.
    ///
    /// Fabric Ports mode determines the MAC Ports speed of all Fabric MAC Ports.
    ///
    /// @param[out] out_fabric_mac_ports_mode   Mode to be queried.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_fabric_mac_ports_mode(fabric_mac_ports_mode_e& out_fabric_mac_ports_mode) const = 0;

    /// @brief Set a device's fabric ports mode.
    ///
    /// Fabric Ports mode determines the MAC Ports speed of all Fabric MAC Ports.
    ///
    /// @param[in]      fabric_mac_ports_mode    Mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_fabric_mac_ports_mode(fabric_mac_ports_mode_e fabric_mac_ports_mode) = 0;

    /// @brief Get Slice mode.
    ///
    /// @param[in]  slice_id            Slice to be queried.
    /// @param[out] out_slice_mode      Slice mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Slice mode retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Slice ID is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_slice_mode(la_slice_id_t slice_id, la_slice_mode_e& out_slice_mode) const = 0;

    /// @brief Set a slice's mode.
    ///
    /// @param[in]  slice_id            Slice to configure.
    /// @param[in]  slice_mode          Slice mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode set successfully.
    /// @retval     LA_STATUS_EBUSY     Slice is in use.
    /// @retval     LA_STATUS_EINVAL    slice_id is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_slice_mode(la_slice_id_t slice_id, la_slice_mode_e slice_mode) = 0;

    /// @brief Set a fabric slice's CLOS topology direction.
    ///
    /// @param[in]  slice_id            Slice to configure.
    /// @param[in]  clos_direction      CLOS topology direction to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Direction set successfully.
    /// @retval     LA_STATUS_EBUSY     Slice is in use.
    /// @retval     LA_STATUS_EINVAL    slice_id is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_fabric_slice_clos_direction(la_slice_id_t slice_id, la_clos_direction_e clos_direction) = 0;

    /// @brief Get a fabric slice's CLOS topology direction.
    ///
    /// @param[in]  slice_id            Slice to be queried.
    /// @param[out] out_clos_direction  CLOS topology direction.
    ///
    /// @retval     LA_STATUS_SUCCESS   Slice CLOS direction retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    slice_id is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_fabric_slice_clos_direction(la_slice_id_t slice_id, la_clos_direction_e& out_clos_direction) const = 0;

    /// @brief Enable/Disable designating this device as the master fabric time generator in the system.
    ///
    /// In a system there should be exactly one linecard device acting as the fabric time generator.
    ///
    /// @param[in]  is_master           true if this device is the fabric time master generator; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Device doesn't support fabric time generation.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_is_fabric_time_master(bool is_master) = 0;

    /// @brief Get fabric time synchronization status.
    ///
    /// @param[out] out_sync_status     true if this device's fabric time is synchronized; false
    /// otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Device doesn't support fabric time synchronization.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_fabric_time_sync_status(bool& out_sync_status) const = 0;

    /// @brief Retrieve number of SerDes elements in specified IFG.
    ///
    /// @param[in]  slice_id                Slice to be queried.
    /// @param[in]  ifg_id                  IFG ID to be queried.
    /// @param[out] out_num_of_serdes       Number of SerDes elements.
    ///
    /// @retval     LA_STATUS_SUCCESS   Number of SerDes elements retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Slice ID or IFG ID is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_num_of_serdes(la_slice_id_t slice_id, la_ifg_id_t ifg_id, size_t& out_num_of_serdes) const = 0;

    /// @brief Retrieve source of all SerDes's in specified IFG.
    ///
    /// @param[in]  slice_id                Slice to be queried.
    /// @param[in]  ifg_id                  IFG ID to be queried.
    /// @param[out] out_serdes_mapping_vec  Retrieved SerDes mapping vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   SerDes mapping retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Slice ID or IFG ID is invalid or vector size is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_serdes_source(la_slice_id_t slice_id,
                                        la_ifg_id_t ifg_id,
                                        std::vector<la_uint_t>& out_serdes_mapping_vec) const = 0;

    /// @brief Retrieve source of specific SerDes in specified IFG.
    ///
    /// @param[in]  slice_id                Slice to be queried.
    /// @param[in]  ifg_id                  IFG ID to be queried.
    /// @param[in]  serdes_index            SerDes index within an IFG to be queried.
    /// @param[out] out_serdes              SerDes source.
    ///
    /// @retval     LA_STATUS_SUCCESS   SerDes source retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Slice ID, IFG ID, or SerDes index is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_serdes_source(la_slice_id_t slice_id,
                                        la_ifg_id_t ifg_id,
                                        la_uint_t serdes_index,
                                        la_uint_t& out_serdes) const = 0;

    /// @brief Change the source of all SerDes's in specified IFG.
    ///
    /// Remap the Rx path of all SerDes's, each SerDes must appear exactly once in the vector.
    ///
    /// Must be called before silicon_one::init_phase_e::TOPOLOGY initialization stage.
    ///
    /// Default configuration is a plain mapping (0->0, 1->1 etc).
    ///
    /// @param[in]  slice_id            Slice to be manipulated.
    /// @param[in]  ifg_id              IFG ID to be manipulated.
    /// @param[in]  serdes_mapping_vec  SerDes mapping vector, the vector must be by the size of total number of SerDes's in the
    /// IFG.
    ///
    /// @retval     LA_STATUS_SUCCESS   SerDes mapping updated successfully.
    /// @retval     LA_STATUS_EBUSY     The device completed TOPOLOGY initialization phase and change is not allowed.
    /// @retval     LA_STATUS_EINVAL    IFG ID/SerDes is invalid or the mapping is not allowed.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_serdes_source(la_slice_id_t slice_id, la_ifg_id_t ifg_id, std::vector<la_uint_t> serdes_mapping_vec) = 0;

    /// @brief Retrieve SerDes Auto Negotiation and link training order.
    ///
    /// @param[in]  slice_id                   Slice to be queried.
    /// @param[in]  ifg_id                     IFG ID to be queried.
    /// @param[out] out_serdes_anlt_order_vec  SerDes ANLT order vector, the vector must be by the size of total number of SerDes's
    /// in the IFG.
    ///
    /// @retval     LA_STATUS_SUCCESS   SerDes ANLT order retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Slice ID or IFG ID is invalid or vector size is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_serdes_anlt_order(la_slice_id_t slice_id,
                                            la_ifg_id_t ifg_id,
                                            std::vector<la_uint_t>& out_serdes_anlt_order_vec) const = 0;

    /// @brief Change SerDes Auto Negotiation and link training order.
    ///
    /// Must be called before silicon_one::init_phase_e::TOPOLOGY initialization stage.
    ///
    /// Default configuration is a plain mapping (0->0, 1->1 etc).
    /// This order is used to decide which SerDes to use for Auto Negotiation and set proper values in link training on multi-lane
    /// port.
    ///
    /// @param[in]  slice_id               Slice to be manipulated.
    /// @param[in]  ifg_id                 IFG ID to be manipulated.
    /// @param[in]  serdes_anlt_order_vec  SerDes ANLT order vector, the vector must be by the size of total number of SerDes's in
    /// the IFG.
    ///
    /// @retval     LA_STATUS_SUCCESS   SerDes ANLT order updated successfully.
    /// @retval     LA_STATUS_EBUSY     The device completed TOPOLOGY initialization phase and change is not allowed.
    /// @retval     LA_STATUS_EINVAL    IFG ID/SerDes is invalid or the ANLT order is not allowed.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_serdes_anlt_order(la_slice_id_t slice_id,
                                            la_ifg_id_t ifg_id,
                                            std::vector<la_uint_t> serdes_anlt_order_vec)
        = 0;

    /// @brief Retrieve the polarity inversion configuration of specific SerDes's in specified IFG.
    ///
    /// @param[in]  slice_id    Slice to be queried.
    /// @param[in]  ifg_id      IFG ID to be queried.
    /// @param[in]  serdes_id   SerDes ID to be queried.
    /// @param[in]  direction   SerDes direction to be queried.
    /// @param[out] out_invert  The polarity inversion setting. True, if polarity inversion enabled.
    ///
    /// @retval     LA_STATUS_SUCCESS   SerDes updated successfully.
    /// @retval     LA_STATUS_EBUSY     The device completed TOPOLOGY initialization phase and change is not allowed.
    /// @retval     LA_STATUS_EINVAL    Slice ID, or IFG ID, or SerDes is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_serdes_polarity_inversion(la_slice_id_t slice_id,
                                                    la_ifg_id_t ifg_id,
                                                    la_uint_t serdes_id,
                                                    la_serdes_direction_e direction,
                                                    bool& out_invert) const = 0;

    /// @brief Change the polarity inversion configuration of specific SerDes's in specified IFG.
    ///
    /// Must be called before silicon_one::init_phase_e::TOPOLOGY initialization stage.
    ///
    /// If not called, the default is disable polarity invert.
    ///
    /// @param[in]  slice_id    Slice to be manipulated.
    /// @param[in]  ifg_id      IFG ID to be manipulated.
    /// @param[in]  serdes_id   SerDes ID to be manipulated.
    /// @param[in]  direction   SerDes direction to be manipulated.
    /// @param[in]  invert      The polarity to be set for a specific SerDes and direction. True, to enable polarity inversion.
    ///
    /// @retval     LA_STATUS_SUCCESS   SerDes updated successfully.
    /// @retval     LA_STATUS_EBUSY     The device completed TOPOLOGY initialization phase and change is not allowed.
    /// @retval     LA_STATUS_EINVAL    Slice ID, or IFG ID, or SerDes is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_serdes_polarity_inversion(la_slice_id_t slice_id,
                                                    la_ifg_id_t ifg_id,
                                                    la_uint_t serdes_id,
                                                    la_serdes_direction_e direction,
                                                    bool invert)
        = 0;

    /// @brief Get internal SerDes address for the specified SerDes lane.
    ///
    /// @param[in]  slice_id         Slice to be queried.
    /// @param[in]  ifg_id           IFG ID to be queried.
    /// @param[in]  serdes_idx       SerDes index to be queried.
    /// @param[in]  direction        SerDes direction to be queried, either TX or RX.
    /// @param[out] out_serdes_addr  The address for the given combination of {slice, ifg, SerDes index, TX/RX}.
    ///
    /// @retval     LA_STATUS_SUCCESS   SerDes address retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Slice ID, IFG ID, SerDes index or direction is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status get_serdes_addr(la_slice_id_t slice_id,
                                      la_ifg_id_t ifg_id,
                                      la_uint_t serdes_idx,
                                      la_serdes_direction_e direction,
                                      uint32_t& out_serdes_addr)
        = 0;

    /// @brief Query overhead accounted for each packet.
    ///
    /// The given value must not include Ethernet preamble, inter-packet-gap or CRC.
    ///
    /// @param[out] out_overhead        The configured overhead value.
    ///
    /// @retval     LA_STATUS_SUCCESS   Overhead accounting retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_accounted_packet_overhead(int& out_overhead) const = 0;

    /// @brief Configure overhead accounted for each packet.
    ///
    /// The given value must not include Ethernet preamble, inter-packet-gap or CRC.
    ///
    /// @param[in]  overhead    Overhead that should be set in the device.
    ///
    /// @retval     LA_STATUS_SUCCESS   Overhead accounting configured successfully.
    /// @retval     LA_STATUS_EINVAL    The value is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_accounted_packet_overhead(int overhead) = 0;

    /// @brief Get an AAPL handler for a specific IFG.
    ///
    /// @param[in]  slice_id            Slice of the SerDes pool.
    /// @param[in]  ifg_id              IFG of the SerDes pool.
    /// @param[out] out_aapl            Reference to Aapl_t handler to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   AAPL handler retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid combination of Slice ID and/or IFG ID.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ifg_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) = 0;

    /// @brief Get an AAPL handler for a specific SBUS ring without any mapping.
    ///
    /// @param[in]  slice_id            Slice of the SerDes pool.
    /// @param[in]  ifg_id              IFG of the SerDes pool.
    /// @param[out] out_aapl            Reference to Aapl_t handler to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   AAPL handler retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid combination of Slice ID and/or IFG ID.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_native_sbus_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) = 0;

    /// @brief Get an AAPL handler for PCI IFG.
    ///
    /// @param[out] out_aapl            Reference to Aapl_t handler to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   AAPL handler retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pci_aapl_handler(Aapl_t*& out_aapl) = 0;

    /// @brief Get an AAPL handler for a specific HBM chain.
    ///
    /// @param[in]  hbm_interface       HBM interface index.
    /// @param[out] out_aapl            Reference to Aapl_t handler to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   AAPL handler retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid HBM interface.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_hbm_aapl_handler(size_t hbm_interface, Aapl_t*& out_aapl) = 0;

    /// @brief Get HBM handler.
    ///
    /// @param[out] out_hbm             Reference to HBM handler to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   HBM handler retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid HBM interface.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_hbm_handler(la_hbm_handler*& out_hbm) = 0;

    /// @brief Get Precision Time Protocol (PTP) handler.
    ///
    /// @param[out] out_ptp             Reference to PTP handler to handle PTP commands.
    ///
    /// @retval     LA_STATUS_SUCCESS   PTP handler retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ptp_handler(la_ptp_handler*& out_ptp) = 0;

    /// @brief Get APB handler.
    ///
    /// @param[in]  interface_type      APB interface type.
    /// @param[out] out_apb             Reference to APB handler.
    ///
    /// @retval     LA_STATUS_SUCCESS   APB handler retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid APB interface type.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_apb_handler(apb_interface_type_e interface_type, apb*& out_apb) = 0;

    /// @brief Get CPU2JTAG handler.
    ///
    /// @param[out] out_cpu2jtag        Reference to CPU2JTAG handler.
    ///
    /// @retval     LA_STATUS_SUCCESS   CPU2JTAG handler retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cpu2jtag_handler(cpu2jtag*& out_cpu2jtag) = 0;

    /// @brief Get InFO Phy handler.
    ///
    /// @param[out] out_info_phy        Reference to InFO Phy handler.
    ///
    /// @retval     LA_STATUS_SUCCESS           InFO Phy handler retrieved successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_info_phy_handler(la_info_phy_handler*& out_info_phy) = 0;

    /// @brief Get Flow cache handler.
    ///
    /// @param[out] out_flow_cache_handler      Reference to Flow cache handler.
    ///
    /// @retval     LA_STATUS_SUCCESS           Flow cache handler retrieved successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Not implemented for this device.
    /// @retval     LA_STATUS_EINVAL            The device is not in Linecard or Standalone mode.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_flow_cache_handler(la_flow_cache_handler*& out_flow_cache_handler) = 0;

    /// @brief Destroy an existing #silicon_one::la_object object.
    ///
    /// All associated data structures are freed.
    /// The object becomes invalid if the call is successful, and should not be used from that point on.
    ///
    /// @param[in]  object              Object to be destroyed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Object has been destroyed successfully.
    /// @retval     LA_STATUS_EAGAIN    Object is not destroyed. Try again.
    /// @retval     LA_STATUS_EBUSY     Object is in use.
    /// @retval     LA_STATUS_EINVAL    Object is corrupt or invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    /// @note: destroy()-ing an #silicon_one::la_system_port or #silicon_one::la_voq_set might return LA_STATUS_EAGAIN while queues
    /// associated
    /// with these
    /// objects are being flushed.
    virtual la_status destroy(la_object* object) = 0;

    /// @brief	Get a list of valid MAC port configurations.
    ///
    /// @param[out] out_config_vec      A list of valid MAC configurations include port speed, FEC, and number of Serdes lanes.
    ///
    /// @retval     LA_STAUS_SUCCESS    Configurations is returned successfully.
    virtual la_status get_valid_mac_port_configs(la_mac_port::mac_config_vec& out_config_vec) const = 0;

    /// @brief Create a non-channelized #silicon_one::la_mac_port over a set of SerDes elements.
    ///
    /// See #silicon_one::la_device_property_e::LC_56_FABRIC_PORT_MODE for allowed SerDes IDs.
    ///
    /// @param[in]  slice_id            Slice to be configured.
    /// @param[in]  ifg_id              IFG to be configured.
    /// @param[in]  first_serdes_id     First SerDes allocated to this MAC port.
    /// @param[in]  last_serdes_id      Last SerDes allocated to this MAC port.
    /// @param[in]  speed               MAC port speed
    /// @param[in]  fc_mode             Flow Control mode.
    /// @param[in]  fec_mode            Forward Error Correction mode.
    /// @param[out] out_mac_port        Reference to #silicon_one::la_mac_port* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port created successfully. out_mac_port contains the actual port.
    /// @retval     LA_STATUS_EBUSY     At least one SerDes is already in use by another port.
    /// @retval     LA_STATUS_EINVAL    Invalid combination of Slice ID, IFG ID, SerDes, speed, flow control or FEC mode.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_mac_port(la_slice_id_t slice_id,
                                      la_ifg_id_t ifg_id,
                                      la_uint_t first_serdes_id,
                                      la_uint_t last_serdes_id,
                                      la_mac_port::port_speed_e speed,
                                      la_mac_port::fc_mode_e fc_mode,
                                      la_mac_port::fec_mode_e fec_mode,
                                      la_mac_port*& out_mac_port)
        = 0;

    /// @brief Get an existing #silicon_one::la_mac_port object by slice/ifg/serdes.
    ///
    /// @param[in]  slice_id            Slice.
    /// @param[in]  ifg_id              IFG.
    /// @param[in]  serdes_id           Any SerDes associated with this MAC port.
    /// @param[out] out_mac_port        Reference to #silicon_one::la_mac_port*.
    ///
    /// @retval     LA_STATUS_SUCCESS   A matching MAC port was found.
    /// @retval     LA_STATUS_ENOTFOUND No matching MAC port was found.
    /// @retval     LA_STATUS_EINVAL    Invalid arguments.
    virtual la_status get_mac_port(la_slice_id_t slice_id,
                                   la_ifg_id_t ifg_id,
                                   la_uint_t serdes_id,
                                   la_mac_port*& out_mac_port) const = 0;

    /// @brief Create a channelized #silicon_one::la_mac_port over a set of SerDes elements.
    ///
    /// See #silicon_one::la_device_property_e::LC_56_FABRIC_PORT_MODE for allowed SerDes IDs.
    ///
    /// @param[in]  slice_id                    Slice to be configured.
    /// @param[in]  ifg_id                      IFG to be configured.
    /// @param[in]  first_serdes_id             First SerDes allocated to this MAC port.
    /// @param[in]  last_serdes_id              Last SerDes allocated to this MAC port.
    /// @param[in]  speed                       MAC port speed
    /// @param[in]  fc_mode                     Flow Control mode.
    /// @param[in]  fec_mode                    Forward Error Correction mode.
    /// @param[out] out_mac_port                Reference to #silicon_one::la_mac_port* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   MAC port created successfully. out_mac_port contains the actual port.
    /// @retval     LA_STATUS_EBUSY     At least one SerDes is already in use by another port.
    /// @retval     LA_STATUS_EINVAL    Invalid combination of Slice ID, IFG ID, SerDes and/or speed.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_channelized_mac_port(la_slice_id_t slice_id,
                                                  la_ifg_id_t ifg_id,
                                                  la_uint_t first_serdes_id,
                                                  la_uint_t last_serdes_id,
                                                  la_mac_port::port_speed_e speed,
                                                  la_mac_port::fc_mode_e fc_mode,
                                                  la_mac_port::fec_mode_e fec_mode,
                                                  la_mac_port*& out_mac_port)
        = 0;

    /// @brief Create a fabric MAC port over a set of SerDes elements.
    ///
    /// Creates a fabric MAC port to be used as a carrier-fabric port. A fabric-port supports the following configuration:
    /// - Speed of #silicon_one::la_mac_port::port_speed_e::E_100G on two consecutive SerDes elements.
    /// - Flow control is either #silicon_one::la_mac_port::fc_mode_e::CFFC or #silicon_one::la_mac_port::fc_mode_e::NONE.
    ///
    /// See #silicon_one::la_device_property_e::LC_56_FABRIC_PORT_MODE for allowed SerDes IDs.
    ///
    /// @param[in]  slice_id            Slice to be configured.
    /// @param[in]  ifg_id              IFG to be configured.
    /// @param[in]  first_serdes_id     First SerDes allocated to this fabric MAC port.
    /// @param[in]  last_serdes_id      Last SerDes allocated to this fabric MAC port.
    /// @param[in]  speed               Fabric MAC port speed
    /// @param[in]  fc_mode             Flow Control mode.
    /// @param[out] out_mac_port        Reference to #silicon_one::la_mac_port* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Fabric MAC port created successfully. out_mac_port contains the actual port.
    /// @retval     LA_STATUS_EBUSY     At least one SerDes is already in use by another port.
    /// @retval     LA_STATUS_EINVAL    Invalid combination of Slice ID, IFG ID, SerDes and/or speed, FC mode.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_fabric_mac_port(la_slice_id_t slice_id,
                                             la_ifg_id_t ifg_id,
                                             la_uint_t first_serdes_id,
                                             la_uint_t last_serdes_id,
                                             la_mac_port::port_speed_e speed,
                                             la_mac_port::fc_mode_e fc_mode,
                                             la_mac_port*& out_mac_port)
        = 0;

    /// @brief Create a fabric port over a fabric MAC port.
    ///
    /// @param[in]  fabric_mac_port     Fabric MAC port to use.
    /// @param[out] out_fabric_port     Reference to #silicon_one::la_fabric_port* to create.
    ///
    /// @retval     LA_STATUS_SUCCESS   Fabric port created successfully. out_fabric_port contains the actual port.
    /// @retval     LA_STATUS_EINVAL    Fabric MAC port is corrupt/invalid.
    /// @retval     LA_STATUS_EBUSY     Fabric MAC port is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_fabric_port(la_mac_port* fabric_mac_port, la_fabric_port*& out_fabric_port) = 0;

    /// @brief Create a #silicon_one::la_pci_port for a specific IFG.
    ///
    /// @param[in]  slice_id            Slice for this PCI port.
    /// @param[in]  ifg_id              IFG for this PCI port.
    /// @param[in]  skip_kernel_driver  Flag to skip kernel driver
    /// @param[out] out_pci_port        Reference to #silicon_one::la_pci_port* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. out_pci_port contains the actual port.
    /// @retval     LA_STATUS_EBUSY     IFG is already in use by another port.
    /// @retval     LA_STATUS_EINVAL    Invalid combination of Slice ID, IFG ID.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_pci_port(la_slice_id_t slice_id,
                                      la_ifg_id_t ifg_id,
                                      bool skip_kernel_driver,
                                      la_pci_port*& out_pci_port)
        = 0;

    /// @brief Create a #silicon_one::la_recycle_port for a specific IFG.
    ///
    /// @param[in]  slice_id            Slice for this recycle port.
    /// @param[in]  ifg_id              IFG for this recycle port.
    /// @param[out] out_recycle_port    Reference to #silicon_one::la_recycle_port* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. out_recycle_port contains the actual port.
    /// @retval     LA_STATUS_EBUSY     Recycle port already created for this IFG.
    /// @retval     LA_STATUS_EINVAL    Invalid combination of Slice ID, IFG ID.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_recycle_port(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_recycle_port*& out_recycle_port) = 0;

    /// @brief Creates a #silicon_one::la_remote_device.
    ///
    /// @param[in]  remote_device_id        Remote device ID.
    /// @param[in]  remote_device_revision  Remote device revision.
    /// @param[out] out_remote_device       Reference to #silicon_one::la_remote_device* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Remote device created successfully. out_remote_device contains the actual remote device.
    /// @retval     LA_STATUS_EINVAL    Invalid remote_device_id or remote_device_revision parameters value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_remote_device(la_device_id_t remote_device_id,
                                           la_device_revision_e remote_device_revision,
                                           la_remote_device*& out_remote_device)
        = 0;

    /// @brief Creates a #silicon_one::la_remote_port.
    ///
    /// @param[in]  remote_device               #silicon_one::la_remote_device.
    /// @param[in]  remote_slice_id             Remote slice ID.
    /// @param[in]  remote_ifg_id               Remote IFG ID.
    /// @param[in]  remote_first_serdes_id      Remote first SerDes allocated to this port.
    /// @param[in]  remote_last_serdes_id       Remote last SerDes allocated to this port.
    /// @param[in]  remote_port_speed       	Remote port's speed.
    /// @param[out] out_remote_port             Reference to #silicon_one::la_remote_port* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Remote port created successfully. out_remote_port contains the actual port.
    /// @retval     LA_STATUS_EBUSY     At least one SerDes is already in use by another remote port.
    /// @retval     LA_STATUS_EINVAL    Invalid combination of Slice ID, IFG ID, SerDes.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @see        destroy_remote_port
    virtual la_status create_remote_port(la_remote_device* remote_device,
                                         la_slice_id_t remote_slice_id,
                                         la_ifg_id_t remote_ifg_id,
                                         la_uint_t remote_first_serdes_id,
                                         la_uint_t remote_last_serdes_id,
                                         la_mac_port::port_speed_e remote_port_speed,
                                         la_remote_port*& out_remote_port)
        = 0;

    /// @brief Creates a #silicon_one::la_system_port on top of a #silicon_one::la_mac_port and assigns it an #la_system_port_gid_t.
    /// non port-extended system port cannot be created on top of channelized MAC
    ///
    /// @param[in]  system_port_gid     System port global ID to assign.
    /// @param[in]  mac_port            MAC port to use.
    /// @param[in]  voq_set             Set of VOQs for (Port, TC)->VOQ mapping.
    /// @param[in]  tc_profile          Profile for (Port, TC)->VOQ mapping for flows.
    /// @param[out] out_system_port     Reference to #silicon_one::la_system_port* to create.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port created successfully. out_system_port contains the actual port.
    /// @retval     LA_STATUS_EINVAL    MAC port is corrupt/invalid or system port GID is out of range.
    /// @retval     LA_STATUS_EBUSY     MAC port or the system port ID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_system_port(la_system_port_gid_t system_port_gid,
                                         la_mac_port* mac_port,
                                         la_voq_set* voq_set,
                                         const la_tc_profile* tc_profile,
                                         la_system_port*& out_system_port)
        = 0;

    /// @brief Creates a #silicon_one::la_system_port on top of a #silicon_one::la_mac_port with port extender and assigns it an
    /// #la_system_port_gid_t.
    /// port-extended system port can only be created on top of channelized MAC
    ///
    /// @param[in]  system_port_gid     System port global ID to assign.
    /// @param[in]  mac_port            MAC port to use.
    /// @param[in]  port_extender_vid   Extended port VID.
    /// @param[in]  voq_set             Set of VOQs for (Port, TC)->VOQ mapping.
    /// @param[in]  tc_profile          Profile for (Port, TC)->VOQ mapping for flows.
    /// @param[out] out_system_port     Reference to #silicon_one::la_system_port* to create.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port created successfully. out_system_port contains the actual port.
    /// @retval     LA_STATUS_EINVAL    MAC port is corrupt/invalid or system port GID is out of range.
    /// @retval     LA_STATUS_EBUSY     MAC port, system port ID or port-extender VID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_system_port(la_system_port_gid_t system_port_gid,
                                         la_port_extender_vid_t port_extender_vid,
                                         la_mac_port* mac_port,
                                         la_voq_set* voq_set,
                                         const la_tc_profile* tc_profile,
                                         la_system_port*& out_system_port)
        = 0;

    /// @brief Creates a #silicon_one::la_system_port on top of a #silicon_one::la_recycle_port and assigns it an
    /// #la_system_port_gid_t.
    ///
    /// @param[in]  system_port_gid     System port global ID to assign.
    /// @param[in]  recycle_port        Recycle port to use.
    /// @param[in]  voq_set             Set of VOQs for (Port, TC)->VOQ mapping.
    /// @param[in]  tc_profile          Profile for (Port, TC)->VOQ mapping for flows.
    /// @param[out] out_system_port     Reference to #silicon_one::la_system_port* to create.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port created successfully. out_system_port contains the actual port.
    /// @retval     LA_STATUS_EINVAL    Recycle port is corrupt/invalid or system port GID is out of range.
    /// @retval     LA_STATUS_EBUSY     Recycle port or the system port ID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_system_port(la_system_port_gid_t system_port_gid,
                                         la_recycle_port* recycle_port,
                                         la_voq_set* voq_set,
                                         const la_tc_profile* tc_profile,
                                         la_system_port*& out_system_port)
        = 0;

    /// @brief Creates a #silicon_one::la_system_port on top of a #silicon_one::la_pci_port and assigns it an #la_system_port_gid_t.
    ///
    /// @param[in]  system_port_gid     System port global ID to assign.
    /// @param[in]  pci_port            PCI port to use.
    /// @param[in]  voq_set             Set of VOQs for (Port, TC)->VOQ mapping.
    /// @param[in]  tc_profile          Profile for (Port, TC)->VOQ mapping for flows.
    /// @param[out] out_system_port     Reference to #silicon_one::la_system_port* to create.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port created successfully. out_system_port contains the actual port.
    /// @retval     LA_STATUS_EINVAL    PCI port is corrupt/invalid or system port GID is out of range.
    /// @retval     LA_STATUS_EBUSY     PCI port or the system port ID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_system_port(la_system_port_gid_t system_port_gid,
                                         la_pci_port* pci_port,
                                         la_voq_set* voq_set,
                                         const la_tc_profile* tc_profile,
                                         la_system_port*& out_system_port)
        = 0;

    /// @brief Creates a #silicon_one::la_system_port on top of a #silicon_one::la_remote_port and assigns it an
    /// #la_system_port_gid_t.
    ///
    /// @param[in]  system_port_gid     System port global ID to assign.
    /// @param[in]  remote_port         Remote port to use.
    /// @param[in]  voq_set             Set of VOQs for (Port, TC)->VOQ mapping.
    /// @param[in]  tc_profile          Profile for (Port, TC)->VOQ mapping for flows.
    /// @param[out] out_system_port     Reference to #silicon_one::la_system_port* to create.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port created successfully. out_system_port contains the actual port.
    /// @retval     LA_STATUS_EINVAL    Remote port is corrupt/invalid or system port GID is out of range.
    /// @retval     LA_STATUS_EBUSY     Remote port or the system port GID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_system_port(la_system_port_gid_t system_port_gid,
                                         la_remote_port* remote_port,
                                         la_voq_set* voq_set,
                                         const la_tc_profile* tc_profile,
                                         la_system_port*& out_system_port)
        = 0;

    /// @brief Creates a #silicon_one::la_spa_port assigns it an #la_spa_port_gid_t.
    ///
    /// @param[in]  spa_port_gid        SPA port global ID to assign.
    /// @param[out] out_spa_port        Reference to #silicon_one::la_spa_port* to create.
    ///
    /// @retval     LA_STATUS_SUCCESS   SPA port created successfully. out_system_port contains the actual port.
    /// @retval     LA_STATUS_EINVAL    SPA port GID is out of range.
    /// @retval     LA_STATUS_EBUSY     Given SPA port ID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_spa_port(la_spa_port_gid_t spa_port_gid, la_spa_port*& out_spa_port) = 0;

    /// @}
    /// @name Punt/Inject, trap and snoop events API-s.
    /// @{

    /// @brief Creates a #silicon_one::la_punt_inject_port over a given system port.
    ///
    /// @param[in]  system_port             System port to create punt/inject port with.
    /// @param[in]  mac_addr                MAC to associate with the port.
    /// @param[out] out_punt_inject_port    Pointer to #silicon_one::la_punt_inject_port to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. out_pi_port contains the created port.
    /// @retval     LA_STATUS_EINVAL    System port is invalid.
    /// @retval     LA_STATUS_EBUSY     System port is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_punt_inject_port(la_system_port* system_port,
                                              la_mac_addr_t mac_addr,
                                              la_punt_inject_port*& out_punt_inject_port)
        = 0;

    /// @brief Creates a #silicon_one::la_l2_punt_destination over a given punt/inject port.
    ///
    /// @param[in]  gid                 L2 Punt destination global ID.
    /// @param[in]  punt_inject_port    Punt/Inject port to create punt destination with.
    /// @param[in]  mac_addr            MAC of the destination encapsulation.
    /// @param[in]  vlan_tag            VLAN tag for the punt destination encapsulation.
    /// @param[out] out_punt_dest       Pointer to #silicon_one::la_l2_punt_destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Punt destination created successfully. out_punt_dest contains the destination.
    /// @retval     LA_STATUS_EINVAL    Punt/inject port is invalid.
    /// @retval     LA_STATUS_ERESOURCE Maximal number of punt destinations exists.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_l2_punt_destination(la_l2_punt_destination_gid_t gid,
                                                 la_punt_inject_port* punt_inject_port,
                                                 la_mac_addr_t mac_addr,
                                                 la_vlan_tag_tci_t vlan_tag,
                                                 la_l2_punt_destination*& out_punt_dest)
        = 0;

    virtual la_status create_l2_punt_destination(la_l2_punt_destination_gid_t gid,
                                                 la_stack_port* stack_port,
                                                 la_mac_addr_t mac_addr,
                                                 la_vlan_tag_tci_t vlan_tag,
                                                 la_l2_punt_destination*& out_punt_dest)
        = 0;

    //
    /// @brief Get a L2 Punt destination object using its global ID.
    ///
    /// @param[in]     gid              L2 Punt destination object global ID.
    /// @param[out]    out_punt_dest    Pointer to #silicon_one::la_l2_punt_destination to populate.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_ENOTFOUND  The global ID does not map to any object.
    /// @retval    LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status get_l2_punt_destination_by_gid(la_l2_punt_destination_gid_t gid,
                                                     la_l2_punt_destination*& out_punt_dest) const = 0;

    /// @brief Creates a #silicon_one::la_npu_host_destination over a given npu host port.
    ///
    /// @param[in]  npu_host_port            NPU host port to create npu host destination over.
    /// @param[out] out_npu_host_destination Pointer to #silicon_one::la_npu_host_destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Punt destination created successfully. out_punt_dest contains the destination.
    /// @retval     LA_STATUS_EINVAL    System port is invalid.
    virtual la_status create_npu_host_destination(la_npu_host_port* npu_host_port,
                                                  la_npu_host_destination*& out_npu_host_destination)
        = 0;

    /// @brief Create a #silicon_one::la_npu_host_port.
    ///
    /// @param[in]  remote_device       Pointer to #silicon_one::la_remote_device.
    /// @param[in]  system_port_gid     System port global ID to assign.
    /// @param[in]  voq_set             Set of VOQs for (Port, TC)->VOQ mapping.
    /// @param[in]  tc_profile          Profile for (Port, TC)->VOQ mapping for flows.
    /// @param[out] out_npu_host_port   Reference to #silicon_one::la_npu_host_port* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. out_npu_host_port contains the port.
    /// @retval     LA_STATUS_EBUSY     NPU host port already created for this IFG.
    /// @retval     LA_STATUS_EINVAL    Invalid parameters.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_npu_host_port(la_remote_device* remote_device,
                                           la_system_port_gid_t system_port_gid,
                                           la_voq_set* voq_set,
                                           const la_tc_profile* tc_profile,
                                           la_npu_host_port*& out_npu_host_port)
        = 0;

    /// @brief Creates a #silicon_one::la_erspan_mirror_command over a given ERSPAN session.
    ///
    /// @param[in]  mirror_gid          Mirror command global ID.
    /// @param[in]  encap_data          ERSPAN encapsulation data.
    /// @param[in]  voq_offset          Offset from base VOQ for TC mapping.
    /// @param[in]  dsp                 Destination system port.
    /// @param[in]  probability         Probabilty a mirror packet will be generated.
    /// @param[out] out_mirror_cmd      Pointer to #silicon_one::la_erspan_mirror_command to populate.
    ///
    /// @note Probability is rounded to the device's supported probability granularity;
    /// @see #MIRROR_SAMPLING_FREQUENCY_GRANULARITY.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mirror command created successfully. out_mirror_cmd contains the command.
    /// @retval     LA_STATUS_EINVAL    ERSPAN session is invalid or Mirror command GID is out of range.
    /// @retval     LA_STATUS_EINVAL    L3 port is invalid.
    /// @retval     LA_STATUS_EEXIST    Given mirror command GID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_erspan_mirror_command(la_mirror_gid_t mirror_gid,
                                                   la_erspan_mirror_command::ipv4_encapsulation encap_data,
                                                   la_uint_t voq_offset,
                                                   const la_system_port* dsp,
                                                   float probability,
                                                   la_erspan_mirror_command*& out_mirror_cmd)
        = 0;

    /// @brief Creates a #silicon_one::la_erspan_mirror_command over a given ERSPAN session.
    ///
    /// @param[in]  mirror_gid          Mirror command global ID.
    /// @param[in]  encap_data          ERSPAN encapsulation data.
    /// @param[in]  voq_offset          Offset from base VOQ for TC mapping.
    /// @param[in]  dsp                 Destination system port.
    /// @param[in]  probability         Probabilty a mirror packet will be generated.
    /// @param[out] out_mirror_cmd      Pointer to #silicon_one::la_erspan_mirror_command to populate.
    ///
    /// @note Probability is rounded to the device's supported probability granularity;
    /// @see #MIRROR_SAMPLING_FREQUENCY_GRANULARITY.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mirror command created successfully. out_mirror_cmd contains the command.
    /// @retval     LA_STATUS_EINVAL    ERSPAN session is invalid or Mirror command GID is out of range.
    /// @retval     LA_STATUS_EINVAL    L3 port is invalid.
    /// @retval     LA_STATUS_EEXIST    Given mirror command GID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_erspan_mirror_command(la_mirror_gid_t mirror_gid,
                                                   la_erspan_mirror_command::ipv6_encapsulation encap_data,
                                                   la_uint_t voq_offset,
                                                   const la_system_port* dsp,
                                                   float probability,
                                                   la_erspan_mirror_command*& out_mirror_cmd)
        = 0;

    /// @brief Creates a #silicon_one::la_l2_mirror_command over a given punt/inject port.
    ///
    /// @param[in]  mirror_gid          Mirror command global ID.
    /// @param[in]  punt_inject_port    Punt/Inject port to create mirror command with.
    /// @param[in]  mac_addr            Destination MAC for mirror command encapsulation.
    /// @param[in]  vlan_tag            VLAN tag for the mirror command encapsulation.
    /// @param[in]  voq_offset          Offset from base VOQ for TC mapping.
    /// @param[in]  meter               Meter.
    /// @param[in]  probability         Probability of a mirror packet to be generated.
    /// @param[out] out_mirror_cmd      Pointer to #silicon_one::la_l2_mirror_command to populate.
    ///
    /// @note Probability is rounded up to the device's supported probability granularity;
    /// @see #MIRROR_SAMPLING_FREQUENCY_GRANULARITY.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mirror command created successfully. out_mirror_cmd contains the command.
    /// @retval     LA_STATUS_EINVAL    Punt/inject port is invalid or Mirror command GID is out of range.
    /// @retval     LA_STATUS_EEXIST    Given mirror command GID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_l2_mirror_command(la_mirror_gid_t mirror_gid,
                                               la_punt_inject_port* punt_inject_port,
                                               la_mac_addr_t mac_addr,
                                               la_vlan_tag_tci_t vlan_tag,
                                               la_uint_t voq_offset,
                                               const la_meter_set* meter,
                                               float probability,
                                               la_l2_mirror_command*& out_mirror_cmd)
        = 0;

    /// @brief Creates a #silicon_one::la_l2_mirror_command over a given system port for
    /// mirroring multicast packet which is catched by LPTS
    ///
    /// @param[in]  mirror_gid          Mirror command global ID.
    /// @param[in]  system_port         System port for mirroring the packet.
    /// @param[out] out_mirror_cmd      Pointer to #silicon_one::la_l2_mirror_command to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mirror command created successfully. out_mirror_cmd contains the command.
    /// @retval     LA_STATUS_EINVAL    System port is invalid or Mirror command GID is out of range.
    /// @retval     LA_STATUS_EEXIST    Given mirror command GID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_mc_lpts_mirror_command(la_mirror_gid_t mirror_gid,
                                                    la_system_port* system_port,
                                                    la_l2_mirror_command*& out_mirror_cmd)
        = 0;

    /// @brief Creates a #silicon_one::la_l2_mirror_command over a given eth/system port.
    ///
    /// @param[in]  mirror_gid          Mirror command global ID.
    /// @param[in]  eth_port            Ethernet port to create mirror command with.
    /// @param[in]  system_port         System port of Etherchannel member to create mirror command with.
    /// @param[in]  voq_offset          Offset from base VOQ for TC mapping.
    /// @param[in]  probability         Probabilty a mirror packet will be generated.
    /// @param[out] out_mirror_cmd      Pointer to #silicon_one::la_l2_mirror_command to populate.
    ///
    /// @note Probability is rounded up to the device's supported probability granularity;
    /// @see #MIRROR_SAMPLING_FREQUENCY_GRANULARITY.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mirror command created successfully. out_mirror_cmd contains the command.
    /// @retval     LA_STATUS_EINVAL    eth_port/system_port is invalid or Mirror command GID is out of range.
    /// @retval     LA_STATUS_EEXIST    Given mirror command GID is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_l2_mirror_command(la_mirror_gid_t mirror_gid,
                                               la_ethernet_port* eth_port,
                                               la_system_port* system_port,
                                               la_uint_t voq_offset,
                                               float probability,
                                               la_l2_mirror_command*& out_mirror_cmd)
        = 0;

    /// @brief Query trap behavior.
    ///
    /// @param[in]  trap                         Trap to be queried.
    /// @param[out] out_priority                 #la_trap_priority_t to populate.
    /// @param[out] out_counter_or_meter         #silicon_one::la_counter_or_meter_set to populate.
    /// @param[out] out_destination              #silicon_one::la_punt_destination* to populate.
    /// @param[out] out_skip_inject_up_packets   bool to populate. True if requested trap should not be triggered for inject up
    /// @param[out] out_skip_p2p_packets         bool to populate. True if requested trap should not be triggered for p2p packets
    /// @param[out] out_overwrite_phb            bool to populate. True if the Traffic Class PHB will be obtained from the trap
    /// configuration. False if the Traffic Class PHB will be obtained from the ACL entry (only valid for
    /// #LA_EVENT_L3_ACL_FORCE_PUNT event).
    /// @param[out] out_tc                       la_traffic_class_t to populate. Trap packet traffic class.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid trap.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_trap_configuration(la_event_e trap,
                                             la_trap_priority_t& out_priority,
                                             la_counter_or_meter_set*& out_counter_or_meter,
                                             const la_punt_destination*& out_destination,
                                             bool& out_skip_inject_up_packets,
                                             bool& out_skip_p2p_packets,
                                             bool& out_overwrite_phb,
                                             la_traffic_class_t& out_tc)
        = 0;

    /// @brief Configure trap behavior.
    ///
    /// Counter or destination or both should be valid (not NULL).
    /// A nullptr destination will result in packet drop. Those drops are counted on
    /// #silicon_one::la_device::get_forwarding_drop_counter.
    ///
    /// @param[in]  trap                    Trap to configure.
    /// @param[in]  priority                Trap priority.
    /// @param[in]  counter_or_meter        Counter/Meter.
    /// @param[in]  destination             Destination to send trapped packets to.
    /// @param[in]  skip_inject_up_packets  True if requested trap should not be triggered for inject up packets.
    /// @param[in]  skip_p2p_packets        True if requested trap should not be triggered for p2p packets.
    /// @param[in]  overwrite_phb           If True, the Traffic Class PHB will be obtained from the trap configuration. If False,
    /// the
    /// Traffic Class PHB will be obtained from the ACL entry (only valid for #LA_EVENT_L3_ACL_FORCE_PUNT event),
    /// @param[in]  tc                      Trap packet traffic class.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid trap.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note       If the same priority is assigned to multiple traps, the priority between those is undefined.
    virtual la_status set_trap_configuration(la_event_e trap,
                                             la_trap_priority_t priority,
                                             la_counter_or_meter_set* counter_or_meter,
                                             const la_punt_destination* destination,
                                             bool skip_inject_up_packets,
                                             bool skip_p2p_packets,
                                             bool overwrite_phb,
                                             la_traffic_class_t tc)
        = 0;

    /// @brief Clear trap settings.
    ///
    /// Trap is ignored, and packet processing continues.
    /// This might cause undefined packet processing behavior for some traps.
    ///
    /// @param[in]  trap                Trap to manipulate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid trap.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_trap_configuration(la_event_e trap) = 0;

    /// @brief Query snoop behavior.
    ///
    /// @param[in]  snoop               Snoop event to query.
    /// @param[out] out_priority        #la_snoop_priority_t to populate.
    /// @param[out] out_mirror_cmd      #silicon_one::la_mirror_command* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_snoop_configuration(la_event_e snoop,
                                              la_snoop_priority_t& out_priority,
                                              const la_mirror_command*& out_mirror_cmd)
        = 0;

    /// @brief Configure snoop behavior.
    ///
    /// @param[in]  snoop                   Snoop to configure.
    /// @param[in]  priority                Snoop priority.
    /// @param[in]  skip_inject_up_packets  True if requested snoop should not be triggered for inject up packets.
    /// @param[in]  skip_p2p_packets        True if requested snoop should not be triggered for p2p packets.
    /// @param[in]  mirror_cmd              Mirror command to replicate snooped packets to.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Mirror command is invalid.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    ///
    /// @note       If the same priority is assigned to multiple snoops, the priority between those is undefined.
    virtual la_status set_snoop_configuration(la_event_e snoop,
                                              la_snoop_priority_t priority,
                                              bool skip_inject_up_packets,
                                              bool skip_p2p_packets,
                                              const la_mirror_command* mirror_cmd)
        = 0;

    /// @brief Configure snoop for L2 MC packet that is LPTS processed
    ///
    /// @param[in]  priority                Snoop priority.
    /// @param[in]  mirror_cmd              Mirror command to replicate snooped packets to.
    /// @param[in]  skip_inject_up_packets  True if requested snoop should not be triggered for inject up packets.
    /// @param[in]  skip_p2p_packets        True if requested snoop should not be triggered for p2p packets.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Mirror command is invalid.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    ///
    /// @note       If the same priority is assigned to multiple snoops, the priority between those is undefined.
    virtual la_status set_mc_lpts_snoop_configuration(la_snoop_priority_t priority,
                                                      bool skip_inject_up_packets,
                                                      bool skip_p2p_packets,
                                                      const la_mirror_command* mirror_cmd)
        = 0;

    /// @brief Clear snoop settings.
    ///
    /// Snoop event will be ignored.
    ///
    /// @param[in]  snoop               Snoop to manipulate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_snoop_configuration(la_event_e snoop) = 0;

    /// @}
    /// @name Global switching
    /// @{

    /// @brief Create a #silicon_one::la_filter_group object.
    ///
    /// @param[out] out_filter_group    Pointer to filter group object. Will be populated with created group.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_group contains the created group.
    /// @retval     LA_STATUS_ERESOURCE Maximum number of groups already created.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_filter_group(la_filter_group*& out_filter_group) = 0;

    /// @brief Get number of available filter groups.
    ///
    /// @return Number of available filter groups.
    virtual la_uint_t get_available_filter_groups() const = 0;

    /// @brief Creates a #silicon_one::la_ethernet_port over a given system port.
    ///
    /// @param[in]  system_port         System port to create ethernet port with.
    /// @param[in]  type                Port type assigned to this ethernet port.
    /// @param[out] out_ethernet_port   Pointer to #silicon_one::la_ethernet_port to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Ethernet port created successfully. out_ethernet_port contains the created port.
    /// @retval     LA_STATUS_EINVAL    System port is invalid.
    /// @retval     LA_STATUS_EBUSY     System port is already used by an aggregate port or ethernet port; or
    ///                                 Port GID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_ethernet_port(la_system_port* system_port,
                                           la_ethernet_port::port_type_e type,
                                           la_ethernet_port*& out_ethernet_port)
        = 0;

    /// @brief Creates a #silicon_one::la_ethernet_port over a given SPA port.
    ///
    /// @param[in]  spa_port            SPA port to create Ethernet port with.
    /// @param[in]  type                Port type assigned to this Ethernet port.
    /// @param[out] out_ethernet_port   Pointer to #silicon_one::la_ethernet_port to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Ethernet port created successfully. out_ethernet_port contains the created port.
    /// @retval     LA_STATUS_EINVAL    SPA port is invalid.
    /// @retval     LA_STATUS_EBUSY     SPA port is already used by an ethernet port; or
    ///                                 Port GID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_ethernet_port(la_spa_port* spa_port,
                                           la_ethernet_port::port_type_e type,
                                           la_ethernet_port*& out_ethernet_port)
        = 0;

    /// @brief Create an AC-type L2 service port.
    ///
    /// Port is created over an Ethernet port.
    /// Incoming packets through the ethernet port first go through a key selection stage, as defined by
    /// #silicon_one::la_ac_profile::set_key_selector_per_format.
    /// Packets whose key matches the (VID1, VID2) are handled by the created AC port.
    ///
    /// @param[in]  port_gid                    Global ID of port to be created.
    /// @param[in]  ethernet_port               Ethernet port to create AC port over.
    /// @param[in]  vid1                        VLAN ID 1.
    /// @param[in]  vid2                        VLAN ID 2.
    /// @param[in]  filter_group                Filter group to use.
    /// @param[in]  ingress_qos_profile         Ingress QoS profile to use.
    /// @param[in]  egress_qos_profile          Egress QoS profile to use.
    /// @param[out] out_l2_service_port         #silicon_one::la_l2_service_port* to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS           Port created successfully. Result placed in out_l2_service_port.
    /// @retval     LA_STATUS_EINVAL            Global ID is out of range or nullptr arguments provided.
    /// @retval     LA_STATUS_EBUSY             Global ID is already used by another port, or VLAN association already used for
    /// the given Ethernet port.
    /// @retval     LA_STATUS_ERESOURCE         Maximal number of AC mapping exists.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    ///
    /// @see        la_ethernet_port::set_ac_profile, la_ac_profile::set_key_selector_per_format
    virtual la_status create_ac_l2_service_port(la_l2_port_gid_t port_gid,
                                                const la_ethernet_port* ethernet_port,
                                                la_vlan_id_t vid1,
                                                la_vlan_id_t vid2,
                                                const la_filter_group* filter_group,
                                                la_ingress_qos_profile* ingress_qos_profile,
                                                la_egress_qos_profile* egress_qos_profile,
                                                la_l2_service_port*& out_l2_service_port)
        = 0;

    /// @brief Create a PWE-type L2 service port.
    ///
    /// PWE ports contain a PWE tag and an L3 destination for transmitted packets.
    /// They can be connected directly to switches, and other L2 service ports.
    ///
    /// @param[in]  port_gid                   Global ID of port to be created.
    /// @param[in]  local_label                Port PWE label for received packets.
    /// @param[in]  remote_label               Port PWE label for transmitted packets.
    /// @param[in]  pwe_gid                    Port PWE Global ID.
    /// @param[in]  destination                L3 destination encapsulating transmitted packets.
    ///                                        Must be an MPLS tunnel, protection group containing only MPLS tunnels,
    ///                                        or ECMP group containing only MPLS tunnels.
    /// @param[in]  ingress_qos_profile        Ingress QoS profile to use.
    /// @param[in]  egress_qos_profile         Egress QoS profile to use.
    /// @param[out] out_l2_service_port        #silicon_one::la_l2_service_port* to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. Result placed in out_port.
    /// @retval     LA_STATUS_EINVAL    Global ID is out of range or nullptr arguments provided.
    /// @retval     LA_STATUS_EBUSY     Global ID is already used by another port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_pwe_l2_service_port(la_l2_port_gid_t port_gid,
                                                 la_mpls_label local_label,
                                                 la_mpls_label remote_label,
                                                 la_pwe_gid_t pwe_gid,
                                                 la_l3_destination* destination,
                                                 la_ingress_qos_profile* ingress_qos_profile,
                                                 la_egress_qos_profile* egress_qos_profile,
                                                 la_l2_service_port*& out_l2_service_port)
        = 0;

    /// @brief Create a PWE-tagged-type L2 service port.
    ///
    /// Packets whose key matches VID1 are handled by the created PWE tagged port, where the key is constructed using the
    /// #silicon_one::la_ac_profile::key_selector_e::PORT_VLAN logic.
    ///
    /// Multiple PWE tagged service ports can have the same local PWE label provided that the VLAN tag is different.
    ///
    /// @param[in]  port_gid                   Global ID of port to be created.
    /// @param[in]  local_label                Port PWE label from received packets.
    /// @param[in]  remote_label               Port PWE label for transmitted packets.
    /// @param[in]  destination                L3 destination encapsulating transmitted packets.
    ///                                        Must be an MPLS tunnel, protection group containing only MPLS tunnels,
    ///                                        or ECMP group containing only MPLS tunnels.
    /// @param[in]  vid1                       VLAN ID 1.
    /// @param[in]  ingress_qos_profile        Ingress QoS profile to use.
    /// @param[in]  egress_qos_profile         Egress QoS profile to use.
    /// @param[out] out_l2_service_port        #silicon_one::la_l2_service_port* to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. Result placed in out_port.
    /// @retval     LA_STATUS_EINVAL    Global ID is out of range or nullptr arguments provided.
    /// @retval     LA_STATUS_EBUSY     Global ID is already used by another port;
    ///                                 Local PWE label is already used, and has different destination;
    ///                                 Local PWE label is already used, and has same vid1/vid2.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_pwe_tagged_l2_service_port(la_l2_port_gid_t port_gid,
                                                        la_mpls_label local_label,
                                                        la_mpls_label remote_label,
                                                        la_l3_destination* destination,
                                                        la_vlan_id_t vid1,
                                                        la_ingress_qos_profile* ingress_qos_profile,
                                                        la_egress_qos_profile* egress_qos_profile,
                                                        la_l2_service_port*& out_l2_service_port)
        = 0;

    /// @brief Create VXLAN L2 port
    ///
    /// @param[in]  port_gid            Global ID of the port to be created.
    /// @param[in]  local_ip_addr       local IP of the tunnel
    /// @param[in]  remote_ip_addr      remote IP of the tunnel
    /// @param[in]  vrf                 VRF the tunnel belongs to
    /// @param[out] out_l2_service_port #silicon_one::la_l2_service_port* to be populated.
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. Result placed in out_l2_service_port
    /// @retval     LA_STATUS_EINVAL    Invalid input parameters
    /// @retval     LA_STATUS_EBUSY     port ID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_vxlan_l2_service_port(la_l2_port_gid_t port_gid,
                                                   la_ipv4_addr_t local_ip_addr,
                                                   la_ipv4_addr_t remote_ip_addr,
                                                   la_vrf* vrf,
                                                   la_l2_service_port*& out_l2_service_port)
        = 0;

    /// @brief Create VXLAN L2 port
    ///
    /// @param[in]  port_gid            Global ID of the port to be created.
    /// @param[in]  tunnel_mode         Operating mode of the tunnel.
    /// @param[in]  local_ip_prefix     local IP prefix of the tunnel
    /// @param[in]  remote_ip_addr      remote IP of the tunnel
    /// @param[in]  vrf                 VRF the tunnel belongs to
    /// @param[out] out_l2_service_port #silicon_one::la_l2_service_port* to be populated.
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. Result placed in out_l2_service_port
    /// @retval     LA_STATUS_EINVAL    Invalid input parameters
    /// @retval     LA_STATUS_EBUSY     port ID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_vxlan_l2_service_port(la_l2_port_gid_t port_gid,
                                                   la_ip_tunnel_mode_e tunnel_mode,
                                                   la_ipv4_prefix_t local_ip_prefix,
                                                   la_ipv4_addr_t remote_ip_addr,
                                                   la_vrf* vrf,
                                                   la_l2_service_port*& out_l2_service_port)
        = 0;

    /// @brief Creates a #silicon_one::la_stack_port over a given system port.
    ///
    /// @param[in]  system_port         System port to create stack port with.
    /// @param[out] out_stack_port      Pointer to #silicon_one::la_stack_port to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Stack port created successfully. out_stack_port contains the created stack port.
    /// @retval     LA_STATUS_EINVAL    System port is invalid.
    /// @retval     LA_STATUS_EBUSY     System port is already used by an aggregate port or ethernet port or stack port; or
    ///                                 Port GID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_stack_port(la_system_port* system_port, la_stack_port*& out_stack_port) = 0;

    /// @brief Creates a #silicon_one::la_stack_port over a given SPA port.
    ///
    /// @param[in]  spa_port            SPA port to create stack port with.
    /// @param[out] out_stack_port      Pointer to #silicon_one::la_stack_port to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Stack port created successfully. out_stack_port contains the created stack port.
    /// @retval     LA_STATUS_EINVAL    SPA port is invalid.
    /// @retval     LA_STATUS_EBUSY     SPA port is already used by an ethernet port; or stack port; or
    ///                                 Port GID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_stack_port(la_spa_port* spa_port, la_stack_port*& out_stack_port) = 0;

    /// @brief Create a new switch object.
    ///
    /// @param[in]  switch_gid          Global ID for the switch.
    /// @param[out] out_switch          Pointer to #silicon_one::la_switch to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Switch created successfully. Handle placed in out_switch.
    /// @retval     LA_STATUS_EINVAL    Global ID is out of range.
    /// @retval     LA_STATUS_EBUSY     Global ID is already used by another switch.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_switch(la_switch_gid_t switch_gid, la_switch*& out_switch) = 0;
    /// @brief Get switch associated with global switch ID.
    ///
    /// @param[in]  sw_gid              Switch global ID.
    ///
    /// @return #silicon_one::la_switch* if switch exists; NULL otherwise.
    virtual la_switch* get_switch_by_id(la_switch_gid_t sw_gid) = 0;

    /// @brief Create a new AC profile object.
    ///
    /// @param[out] out_ac_profile      Pointer to #silicon_one::la_ac_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_ac_profile contains the created profile.
    /// @retval     LA_STATUS_ERESOURCE Maximum number of profiles is already used.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_ac_profile(la_ac_profile*& out_ac_profile) = 0;

    /// @brief Get number of available AC profiles for given device.
    ///
    /// @retval     Number of available AC profiles for given device.
    virtual size_t get_num_of_available_ac_profiles() const = 0;

    /// @}
    /// @name Multicast settings
    /// @{

    /// @brief Create a switch multicast group.
    ///
    /// @param[in]  multicast_gid                Global ID of multicast group.
    /// @param[in]  rep_paradigm                 Replication paradigm for the multicast group.
    /// @param[out] out_l2_multicast_group       Pointer to #silicon_one::la_l2_multicast_group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Multicast GID or profile is invalid.
    /// @retval     LA_STATUS_EBUSY     Multicast global ID is in use.
    /// @retval     LA_STATUS_ERESOURCE Maximal number of multicast groups has already been allocated.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    /// @retval     LA_STATUS_EEXIST    L2 multicast group with the given ID already exists.
    virtual la_status create_l2_multicast_group(la_multicast_group_gid_t multicast_gid,
                                                la_replication_paradigm_e rep_paradigm,
                                                la_l2_multicast_group*& out_l2_multicast_group)
        = 0;

    /// @brief Create IP multicast group.
    ///
    /// @param[in]  multicast_gid             Global ID of multicast group.
    /// @param[in]  rep_paradigm              Replication paradigm for the multicast group.
    /// @param[out] out_ip_multicast_group    #silicon_one::la_ip_multicast_group pointer to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL          Multicast GID or profile is invalid.
    /// @retval     LA_STATUS_EBUSY           Multicast global ID is already in use.
    /// @retval     LA_STATUS_ERESOURCE       Maximal number of multicast groups has already been allocated.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EEXIST          IP multicast group with the given ID already exists.
    virtual la_status create_ip_multicast_group(la_multicast_group_gid_t multicast_gid,
                                                la_replication_paradigm_e rep_paradigm,
                                                la_ip_multicast_group*& out_ip_multicast_group)
        = 0;

    /// @brief Create a fabric multicast group.
    ///
    /// @param[in]  multicast_gid                 Global ID of multicast group, it has to match the relevant
    /// #silicon_one::la_l2_multicast_group/#silicon_one::la_ip_multicast_group's GID.
    /// @param[in]  rep_paradigm                  Replication paradigm for the multicast group.
    /// @param[out] out_fabric_multicast_group    #silicon_one::la_fabric_multicast_group pointer to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL          Multicast GID is invalid, or device is not fabric-element.
    /// @retval     LA_STATUS_EBUSY           Multicast global ID is already in use.
    /// @retval     LA_STATUS_ERESOURCE       Maximal number of multicast groups has already been allocated.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EEXIST          Fabric multicast group with the given ID already exists.
    virtual la_status create_fabric_multicast_group(la_multicast_group_gid_t multicast_gid,
                                                    la_replication_paradigm_e rep_paradigm,
                                                    la_fabric_multicast_group*& out_fabric_multicast_group)
        = 0;

    /// @brief Create MPLS multicast group.
    ///
    /// @param[in]  multicast_gid                  Global ID of multicast group.
    /// @param[in]  rep_paradigm                   Replication paradigm for the multicast group.
    /// @param[out] out_mpls_multicast_group       #silicon_one::la_mpls_multicast_group pointer to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS              Operation completed successfully.
    /// @retval     LA_STATUS_EBUSY                Multicast global ID is in use.
    /// @retval     LA_STATUS_ERESOURCE            Maximal number of multicast groups is allocated.
    /// @retval     LA_STATUS_EUNKNOWN             An unknown error occurred.
    /// @retval     LA_STATUS_EEXIST               MPLS multicast group with the given ID already exists.
    ///
    /// @see create_transmit_multicast_tc_oq_profile and create_ingress_multicast_tc_profile.
    virtual la_status create_mpls_multicast_group(la_multicast_group_gid_t multicast_gid,
                                                  la_replication_paradigm_e rep_paradigm,
                                                  la_mpls_multicast_group*& out_mpls_multicast_group)
        = 0;

    /// @brief Get a switch multicast group.
    ///
    /// @param[in]  multicast_gid            Global ID of multicast group.
    /// @param[out] out_l2_multicast_group   #silicon_one::la_l2_multicast_group pointer to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL         Multicast GID is invalid.
    /// @retval     LA_STATUS_ENOTFOUND      The global ID does not map to any multicast group.
    virtual la_status get_l2_multicast_group(la_multicast_group_gid_t multicast_gid,
                                             la_l2_multicast_group*& out_l2_multicast_group) const = 0;

    /// @brief Get an IP multicast group.
    ///
    /// @param[in]  multicast_gid            Global ID of multicast group.
    /// @param[out] out_ip_multicast_group   #silicon_one::la_ip_multicast_group pointer to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL         Multicast GID is invalid.
    /// @retval     LA_STATUS_ENOTFOUND      The global ID does not map to any multicast group.
    virtual la_status get_ip_multicast_group(la_multicast_group_gid_t multicast_gid,
                                             la_ip_multicast_group*& out_ip_multicast_group) const = 0;

    /// @brief Get a Fabric multicast group.
    ///
    /// @param[in]  multicast_gid                Global ID of multicast group.
    /// @param[out] out_fabric_multicast_group   #silicon_one::la_fabric_multicast_group pointer to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL         Multicast GID is invalid, or device is not fabric-element.
    /// @retval     LA_STATUS_ENOTFOUND      The global ID does not map to any multicast group.
    virtual la_status get_fabric_multicast_group(la_multicast_group_gid_t multicast_gid,
                                                 la_fabric_multicast_group*& out_fabric_multicast_group) const = 0;
    /// @brief Get MPLS multicast group.
    ///
    /// @param[in]  multicast_gid              Global ID of multicast group.
    /// @param[out] out_mpls_multicast_group   #silicon_one::la_mpls_multicast_group pointer to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL           Multicast GID is invalid.
    /// @retval     LA_STATUS_ENOTFOUND        The global ID does not map to any multicast group.
    virtual la_status get_mpls_multicast_group(la_multicast_group_gid_t multicast_gid,
                                               la_mpls_multicast_group*& out_mpls_multicast_group) const = 0;

    /// @brief Create a MPLS label destination object.
    ///
    /// MPLS label destination objects can be chained with MPLS tunnels to define
    /// complex MPLS scenarios such as per-CE VPN tunnels and swap-and-push operations.
    ///
    ///
    /// @param[in]     gid                             L3 destination global ID.
    /// @param[in]     label                           Inner label (before the MPLS label).
    /// @param[in]     destination                     L3 destination.
    /// @param[out]    out_mpls_label_destination      Return the newly created tunnel object.
    ///
    /// @retval     LA_STATUS_SUCCESS       Tunnel created successfully. Result placed in out_mpls_label_destination.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status create_mpls_label_destination(la_l3_destination_gid_t gid,
                                                    la_mpls_label label,
                                                    la_l3_destination* destination,
                                                    la_mpls_label_destination*& out_mpls_label_destination)
        = 0;

    /// @brief Create a MPLS VPN encap object.
    ///
    /// MPLS VPN encap object is to be associated with VPN IP prefix to determine the VPN label
    /// for a given object.
    ///
    /// @param[in]     gid                  MPLS VPN encap object global ID.
    /// @param[out]    out_mpls_vpn_encap   Return the newly created MPLS VPN encap object.
    ///
    /// @retval     LA_STATUS_SUCCESS       MPLS VPN encap object created successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status create_mpls_vpn_encap(la_mpls_vpn_encap_gid_t gid, la_mpls_vpn_encap*& out_mpls_vpn_encap) = 0;

    /// @brief Get MPLS VPN encap object using its global ID.
    ///
    /// @param[in]     gid                  MPLS VPN encap object global ID.
    /// @param[out]    out_mpls_vpn_encap   Return the MPLS VPN encap object.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_ENOTFOUND  The global ID does not map to any MPLS VPN encap object.
    /// @retval    LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status get_mpls_vpn_encap_by_gid(la_mpls_vpn_encap_gid_t gid, la_mpls_vpn_encap*& out_mpls_vpn_encap) const = 0;

    /// @brief Create a Prefix object.
    ///
    /// Prefix objects are used to create MPLS LDP or TE tunnels.
    ///
    /// @param[in]     gid              Prefix object global ID.
    /// @param[in]     destination      L3 destination.
    /// @param[in]     type             Prefix object type.
    /// @param[out]    out_prefix       Return the newly created prefix object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Prefix object created successfully. Result placed in out_prefix.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_EBUSY     GID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_prefix_object(la_l3_destination_gid_t gid,
                                           const la_l3_destination* destination,
                                           la_prefix_object::prefix_type_e type,
                                           la_prefix_object*& out_prefix)
        = 0;

    //
    /// @brief Get a Prefix object using its global ID.
    ///
    /// @param[in]     gid              Prefix object global ID.
    /// @param[out]    out_prefix       Pointer to #silicon_one::la_prefix_object to populate.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_ENOTFOUND  The global ID does not map to any prefix object.
    /// @retval    LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status get_prefix_object_by_id(la_l3_destination_gid_t gid, la_prefix_object*& out_prefix) const = 0;

    /// @brief Create IP tunnel destination.
    ///
    /// IP tunnel destination is used to represent the tunnel destination on the overlay.
    ///
    /// @param[in]     gid                        IP tunnel destination ID.
    /// @param[in]     ip_tunnel_port             The ip tunnel port.
    /// @param[in]     underlay_destination       The underlay destination to reach tunnel destination.
    /// @param[out]    out_ip_tunnel_destination  Return the newly created ip tunnel destination.
    ///
    /// @retval     LA_STATUS_SUCCESS   IP tunnel destination created successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid. Or GID is invalid.
    /// @retval     LA_STATUS_EBUSY     GID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_ip_tunnel_destination(la_l3_destination_gid_t gid,
                                                   const la_l3_port* ip_tunnel_port,
                                                   const la_l3_destination* underlay_destination,
                                                   la_ip_tunnel_destination*& out_ip_tunnel_destination)
        = 0;

    /// @brief Get IP tunnel destination using its global ID.
    ///
    /// @param[in]     gid                         IP tunnel destination global ID.
    /// @param[out]    out_ip_tunnel_destination   Pointer to #silicon_one::la_ip_tunnel_destination to populate.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_ENOTFOUND  The global ID does not map to any prefix object.
    /// @retval    LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status get_ip_tunnel_destination_by_gid(la_l3_destination_gid_t gid,
                                                       la_ip_tunnel_destination*& out_ip_tunnel_destination) const = 0;

    /// @brief Create a Destination PE in the Remote AS in an Inter AS configuration.
    ///
    /// Destination PE represents a node in the remote AS in an Inter AS configuration to which traffic is destined to.
    ///
    /// @param[in]     destination_pe_gid  Global ID of the destination_PE.
    /// @param[in]     destination         L3 destination.
    /// @param[out]    out_destination_pe  Return the newly created destination pe.
    ///
    /// @retval     LA_STATUS_SUCCESS   Destination PE created successfully. Result placed in out_destination_pe.
    /// @retval     LA_STATUS_EINVAL    The destination PE GID is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_destination_pe(la_l3_destination_gid_t destination_pe_gid,
                                            const la_l3_destination* destination,
                                            la_destination_pe*& out_destination_pe)
        = 0;

    /// @brief Create a labeled path to reach an ASBR destination.
    ///
    /// ASBR LSPs are used to create/enable forwarding paths to send traffic to remote ASBRs.
    ///
    /// @param[in]  asbr                Prefix object representing the ASBR.
    /// @param[in]  destination         Represents the next destination to which the traffic should be sent to.
    /// @param[out] out_asbr_lsp        Return the newly created ASBR LSP.
    ///
    /// @retval     LA_STATUS_SUCCESS   ASBR LSP created successfully.
    /// @retval     LA_STATUS_EINVAL    Either the ASBR or the next destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_asbr_lsp(const la_prefix_object* asbr,
                                      const la_l3_destination* destination,
                                      la_asbr_lsp*& out_asbr_lsp)
        = 0;

    /// @brief Get the ASBR LSP using the ASBR and destination pair.
    ///
    /// @param[in]     asbr             Prefix object representing the ASBR.
    /// @param[in]     destination      Represents the next destination to which the traffic should be sent to.
    /// @param[out]    out_asbr_lsp     Return the ASBR LSP if found.
    ///
    /// @retval     LA_STATUS_SUCCESS   ASBR LSP retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Either the ASBR or the next destination is invalid.
    /// @retval     LA_STATUS_ENOTFOUND An ASBR LSP was not found.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_asbr_lsp(const la_prefix_object* asbr, const la_l3_destination* destination, la_asbr_lsp*& out_asbr_lsp)
        = 0;

    /// @brief Create a TE tunnel.
    ///
    /// TE tunnel is used to create MPLS RSVP-TE tunnel.
    ///
    /// @param[in]     gid              TE Tunnel global ID.
    /// @param[in]     destination      L3 destination.
    /// @param[in]     type             TE tunnel type.
    /// @param[out]    out_te_tunnel    Return the newly created TE tunnel.
    ///
    /// @retval     LA_STATUS_SUCCESS   TE Tunnel created successfully. Result placed in out_te_tunnel.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_EBUSY     GID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_te_tunnel(la_te_tunnel_gid_t gid,
                                       const la_l3_destination* destination,
                                       la_te_tunnel::tunnel_type_e type,
                                       la_te_tunnel*& out_te_tunnel)
        = 0;

    /// @brief Create a pbts map profile.
    ///
    /// @param[in]  level                   PBTS MAP Profile Resolution level.
    /// @param[in]  max_offset              Number of destinations used by this profile.
    /// @param[out] out_pbts_map_profile    Pointer to a #silicon_one::la_pbts_map_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully. out_pbts_map_profile contains the PBTS Map
    /// profile.
    /// @retval     LA_STATUS_ERESOURCE         Maximum number of PBTS Map profiles is already used.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status create_pbts_map_profile(la_pbts_map_profile::level_e level,
                                              la_pbts_destination_offset max_offset,
                                              la_pbts_map_profile*& out_pbts_map_profile)
        = 0;

    /// @brief Create a group of L3 destination members.
    /// Currently supports #silicon_one::la_prefix_object and #silicon_one::la_ecmp_group
    ///
    /// @param[in]     profile           #silicon_one::la_pbts_map_profile used by this group.
    /// @param[out]    out_pbts_group    Return the newly created pbts group.
    ///
    /// @retval     LA_STATUS_SUCCESS   pbts group created successfully. Result placed in out_pbts_group.
    /// @retval     LA_STATUS_EINVAL    profile max_result_offset doesnt match ecmp_set size
    /// @retval     LA_STATUS_EBUSY     One of the GIDs to be used by this group is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_pbts_group(la_pbts_map_profile* profile, la_pbts_group*& out_pbts_group) = 0;

    /// @brief Create MPLS swap NHLFE object.
    ///
    /// @param[in]  next_hop          Destination.
    /// @param[in]  label             New label.
    /// @param[out] out_nhlfe         Newly created NHLFE object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_mpls_swap_nhlfe(const la_next_hop* next_hop, la_mpls_label label, la_mpls_nhlfe*& out_nhlfe) = 0;

    /// @brief Create MPLS PHP NHLFE object.
    ///
    /// @param[in]  next_hop          Destination.
    /// @param[out] out_nhlfe         Newly created NHLFE object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_mpls_php_nhlfe(const la_next_hop* next_hop, la_mpls_nhlfe*& out_nhlfe) = 0;

    /// @brief Create MPLS Tunnel Protection NHLFE object.
    ///
    /// @param[in]  l3_protection_group     Destination.
    /// @param[in]  te_label                Primary TE label.
    /// @param[in]  mp_label                Merge-Point label.
    /// @param[out] out_nhlfe               Newly created NHLFE object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_mpls_tunnel_protection_nhlfe(const la_l3_protection_group* l3_protection_group,
                                                          la_mpls_label te_label,
                                                          la_mpls_label mp_label,
                                                          la_mpls_nhlfe*& out_nhlfe)
        = 0;

    /// @brief Create MPLS L2 Adjacency NHLFE object.
    ///
    /// @param[in]  prefix          Destination prefix object.
    /// @param[in]  dsp             L2 adjacency system port.
    /// @param[out] out_nhlfe       Newly created NHLFE object.
    ///
    /// @retval   LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval   LA_STATUS_EINVAL    Prefix object destination or destination system port is invalid.
    /// @retval   LA_STATUS_UNKNOWN   An unknown error occured.
    virtual la_status create_mpls_l2_adjacency_nhlfe(const la_prefix_object* prefix,
                                                     const la_system_port* dsp,
                                                     la_mpls_nhlfe*& out_nhlfe)
        = 0;

    /// @brief Get the global LSR object.
    ///
    /// @param[out]    out_lsr  Global LSR object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_lsr(la_lsr*& out_lsr) = 0;

    /// @brief Set tunnel TTL inheritance mode for the device.
    ///
    /// @param[in]    mode   The TTL mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode) = 0;

    /// @brief Get TTL inheritance mode.
    ///
    /// @retval     The Device's TTL inheritance mode.
    virtual la_mpls_ttl_inheritance_mode_e get_ttl_inheritance_mode() const = 0;

    /// @brief Get the global for-us destination object.
    ///
    /// @param[out]    out_forus_destination  for-us destination object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_forus_destination(la_forus_destination*& out_forus_destination) = 0;

    /// @}
    /// @name TM settings
    /// @{

    /// @brief Set a device's fabric mode.
    ///
    /// Fabric mode determines how load-balancing is performed towards fabric slices.
    ///
    /// @param[in]      mode            Mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_fabric_mode(la_fabric_mode_e mode) = 0;

    /// @brief Set fabric delay for segment load-balancing purposes.
    ///
    /// @param[in]      delay           Fabric delay.
    ///
    /// @retval     LA_STATUS_SUCCESS   Delay set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_slb_fabric_delay(la_float_t delay) = 0;

    /// @brief Set maximum allowed packets per-second utilization per IFG.
    ///
    /// @note Actual value may be lower than the configured value due to accuracy limitations.
    /// @note This controls only Network slices.
    ///
    /// @param[in]  max_pps_percent         Maximum packets per-second percentage. Acceptable range is [0..1].
    ///
    /// @retval     LA_STATUS_SUCCESS       Maximum packet per-second percentage set successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid value.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_ifg_maximum_pps_utilization(la_float_t max_pps_percent) = 0;

    /// @brief Retrieve maximum allowed packets per-second utilization per-IFG.
    ///
    ///
    /// @param[out] out_max_pps_percent Maximum packets per-second percentage.
    ///
    /// @retval     LA_STATUS_SUCCESS   Maximum packets per-second percentage retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ifg_maximum_pps_utilization(la_float_t& out_max_pps_percent) const = 0;

    /// @brief Get a device's IFG scheduler.
    ///
    /// @param[in]  slice_id            Scheduler slice ID.
    /// @param[in]  ifg_id              Scheduler IFG ID.
    /// @param[out] out_sch             #silicon_one::la_ifg_scheduler* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Scheduler fetched successfully. out_sch contains the scheduler.
    /// @retval     LA_STATUS_EINVAL    Slice or IFG ID are out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ifg_scheduler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, la_ifg_scheduler*& out_sch) const = 0;

    /// @brief Create Output Queue scheduler.
    ///
    /// @param[in]  slice_id            Scheduler slice ID.
    /// @param[in]  ifg_id              Scheduler IFG ID.
    /// @param[in]  mode                Scheduling mode.
    /// @param[out] out_oq_sch          Pointer to #silicon_one::la_output_queue_scheduler to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_oq_sch contains the OQ scheduler.
    /// @retval     LA_STATUS_EINVAL    out_oq_sch is NULL.
    /// @retval     LA_STATUS_ERESOURCE Insufficient resources to allocate
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_output_queue_scheduler(la_slice_id_t slice_id,
                                                    la_ifg_id_t ifg_id,
                                                    la_output_queue_scheduler::scheduling_mode_e mode,
                                                    la_output_queue_scheduler*& out_oq_sch)
        = 0;

    /// @brief Set the quantization thresholds for the number of valid fabric links.
    ///
    /// If # of valid links < threshold 0, give a value of 3, # of valid links >= threshold 0 and # valid links < threshold 1,
    /// give value of 2, etc.
    ///
    /// @param[in]  thresholds      Thresholds to configure, given in # of links.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Thresholds invalid.
    /// @retval     LA_STATUS_EUNKNOWN  Unknown error occurred.
    virtual la_status set_fabric_sch_valid_links_quantization_thresholds(const la_fabric_valid_links_thresholds& thresholds) = 0;

    /// @brief Get the quantization thresholds for the number of valid fabric links.
    ///
    /// @param[out]  out_thresholds      Thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  Unknown error occurred.
    virtual la_status get_fabric_sch_valid_links_quantization_thresholds(la_fabric_valid_links_thresholds& out_thresholds) = 0;

    /// @brief Set the quantization thresholds for the number of congested fabric links.
    ///
    /// If # of valid links < threshold 0, give a value of 0, # of valid links >= threshold 0 and # valid links < threshold 1,
    /// give a value of 1, etc.
    ///
    /// @param[in]  thresholds      Thresholds to configure, given in # of links.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Thresholds invalid.
    /// @retval     LA_STATUS_EUNKNOWN  Unknown error occurred.
    virtual la_status set_fabric_sch_congested_links_quantization_thresholds(const la_fabric_congested_links_thresholds& thresholds)
        = 0;

    /// @brief Get the quantization thresholds for the number of congested fabric links.
    ///
    /// @param[out]  out_thresholds      Thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  Unknown error occurred.
    virtual la_status get_fabric_sch_congested_links_quantization_thresholds(la_fabric_congested_links_thresholds& out_thresholds)
        = 0;

    /// @brief Set the fabric scheduling rate for a given index.
    ///
    /// The index to use for fabric scheduling is determined via the API #silicon_one::la_device::set_fabric_sch_links_map_entry.
    ///
    /// @param[in]  index       Index to program in the rate map table.
    /// @param[in]  rate        Rate to program, in KBs.
    ///
    /// @retval LA_STATUS_SUCCESS   Rate programmed successfully.
    /// @retval LA_STATUS_EINVAL    Index or rate invalid.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error occured.
    virtual la_status set_fabric_sch_rate_map_entry(la_uint_t index, la_uint_t rate) = 0;

    /// @brief Get the fabric scheduling rate for a given index.
    ///
    /// @param[in]  index       Index to get in the rate map table.
    /// @param[out] out_rate    Rate to populate, in KB.
    ///
    /// @retval LA_STATUS_SUCCESS   Rate programmed successfully.
    /// @retval LA_STATUS_EINVAL    Index invalid
    /// @retval LA_STATUS_EUNKNOWN  Unknown error occured.
    virtual la_status get_fabric_sch_rate_map_entry(la_uint_t index, la_uint_t& out_rate) = 0;

    /// @brief Program the mapping from valid link status and congested link status to an index in the rate map table.
    ///
    /// Maps a 2 bit valid link status and a 2 bit congested link status (16 options), to a 2 bit rate map table index.
    ///
    /// @param[in]  valid_link_status       Status of valid link mapping.
    /// @param[in]  congested_link_status   Status of congested link mapping.
    /// @param[in]  rate_map_index          Index of rate map table.
    ///
    /// @retval LA_STATUS_SUCCESS   Mapping programmed successfully.
    /// @retval LA_STATUS_EINVAL    Status or index invalid.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error occured.
    virtual la_status set_fabric_sch_links_map_entry(la_uint_t valid_link_status,
                                                     la_uint_t congested_link_status,
                                                     la_uint_t rate_map_index)
        = 0;

    /// @brief Get the mapping from valid link status and congested link status to an index in the rate map table.
    ///
    /// @param[in]  valid_link_status       Status of valid link mapping.
    /// @param[in]  congested_link_status   Status of congested link mapping.
    /// @param[out] out_rate_map_index      Index to populate.
    ///
    /// @retval LA_STATUS_SUCCESS   Mapping programmed successfully.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error occured.
    virtual la_status get_fabric_sch_links_map_entry(la_uint_t valid_link_status,
                                                     la_uint_t congested_link_status,
                                                     la_uint_t& out_rate_map_index)
        = 0;

    /// @}
    /// @name VOQ API-s
    /// @{

    /// @brief Create a set of Virtual Output Queues.
    ///
    /// Each #NATIVE_VOQ_SET_SIZE VOQs share a single device/slice/ifg/VSC base values.
    /// Trying to create VOQ sets which share the same #NATIVE_VOQ_SET_SIZE group but
    /// have different values for these will result in LA_STATUS_EBUSY.
    ///
    /// @param[in]  base_voq_id           Base VOQ ID for this VOQ set.
    /// @param[in]  set_size              Number of VOQs in the set.
    /// @param[in]  base_vsc_vec          Base VSC ID vector. Each entry is the base VSC ID of a slice. For non-network slice,
    /// the
    ///                                   value must be LA_VSC_GID_INVALID.
    /// @param[in]  dest_device           Destination device.
    /// @param[in]  dest_slice            Destination slice.
    /// @param[in]  dest_ifg              Destination IFG ID.
    /// @param[out] out_voq_set           Pointer to #silicon_one::la_voq_set to populate.
    ///
    /// @return     status.
    /// @retval     LA_STATUS_SUCCESS   VOQ created successfully. out_voq contains the VOQ.
    /// @retval     LA_STATUS_EEXIST    VOQs with the given IDs already exist.
    /// @retval     LA_STATUS_EINVAL    Destination device/slice/VSC are invalid;
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_voq_set(la_voq_gid_t base_voq_id,
                                     size_t set_size,
                                     const la_vsc_gid_vec_t& base_vsc_vec,
                                     la_device_id_t dest_device,
                                     la_slice_id_t dest_slice,
                                     la_ifg_id_t dest_ifg,
                                     la_voq_set*& out_voq_set)
        = 0;

    /// @brief   Create a unicast Traffic-Class->VOQ profile.
    ///
    /// @param[out] out_tc_profile         Pointer to #silicon_one::la_tc_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Profile created successfully.
    /// @retval     LA_STATUS_ERESOURCE No more profiles to allocate.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_tc_profile(la_tc_profile*& out_tc_profile) = 0;

    /// @brief       Get per-slice VOQ-set for egress replication.
    ///
    /// @param[in]   dest_slice          Destination slice ID.
    /// @param[out]  out_voq_set         Pointer to #silicon_one::la_voq_set.
    ///
    /// @retval      LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval      LA_STATUS_ENOTFOUND      No VOQ set on slice.
    /// @retval      LA_STATUS_EUNKNOWN       An unknown error occurred.
    virtual la_status get_egress_multicast_slice_replication_voq_set(la_slice_id_t dest_slice, la_voq_set*& out_voq_set) const = 0;

    /// @brief       Get VOQ-set for fabric egress replication.
    ///
    /// @param[out]  out_voq_set         Pointer to #silicon_one::la_voq_set.
    ///
    /// @retval      LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval      LA_STATUS_EINVAL         The device is not in Linecard mode.
    /// @retval      LA_STATUS_EUNKNOWN       An unknown error occurred.
    virtual la_status get_egress_multicast_fabric_replication_voq_set(la_voq_set*& out_voq_set) const = 0;

    /// @brief  Set the priority level for a traffic class for slice replication.
    ///
    /// @param[in]  tc                 Traffic class.
    /// @param[in]  voq_offset         Traffic class is mapped to voq_base + voq_offset, VOQs with offsets 0-5 are low priority,
    /// VOQs with offsets 6 and 7 are high priority.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note This API is still WIP.
    virtual la_status set_egress_multicast_slice_replication_tc_mapping(la_traffic_class_t tc, la_uint_t voq_offset) = 0;

    /// @brief   Get the default VOQ Congestion Management evicted profile.
    ///
    /// @param[out] out_evicted_profile Pointer to #silicon_one::la_voq_cgm_evicted_profile.
    ///
    /// @retval     LA_STATUS_SUCCESS   Profile created successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_voq_cgm_default_evicted_profile(const la_voq_cgm_evicted_profile*& out_evicted_profile) const = 0;

    /// @brief   Create a VOQ Congestion Management evicted profile.
    ///
    /// @param[out] out_evicted_profile Pointer to #silicon_one::la_voq_cgm_evicted_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Profile created successfully.
    /// @retval     LA_STATUS_ERESOURCE No more profiles to allocate.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_voq_cgm_evicted_profile(la_voq_cgm_evicted_profile*& out_evicted_profile) = 0;

    /// @brief   Create a VOQ Congestion Management profile.
    ///
    /// @param[out] out_profile         Pointer to #silicon_one::la_voq_cgm_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Profile created successfully.
    /// @retval     LA_STATUS_ERESOURCE No more profiles to allocate.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_voq_cgm_profile(la_voq_cgm_profile*& out_profile) = 0;

    /// @brief   Set the maximum value that the VOQ credit balance can go negative.
    ///
    /// @param[in] balance      Maximum negative value.
    ///
    /// @retval     LA_STATUS_SUCCESS   Value updated successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid balance value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured
    virtual la_status set_voq_max_negative_credit_balance(la_uint_t balance) = 0;

    /// @brief   Get the maximum value that the VOQ credit balance can go negative.
    ///
    /// @param[out] out_balance      Value to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Value retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured
    virtual la_status get_voq_max_negative_credit_balance(la_uint_t& out_balance) = 0;

    /// @brief   Create a Bidirectional Forwarding Detection (BFD) session
    ///
    /// @param[in]  local_discriminator  Local discriminator value for this BFD session.
    ///                                  The full 32b of the discriminator determines the session.
    ///                                  In a distributed system, the 16 msb of the discriminator along
    ///                                  with the session_type and protocol route the packet to the correct
    ///                                  NPU host destination where the session is programmed. It is up
    ///                                  to the application to ensure that there is a 1:1 relationship between
    ///                                  16b msb of the discriminator, session_type and protocol to an NPU host.
    /// @param[in]  session_type         Type of the BFD session.
    /// @param[in]  protocol             #la_l3_protocol_e::IPV4_UC or #la_l3_protocol_e::IPV6_UC
    /// @param[in]  punt_destination     NPU host or CPU destination where this session is sent.
    /// @param[out] out_bfd_session      Pointer to #silicon_one::la_bfd_session to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS    Session created successfully.
    /// @retval     LA_STATUS_EINVAL     Invalid protocol or local port
    /// @retval     LA_STATUS_ERESOURCE  Insufficient resources
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status create_bfd_session(la_bfd_discriminator local_discriminator,
                                         la_bfd_session::type_e session_type,
                                         la_l3_protocol_e protocol,
                                         const la_punt_destination* punt_destination,
                                         la_bfd_session*& out_bfd_session)
        = 0;

    /// @brief   Set the Inject up destination MAC address for BFD session packets.
    ///
    /// This should be the mac of an inject port.
    ///
    /// @param[in]  mac_addr             Destination Mac address.
    ///
    /// @retval     LA_STATUS_SUCCESS    Mac address set successfully.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status set_bfd_inject_up_mac_address(la_mac_addr_t mac_addr) = 0;

    /// @brief   Get the Inject up destination MAC address for BFD session packets.
    ///
    /// @param[out] out_mac_addr         Mac address to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS    Mac address successfully returned.
    virtual la_status get_bfd_inject_up_mac_address(la_mac_addr_t& out_mac_addr) const = 0;

    /// @}
    /// @name CM API-s
    /// @{

    /// @brief Set the quantization thresholds for the size in bytes that all VOQs consume in the SMS. DEPRECATED.
    ///
    /// Set the quantization thresholds that translates the instantaneous size in bytes that all VOQs consume in the SMS to
    /// regions. Internally, the granularity of the VOQ size is in chunks of 384B.
    ///
    /// @param[in]  thresholds          Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_sms_voqs_bytes_quantization(const la_cgm_sms_bytes_quantization_thresholds& thresholds) = 0;

    /// @brief Get the quantization thresholds for the size in bytes that all VOQs consume in the SMS. DEPRECATED.
    ///
    /// @param[out] out_thresholds      Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_sms_voqs_bytes_quantization(la_cgm_sms_bytes_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the quantization thresholds for the size in bytes that all VOQs consume in the SMS.
    ///
    /// Set the quantization thresholds that translates the instantaneous size in bytes that all VOQs consume in the SMS to
    /// regions. Internally, the granularity of the VOQ size is in chunks of 384B.
    ///
    /// @param[in]  thresholds          Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_sms_voqs_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get the quantization thresholds for the size in bytes that all VOQs consume in the SMS.
    ///
    /// @param[out] out_thresholds      Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_sms_voqs_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set SMS total evicted bytes quantization thresholds.
    ///
    /// Set the quantization thresholds that translates the bytes used by all VOQs evicted to HBM, to regions.
    ///
    /// @param[in]  thresholds          quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_sms_evicted_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get SMS total evicted bytes quantization thresholds.
    ///
    /// @param[out] out_thresholds      quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_sms_evicted_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the quantization thresholds for the size in packets that all VOQs consume in the SMS. DEPRECATED.
    ///
    /// Set the quantization thresholds that translates the instantaneous size in packets that all VOQs consume in the SMS to
    /// regions.
    ///
    /// @param[in]  thresholds          Packets quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_sms_voqs_packets_quantization(const la_cgm_sms_packets_quantization_thresholds& thresholds) = 0;

    /// @brief Get quantization thresholds for the size in packets that all VOQs consume in the SMS. DEPRECATED.
    ///
    /// @param[out] out_thresholds      Packets quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_sms_voqs_packets_quantization(la_cgm_sms_packets_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the quantization thresholds for the size in packets that all VOQs consume in the SMS.
    ///
    /// Set the quantization thresholds that translates the instantaneous size in packets that all VOQs consume in the SMS to
    /// regions.
    ///
    /// @param[in]  thresholds          Packets quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_sms_voqs_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get quantization thresholds for the size in packets that all VOQs consume in the SMS.
    ///
    /// @param[out] out_thresholds      Packets quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_sms_voqs_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the quantization thresholds for the numbers of VOQs in the HBM. DEPRECATED.
    ///
    /// Set the quantization thresholds that translates the instantaneous number of VOQs evicted to the HBM, to regions.
    ///
    /// @param[in]  thresholds          Number of evicted VOQs quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_hbm_number_of_voqs_quantization(const la_cgm_hbm_number_of_voqs_quantization_thresholds& thresholds)
        = 0;

    /// @brief Get the quantization thresholds for the numbers of VOQs in the HBM. DEPRECATED.
    ///
    /// @param[out] out_thresholds      Number of evicted VOQs quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_hbm_number_of_voqs_quantization(
        la_cgm_hbm_number_of_voqs_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the quantization thresholds for the numbers of VOQs in the HBM.
    ///
    /// Set the quantization thresholds that translates the instantaneous number of VOQs evicted to the HBM, to regions.
    ///
    /// @param[in]  thresholds          Number of evicted VOQs quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_hbm_number_of_voqs_quantization(const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get the quantization thresholds for the numbers of VOQs in the HBM.
    ///
    /// @param[out] out_thresholds      Number of evicted VOQs quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_hbm_number_of_voqs_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set max capacity of a given HBM pool.
    ///
    /// HBM is divided to 2 pools. Set the max size of a given pool.
    ///
    /// @param[in]  hbm_pool_id             HBM pool ID.
    /// @param[in]  threshold               Max size of the given pool related to the whole HBM size.
    ///
    /// @retval     LA_STATUS_SUCCESS       Threshold was set successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Threshold is lower than 0 or greater than 1.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float threshold) = 0;

    /// @brief Get the max capacity of a given HBM pool.
    ///
    /// @param[in]  hbm_pool_id             HBM pool ID.
    /// @param[out] out_threshold           Threshold of the given pool related to the whole HBM size.
    ///
    /// @retval     LA_STATUS_SUCCESS       Threshold was set successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float& out_threshold) const = 0;

    /// @brief Set the quantization thresholds for the free blocks in an HBM pool. DEPRECATED.
    ///
    /// Set the quantization thresholds that translates the instantaneous number free blocks in an HBM pool, to regions.
    ///
    /// @note For Pacific, HBM count granularity is 16 blocks.
    /// Thresholds are rounded to the lower discrete value.
    ///
    /// @param[in]  hbm_pool_id         HBM pool ID.
    /// @param[in]  thresholds          Free blocks in an HBM pool thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_hbm_pool_free_blocks_quantization(
        la_cgm_hbm_pool_id_t hbm_pool_id,
        const la_cgm_hbm_pool_free_blocks_quantization_thresholds& thresholds)
        = 0;

    /// @brief Get the quantization thresholds for the free blocks in an HBM pool. DEPRECATED.
    ///
    /// @param[in]  hbm_pool_id         HBM pool ID.
    /// @param[out] out_thresholds      Free blocks in an HBM pool thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_hbm_pool_free_blocks_quantization(
        la_cgm_hbm_pool_id_t hbm_pool_id,
        la_cgm_hbm_pool_free_blocks_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the quantization thresholds for the free blocks in an HBM pool.
    ///
    /// Set the quantization thresholds that translates the instantaneous number free blocks in an HBM pool, to regions.
    ///
    /// @note For Pacific, HBM count granularity is 16 blocks.
    /// Thresholds are rounded to the lower discrete value.
    ///
    /// @param[in]  hbm_pool_id         HBM pool ID.
    /// @param[in]  thresholds          Free blocks in an HBM pool thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                                const la_voq_cgm_quantization_thresholds& thresholds)
        = 0;

    /// @brief Get the quantization thresholds for the free blocks in an HBM pool.
    ///
    /// @param[in]  hbm_pool_id         HBM pool ID.
    /// @param[out] out_thresholds      Free blocks in an HBM pool thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                                la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set a VOQ-in-HBM age quantization thresholds.
    ///
    /// Set the quantization thresholds in milliseconds that translates the HBM queue delay to regions.
    ///
    /// @param[in]  thresholds          quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_hbm_voq_age_quantization(const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get a VOQ-in-HBM age quantization thresholds.
    ///
    /// @param[out] out_thresholds      quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_hbm_voq_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set a VOQ-in-HBM size in blocks quantization thresholds. DEPRECATED
    ///
    /// Set the quantization thresholds that translates the instantaneous size in blocks of a VOQ the HBM pool, to regions.
    ///
    /// @note For Pacific, HBM count granularity is 16 blocks.
    /// Thresholds are rounded to the lower discrete value.
    ///
    /// @param[in]  thresholds          Blocks quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_hbm_blocks_by_voq_quantization(const la_cgm_hbm_blocks_by_voq_quantization_thresholds& thresholds)
        = 0;

    /// @brief Get a VOQ-in-HBM size in blocks quantization thresholds. DEPRECATED
    ///
    /// @param[out] out_thresholds      Blocks quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_hbm_blocks_by_voq_quantization(
        la_cgm_hbm_blocks_by_voq_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set a VOQ-in-HBM size in blocks quantization thresholds.
    ///
    /// Set the quantization thresholds that translates the instantaneous size in blocks of a VOQ the HBM pool, to regions.
    ///
    /// @note For Pacific, HBM count granularity is 16 blocks.
    /// Thresholds are rounded to the lower discrete value.
    ///
    /// @param[in]  thresholds          Blocks quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cgm_hbm_blocks_by_voq_quantization(const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get a VOQ-in-HBM size in blocks quantization thresholds.
    ///
    /// @param[out] out_thresholds      Blocks quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cgm_hbm_blocks_by_voq_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the mark probability of the level for ecn mark feature.
    ///
    /// Internally convert the float probability to bits and program the ASIC.
    ///
    /// @param[in]  level                      ECN mark level of dequeue
    /// @param[in]  probability                Probability between 0 and 1
    ///
    /// @retval     LA_STATUS_SUCCESS          ECN level-probobality table programmed successfully
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status set_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(la_uint_t level, float probability) = 0;

    /// @brief Get the mark probability of the level.
    ///
    /// Internally get the probability bits programmed to ASIC and convert to float.
    ///
    /// the RXPDR to regions. Internally, the granularity of the size is in buffers.
    /// @param[in]  level                      ECN mark level of dequeue
    /// @param[in]  out_probability            Programmed probability between 0 and 1.
    ///
    /// @retval     LA_STATUS_SUCCESS          Successfully get probability
    /// @retval     LA_STATUS_EINVAL           Received invalid inputs.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status get_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(la_uint_t level, float& out_probability) = 0;

    /// @brief Clear the mark probability of the level.
    ///
    /// @param[in]  level                      ECN mark level of dequeue
    ///
    /// @retval     LA_STATUS_SUCCESS          ECN level-probobality table programmed successfully
    /// @retval     LA_STATUS_EINVAL           Received invalid inputs.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status clear_cgm_sms_voqs_deque_congestion_level_mark_ecn_probability(la_uint_t level) = 0;

    /// @brief Set the VOQ-in-SMS age time units.
    ///
    /// In Pacific, the allowed time unit values are 1000 [nanosecond] and 2000 [nanosecond].
    ///
    /// @param[in]  sms_voqs_age_time_units     VOQ-in-SMS age time units in nanoseconds.
    ///
    /// @retval     LA_STATUS_SUCCESS           Time units updated successfully.
    /// @retval     LA_STATUS_EINVAL            Invalid time unit value.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    ///
    /// @note Changing time units causes penalty on VOQ profiles adjustment to new units.
    virtual la_status set_cgm_sms_voqs_age_time_granularity(la_cgm_sms_voqs_age_time_units_t sms_voqs_age_time_units) = 0;

    /// @brief Get the VOQ-in-SMS age time units.
    ///
    /// @param[out]     out_sms_voqs_age_time_units     VOQ-in-SMS age time units in nanoseconds to populate.
    ///
    /// @retval         LA_STATUS_SUCCESS               Time units were read successfully.
    /// @retval         LA_STATUS_ENOTINITIALIZED       Time units were not iniitialized.
    virtual la_status get_cgm_sms_voqs_age_time_granularity(
        la_cgm_sms_voqs_age_time_units_t& out_sms_voqs_age_time_units) const = 0;

    /// @brief Set the drop quantization thresholds for the size in bytes that packets consume in RXPDR.
    ///
    /// Set the quantization thresholds that translates the instantaneous size in bytes that all packets consume in
    /// the RXPDR to regions. Internally, the granularity of the size is in buffers.
    ///
    /// @param[in]  thresholds          Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_rx_pdr_sms_bytes_drop_thresholds(const la_rx_pdr_sms_bytes_drop_thresholds& thresholds) = 0;

    /// @brief Get the drop quantization thresholds for the size in bytes that all packets consume in RXPDR.
    ///
    /// @param[out]  out_thresholds          Bytes drop quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_rx_pdr_sms_bytes_drop_thresholds(la_rx_pdr_sms_bytes_drop_thresholds& out_thresholds) = 0;

    /// @brief Set the quantization thresholds for the size in bytes that all SQs consume in the SMS.
    ///
    /// Set the quantization thresholds that translates the instantaneous size in bytes that all SQs consume in
    /// the SMS to regions. Internally, the granularity of the SQ size is in buffers.
    ///
    /// @param[in]  thresholds          Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_rx_cgm_sms_bytes_quantization(const la_rx_cgm_sms_bytes_quantization_thresholds& thresholds) = 0;

    /// @brief Get the quantization thresholds for the size in bytes that all SQs consume in the SMS.
    ///
    /// @param[out]  out_thresholds          Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_rx_cgm_sms_bytes_quantization(la_rx_cgm_sms_bytes_quantization_thresholds& out_thresholds) = 0;

    /// @brief Set the quantization thresholds for the size in bytes of the given SQ Group.
    ///
    /// Set the quantization thresholds that translates the instantaneous size in bytes that the given SQ Group
    /// consumes to regions. Internally, the granularity of the SQG size is in buffers.
    ///
    /// @param[in]  group_index         Group to set thresholds for.
    /// @param[in]  thresholds          Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_rx_cgm_sqg_thresholds(la_uint_t group_index, const la_rx_cgm_sqg_thresholds& thresholds) = 0;

    /// @brief Get the quantization thresholds for the size in bytes of the given SQ group.
    ///
    /// @param[in]   group_index             Group to get thresholds for.
    /// @param[out]  out_thresholds          Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_rx_cgm_sqg_thresholds(la_uint_t group_index, la_rx_cgm_sqg_thresholds& out_thresholds) = 0;

    /// @brief   Create an RXCGM Source Queue congestion management profile.
    ///
    /// @param[out] out_rx_cgm_sq_profile         Pointer to #silicon_one::la_rx_cgm_sq_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Profile created successfully.
    /// @retval     LA_STATUS_ERESOURCE No more profiles to allocate.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_rx_cgm_sq_profile(la_rx_cgm_sq_profile*& out_rx_cgm_sq_profile) = 0;

    /// @brief   Get the default RXCGM Source Queue congestion management profile.
    ///
    /// In RXCGM, all source queues must map to a profile  there is no option for no profile. Thus, SDK
    /// will create and handle the default profile that all source queues initially map to. This API retrieves
    /// that profile so it can be modified.
    ///
    /// @param[out] out_default_rx_cgm_sq_profile         Pointer to #silicon_one::la_rx_cgm_sq_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Profile retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_default_rx_cgm_sq_profile(la_rx_cgm_sq_profile*& out_default_rx_cgm_sq_profile) = 0;

    /// @brief   Set the headroom management mode for use with RXCGM flow control.
    ///
    /// The HR management mode may be timer mode, or threshold mode.
    ///
    /// @param[in] mode         Management mode to use.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_headroom_mode(la_rx_cgm_headroom_mode_e mode) = 0;

    /// @brief   Get the headroom management mode for use with RXCGM flow control.
    ///
    /// @param[out] out_mode         Management mode in use.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_headroom_mode(la_rx_cgm_headroom_mode_e& out_mode) = 0;

    /// @brief   Read the given RXCGM drop counter.
    ///
    /// @param[in]    slice                       Slice to read from. Network slices only.
    /// @param[in]    counter_index     Counter index to read from.
    /// @param[out]   out_packets          Value of this drop counter, in packets.
    ///
    /// @retval     LA_STATUS_SUCCESS   Counter read successfully.
    /// @retval     LA_STATUS_EINVAL      Invalid parameter supplied.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_rx_cgm_drop_counter(la_slice_id_t slice, la_uint_t counter_index, la_uint_t& out_packets) = 0;

    /// @brief Set the drop and flow control thresholds on the OQ profile for a given port speed, on a given slice.
    ///
    /// Configures the base OQ profile thresholds for all OQs on a slice belonging to the given port speed.
    ///
    /// @param[in]  slice       Slice to configure on.
    /// @param[in]  port_speed  Port speed to configure OQ profiles for.
    /// @param[in]  thresholds  Drop and Flow Control thresholds to configure OQ profiles to.
    ///
    /// @retval     LA_STATUS_SUCCESS   Thresholds configured successfully.
    /// @retval     LA_STATUS_EINVAL    Thresholds or slice invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status set_tx_cgm_port_oq_profile_thresholds(la_slice_id_t slice,
                                                            la_mac_port::port_speed_e port_speed,
                                                            const la_tx_cgm_oq_profile_thresholds& thresholds)
        = 0;

    /// @brief Get the drop and flow control thresholds on the OQ profile for a given port speed, on a given slice.
    ///
    /// @param[in]  slice           Slice to get configuration for.
    /// @param[in]  port_speed      Port speed to get configuration for.
    /// @param[out] out_thresholds  Drop and Flow Control thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Thresholds configured successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status get_tx_cgm_port_oq_profile_thresholds(la_slice_id_t slice,
                                                            la_mac_port::port_speed_e port_speed,
                                                            la_tx_cgm_oq_profile_thresholds& out_thresholds)
        = 0;
    /// @brief Set the drop and flow control thresholds on the PFC OQ profile for a given port speed, on a given slice.
    ///
    /// Configures the PFC OQ profile thresholds for all OQs on a slice belonging to the given port speed.
    /// If PFC is enabled for a given OQ, these thresholds are used rather than the base thresholds.
    ///
    /// @param[in]  slice       Slice to configure on.
    /// @param[in]  port_speed  Port speed to configure OQ profiles for.
    /// @param[in]  thresholds  Drop and Flow Control thresholds to configure OQ profiles to.
    ///
    /// @retval     LA_STATUS_SUCCESS   Thresholds configured successfully.
    /// @retval     LA_STATUS_EINVAL    Thresholds or slice invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status set_tx_cgm_pfc_port_oq_profile_thresholds(la_slice_id_t slice,
                                                                la_mac_port::port_speed_e port_speed,
                                                                const la_tx_cgm_oq_profile_thresholds& thresholds)
        = 0;

    /// @brief Get the drop and flow control thresholds on the PFC OQ profile for a given port speed, on a given slice.
    ///
    /// @param[in]  slice           Slice to get configuration for.
    /// @param[in]  port_speed      Port speed to get configuration for.
    /// @param[out] out_thresholds  Drop and Flow Control thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Thresholds configured successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status get_tx_cgm_pfc_port_oq_profile_thresholds(la_slice_id_t slice,
                                                                la_mac_port::port_speed_e port_speed,
                                                                la_tx_cgm_oq_profile_thresholds& out_thresholds)
        = 0;

    /// @brief Apply additional tuning for PFC, based on whether device is to be used for long or short links
    ///
    /// @param[in]  use_long_links      Whether PFC is being used for long or short links.
    ///
    /// @retval     LA_STATUS_SUCCESS   Tuning applied successfully
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status set_pfc_additional_link_tuning(bool use_long_links) = 0;

    /// @}
    /// @name VRF management
    /// @{

    /// @brief Enable/Disable trapping for specific IPv6 extension header.
    ///
    /// By default, trap is disabled for all IPv6 extension header.
    /// This is a global setting.
    ///
    /// @param[in]  ext_hdr_id  IPv6 extension header ID.
    /// @param[in]  enabled     true if trap should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ipv6_ext_header_trap_enabled(la_ipv6_extension_header_t ext_hdr_id, bool enabled) = 0;

    /// @brief Create a new VRF object, with specific attributes.
    ///
    /// @param[in]  vrf_gid             Global ID of VRF.
    /// @param[out] out_vrf             Pointer to #silicon_one::la_vrf to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_vrf contains the VRF object.
    /// @retval     LA_STATUS_EBUSY     VRF global ID in use.
    /// @retval     LA_STATUS_EINVAL    VRF global ID is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_vrf(la_vrf_gid_t vrf_gid, la_vrf*& out_vrf) = 0;

    /// @brief Get a VRF object using its global ID.
    ///
    /// @param[in]  vrf_gid             Global ID of the VRF to be fetched.
    /// @param[out] out_vrf             Pointer to #silicon_one::la_vrf to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_vrf contains the VRF object.
    /// @retval     LA_STATUS_ENOTFOUND VRF global ID does not map to any #silicon_one::la_vrf object.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_vrf_by_id(la_vrf_gid_t vrf_gid, la_vrf*& out_vrf) const = 0;

    /// @brief Get a Next Hop object using its global ID.
    ///
    /// @param[in]  next_hop_gid        Global ID of the VRF to be fetched.
    /// @param[out] out_next_hop        Pointer to #silicon_one::la_next_hop to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_next_hop contains the NEXT HOP object.
    /// @retval     LA_STATUS_ENOTFOUND NEXT HOP global ID does not map to any #silicon_one::la_next_hop object.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_next_hop_by_id(la_next_hop_gid_t next_hop_gid, la_next_hop*& out_next_hop) const = 0;

    /// @brief Create new #silicon_one::la_next_hop, which can be used as a routing destination
    ///
    /// @param[in]  nh_gid              Global ID of next hop to be created.
    /// @param[in]  nh_mac_addr         Next hop MAC.
    /// @param[in]  port                L3 port to use.
    /// @param[in]  nh_type             Type of the Next hop.
    /// @param[out] out_next_hop        Pointer to #silicon_one::la_next_hop to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. Result placed in out_next_hop.
    /// @retval     LA_STATUS_EINVAL    Port is corrupt/invalid; next hop type is NORMAL and L3 port is nullptr.
    /// @retval     LA_STATUS_ERESOURCE Maximal number of Next hop objects created.
    /// @retval     LA_STATUS_EBUSY     Next hop ID is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_next_hop(la_next_hop_gid_t nh_gid,
                                      la_mac_addr_t nh_mac_addr,
                                      la_l3_port* port,
                                      la_next_hop::nh_type_e nh_type,
                                      la_next_hop*& out_next_hop)
        = 0;

    /// @brief Create new #silicon_one::la_vxlan_next_hop, which can be used as a routing destination
    ///
    /// @param[in]  nh_mac_addr         Next hop MAC.
    /// @param[in]  port                L3 port to use.
    /// @param[in]  vxlan_port          Vxlan port to use.
    /// @param[out] out_vxlan_next_hop  Pointer to #silicon_one::la_vxlan_next_hop to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port created successfully. Result placed in out_vxlan_next_hop.
    /// @retval     LA_STATUS_EINVAL    Port is corrupt/invalid.
    /// @retval     LA_STATUS_ERESOURCE Maximal number of Next hop objects created.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_vxlan_next_hop(la_mac_addr_t nh_mac_addr,
                                            la_l3_port* port,
                                            la_l2_service_port* vxlan_port,
                                            la_vxlan_next_hop*& out_vxlan_next_hop)
        = 0;

    /// @brief Create an L3 FEC.
    ///
    /// @param[in]  destination         L3 destination FEC points to
    /// @param[out] out_fec             Pointer to #silicon_one::la_l3_fec to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   FEC created successfully. out_fec contains the created group.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_l3_fec(la_l3_destination* destination, la_l3_fec*& out_fec) = 0;

    /// @brief Create an AC-type L3 port.
    ///
    /// Port is created over an Ethernet port.
    /// Incoming packets through the ethernet port first go through a key selection stage, as defined by
    /// #silicon_one::la_ac_profile::set_key_selector_per_format.
    /// Packets whose key matches the (VID1, VID2) are handled by the created L3 AC port.
    ///
    /// @param[in]  port_gid                    Global L3 port ID.
    /// @param[in]  ethernet_port               Ethernet port to create AC port over.
    /// @param[in]  vid1                        VLAN ID 1.
    /// @param[in]  vid2                        VLAN ID 2.
    /// @param[in]  mac_addr                    MAC to associate with the port.
    /// @param[in]  vrf                         VRF attached to the port.
    /// @param[in]  ingress_qos_profile         Ingress QoS profile to use.
    /// @param[in]  egress_qos_profile          Egress QoS profile to use.
    /// @param[out] out_l3_ac_port              Pointer to #silicon_one::la_l3_ac_port to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS           Port created successfully. Result placed in out_port.
    /// @retval     LA_STATUS_EBUSY             Global ID is already used by another port, or VLAN association already used for
    /// the
    /// given
    /// Ethernet port.
    /// @retval     LA_STATUS_EINVAL            Global ID is out of range or corrupt/nullptr arguments.
    /// @retval     LA_STATUS_ERESOURCE         Maximal number of L3 ports created.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status create_l3_ac_port(la_l3_port_gid_t port_gid,
                                        const la_ethernet_port* ethernet_port,
                                        la_vlan_id_t vid1,
                                        la_vlan_id_t vid2,
                                        la_mac_addr_t mac_addr,
                                        la_vrf* vrf,
                                        la_ingress_qos_profile* ingress_qos_profile,
                                        la_egress_qos_profile* egress_qos_profile,
                                        la_l3_ac_port*& out_l3_ac_port)
        = 0;

    /// @}
    /// @name SVI port
    /// @{

    /// Create SVI port. Port is connected to a #silicon_one::la_switch and #silicon_one::la_vrf.
    ///
    /// @param[in]  gid                         L3 port global ID.
    /// @param[in]  sw                          Switch SVI is connected to.
    /// @param[in]  vrf                         VRF SVI is connected to.
    /// @param[in]  mac_addr                    MAC to associate with the port.
    /// @param[in]  ingress_qos_profile         Ingress QoS profile to use.
    /// @param[in]  egress_qos_profile          Egress QoS profile to use.
    /// @param[out] out_svi_port                Pointer to #silicon_one::la_svi_port to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS           Port created successfully. Result placed in out_port.
    /// @retval     LA_STATUS_EINVAL            Global ID is out of range or corrupt/nullptr arguments.
    /// @retval     LA_STATUS_ERESOURCE         Maximal number of ports created.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status create_svi_port(la_l3_port_gid_t gid,
                                      const la_switch* sw,
                                      const la_vrf* vrf,
                                      la_mac_addr_t mac_addr,
                                      la_ingress_qos_profile* ingress_qos_profile,
                                      la_egress_qos_profile* egress_qos_profile,
                                      la_svi_port*& out_svi_port)
        = 0;

    /// @brief Create an L3 Tunnel port.
    ///
    /// Port is created as a logical port and can be used as an Tunnel Endpoint for IPinIP Tunnel termination.
    ///
    /// @param[in]  port_gid                    Global L3 port ID.
    /// @param[in]  underlay_vrf                Underlay VRF for the tunnel.
    /// @param[in]  prefix                      Local IPv4 prefix.
    /// @param[in]  ip_addr                     Remote IPv4 address.
    /// @param[in]  vrf                         VRF attached to the port.
    /// @param[in]  ingress_qos_profile         Ingress QoS profile.
    /// @param[in]  egress_qos_profile          Egress QoS profile.
    /// @param[out] out_ip_over_ip_tunnel_port  Pointer to #silicon_one::la_ip_over_ip_tunnel_port to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS           Port created successfully. Result placed in out_port.
    /// @retval     LA_STATUS_EBUSY             Global ID is already used by another port
    /// @retval     LA_STATUS_EINVAL            Global ID is out of range or corrupt/nullptr arguments.
    /// @retval     LA_STATUS_ERESOURCE         Maximal number of L3 ports created.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status create_ip_over_ip_tunnel_port(la_l3_port_gid_t port_gid,
                                                    la_vrf* underlay_vrf,
                                                    la_ipv4_prefix_t prefix,
                                                    la_ipv4_addr_t ip_addr,
                                                    la_vrf* vrf,
                                                    la_ingress_qos_profile* ingress_qos_profile,
                                                    la_egress_qos_profile* egress_qos_profile,
                                                    la_ip_over_ip_tunnel_port*& out_ip_over_ip_tunnel_port)
        = 0;

    /// @brief Create an IP over IP Tunnel port.
    ///
    /// Port is created as a logical port and can be used as an Tunnel Endpoint for IPinIP Tunnel termination.
    ///
    /// @param[in]  port_gid                    Global L3 port ID.
    /// @param[in]  tunnel_mode                 Tunnel mode: only decap supported
    /// @param[in]  underlay_vrf                Underlay VRF for the tunnel.
    /// @param[in]  prefix                      Local IPv4 prefix.
    /// @param[in]  ip_addr                     Remote IPv4 address.
    /// @param[in]  vrf                         VRF attached to the port.
    /// @param[in]  ingress_qos_profile         Ingress QoS profile.
    /// @param[in]  egress_qos_profile          Egress QoS profile.
    /// @param[out] out_ip_over_ip_tunnel_port  Pointer to #silicon_one::la_ip_over_ip_tunnel_port to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS           Port created successfully. Result placed in out_port.
    /// @retval     LA_STATUS_EBUSY             Global ID is already used by another port
    /// @retval     LA_STATUS_EINVAL            Global ID is out of range or corrupt/nullptr arguments.
    /// @retval     LA_STATUS_ERESOURCE         Maximal number of L3 ports created.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   If tunnel mode is not decap-only.
    virtual la_status create_ip_over_ip_tunnel_port(la_l3_port_gid_t port_gid,
                                                    la_ip_tunnel_mode_e tunnel_mode,
                                                    la_vrf* underlay_vrf,
                                                    la_ipv4_prefix_t prefix,
                                                    la_ipv4_addr_t ip_addr,
                                                    la_vrf* vrf,
                                                    la_ingress_qos_profile* ingress_qos_profile,
                                                    la_egress_qos_profile* egress_qos_profile,
                                                    la_ip_over_ip_tunnel_port*& out_ip_over_ip_tunnel_port)
        = 0;

    /// @brief Create an GUE port.
    ///
    /// Port is created as a logical port and can be used as an Tunnel Endpoint for GUE Tunnel termination.
    ///
    /// @param[in]  port_gid                    Global L3 port ID.
    /// @param[in]  tunnel_mode                 Tunnel mode: only decap supported
    /// @param[in]  underlay_vrf                Underlay VRF for the tunnel.
    /// @param[in]  local_prefix                Local IPv4 prefix.
    /// @param[in]  remote_ip_addr              Remote IPv4 address.
    /// @param[in]  overlay_vrf                 Overlay VRF attached to the port.
    /// @param[in]  ingress_qos_profile         Ingress QoS profile.
    /// @param[in]  egress_qos_profile          Egress QoS profile.
    /// @param[out] out_gue_port                Pointer to #silicon_one::la_gue_port to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS           Port created successfully. Result placed in out_port.
    /// @retval     LA_STATUS_EBUSY             Global ID is already used by another port
    /// @retval     LA_STATUS_EINVAL            Global ID is out of range or corrupt/nullptr arguments.
    /// @retval     LA_STATUS_ERESOURCE         Maximal number of L3 ports created.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   If tunnel mode is not decap-only.
    virtual la_status create_gue_port(la_l3_port_gid_t port_gid,
                                      la_ip_tunnel_mode_e tunnel_mode,
                                      la_vrf* underlay_vrf,
                                      la_ipv4_prefix_t local_prefix,
                                      la_ipv4_addr_t remote_ip_addr,
                                      la_vrf* overlay_vrf,
                                      la_ingress_qos_profile* ingress_qos_profile,
                                      la_egress_qos_profile* egress_qos_profile,
                                      la_gue_port*& out_gue_port)
        = 0;

    /// @}
    /// @name GRE port
    /// @{

    ///
    /// @brief Create a GRE port.
    ///
    /// @param[in]  port_gid                    Global L3 port ID.
    /// @param[in]  underlay_vrf                Underlay VRF for the tunnel
    /// @param[in]  local_ip_addr               local IP of the tunnel
    /// @param[in]  remote_ip_addr              remote IP of the tunnel
    /// @param[in]  overlay_vrf                 Overlay VRF attached to the port.
    /// @param[in]  ingress_qos_profile         Ingress QoS profile to use.
    /// @param[in]  egress_qos_profile          Egress QoS profile to use.
    /// @param[out] out_gre_port                Pointer to #silicon_one::la_gre_port to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS           Port created successfully. Result placed in out_port.
    /// @retval     LA_STATUS_EINVAL            Global ID is out of range or corrupt/nullptr arguments.
    /// @retval     LA_STATUS_ERESOURCE         Maximal number of L3 ports created.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status create_gre_port(la_l3_port_gid_t port_gid,
                                      const la_vrf* underlay_vrf,
                                      la_ipv4_addr_t local_ip_addr,
                                      la_ipv4_addr_t remote_ip_addr,
                                      const la_vrf* overlay_vrf,
                                      la_ingress_qos_profile* ingress_qos_profile,
                                      la_egress_qos_profile* egress_qos_profile,
                                      la_gre_port*& out_gre_port)
        = 0;

    /// @}
    /// @name GRE port
    /// @{

    ///
    /// @brief Create a GRE port.
    ///
    /// @param[in]  port_gid                    Global L3 port ID.
    /// @param[in]  tunnel_mode                 Tunnel mode: encap, decap, encap-decap
    /// @param[in]  underlay_vrf                Underlay VRF for the tunnel
    /// @param[in]  local_ip_addr               local IP of the tunnel
    /// @param[in]  remote_ip_addr              remote IP of the tunnel
    /// @param[in]  overlay_vrf                 Overlay VRF attached to the port.
    /// @param[in]  ingress_qos_profile         Ingress QoS profile to use.
    /// @param[in]  egress_qos_profile          Egress QoS profile to use.
    /// @param[out] out_gre_port                Pointer to #silicon_one::la_gre_port to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS           Port created successfully. Result placed in out_port.
    /// @retval     LA_STATUS_EINVAL            Global ID is out of range or corrupt/nullptr arguments.
    /// @retval     LA_STATUS_ERESOURCE         Maximal number of L3 ports created.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status create_gre_port(la_l3_port_gid_t port_gid,
                                      la_ip_tunnel_mode_e tunnel_mode,
                                      const la_vrf* underlay_vrf,
                                      la_ipv4_addr_t local_ip_addr,
                                      la_ipv4_addr_t remote_ip_addr,
                                      const la_vrf* overlay_vrf,
                                      la_ingress_qos_profile* ingress_qos_profile,
                                      la_egress_qos_profile* egress_qos_profile,
                                      la_gre_port*& out_gre_port)
        = 0;

    /// @brief Get GRE port using its global ID.
    ///
    /// @param[in]     port_id         GRE port  global ID.
    /// @param[out]    out_gre_port    Pointer to #silicon_one::la_gre_port to populate.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_ENOTFOUND  The global ID does not map to any prefix object.
    /// @retval    LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status get_gre_port_by_gid(la_l3_port_gid_t port_id, la_gre_port*& out_gre_port) const = 0;
    /// @}
    /// @name ACL
    /// @{

    /// @brief Enable/Disable scaled ACL.
    ///
    /// Default setting is disabled.
    /// This is a global setting.
    ///
    /// @param[in]  enabled             true if scaled ACL should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_acl_scaled_enabled(bool enabled) = 0;

    /// @brief Return scaled ACL status.
    ///
    /// @param[out] out_enabled         true if scaled ACL is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_acl_scaled_enabled(bool& out_enabled) = 0;

    /// @brief Create ACL key profile.
    ///
    /// @param[in]  key_type            Key type to be used in this ACL.
    /// @param[in]  dir                 ACL direction (INGRESS or EGRESS).
    /// @param[in]  key_def             Key definition.
    /// @param[in]  tcam_pool_id        TCAM pool ID.
    /// @param[out] out_acl_key_profile Reference to #silicon_one::la_acl_key_profile* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid key provided.
    /// @retval     LA_STATUS_ERESOURCE Maximum number of ACL key profile instances already used.
    /// @retval     LA_STATUS_EUNKNOWN  Internal error.
    virtual la_status create_acl_key_profile(la_acl_key_type_e key_type,
                                             la_acl_direction_e dir,
                                             const la_acl_key_def_vec_t& key_def,
                                             la_acl_tcam_pool_id_t tcam_pool_id,
                                             la_acl_key_profile*& out_acl_key_profile)
        = 0;

    /// @brief Create ACL command profile.
    ///
    /// @param[in]  command_def             Command definition.
    /// @param[out] out_acl_command_profile Reference to #silicon_one::la_acl_command_profile* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Unsupported set of actions within the command.
    /// @retval     LA_STATUS_ERESOURCE Maximum number of ACL command profiles instances already used.
    /// @retval     LA_STATUS_EUNKNOWN  Internal error.
    virtual la_status create_acl_command_profile(const la_acl_command_def_vec_t& command_def,
                                                 la_acl_command_profile*& out_acl_command_profile)
        = 0;

    /// @brief Create an Access Control List.
    ///
    /// @param[in]  acl_key_profile           ACL key profile.
    /// @param[in]  acl_command_profile       ACL command profile.
    /// @param[out] out_acl                   Pointer to a #silicon_one::la_acl to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS         ACL created successfully.
    /// @retval     LA_STATUS_ERESOURCE       Maximum number of ACL objects reached.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS ACL profile passed is on a different device.
    virtual la_status create_acl(const la_acl_key_profile* acl_key_profile,
                                 const la_acl_command_profile* acl_command_profile,
                                 la_acl*& out_acl)
        = 0;

    /// @brief Create an Access Control List.
    ///
    /// @param[in]  acl_key_profile           ACL key profile.
    /// @param[in]  acl_command_profile       ACL command profile.
    /// @param[in]  src_pcl                   Source PCL
    /// @param[in]  dst_pcl                   Destination PCL
    /// @param[out] out_acl                   Pointer to a #silicon_one::la_acl to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS         ACL created successfully.
    /// @retval     LA_STATUS_ERESOURCE       Maximum number of ACL objects reached.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS ACL profile passed is on a different device.
    virtual la_status create_acl(const la_acl_key_profile* acl_key_profile,
                                 const la_acl_command_profile* acl_command_profile,
                                 la_pcl* src_pcl,
                                 la_pcl* dst_pcl,
                                 la_acl*& out_acl)
        = 0;

    /// @brief Create an Access Control List Group.
    ///
    /// @param[out] out_acl_group             Pointer to a #silicon_one::la_acl_group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS         ACL group created successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS ACL profile passed is on a different device.
    virtual la_status create_acl_group(la_acl_group*& out_acl_group) = 0;

    /// @brief Set ACL range for specific range type in a specific range index.
    ///
    /// @param[in]  stage               ACL range stage.
    /// @param[in]  range               ACL range type to configure.
    /// @param[in]  idx                 ACL range index to configure.
    /// @param[in]  rstart              Range start value.
    /// @param[in]  rend                Range end value.
    ///
    /// @retval     LA_STATUS_SUCCESS   Range set successfully.
    /// @retval     LA_STATUS_EINVAL    Either vlan_range_idx, vid_start or vid_end are invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_acl_range(la_acl::stage_e stage,
                                    la_acl::range_type_e range,
                                    la_uint_t idx,
                                    la_uint16_t rstart,
                                    la_uint16_t rend)
        = 0;

    /// @brief Reserve ACL resource on every slice
    ///
    /// @param[in]  acl                 acl to reserve
    ///
    /// @retval     LA_STATUS_SUCCESS   ACL reserved successfully.
    /// @retval     LA_STATUS_ERESOURCE Maximum number of ACL objects reached.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status reserve_acl(la_acl* acl) = 0;

    /// @brief Create a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV4 prefix compression entries
    /// @param[in]  feature                   ACL / LPTS feature type the PCL is attached to.
    /// @param[out] out_pcl                   Pointer to a #silicon_one::la_pcl to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL created successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status create_pcl(const la_pcl_v4_vec_t& prefixes, const pcl_feature_type_e& feature, silicon_one::la_pcl*& out_pcl)
        = 0;

    /// @brief Create a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV6 prefix compression entries
    /// @param[in]  feature                   ACL / LPTS feature type the PCL is attached to.
    /// @param[out] out_pcl                   Pointer to a #silicon_one::la_pcl to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL created successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status create_pcl(const la_pcl_v6_vec_t& prefixes, const pcl_feature_type_e& feature, silicon_one::la_pcl*& out_pcl)
        = 0;

    /// @brief Create an LPTS instance.
    ///
    /// @param[in]  type                LPTS instance type.
    /// @param[out] out_lpts            Pointer to a #silicon_one::la_lpts to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   LPTS instance created successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_lpts(lpts_type_e type, la_lpts*& out_lpts) = 0;

    /// @brief Create a Object Group LPTS application.
    ///
    /// @param[in]  properties                Application properties
    /// @param[in]  src_pcl                   source prefix compression list
    /// @param[out] out_lpts_app              Pointer to a #silicon_one::la_lpts_app_properties to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS         OG LPTS App created successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status create_og_lpts_app(const la_lpts_app_properties& properties,
                                         la_pcl* src_pcl,
                                         la_og_lpts_application*& out_lpts_app)
        = 0;

    /// @}
    /// @name ECMP
    /// @{

    /// @brief Create an ECMP group.
    ///
    /// @param[in]  level               ECMP level.
    /// @param[out] out_ecmp_group      Pointer to #silicon_one::la_ecmp_group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   ECMP group created successfully. out_ecmp_group contains the created group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_ecmp_group(la_ecmp_group::level_e level, la_ecmp_group*& out_ecmp_group) = 0;

    /// @}
    /// @name L2 Protection
    /// @{

    /// @brief Create a protection monitor.
    ///
    /// A monitor is created by default in the untriggered mode.
    ///
    /// @param[out] out_protection_monitor  Pointer to #silicon_one::la_protection_monitor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully. out_protection_monitor contains the created group.
    /// @retval     LA_STATUS_ERESOURCE     Maximum number of monitors is already used.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status create_protection_monitor(la_protection_monitor*& out_protection_monitor) = 0;

    /// @brief Create a multicast protection monitor.
    ///
    /// A monitor is created by default in the primary, backup disabled mode.
    ///
    /// @param[out] out_protection_monitor  Pointer to #silicon_one::la_multicast_protection_monitor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully. out_protection_monitor contains the created group.
    /// @retval     LA_STATUS_ERESOURCE     Maximum number of monitors is already used.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status create_multicast_protection_monitor(la_multicast_protection_monitor*& out_protection_monitor) = 0;

    /// @brief Create a Layer 2 protection group.
    ///
    /// For 1:1 protection:
    ///     When the monitor is untriggered, traffic is directed at the primary destination.
    ///     When the monitor is triggered, traffic is diverted at the protecting destination.
    ///
    /// @param[in]  group_gid               Global ID of L2 protection group.
    /// @param[in]  primary_destination     Primary destination.
    /// @param[in]  protecting_destination  Protecting destination.
    /// @param[in]  protection_monitor      Protection monitor.
    /// @param[out] out_l2_protection_group Pointer to #silicon_one::la_l2_protection_group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully
    /// @retval     LA_STATUS_EINVAL        Destinations or monitor are corrupt/invalid;
    /// @retval     LA_STATUS_EBUSY         Global ID is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status create_l2_protection_group(la_l2_port_gid_t group_gid,
                                                 la_l2_destination* primary_destination,
                                                 la_l2_destination* protecting_destination,
                                                 la_protection_monitor* protection_monitor,
                                                 la_l2_protection_group*& out_l2_protection_group)
        = 0;

    /// @brief Get an L2 protection group object using its global ID.
    ///
    /// @param[in]  group_gid                   Global ID of the L2 protection group to be fetched.
    /// @param[out] out_l2_protection_group     Pointer to #silicon_one::la_l2_protection_group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_l2_protection_group contains the L2 protection
    /// group
    /// object.
    /// @retval     LA_STATUS_ENOTFOUND L2 protection group global ID does not map to any #silicon_one::la_l2_protection_group
    /// object.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_l2_protection_group_by_id(la_l2_port_gid_t group_gid,
                                                    la_l2_protection_group*& out_l2_protection_group) const = 0;

    /// @brief Create a Layer 3 protection group.
    ///
    /// For 1:1 protection:
    ///     When the monitor is untriggered, traffic is directed at the primary destination.
    ///     When the monitor is triggered, traffic is diverted at the protecting destination.
    ///
    /// @param[in]  group_gid               Global ID of L3 protection group.
    /// @param[in]  primary_destination     Primary destination.
    /// @param[in]  protecting_destination  Protecting destination.
    /// @param[in]  protection_monitor      Protection monitor.
    /// @param[out] out_l3_protection_group Pointer to #silicon_one::la_l3_protection_group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully
    /// @retval     LA_STATUS_EINVAL        Destinations or monitor are corrupt/invalid;
    /// @retval     LA_STATUS_EBUSY         Global ID is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status create_l3_protection_group(la_l3_protection_group_gid_t group_gid,
                                                 la_l3_destination* primary_destination,
                                                 la_l3_destination* protecting_destination,
                                                 la_protection_monitor* protection_monitor,
                                                 la_l3_protection_group*& out_l3_protection_group)
        = 0;

    /// @brief Create a multicast protection group.
    ///
    /// A multicast protection group provides egress protection of destinations, for use with MPLS multicast.
    ///
    /// @param[in]  primary_destination     Primary destination.
    /// @param[in]  primary_system_port     System port to use with primary destination.
    /// @param[in]  protecting_destination  Protecting destination.
    /// @param[in]  protecting_system_port  System port to use with protecting destination.
    /// @param[in]  protection_monitor      Protection monitor.
    /// @param[out] out_multicast_protection_group Pointer to #silicon_one::la_multicast_protection_group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully
    /// @retval     LA_STATUS_EINVAL        Destinations, system ports or monitor are corrupt/invalid;
    /// @retval     LA_STATUS_EBUSY         Global ID is in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status create_multicast_protection_group(la_next_hop* primary_destination,
                                                        la_system_port* primary_system_port,
                                                        la_next_hop* protecting_destination,
                                                        la_system_port* protecting_system_port,
                                                        la_multicast_protection_monitor* protection_monitor,
                                                        la_multicast_protection_group*& out_multicast_protection_group)
        = 0;

    /// @brief Get an L3 protection group object using its global ID.
    ///
    /// @param[in]  group_gid                   Global ID of the L3 protection group to be fetched.
    /// @param[out] out_l3_protection_group     Pointer to #silicon_one::la_l3_protection_group to populate.
    ///
    /// @retval    LA_STATUS_SUCCESS Operation completed successfully. out_l3_protection_group has the L3 protection group object.
    /// @retval    LA_STATUS_ENOTFOUND L3 protection group global ID does not map to any #silicon_one::la_l3_protection_group
    /// object.
    /// @retval    LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_l3_protection_group_by_id(la_l3_protection_group_gid_t group_gid,
                                                    la_l3_protection_group*& out_l3_protection_group) const = 0;

    /// @}
    /// @name Meters and Counters
    /// @{

    /// @brief Create a counter.
    ///
    /// @param[in]   set_size             Counter-set size.
    /// @param[out]  out_counter          Reference #silicon_one::la_counter_set* to populate.
    ///
    /// @retval    LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval    LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status create_counter(size_t set_size, la_counter_set*& out_counter) = 0;

    /// @brief Create a meter.
    ///
    /// @param[in]  set_type            Meter-set type.
    /// @param[in]  set_size            Meter-set size.
    /// @param[out] out_meter           Reference to #silicon_one::la_meter_set* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ERESOURCE Maximum number of meter-sets created.
    /// @retval     LA_STATUS_EUNKNOWN  Internal error.
    virtual la_status create_meter(la_meter_set::type_e set_type, size_t set_size, la_meter_set*& out_meter) = 0;

    /// @brief Create a rate limiter.
    ///
    /// @param[in]  system_port          System port associated with this rate limiter
    /// @param[out] out_rate_limiter_set Reference to #silicon_one::la_rate_limiter_set* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  Internal error.
    virtual la_status create_rate_limiter(la_system_port* system_port, la_rate_limiter_set*& out_rate_limiter_set) = 0;

    /// @brief Create a meter profile.
    ///
    /// @param[in]  profile_type            Meter profile type.
    /// @param[in]  meter_measure_mode      Meter measure mode.
    /// @param[in]  meter_rate_mode         Meter rate mode.
    /// @param[in]  color_awareness_mode    Packet color awareness mode.
    /// @param[out] out_meter_profile       Reference to #silicon_one::la_meter_profile* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ERESOURCE Maximum number of meter profiles created.
    /// @retval     LA_STATUS_EUNKNOWN  Internal error.
    virtual la_status create_meter_profile(la_meter_profile::type_e profile_type,
                                           la_meter_profile::meter_measure_mode_e meter_measure_mode,
                                           la_meter_profile::meter_rate_mode_e meter_rate_mode,
                                           la_meter_profile::color_awareness_mode_e color_awareness_mode,
                                           la_meter_profile*& out_meter_profile)
        = 0;

    /// @brief Create a meter action profile.
    ///
    /// @param[out] out_meter_action_profile    Reference to #silicon_one::la_meter_profile* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ERESOURCE         Maximum number of meter profiles created.
    /// @retval     LA_STATUS_EUNKNOWN          Internal error.
    virtual la_status create_meter_action_profile(la_meter_action_profile*& out_meter_action_profile) = 0;

    /// @}
    /// @name QoS
    /// @{

    /// @brief Create an ingress Quality of Service profile.
    ///
    /// @param[out] out_ingress_qos_profile     Pointer to a #silicon_one::la_ingress_qos_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully. out_ingress_qos_profile contains the ingress
    ///                                         QoS profile.
    /// @retval     LA_STATUS_ERESOURCE         Maximum number of ingress QoS profiles is already used.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status create_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) = 0;

    /// @brief Create an egress Quality of Service profile.
    ///
    /// @param[in]  marking_source          Whether profile is qos-group or tos-based.
    /// @param[out] out_egress_qos_profile  Pointer to a #silicon_one::la_egress_qos_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully. out_egress_qos_profile contains the egress QoS
    /// profile.
    /// @retval     LA_STATUS_ERESOURCE     Maximum number of egress QoS profiles is already used.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status create_egress_qos_profile(la_egress_qos_marking_source_e marking_source,
                                                la_egress_qos_profile*& out_egress_qos_profile)
        = 0;

    /// @brief Return object's chosen limitation.
    ///
    /// @param[in]  limit_type              Type of max limit to return.
    /// @param[out] out_limit               Max limit.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_limit(limit_type_e limit_type, la_uint64_t& out_limit) const = 0;

    /// @brief Return object's chosen floating-point precision.
    ///
    /// @param[in]  precision_type          Type of precision to return.
    /// @param[out] out_precision           Required precision
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_precision(la_precision_type_e precision_type, double& out_precision) const = 0;

    /// @brief Create file descriptors for reading critical and normal notifications.
    ///
    /// @note  See #silicon_one::la_notification_desc
    ///
    /// @param[in]  mask             Bitwise or'd selector of notification types. See #silicon_one::la_notification_type_e.
    /// @param[out] out_fd_critical  File descriptor for reading critical notifications.
    /// @param[out] out_fd_normal    File descriptor for reading normal notifications.
    ///
    /// @retval     LA_STATUS_SUCCESS   File descriptors have been created.
    /// @retval     LA_STATUS_EINVAL    Invalid parameters.
    /// @retval     LA_STATUS_ERESOURCE Cannot create file descriptors, reached system limit.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status open_notification_fds(int mask, int& out_fd_critical, int& out_fd_normal) = 0;

    /// @brief Close notification file descriptors.
    ///
    /// @retval     LA_STATUS_SUCCESS   File descriptors have been closed.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status close_notification_fds() = 0;

    /// @}

    /// @brief check if given device property is supported
    ///
    /// @param[in]  device_property            Property to verify.
    /// @param[out] supported                  Flag indicating if device_property is supported.
    ///
    /// @retval     LA_STATUS_SUCCESS          device property is found.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  device property is not supported.
    virtual la_status is_property_supported(la_device_property_e device_property, bool& supported) const = 0;

    /// @brief Set a device property of a boolean type.
    ///
    /// @param[in]  device_property     Property to set.
    /// @param[in]  property_value      Value to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Property set successfully.
    /// @retval     LA_STATUS_EINVAL    The property is not of boolean type.
    /// @retval     LA_STATUS_EBUSY     The property's value is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_bool_property(la_device_property_e device_property, bool property_value) = 0;

    /// @brief Get a device property of a boolean type.
    ///
    /// @param[in]  device_property     Property to retrieve.
    /// @param[out] out_property_value  Value to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Property retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    The property is not of boolean type.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_bool_property(la_device_property_e device_property, bool& out_property_value) const = 0;

    /// @brief Set a device property of an integer type.
    ///
    /// @param[in]  device_property     Property to set.
    /// @param[in]  property_value      Value to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Property set successfully.
    /// @retval     LA_STATUS_EINVAL    The property is not of integer type.
    /// @retval     LA_STATUS_EBUSY     The property's value is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_int_property(la_device_property_e device_property, int property_value) = 0;

    /// @brief Get a device property of an integer type.
    ///
    /// @param[in]  device_property     Property to retrieve.
    /// @param[out] out_property_value  Value to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Property retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    The property is not of integer type.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_int_property(la_device_property_e device_property, int& out_property_value) const = 0;

    /// @brief Set a device property of a string type.
    ///
    /// @param[in]  device_property     Property to set.
    /// @param[in]  property_value      Value to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Property set successfully.
    /// @retval     LA_STATUS_EINVAL    The property is not of string type.
    /// @retval     LA_STATUS_EBUSY     The property's value is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_string_property(la_device_property_e device_property, std::string property_value) = 0;

    /// @brief Get a device property of a string type.
    ///
    /// @param[in]  device_property     Property to retrieve.
    /// @param[out] out_property_value  Value to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Property retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    The property is not of string type.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_string_property(la_device_property_e device_property, std::string& out_property_value) const = 0;

    /// @brief Execute a diagnostics test.
    ///
    /// @retval     LA_STATUS_SUCCESS   Test completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  Test failed. Detailed failure information exists in the log.
    virtual la_status diagnostics_test(test_feature_e feature) = 0;

    /// @brief Get the granularity of a given resource.
    ///
    /// param[int]  resource_type               Resource type.
    /// param[out]  out_granularity             Resource granularity to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Resource usage data was retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_granularity(la_resource_descriptor::type_e resource_type,
                                      la_resource_granularity& out_granularity) const = 0;

    /// @brief Get resource usage information for all resources.
    ///
    /// param[out]  out_descriptors             Vector of the resources' usage descriptors.
    ///
    /// @retval     LA_STATUS_SUCCESS           Resource usage data was retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_resource_usage(la_resource_usage_descriptor_vec& out_descriptors) const = 0;

    /// @brief Get resource usage information for a given resource.
    ///
    /// param[in]   resource_type               Resource to retrieve.
    /// param[out]  out_descriptors             Vector of the resources' usage descriptors.
    ///
    /// @retval     LA_STATUS_SUCCESS           Resource usage data was retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_resource_usage(la_resource_descriptor::type_e resource_type,
                                         la_resource_usage_descriptor_vec& out_descriptors) const = 0;

    /// @brief Get resource usage information for a given resource on a given slice_pair/slice/ifg.
    ///
    /// param[in]   resource_descriptor         Resource to retrieve.
    /// param[out]  out_descriptor              Resource's usage descriptor.
    ///
    /// @retval     LA_STATUS_SUCCESS           Resource usage data was retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_resource_usage(const la_resource_descriptor& resource_descriptor,
                                         la_resource_usage_descriptor& out_descriptor) const = 0;

    /// @brief Set thresholds for resource utilization notification.
    ///
    /// Notifications are sent in the following:
    /// * Utilization rises above any of the high watermarks in resource notification thresholds vector,
    ///   and current resource monitor state is at a lower state. In this case resource monitor state is
    ///   set to threshold index + 1.
    /// * Utilization falls below any of the low watermarks in resource notification thresholds vector,
    ///   and current resource monitor state is at a higher state. In this case resource monitor state is
    ///   set to threshold index.
    ///
    /// param[in]   resource_type               Resource to set thresholds for.
    /// param[in]   thresholds_vec              Vector of Low and High notification threshold pairs.
    ///
    /// @retval     LA_STATUS_SUCCESS           Thresholds were set successfully.
    /// @retval     LA_STATUS_EINVAL            Threshold pair is invalid if high_watermark < low_watermark,
    ///                                         Threshold vector is invalid if pairs overlap.
    ///                                         Threshold vector is invalid if thresholds are not in increasing order.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                           const std::vector<la_resource_thresholds>& thresholds_vec)
        = 0;

    /// @brief Get thresholds for utilization notification.
    ///
    /// param[in]   resource_type               Resource to retrieve its thresholds.
    /// param[out]  out_thresholds_vec          Vector of Low and High notification thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Thresholds were returned successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                           std::vector<la_resource_thresholds>& out_thresholds_vec) const = 0;

    /// @brief Flush all pending operations to the device.
    ///
    /// Returns when device is fully configured with all pending operations.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status flush() const = 0;

    /// @brief Read temperature from a given sensor in Celsius degrees.
    ///
    /// param[in]   sensor              Sensor to read temperature from.
    /// param[out]  out_temperature     A reading from temperature sensor.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_temperature(la_temperature_sensor_e sensor, la_temperature_t& out_temperature) = 0;

    /// @brief Read voltage from a given sensor.
    ///
    /// param[in]   sensor              Sensor to read voltage from.
    /// param[out]  out_voltage         Sensor's voltage.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_voltage(la_voltage_sensor_e sensor, la_voltage_t& out_voltage) = 0;

    /// @brief Enable/Disable FE fabric reachability advertisement.
    ///
    /// FE device that does not advertise fabric reachability will not receive traffic from peer devices.
    /// Default setting is enabled.
    ///
    /// @param[in]  enabled             true if fabric reachability advertisement should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an FE device.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_fe_fabric_reachability_enabled(bool enabled) = 0;

    /// @brief Return FE fabric reachability advertisement state.
    ///
    /// @param[out] out_enabled         true if fabric reachability advertisement is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an FE device.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_fe_fabric_reachability_enabled(bool& out_enabled) const = 0;

    /// @brief Set the global threshold of fabric links that should be connected to any LC to be considered reachable.
    ///
    /// An FE will advertise that it can reach a LC if the number of active fabric links to that LC is at least num_links.
    ///
    /// This API can be used only if #silicon_one::la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS property is not set in this
    /// device.
    ///
    /// @param[in]  num_links                The minimum number of fabric links.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an FE device or #silicon_one::la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS is
    /// set.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_global_minimum_fabric_links(size_t num_links) = 0;

    /// @brief Return the global threshold of fabric links that should be connected to any LC to be considered reachable.
    ///
    /// @param[out] out_num_links            The minimum number of fabric links.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an FE device or #silicon_one::la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS is
    /// set.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_global_minimum_fabric_links(size_t& out_num_links) const = 0;

    /// @brief Set the minimal number of fabric links that should be connected to the given LC to be considered reachable.
    ///
    /// An FE will advertise that it can reach a LC with dev_id device-ID only if the number of active fabric
    /// links to that LC is at least num_links.
    ///
    /// This API can be used only if #silicon_one::la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS property is set in this
    /// device.
    ///
    /// @param[in]  device_id                The LC device ID.
    /// @param[in]  num_links                The minimum number of fabric links.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an FE device or #silicon_one::la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS is
    /// not set.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_minimum_fabric_links_per_lc(la_device_id_t device_id, size_t num_links) = 0;

    /// @brief Return the minimal number of fabric links that should be connected to the given LC to be considered reachable.
    ///
    /// @param[in]  device_id                The LC device ID.
    /// @param[out] out_num_links            The minimum number of fabric links.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an FE device or #silicon_one::la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS is
    /// not set.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_minimum_fabric_links_per_lc(la_device_id_t device_id, size_t& out_num_links) const = 0;

    /// @brief Save current device state to file.
    ///
    /// File includes the full register/memory state of all configuration memories.
    ///
    /// @param[in]  options                 Options to control which data to include in the state.
    /// @param[in]  file_name               File name to write the state to.
    ///                                     If file already exists, it will be overwritten.
    ///                                     Supports .gz file
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status save_state(save_state_options options, std::string file_name) const = 0;

    /// @brief Save current device state to file.
    ///
    /// @param[in]  options                 Options to control which data to include in the state.
    /// @param[out] out_json                JSON root of all the counters. Caller is in charge of freeing up the memory after usage.
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status save_state(save_state_options options, json_t*& out_json) const = 0;

    /// @brief Configure how often device state is saved automatically.
    ///
    /// Values <= 0 will stop periodic save state.
    /// Values >  0 will schedule/reschedule periodic save state with the given period.
    ///
    /// @param[in]  period                  Time between two saved states in ms.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_periodic_save_state_period(const std::chrono::milliseconds period) = 0;

    /// @brief Set the data to be saved periodically and the prefix for the save-file name.
    ///
    /// The full file name is a concatenation separated by underscores of: file_name_prefix, device ID and timestamp.
    /// For more information on the timestamp please see gen_utils.h:add_timestamp(..).
    /// By default file name prefix is: "./", and for the options default values please consult the default constructor for the
    /// save_state_options.
    ///
    /// @param[in] options                  Options to control which data to include in the state.
    /// @param[in] file_name_prefix         File name prefix for the save-file.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EEXIST        Bad file_name_prefix.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_periodic_save_state_parameters(const save_state_options& options, const std::string& file_name_prefix)
        = 0;

    /// @brief Retrieve how often device state is saved automatically.
    ///
    /// Values 0 indicates that the periodic save state is turned off.
    /// Value greater than 0 indicates how often the state is saved.
    ///
    /// @param[out] out_period                  Time between two saved states in ms.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_periodic_save_state_period(std::chrono::milliseconds& out_period) const = 0;

    /// @brief Retrive what data is to be saved periodically and the prefix for the save-file name.
    ///
    /// The full file name is a concatenation separated by underscores of: file_name_prefix, device ID and timestamp.
    /// For more information on the timestamp please see gen_utils.h:add_timestamp(..).
    ///
    /// @param[out] out_options                  Options to control which data to include in the state.
    /// @param[out] out_file_name_prefix         File name prefix for the save-file.
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_ENOTINITIALIZED    Either options or file_name_prefix or both are not initialized..
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred.
    virtual la_status get_periodic_save_state_parameters(save_state_options& out_options,
                                                         std::string& out_file_name_prefix) const = 0;

    /// @brief Retrieve counter of dropped packets/bytes due to NPU error.
    ///
    /// @param[out]  out_counter          Reference #silicon_one::la_counter_set* to populate with the counter.
    ///
    /// @note This API is only relevant to the Pacific A0 ASIC.
    ///
    /// @retval    LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval    LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status get_npu_error_counter(la_counter_set*& out_counter) = 0;

    /// @brief Retrieve counter of dropped packets/bytes on nullptr forwarding destination.
    ///
    /// Dropped traffic that affects this counter is documented as counted on #silicon_one::la_device::get_forwarding_drop_counter.
    ///
    /// @param[out]  out_counter          Reference #silicon_one::la_counter_set* to populate with the counter.
    ///
    /// @retval    LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval    LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status get_forwarding_drop_counter(la_counter_set*& out_counter) = 0;

    /// @brief Perform a soft reset to a live system.
    ///
    /// This will cause traffic to momentarily drop, while the system is being reset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status soft_reset() = 0;

    /// @brief Retrieve MAC aging intervals.
    ///
    /// @param[out]  out_aging_interval     Seconds per aging scrub interval.
    ///
    /// @retval      LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval      LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status get_mac_aging_interval(la_mac_aging_time_t& out_aging_interval) = 0;

    /// @brief Configure global MAC aging interval.
    ///
    /// @param[in]  aging_interval         Seconds per aging scrub interval.
    ///
    /// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status set_mac_aging_interval(la_mac_aging_time_t aging_interval) = 0;

    /// @brief Set learning mode to LOCAL or SYSTEM
    ///
    /// This will cause learn records to be sent to local device or CPU for processing.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_learn_mode(learn_mode_e learn_mode) = 0;

    /// @brief Get currently configured learning mode
    ///
    /// This will return what's currently configured on the device.
    ///
    /// @param[out]  out_learn_mode     SYSTEM or LOCAL
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_learn_mode(learn_mode_e& out_learn_mode) = 0;

    /// @brief Create a new meter markdown object.
    ///
    /// @param[in]  meter_markdown_gid          Global ID of meter markdown profile object.
    /// @param[out] out_meter_markdown_profile  Pointer to #silicon_one::la_meter_markdown_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
    ///                                    out_meter_markdown_profile contains the meter markdown object.
    /// @retval     LA_STATUS_EBUSY        Meter markdown global ID in use.
    /// @retval     LA_STATUS_EINVAL       Meter markdown global ID is invalid.
    /// @retval     LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status create_meter_markdown_profile(la_meter_markdown_gid_t meter_markdown_gid,
                                                    la_meter_markdown_profile*& out_meter_markdown_profile)
        = 0;

    /// @brief Get a meter markdown object using its global ID.
    ///
    /// @param[in]  meter_markdown_gid          Global ID of meter markdown profile object.
    /// @param[out] out_meter_markdown_profile  Pointer to #silicon_one::la_meter_markdown_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    ///                                 out_meter_markdown_profile contains the meter markdown object.
    /// @retval     LA_STATUS_ENOTFOUND Meter markdown global ID does not map to #silicon_one::la_meter_markdown_profile object.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_meter_markdown_profile_by_id(la_meter_markdown_gid_t meter_markdown_gid,
                                                       la_meter_markdown_profile*& out_meter_markdown_profile) const = 0;

    /// @brief Enable or disable a bit in an interrupt register.
    ///
    /// @note On enable, interrupt bit is unmasked.
    /// @note On disable, interrupt bit is masked off.
    ///
    /// @param[in]  reg     Interrupt register.
    /// @param[in]  bit_i   Bit to be enabled/disabled.
    /// @param[in]  enabled Whether to set to enabled or disabled.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      Invalid interrupt register.
    /// @retval     LA_STATUS_EOUTOFRANGE Bit position is out of range.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_interrupt_enabled(const lld_register_scptr& reg, size_t bit_i, bool enabled) = 0;

    /// @brief Check whether a bit in an interrupt register is enabled.
    ///
    /// @param[in]  reg         Interrupt register.
    /// @param[in]  bit_i       Bit to get enabled/disabled.
    /// @param[out] out_enabled Enabled/disabled state.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      Invalid interrupt register.
    /// @retval     LA_STATUS_EOUTOFRANGE Bit position is out of range.
    virtual la_status get_interrupt_enabled(const lld_register_scptr& reg, size_t bit_i, bool& out_enabled) = 0;

    /// @brief Enable or disable memory protection interrupt for this memory.
    ///
    /// @note On enable, memory protection interrupt for this memory is unmasked.
    /// @note On disable, memory protection interrupt for this memory is masked off.
    ///
    /// @param[in]  mem       Memory instance.
    /// @param[in]  enabled   Whether to set to enable or disable.
    ///
    /// @retval     LA_STATUS_SUCCESS  Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL   Not a protected memory.
    /// @retval     LA_STATUS_EUNKNOWN An unknown error occurred.
    virtual la_status set_interrupt_enabled(const lld_memory_scptr& mem, bool enabled) = 0;

    /// @brief Check whether memory protection interrupt is enabled for this memory.
    ///
    /// @param[in]  mem         Memory instance.
    /// @param[out] out_enabled Enabled/disabled state.
    ///
    /// @retval     LA_STATUS_SUCCESS  Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL   Not a protected memory.
    virtual la_status get_interrupt_enabled(const lld_memory_scptr& mem, bool& out_enabled) = 0;

    /// @brief Resolve load balancing on the given object's load balance stage.
    ///
    /// @param[in]  forwarding_object            The forwarding object which requires to resolve load balance.
    /// @param[in]  lb_vec                       Input packet fields for forming load balance vector.
    /// @param[out] out_member_id                The resolved load balance member instance.
    /// @param[out] out_resolved_object          The resolved object after the load balancing the current stage.
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL             Invalid parameter passed.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED    Invalid object parameter which doesn't support load balancing.
    virtual la_status get_forwarding_load_balance_stage(const la_object* forwarding_object,
                                                        const la_lb_pak_fields_vec& lb_vec,
                                                        size_t& out_member_id,
                                                        const la_object*& out_resolved_object) const = 0;

    /// @brief Resolve load balancing on the given object and follow further object path.
    ///
    /// @param[in]  forwarding_object            The forwarding object which requires to resolve load balance.
    /// @param[in]  lb_vec                       Input packet fields for forming load balance vector.
    /// @param[out] out_resolution_chain         The resolved object chain across stages.
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL             Invalid parameter passed.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED    Invalid object parameter which doesn't support load balancing.
    virtual la_status get_forwarding_load_balance_chain(const la_object* forwarding_object,
                                                        const la_lb_pak_fields_vec& lb_vec,
                                                        std::vector<const la_object*>& out_resolution_chain) const = 0;

    /// @brief Write persistent token to device.
    ///
    /// @note  Can be called both before and after la_device::reconnect.
    ///
    /// @param[in]  token                        Token to be saved.
    ///
    /// @retval     LA_STATUS_SUCCESS            Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred. Token wasn't written to device.
    virtual la_status write_persistent_token(la_user_data_t token) = 0;

    /// @brief Read persistent token from device.
    ///
    /// @note  Returns the last value written by user. If no token was ever successfully written
    ///        the function won't automatically fail. If it sucessfully returns, the out_token will be a meaningless value.
    ///
    /// @param[out] out_token                    Persistent token from device.
    ///
    /// @retval     LA_STATUS_SUCCESS            Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred. Token wasn't read from device.
    virtual la_status read_persistent_token(la_user_data_t& out_token) const = 0;
    /// @brief Fetch system port with lowest mtu, sharing slice with sys_port.
    ///
    /// @param[in] sys_port             The system port whose slice sibling(with lowest mtu) is being fetched.
    /// @param[out] out_sys_port        The sibling port of sys_port with lowest mtu.
    ///
    /// @retval   LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval   LA_STATUS_EUNKNOWN    Internal error.
    virtual la_status get_lowest_mtu_sibling_port_of_this_slice(const la_system_port* sys_port,
                                                                const la_system_port*& out_sys_port) const = 0;

    /// @brief Set the PFC latency threshold for a given traffic class.
    ///
    /// @param[in]  tc                          Traffic class
    /// @param[in]  latency                     Latency threshold when XOFF PFC packet is sent. Latency of zero means disabled.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE       Parameters are out of range.
    virtual la_status set_sw_fc_pause_threshold(la_traffic_class_t tc, std::chrono::microseconds latency) = 0;

    /// @brief Get the PFC latency threshold for a given traffic class.
    ///
    /// @param[in]  tc                          Traffic class
    /// @param[out] out_latency                 Latency threshold when XOFF PFC packet is sent. Latency of zero means disabled.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE       Parameters are out of range.
    virtual la_status get_sw_fc_pause_threshold(la_traffic_class_t tc, std::chrono::microseconds& out_latency) const = 0;

    /// @brief Set the PFC destination for SW-based PFC.
    ///
    /// @param[in]  gid                         system port gid
    /// @param[in]  npu_dest                    NPU host dest
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE       Parameters are out of range.
    virtual la_status set_sw_pfc_destination(la_system_port_gid_t gid, la_npu_host_destination* npu_dest) = 0;

    /// @brief Clear the PFC congestion state for Pacific software based PFC for a given destination and traffic class.
    ///
    /// @param[in]  gid                         Destination system port gid
    /// @param[in]  tc                          Traffic class
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE       Parameters are out of range.
    virtual la_status clear_sw_pfc_congestion_state(la_system_port_gid_t gid, la_traffic_class_t tc) = 0;

    /// @brief Set network node ID used for load-balancing.
    ///
    /// Sets the node ID used in load-balancing decisions of ECMP and SPA.
    ///
    /// @note: In order to improve load-balancing decisions of flows across systems in a network, each system should have a unique
    /// node ID.
    ///
    /// @param[in]      load_balancing_node_id      Unique device identifier.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_load_balancing_node_id(size_t load_balancing_node_id) = 0;

    /// @brief Get network node ID used for load-balancing.
    ///
    /// @param[out]     out_load_balancing_node_id  Unique device identifier.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    virtual la_status get_load_balancing_node_id(size_t& out_load_balancing_node_id) const = 0;

    /// @brief Set ECMP hash seed.
    ///
    /// Sets the seed used by a hash function that calculates the load balancing ECMP member.
    ///
    /// @param[in]      ecmp_lb_seed            ECMP Load balance hash seed.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_ecmp_hash_seed(la_uint16_t ecmp_lb_seed) = 0;

    /// @brief Get the ECMP hash seed.
    ///
    /// @param[out]     out_ecmp_lb_seed        ECMP Load balance hash seed.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    virtual la_status get_ecmp_hash_seed(la_uint16_t& out_ecmp_lb_seed) const = 0;

    /// @brief Set the SPA hash seed.
    ///
    /// Sets the seed used by a hash function that calculates the load balancing SPA member.
    ///
    /// @param[in]      spa_lb_seed             SPA Load balance hash seed.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.

    virtual la_status set_spa_hash_seed(la_uint16_t spa_lb_seed) = 0;

    /// @brief Get the SPA hash seed.
    ///
    /// @param[out]     out_spa_lb_seed         SPA Load balance hash seed.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    virtual la_status get_spa_hash_seed(la_uint16_t& out_spa_lb_seed) const = 0;

    /// @brief  Set SyncE recovered clock for an output clock pin.
    ///
    /// @note:  User need to clear existing SyncE recovered clock selection on the output pin
    ///         by calling #silicon_one::la_device::detach_synce_output before new one can be applied.
    ///
    /// @param[in]  prim_sec_clock          To select the output recovered clock source: Primary or Secondary.
    /// @param[in]  slice_id                The selected recovered clock Slice number.
    /// @param[in]  ifg_id                  The selected recovered clock IFG number.
    /// @param[in]  serdes_id               The selected recovered clock SerDes number.
    /// @param[in]  divider                 The selected recovered clock divider value.
    /// @param[out] out_synce_pin           The device global SyncE pin number.
    ///
    /// @retval LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval LA_STATUS_EINVAL            One of the parameters is invalid.
    /// @retval LA_STATUS_EBUSY             Recovered clock already attached to the pin.
    /// @retval LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status attach_synce_output(synce_clock_sel_e prim_sec_clock,
                                          la_slice_id_t slice_id,
                                          la_ifg_id_t ifg_id,
                                          la_uint_t serdes_id,
                                          uint32_t divider,
                                          uint32_t& out_synce_pin)
        = 0;

    /// @brief  Get SyncE recovered clock of an output clock pin.
    ///
    /// @param[in]   prim_sec_clock              To select the output recovered clock source.
    /// @param[in]   synce_pin                   The device global SyncE pin number, each output pin has Primary & Secondary clock
    /// source.
    /// @param[out]  out_slice_id                The Slice number of the source SerDes.
    /// @param[out]  out_ifg_id                  The IFG number of the source SerDes.
    /// @param[out]  out_serdes_id               The Serdes number of the source SerDes.
    /// @param[out]  out_divider                 The divider value of the source SerDes.
    ///
    /// @retval LA_STATUS_SUCCESS                Operation completed successfully.
    /// @retval LA_STATUS_EINVAL                 One of the parameters is invalid.
    /// @retval LA_STATUS_ENOTFOUND              The clock pin has no clock attached.
    /// @retval LA_STATUS_EUNKNOWN               An unknown error occurred.
    virtual la_status get_synce_output(synce_clock_sel_e prim_sec_clock,
                                       uint32_t synce_pin,
                                       la_slice_id_t& out_slice_id,
                                       la_ifg_id_t& out_ifg_id,
                                       la_uint_t& out_serdes_id,
                                       uint32_t& out_divider) const = 0;

    /// @brief  De-select SyncE recovered clock on an output clock pin.
    ///
    /// @param[in]  prim_sec_clock           To select the output recovered clock source.
    /// @param[in]  synce_pin                The device global SyncE pin number, each output pin has Primary & Secondary clock
    /// source.
    ///
    /// @retval LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval LA_STATUS_EINVAL             One of the parameters is invalid.
    /// @retval LA_STATUS_EUNKNOWN           An unknown error occurred.
    /// @retval LA_STATUS_ENOTFOUND          Recovered clock not attached.
    virtual la_status detach_synce_output(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin) = 0;

    /// @brief  Clear SyncE unlock status of auto squelch.
    ///
    /// @param[in]  prim_sec_clock          To select the output recovered clock source: Primary or Secondary.
    /// @param[in]  synce_pin               The device global SyncE pin number, each output pin has Primary & Secondary clock
    ///
    /// @retval LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval LA_STATUS_EINVAL            One of the parameters is invalid.
    /// @retval LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status clear_synce_squelch_lock(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin) = 0;

    /// @brief  Set SyncE auto squelch enable/disable.
    ///
    /// @param[in]  prim_sec_clock          To select the output recovered clock source: Primary or Secondary.
    /// @param[in]  synce_pin               The device global SyncE pin number, each output pin has Primary & Secondary clock
    /// @param[in]  squelch_enable          Enable or Disable SyncE auto squelch.
    ///
    /// @retval LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval LA_STATUS_EINVAL            One of the parameters is invalid.
    /// @retval LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_synce_auto_squelch(synce_clock_sel_e prim_sec_clock, uint32_t synce_pin, bool squelch_enable) = 0;

    /// @brief  Get SyncE auto squelch setting.
    ///
    /// @param[in]  prim_sec_clock          To select the output recovered clock source: Primary or Secondary.
    /// @param[in]  synce_pin               The device global SyncE pin number, each output pin has Primary & Secondary clock
    /// @param[out] out_squelch_enable      Auto squelch enable or disable.
    ///
    /// @retval LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval LA_STATUS_EINVAL            One of the parameters is invalid.
    /// @retval LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_synce_auto_squelch(synce_clock_sel_e prim_sec_clock,
                                             uint32_t synce_pin,
                                             bool& out_squelch_enable) const = 0;

    /// @brief Get device boolean capabilities vector. Each element in the vector indicates a capability.
    ///
    /// @param[out]   out_device_bool_capabilities  Vector containing capabilities values.
    ///
    /// @return LA_STATUS_SUCCESS  Operation completed successfully.
    virtual la_status get_device_bool_capabilities(std::vector<bool>& out_device_bool_capabilities) const = 0;

    /// @brief Get device integer capabilities vector. Each element in the vector indicates a capability.
    ///
    /// @param[out]   out_device_int_capabilities  Vector containing capabilities values.
    ///
    /// @return LA_STATUS_SUCCESS  Operation completed successfully.
    virtual la_status get_device_int_capabilities(std::vector<uint32_t>& out_device_int_capabilities) const = 0;

    /// @brief Get device string capabilities vector. Each element in the vector indicates a capability.
    ///
    /// @param[out]   out_device_string_capabilities  Vector containing capabilities values.
    ///
    /// @return LA_STATUS_SUCCESS  Operation completed successfully.
    virtual la_status get_device_string_capabilities(std::vector<std::string>& out_device_string_capabilities) const = 0;

    /// @brief Get fuse userbits vector. each element in the vector is a value of the corresponding register.
    ///
    /// @param[out]   out_fuse_userbits  vector containing the fuse registers values.
    ///
    /// @return LA_STATUS_SUCCESS  Operation completed successfully.
    virtual la_status get_fuse_userbits(std::vector<uint32_t>& out_fuse_userbits) const = 0;

    /// @brief Get the current state of the heartbeat.
    ///
    /// @param[out]   out_heartbeat  Struct containing the heartbeat information.
    ///
    /// @return LA_STATUS_SUCCESS  Operation completed successfully.
    virtual la_status get_heartbeat(la_heartbeat_t& out_heartbeat) const = 0;

    /// @brief  Get an internal-error counter object.
    ///
    /// @param[in]  stage           Stage.
    /// @param[in]  type            Error type.
    /// @param[out] out_counter     Returned counter object.
    ///
    /// @retval LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_internal_error_counter(internal_error_stage_e stage,
                                                 internal_error_type_e type,
                                                 la_counter_set*& out_counter) const = 0;

    /// @brief Enable/Disable trapping for L2PT mac address.
    ///
    /// By default, trap is disabled for L2PT mac address.
    ///
    /// @param[in]  enabled     true if trap should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_l2pt_trap_enabled(bool enabled) = 0;

    /// @brief Return L2PT trap status.
    ///
    /// @param[out] out_enabled         true if L2PT trap is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_l2pt_trap_enabled(bool& out_enabled) = 0;

    /// @brief  Get TTL Decrement mode for given tunnel type
    ///
    /// @param[in] type           Tunnel Type
    /// @param[out] out_enabled   Enabled/disabled state.
    ///
    /// @retval LA_STATUS_SUCCESS Operation completed successfully
    virtual la_status get_decap_ttl_decrement_enabled(la_ip_tunnel_type_e type, bool& out_enabled) const = 0;

    /// @brief Set TTL Decrement mode for given tunnel type
    ///
    /// @param[in] type           Tunnel Type
    /// @param[in] enabled        After Tunnel Decapulation, True Decrements inner TTL, False Retains inner TTL. Default is True.
    /// @retval LA_STATUS_SUCCESS Operation completed successfully
    virtual la_status set_decap_ttl_decrement_enabled(la_ip_tunnel_type_e type, bool enabled) = 0;

    /// @brief Retrieve total Number of packets written to and read from SMS.
    ///
    /// @param[in]  slice_id            Slice to be queried.
    /// @param[in]  ifg                 IFG id to be queried.
    /// @param[in]  clear_on_read       Clear counters after read.
    /// @param[out] out_packet_count    Struct containing count of packets written to and read from SMS.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_sms_total_packet_counts(la_slice_id_t slice_id,
                                                  la_ifg_id_t ifg,
                                                  bool clear_on_read,
                                                  la_sms_packet_counts& out_packet_count)
        = 0;

    /// @brief Retrieve number of errors for SMS write and SMS read.
    ///
    /// @param[in]  clear_on_read           Clear counters after read.
    /// @param[out] out_error_count         Struct containing count of SMS read and SMS write path errors.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_sms_error_counts(bool clear_on_read, la_sms_error_counts& out_error_count) = 0;

    /// @brief Retrieve Number of SMS free buffers.
    ///
    /// @param[in]  clear_on_read           Clear counters after read.
    /// @param[out] out_free_buffer_count   Instantaneous number of SMS free buffers.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_sms_total_free_buffer_summary(bool clear_on_read, la_uint64_t& out_free_buffer_count) = 0;

    /// @brief Retrieve watermark values for counters.
    ///
    /// @param[out] out_watermarks         Struct containing watermark values of counters.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_cgm_watermarks(la_cgm_watermarks& out_watermarks) = 0;

    /// @brief Enable IP tunnel transit counter
    ///
    /// @param[in]  counter                 Counter object to set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_ip_tunnel_transit_counter(la_counter_set* counter) = 0;

    /// @brief Get IP tunnel transit counter
    ///
    /// @param[out] out_counter             Returned counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_ip_tunnel_transit_counter(la_counter_set*& out_counter) const = 0;

    /// @brief Create forus destination for lpts with object group code
    ///
    /// @param[in]  bincode                 destination object group code.
    /// @param[out] out_destination         Returned la_forus_destination object.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status create_forus_destination(la_uint_t bincode, la_forus_destination*& out_destination) = 0;

    /// @brief  Get a list of components and their health.
    ///
    /// @param[out] out_component_health     Returned vector of component health objects.
    ///
    /// @retval LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_component_health(la_component_health_vec_t& out_component_health) const = 0;

    /// @brief Return a vector of all MAC entries on the switch.
    ///
    /// @param[out] out_count           #la_uint32_t count to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac_entries_count(la_uint32_t& out_count) = 0;

    /// @brief Return a vector of all MAC entries on the switch.
    ///
    /// @param[out] out_mac_entries     #la_mac_entry_vec to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac_entries(la_mac_entry_vec& out_mac_entries) = 0;

    /// @brief Create an COPC instance.
    ///
    /// @param[in]  type                COPC instance type.
    /// @param[out] out_copc         Pointer to a #silicon_one::la_control_plane_classifier to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   COPC instance created successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status create_copc(la_control_plane_classifier::type_e type, la_control_plane_classifier*& out_copc) = 0;

    /// @brief   Set SDA mode for the device.
    ///
    /// @param[in]  mode                     Set enable/disable mode.
    ///
    /// @retval     LA_STATUS_SUCCESS        Operation completed successfully.
    virtual la_status set_sda_mode(bool mode) = 0;

    /// @brief Get SDA mode for the device.
    ///
    /// @param[out] out_mode                 Get enable/disable mode.
    ///
    /// @retval LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval LA_STATUS_ENOTIMPLEMENTED    Not implemented for this device.
    virtual la_status get_sda_mode(bool& out_mode) const = 0;

    /// @brief Creates a #silicon_one::la_security_group_cell over a given <sgt,dgt,ip_version> tuple.
    ///
    /// @param[in]  sgt                        SGT.
    /// @param[in]  dgt                        DGT.
    /// @param[in]  ip_version                 IP Version (V4/V6).
    /// @param[out] out_security_group_cell    Pointer to #silicon_one::la_security_group_cell to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS          Security Group Cell created successfully.
    /// @retval     LA_STATUS_EINVAL           Received invalid inputs.
    /// @retval     LA_STATUS_EBUSY            Security Group Cell is in use.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status create_security_group_cell(la_sgt_t sgt,
                                                 la_dgt_t dgt,
                                                 la_ip_version_e ip_version,
                                                 la_security_group_cell*& out_security_group_cell)
        = 0;

    /// @brief Create a new VRF redirect destination object, with specific attributes.
    ///
    /// @param[in]  vrf                         Pointer to #silicon_one::la_vrf to refer.
    /// @param[out] out_vrf_redirect_dest       Pointer to #silicon_one::la_vrf_redirect_destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully. out_vrf contains the VRF object.
    /// @retval     LA_STATUS_EINVAL            VRF is invalid.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS   VRF passed is on a different device.
    /// @retval     LA_STATUS_EBUSY             VRF already in use by another VRF redirect destination object.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status create_vrf_redirect_destination(const la_vrf* vrf, la_vrf_redirect_destination*& out_vrf_redirect_dest) = 0;

    /// @brief Get a VRF redirect destination object using its global ID.
    ///
    /// @param[in]  vrf                         Pointer to #silicon_one::la_vrf to refer.
    /// @param[out] out_vrf_redirect_dest       Pointer to #silicon_one::la_vrf_redirect_destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully. out_vrf contains the VRF object.
    /// @retval     LA_STATUS_EINVAL            VRF is invalid.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS   VRF passed is on a different device.
    /// @retval     LA_STATUS_ENOTFOUND         VRF passed does not have any corresponding #silicon_one::la_vrf_redirect_destination
    /// object.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_vrf_redirect_destination(const la_vrf* vrf,
                                                   la_vrf_redirect_destination*& out_vrf_redirect_dest) const = 0;

    /// @brief Configure schedulers of this device to grant credits to VOQs without being asked.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully..
    /// @retval     LA_STATUS_EINVAL            When this API is called on device that is not Linecard.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status open_scheduler_auto_grants() = 0;

    /// @brief Delete all MAC entries on the device.
    ///
    /// @param[out] out_mac_entries     #la_mac_entry_vec to be populated.
    /// @param[in] dynamic_only         Flush dynamic MAC entries only
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status flush_mac_entries(bool dynamic_only, la_mac_entry_vec& out_mac_entries) = 0;

    /// @brief Initiate Memory Protection Error in HW device.
    ///
    /// @param[in]  error_type          Error type
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed and ECC error is initiated.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status trigger_mem_protect_error(la_mem_protect_error_e error_type) = 0;

    /// @brief Add source IPv4 prefix for snooping.
    ///
    /// @param[in]  vrf                         Pointer to #silicon_one::la_vrf to refer.
    /// @param[in]  prefix                      IPv4 prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            VRF is invalid.
    /// @retval     LA_STATUS_ENOTFOUND         No free space found in the table.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status add_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv4_prefix_t prefix) = 0;

    /// @brief Remove source IPv4 prefix from snooping.
    ///
    /// @param[in]  vrf                         Pointer to #silicon_one::la_vrf to refer.
    /// @param[in]  prefix                      IPv4 prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            VRF is invalid.
    /// @retval     LA_STATUS_ENOTFOUND         Entry not found in the table.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status remove_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv4_prefix_t prefix) = 0;

    /// @brief Add source IPv6 prefix for snooping.
    ///
    /// @param[in]  vrf                         Pointer to #silicon_one::la_vrf to refer.
    /// @param[in]  prefix                      IPv6 prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            VRF is invalid.
    /// @retval     LA_STATUS_ENOTFOUND         No free space found in the table.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status add_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv6_prefix_t prefix) = 0;

    /// @brief Remove source IPv6 prefix from snooping.
    ///
    /// @param[in]  vrf                         Pointer to #silicon_one::la_vrf to refer.
    /// @param[in]  prefix                      IPv6 prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            VRF is invalid.
    /// @retval     LA_STATUS_ENOTFOUND         Entry not found in the table.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status remove_source_ip_snooping_prefix(const la_vrf* vrf, la_ipv6_prefix_t prefix) = 0;

    /// @brief Returns a vector of all ip snooping prefixes from the device.
    ///
    /// @param[out] out_ip_snooping_prefixes    #la_ip_snooping_entry_vec_t to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    virtual la_status get_source_ip_snooping_prefixes(la_ip_snooping_entry_vec_t& out_ip_snooping_prefixes) = 0;

protected:
    ~la_device() override = default;
};

} // namespace silicon_one

/// @}

#endif
