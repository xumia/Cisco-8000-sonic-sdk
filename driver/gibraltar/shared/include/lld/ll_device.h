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

#ifndef __LEABA_LLD_LL_DEVICE_H__
#define __LEABA_LLD_LL_DEVICE_H__

#include <string>

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"
#include "lld/device_simulator.h"
#include "lld/lld_fwd.h"

#include "common/bit_vector.h"
#include "common/defines.h"
#include "common/weak_ptr_unsafe.h"
#include <functional>
#include <vector>

namespace silicon_one
{

class pacific_tree;
class gibraltar_tree;
class asic3_tree;
class asic4_tree;
class asic3_tree;
class asic5_tree;
class interrupt_tree;
class access_engine;
class arc_cpu;
class lld_memory;
class lld_register;

class ll_device : public std::enable_shared_from_this<ll_device>
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
#ifndef SWIG
    /// @brief Access descriptor.
    ///
    /// Defines a single device access operation to perform.
    /// These include read/write/wait actions for memory and registers.
    ///
    /// Executing sets of #silicon_one::ll_device::access_desc-s using the ll_device::access(..) API allows for improved throughput.
    struct access_desc {

        /// @brief Operation to be performed by this access_desc.
        enum class operation_e {
            INVALID,                    ///< Invalid command.
            READ_MEMORY,                ///< Reading from a memory.
            READ_MODIFY_WRITE_MEMORY,   ///< Update bits of a memory line.
            READ_MODIFY_WRITE_REGISTER, ///< Update bits of a register.
            READ_REGISTER,              ///< Reading from a register.
            PEEK_REGISTER,              ///< Peeking a register.
            WAIT_FOR_VALUE,             ///< Wait for a value to become equal / not equal.
            WRITE_MEMORY,               ///< Writing to a memory.
            WRITE_REGISTER,             ///< Writing to a register.
            WRITE_REGISTER_ARRAY,       ///< Writing to a registar array.
            DELAY,                      ///< Delay for a specified amount of core cycles.
        };

        operation_e action;  ///< Action to execute.
        bit_vector* out_val; ///< bit_vector to populate for read command.
        bit_vector in_val;   ///< bit_vector that contains data to write to HW.

        const lld_register* reg;                       ///< Register to read/write to/from.
        const lld_memory* mem;                         ///< Memory to read/write to/from.
        const lld_register_array_container* reg_array; ///< Register array to write to.
        la_entry_addr_t first;                         ///< First entrie to read/write. Used in memory/register array command.
        size_t count;                                  ///< Number of entries in the memory.

        union emw_or_wait_for_value_args_s { ///< Arguments for each function.
            struct rmw_s {
                size_t msb; ///< Subfield's MSB index.
                size_t lsb; ///< Subfield's LSB index.
            } rmw;

            struct wait_for_value_s {
                la_block_id_t block_id; ///< Block ID of the storage.
                la_entry_addr_t addr;   ///< Storage address in the block.
                bool equal;             ///< Wait for value to become equal or not.
                uint8_t poll_cnt;       ///< Number of times to poll for the value.
                uint16_t val;           ///< Value to compare with.
                uint16_t mask;          ///< Comparison mask.
            } wait_for_value;
            uint64_t delay_cycles; ///< Cycles argument for AE delay opcode.
        } args;
    };

    /// @name General
    /// @{
    /// @brief Create low-level device object.
    ///
    /// @param[in]  device_id              Device id attached to this lld.
    /// @param[in]  device_path            Device path (e.g. /dev/uioX).
    ///
    /// @retval                            Pointer to low-level device object.
    static ll_device_sptr create(la_device_id_t device_id, const char* device_path);

    /// @brief Create low-level device object.
    ///
    /// Set platform-specific operations.
    ///
    /// @param[in]  device_id              Device id attached to this lld.
    /// @param[in]  device_path            Device path (e.g. /dev/uioX).
    /// @param[in]  sim                    Device simulator.
    /// @param[in]  platform_cbs           Platform specific operations.
    ///
    /// @retval                            Pointer to low-level device object.
    static ll_device_sptr create(la_device_id_t device_id,
                                 const char* device_path,
                                 device_simulator* sim,
                                 const la_platform_cbs& platform_cbs);

    /// Set platform-specific operations.
    ///
    /// @param[in]  device_id              Device id attached to this lld.
    /// @param[in]  device_path            Device path (e.g. /dev/uioX).
    /// @param[in]  sim                    Device simulator.
    /// @param[in]  platform_cbs           Platform specific operations.
    /// @param[in]  use_filtered           Use ll_filtered_device implementation.
    ///
    /// @retval                            Pointer to low-level device object.
    static ll_device_sptr create(la_device_id_t device_id,
                                 const char* device_path,
                                 device_simulator* sim,
                                 const la_platform_cbs& platform_cbs,
                                 bool use_filtered);
#endif
    virtual ~ll_device() = default;

    /// @brief      Get Pacific device tree.
    ///
    /// @return     pacific_tree object.
    virtual const pacific_tree* get_pacific_tree() const = 0;

    /// @brief      Get Gibraltar device tree.
    ///
    /// @return     gibraltar_tree object.
    virtual const gibraltar_tree* get_gibraltar_tree() const = 0;

    /// @brief      Get Asic4 device tree.
    ///
    /// @return     asic4_tree object.
    virtual const asic4_tree* get_asic4_tree() const = 0;

    /// @brief      Get Asic3 device tree.
    ///
    /// @return     asic3_tree object.
    virtual const asic3_tree* get_asic3_tree() const = 0;

    /// @brief      Get Asic5 device tree.
    ///
    /// @return     asic5_tree object.
    virtual const asic5_tree* get_asic5_tree() const = 0;

    /// @brief      Get a shared pointer of Pacific device tree.
    ///
    /// @return     shared pointer of pacific_tree object.
    virtual pacific_tree_scptr get_pacific_tree_scptr() const = 0;

    /// @brief      Get a shared pointer of Gibraltar device tree.
    ///
    /// @return     shared pointer of gibraltar_tree object.
    virtual gibraltar_tree_scptr get_gibraltar_tree_scptr() const = 0;

    /// @brief      Get a shared pointer of Asic4 device tree.
    ///
    /// @return     shared pointer of asic4_tree object.
    virtual asic4_tree_scptr get_asic4_tree_scptr() const = 0;

    /// @brief      Get a shared pointer of Asic3 device tree.
    ///
    /// @return     shared pointer of asic3_tree object.
    virtual asic3_tree_scptr get_asic3_tree_scptr() const = 0;

    /// @brief      Get a shared pointer of Asic5 device tree.
    ///
    /// @return     shared pointer of asic5_tree object.
    virtual asic5_tree_scptr get_asic5_tree_scptr() const = 0;

    /// @brief      Get device tree
    ///
    /// @return     lld_block object
    virtual lld_block_scptr get_device_tree() const = 0;

    /// @brief      Get device family.
    ///
    /// @return     Device family.
    virtual la_device_family_e get_device_family() const = 0;

    /// @brief      Get device revision.
    ///
    /// @return     Device revision.
    virtual la_device_revision_e get_device_revision() const = 0;

    /// @brief      Check if this is a Asic5 device.
    ///
    /// @return     true if Asic5, false if otherwise.
    virtual bool is_asic5() const = 0;

    /// @brief      Check if this is a Asic4 device.
    ///
    /// @return     true if Asic4, false if otherwise.
    virtual bool is_asic4() const = 0;

    /// @brief      Check if this is a Asic3 device.
    ///
    /// @return     true if Asic3, false if otherwise.
    virtual bool is_asic3() const = 0;

    /// @brief      Check if this is a Asic7 device.
    ///
    /// @return     true if Asic7, false if otherwise.
    virtual bool is_asic7() const = 0;

    /// @brief      Check if this is a Gibraltar device.
    ///
    /// @return     true if Gibraltar, false if otherwise.
    virtual bool is_gibraltar() const = 0;

    /// @brief      Check if this is a Pacific device.
    ///
    /// @return     true if Pacific, false if otherwise.
    virtual bool is_pacific() const = 0;

    /// @brief      Get device path.
    ///
    /// @return     device path string.
    virtual std::string get_device_path() const = 0;

    /// @brief      Get device interrupt tree.
    ///
    /// @return     interrupt_tree object.
    virtual interrupt_tree* get_interrupt_tree() = 0;

    /// @brief      Get device interrupt tree.
    ///
    /// @return     interrupt_tree object.
    virtual interrupt_tree_sptr get_interrupt_tree_sptr() = 0;

    virtual ll_device_context_sptr get_device_context() = 0;

    /// @brief Perform full hardware reset of the device.
    virtual la_status reset() = 0;

    /// @brief Return True if the device is valid, False otherwise.
    virtual bool is_valid() const = 0;

    /// @brief Get device id of the device created this ll_device.
    ///
    /// @return     silicon_one::la_device_id_t of the device that created this ll_device.
    virtual la_device_id_t get_device_id() const = 0;

    /// @brief Check if this a simulated or physical device.
    ///
    /// @return true if simulated device; false if physical device.
    virtual bool is_simulated_device() const = 0;

    /// @brief Enable/disable write burst mode.
    ///
    /// @note  In this mode, writes occur in burst instead of sequentially.
    ///        This should only be used when the device is not under operation
    ///        or handling traffic; otherwise, behavior is undefined.
    ///
    /// @param[in]  en  True to enable, False to disable.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EBUSY     Device is busy.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_write_burst(bool en) = 0;

    /// @brief Flush write operations after each write.
    ///
    /// This mode enables non-posted, slower writes. Failed writes are detected immediately.
    /// Set to False by default.
    ///
    /// @param[in]  en  True to enable non-posted mode, False to disable.
    ///
    /// @note this API should only be used in debug mode, as it adversely affects access performance.
    virtual void set_flush_after_write(bool en) = 0;

    /// @brief Enable/disable read from shadow.
    ///
    /// @note If enabled (default), read from shadow.
    ///       If disabled, read from device and update the shadow.
    //        The setting only affects reads from non-volatile registers and memories.
    ///
    /// @param[in]  en  True to enable, False to disable.
    virtual void set_shadow_read_enabled(bool en) = 0;

    /// @brief Check if shadow is enabled or disabled.
    ///
    /// @return True if enabled, False if disabled.
    virtual bool get_shadow_read_enabled() const = 0;

    /// @brief Enable/disable write to device.
    ///
    /// @note If enabled (default), write to shadow and to device.
    ///       If disabled, write only to shadow.
    ///
    /// @param[in]  en  True to enable, False to disable.
    virtual void set_write_to_device(bool en) = 0;

    /// @brief Check if write-to-device device is enabled or disabled.
    ///
    /// @return True if enabled, False if disabled.
    virtual bool get_write_to_device() const = 0;

    /// @brief Reset all access engines.
    ///
    /// @note  This is a debug-only API.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EBUSY     One or more of Access Engines is busy.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status reset_access_engines() = 0;

    /// @brief Reset access engines as specified by the bit mask.
    ///
    /// @note  This is a debug-only API.
    ///
    /// @param[in]  mask  Bit mask to select access engines.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EBUSY     One or more of Access Engines is busy.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status reset_access_engines(uint32_t mask) = 0;

    /// @brief Enable/disable FIFO mode for access engine command memory.
    ///
    /// @note  This is a debug-only API.
    ///        Should be set only once, before any R/W api is called.
    ///        Otherwise, the behaivor is undefined.
    ///
    /// @param[in]  en  True to enable, False to disable.
    virtual void set_access_engine_cmd_fifo_enabled(bool en) = 0;

    /// @brief Check if access engine command memory is in FIFO or flat-memory mode.
    ///
    /// @return  True if FIFO, False if flat-memory.
    virtual bool get_access_engine_cmd_fifo_enabled() const = 0;

    /// @brief Start all CSS ARC CPUs.
    ///
    /// @note  This is a debug-only API.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    virtual la_status start_css_arcs() = 0;

    /// @brief Stop all CSS ARC CPUs.
    ///
    /// @note  This is a debug-only API.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    virtual la_status stop_css_arcs() = 0;

    /// @brief Resets all CSS ARC CPUs.
    ///
    /// @note  This is a debug-only API.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    virtual la_status reset_css_arcs() = 0;

    /// @brief Load CSS ARC CPU microcode.
    ///
    /// @note  This is a debug-only API.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    virtual la_status load_css_arc_microcode(const std::string& filename) = 0;

    // Simulation mode
    enum class simulation_mode_e {
        NONE = 0,
        LBR,  // All R/W operations are redirected to simulator
        SBIF, // Only R/W operations to SBIF are redirected to simulator
    };

    /// @brief Set #silicon_one::device_simulator object.
    ///
    /// @param[in]   simulator  Pointer to device simulator object.
    ///
    /// @retval      LA_STATUS_SUCCESS  Simulator was successfully set.
    /// @retval      LA_STATUS_EEXIST   A simulator already exists.
    ///
    /// @note ll_device becomes the owner of the simulator and is responsible for its destruction.
    virtual la_status set_device_simulator(device_simulator* simulator) = 0;

    /// @brief Set #silicon_one::device_simulator object.
    ///
    /// @param[in]   simulator  Pointer to device simulator object.
    /// @param[in]   mode       Simulation mode, see #silicon_one::ll_device::simulation_mode_e.
    ///
    /// @retval      LA_STATUS_SUCCESS  Simulator was successfully set.
    /// @retval      LA_STATUS_EEXIST   A simulator already exists.
    ///
    /// @note ll_device becomes the owner of the simulator and is responsible for its destruction.
    virtual la_status set_device_simulator(device_simulator* simulator, simulation_mode_e mode) = 0;

    /// @brief Retrieve #silicon_one::device_simulator object.
    ///
    /// @retval     Pointer to device simulator object, or nullptr if not set.
    virtual device_simulator* get_device_simulator() const = 0;

    /// @brief Get device simulation mode.
    ///
    /// @retval     Simulation mode, see #silicon_one::ll_device::simulation_mode_e.
    virtual simulation_mode_e get_device_simulation_mode() const = 0;

    /// @brief Get file descriptor for device interrupt.
    ///
    /// @note The file descriptor can be used with read/select/poll/... system calls.
    //
    /// @param[out] out_pci_event_fd            An open PCI event file descriptor.
    /// @param[out] out_interrupt_fd            An open interrupt file descriptor.
    /// @param[out] out_interrupt_width_bytes   Interrupt payload width in bytes.
    virtual void get_event_fds(int& out_pci_event_fd, int& out_interrupt_fd, size_t& out_interrupt_width_bytes) const = 0;

    /// @}
    /// @name ISSU
    /// @{

    /// @brief Perform post-restore adjustments to ll_device.
    ///
    /// @param[in]  device_path            Device path (e.g. /dev/uioX).
    ///
    /// @retval      LA_STATUS_SUCCESS  Device was restored successfully.
    /// @retval      LA_STATUS_ENOTINITIALIZED A simulator device isn't set.
    /// @retval      LA_STATUS_ENODEV   Device isn't accessible.
    /// @retval      LA_STATUS_EUNKNOWN Unknown error.
    virtual la_status post_restore(const char* device_path) = 0;

    /// @}
    /// @name ISSU
    /// @{

    /// @brief Perform post-restore adjustments to ll_device.
    ///
    /// @param[in]  device_path            Device path (e.g. /dev/uioX).
    /// @param[in]  platform_cbs           Platform specific operations.
    ///
    /// @retval      LA_STATUS_SUCCESS  Device was restored successfully.
    /// @retval      LA_STATUS_ENOTINITIALIZED A simulator device isn't set.
    /// @retval      LA_STATUS_ENODEV   Device isn't accessible.
    /// @retval      LA_STATUS_EUNKNOWN Unknown error.
    virtual la_status post_restore(const char* device_path, const la_platform_cbs& platform_cbs) = 0;

    /// @name Registers/Memory/TCAM access API.
    /// @{
    /// @brief Read register.
    ///
    /// @param[in]  reg                    Register to be queried.
    /// @param[out] out_bv                 Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_register(const lld_register& reg, bit_vector& out_bv) = 0;

#ifndef SWIG
    /// @brief Read register by handle.
    ///
    /// @param[in]  reg                    Register handle.
    /// @param[out] out_bv                 Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_register(const lld_register_scptr& reg, bit_vector& out_bv) = 0;
#endif

    /// @brief Change traffic rate by modifying device's shapers.
    ///
    /// @param[in] traffic_reduce         true - reduce traffic, else - restore traffic
    virtual void change_traffic_rate(bool traffic_reduce) = 0;

    /// @brief Peek register.
    //
    /// Peek at register, do not perform any side-effects (e.g. clearing).
    ///
    /// @param[in]  reg                    Register to be queried.
    /// @param[out] out_bv                 Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status peek_register(const lld_register& reg, bit_vector& out_bv) = 0;

#ifndef SWIG
    /// @brief Peek register by handle.
    //
    /// Peek at register, do not perform any side-effects (e.g. clearing).
    ///
    /// @param[in]  reg                    Register handle to be queried.
    /// @param[out] out_bv                 Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status peek_register(const lld_register_scptr& reg, bit_vector& out_bv) = 0;
#endif

    /// @brief Read register.
    ///
    /// Store value in an auto-generated register struct.
    ///
    /// @param[in]  reg                 Register to be queried.
    /// @param[out] out_register_struct Register struct to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    template <class _StructType>
    inline la_status read_register(const lld_register& reg, _StructType& out_register_struct)
    {
        uint64_t* struct_ptr = (uint64_t*)&out_register_struct;
        bit_vector bv(struct_ptr, _StructType::SIZE_IN_BITS);
        return read_register(reg, bv);
    }

    /// @brief Read register by handle.
    ///
    /// Store value in an auto-generated register struct.
    ///
    /// @param[in]  reg                 Register handle to be queried.
    /// @param[out] out_register_struct Register struct to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    template <class _StructType>
    inline la_status read_register(const lld_register_scptr& reg, _StructType& out_register_struct)
    {
        uint64_t* struct_ptr = (uint64_t*)&out_register_struct;
        bit_vector bv(struct_ptr, _StructType::SIZE_IN_BITS);
        return read_register(reg, bv);
    }

    /// @brief Peak register.
    ///
    /// Peek at register, do not perform any side-effects (e.g. clearing).
    /// Store value in an auto-generated register struct.
    ///
    /// @param[in]  reg                 Register to be queried.
    /// @param[out] out_register_struct Register struct to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    template <class _StructType>
    inline la_status peek_register(const lld_register& reg, _StructType& out_register_struct)
    {
        uint64_t* struct_ptr = (uint64_t*)&out_register_struct;
        bit_vector bv(struct_ptr, _StructType::SIZE_IN_BITS);
        return peek_register(reg, bv);
    }

    /// @brief Peak register by handle.
    ///
    /// Peek at register, do not perform any side-effects (e.g. clearing).
    /// Store value in an auto-generated register struct.
    ///
    /// @param[in]  reg                 Register handle to be queried.
    /// @param[out] out_register_struct Register struct to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    template <class _StructType>
    inline la_status peek_register(const lld_register_scptr& reg, _StructType& out_register_struct)
    {
        uint64_t* struct_ptr = (uint64_t*)&out_register_struct;
        bit_vector bv(struct_ptr, _StructType::SIZE_IN_BITS);
        return peek_register(*reg, bv);
    }

#ifndef SWIG
    /// @brief Read register.
    ///
    /// @param[in]  reg                    Register to be queried.
    /// @param[in]  out_val_sz             Size of return buffer.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_register(const lld_register& reg, size_t out_val_sz, void* out_val) = 0;

    /// @brief Peek register.
    ///
    /// Peek at register, do not perform any side-effects (e.g. clearing).
    ///
    /// @param[in]  reg                    Register to be queried.
    /// @param[in]  out_val_sz             Size of return buffer.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status peek_register(const lld_register& reg, size_t out_val_sz, void* out_val) = 0;
#endif

    /// @brief Raw read register.
    ///
    /// @param[in]  block_id               Block ID of the register.
    /// @param[in]  addr                   Register address in the block.
    /// @param[in]  width_bits             Width of the register in bits.
    /// @param[out] out_bv                 Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv) = 0;

    /// @brief Raw peek register.
    ///
    /// @param[in]  block_id               Block ID of the register.
    /// @param[in]  addr                   Register address in the block.
    /// @param[in]  width_bits             Width of the register in bits.
    /// @param[out] out_bv                 Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status peek_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv) = 0;

    /// @brief Write register.
    ///
    /// @param[in]  reg                    Register to be manipulated.
    /// @param[in]  in_bv                  Data bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status write_register(const lld_register& reg, const bit_vector& in_bv) = 0;

#ifndef SWIG
    /// @brief Write register by handle.
    ///
    /// @param[in]  reg                    Register handle to be manipulated.
    /// @param[in]  in_bv                  Data bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status write_register(const lld_register_scptr& reg, const bit_vector& in_bv) = 0;

    /// @brief Write register.
    ///
    /// @param[in]  reg                    Register to be manipulated.
    /// @param[in]  in_val_sz              Data buffer size.
    /// @param[in]  in_val                 Data buffer.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status write_register(const lld_register& reg, size_t in_val_sz, const void* in_val) = 0;
#endif

    /// @brief Write register array.
    ///
    /// @param[in]  reg                    Register array to be manipulated.
    /// @param[in]  first                  First register to be manipulated.
    /// @param[in]  count                  Number of registers in register array to be manipulated.
    /// @param[in]  in_bv                  Data bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status write_register_array(const lld_register_array_container& reg,
                                           size_t first,
                                           size_t count,
                                           const bit_vector& in_bv)
        = 0;

    /// @brief Raw write of single specific register at a specific address in a specific block in the device.
    ///
    /// @param[in]  block_id               Block ID of the register.
    /// @param[in]  addr                   Register address in the block.
    /// @param[in]  width_bits             Width of the register in bits.
    /// @param[in]  in_bv                  Input bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status write_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, const bit_vector& in_bv)
        = 0;

    /// @brief Update a subfield of a register.
    ///
    /// @param[in]  reg                 Register to be manipulated.
    /// @param[in]  msb                 Subfield's MSB index.
    /// @param[in]  lsb                 Subfield's LSB index.
    /// @param[in]  value               Value to update.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& value) = 0;

    /// @brief Wait for value to become equal / not equal.
    ///
    /// @note This operation is only allowed for a volatile resource.
    ///
    /// @param[in]  reg                   Register to be manipulated.
    /// @param[in]  equal                 Wait for value to become equal or not.
    /// @param[in]  val                   Value to compare with.
    /// @param[in]  mask                  Comparison mask.
    ///
    /// @retval     LA_STATUS_SUCCESS     Command completed successfully.
    /// @retval     LA_STATUS_EINVAL      One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask) = 0;

    /// @brief Delay for a specified amount of core cycles.
    ///
    /// @param[in]  cycles                Amount of core cycles to delay.
    ///
    /// @retval     LA_STATUS_SUCCESS     Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status delay(uint64_t cycles) = 0;

    /// @}
    /// @name Memory access API-s
    /// @{
    /// @brief Read data from memory.
    ///
    /// @param[in]  mem                 Memory to access.
    /// @param[in]  mem_line            Entry index to read from.
    /// @param[out] out_bv              Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  Entry index out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status read_memory(const lld_memory& mem, size_t mem_line, bit_vector& out_bv) = 0;

#ifndef SWIG
    /// @brief Read data from memory by handle.
    ///
    /// @param[in]  mem                 Memory handle to access.
    /// @param[in]  mem_line            Entry index to read from.
    /// @param[out] out_bv              Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  Entry index out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status read_memory(const lld_memory_scptr& mem, size_t mem_line, bit_vector& out_bv) = 0;
#endif

    /// @brief Read data from memory.
    ///
    /// Read memory into auto-generated SW memory struct.
    ///
    /// @param[in]  mem                 Memory to access.
    /// @param[in]  mem_line            Entry index to read from.
    /// @param[out] out_memory_struct   Memory struct to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  Entry index out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    template <class _StructType>
    inline la_status read_memory(const lld_memory& mem, size_t mem_line, _StructType& out_memory_struct)
    {
        bit_vector bv;
        la_status status = read_memory(mem, mem_line, bv);
        return_on_error(status);

        memcpy(&out_memory_struct, bv.byte_array(), _StructType::SIZE);
        return LA_STATUS_SUCCESS;
    }

    /// @brief Read data from memory by handle.
    ///
    /// Read memory into auto-generated SW memory struct.
    ///
    /// @param[in]  mem                 Memory handle to access.
    /// @param[in]  mem_line            Entry index to read from.
    /// @param[out] out_memory_struct   Memory struct to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  Entry index out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    template <class _StructType>
    inline la_status read_memory(const lld_memory_scptr& mem, size_t mem_line, _StructType& out_memory_struct)
    {
        bit_vector bv;
        la_status status = read_memory(*mem, mem_line, bv);
        return_on_error(status);

        memcpy(&out_memory_struct, bv.byte_array(), _StructType::SIZE);
        return LA_STATUS_SUCCESS;
    }

#ifndef SWIG
    /// @brief Read data from memory.
    ///
    /// @param[in]  mem                 Memory to access.
    /// @param[in]  mem_first_entry     Entry index to start read from.
    /// @param[in]  count               Number of entries to read.
    /// @param[in]  out_val_sz          Size of return buffer.
    /// @param[out] out_val             Return value destination buffer.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  First entry index or count out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status read_memory(const lld_memory& mem, size_t mem_first_entry, size_t count, size_t out_val_sz, void* out_val)
        = 0;
#endif

    /// @brief Read data from memory from several lines.
    ///
    /// @param[in]  mem                 Memory to access.
    /// @param[in]  mem_first_entry     Entry index to start read from.
    /// @param[in]  count               Number of entries to read.
    /// @param[out] out_bv              Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  First entry index or count out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status read_memory(const lld_memory& mem, size_t mem_first_entry, size_t count, bit_vector& out_bv) = 0;

    /// @brief Raw data read from memory.
    ///
    /// @param[in]  block_id               Block ID of the memory.
    /// @param[in]  addr                   Memory address in the block.
    /// @param[in]  width_bits             Width of the memory in bits.
    /// @param[out] out_bv                 Return value bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_memory_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv) = 0;

    /// @brief Write data to memory.
    ///
    /// @param[in]  mem                    Memory to be manipulated.
    /// @param[in]  mem_line               Entry index to write to.
    /// @param[in]  in_bv                  Data bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  Entry index is out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status write_memory(const lld_memory& mem, size_t mem_line, const bit_vector& in_bv) = 0;

#ifndef SWIG
    /// @brief Write data to memory by handle.
    ///
    /// @param[in]  mem                    Memory handle to be manipulated.
    /// @param[in]  mem_line               Entry index to write to.
    /// @param[in]  in_bv                  Data bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  Entry index is out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status write_memory(const lld_memory_scptr& mem, size_t mem_line, const bit_vector& in_bv) = 0;

    /// @brief Write data to memory.
    ///
    /// @param[in]  mem                    Memory to be manipulated.
    /// @param[in]  mem_first_entry        Entry index to start write to.
    /// @param[in]  count                  Number of entries to write.
    /// @param[in]  in_val_sz              Data buffer size.
    /// @param[in]  in_val                 Data buffer.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  First entry index or count out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status write_memory(const lld_memory& mem,
                                   size_t mem_first_entry,
                                   size_t count,
                                   size_t in_val_sz,
                                   const void* in_val)
        = 0;
#endif

    /// @brief Write a fixed value to all memory entries in range.
    ///
    /// @param[in]  mem                    Memory to be manipulated.
    /// @param[in]  mem_first_entry        Entry index to write to.
    /// @param[in]  count                  umber of entries to write.
    /// @param[in]  in_bv                  The value to fill with.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EINVAL       One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE  First entry index or count out of range.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status fill_memory(const lld_memory& mem, size_t mem_first_entry, size_t count, const bit_vector& in_bv) = 0;

    /// @brief Raw data write to memory.
    ///
    /// @param[in]  block_id               Block ID of the memory.
    /// @param[in]  addr                   Memory address in the block.
    /// @param[in]  width_bits             Width of the memory in bits.
    /// @param[in]  in_bv                  Input bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status write_memory_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, const bit_vector& in_bv)
        = 0;

    /// @brief Update a subfield of a single memory line in a memory instance.
    ///
    /// @param[in]  mem                 Memory to be manipulated.
    /// @param[in]  mem_line            Line index to manipulate.
    /// @param[in]  msb                 Subfield's MSB index.
    /// @param[in]  lsb                 Subfield's LSB index.
    /// @param[in]  value               Value to update.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_modify_write_memory(const lld_memory& mem,
                                               size_t mem_line,
                                               size_t msb,
                                               size_t lsb,
                                               const bit_vector& value)
        = 0;

    /// @brief Refresh a non-volatile memory by writing a shadowed value back to HW.
    ///
    /// @param[in]  mem                   Memory to be manipulated.
    /// @param[in]  line                  Memory line.
    ///
    /// @retval     LA_STATUS_SUCCESS     Command completed successfully.
    /// @retval     LA_STATUS_EINVAL      One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE Line index is out of range.
    virtual la_status refresh_memory(const lld_memory& mem, size_t line) = 0;

    /// @brief Wait for value to become equal / not equal.
    ///
    /// @note This operation is only allowed for a volatile resource.
    ///
    /// @param[in]  mem                   Memory to be manipulated.
    /// @param[in]  line                  Memory line.
    /// @param[in]  equal                 Wait for value to become equal or not.
    /// @param[in]  val                   Value to compare with.
    /// @param[in]  mask                  Comparison mask.
    ///
    /// @retval     LA_STATUS_SUCCESS     Command completed successfully.
    /// @retval     LA_STATUS_EINVAL      One of the parameters is invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE Line index is out of range.
    virtual la_status wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask) = 0;

    /// @}
    /// @name TCAM access API-s
    /// @{
    /// @brief Read TCAM entry.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              TCAM line to access.
    /// @param[out] out_key_bv             Return bit_vector for key.
    /// @param[out] out_mask_bv            Return bit_vector for mask.
    /// @param[in]  out_valid              Return valid bit.
    ///
    /// @retval     LA_STATUS_SUCCESS       Command completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status read_tcam(lld_memory const& tcam,
                                size_t tcam_line,
                                bit_vector& out_key_bv,
                                bit_vector& out_mask_bv,
                                bool& out_valid)
        = 0;

#ifndef SWIG
    /// @brief Read TCAM entry.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              TCAM line to access.
    /// @param[in]  key_mask_sz            Size of key and mask buffers (must be same sizes).
    /// @param[out] out_key                Return buffer for key.
    /// @param[out] out_mask               Return buffer for mask.
    /// @param[in]  out_valid              Return valid bit.
    ///
    /// @retval     LA_STATUS_SUCCESS       Command completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status read_tcam(lld_memory const& tcam,
                                size_t tcam_line,
                                size_t key_mask_sz,
                                void*& out_key,
                                void*& out_mask,
                                bool& out_valid)
        = 0;
#endif

    /// @brief Write TCAM entry and make it valid.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              TCAM line to access.
    /// @param[out] in_key_bv              Key bit_vector.
    /// @param[out] in_mask_bv             Mask bit_vector.
    ///
    /// @retval     LA_STATUS_SUCCESS       Command completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status write_tcam(const lld_memory& tcam,
                                 size_t tcam_line,
                                 const bit_vector& in_key_bv,
                                 const bit_vector& in_mask_bv)
        = 0;

#ifndef SWIG
    /// @brief Write TCAM entry and make it valid.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              TCAM line to access.
    /// @param[in]  key_mask_sz            Size of key and mask buffers (must be same sizes).
    /// @param[out] in_key                 Key buffer.
    /// @param[out] in_mask                Mask buffer.
    ///
    /// @retval     LA_STATUS_SUCCESS       Command completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status write_tcam(const lld_memory& tcam,
                                 size_t tcam_line,
                                 size_t key_mask_sz,
                                 const void* in_key,
                                 const void* in_mask)
        = 0;
#endif

    /// @brief Invalidate TCAM entry.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              The line number in the TCAM to access.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status invalidate_tcam(const lld_memory& tcam, size_t tcam_line) = 0;

/// @}
/// @name Miscalenious
/// @{
#ifndef SWIG

    /// @brief Serialize transaction actions to HW.
    ///
    /// @param[in] ad   Vector of HW access descriptors.
    ///
    /// @return     LA_STATUS_SUCCESS   Command completed successfully.
    /// @return     LA_STATUS_ENODEV    Device is not present.
    virtual la_status access(vector_alloc<access_desc> ad) = 0;

    /// @brief Create access descriptor for reading from a HW register.
    ///
    /// @param[in]  reg     Register to read from.
    /// @param[in]  peek    Peek at value without performing side-effects.
    /// @param[out] out_bv  Output data bit_vector.
    //
    /// @return     HW access descriptor.
    virtual access_desc make_read_register(const lld_register& reg, bool peek, bit_vector& out_bv) = 0;

    /// @brief Create access descriptor for writing to a HW register.
    ///
    /// @param[in]  reg     Register to write to.
    /// @param[in]  in_val  Input value.
    //
    /// @return     HW access descriptor.
    virtual access_desc make_write_register(const lld_register& reg, const bit_vector& in_val) = 0;

    /// @brief Create access descriptor for writing to a HW registers.
    ///
    /// @param[in]  reg     Register array to write to.
    /// @param[in]  first   First register to to write to.
    /// @param[in]  count   Number of registers to write to.
    /// @param[in]  in_val  Input value.
    //
    /// @return     HW access descriptor.
    virtual access_desc make_write_register_array(const lld_register_array_container& reg,
                                                  size_t first,
                                                  size_t count,
                                                  const bit_vector& in_val)
        = 0;

    /// @brief Create access descriptor for read-modify-write operation on HW register.
    ///
    /// @param[in]  reg                 Register to read-modify-write.
    /// @param[in]  msb                 Subfield's MSB index.
    /// @param[in]  lsb                 Subfield's LSB index.
    /// @param[in]  in_bv               Value of the subfield to update.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    //
    /// @return     HW access descriptor.
    virtual access_desc make_read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& in_bv)
        = 0;

    /// @brief Create access descriptor for reading from a HW memory.
    ///
    /// @param[in]  mem         Memory to read from.
    /// @param[in]  first_entry First memory entry to read from.
    /// @param[in]  count       Number of entries to read.
    /// @param[out] out_bv      bit_vector to fill when HW read completes.
    //
    /// @return     HW access descriptor.
    virtual access_desc make_read_memory(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv) = 0;

    /// @brief Create access descriptor for writing to HW memory.
    ///
    /// @param[in]  mem         Memory to write to.
    /// @param[in]  first_entry First memory entry to write to.
    /// @param[in]  count       Number of entries to write.
    /// @param[in]  in_bv       Input value.
    //
    /// @return     HW access descriptor.
    virtual access_desc make_write_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_bv) = 0;

    /// @brief Create access descriptor for read-modify-write operation on HW memory.
    ///
    /// @param[in]  mem                 Memory to read-modify-write.
    /// @param[in]  line                Line index.
    /// @param[in]  msb                 Subfield's MSB index.
    /// @param[in]  lsb                 Subfield's LSB index.
    /// @param[in]  in_bv               Value of the subfield to update.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    //
    /// @return     HW access descriptor.
    virtual access_desc make_read_modify_write_memory(const lld_memory& mem,
                                                      size_t line,
                                                      size_t msb,
                                                      size_t lsb,
                                                      const bit_vector& in_bv)
        = 0;

    /// @brief Create access descriptor for reading from TCAM.
    ///
    /// @param[in]  tcam        TCAM to read from.
    /// @param[in]  tcam_line   TCAM line to read from.
    /// @param[in]  out_key_bv  bit_vector for key to fill when HW read completes.
    /// @param[in]  out_mask_bv bit_vector for mask to fill when HW read completes.
    /// @param[in]  out_valid   valid bit to fill when HW read completes.
    //
    /// @return     HW access descriptor.
    virtual access_desc make_read_tcam(lld_memory const& tcam,
                                       size_t tcam_line,
                                       bit_vector& out_key_bv,
                                       bit_vector& out_mask_bv,
                                       bool& out_valid)
        = 0;

    /// @brief Create access descriptor for writing to TCAM.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              TCAM line to access.
    /// @param[out] in_key_bv              Key bit_vector.
    /// @param[out] in_mask_bv             Mask bit_vector.
    ///
    /// @return     HW access descriptor.
    virtual access_desc make_write_tcam(const lld_memory& tcam,
                                        size_t tcam_line,
                                        const bit_vector& in_key_bv,
                                        const bit_vector& in_mask_bv)
        = 0;

    /// @brief Create access descriptor for invalidating TCAM.
    ///
    /// @param[in]  tcam                   TCAM to access.
    /// @param[in]  tcam_line              TCAM line to access.
    ///
    /// @return     HW access descriptor.
    virtual access_desc make_invalidate_tcam(const lld_memory& tcam, size_t tcam_line) = 0;

    /// @brief Create access descriptor for wait_for_value.
    ///
    /// @param[in]  reg                   Register to be manipulated.
    /// @param[in]  equal                 Wait for value to become equal or not.
    /// @param[in]  val                   Value to compare with.
    /// @param[in]  mask                  Comparison mask.
    ///
    /// @return     HW access descriptor.
    virtual access_desc make_wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask) = 0;

    /// @brief Create access descriptor for wait_for_value.
    ///
    /// @param[in]  mem                   Memory to be manipulated.
    /// @param[in]  line                  Memory line.
    /// @param[in]  equal                 Wait for value to become equal or not.
    /// @param[in]  val                   Value to compare with.
    /// @param[in]  mask                  Comparison mask.
    ///
    /// @return     HW access descriptor.
    virtual access_desc make_wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask) = 0;

    /// @brief Create access descriptor for delay.
    ///
    /// @param[in]  cycles    Delay cycles.
    ///
    /// @return     HW access descriptor.
    virtual access_desc make_delay(uint64_t cycles) = 0;

#endif

    /// @brief Returns true if block ID is available on the chip.
    ///
    /// @param[in]   block_id     Block identifier.
    ///
    /// @return    True if block id is available
    virtual bool is_block_available(la_block_id_t block_id) = 0;

    /// @brief Return the network-interface name for the given slice.
    ///
    /// @param[in]  slice   Slice.
    ///
    /// @return     The network-interface name for the given slice.
    virtual std::string get_network_interface_name(la_slice_id_t slice) const = 0;

    /// @brief Return the network-interface file name for the given slice.
    ///
    /// @param[in]  slice   Slice.
    ///
    /// @return     The network-interface file name for the given slice. An empty string in case the device type is other than PCI.
    virtual std::string get_network_interface_file_name(la_slice_id_t slice) const = 0;

    /// @brief Return the path to the device files.
    ///
    /// @return     The path to the device files.
    virtual std::string get_device_files_path() const = 0;

    /// @brief Check health of device interface.
    ///
    /// @return true if ok, false otherwise.
    virtual bool check_health() = 0;

    /// @brief Check if device is in core reset.
    ///
    /// @param[out] is_reset         Output value. True if core is in reset, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_core_reset(bool& is_reset) = 0;

    /// @brief Check if a block is accessible.
    ///
    /// @retval     true      The block is accessible. This is the default for all blocks
    /// @retval     false     Access to this block was restricted. It has been turned off or disabled.
    virtual bool is_block_allowed(const lld_block_scptr& b) const = 0;

}; // class ll_device

} // namespace silicon_one

#endif // __LEABA_LLD_LA_DEVICE_H__
