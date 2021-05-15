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

#ifndef __LEABA_LLD_LL_DEVICE_IMPL_H__
#define __LEABA_LLD_LL_DEVICE_IMPL_H__

#include <string>

#include "common/la_lock_guard.h"
#include "lld/ll_device.h"
#include "lld/ll_transaction.h"
#include "lld/socket_connection/lld_conn_lib.h"

#include "lld/interrupt_tree.h"
#include "lld/lld_fwd.h"

#include "lld_types_internal.h"

#include "ll_device_context.h"

#include <memory>
#include <mutex>

namespace silicon_one
{
/// @brief Leaba device - general, register and memory interface.
///
/// Enables per-device management, access to registers, memories and memory ranges.

#define start_lld_call_base(ldev, val)                                                                                             \
    const ll_device_impl* dev_##__LINE__ = ldev;                                                                                   \
    la_lock_guard<std::recursive_mutex> lock(dev_##__LINE__->get_lock(), dev_##__LINE__->get_device_id());                         \
    if (!dev_##__LINE__->is_device_accessible()) {                                                                                 \
        return val;                                                                                                                \
    }

#define start_lld_call(ldev) start_lld_call_base(ldev, LA_STATUS_ENODEV)
#define start_bool_lld_call(ldev) start_lld_call_base(ldev, false)
#define start_void_lld_call(ldev) start_lld_call_base(ldev, )

/// @brief Leaba device - SBIF part implementation.
class ll_device_impl : public ll_device
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Internal platform data for I2C access functions.
    struct i2c_data {
        int fd;
        uint16_t slave_addr;
    };

    /// @brief C'tor, the actual initialization of leaba module device is done in init().
    explicit ll_device_impl(la_device_id_t device_id);

    /// @brief Copy c'tor - disallowed.
    ll_device_impl(const ll_device_impl&) = delete;

    /// @brief Destruct leaba module device.
    ~ll_device_impl() override;

    /// @brief Initialize Leaba ll_device_impl to a given device path, and use the device_tree as a reference to the reg/mem tree.
    virtual bool initialize(const char* device_path, device_simulator* sim, const la_platform_cbs& platform_cbs);

    /// @brief Get low-level device's lock
    std::recursive_mutex& get_lock() const
    {
        return m_mutex;
    }

    //-------------------------------------------------------
    // Inherited from ll_device.h
    //-------------------------------------------------------
    const pacific_tree* get_pacific_tree() const override;
    const gibraltar_tree* get_gibraltar_tree() const override;
    const asic4_tree* get_asic4_tree() const override;
    const asic3_tree* get_asic3_tree() const override;
    const asic5_tree* get_asic5_tree() const override;
    pacific_tree_scptr get_pacific_tree_scptr() const override;
    gibraltar_tree_scptr get_gibraltar_tree_scptr() const override;
    asic4_tree_scptr get_asic4_tree_scptr() const override;
    asic3_tree_scptr get_asic3_tree_scptr() const override;
    asic5_tree_scptr get_asic5_tree_scptr() const override;
    lld_block_scptr get_device_tree() const override;
    la_device_family_e get_device_family() const override;
    la_device_revision_e get_device_revision() const override;
    bool is_asic5() const override;
    bool is_asic4() const override;
    bool is_asic3() const override;
    bool is_asic7() const override;
    bool is_gibraltar() const override;
    bool is_pacific() const override;
    std::string get_device_path() const override;
    interrupt_tree* get_interrupt_tree() override;
    interrupt_tree_sptr get_interrupt_tree_sptr() override;
    ll_device_context_sptr get_device_context() override;
    la_status reset() override;
    bool is_valid() const override;
    bool is_simulated_device() const override;
    la_device_id_t get_device_id() const override;
    la_status set_write_burst(bool en) override;
    void set_flush_after_write(bool en) override;
    void set_shadow_read_enabled(bool en) override;
    bool get_shadow_read_enabled() const override;
    void set_write_to_device(bool write_to_device) override;
    bool get_write_to_device() const override;
    la_status reset_access_engines() override;
    la_status reset_access_engines(uint32_t mask) override;
    void set_access_engine_cmd_fifo_enabled(bool en) override;
    bool get_access_engine_cmd_fifo_enabled() const override;
    la_status start_css_arcs() override;
    la_status stop_css_arcs() override;
    la_status reset_css_arcs() override;
    la_status load_css_arc_microcode(const std::string& filename) override;
    la_status set_device_simulator(device_simulator* simulator) override;
    la_status set_device_simulator(device_simulator* simulator, simulation_mode_e mode) override;
    device_simulator* get_device_simulator() const override;
    simulation_mode_e get_device_simulation_mode() const override;
    la_status get_core_reset(bool& is_reset) override;
    // CEM bubble issue workaround
    /// @brief Reduce traffic rate by modifying device's shapers.
    ///
    /// @param[out] out_original_rxpp_values  Original shapers values
    void reduce_traffic(std::vector<bit_vector>& out_original_rxpp_values);

    /// @brief Restore the device's shapers to the original value.
    ///
    /// @param[in] original_rxpp_values    Original shapers values
    void restore_traffic(std::vector<bit_vector> original_rxpp_values);

    void change_traffic_rate(bool traffic_reduce) override;

    /// @brief Read rxpp traffic shaper register.
    ///
    /// @param[in]       ae         Access engine to use.
    /// @param[in]       sid        Read register from slice sid.
    /// @param[out]      bv         Value of rxpp traffic shaper register.
    la_status read_rxpp_traffic_shaper(access_engine* ae, la_slice_id_t sid, bit_vector& out);

    /// @brief Write rxpp traffic shaper register.
    ///
    /// @param[in]       ae         Access engine to use.
    /// @param[in]       sid        Read register from slice sid.
    /// @param[in]       bv         Value of rxpp traffic shaper register
    la_status write_rxpp_traffic_shaper(access_engine* ae, la_slice_id_t sid, const bit_vector& in);

    // Interrupt and PCI event API
    void get_event_fds(int& out_pci_event_fd, int& out_interrupt_fd, size_t& out_interrupt_width_bytes) const override;

    // ISSU API
    la_status post_restore(const char* device_path) override;
    la_status post_restore(const char* device_path, const la_platform_cbs& platform_cbs) override;

    // Registers API
    la_status read_register(const lld_register& reg, bit_vector& out_bv) override;
    la_status read_register(const lld_register_scptr& reg, bit_vector& out_bv) override;
    la_status peek_register(const lld_register& reg, bit_vector& out_bv) override;
    la_status peek_register(const lld_register_scptr& reg, bit_vector& out_bv) override;
    la_status read_register(const lld_register& reg, size_t out_val_sz, void* out_val) override;
    la_status peek_register(const lld_register& reg, size_t out_val_sz, void* out_val) override;
    la_status read_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv) override;
    la_status peek_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv) override;

    la_status write_register(const lld_register& reg, const bit_vector& in_bv) override;
    la_status write_register(const lld_register_scptr& reg, const bit_vector& in_bv) override;
    la_status write_register(const lld_register& reg, size_t in_val_sz, const void* in_val) override;
    la_status write_register_array(const lld_register_array_container& reg,
                                   size_t first,
                                   size_t count,
                                   const bit_vector& in_bv) override;
    la_status write_register_raw(la_block_id_t block_id,
                                 la_entry_addr_t addr,
                                 uint32_t width_bits,
                                 const bit_vector& in_bv) override;

    la_status read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& value) override;
    la_status wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask) override;
    la_status delay(uint64_t cycles) override;

    la_status do_write_register(access_engine* ae, const lld_register* reg, const bit_vector& in_val);
    la_status do_read_register(access_engine* ae, const lld_register* reg, bool peek, bit_vector* out_val);
    la_status do_write_register_array(access_engine* ae,
                                      const lld_register_array_container* reg,
                                      const bit_vector& in_val,
                                      size_t first,
                                      size_t count);

    // Memory API
    la_status read_memory(const lld_memory& mem, size_t line, bit_vector& out_bv) override;
    la_status read_memory(const lld_memory_scptr& mem, size_t line, bit_vector& out_bv) override;
    la_status read_memory(const lld_memory& mem, size_t first_line, size_t count, size_t out_val_sz, void* out_val) override;
    la_status read_memory(const lld_memory& mem, size_t first_line, size_t count, bit_vector& out_bv) override;
    la_status read_memory_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv) override;

    la_status write_memory(const lld_memory& mem, size_t line, const bit_vector& in_bv) override;
    la_status write_memory(const lld_memory_scptr& mem, size_t line, const bit_vector& in_bv) override;
    la_status write_memory(const lld_memory& mem, size_t first_line, size_t count, size_t in_val_sz, const void* in_val) override;
    la_status fill_memory(const lld_memory& mem, size_t mem_first_entry, size_t count, const bit_vector& in_bv) override;
    la_status write_memory_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, const bit_vector& in_bv) override;

    la_status read_modify_write_memory(const lld_memory& mem,
                                       size_t line,
                                       size_t msb,
                                       size_t lsb,
                                       const bit_vector& value) override;

    la_status refresh_memory(const lld_memory& mem, size_t line) override;

    la_status wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask) override;

    // TCAM API
    la_status read_tcam(lld_memory const& tcam,
                        size_t tcam_line,
                        bit_vector& out_key_bv,
                        bit_vector& out_mask_bv,
                        bool& out_valid) override;
    la_status read_tcam(lld_memory const& tcam,
                        size_t tcam_line,
                        size_t key_mask_sz,
                        void*& out_key,
                        void*& out_mask,
                        bool& out_valid) override;

    la_status write_tcam(const lld_memory& tcam,
                         size_t tcam_line,
                         const bit_vector& in_key_bv,
                         const bit_vector& in_mask_bv) override;
    la_status write_tcam(const lld_memory& tcam,
                         size_t tcam_line,
                         size_t key_mask_sz,
                         const void* in_key,
                         const void* in_mask) override;

    la_status invalidate_tcam(const lld_memory& tcam, size_t tcam_line) override;

    // Transaction API - create HW access descriptors
    access_desc make_read_register(const lld_register& reg, bool peek, bit_vector& out_bv) override;
    access_desc make_write_register(const lld_register& reg, const bit_vector& in_val) override;
    access_desc make_write_register_array(const lld_register_array_container& reg,
                                          size_t first,
                                          size_t count,
                                          const bit_vector& in_bv) override;
    access_desc make_read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& in_val) override;

    access_desc make_read_memory(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv) override;
    access_desc make_write_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_val) override;
    access_desc make_read_modify_write_memory(const lld_memory& mem,
                                              size_t line,
                                              size_t msb,
                                              size_t lsb,
                                              const bit_vector& in_val) override;
    access_desc make_read_tcam(lld_memory const& tcam,
                               size_t tcam_line,
                               bit_vector& out_key_bv,
                               bit_vector& out_mask_bv,
                               bool& out_valid) override;
    access_desc make_write_tcam(const lld_memory& tcam,
                                size_t tcam_line,
                                const bit_vector& in_key_bv,
                                const bit_vector& in_mask_bv) override;
    access_desc make_invalidate_tcam(const lld_memory& tcam, size_t tcam_line) override;
    access_desc make_wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask) override;
    access_desc make_wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask) override;
    access_desc make_delay(uint64_t cycles) override;

    bool is_block_available(la_block_id_t block_id) override;

    // Network interface utilities
    std::string get_network_interface_name(la_slice_id_t slice) const override;
    std::string get_network_interface_file_name(la_slice_id_t slice) const override;

    /// @brief Return path to sysfs folder where device files are located.
    std::string get_device_files_path() const override;

    /// @brief Read SBIF memory value from a specific memory on the device.
    ///
    /// @param[in]  addr            Base address of the memory region
    /// @param[in]  entry           Memory entry
    /// @param[out] val             Output value
    /// @return                     Status code
    la_status sbif_read_memory(la_entry_addr_t addr, size_t entry, uint32_t* val) const;

    /// @brief Read an array of values from SBIF memory.
    ///
    /// @param[in]  mem_addr        Base address of the memory region.
    /// @param[in]  first_entry     First memory entry.
    /// @param[in]  count           Number of memory entries.
    /// @param[out] val             Array of value.
    /// @return                     Status code.
    la_status sbif_read_memory_entries(la_entry_addr_t addr, size_t first_entry, size_t count, uint32_t* val) const;

    /// @brief Write SBIF memory value for a specific memory on the device.
    ///
    /// @param[in]  addr            Base address of the memory region
    /// @param[in]  entry           Memory entry
    /// @param[in]  val             Value to set.
    /// @return                     Status code
    la_status sbif_write_memory(la_entry_addr_t addr, size_t entry, uint32_t val);

    /// @brief Write an array of values to SBIF memory.
    ///
    /// @param[in]  addr            Base address of the memory region
    /// @param[in]  first_entry     First memory entry
    /// @param[in]  count           Number of values.
    /// @param[in]  val             Array of value.
    /// @return                     Status code.
    la_status sbif_write_memory_entries(la_entry_addr_t addr, size_t first_entry, size_t count, const uint32_t* val);

    /// @brief Read SBIF register value from a specific address of the device.
    ///
    /// @param[in]  addr            Address of the register to be queried
    /// @param[out] out_val         Value read from the register
    /// @return                     Status code
    la_status sbif_read_register(la_entry_addr_t addr, uint32_t* val) const;

    /// @brief Set SBIF register value at a specific address of the device.
    ///
    /// @param[in]  addr            Address of the register to be manipulated
    /// @param[in]  val             Value to set.
    /// @return                     Status code
    la_status sbif_write_register(la_entry_addr_t addr, uint32_t val);

    /// @brief Wait for value on SBIF register to become equal / not equal.
    ///
    /// @param[in]  addr            Address of the register to be manipulated
    /// @param[in]  equal           Wait for value to become equal or not.
    /// @param[in]  poll_cnt        Number of times to poll for the value.
    /// @param[in]  val             Value to compare with.
    /// @param[in]  mask            Comparison mask.
    /// @return                     Status code
    la_status sbif_wait_for_value(la_entry_addr_t addr, bool equal, uint8_t poll_cnt, uint16_t val, uint16_t mask);

    /// @brief Serialize transaction actions to HW.
    ///
    /// @param[in] ad   Vector of HW access descriptors.
    ///
    /// @return     LA_STATUS_SUCCESS   Command completed successfully.
    /// @return     LA_STATUS_ENODEV    Device is not present.
    la_status access(vector_alloc<access_desc> ad) override;

    /// @brief Reserve Access engine.
    ///
    /// @retval     Pointer to a valid access engine or nullptr if none available.
    access_engine_uptr reserve_access_engine(void);

    /// @brief Release Access engine.
    ///
    /// @param[in]  ae Engine to release.
    void release_access_engine(access_engine_uptr ae);

    /// @brief Check health of interface.
    ///
    /// @return true if ok, false otherwise.
    bool check_health() override;

    /// @brief Device is accessible only if previous status of transaction actions to HW was not LA_STATUS_ENODEV.
    ///
    /// @return true if ok, false otherwise.
    bool is_device_accessible() const
    {
        return m_device_accessible;
    }

    virtual bool is_block_allowed(const lld_block_scptr& b) const override;

protected:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    ll_device_impl() = default;

    lld_block_scptr get_block(la_block_id_t block_id);

private:
    ll_device_context_sptr m_device_context;
    std::shared_ptr<interrupt_tree> m_interrupt_tree; // Device interrupt tree

    device_simulator* m_simulator;        // Device simulator
    la_block_id_t m_sbif_block_id;        // SBIF block id
    la_block_id_t m_top_regfile_block_id; // Gibraltar top regfile

    mutable std::recursive_mutex m_mutex; ///< LLD recursive lock, synchronizes low-level access

    std::vector<bit_vector> m_rxpp_values; // used to save original expp values for CEM bubble WA

    /// @brief Device interface - the interface used to connect to the device.
    enum device_interface_e {
        DEVICE_INTERFACE_UNKNOWN = 0, ///< Unknown interface
        DEVICE_INTERFACE_PCI = 1,     ///< PCI interface
        DEVICE_INTERFACE_SPI = 2,     ///< SPI interface
        DEVICE_INTERFACE_I2C = 3,     ///< I2C interface
        DEVICE_INTERFACE_TEST = 4,    ///< TEST interface (used for SW testing)
    };

    enum leaba_spi_cmd_e {
        LEABA_SPI_CMD_IDLE = 0,
        LEABA_SPI_CMD_READ = 1,
        LEABA_SPI_CMD_WRITE = 3,
    };

    enum leaba_spi_result_e {
        LEABA_SPI_RESULT_SUCCESS = 0,
    };

    enum leaba_mmap_size_e {
        LEABA_PCI_BAR_SZ = (1 << 25), // 32MB - min size for PCI BAR on Pacific/Gibraltar/Asic4.
    };

    struct mmap_info {
        size_t size;        ///< Size of the map
        uint64_t phys_addr; ///< Physical memory address
        union addr_union_s {
            void* raw;
            uint32_t* u32;
            uint64_t* u64;
        } addr;       ///< Memory map
        off_t offset; ///< Offset in the file
    };

    // I2C constants
    enum {
        LLD_DEFAULT_I2C_SLAVE_ID = 42,
    };

    mmap_info m_pci_bar_map_info;
    mmap_info m_dma_map_info;
    la_dma_desc m_dma_desc;

    std::string m_device_path;              // device filename for UIO, SPI or I2C (e.g. /dev/uio0)
                                            // or URI for socket interface (e.g. ip:localhost:7474)
    device_interface_e m_dev_type;          // device interface type
    la_device_revision_e m_device_revision; // device revision
    la_device_id_t m_device_id;             // device id this lld is attached to

    int m_fd;                       // File descriptor for UIO mmap or SPI or I2C
    int m_pci_event_fd;             // File descriptor for PCI events - hotplug and AER
    int m_interrupt_fd;             // File descriptor for listening to interrupts from UIO or a simulator
    size_t m_interrupt_width_bytes; // Width of value to read from interrupt file descriptor

    // Pool of available (idle) access engines.
    // reserve_access_engine() removes an engine form the list.
    // release_access_engine() puts an engine back into the list.
    //
    // Storage: C-like singly linked list.
    std::vector<access_engine_uptr> m_ae;

    // List of reserved access engines (not to be used by SDK).
    // Access engine 1 reserved for ARC
    std::set<uint16_t> reserved_engines = {0, 1, 6};

    // List of ARC CPUs
    std::vector<arc_cpu_uptr> m_arc_cpu;

    // Default transaction, used with dev::read/write API
    std::unique_ptr<ll_transaction> m_default_tr;

    simulation_mode_e m_simulation_mode;
    bool m_flush_after_write;
    bool m_non_volatile_read_from_device;
    bool m_write_to_device;
    bool m_access_engine_cmd_fifo_enabled;

    i2c_data m_i2c_data;
    // Internal representation of la_platform_cbs
    struct m_platform_cbs_s {
        uintptr_t i2c_user_data;
        la_i2c_register_access_cb i2c_register_access;

        uintptr_t dma_user_data;
        la_dma_alloc_cb dma_alloc;
        la_dma_free_cb dma_free;

        uintptr_t open_close_user_data;
        la_open_device_cb open_device;
        la_close_device_cb close_device;
    } m_platform_cbs;

    // UIO index
    int m_uio_dev_id;

    // Previous status of transaction actions to HW
    bool m_device_accessible;

    /// @brief Initialize device interfaces (UIO/SPI/...).
    bool initialize_device_interfaces(const char* device_path, const la_platform_cbs& platform_cbs);

    /// @brief Init access engines.
    void init_access_engines();

    /// @brief Init ARC CPUs.
    void init_arc_cpus();

    /// @brief Init device connection, PCI specific.
    ///
    /// @return true on success, false otherwise.
    bool init_pci();

    /// @brief Init DMA for PCI interface.
    ///
    /// @return true on success, false otherwise.
    bool init_pci_dma();

    /// @brief Init device connection, I2C specific.
    ///
    /// @return true on success, false otherwise.
    bool init_i2c();

    /// @brief Init device connection, SPI specific.
    ///
    /// @return true on success, false otherwise.
    bool init_spi();

    /// @brief Init device connection, TESTDEV specific.
    ///
    /// @return true on success, false otherwise.
    bool init_testdev();

    /// @brief Map UIO memory resource.
    ///
    /// @param[in]  map_i       Index of UIO map
    /// @param[in]  min_sz      Map at least this size
    /// @param[out] mi          mmap info
    ///
    /// @return true on success, false otherwise.
    bool uio_mmap(int map_i, size_t min_sz, mmap_info& mi);

    /// @brief Unmap UIO memory resource.
    ///
    /// @return true on success, false otherwise.
    void uio_munmap(const mmap_info& mi);

    /// @brief Discover device revision.
    ///
    /// @return Device revision.
    la_device_revision_e discover_device_revision();

    /// @brief Discover device revision through SBIF device_id_status register.
    ///
    /// @note Pacific only.
    ///
    /// @return Device revision.
    la_device_revision_e sbif_discover_pacific_revision();

    /// @brief Discover device revision through TOP chip_id register.
    ///
    /// @param[in] family   Device family.
    ///
    /// @return Device revision.
    la_device_revision_e topreg_discover_device_revision(la_device_family_e family);

    /// @brief Discover device revision from ASIC environment variable.
    ///
    /// @param[in] asic   Value of ASIC environment variable.
    ///
    /// @return Device revision.
    la_device_revision_e envvar_discover_device_revision(std::string asic);

    /// @brief Insert line to TCAM shadow with spicific valid bit
    ///
    /// @param[in] tcam                  TCAM to access.
    /// @param[in] tcam_phys_line        TCAM line to access.
    /// @param[in] tcam_line_bv          Phys TCAM line bv
    /// @param[in] valid_bit             Shadow valid bit to set
    void set_tcam_shadow_valid_bit(const lld_memory& tcam, size_t tcam_phys_line, bit_vector tcam_line_bv, bool out_valid);

    // sysfs
    std::string get_uio_sysfs_path() const;
    uint64_t read_uio_sysfs_u64(std::string attr_name);

    // HW-only access (w/o shadow)
    la_status do_read_register_raw(access_engine* ae,
                                   la_block_id_t block_id,
                                   la_entry_addr_t addr,
                                   la_entry_width_t width,
                                   size_t count,
                                   bool peek,
                                   void* out_val);
    la_status do_write_register_raw(access_engine* ae,
                                    la_block_id_t block_id,
                                    la_entry_addr_t addr,
                                    la_entry_width_t width,
                                    size_t count,
                                    const uint8_t* in_val);

    la_status do_wait_for_value(access_engine* ae,
                                la_block_id_t block_id,
                                la_entry_addr_t addr,
                                bool equal,
                                uint8_t poll_cnt,
                                uint16_t val,
                                uint16_t mask);

    la_status do_read_memory_raw(access_engine* ae,
                                 la_block_id_t block_id,
                                 la_entry_addr_t addr,
                                 la_entry_addr_t first_entry,
                                 la_entry_width_t width,
                                 size_t count,
                                 void* out_val);
    la_status do_read_ae(access_engine* ae,
                         la_block_id_t block_id,
                         la_entry_addr_t addr,
                         la_entry_width_t width,
                         size_t count,
                         bool peek,
                         void* out_val);
    la_status do_write_memory_raw(access_engine* ae,
                                  la_block_id_t block_id,
                                  la_entry_addr_t addr,
                                  la_entry_addr_t first_entry,
                                  la_entry_width_t width,
                                  size_t count,
                                  const uint8_t* in_val);
    la_status do_fill_memory(la_block_id_t block_id,
                             la_entry_addr_t addr,
                             la_entry_width_t width,
                             size_t count,
                             const bit_vector& in_bv);

    la_status do_read_xy_tcam(lld_memory const& tcam,
                              size_t tcam_line,
                              bit_vector& out_key_bv,
                              bit_vector& out_mask_bv,
                              bool& out_valid);
    la_status do_read_key_mask_tcam(lld_memory const& tcam,
                                    size_t tcam_line,
                                    bit_vector& out_key_bv,
                                    bit_vector& out_mask_bv,
                                    bool& out_valid);
    la_status do_read_reg_tcam(const lld_memory& tcam, size_t tcam_line, bit_vector& key, bit_vector& mask, bool& out_valid);

    access_desc make_write_xy_tcam(const lld_memory& tcam,
                                   size_t tcam_line,
                                   const bit_vector& in_key_bv,
                                   const bit_vector& in_mask_bv);
    access_desc make_write_key_mask_tcam(const lld_memory& tcam,
                                         size_t tcam_line,
                                         const bit_vector& in_key_bv,
                                         const bit_vector& in_mask_bv);
    access_desc make_write_reg_tcam(const lld_memory& tcam, size_t tcam_line, const bit_vector& key, const bit_vector& mask);
    access_desc make_invalidate_xy_tcam(const lld_memory& tcam, size_t tcam_line);
    access_desc make_invalidate_key_mask_tcam(const lld_memory& tcam, size_t tcam_line);
    access_desc make_invalidate_reg_tcam(const lld_memory& tcam, size_t tcam_line);

    std::string get_memory_name(la_block_id_t block_id, la_entry_addr_t addr);
    std::string get_register_name(la_block_id_t block_id, la_entry_addr_t addr);

    // Implementation helper functions
    la_status do_write_memory(access_engine* ae,
                              const lld_memory* mem,
                              la_entry_addr_t line,
                              size_t count,
                              const bit_vector& in_val);
    la_status do_read_memory(access_engine* ae, const lld_memory* mem, la_entry_addr_t line, size_t count, bit_vector* out_val);
    la_status do_read_modify_write_register(access_engine* ae,
                                            const lld_register* reg,
                                            size_t msb,
                                            size_t lsb,
                                            const bit_vector& in_val);

    la_status do_read_modify_write_memory(access_engine* ae,
                                          const lld_memory* mem,
                                          size_t line,
                                          size_t msb,
                                          size_t lsb,
                                          const bit_vector& in_val);

    la_status do_write_top_regfile(la_device_family_e family, la_entry_addr_t addr, uint32_t in_val);
    la_status do_read_top_regfile(la_device_family_e family, la_entry_addr_t addr, uint32_t* out_val);
    la_uint_t get_num_of_css_arcs();

    /// @brief Get ll_device_impl shared_ptr for this object.
    ll_device_impl_sptr sptr();

    /// @brief Sanity checks performed after interfaces (PCI/I2C/SPI/...) are brought up in restore mode.
    la_status post_restore_interfaces_sanity_checks();
};
}

#endif // __LEABA_LLD_LL_DEVICE_IMPL_H__
