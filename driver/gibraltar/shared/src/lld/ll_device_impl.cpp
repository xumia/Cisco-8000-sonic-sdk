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

#include "ll_device_impl.h"
#include "access_engine.h"
#include "api/system/la_css_memory_layout.h"
#include "arc_cpu.h"
#include "common/bit_utils.h"
#include "common/common_strings.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "lld_types_internal.h"

#include "ll_device_context.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/leaba_kernel_types.h"
#include "lld/lld_utils.h"

#include <arpa/inet.h>
#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <linux/spi/spidev.h>
#include <linux/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <string>
#include <thread>

using namespace std;
#include <sstream>
using namespace silicon_one;

enum { LINE_SIZE = 256 };
enum {
    NUM_SLICES_PER_DEVICE_WALKAROUND = 6,
    NUM_IFGS_PER_SLICE = 2,
    ACCESS_ENGINE_RESET_SLEEP_USEC = 10,
};

static constexpr auto HARD_RESET_DELAY = chrono::milliseconds(10);
static constexpr auto POST_HARD_RESET_DELAY = chrono::milliseconds(10);
static constexpr auto ACCESS_ENGINE_RESET_DELAY = chrono::microseconds(10);
static constexpr auto ARC_CPU_RESET_DELAY = chrono::microseconds(10);
static constexpr auto TOPREG_READ_DELAY = chrono::microseconds(10);

bool writeBurstMode = false;

static bool
is_matching_device_revision(ll_device* ldev, const lld_storage& storage)
{
    bool match
        = ((IS_SIM_BLOCK_ID(storage.get_block_id())) || (storage.get_block()->get_revision() == ldev->get_device_revision()));

    return match;
}

string
ll_device_impl::get_register_name(la_block_id_t block_id, la_entry_addr_t addr)
{
    lld_block_scptr block = get_block(block_id);
    lld_register_scptr reg = block ? block->get_register(addr) : nullptr;

    return reg ? reg->get_name() : "unknown";
}

string
ll_device_impl::get_memory_name(la_block_id_t block_id, la_entry_addr_t addr)
{
    lld_block_scptr block = get_block(block_id);
    lld_memory_scptr mem = block ? block->get_memory(addr) : nullptr;

    return mem ? mem->get_name() : "unknown";
}

static void
i2c_log(const struct i2c_rdwr_ioctl_data* ioctl_data)
{
    if (logger::instance().is_logging_nodev(la_logger_component_e::LLD, la_logger_level_e::DEBUG)) {
        char log_str[1024];
        char* lp = log_str;
        size_t off, remaining = sizeof(log_str);

        off = snprintf(lp, remaining, "ioctl(I2C_RDRW) data: nmsgs %d, ", ioctl_data->nmsgs);
        remaining -= off;
        lp += off;

        for (uint32_t i = 0; i < ioctl_data->nmsgs; i++) {
            struct i2c_msg* msg = &ioctl_data->msgs[i];
            off = snprintf(lp, remaining, "msgs[%d]: [addr=%04x, flags=%04x, len=%u, buf=", i, msg->addr, msg->flags, msg->len);
            remaining -= off;
            lp += off;

            for (uint16_t j = 0; j < msg->len; j++) {
                off = snprintf(lp, remaining, "%02x ", msg->buf[j]);
                remaining -= off;
                lp += off;
            }

            off = snprintf(lp, remaining, "], ");
            remaining -= off;
            lp += off;
        }

        log_debug(LLD, "%s: %s", __func__, log_str);
    }
}

la_status
i2c_write_register(int fd, uint16_t slave_addr, la_entry_addr_t addr, uint32_t val)
{
    static_assert(sizeof(addr) == sizeof(uint32_t), "Unexpected addr size");
    uint32_t swapped_addr = bswap_32(addr);
    uint32_t swapped_val = bswap_32(val);
    uint32_t msg_buf[2] = {swapped_addr, swapped_val};

    struct i2c_msg msg = {
        .addr = slave_addr, .flags = 0, .len = sizeof(msg_buf), .buf = (uint8_t*)&msg_buf[0],
    };

    struct i2c_rdwr_ioctl_data ioctl_data = {
        .msgs = &msg, .nmsgs = 1,
    };

    i2c_log(&ioctl_data);

    int ret = ioctl(fd, I2C_RDWR, &ioctl_data);
    if (ret < 0) {
        log_err(LLD, "ioctl(I2C_RDRW) failed - %d (%s)", errno, strerror(errno));
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

static la_status
i2c_read_register(int fd, uint16_t slave_addr, la_entry_addr_t addr, uint32_t* out_val)
{
    static_assert(sizeof(addr) == sizeof(uint32_t), "Unexpected addr size");

    uint32_t swapped_addr = bswap_32(addr);
    uint32_t swapped_val = bswap_32(0xdeadbeaf);

    struct i2c_msg msgs[2];

    /*addr_msg*/
    msgs[0].addr = slave_addr;
    msgs[0].flags = 0;
    msgs[0].len = sizeof(addr);
    msgs[0].buf = (uint8_t*)&swapped_addr;

    /*data_msg*/
    msgs[1].addr = slave_addr;
    msgs[1].flags = I2C_M_RD;
    msgs[1].len = sizeof(swapped_val);
    msgs[1].buf = (uint8_t*)&swapped_val;

    struct i2c_rdwr_ioctl_data ioctl_data = {
        .msgs = msgs, .nmsgs = array_size(msgs),
    };

    int ret = ioctl(fd, I2C_RDWR, &ioctl_data);
    if (ret < 0) {
        log_err(LLD, "ioctl(I2C_RDRW) failed - %d (%s)", errno, strerror(errno));
        return LA_STATUS_EUNKNOWN;
    }

    *out_val = bswap_32(swapped_val);

    i2c_log(&ioctl_data);
    log_debug(LLD, "ioctl(I2C_RDRW) read val=0x%08x", *out_val);

    return LA_STATUS_SUCCESS;
}

static la_status
i2c_register_access(uintptr_t user_data, bool is_read, la_entry_addr_t addr, uint32_t* val)
{
    const ll_device_impl::i2c_data* ud = reinterpret_cast<const ll_device_impl::i2c_data*>(user_data);

    if (is_read) {
        return i2c_read_register(ud->fd, ud->slave_addr, addr, val);
    }

    return i2c_write_register(ud->fd, ud->slave_addr, addr, *val);
}

//------------------------------------------------------------------------------
// Internal helper functions
//------------------------------------------------------------------------------
ll_device_impl::ll_device_impl(la_device_id_t device_id)
    : m_simulator(nullptr),
      m_sbif_block_id(LA_BLOCK_ID_INVALID),
      m_top_regfile_block_id(LA_BLOCK_ID_INVALID),
      m_dev_type(DEVICE_INTERFACE_UNKNOWN),
      m_device_id(device_id),
      m_fd(-1),
      m_pci_event_fd(-1),
      m_interrupt_fd(-1),
      m_interrupt_width_bytes(0),
      m_ae(0),
      m_default_tr(nullptr),
      m_simulation_mode(simulation_mode_e::NONE),
      m_flush_after_write(false),
      m_non_volatile_read_from_device(false),
      m_write_to_device(true),
      m_access_engine_cmd_fifo_enabled(true),
      m_platform_cbs{.i2c_user_data = 0,
                     .i2c_register_access = nullptr,
                     .dma_user_data = 0,
                     .dma_alloc = nullptr,
                     .dma_free = nullptr,
                     .open_close_user_data = 0,
                     .open_device = nullptr,
                     .close_device = nullptr},
      m_uio_dev_id(-1),
      m_device_accessible(true)
{
    m_pci_bar_map_info.addr.raw = nullptr;
    m_dma_map_info.addr.raw = nullptr;
    m_dma_desc.virt_addr = nullptr;
    m_device_context = std::make_shared<ll_device_context>(device_id);
}

bool
ll_device_impl::initialize(const char* device_path, device_simulator* sim, const la_platform_cbs& platform_cbs)
{
    start_bool_lld_call(this);

    m_simulator = sim;

    bool success = initialize_device_interfaces(device_path, platform_cbs);
    if (!success) {
        return false;
    }

    if (m_dev_type != DEVICE_INTERFACE_TEST && sim) {
        log_err(LLD, "%s: device simulator can only be provided for a testdev", __func__);
        return false;
    }

    m_device_revision = discover_device_revision();
    if (m_device_revision == la_device_revision_e::NONE) {
        return false;
    }

    log_debug(LLD, "%s: device revision=%d", __func__, (int)m_device_revision);

    m_device_context->initialize(m_device_revision);

    if (m_simulator) {
        m_simulator->set_pacific_tree(get_pacific_tree());
        m_simulator->set_gibraltar_tree(get_gibraltar_tree());
        m_simulator->set_asic4_tree(get_asic4_tree());
        m_simulator->set_asic3_tree(get_asic3_tree());
        m_simulator->set_asic5_tree(get_asic5_tree());
    }

    m_sbif_block_id = m_device_context->m_sbif_block_id;
    m_top_regfile_block_id = m_device_context->m_top_regfile_block_id;

    m_default_tr = silicon_one::make_unique<ll_transaction>(sptr());

    init_access_engines();

    init_arc_cpus();

    m_interrupt_tree = make_shared<interrupt_tree>(sptr());

    la_status rc = m_interrupt_tree->initialize();
    if (rc) {
        return false;
    }

    bool ok = check_health();
    log_debug(LLD, "%s: check_health %s", __func__, ok ? "ok" : "error");

    return ok;
}

la_uint_t
ll_device_impl::get_num_of_css_arcs()
{
    return m_device_context->get_num_of_css_arcs();
}

la_status
ll_device_impl::start_css_arcs()
{
    start_lld_call(this);
    log_debug(LLD, "%s: Start all ARCs", __func__);

    la_status status;

    la_uint_t num_of_css_arcs = get_num_of_css_arcs();

    for (la_uint_t ix = 0; ix < num_of_css_arcs; ix++) {
        status = m_arc_cpu[ix]->go();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::stop_css_arcs()
{
    start_lld_call(this);
    log_debug(LLD, "%s: Stop all ARCs", __func__);
    la_status status;

    la_uint_t num_of_css_arcs = get_num_of_css_arcs();

    for (la_uint_t ix = 0; ix < num_of_css_arcs; ix++) {
        status = m_arc_cpu[ix]->halt();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::reset_css_arcs()
{
    start_lld_call(this);
    log_debug(LLD, "%s: Reset all ARCs", __func__);
    la_status status;

    la_uint_t num_of_css_arcs = get_num_of_css_arcs();

    for (la_uint_t ix = 0; ix < num_of_css_arcs; ix++) {
        status = m_arc_cpu[ix]->reset();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::load_css_arc_microcode(const string& filename)
{
    start_lld_call(this);
    log_debug(LLD, "%s: Loading ARC microcode", __func__);

    // Check that the file exists
    struct stat file_stat;
    int rc = stat(filename.c_str(), &file_stat);
    if (rc) {
        log_err(LLD, "%s: Failed to stat %s, errno=%d (%s)", __func__, filename.c_str(), errno, strerror(errno));
        return LA_STATUS_ENOTFOUND;
    }

    // Check the file is not too big
    size_t file_size = (size_t)file_stat.st_size;
    if (file_size > (size_t)la_css_memory_layout_e::ARC_FIRMWARE_SIZE_MAX) {
        log_err(LLD,
                "Microcode file=%s, size=%lu, is too big to fit in CSS size=%lu",
                filename.c_str(),
                file_size,
                (size_t)la_css_memory_layout_e::ARC_FIRMWARE_SIZE_MAX);
        return LA_STATUS_ESIZE;
    }

    // Open the file
    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) {
        log_err(LLD, "%s: Failed to open %s, errnoo=%d (%s)", __func__, filename.c_str(), errno, strerror(errno));
        return LA_STATUS_EUNKNOWN;
    }

    // Read in the file
    std::vector<uint32_t> buffer(file_size / 4);
    size_t n = fread(buffer.data(), 1 /* element size */, file_size /* count of elements */, fp);
    fclose(fp);
    if (n != file_size) {
        log_err(LLD, "%s: Failed to read %s, errnoo=%d (%s)", __func__, filename.c_str(), errno, strerror(errno));
        return LA_STATUS_EUNKNOWN;
    }

    // Write the microcode to the CSS memory
    auto css_memory = m_device_context->m_sbif_css_memory;
    return write_memory(*css_memory, (size_t)la_css_memory_layout_e::ARC_FIRMWARE, file_size / 4, file_size, buffer.data());
}

void
ll_device_impl::init_arc_cpus()
{
    log_debug(LLD, "%s: ARC CPUs initialize", __func__);

    arc_cpu_info arc_info;

    la_uint_t num_of_css_arcs = get_num_of_css_arcs();
    // Create all the ARC CPU objects
    for (la_uint_t id = 0; id < num_of_css_arcs; id++) {
        m_device_context->get_arc_cpu_info(id, arc_info);
        m_arc_cpu.push_back(silicon_one::make_unique<arc_cpu>(sptr(), arc_info, id));
    }
}

bool
ll_device_impl::initialize_device_interfaces(const char* device_path, const la_platform_cbs& platform_cbs)
{
    struct dev_match_s {
        device_interface_e type;
        const char* prefix;
        bool (silicon_one::ll_device_impl::*init_func)();
    } * dev,
        dev_match[] = {
            {DEVICE_INTERFACE_I2C, "/dev/i2c", &silicon_one::ll_device_impl::init_i2c},
            {DEVICE_INTERFACE_PCI, "/dev/uio", &silicon_one::ll_device_impl::init_pci},
            {DEVICE_INTERFACE_SPI, "/dev/spidev", &silicon_one::ll_device_impl::init_spi},
            {DEVICE_INTERFACE_TEST, "/dev/testdev", &silicon_one::ll_device_impl::init_testdev},
            {DEVICE_INTERFACE_UNKNOWN, nullptr, nullptr},
        };

    if (platform_cbs.i2c_register_access) {
        m_platform_cbs.i2c_user_data = platform_cbs.user_data;
        m_platform_cbs.i2c_register_access = platform_cbs.i2c_register_access;
    }
    if (platform_cbs.dma_alloc && platform_cbs.dma_free) {
        m_platform_cbs.dma_user_data = platform_cbs.user_data;
        m_platform_cbs.dma_alloc = platform_cbs.dma_alloc;
        m_platform_cbs.dma_free = platform_cbs.dma_free;
    }
    if (platform_cbs.open_device) {
        m_platform_cbs.open_close_user_data = platform_cbs.user_data;
        m_platform_cbs.open_device = platform_cbs.open_device;
        m_platform_cbs.close_device = platform_cbs.close_device;
    }

    for (dev = dev_match; dev->prefix; dev++) {
        if (strncmp(device_path, dev->prefix, strlen(dev->prefix)) == 0) {
            break;
        }
    }

    if (!dev->prefix) {
        log_err(LLD, "%s: bad device path - %s", __func__, device_path);
        return false;
    }

    m_device_path = device_path;
    m_dev_type = dev->type;

    // Interface-specific init - PCI/SPI/socket
    if (dev->init_func && !(this->*dev->init_func)()) {
        return false;
    }

    return true;
}

void
ll_device_impl::init_access_engines()
{
    uint16_t ae_count = m_device_context->get_access_engine_count();

    dassert_crit(ae_count && ae_count != USHRT_MAX);

    log_debug(LLD, "%s: AE instances %d", __func__, ae_count);

    // The single DMA buffer is distributed among 'ae_count' access engines in equal chunks.
    size_t dma_chunk_size = m_dma_desc.length / ae_count;
    access_engine_info ae_info;

    for (uint16_t engine_id = 0; engine_id < ae_count; ++engine_id) {
        // asic4 uses all 8 engines, asic7 has 1 engine
        if (!is_asic4() && !is_asic7()) {
            if (reserved_engines.find(engine_id) != reserved_engines.end()) {
                continue;
            }
        }
        la_dma_desc dma_desc = {};
        if (m_dma_desc.virt_addr) {
            dma_desc.virt_addr = (uint8_t*)m_dma_desc.virt_addr + (dma_chunk_size * engine_id);
            dma_desc.phys_addr = m_dma_desc.phys_addr + (dma_chunk_size * engine_id);
            dma_desc.length = dma_chunk_size;
            dma_desc.is_64bit = m_dma_desc.is_64bit;
        }

        m_device_context->get_access_engine_info(engine_id, ae_info);

        m_ae.push_back(silicon_one::make_unique<access_engine>(sptr(), engine_id, ae_info, dma_desc));
    }
}

bool
ll_device_impl::init_i2c()
{
    if (m_platform_cbs.i2c_register_access) {
        // User takes care of I2C accesses. Nothing to do here.
        return true;
    }

    enum { MAX_I2C_SLAVE_ADDR = (1 << 7) - 1 };

    uint32_t bus_index;
    uint32_t slave_addr = LLD_DEFAULT_I2C_SLAVE_ID;
    // Handle explicit slave address : file name is in the format
    // /dev/i2c<bus-index>:<slave address>.
    // For instance : "/dev/i2c0:42".
    int n = sscanf(m_device_path.c_str(), "/dev/i2c-%d:%d", &bus_index, &slave_addr);
    if (n == 2 && slave_addr > MAX_I2C_SLAVE_ADDR) {
        log_err(LLD, "%s: Illegal slave address %d", __func__, slave_addr);
        return false;
    }

    std::string device_path_truncated = "/dev/i2c-" + std::to_string(bus_index);

    if ((m_fd = open(device_path_truncated.c_str(), O_RDWR)) < 0) {
        log_err(LLD, "%s: Failed to open %s, errno=%d (%s)", __func__, m_device_path.c_str(), errno, strerror(errno));
        return false;
    }

    m_i2c_data.fd = m_fd;
    m_i2c_data.slave_addr = (uint16_t)slave_addr;
    m_platform_cbs.i2c_user_data = reinterpret_cast<uintptr_t>(&m_i2c_data);
    m_platform_cbs.i2c_register_access = i2c_register_access;

    return true;
}

bool
ll_device_impl::init_pci()
{
    // Parse string of the form '/dev/uioN', extract N
    int n = sscanf(m_device_path.c_str(), "/dev/uio%d", &m_uio_dev_id);
    if (n != 1) {
        log_err(LLD, "%s: malformed dev path %s", __func__, m_device_path.c_str());
        return false;
    }

    // File descriptors
    if (m_platform_cbs.open_device) {
        // 'Platform' file descriptors for mmap and interrupt
        int interrupt_fd;
        size_t interrupt_width;
        la_status rc = m_platform_cbs.open_device(m_platform_cbs.open_close_user_data, m_fd, interrupt_fd, interrupt_width);
        if (rc) {
            log_err(LLD, "platform_cbs.open_device() error, %d (%s)", rc.value(), la_status2str(rc).c_str());
            return false;
        }
        // Interrupt counter is either 4-bytes (vanilla UIO) or 8-bytes (eventfd)
        if (m_fd < 0 || interrupt_fd < 0 || (interrupt_width != 4 && interrupt_width != 8)) {
            log_err(LLD,
                    "platform_cbs.open_device() error, bad output - fd=%d, interrupt_fd=%d, width=%ld",
                    m_fd,
                    interrupt_fd,
                    interrupt_width);
            return false;
        }

        // 'Platform' is not required to provide pci_event
        m_pci_event_fd = -1;

        m_interrupt_fd = interrupt_fd;
        m_interrupt_width_bytes = interrupt_width;
    } else {
        m_fd = open(m_device_path.c_str(), O_RDWR);
        if (m_fd < 0) {
            log_err(LLD, "%s: Failed opening %s, errno %d (%s)", __func__, m_device_path.c_str(), errno, strerror(errno));
            return false;
        }

        std::string path = get_device_files_path() + "/leaba_pci_event";
        m_pci_event_fd = open(path.c_str(), O_RDONLY);
        if (m_pci_event_fd < 0) {
            log_err(LLD, "%s: Failed opening %s, errno %d (%s)", __func__, path.c_str(), errno, strerror(errno));
            return false;
        }

        // With vanilla UIO, m_fd is used both for mmap() and for reading a 32bit interrupt counter
        m_interrupt_fd = m_fd;
        m_interrupt_width_bytes = 4;
    }

    // MMIO
    bool ok = uio_mmap(0 /* map_i */, LEABA_PCI_BAR_SZ, m_pci_bar_map_info);
    if (!ok) {
        return false;
    }

    // DMA
    ok = init_pci_dma();

    return ok;
}

bool
ll_device_impl::check_health()
{
    if (m_dev_type != DEVICE_INTERFACE_PCI) {
        return true;
    }

    // Check if PCI interface is alive.
    //
    // Read "reset_reg", it is narrower than 32bits.
    // If PCI memory-mapped IO is ok, the higher bits will be zero.
    // Otherwise, the result will be 0xffffffff (UINT32_MAX).

    uint32_t tmp = 0;
    sbif_read_register(m_device_context->m_sbif_reset_register_addr, &tmp);
    if (tmp == UINT32_MAX) {
        log_crit(LLD, "PCI device interface for %s, revision=%d does not respond.", m_device_path.c_str(), (int)m_device_revision);
        return false;
    }

    log_debug(LLD, "%s: reset_reg=0x%x", __func__, tmp);

    return true;
}

bool
ll_device_impl::is_block_allowed(const lld_block_scptr& b) const
{
    return true;
}

bool
ll_device_impl::init_pci_dma()
{
    if (m_platform_cbs.dma_alloc) {
        la_status rc = m_platform_cbs.dma_alloc(m_platform_cbs.dma_user_data, LEABA_DMA_COH_SZ, m_dma_desc);
        if (rc || !m_dma_desc.virt_addr || !m_dma_desc.phys_addr) {
            log_err(LLD, "platform_cbs.dma_alloc() error, %d (%s)", rc.value(), la_status2str(rc).c_str());
            return false;
        }
        if (!m_dma_desc.length) {
            m_dma_desc.length = LEABA_DMA_COH_SZ;
        }

        return true;
    }

    // Get the PCI domain address of the DMA buffer.
    std::string path = get_device_files_path() + "/leaba_dma_pa";
    int dma_fd = open(path.c_str(), O_RDONLY);
    if (dma_fd < 0) {
        log_err(LLD, "%s: Failed opening %s, errno %d (%s)", __func__, path.c_str(), errno, strerror(errno));
        return false;
    }

    uint64_t dma_phys_addr;
    read(dma_fd, &dma_phys_addr, sizeof(dma_phys_addr));
    if (!dma_phys_addr) {
        log_err(LLD, "%s: Failed reading DMA phys addr", __func__);
        return false;
    }

    bool ok = uio_mmap(1 /* map_i */, LEABA_DMA_COH_SZ, m_dma_map_info);
    if (!ok) {
        return false;
    }

    m_dma_desc.virt_addr = m_dma_map_info.addr.raw;
    m_dma_desc.phys_addr = dma_phys_addr;
    // TODO: Stock UIO's limitation - only the first page of DMA buffer is mapped to user space
    m_dma_desc.length = 0x1000; // LEABA_DMA_COH_SZ
    m_dma_desc.is_64bit = true;

    return true;
}

la_device_revision_e
ll_device_impl::discover_device_revision()
{
    // First, check for override through environment variable
    const char* asic = getenv("ASIC");
    if (asic) {
        return envvar_discover_device_revision(asic);
    }

    if (m_simulator) {
        return m_simulator->get_device_revision();
    }

    if (m_dev_type != DEVICE_INTERFACE_PCI) {
        // If non-PCI interface, and no environment variable - read revision from SBIF, this works only for Pacific.
        return sbif_discover_pacific_revision();
    }

    uint64_t vid = read_uio_sysfs_u64("device/vendor");
    uint64_t did = read_uio_sysfs_u64("device/device");

    if (vid == 0x16c3 && did == LEABA_PACIFIC_DEVICE_ID) {
        return la_device_revision_e::PACIFIC_A0;
    }
    if (vid != VENDOR_ID_CISCO) {
        log_err(LLD, "%s: unexpected PCI vid/did=%lx/%lx", __func__, vid, did);
        return la_device_revision_e::NONE;
    }

    if (did == LEABA_PACIFIC_DEVICE_ID) { // PACIFIC_B0 or PACIFIC_B1
        return sbif_discover_pacific_revision();
    }

    if (ll_device_context::s_pci_device_id_to_family.count(did) == 0) {
        log_err(LLD, "%s: unexpected PCI vid/did=%lx/%lx", __func__, vid, did);
        return la_device_revision_e::NONE;
    }
    la_device_family_e family = ll_device_context::s_pci_device_id_to_family[did];
    la_device_revision_e revision = ll_device_context::translate_family_to_revision(family);
    if (revision != la_device_revision_e::NONE) {
        return revision;
    }

    return topreg_discover_device_revision(family);
}

la_device_revision_e
ll_device_impl::sbif_discover_pacific_revision()
{
    la_device_revision_e out_revision;
    sbif_device_id_status_reg_register dev_id_reg{{0}};

    // m_pacific_tree is not constructed yet, use reg descriptor directly
    lld_register_desc_t const& desc = pacific_tree::get_register_desc(pacific_tree::LLD_REGISTER_SBIF_DEVICE_ID_STATUS_REG);
    sbif_read_register(desc.addr, (uint32_t*)&dev_id_reg);

    if (dev_id_reg.fields.device_id_rev_num == 0 && m_dev_type == DEVICE_INTERFACE_TEST) {
        out_revision = la_device_revision_e::PACIFIC_A0;
    } else if (dev_id_reg.fields.device_id_rev_num == 1) {
        out_revision = la_device_revision_e::PACIFIC_A0;
    } else if (dev_id_reg.fields.device_id_rev_num == 2) {
        out_revision = la_device_revision_e::PACIFIC_B0;
    } else if (dev_id_reg.fields.device_id_rev_num == 3) {
        out_revision = la_device_revision_e::PACIFIC_B1;
    } else {
        log_err(LLD, "%s: unexpected revision=%ld", __func__, dev_id_reg.fields.device_id_rev_num);
        out_revision = la_device_revision_e::NONE;
    }

    return out_revision;
}

la_device_revision_e
ll_device_impl::topreg_discover_device_revision(la_device_family_e family)
{
    // m_device_tree is not created yet, use reg descriptor directly
    la_entry_addr_t chip_id_addr = ll_device_context::get_chip_id_addr(family);
    if (chip_id_addr == 0) {
        dassert_crit(false, "unexpected device family");
        return la_device_revision_e::NONE;
    }

    uint32_t id_val;
    do_read_top_regfile(family, chip_id_addr, &id_val);

    la_device_revision_e revision = ll_device_context::translate_id_to_revision(family, id_val);

    if (revision == la_device_revision_e::NONE) {
        log_err(LLD, "%s: unexpected chip_id val=0x%x", __func__, id_val);
    }
    return revision;
}

la_device_revision_e
ll_device_impl::envvar_discover_device_revision(string asic)
{
    if (ll_device_context::s_envvar_asic_name_to_revision.count(asic) == 0) {
        log_err(LLD, "Invalid 'ASIC' variable (%s)", asic.c_str());
        dassert_crit(false);

        return la_device_revision_e::NONE;
    }
    return ll_device_context::s_envvar_asic_name_to_revision[asic];
}

uint64_t
ll_device_impl::read_uio_sysfs_u64(string attr_name)
{
    string sysfs_path = get_uio_sysfs_path() + "/" + attr_name;
    int fd = open(sysfs_path.c_str(), O_RDONLY);
    if (fd < 0) {
        log_err(LLD, "%s: Failed to open %s, errno=%d (%s)", __func__, sysfs_path.c_str(), errno, strerror(errno));
        return 0;
    }

    char buf[LINE_SIZE];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);

    if (n <= 0) {
        log_err(LLD, "%s: Failed to read %s, errno=%d (%s)", __func__, sysfs_path.c_str(), errno, strerror(errno));
        return 0;
    }

    uint64_t attr_val = strtoull(buf, nullptr, 0);

    return attr_val;
}

bool
ll_device_impl::uio_mmap(int map_i, size_t min_sz, ll_device_impl::mmap_info& mi)
{
    char attr_name[LINE_SIZE];

    snprintf(attr_name, sizeof(attr_name), "maps/map%d/size", map_i);
    uint64_t size = read_uio_sysfs_u64(attr_name);

    snprintf(attr_name, sizeof(attr_name), "maps/map%d/addr", map_i);
    uint64_t phys_addr = read_uio_sysfs_u64(attr_name);

    if (!size || !phys_addr) {
        log_err(LLD, "uio%d map%d: bad resource, size=0x%lx, phys_addr=0x%lx", m_uio_dev_id, map_i, size, phys_addr);
        return false;
    }
    if (size < min_sz) {
        log_err(LLD, "uio%d map%d: size=0x%lx is too small, must be at least 0x%lx", m_uio_dev_id, map_i, size, min_sz);
        return false;
    }

    static long page_sz = sysconf(_SC_PAGESIZE);
    off_t off = map_i * page_sz;
    void* virt_addr = mmap(0 /* addr */, (size_t)size, PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, off);
    if (virt_addr == (caddr_t)-1) {
        log_err(LLD, "Failed to mmap map_i=%d, %d (%s)", map_i, errno, strerror(errno));
        return false;
    }

    log_debug(LLD,
              "%s: uio%d map[%d]: size=0x%lx, pa=0x%lx, va=%p, off=0x%lx",
              __func__,
              m_uio_dev_id,
              map_i,
              size,
              phys_addr,
              virt_addr,
              off);

    mi.size = (size_t)size;
    mi.phys_addr = phys_addr;
    mi.addr.raw = virt_addr;
    mi.offset = off;

    return true;
}

void
ll_device_impl::uio_munmap(const ll_device_impl::mmap_info& mi)
{
    int rc = munmap(mi.addr.raw, mi.size);
    if (rc < 0) {
        log_err(LLD, "Failed to munmap %p", mi.addr.raw);
    }
}

bool
ll_device_impl::init_spi()
{
    int ret = 0;
    uint32_t mode = 0;
    uint8_t bits = 8;         // 8 bits per word
    uint32_t speed = 1000000; // 1MHz

    if ((m_fd = open(m_device_path.c_str(), O_RDWR)) < 0) {
        log_err(LLD, "%s: Failed to open %s, errno=%d (%s)", __func__, m_device_path.c_str(), errno, strerror(errno));
        return false;
    }

    ret = ioctl(m_fd, SPI_IOC_WR_MODE, &mode);
    if (ret != 0) {
        log_err(
            LLD, "%s: Failed to set SPI mode on device %s, errno=%d (%s)", __func__, m_device_path.c_str(), errno, strerror(errno));
        return false;
    }

    ret = ioctl(m_fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    if (ret != 0) {
        log_err(LLD,
                "%s: Failed to set bits per word on device %s, errno=%d (%s)",
                __func__,
                m_device_path.c_str(),
                errno,
                strerror(errno));
        return false;
    }

    ret = ioctl(m_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
    if (ret != 0) {
        log_err(LLD, "Failed to set max speed Hz on device %s - %d (%s)", m_device_path.c_str(), errno, strerror(errno));
        return false;
    }

    return true;
}

bool
ll_device_impl::init_testdev()
{
    if (m_simulator) {
        // TODO: discover LBR or SBIF simulation mode from device_path
        m_simulation_mode = simulation_mode_e::LBR;
    } else {
        m_simulation_mode = simulation_mode_e::NONE;
    }

    return true;
}

ll_device_impl::~ll_device_impl()
{
    if (m_pci_bar_map_info.addr.raw) {
        uio_munmap(m_pci_bar_map_info);
    }
    if (m_dma_map_info.addr.raw) {
        uio_munmap(m_dma_map_info);
    }
    if (m_dma_desc.virt_addr && m_platform_cbs.dma_free) {
        m_platform_cbs.dma_free(m_platform_cbs.dma_user_data, m_dma_desc);
    }
    if (m_platform_cbs.close_device) {
        m_platform_cbs.close_device(m_platform_cbs.open_close_user_data, m_fd, m_interrupt_fd);
    } else {
        if (m_pci_event_fd >= 0) {
            close(m_pci_event_fd);
        }
        if (m_fd >= 0) {
            close(m_fd);
        }
    }

    if (m_simulator) {
        delete m_simulator;
    }
}

la_device_id_t
ll_device_impl::get_device_id() const
{
    return m_device_id;
}

la_status
ll_device_impl::sbif_read_register(la_entry_addr_t addr, uint32_t* out_val) const
{
    log_debug(SBIF, "%s: addr 0x%x", __func__, addr);

    switch (m_dev_type) {
    case DEVICE_INTERFACE_PCI:
        *out_val = m_pci_bar_map_info.addr.u32[addr >> 2];
        return LA_STATUS_SUCCESS;

    case DEVICE_INTERFACE_I2C:
        return m_platform_cbs.i2c_register_access(m_platform_cbs.i2c_user_data, true /*is_read*/, addr, out_val);

    case DEVICE_INTERFACE_SPI: {
        int ret;
        struct spi_ioc_transfer tr[2];
        struct LA_PACKED {
            uint8_t spi_cmd;
            uint32_t addr;
        } command;
        struct LA_PACKED {
            uint8_t spi_res;
            uint32_t data;
        } result;

        memset(tr, 0, sizeof(tr));

        tr[0].tx_buf = (unsigned long)&command;
        tr[0].len = sizeof(command);
        tr[1].rx_buf = (unsigned long)&result;
        tr[1].len = sizeof(result);

        command.spi_cmd = LEABA_SPI_CMD_READ;
        command.addr = htonl(addr << 2);

        ret = ioctl(m_fd, SPI_IOC_MESSAGE(2), &tr);
        if (ret < 0) {
            log_err(SBIF, "Failed SPI READ, dev %s, %d (%s)", m_device_path.c_str(), errno, strerror(errno));
            return LA_STATUS_EUNKNOWN;
        }

        if (result.spi_res != LEABA_SPI_RESULT_SUCCESS) {
            log_err(SBIF, "Failed SPI READ, dev %s, addr 0x%X, res %d", m_device_path.c_str(), addr, result.spi_res);
            return LA_STATUS_EUNKNOWN;
        }

        *out_val = ntohl(result.data);
        log_debug(SBIF,
                  "SPI READ, dev %s, addr 0x%X (0x%X) -> data 0x%X (0x%X)",
                  m_device_path.c_str(),
                  addr,
                  command.addr,
                  result.data,
                  *out_val);
        return LA_STATUS_SUCCESS;
    }

    case DEVICE_INTERFACE_TEST:
        if (m_simulation_mode == simulation_mode_e::SBIF || m_simulation_mode == simulation_mode_e::LBR) {
            return m_simulator->read_register(m_sbif_block_id, addr, sizeof(*out_val), 1, out_val);
        }

        *out_val = 0; /* TODO: this preserves behavior on which the tests depend. */
        return LA_STATUS_SUCCESS;

    default:
        log_err(SBIF, "%s: unknown device type (%s)", __func__, m_device_path.c_str());
        break;
    }

    return LA_STATUS_EINVAL;
}

la_status
ll_device_impl::sbif_write_register(la_entry_addr_t addr, uint32_t val)
{
    log_debug(SBIF, "%s: addr 0x%x, val 0x%x", __func__, addr, val);

    switch (m_dev_type) {
    case DEVICE_INTERFACE_PCI:
        m_pci_bar_map_info.addr.u32[addr >> 2] = val;
        return LA_STATUS_SUCCESS;

    case DEVICE_INTERFACE_I2C:
        return m_platform_cbs.i2c_register_access(m_platform_cbs.i2c_user_data, false /*is_read*/, addr, &val);

    case DEVICE_INTERFACE_SPI: {
        int ret;
        struct spi_ioc_transfer tr[2];
        struct LA_PACKED {
            uint8_t spi_cmd;
            uint32_t addr;
            uint32_t data;
        } command;
        struct LA_PACKED {
            uint8_t spi_res;
        } result;

        memset(tr, 0, sizeof(tr));

        tr[0].tx_buf = (unsigned long)&command;
        tr[0].len = sizeof(command);
        tr[1].rx_buf = (unsigned long)&result;
        tr[1].len = sizeof(result);

        command.spi_cmd = LEABA_SPI_CMD_WRITE;
        command.addr = htonl(addr << 2);
        command.data = htonl(val);

        ret = ioctl(m_fd, SPI_IOC_MESSAGE(2), &tr);
        if (ret < 0) {
            log_err(SBIF, "Failed SPI WRITE, dev %s, %d (%s)", m_device_path.c_str(), errno, strerror(errno));
            return LA_STATUS_EUNKNOWN;
        }

        if (result.spi_res != LEABA_SPI_RESULT_SUCCESS) {
            log_err(
                SBIF, "Failed SPI WRITE, dev %s, addr 0x%X, val 0x%X, res %d", m_device_path.c_str(), addr, val, result.spi_res);
            return LA_STATUS_EUNKNOWN;
        }

        return LA_STATUS_SUCCESS;
    }

    case DEVICE_INTERFACE_TEST:
        if (m_simulation_mode == simulation_mode_e::SBIF || m_simulation_mode == simulation_mode_e::LBR) {
            m_simulator->write_register(m_sbif_block_id, addr, sizeof(val), 1, &val);
        }

        return LA_STATUS_SUCCESS;

    default:
        log_err(SBIF, "%s: unknown device type (%s)", __func__, m_device_path.c_str());
        break;
    }

    return LA_STATUS_EINVAL;
}

la_status
ll_device_impl::sbif_wait_for_value(la_entry_addr_t addr, bool equal, uint8_t poll_cnt, uint16_t val, uint16_t mask)
{
    log_debug(SBIF, "%s: addr 0x%x, equal %d, val 0x%x, mask 0x%x", __func__, addr, equal, val, mask);

    bool done = false;
    for (uint8_t i = 0; !done && (i < poll_cnt); i++) {
        uint32_t tmp = 0;
        sbif_read_register(addr, &tmp);
        bool is_equal = (tmp & mask) == (val & mask);
        done = equal ? is_equal : !is_equal;
    }

    if (done) {
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_EUNKNOWN;
}

la_status
ll_device_impl::reset()
{
    start_lld_call(this);

    log_debug(LLD, "%s: device_revision=%s", __func__, silicon_one::to_string(m_device_revision).c_str());

    // Pacific and Gibraltar share the same layout of core_hard_rstn and arc_rstn fields
    // We use the Pacific struct here, because it is narrower.
    sbif_reset_reg_register common_reset_val{{0}};
    la_status rc;

    // On GIBRALTAR_A0, avoid toggling hard-reset from 1 to 0.
    // Doing so would break synchronization between access engine fifos and CIF fifos.
    if (m_device_revision == la_device_revision_e::GIBRALTAR_A0) {
        gibraltar::sbif_reset_reg_register gb_reset_val;

        bool tmp = get_shadow_read_enabled();
        set_shadow_read_enabled(false);
        rc = LA_STATUS_SUCCESS;
        if (is_block_allowed(m_device_context->m_sbif_reset_reg->get_block())) {
            rc = ll_device::read_register(*m_device_context->m_sbif_reset_reg, gb_reset_val);
        }

        set_shadow_read_enabled(tmp);

        return_on_error(rc);

        common_reset_val.fields.core_hard_rstn = gb_reset_val.fields.core_hard_rstn;
    }

    // Reset (active low)
    rc = write_register(*m_device_context->m_sbif_reset_reg, common_reset_val);
    return_on_error(rc);

    // Stay "active low" for a while, let the reset propagate
    log_debug(LLD, "command::step_no_response %ld", HARD_RESET_DELAY.count());
    std::this_thread::sleep_for(HARD_RESET_DELAY);

    // Take out of reset
    common_reset_val.fields.core_hard_rstn = 1;
    // We leave ARCs reset, will turn them on later
    common_reset_val.fields.arc_rstn = 0;
    rc = write_register(*m_device_context->m_sbif_reset_reg, common_reset_val);
    return_on_error(rc);

    // Check if need wait here...
    log_debug(LLD, "command::step_no_response %ld", POST_HARD_RESET_DELAY.count());
    std::this_thread::sleep_for(POST_HARD_RESET_DELAY);

    // The code block below replaces future interface of polling on access engine.
    // Once LLD interface will be ready, this block should be removed
    std::vector<size_t> addresses;
    bit_vector expected_val(1, 16);
    bit_vector mask(1, 16);
    m_device_context->get_simulation_poll_address_list(addresses);
    for (size_t addr : addresses) {
        log_debug(
            SIM, "command::poll_no_response %016zx 2 %s %s 200", addr, expected_val.to_string().c_str(), mask.to_string().c_str());
    }

    // Workaround for IDB in Pacific
    if (is_pacific()) {
        size_t addr2 = m_device_context->get_simulation_poll_idb_done_addr();
        bit_vector idb_init_done_expected_val(0, 98);
        bit_vector idb_init_done_mask = bit_vector::ones(98);
        log_debug(SIM,
                  "command::poll_no_response %016zx 2 %s %s 200",
                  addr2,
                  idb_init_done_expected_val.to_string().c_str(),
                  idb_init_done_mask.to_string().c_str());
    }
    m_device_accessible = true;
    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::get_core_reset(bool& out_is_reset)
{
    la_status rc;

    bool is_reset = false;
    bool shadow_enabled = get_shadow_read_enabled();
    set_shadow_read_enabled(false);

    const lld_register* reset_reg = m_device_context->m_sbif_reset_reg.get();

    /*
    gibraltar::sbif_reset_reg_register common_reset_val{};
    rc = ll_device::read_register(*reset_reg, common_reset_val);
    is_reset = common_reset_val.fields.core_hard_rstn == 0;
    log_err(LLD, "%s: 5 is_reset = %d", __func__, is_reset);
    */

    bit_vector tmp_bv;
    rc = read_register(*reset_reg, tmp_bv);
    is_reset = tmp_bv.bit(0) == 0;
    log_info(LLD, "%s: 0x%lx is_reset = %d", __func__, tmp_bv.get_value(), is_reset);

    set_shadow_read_enabled(shadow_enabled);
    return_on_error(rc);

    out_is_reset = is_reset;

    return LA_STATUS_SUCCESS;
}

const pacific_tree*
ll_device_impl::get_pacific_tree() const
{
    return get_pacific_tree_scptr().get();
}

const gibraltar_tree*
ll_device_impl::get_gibraltar_tree() const
{
    return get_gibraltar_tree_scptr().get();
}

const asic4_tree*
ll_device_impl::get_asic4_tree() const
{
    return get_asic4_tree_scptr().get();
}

const asic3_tree*
ll_device_impl::get_asic3_tree() const
{
    return get_asic3_tree_scptr().get();
}

const asic5_tree*
ll_device_impl::get_asic5_tree() const
{
    return get_asic5_tree_scptr().get();
}

pacific_tree_scptr
ll_device_impl::get_pacific_tree_scptr() const
{
    return m_device_context->get_pacific_tree_scptr();
}

gibraltar_tree_scptr
ll_device_impl::get_gibraltar_tree_scptr() const
{
    return m_device_context->get_gibraltar_tree_scptr();
}

asic4_tree_scptr
ll_device_impl::get_asic4_tree_scptr() const
{
    return m_device_context->get_asic4_tree_scptr();
}

asic3_tree_scptr
ll_device_impl::get_asic3_tree_scptr() const
{
    return m_device_context->get_asic3_tree_scptr();
}

asic5_tree_scptr
ll_device_impl::get_asic5_tree_scptr() const
{
    return m_device_context->get_asic5_tree_scptr();
}

lld_block_scptr
ll_device_impl::get_device_tree() const
{
    return m_device_context->get_device_tree();
}

la_device_family_e
ll_device_impl::get_device_family() const
{
    return m_device_context->get_device_family();
}

la_device_revision_e
ll_device_impl::get_device_revision() const
{
    return m_device_revision;
}

interrupt_tree*
ll_device_impl::get_interrupt_tree()
{
    return m_interrupt_tree.get();
}

interrupt_tree_sptr
ll_device_impl::get_interrupt_tree_sptr()
{
    return m_interrupt_tree;
}

ll_device_context_sptr
ll_device_impl::get_device_context()
{
    return std::shared_ptr<ll_device_context>(m_device_context);
}

bool
ll_device_impl::is_asic5() const
{
    return m_device_context->is_asic5();
}

bool
ll_device_impl::is_asic4() const
{
    return m_device_context->is_asic4();
}
bool
ll_device_impl::is_asic3() const
{
    return m_device_context->is_asic3();
}
bool
ll_device_impl::is_asic7() const
{
    return m_device_context->is_asic7();
}
bool
ll_device_impl::is_gibraltar() const
{
    return m_device_context->is_gibraltar();
}
bool
ll_device_impl::is_pacific() const
{
    return m_device_context->is_pacific();
}

lld_block_scptr
ll_device_impl::get_block(la_block_id_t block_id)
{
    return m_device_context->get_block(block_id);
}

std::string
ll_device_impl::get_device_path() const
{
    return m_device_path;
}

bool
ll_device_impl::is_valid() const
{
    start_bool_lld_call(this);

    return m_fd >= 0 || m_simulator;
}

bool
ll_device_impl::is_simulated_device() const
{
    if (m_simulation_mode != simulation_mode_e::NONE) {
        return true;
    }

    // A simulator may not be set, but the device may still be not a physical device but a 'testdev'.
    return (m_dev_type == DEVICE_INTERFACE_TEST);
}

la_status
ll_device_impl::set_write_burst(bool en)
{
    start_lld_call(this);

    // Wait for completion of in-flight commands
    for (auto& ae : m_ae) {
        ae->flush();
    }

    // If enabled, don't wait for CIF response, allows the access engines to put
    // multiple commands from command fifo to CIF, without waiting for full
    // round trip of each command in between.
    //
    // If disabled, wait for full round trip before next command can be put on
    // CIF.
    la_status rc;
    uint32_t reg_val = 0;
    lld_register_scptr reset_reg;
    la_entry_addr_t global_cfg_addr = m_device_context->m_access_engine_global_cfg_addr;

    rc = sbif_read_register(global_cfg_addr, &reg_val);
    return_on_error(rc);

    if (en) {
        reg_val |= 1;
        if (is_asic4()) {
            /*
             * must increase the cif_trans_gap_counter to d20 (default is d10)
             */
            reg_val &= ~(0xff << 17);
            reg_val |= (0x14 << 17);
            writeBurstMode = true;
        }
    } else {
        reg_val &= ~1;
        if (is_asic4()) {
            writeBurstMode = false;
        }
    }

    return sbif_write_register(global_cfg_addr, reg_val);
}

void
ll_device_impl::set_flush_after_write(bool en)
{
    start_void_lld_call(this);

    log_debug(LLD, "%s: %d", __func__, (int)en);

    m_flush_after_write = en;
}

void
ll_device_impl::set_shadow_read_enabled(bool en)
{
    start_void_lld_call(this);

    log_debug(LLD, "%s: %d", __func__, (int)en);

    m_non_volatile_read_from_device = !en;
}

bool
ll_device_impl::get_shadow_read_enabled() const
{
    start_bool_lld_call(this);

    return !m_non_volatile_read_from_device;
}

void
ll_device_impl::set_write_to_device(bool write_to_device)
{
    start_void_lld_call(this);

    log_debug(LLD, "%s: %u", __func__, (la_uint_t)write_to_device);

    m_write_to_device = write_to_device;
}

bool
ll_device_impl::get_write_to_device() const
{
    start_bool_lld_call(this);

    return m_write_to_device;
}

la_status
ll_device_impl::reset_access_engines()
{
    uint16_t ae_count = m_device_context->get_access_engine_count();
    uint32_t ae_mask = (1 << ae_count) - 1;

    // Reset all access engines
    return reset_access_engines(ae_mask);
}

void
ll_device_impl::reduce_traffic(std::vector<bit_vector>& out_original_rxpp_values)
{
    start_void_lld_call(this);

    static constexpr size_t NUM_SLICES_PER_DEVICE_WALKAROUND = 6;
    constexpr uint64_t CEM_BUBBLE_ERRATA_BUBBLE = 15;
    constexpr uint64_t CEM_BUBBLE_ERRATA_PERIOD = 16;

    access_engine_uptr ae_ptr = reserve_access_engine();

    for (la_slice_id_t i = 0; i < NUM_SLICES_PER_DEVICE_WALKAROUND; i++) {
        out_original_rxpp_values.push_back(bit_vector(0));
        read_rxpp_traffic_shaper(ae_ptr.get(), i, out_original_rxpp_values[i]);

        bit_vector new_rxpp_val = out_original_rxpp_values[i];
        new_rxpp_val.set_bits(67, 64, CEM_BUBBLE_ERRATA_BUBBLE);
        new_rxpp_val.set_bits(79, 68, CEM_BUBBLE_ERRATA_PERIOD);

        write_rxpp_traffic_shaper(ae_ptr.get(), i, new_rxpp_val);
    }

    release_access_engine(std::move(ae_ptr));
}

void
ll_device_impl::restore_traffic(std::vector<bit_vector> original_rxpp_values)
{
    start_void_lld_call(this);

    static constexpr size_t NUM_SLICES_PER_DEVICE_WALKAROUND = 6;

    access_engine_uptr ae_ptr = reserve_access_engine();

    for (la_slice_id_t i = 0; i < NUM_SLICES_PER_DEVICE_WALKAROUND; i++) {
        write_rxpp_traffic_shaper(ae_ptr.get(), i, original_rxpp_values[i]);
    }

    release_access_engine(std::move(ae_ptr));
}

void
ll_device_impl::change_traffic_rate(bool traffic_reduce)
{
    if (traffic_reduce) {
        m_rxpp_values.clear();
        reduce_traffic(m_rxpp_values);
    } else {
        restore_traffic(m_rxpp_values);
    }
}

la_status
ll_device_impl::read_rxpp_traffic_shaper(access_engine* ae, la_slice_id_t sid, bit_vector& out)
{
    lld_register_scptr reg;

    if (is_pacific()) {
        reg = get_pacific_tree()->slice[sid]->npu->rxpp_term->rxpp_term->spare_reg;
    } else if (is_gibraltar()) {
        reg = get_gibraltar_tree()->slice[sid]->npu->rxpp_term->top->spare_reg;
    } else {
        // No traffic shaper registers for other devices
        return LA_STATUS_SUCCESS;
    }

    out.resize(reg->get_desc()->width_in_bits);

    la_status stat = do_read_register(ae, reg.get(), false, &out);
    return_on_error_log(stat, AE, ERROR, "Could not read rxpp traffic shaper");

    return stat;
}

la_status
ll_device_impl::write_rxpp_traffic_shaper(access_engine* ae, la_slice_id_t sid, const bit_vector& in)
{
    lld_register_scptr reg;

    if (is_pacific()) {
        reg = get_pacific_tree()->slice[sid]->npu->rxpp_term->rxpp_term->spare_reg;
    } else if (is_gibraltar()) {
        reg = get_gibraltar_tree()->slice[sid]->npu->rxpp_term->top->spare_reg;
    } else {
        // No traffic shaper for other devices
        return LA_STATUS_SUCCESS;
    }

    la_status stat = do_write_register(ae, reg.get(), in);
    return_on_error_log(stat, AE, ERROR, "Could not write rxpp traffic shaper");

    stat = ae->flush();
    return stat;
}

la_status
ll_device_impl::reset_access_engines(uint32_t select_access_engines)
{
    start_lld_call(this);

    if (m_simulator) {
        return LA_STATUS_SUCCESS;
    }

    log_debug(LLD, "%s: select_access_engines 0x%x", __func__, select_access_engines);

    // Assert reset bits
    la_entry_addr_t ae_reset_addr = m_device_context->m_ae_reset_addr;
    uint32_t ae_reset_bits = m_device_context->get_ae_reset_bits(select_access_engines);
    uint32_t val = 0;

    sbif_read_register(ae_reset_addr, &val);
    val |= ae_reset_bits;
    sbif_write_register(ae_reset_addr, val);

    // Wait a bit
    std::this_thread::sleep_for(ACCESS_ENGINE_RESET_DELAY);

    // De-assert reset bits
    val &= ~ae_reset_bits;
    sbif_write_register(ae_reset_addr, val);

    // Reset soft states of matching access engines
    for (auto& ae : m_ae) {
        uint32_t ae_id = ae->get_engine_id();
        if (select_access_engines & (1 << ae_id)) {
            la_status rc = ae->reset();

            // Ignore error for test device
            if (rc && (m_dev_type != DEVICE_INTERFACE_TEST)) {
                // Ignore even if AE is known to be in error state.
                // return rc;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

void
ll_device_impl::set_access_engine_cmd_fifo_enabled(bool en)
{
    start_void_lld_call(this);

    la_entry_addr_t addr = m_device_context->m_access_engine_cmd_mem_override_fifo_addr;

    if (!is_asic7()) {
        uint8_t val = en ? 0 : 0xff;

        sbif_write_register(addr, val);
    } else {
        uint32_t val = 0;

        sbif_read_register(addr, &val);

        if (en)
            val |= 1 << 17;
        else
            val &= ~(1 << 17);

        sbif_write_register(addr, val);
    }
    m_access_engine_cmd_fifo_enabled = en;
    log_debug(LLD, "%s: %d", __func__, (int)en);
}

bool
ll_device_impl::get_access_engine_cmd_fifo_enabled() const
{
    return m_access_engine_cmd_fifo_enabled;
}

la_status
ll_device_impl::set_device_simulator(device_simulator* simulator)
{
    return set_device_simulator(simulator, simulation_mode_e::LBR);
}

la_status
ll_device_impl::set_device_simulator(device_simulator* simulator, simulation_mode_e mode)
{
    start_lld_call(this);

    if (simulator == nullptr && m_simulator != nullptr) {
        delete m_simulator;
        m_simulator = nullptr;
        return LA_STATUS_SUCCESS;
    }

    if (m_simulator) {
        log_err(LLD, "%s: device simulator is already set", __func__);
        return LA_STATUS_EEXIST;
    }

    if (simulator) {
        simulator->set_pacific_tree(get_pacific_tree());
        simulator->set_gibraltar_tree(get_gibraltar_tree());
        simulator->set_asic4_tree(get_asic4_tree());
        simulator->set_asic3_tree(get_asic3_tree());
        simulator->set_asic5_tree(get_asic5_tree());
        m_simulator = simulator;
        m_simulation_mode = mode;
    } else {
        m_simulator = nullptr;
        m_simulation_mode = simulation_mode_e::NONE;
    }

    return LA_STATUS_SUCCESS;
}

device_simulator*
ll_device_impl::get_device_simulator() const
{
    return m_simulator;
}

ll_device::simulation_mode_e
ll_device_impl::get_device_simulation_mode() const
{
    return m_simulation_mode;
}

void
ll_device_impl::get_event_fds(int& out_pci_event_fd, int& out_interrupt_fd, size_t& out_interrupt_width_bytes) const
{
    out_pci_event_fd = m_pci_event_fd;
    out_interrupt_fd = m_interrupt_fd;
    out_interrupt_width_bytes = m_interrupt_width_bytes;
}

la_status
ll_device_impl::post_restore(const char* device_path, const la_platform_cbs& platform_cbs)
{
    // 1. Initialize device connectivity.
    //    Device path, device type, platform callbacks, event file descriptors and DMA mappings are all re-initialized.
    bool success = initialize_device_interfaces(device_path, platform_cbs);
    if (!success) {
        return LA_STATUS_EUNKNOWN;
    }

    // 2. Ensure device ID, revision match expected.
    la_status status = post_restore_interfaces_sanity_checks();
    return_on_error(status);

    // 3. Ensure device is accessible, and update m_device_accessible.
    m_device_accessible = check_health();
    if (!m_device_accessible) {
        return LA_STATUS_ENODEV;
    }

    // 4. Update access engines' DMA mappings by reconfiguring the access engines array, then resetting their ASIC state.
    m_ae.clear();
    init_access_engines();
    status = reset_access_engines();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::post_restore(const char* device_path)
{
    la_platform_cbs cbs = {.user_data = 0,
                           .i2c_register_access = nullptr,
                           .dma_alloc = nullptr,
                           .dma_free = nullptr,
                           .open_device = nullptr,
                           .close_device = nullptr};

    return post_restore(device_path, cbs);
}

//---------------------------------------------------------------------------------------------

la_status
ll_device_impl::sbif_read_memory(la_entry_addr_t addr, size_t entry, uint32_t* val) const
{
    // Byte addressable on HW and RTL frontdoor, dword addressable with RTL
    // backdoor
    size_t off = m_simulator ? entry : entry << 2;

    return sbif_read_register(addr + off, val);
}

la_status
ll_device_impl::sbif_read_memory_entries(la_entry_addr_t addr, size_t first_entry, size_t count, uint32_t* val) const
{
    la_status rc = LA_STATUS_SUCCESS;

    log_debug(SBIF, "%s: base addr 0x%x, first_entry 0x%lx, count 0x%lx", __func__, addr, first_entry, count);
    for (size_t i = 0; (i < count) && (rc == LA_STATUS_SUCCESS); i++) {
        rc = sbif_read_memory(addr, first_entry + i, &val[i]);
    }

    return rc;
}

la_status
ll_device_impl::sbif_write_memory(la_entry_addr_t addr, size_t entry, uint32_t val)
{
    // Byte addressable on HW and RTL frontdoor, dword addressable with RTL
    // backdoor
    size_t off = m_simulator ? entry : entry << 2;

    return sbif_write_register(addr + off, val);
}

la_status
ll_device_impl::sbif_write_memory_entries(la_entry_addr_t addr, size_t first_entry, size_t count, const uint32_t* val)
{
    la_status rc = LA_STATUS_SUCCESS;

    log_debug(SBIF, "%s: base addr 0x%x, first_entry 0x%lx, count 0x%lx", __func__, addr, first_entry, count);
    for (size_t i = 0; (i < count) && (rc == LA_STATUS_SUCCESS); i++) {
        rc = sbif_write_memory(addr, first_entry + i, val[i]);
    }

    return rc;
}

la_status
ll_device_impl::do_write_top_regfile(la_device_family_e family, la_entry_addr_t addr, uint32_t in_val)
{
    start_lld_call(this);

    if ((family != la_device_family_e::GIBRALTAR) && (family != la_device_family_e::ASIC4)
        && (family != la_device_family_e::ASIC3)
        && (family != la_device_family_e::ASIC5)
        && (family != la_device_family_e::ASIC7)) {
        dassert_crit(false, "unexpected device revision");
        return LA_STATUS_EUNKNOWN;
    }

    // Don't use m_device_tree because top-reg may be used for device revision discover, before device_tree is created.
    la_entry_addr_t cfg_addr = ll_device_context::s_sbif_top_addr[family].cfg;
    la_entry_addr_t wdata_addr = ll_device_context::s_sbif_top_addr[family].wdata;

    // Since the registers are identical, we use the type from 'gibraltar' namespace.
    gibraltar::sbif_top_regfile_cfg_reg_register cfg_val{{0}};

    // Write the address, 'valid' remains deasserted
    cfg_val.fields.top_regfile_cfg_valid = 0;
    cfg_val.fields.top_regfile_cfg_addr = addr;
    sbif_write_register(cfg_addr, *(uint32_t*)cfg_val.u8);

    // Write the data
    sbif_write_register(wdata_addr, in_val);

    // Assert 'valid'
    cfg_val.fields.top_regfile_cfg_valid = 1;
    sbif_write_register(cfg_addr, *(uint32_t*)cfg_val.u8);

    // Deassert 'valid'
    cfg_val.fields.top_regfile_cfg_valid = 0;
    sbif_write_register(cfg_addr, *(uint32_t*)cfg_val.u8);

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::do_read_top_regfile(la_device_family_e family, la_entry_addr_t addr, uint32_t* out_val)
{
    start_lld_call(this);

    if ((family != la_device_family_e::GIBRALTAR) && (family != la_device_family_e::ASIC4)
        && (family != la_device_family_e::ASIC3)
        && (family != la_device_family_e::ASIC5)
        && (family != la_device_family_e::ASIC7)) {
        dassert_crit(false, "unexpected device revision");
        return LA_STATUS_EUNKNOWN;
    }

    // Don't use m_device_tree because top-reg may be used for device revision discover, before device_tree is created.
    la_entry_addr_t cfg_addr = ll_device_context::s_sbif_top_addr[family].cfg;
    la_entry_addr_t rdata_addr = ll_device_context::s_sbif_top_addr[family].rdata;

    // Since the registers are identical, we use the type from 'gibraltar' namespace.
    gibraltar::sbif_top_regfile_cfg_reg_register cfg_val{{0}};

    if (family == la_device_family_e::ASIC7) {
        // Asic7 workaround:
        // Issue write to an invalid address
        cfg_val.fields.top_regfile_cfg_valid = 1;
        cfg_val.fields.top_regfile_cfg_addr = 0x3ff;
        sbif_write_register(cfg_addr, *(uint32_t*)cfg_val.u8);
    } else {
        // Write the address, 'valid' remains deasserted
        cfg_val.fields.top_regfile_cfg_valid = 0;
    }
    // In case of Asic7 device cfg_val.fields.top_regfile_cfg_valid = 1
    // Does not issue a write, as the valid bit is already set, but enables the capturing of the address, which is otherwise ignored
    cfg_val.fields.top_regfile_cfg_addr = addr;
    sbif_write_register(cfg_addr, *(uint32_t*)cfg_val.u8);

    // wait for a value to be updated in topreg read register
    std::this_thread::sleep_for(TOPREG_READ_DELAY);

    // Read data
    sbif_read_register(rdata_addr, out_val);

    // Ocassionaly we read the wrong value because we are faster than the device.
    // Reread the value and make sure that it is stable.
    bool value_stable = false;
    int max_read_count = 4;
    do {
        uint32_t tmp_buffer;

        memcpy(&tmp_buffer, out_val, sizeof(tmp_buffer));
        sbif_read_register(rdata_addr, out_val);

        if (memcmp(&tmp_buffer, out_val, sizeof(tmp_buffer)) == 0) {
            value_stable = true;
        } else {
            log_info(LLD, "%s: Wrong value read: value1 %d value2 %d", __func__, out_val[0], tmp_buffer);
            std::this_thread::sleep_for(TOPREG_READ_DELAY);
        }

        max_read_count--;
    } while ((max_read_count > 0) && (!value_stable));

    if (!value_stable) {
        log_err(LLD, "%s: Failed to read topreg value", __func__);
    }

    if (family == la_device_family_e::ASIC7) {
        // Asic7 workaround
        cfg_val.fields.top_regfile_cfg_valid = 0;
        cfg_val.fields.top_regfile_cfg_addr = 0;
        sbif_write_register(cfg_addr, *(uint32_t*)cfg_val.u8);
    }

    return LA_STATUS_SUCCESS;
}

access_engine_uptr
ll_device_impl::reserve_access_engine(void)
{
    if (m_ae.empty()) {
        log_err(LLD, "%s: all engines are already reserved", __func__);
        return nullptr;
    }

    access_engine_uptr ae = move(m_ae.back());
    m_ae.pop_back();

    return ae;
}

void
ll_device_impl::release_access_engine(access_engine_uptr ae)
{
    m_ae.push_back(move(ae));
}

la_status
ll_device_impl::access(vector_alloc<ll_device::access_desc> ads)
{
    start_lld_call(this);

    access_engine_uptr ae_ptr = reserve_access_engine();
    if (!ae_ptr) {
        return LA_STATUS_EBUSY;
    }

    la_status rc;
    access_engine* ae = ae_ptr.get();

    for (const auto& ad : ads) {
        dassert_crit((ad.mem == nullptr) || (ad.reg == nullptr));
        bool is_match = true;
        if (ad.mem != nullptr) {
            is_match = is_matching_device_revision(this, *ad.mem);
        } else if (ad.reg != nullptr) {
            is_match = is_matching_device_revision(this, *ad.reg);
        }

        if (!is_match) {
            log_debug(ACCESS,
                      "%s: %s - skip due to device revision mismatch",
                      __func__,
                      ad.mem ? ad.mem->get_name().c_str() : ad.reg->get_name().c_str());
            continue;
        }
        switch (ad.action) {
        case silicon_one::ll_device::access_desc::operation_e::INVALID:
            log_debug(LLD, "%s: Got INVALID operation", __func__);
            rc = LA_STATUS_EUNKNOWN;
            break;
        case silicon_one::ll_device::access_desc::operation_e::WRITE_REGISTER: {
            rc = do_write_register(ae, ad.reg, ad.in_val);
            break;
        }
        case silicon_one::ll_device::access_desc::operation_e::WRITE_REGISTER_ARRAY: {
            rc = do_write_register_array(ae, ad.reg_array, ad.in_val, ad.first, ad.count);
            break;
        }
        case silicon_one::ll_device::access_desc::operation_e::READ_REGISTER: {
            rc = do_read_register(ae, ad.reg, false /* peek */, ad.out_val);
            break;
        }

        case silicon_one::ll_device::access_desc::operation_e::PEEK_REGISTER: {
            rc = do_read_register(ae, ad.reg, true /* peek */, ad.out_val);
            break;
        }

        case silicon_one::ll_device::access_desc::operation_e::WRITE_MEMORY: {
            rc = do_write_memory(ae, ad.mem, ad.first, ad.count, ad.in_val);
            break;
        }

        case silicon_one::ll_device::access_desc::operation_e::READ_MEMORY: {
            rc = do_read_memory(ae, ad.mem, ad.first, ad.count, ad.out_val);
            break;
        }

        case silicon_one::ll_device::access_desc::operation_e::READ_MODIFY_WRITE_REGISTER: {
            rc = do_read_modify_write_register(ae, ad.reg, ad.args.rmw.msb, ad.args.rmw.lsb, ad.in_val);
            break;
        }

        case silicon_one::ll_device::access_desc::operation_e::READ_MODIFY_WRITE_MEMORY: {
            rc = do_read_modify_write_memory(ae, ad.mem, ad.first, ad.args.rmw.msb, ad.args.rmw.lsb, ad.in_val);
            break;
        }

        case silicon_one::ll_device::access_desc::operation_e::WAIT_FOR_VALUE: {
            rc = do_wait_for_value(ae,
                                   ad.args.wait_for_value.block_id,
                                   ad.args.wait_for_value.addr,
                                   ad.args.wait_for_value.equal,
                                   ad.args.wait_for_value.poll_cnt,
                                   ad.args.wait_for_value.val,
                                   ad.args.wait_for_value.mask);
            break;
        }

        case silicon_one::ll_device::access_desc::operation_e::DELAY: {
            rc = ae->delay(ad.args.delay_cycles);
            break;
        }
        }
        if (rc != LA_STATUS_SUCCESS) {
            break; // for loop
        }
    }
    if (rc == LA_STATUS_ENODEV) {
        m_device_accessible = false;
    }

    release_access_engine(std::move(ae_ptr));

    return rc;
}

//---------------------------------------------------------------
// Registers/Memory/TCAM API
//---------------------------------------------------------------
la_status
ll_device_impl::read_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv)
{
    start_lld_call(this);

    // Resize to the specified width
    out_bv.resize(width_bits);

    access_engine_uptr ae = reserve_access_engine();
    if (!ae) {
        return LA_STATUS_EBUSY;
    }
    la_status rc = do_read_register_raw(
        ae.get(), block_id, addr, out_bv.get_width_in_bytes(), 1 /* count */, false /* peek */, out_bv.byte_array());
    release_access_engine(std::move(ae));

    return rc;
}

la_status
ll_device_impl::peek_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv)
{
    start_lld_call(this);

    log_debug(ACCESS, "peek_register: block_id %d, addr 0x%x, width_bits %d", block_id, addr, width_bits);

    // Resize to the specified width
    out_bv.resize(width_bits);

    access_engine_uptr ae = reserve_access_engine();
    if (!ae) {
        return LA_STATUS_EBUSY;
    }
    la_status rc = do_read_register_raw(
        ae.get(), block_id, addr, out_bv.get_width_in_bytes(), 1 /* count */, true /* peek */, out_bv.byte_array());
    release_access_engine(std::move(ae));

    return rc;
}

// We might be called in a context of an offloaded transaction. Hence, cannot
// just "return" an error.
// Assume, all inputs have alredy been sanitized.
la_status
ll_device_impl::do_read_register_raw(access_engine* ae,
                                     la_block_id_t block_id,
                                     la_entry_addr_t addr,
                                     la_entry_width_t width,
                                     size_t count,
                                     bool peek,
                                     void* out_val)
{
    la_status rc;

    if (block_id == m_sbif_block_id) {
        rc = sbif_read_register(addr, (uint32_t*)out_val);
    } else if (m_simulation_mode == simulation_mode_e::LBR) {
        rc = m_simulator->read_register(block_id, addr, width, count, out_val);
    } else if (block_id == m_top_regfile_block_id) {
        auto device_family = get_device_family();
        rc = do_read_top_regfile(device_family, addr, (uint32_t*)out_val);
    } else {
        rc = do_read_ae(ae, block_id, addr, width, count, peek, out_val);
    }

    auto level = rc ? la_logger_level_e::ERROR : la_logger_level_e::DEBUG;
    uint64_t* storage = (uint64_t*)out_val;
    log_message(la_logger_component_e::ACCESS,
                level,
                "read_register: %s, block_id=0x%x, addr=0x%x, width=%d, count=%ld, peek=%d, val=0x%s, rc=%d",
                get_register_name(block_id, addr).c_str(),
                block_id,
                addr,
                width,
                count,
                peek,
                bit_vector(storage, width * 8).to_string().c_str(),
                rc.value());

    return rc;
}

la_status
ll_device_impl::do_write_register_raw(access_engine* ae,
                                      la_block_id_t block_id,
                                      la_entry_addr_t addr,
                                      la_entry_width_t width,
                                      size_t count,
                                      const uint8_t* in_val)
{
    la_status rc;

    log_debug(ACCESS,
              "write_register: %s, block_id=0x%x, addr=0x%x, width=%d, count=%ld, val=0x%s",
              get_register_name(block_id, addr).c_str(),
              block_id,
              addr,
              width,
              count,
              bit_vector(width, in_val, width * bit_vector::BV_BITS_IN_BYTE).to_string().c_str());

    if (block_id == m_sbif_block_id) {
        if (m_simulation_mode == simulation_mode_e::LBR) {
            rc = LA_STATUS_SUCCESS;
        } else {
            // Serialize SBIF write with posted access engine operations (i.e. CIF write).
            // Wait for completion of posted access engine operations.

            rc = ae->flush();
        }
        rc = rc ?: sbif_write_memory_entries(addr, 0, count, (const uint32_t*)in_val);
    } else if (m_simulation_mode == simulation_mode_e::LBR) {
        m_simulator->write_register(block_id, addr, width, count, in_val);
        // TODO: for testing only!!!!!!
        rc = LA_STATUS_SUCCESS;
    } else if (block_id == m_top_regfile_block_id) {
        auto device_family = get_device_family();
        rc = do_write_top_regfile(device_family, addr, *(uint32_t*)in_val);
    } else {
        rc = ae->write(block_id, addr, width, count, in_val);
        if (m_flush_after_write && !rc) {
            rc = ae->flush();
        }
    }

    if (rc) {
        log_err(ACCESS,
                "write_register: %s, block_id=0x%x, addr=0x%x, width=%d, count=%ld, val=0x%s, rc=%d",
                get_register_name(block_id, addr).c_str(),
                block_id,
                addr,
                width,
                count,
                bit_vector(width, in_val, width * bit_vector::BV_BITS_IN_BYTE).to_string().c_str(),
                rc.value());
    }

    return rc;
}

la_status
ll_device_impl::do_wait_for_value(access_engine* ae,
                                  la_block_id_t block_id,
                                  la_entry_addr_t addr,
                                  bool equal,
                                  uint8_t poll_cnt,
                                  uint16_t val,
                                  uint16_t mask)
{
    la_status rc;
    la_status rc_flush;

    if (block_id == m_sbif_block_id) {
        rc = sbif_wait_for_value(addr, equal, poll_cnt, val, mask);
    } else if (m_simulation_mode == simulation_mode_e::LBR) {
        // TODO: for testing only!!!!!!
        rc = LA_STATUS_SUCCESS;
    } else {
        rc = ae->wait_for_value(block_id, addr, equal, poll_cnt, val, mask);
        if (rc) {
            // recover AE after wait failed
            rc_flush = ae->flush();
            if (rc_flush) {
                log_err(ACCESS, "failed to recover after wait for valie : rc: %d", rc.value());
            }
        }
    }

    if (rc) {
        log_err(ACCESS,
                "wait_for_value: rc %d, block_id 0x%x, addr 0x%x, equal %d, val 0x%X, mask 0x%X",
                rc.value(),
                block_id,
                addr,
                equal,
                val,
                mask);
    }

    return rc;
}

la_status
ll_device_impl::read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& value)
{
    start_lld_call(this);

    la_status rc = m_default_tr->read_modify_write_register(reg, msb, lsb, value);
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::write_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, const bit_vector& in_bv)
{
    start_lld_call(this);

    // Truncate/zero-pad to the specified width
    bit_vector bv(in_bv);
    bv.resize(width_bits);

    access_engine_uptr ae = reserve_access_engine();
    if (!ae) {
        return LA_STATUS_EBUSY;
    }
    la_status rc = do_write_register_raw(ae.get(), block_id, addr, bv.get_width_in_bytes(), 1 /* count */, bv.byte_array());
    release_access_engine(move(ae));

    return rc;
}

la_status
ll_device_impl::read_memory(const lld_memory& mem, size_t line, bit_vector& out_bv)
{
    start_lld_call(this);

    la_status rc;
    if (mem.get_desc()->is_volatile()) {
        rc = m_default_tr->read_memory_volatile(mem, line, 1 /* count */, out_bv);
    } else {
        rc = m_default_tr->read_memory(mem, line, 1 /* count */, out_bv);
    }
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::read_memory(const lld_memory_scptr& mem, size_t line, bit_vector& out_bv)
{
    start_lld_call(this);

    return read_memory(*mem, line, out_bv);
}

la_status
ll_device_impl::read_memory(const lld_memory& mem, size_t first_entry, size_t count, size_t out_val_sz, void* out_val)
{
    start_lld_call(this);

    const lld_memory_desc_t* mdesc = mem.get_desc();

    // Check only stuff that directly applies to the creation of 'bit_vector tmp'.
    // Other things will be sanitized in ll_transaction::read_memory()
    if (!mem.is_valid() || !count || !out_val_sz || !out_val) {
        log_err(ACCESS, "%s: invalid params, %s, %ld/%ld/%p", __func__, mdesc->name.c_str(), count, out_val_sz, out_val);
        return LA_STATUS_EINVAL;
    }
    if (out_val_sz < count * mdesc->width_total) {
        log_err(ACCESS,
                "%s: out buf too small, %s, sz %ld, count %ld, width %d",
                __func__,
                mdesc->name.c_str(),
                out_val_sz,
                count,
                mdesc->width_total);
        return LA_STATUS_ESIZE;
    }

    la_status rc;
    bit_vector tmp;

    if (mdesc->is_volatile()) {
        rc = m_default_tr->read_memory_volatile(mem, first_entry, count, tmp);
    } else {
        rc = m_default_tr->read_memory(mem, first_entry, count, tmp);
    }
    return_on_error(rc);

    rc = m_default_tr->commit();

    // TODO: wait for completion of HW read

    if (rc == LA_STATUS_SUCCESS) {
        memcpy(out_val, tmp.byte_array(), std::min(tmp.get_width_in_bytes(), out_val_sz));
    }

    return rc;
}

la_status
ll_device_impl::read_memory(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv)
{
    start_lld_call(this);

    const lld_memory_desc_t* mdesc = mem.get_desc();

    // Check only stuff that directly applies to the creation of 'bit_vector tmp'.
    // Other things will be sanitized in ll_transaction::read_memory()
    if (!mem.is_valid() || !count) {
        log_err(ACCESS, "%s: invalid params, %s, %ld", __func__, mdesc->name.c_str(), count);
        return LA_STATUS_EINVAL;
    }

    la_status rc;

    if (mdesc->is_volatile()) {
        rc = m_default_tr->read_memory_volatile(mem, first_entry, count, out_bv);
    } else {
        rc = m_default_tr->read_memory(mem, first_entry, count, out_bv);
    }
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::read_memory_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv)
{
    start_lld_call(this);

    // Resize to the specified width
    out_bv.resize(width_bits);

    access_engine_uptr ae = reserve_access_engine();
    if (!ae) {
        return LA_STATUS_EBUSY;
    }
    la_status rc = do_read_memory_raw(
        ae.get(), block_id, addr, 0 /* first_entry */, out_bv.get_width_in_bytes(), 1 /* count */, out_bv.byte_array());
    release_access_engine(std::move(ae));

    return rc;
}

la_status
ll_device_impl::do_read_memory_raw(access_engine* ae,
                                   la_block_id_t block_id,
                                   la_entry_addr_t addr,
                                   la_entry_addr_t first_entry,
                                   la_entry_width_t width,
                                   size_t count,
                                   void* out_val)
{
    la_status rc;

    if (block_id == m_sbif_block_id) {
        rc = sbif_read_memory_entries(addr, first_entry, count, (uint32_t*)out_val);
    } else if (m_simulation_mode == simulation_mode_e::LBR) {
        rc = m_simulator->read_memory(block_id, addr + first_entry, width, count, out_val);
    } else {
        rc = do_read_ae(ae, block_id, addr + first_entry, width, count, false /* peek */, out_val);
    }

    auto level = rc ? la_logger_level_e::ERROR : la_logger_level_e::DEBUG;
    uint64_t* storage = (uint64_t*)out_val;
    log_message(la_logger_component_e::ACCESS,
                level,
                "read_memory: %s, block_id=0x%x, addr=0x%x, entry=0x%x, width=%d, count=%ld, val=0x%s, rc=%d",
                get_memory_name(block_id, addr).c_str(),
                block_id,
                addr,
                first_entry,
                width,
                count,
                bit_vector(storage, width * 8).to_string().c_str(),
                rc.value());

    return rc;
}

la_status
ll_device_impl::do_read_ae(access_engine* ae,
                           la_block_id_t block_id,
                           la_entry_addr_t addr,
                           la_entry_width_t width,
                           size_t count,
                           bool peek,
                           void* out_val)
{
    uint8_t* out_val_uint8 = (uint8_t*)out_val;
    uint32_t mem_size = ae->get_data_mem_entries_number();
    la_entry_width_t width_dwords = bit_utils::width_bytes_to_dwords(width);
    size_t max_lines_to_read = mem_size / width_dwords;

    dassert_crit(max_lines_to_read > 0);

    size_t remaining_lines = count;
    size_t current_line = 0;
    while (remaining_lines > 0) {

        size_t n_lines_to_read = std::min(max_lines_to_read, remaining_lines);
        uint32_t data_pos = 0;

        la_status rc = ae->read(block_id, addr + current_line, width, n_lines_to_read, peek, data_pos);
        return_on_error(rc);

        rc = ae->flush();
        return_on_error(rc);

        rc = ae->copy_read_result(data_pos, width, n_lines_to_read, (void*)(out_val_uint8 + current_line * width));
        return_on_error(rc);

        remaining_lines -= n_lines_to_read;
        current_line += n_lines_to_read;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::write_memory(const lld_memory& mem, size_t line, const bit_vector& in_bv)
{
    start_lld_call(this);

    la_status rc = m_default_tr->write_memory(mem, line, 1 /* count */, in_bv);
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::write_memory(const lld_memory_scptr& mem, size_t line, const bit_vector& in_bv)
{
    start_lld_call(this);

    return write_memory(*mem, line, in_bv);
}

la_status
ll_device_impl::write_memory(const lld_memory& mem, size_t first_entry, size_t count, size_t in_val_sz, const void* in_val)
{
    start_lld_call(this);

    const lld_memory_desc_t* mdesc = mem.get_desc();

    // Check only stuff that directly applies to the creation of 'bit_vector tmp'.
    // Other things will be sanitized in ll_transaction::write_memory()
    if (!mem.is_valid() || !count || !in_val_sz || !in_val) {
        log_err(ACCESS, "%s: invalid params, %s, %ld/%ld/%p", __func__, mdesc->name.c_str(), count, in_val_sz, in_val);
        return LA_STATUS_EINVAL;
    }
    if (count > 1 && in_val_sz != count * mdesc->width_total) {
        log_err(ACCESS,
                "%s: in buf size does not match, %s, sz %ld, count %ld, width %d",
                __func__,
                mdesc->name.c_str(),
                in_val_sz,
                count,
                mdesc->width_total);
        return LA_STATUS_ESIZE;
    }
    if (count == 1 && in_val_sz > mdesc->width_total) {
        // TODO: Currently, some tests provide input buffer wider than the memory
        // width!
        // Hopefully, this problem will be gone when we switch to bit_vector only.
        log_info(ACCESS,
                 "%s: in buf too big, %s, sz %ld, count %ld, width %d - resizing!",
                 __func__,
                 mdesc->name.c_str(),
                 in_val_sz,
                 count,
                 mdesc->width_total);
        in_val_sz = mdesc->width_total;
    }

    bit_vector tmp(in_val_sz, (const uint8_t*)in_val, 8 * count * mdesc->width_total);
    la_status rc = m_default_tr->write_memory(mem, first_entry, count, tmp);
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::do_write_register(access_engine* ae, const lld_register* reg, const bit_vector& in_val)
{
    const lld_register_desc_t* rd = reg->get_desc();
    const auto desc = reg->get_desc();
    size_t reg_width = desc->width_in_bits;

    const uint8_t* raw_data;
    bit_vector tmp_bv;
    if (in_val.get_width() == reg_width) {
        raw_data = in_val.byte_array();
    } else {
        tmp_bv = in_val;
        tmp_bv.resize(reg_width);
        raw_data = tmp_bv.byte_array();
    }

    // Update the shadow
    reg->write_shadow(rd->width, raw_data);
    if (!m_write_to_device) {
        log_debug(LLD, "%s: write_to_device is disabled. Skipping...", __func__);
        return LA_STATUS_SUCCESS;
    }

    // Actual writing
    la_status rc = do_write_register_raw(ae, reg->get_block_id(), rd->addr, rd->width, 1 /* count */, raw_data);

    return rc;
}

la_status
ll_device_impl::do_write_register_array(access_engine* ae,
                                        const lld_register_array_container* reg,
                                        const bit_vector& in_val,
                                        size_t first,
                                        size_t count)
{
    const lld_register_desc_t* rd = reg->get_desc();

    // Update the shadow
    reg->write_shadow(first, count, in_val.byte_array());
    if (!m_write_to_device) {
        log_debug(LLD, "%s: write_to_device is disabled. Skipping...", __func__);
        return LA_STATUS_SUCCESS;
    }

    // Actual writing
    return do_write_register_raw(ae, reg->get_block_id(), rd->addr + first, rd->width, count, in_val.byte_array());
}

la_status
ll_device_impl::do_read_register(access_engine* ae, const lld_register* reg, bool peek, bit_vector* out_val)
{
    const lld_register_desc_t* rd = reg->get_desc();

    if (!rd->is_volatile() && get_shadow_read_enabled()) {
        return reg->read_shadow(rd->width, out_val->byte_array());
    }

    la_status rc = do_read_register_raw(ae, reg->get_block_id(), rd->addr, rd->width, 1 /* count */, peek, out_val->byte_array());
    return_on_error(rc);

    if (!rd->is_volatile()) {
        // Non-volatile register and "read" was not terminated in shadow. Update the shadow with value fetched from HW.
        reg->write_shadow(rd->width, out_val->byte_array());
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::do_write_memory(access_engine* ae,
                                const lld_memory* mem,
                                la_entry_addr_t line,
                                size_t count,
                                const bit_vector& in_val)
{
    const lld_memory_desc_t* md = mem->get_desc();

    // Update the shadow
    mem->write_shadow(line, count, in_val.byte_array());
    if (!m_write_to_device) {
        log_debug(LLD, "%s: write_to_device is disabled. Skipping...", __func__);
        return LA_STATUS_SUCCESS;
    }

    // Actual writing
    return do_write_memory_raw(ae, mem->get_block_id(), md->addr, line, md->width_total, count, in_val.byte_array());
}

la_status
ll_device_impl::do_read_memory(access_engine* ae, const lld_memory* mem, la_entry_addr_t line, size_t count, bit_vector* out_val)
{
    const lld_memory_desc_t* md = mem->get_desc();

    if (!md->is_volatile() && get_shadow_read_enabled()) {
        return mem->read_shadow(line, count, out_val->byte_array());
    }

    la_status rc = do_read_memory_raw(ae, mem->get_block_id(), md->addr, line, md->width_total, count, out_val->byte_array());
    return_on_error(rc);

    if (!md->is_volatile()) {
        // Non-volatile memory and "read" was not terminated in shadow. Update the shadow with value fetched from HW.
        mem->write_shadow(line, count, out_val->byte_array());
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::do_read_modify_write_register(access_engine* ae,
                                              const lld_register* reg,
                                              size_t msb,
                                              size_t lsb,
                                              const bit_vector& in_val)
{
    const lld_register_desc_t* rd = reg->get_desc();
    la_block_id_t block_id = reg->get_block_id();
    bit_vector tmp_bv(0, rd->width_in_bits);

    // Read from HW
    la_status rc = do_read_register_raw(ae, block_id, rd->addr, rd->width, 1 /* count */, false /* peek */, tmp_bv.byte_array());
    if (rc) {
        return rc;
    }

    // Modify
    tmp_bv.set_bits(msb, lsb, in_val);

    // Write to shadow
    reg->write_shadow(rd->width, tmp_bv.byte_array());

    if (!m_write_to_device) {
        return LA_STATUS_SUCCESS;
    }

    // Write to HW
    return do_write_register_raw(ae, block_id, rd->addr, rd->width, 1 /* count */, tmp_bv.byte_array());
}

la_status
ll_device_impl::do_read_modify_write_memory(access_engine* ae,
                                            const lld_memory* mem,
                                            size_t line,
                                            size_t msb,
                                            size_t lsb,
                                            const bit_vector& in_val)
{
    const lld_memory_desc_t* md = mem->get_desc();
    la_block_id_t block_id = mem->get_block_id();
    bit_vector tmp_bv(0, md->width_total_bits);

    // Read from HW
    la_status rc = do_read_memory_raw(ae, block_id, md->addr, line, md->width_total, 1 /* count */, tmp_bv.byte_array());
    if (rc) {
        return rc;
    }

    // Modify
    tmp_bv.set_bits(msb, lsb, in_val);

    // Write to shadow
    mem->write_shadow(line, 1 /* count */, tmp_bv.byte_array());

    if (!m_write_to_device) {
        return LA_STATUS_SUCCESS;
    }

    // Write to HW
    return do_write_memory_raw(ae, block_id, md->addr, line, md->width_total, 1 /* count */, tmp_bv.byte_array());
}

la_status
ll_device_impl::write_memory_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, const bit_vector& in_bv)
{
    start_lld_call(this);

    log_debug(ACCESS, "write_memory_raw: block_id %d, addr 0x%x, width_bits %d", block_id, addr, width_bits);

    // Truncate/zero-pad to the specified width
    bit_vector bv(in_bv);
    bv.resize(width_bits);

    access_engine_uptr ae = reserve_access_engine();
    if (!ae) {
        return LA_STATUS_EBUSY;
    }
    la_status rc = do_write_memory_raw(
        ae.get(), block_id, addr, 0 /* first_entry*/, bv.get_width_in_bytes(), 1 /* count */, bv.byte_array());
    release_access_engine(std::move(ae));

    return rc;
}

la_status
ll_device_impl::do_write_memory_raw(access_engine* ae,
                                    la_block_id_t block_id,
                                    la_entry_addr_t addr,
                                    la_entry_addr_t first_entry,
                                    la_entry_width_t width,
                                    size_t count,
                                    const uint8_t* in_val)
{
    la_status rc;

    log_debug(ACCESS,
              "write_memory: %s, block_id=0x%x, addr=0x%x, entry=0x%x, width=%d, count=%ld, val=0x%s",
              get_memory_name(block_id, addr).c_str(),
              block_id,
              addr,
              first_entry,
              width,
              count,
              bit_vector(count * width, in_val, count * width * bit_vector::BV_BITS_IN_BYTE).to_string().c_str());

    if (block_id == m_sbif_block_id) {
        rc = sbif_write_memory_entries(addr, first_entry, count, (const uint32_t*)in_val);
    } else if (m_simulation_mode == simulation_mode_e::LBR) {
        m_simulator->write_memory(block_id, addr + first_entry, width, count, in_val);
        // TODO: for testing only!!!!!!
        rc = LA_STATUS_SUCCESS;
    } else {
        rc = ae->write(block_id, addr + first_entry, width, count, in_val);
        if (m_flush_after_write && !rc) {
            rc = ae->flush();
        }
    }

    if (rc) {
        log_err(ACCESS,
                "write_memory: %s, block_id=0x%x, addr=0x%x, entry=0x%x, width=%d, count=%ld, val=0x%s, rc=%d",
                get_memory_name(block_id, addr).c_str(),
                block_id,
                addr,
                first_entry,
                width,
                count,
                bit_vector(count * width, in_val, count * width * bit_vector::BV_BITS_IN_BYTE).to_string().c_str(),
                rc.value());
    }

    return rc;
}

la_status
ll_device_impl::fill_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_bv)
{
    if (mem.get_block()->get_revision() != get_device_revision()) {
        log_debug(ACCESS, "%s: %s - skip due to device revision mismatch", __func__, mem.get_name().c_str());
        return LA_STATUS_SUCCESS;
    }

    start_lld_call(this);

    if (!mem.is_valid()) {
        log_err(ACCESS, "%s: %s is invalid", __func__, mem.get_name().c_str());
        return LA_STATUS_EINVAL;
    }

    const lld_memory_desc_t* mdesc = mem.get_desc();
    if (first_entry + count > mdesc->entries) {
        log_err(ACCESS, "%s: out of range, %s, first_entry=%ld, count=%ld", __func__, mem.get_name().c_str(), first_entry, count);
        return LA_STATUS_EOUTOFRANGE;
    }

    if (in_bv.get_width() > mdesc->width_total_bits) {
        log_err(ACCESS,
                "%s: %s, value too wide, width=%ld, entry width=%d",
                __func__,
                mem.get_name().c_str(),
                in_bv.get_width(),
                mdesc->width_total_bits);
        return LA_STATUS_ESIZE;
    }

    la_status rc;
    if (in_bv.get_width() < mdesc->width_total_bits) {
        bit_vector tmp(in_bv);
        tmp.resize(mdesc->width_total_bits);

        mem.fill_shadow(first_entry, count, tmp);
        rc = do_fill_memory(mem.get_block_id(), mdesc->addr + first_entry, mdesc->width_total, count, tmp);
    } else {
        mem.fill_shadow(first_entry, count, in_bv);
        rc = do_fill_memory(mem.get_block_id(), mdesc->addr + first_entry, mdesc->width_total, count, in_bv);
    }

    return rc;
}

la_status
ll_device_impl::do_fill_memory(la_block_id_t block_id,
                               la_entry_addr_t addr,
                               la_entry_width_t width_bytes,
                               size_t count,
                               const bit_vector& in_bv)
{
    la_status rc;

    access_engine_uptr ae = reserve_access_engine();
    if (!ae) {
        return LA_STATUS_EBUSY;
    }

    if (block_id == m_sbif_block_id || m_simulation_mode == simulation_mode_e::LBR) {
        rc = LA_STATUS_SUCCESS;
        for (size_t i = 0; i < count && !rc; ++i) {
            rc = do_write_memory_raw(ae.get(), block_id, addr, i, width_bytes, 1 /* count */, in_bv.byte_array());
        }
    } else if (m_write_to_device) {
        rc = ae->write_fill(block_id, addr, width_bytes, count, in_bv.byte_array());
        if (m_flush_after_write && !rc) {
            rc = ae->flush();
        }
    } else {
        rc = LA_STATUS_SUCCESS;
    }

    release_access_engine(std::move(ae));

    auto level = rc ? la_logger_level_e::ERROR : la_logger_level_e::DEBUG;
    log_message(la_logger_component_e::ACCESS,
                level,
                "fill_memory: %s, block_id=0x%x, addr=0x%x, entry=0x%x, width=%d, count=%ld, val=0x%s, rc=%d",
                get_memory_name(block_id, addr).c_str(),
                block_id,
                addr,
                0,
                width_bytes,
                count,
                in_bv.to_string().c_str(),
                rc.value());

    return rc;
}

la_status
ll_device_impl::read_modify_write_memory(const lld_memory& mem, size_t line, size_t msb, size_t lsb, const bit_vector& value)
{
    start_lld_call(this);

    la_status rc = m_default_tr->read_modify_write_memory(mem, line, msb, lsb, value);
    return_on_error(rc);

    return m_default_tr->commit();
}

//-----------------------------------------------------------------------------
// TCAMs
//-----------------------------------------------------------------------------

la_status
ll_device_impl::read_tcam(lld_memory const& tcam,
                          size_t tcam_line,
                          bit_vector& out_key_bv,
                          bit_vector& out_mask_bv,
                          bool& out_valid)
{
    start_lld_call(this);

    la_status rc = m_default_tr->read_tcam(tcam, tcam_line, out_key_bv, out_mask_bv, out_valid);
    return_on_error(rc);

    return m_default_tr->commit();
}

ll_device::access_desc
ll_device_impl::make_read_tcam(lld_memory const& tcam,
                               size_t tcam_line,
                               bit_vector& out_key_bv,
                               bit_vector& out_mask_bv,
                               bool& out_valid)
{
    la_status rc;
    const lld_memory_desc_t* mdesc = tcam.get_desc();

    switch (mdesc->subtype) {
    case lld_memory_subtype_e::X_Y_TCAM:
        rc = do_read_xy_tcam(tcam, tcam_line, out_key_bv, out_mask_bv, out_valid);
        break;
    case lld_memory_subtype_e::KEY_MASK_TCAM:
        rc = do_read_key_mask_tcam(tcam, tcam_line, out_key_bv, out_mask_bv, out_valid);
        break;
    case lld_memory_subtype_e::REG_TCAM:
        rc = do_read_reg_tcam(tcam, tcam_line, out_key_bv, out_mask_bv, out_valid);
        break;
    default:
        rc = LA_STATUS_ENOTIMPLEMENTED;
        break;
    }

    auto level = rc ? la_logger_level_e::ERROR : la_logger_level_e::DEBUG;
    log_message(la_logger_component_e::ACCESS,
                level,
                "read_tcam: %s, line=%ld, key=0x%s, mask=0x%s, valid=%d, rc=%d",
                tcam.get_name().c_str(),
                tcam_line,
                out_key_bv.to_string().c_str(),
                out_mask_bv.to_string().c_str(),
                out_valid,
                rc.value());

    return access_desc{.action = access_desc::operation_e::INVALID};
}

la_status
ll_device_impl::read_tcam(lld_memory const& tcam,
                          size_t tcam_line,
                          size_t key_mask_sz,
                          void*& out_key,
                          void*& out_mask,
                          bool& out_valid)
{
    start_lld_call(this);

    if (!key_mask_sz || !out_key || !out_mask) {
        return LA_STATUS_EINVAL;
    }

    bit_vector out_key_bv;
    bit_vector out_mask_bv;

    la_status ret = read_tcam(tcam, tcam_line, out_key_bv, out_mask_bv, out_valid);
    return_on_error(ret);

    if (out_key_bv.get_width_in_bytes() > key_mask_sz) {
        return LA_STATUS_EINVAL;
    }

    memset(out_key, 0, key_mask_sz);
    memcpy(out_key, out_key_bv.byte_array(), out_key_bv.get_width_in_bytes());

    memset(out_mask, 0, key_mask_sz);
    memcpy(out_mask, out_mask_bv.byte_array(), out_mask_bv.get_width_in_bytes());

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::write_tcam(const lld_memory& tcam, size_t tcam_line, const bit_vector& in_key_bv, const bit_vector& in_mask_bv)
{
    start_lld_call(this);

    la_status rc = m_default_tr->write_tcam(tcam, tcam_line, in_key_bv, in_mask_bv);
    return_on_error(rc);

    return m_default_tr->commit();
}

ll_device::access_desc
ll_device_impl::make_write_tcam(const lld_memory& tcam, size_t tcam_line, const bit_vector& in_key_bv, const bit_vector& in_mask_bv)
{
    const lld_memory_desc_t* mdesc = tcam.get_desc();

    log_debug(ACCESS,
              "write_tcam: %s, line=%ld, key=0x%s, mask=0x%s",
              tcam.get_name().c_str(),
              tcam_line,
              in_key_bv.to_string().c_str(),
              in_mask_bv.to_string().c_str());

    switch (mdesc->subtype) {
    case lld_memory_subtype_e::X_Y_TCAM:
        return make_write_xy_tcam(tcam, tcam_line, in_key_bv, in_mask_bv);
    case lld_memory_subtype_e::KEY_MASK_TCAM:
        return make_write_key_mask_tcam(tcam, tcam_line, in_key_bv, in_mask_bv);
    case lld_memory_subtype_e::REG_TCAM:
        return make_write_reg_tcam(tcam, tcam_line, in_key_bv, in_mask_bv);
    default:
        break;
    }

    log_err(ACCESS, "write_tcam: %s, not implemented for subtype=%d", mdesc->name.c_str(), (int)mdesc->subtype);

    access_desc ad = {.action = access_desc::operation_e::INVALID};

    return ad;
}

la_status
ll_device_impl::write_tcam(const lld_memory& tcam, size_t tcam_line, size_t key_mask_sz, const void* in_key, const void* in_mask)
{
    start_lld_call(this);

    if (!key_mask_sz || !in_key || !in_mask) {
        return LA_STATUS_EINVAL;
    }

    bit_vector in_key_bv(key_mask_sz, (const uint8_t*)in_key, 1 /*min width*/);
    bit_vector in_mask_bv(key_mask_sz, (const uint8_t*)in_mask, 1 /*min width*/);

    return write_tcam(tcam, tcam_line, in_key_bv, in_mask_bv);
}

la_status
ll_device_impl::invalidate_tcam(const lld_memory& tcam, size_t tcam_line)
{
    start_lld_call(this);

    la_status rc = m_default_tr->invalidate_tcam(tcam, tcam_line);
    return_on_error(rc);

    return m_default_tr->commit();
}

void
ll_device_impl::set_tcam_shadow_valid_bit(const lld_memory& tcam, size_t tcam_phys_line, bit_vector tcam_line_bv, bool valid_bit)
{
    tcam_line_bv.set_bit(tcam_line_bv.get_width() - 1, valid_bit);
    tcam.write_shadow(tcam_phys_line, 1 /* count */, tcam_line_bv.byte_array());
}

ll_device::access_desc
ll_device_impl::make_invalidate_tcam(const lld_memory& tcam, size_t tcam_line)
{
    const lld_memory_desc_t* mdesc = tcam.get_desc();

    log_debug(ACCESS, "invalidate_tcam: %s, line=%ld", tcam.get_name().c_str(), tcam_line);

    switch (mdesc->subtype) {
    case lld_memory_subtype_e::X_Y_TCAM:
        return make_invalidate_xy_tcam(tcam, tcam_line);
    case lld_memory_subtype_e::KEY_MASK_TCAM:
        return make_invalidate_key_mask_tcam(tcam, tcam_line);
    case lld_memory_subtype_e::REG_TCAM:
        return make_invalidate_reg_tcam(tcam, tcam_line);
    default:
        break;
    }

    log_err(ACCESS, "invalidate_tcam: %s, not implemented for subtype=%d", mdesc->name.c_str(), (int)mdesc->subtype);

    access_desc ad = {.action = access_desc::operation_e::INVALID};

    return ad;
}

// XY-TCAM access
// ------------------
//
// Pacific uses an X/Y TCAM implementation.
// Given a (key, mask) pair, we define the following:
//
// x = ( key & mask)
// y = (~key & mask)
//
// Each part (x, y) is written separately, so writing a logical TCAM line is not
// atomic.
// Each logical line (key, mask) is implemented as two HW lines. Inserting (key,
// mask) to a logical line N, will result in:
// - x-value stored at line 2*N
// - y-value stored at line 2*N+1
//
// Memory layout for a read/write operation is as follows:
//
// lsb
// +-------------+------------+
// |    value    |  is_delete |
// +-------------+------------+
//     key width   1 bit
//
// For writes, is_delete selects whether an operation writes a new value
// (is_delete=0) or invalidates both rows (is_delete=1).
// The logical line gets invalid, if any is_delete=1 is written to any of x or y
// rows.
//
// A row becomes active (enabled) whenever its Y field is updated.
//
// Note: it's impossible to reconstruct full key, reading from TCAM. Only
// non-masked portion of the key is returned.
la_status
ll_device_impl::do_read_xy_tcam(lld_memory const& tcam,
                                size_t tcam_line,
                                bit_vector& out_key_bv,
                                bit_vector& out_mask_bv,
                                bool& out_valid)
{
    const lld_memory_desc_t* mdesc = tcam.get_desc();
    la_status rc;

    // Each entry takes two lines.
    size_t tcam_phys_line = tcam_line * 2;

    // X bits & Y bits
    bit_vector x_bv(0, mdesc->width_total_bits);
    bit_vector y_bv(0, mdesc->width_total_bits);

    rc = read_memory(tcam, tcam_phys_line, x_bv);
    rc = rc ?: read_memory(tcam, tcam_phys_line + 1, y_bv);
    if (rc) {
        log_err(
            ACCESS, "read_xy_tcam: tcam=%s, line=%ld, rc=%s", tcam.get_name().c_str(), tcam_phys_line, la_status2str(rc).c_str());
        return rc;
    }

    // Check if line is valid, read the 'delete/valid' bit
    out_valid = y_bv.bit(mdesc->width_total_bits - 1);
    if (get_shadow_read_enabled()) {
        // In HW, reading '1' means valid. In shadow, '1' means invalidated.
        out_valid = !out_valid;
    } else {
        // In case when test device is used, out_valid needs to be flipped as well
        if (is_simulated_device()) {
            out_valid = !out_valid;
        }
        // Flip the TCAM valid/delete bit in shadow, so that the valid bit is consistent.
        set_tcam_shadow_valid_bit(tcam, tcam_phys_line + 1, y_bv, !out_valid);
    }

    if (!out_valid) {
        return LA_STATUS_SUCCESS;
    }

    // Clear the 'delete/valid' bit, it is not part of the value
    x_bv.set_bit(mdesc->width_total_bits - 1, 0);
    y_bv.set_bit(mdesc->width_total_bits - 1, 0);

    // Xbits = key & mask
    // Ybits = ~key & mask
    // therefore
    // mask = Xbits | Ybits = key & mask + ~key & mask = mask & (key | ~key)
    // key = Xbits
    out_key_bv = x_bv;
    out_mask_bv = x_bv | y_bv;

    return LA_STATUS_SUCCESS;
}

ll_device::access_desc
ll_device_impl::make_write_xy_tcam(const lld_memory& tcam,
                                   size_t tcam_line,
                                   const bit_vector& in_key_bv,
                                   const bit_vector& in_mask_bv)
{

    const lld_memory_desc_t* mdesc = tcam.get_desc();

    // Each entry takes two lines.
    la_entry_addr_t tcam_phys_line = tcam_line * 2;

    // Xbits = key & mask
    bit_vector x_bv(in_key_bv);
    x_bv.resize(mdesc->width_total_bits);
    x_bv &= in_mask_bv;
    // turn off is_delete bit
    x_bv.set_bit(mdesc->width_total_bits - 1, false);

    // Ybits = ~key & mask
    bit_vector y_bv(in_key_bv);
    y_bv.resize(mdesc->width_total_bits);
    y_bv.negate();
    y_bv &= in_mask_bv;
    // turn off is_delete bit
    y_bv.set_bit(mdesc->width_total_bits - 1, false);

    // Double the size of x_bv (the original value remains in the lower half)
    x_bv.resize(mdesc->width_total * 8 * 2);
    size_t y_lsb = mdesc->width_total * 8;
    size_t y_msb = y_lsb + mdesc->width_total_bits - 1;
    // Emplace y_bv in the higher half of the bit_vector
    x_bv.set_bits(y_msb, y_lsb, y_bv);

    // Update two lines in shadow
    tcam.write_shadow(tcam_phys_line, 2 /* count */, x_bv.byte_array());
    if (!m_write_to_device) {
        return access_desc{.action = access_desc::operation_e::INVALID};
    }

    // Write to HW descriptor
    access_desc ad = {
        .action = access_desc::operation_e::WRITE_MEMORY,
        .out_val = nullptr,
        .in_val = x_bv,
        .reg = nullptr,
        .mem = &tcam,
        .reg_array = nullptr,
        .first = tcam_phys_line,
        .count = 2,
    };

    return ad;
}

ll_device::access_desc
ll_device_impl::make_invalidate_xy_tcam(const lld_memory& tcam, size_t tcam_line)
{
    const lld_memory_desc_t* mdesc = tcam.get_desc();

    // Each entry takes two lines.
    // Valid bit is meaningfull only on second line.
    size_t tcam_phys_line = tcam_line * 2 + 1;

    bit_vector invalid_bit(0, mdesc->width_total_bits);
    // invalid bit is right after the value
    invalid_bit.set_bit(mdesc->width_total_bits - 1, true);

    return make_write_memory(tcam, tcam_phys_line, 1 /* count */, invalid_bit);
}

// KEY-MASK-TCAM access
// --------------------
//
// Gibraltar uses a KEY-MASK TCAM implementation.
//
// Each part (key, mask) is written separately, so writing a logical TCAM line is not
// atomic.
// Each logical line (key, mask) is implemented as two HW lines. Inserting (key,
// mask) to a logical line N, will result in:
// - mask is stored at line 2*N
// - key  is stored at line 2*N+1
//
// Memory layout for a *write* operation is as follows:
// lsb
// +-------------+------------+
// |    value    |  is_delete |
// +-------------+------------+
//    key width      1 bit
// Each writing operation will write either (is_delete, key) or (is_delete, mask)
// So, if we write a new entry, and we write the mask first then the key, we must write
// the entries: (1, mask) then write (0, key) to make sure the entry is invalid before
// completing writing both the key and the mask.
//
// Memory layout for a *read* operation is as follows:
// lsb
// +-------------+------------+
// |    value    |  is_valid  |
// +-------------+------------+
//     key width   1 bit
// Each reading operation will return (is_valid, key) or (is_valid, mask)
// If is_valis is not set, then this entry is invalid.
//

la_status
ll_device_impl::do_read_key_mask_tcam(lld_memory const& tcam,
                                      size_t tcam_line,
                                      bit_vector& out_key_bv,
                                      bit_vector& out_mask_bv,
                                      bool& out_valid)
{
    if (tcam.get_block()->get_revision() != get_device_revision()) {
        return LA_STATUS_SUCCESS;
    }

    const lld_memory_desc_t* mdesc = tcam.get_desc();
    la_status rc;

    // Each entry takes two lines.
    size_t tcam_phys_line = tcam_line * 2;
    bit_vector key_bv(0, mdesc->width_total_bits);
    bit_vector mask_bv(0, mdesc->width_total_bits);

    rc = read_memory(tcam, tcam_phys_line, mask_bv);
    rc = rc ?: read_memory(tcam, tcam_phys_line + 1, key_bv);
    if (rc) {
        log_err(ACCESS,
                "read_key_mask_tcam: tcam=%s, line=%ld, rc=%s",
                tcam.get_name().c_str(),
                tcam_phys_line,
                la_status2str(rc).c_str());
        return rc;
    }

    // Check if line is valid, read the 'delete/valid' bit
    out_valid = key_bv.bit(mdesc->width_total_bits - 1);

    if (get_shadow_read_enabled()) {
        // In HW, reading '1' means valid. In shadow, '1' means invalidated.
        out_valid = !out_valid;
    } else {
        // In case when test device is used, out_valid needs to be flipped as well
        if (is_simulated_device()) {
            out_valid = !out_valid;
        }
        // Flip the TCAM valid/delete bit in shadow, so that the valid bit is consistent.
        set_tcam_shadow_valid_bit(tcam, tcam_phys_line + 1, key_bv, !out_valid);
    }

    if (!out_valid) {
        return LA_STATUS_SUCCESS;
    }

    // Clear the 'delete/valid' bit, it is not part of the value
    key_bv.set_bit(mdesc->width_total_bits - 1, 0);
    mask_bv.set_bit(mdesc->width_total_bits - 1, 0);

    // tcam_key = key & mask
    // tcam_mask = ~key & mask
    // therfore
    // out_mask_bv = tcam_key | tcam_mask = key & mask | ~key & mask = mask & (key | ~key) = mask
    // key can't be fully reconstructed from TCAM key as it's already masked with mask
    // out_key_bv = tcam_key = key & mask
    out_key_bv = key_bv;
    out_mask_bv = key_bv | mask_bv;

    return LA_STATUS_SUCCESS;
}

ll_device::access_desc
ll_device_impl::make_write_key_mask_tcam(const lld_memory& tcam,
                                         size_t tcam_line,
                                         const bit_vector& in_key_bv,
                                         const bit_vector& in_mask_bv)
{

    const lld_memory_desc_t* mdesc = tcam.get_desc();

    // Each entry takes two lines.
    la_entry_addr_t tcam_phys_line = tcam_line * 2;

    // The logic for this Tcam is as follows (Quite similar to x/y Tcam):
    //  Key = in_key & mask_n
    //  Delete = false
    bit_vector key_bv(in_key_bv);
    key_bv.resize(mdesc->width_total_bits);
    key_bv &= in_mask_bv;
    key_bv.set_bit(mdesc->width_total_bits - 1, false);

    //  Mask = ~in_key & mask_n
    //  Delete = false
    bit_vector key_n_bv(in_key_bv);
    key_n_bv.resize(mdesc->width_total_bits);
    key_n_bv.negate();

    bit_vector mask_bv(in_mask_bv);
    mask_bv.resize(mdesc->width_total_bits);
    mask_bv &= key_n_bv;

    mask_bv.set_bit(mdesc->width_total_bits - 1, true);

    bit_vector whole_line_value(0, mdesc->width_total * 8 * 2);
    // mask is in LSB bits because it is written in tcam_phys_line
    whole_line_value.set_bits(mdesc->width_total_bits - 1, 0, mask_bv);
    // key is in MSB bits because it is written in tcam_phys_line+1
    size_t key_lsb = mdesc->width_total * 8;
    size_t key_msb = key_lsb + mdesc->width_total_bits - 1;
    whole_line_value.set_bits(key_msb, key_lsb, key_bv);

    // Update two lines in shadow
    tcam.write_shadow(tcam_phys_line, 2 /* count */, whole_line_value.byte_array());
    if (!m_write_to_device) {
        return access_desc{.action = access_desc::operation_e::INVALID};
    }

    // Write to HW descriptor
    access_desc ad = {
        .action = access_desc::operation_e::WRITE_MEMORY,
        .out_val = nullptr,
        .in_val = whole_line_value,
        .reg = nullptr,
        .mem = &tcam,
        .reg_array = nullptr,
        .first = tcam_phys_line,
        .count = 2,
    };

    return ad;
}

ll_device::access_desc
ll_device_impl::make_invalidate_key_mask_tcam(const lld_memory& tcam, size_t tcam_line)
{
    const lld_memory_desc_t* mdesc = tcam.get_desc();

    // Each entry takes two lines.
    // It is enough to write either the key or the mask with is_delete=1. Here we write the key
    la_entry_addr_t tcam_phys_line = tcam_line * 2;

    bit_vector invalidate_entry_key(0, mdesc->width_total * 8 * 2);
    // Write is_delete bit of mask.
    invalidate_entry_key.set_bit(mdesc->width_total_bits - 1, 1);
    // Write is_delete bit of key.
    size_t key_msb = mdesc->width_total * 8 + mdesc->width_total_bits - 1;
    invalidate_entry_key.set_bit(key_msb, 1);

    // Write to HW descriptor
    access_desc ad = {
        .action = access_desc::operation_e::WRITE_MEMORY,
        .out_val = nullptr,
        .in_val = invalidate_entry_key,
        .reg = nullptr,
        .mem = &tcam,
        .reg_array = nullptr,
        .first = tcam_phys_line,
        .count = 2,
    };

    return ad;
}

// Register TCAM access
// -----------------------------------
//
// Register Tcam memory is used only in NPE blocks, only for internal tables.
// As opposed to X-Y Tcam, where the access is done in two subsequent rows, in
// register TCAM, access is done in one row.
//
// Memory layout for a read/write operation is as follows:
//
// lsb
// +---------- ---+-----  -------+------------+
// |    mask     |  mask & key |  is_delete |
// +------------ -+---  ---------+------------+
//     key width     key_width       1 bit

la_status
ll_device_impl::do_read_reg_tcam(const lld_memory& tcam,
                                 size_t tcam_line,
                                 bit_vector& out_key,
                                 bit_vector& out_mask,
                                 bool& out_valid)
{
    const lld_memory_desc_t* mdesc = tcam.get_desc();
    bit_vector payload(0, mdesc->width_total_bits);
    la_status rc = read_memory(tcam, tcam_line, payload);
    if (rc) {
        log_err(ACCESS, "read_reg_tcam: tcam=%s, line=%ld, rc=%s", tcam.get_name().c_str(), tcam_line, la_status2str(rc).c_str());
        return rc;
    }

    // Check if line is valid, read the 'delete/valid' bit
    out_valid = payload.bit(mdesc->width_total_bits - 1);
    if (get_shadow_read_enabled()) {
        // In HW, reading '1' means valid. In shadow, '1' means invalidated.
        out_valid = !out_valid;
    } else {
        // In case when test device is used, out_valid needs to be flipped as well
        if (is_simulated_device()) {
            out_valid = !out_valid;
        }
        // Flip the TCAM valid/delete bit in shadow, so that the valid bit is consistent.
        set_tcam_shadow_valid_bit(tcam, tcam_line, payload, !out_valid);
    }

    if (!out_valid) {
        return LA_STATUS_SUCCESS;
    }

    // Clear the 'delete/valid' bit, it is not part of the value
    payload.set_bit(mdesc->width_total_bits - 1, 0);

    size_t key_width = mdesc->width_bits;
    size_t mask_msb = key_width - 1;
    size_t key_msb = 2 * key_width - 1;

    out_key = payload.bits(key_msb, mask_msb + 1);
    out_mask = payload.bits(mask_msb, 0);

    return LA_STATUS_SUCCESS;
}

ll_device::access_desc
ll_device_impl::make_write_reg_tcam(const lld_memory& tcam, size_t tcam_line, const bit_vector& key, const bit_vector& mask)
{
    const lld_memory_desc_t* mdesc = tcam.get_desc();

    size_t key_width = mdesc->width_bits;
    size_t mask_msb = key_width - 1;
    size_t key_msb = mask_msb + key_width;

    bit_vector payload(0, mdesc->width_total_bits);
    payload.set_bits(mask_msb, 0, mask);
    payload.set_bits(key_msb, mask_msb + 1, key & mask);
    // turn off the invalidate bit
    payload.set_bit(key_msb + 1, false /*bit value*/);

    return make_write_memory(tcam, tcam_line, 1 /* count */, payload);
}

ll_device::access_desc
ll_device_impl::make_invalidate_reg_tcam(const lld_memory& tcam, size_t tcam_line)
{
    const lld_memory_desc_t* mdesc = tcam.get_desc();

    bit_vector payload(0, mdesc->width_total_bits);
    // turn on the invalidate bit
    payload.set_bit(mdesc->width_total_bits - 1, true /*bit value*/);

    return make_write_memory(tcam, tcam_line, 1 /* count */, payload);
}

//---------------------------------------------------------------
// ll_device::read/write API - uses the default transaction.
//---------------------------------------------------------------
la_status
ll_device_impl::read_register(const lld_register& reg, bit_vector& out_bv)
{
    start_lld_call(this);

    la_status rc;

    if (reg.get_desc()->is_volatile()) {
        rc = m_default_tr->read_register_volatile(reg, false /* peek */, out_bv);
    } else {
        rc = m_default_tr->read_register(reg, out_bv);
    }
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::read_register(const lld_register_scptr& reg, bit_vector& out_bv)
{
    start_lld_call(this);

    return read_register(*reg, out_bv);
}

la_status
ll_device_impl::peek_register(const lld_register& reg, bit_vector& out_bv)
{
    start_lld_call(this);

    la_status rc;

    if (reg.get_desc()->is_volatile()) {
        rc = m_default_tr->read_register_volatile(reg, true /* peek */, out_bv);
    } else {
        rc = m_default_tr->read_register(reg, out_bv);
    }
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::peek_register(const lld_register_scptr& reg, bit_vector& out_bv)
{
    start_lld_call(this);

    return peek_register(*reg, out_bv);
}

static la_status
read_register_sanity(const lld_register& reg, size_t out_val_sz, void* out_val)
{
    if (!reg.is_valid() || !out_val_sz || !out_val) {
        log_err(ACCESS, "%s: invalid params, %d/%ld/%p", __func__, reg.is_valid(), out_val_sz, out_val);
        return LA_STATUS_EINVAL;
    }
    if (out_val_sz < reg.get_desc()->width) {
        log_err(ACCESS, "%s: out buf too small, %ld/%d", __func__, out_val_sz, reg.get_desc()->width);
        return LA_STATUS_ESIZE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ll_device_impl::read_register(const lld_register& reg, size_t out_val_sz, void* out_val)
{
    start_lld_call(this);

    la_status rc = read_register_sanity(reg, out_val_sz, out_val);
    if (rc) {
        return rc;
    }

    bit_vector tmp;
    rc = read_register(reg, tmp);
    if (!rc) {
        memcpy(out_val, tmp.byte_array(), tmp.get_width_in_bytes());
    }

    return rc;
}

la_status
ll_device_impl::peek_register(const lld_register& reg, size_t out_val_sz, void* out_val)
{
    start_lld_call(this);

    la_status rc = read_register_sanity(reg, out_val_sz, out_val);
    if (rc) {
        return rc;
    }

    bit_vector tmp;
    rc = peek_register(reg, tmp);
    if (!rc) {
        memcpy(out_val, tmp.byte_array(), tmp.get_width_in_bytes());
    }

    return rc;
}

la_status
ll_device_impl::write_register(const lld_register& reg, const bit_vector& in_bv)
{
    start_lld_call(this);

    bool is_match = is_matching_device_revision(this, reg);
    if (!is_match) {
        log_debug(ACCESS, "%s: dev revision mismatch, %s", __func__, reg.get_name().c_str());
        return LA_STATUS_SUCCESS;
    }

    la_status rc = validate_params(__PRETTY_FUNCTION__, reg, -1 /* is_volatile */, true);
    return_on_error(rc);

    access_engine_uptr ae_ptr = reserve_access_engine();
    if (!ae_ptr) {
        return LA_STATUS_EBUSY;
    }

    rc = do_write_register(ae_ptr.get(), &reg, in_bv);

    release_access_engine(std::move(ae_ptr));

    return rc;
}

la_status
ll_device_impl::write_register(const lld_register_scptr& reg, const bit_vector& in_bv)
{
    start_lld_call(this);

    return write_register(*reg, in_bv);
}

la_status
ll_device_impl::write_register(const lld_register& reg, size_t in_val_sz, const void* in_val)
{
    start_lld_call(this);

    bool is_match = is_matching_device_revision(this, reg);
    if (!is_match) {
        log_debug(ACCESS, "%s: dev revision mismatch, %s", __func__, reg.get_name().c_str());
        return LA_STATUS_SUCCESS;
    }

    la_status rc = validate_params(__PRETTY_FUNCTION__, reg, -1 /* is_volatile */, true);
    return_on_error(rc);

    if (!reg.is_valid() || !in_val_sz || !in_val) {
        log_err(ACCESS, "%s: invalid params, %d/%ld/%p", __func__, reg.is_valid(), in_val_sz, in_val);
        return LA_STATUS_EINVAL;
    }

    // TODO: Currently, many tests provide input buffer wider than the register
    // width!
    // Hopefully, this problem will be gone when we switch to bit_vector only.
    if (in_val_sz > reg.get_desc()->width) {
        log_info(ACCESS,
                 "%s: in buf too big, %s, %ld/%d - resizing!",
                 __func__,
                 reg.get_desc()->name.c_str(),
                 in_val_sz,
                 reg.get_desc()->width);
    }

    access_engine_uptr ae_ptr = reserve_access_engine();
    if (!ae_ptr) {
        return LA_STATUS_EBUSY;
    }

    bit_vector tmp_bv(in_val_sz, (const uint8_t*)in_val, reg.get_desc()->width_in_bits);
    rc = do_write_register(ae_ptr.get(), &reg, tmp_bv);

    release_access_engine(std::move(ae_ptr));

    return rc;
}

la_status
ll_device_impl::write_register_array(const lld_register_array_container& reg, size_t first, size_t count, const bit_vector& in_bv)
{
    start_lld_call(this);

    bool is_match = is_matching_device_revision(this, *reg[0]);
    if (!is_match) {
        return LA_STATUS_SUCCESS;
    }

    la_status rc = validate_params(__PRETTY_FUNCTION__, reg, -1 /* is_volatile */, true);
    return_on_error(rc);

    access_engine_uptr ae_ptr = reserve_access_engine();
    if (!ae_ptr) {
        return LA_STATUS_EBUSY;
    }

    const lld_register_desc_t* rdesc = reg.get_desc();
    size_t width_bytes = rdesc->width * 8 * rdesc->instances;
    if (in_bv.get_width() > width_bytes) {
        log_err(LLD,
                "%s: in buf too big, %s, val width %ld, reg width %d",
                __func__,
                rdesc->name.c_str(),
                in_bv.get_width(),
                rdesc->width_in_bits);
        return LA_STATUS_ESIZE;
    }

    if (first + count > reg.size()) {
        log_err(ACCESS,
                "%s first: %lu + count: %lu = %lu is bigger than the register array capacity : %lu",
                __func__,
                first,
                count,
                first + count,
                reg.size());
        return LA_STATUS_ESIZE;
    }

    rc = do_write_register_array(ae_ptr.get(), &reg, in_bv, first, count);

    release_access_engine(std::move(ae_ptr));

    return rc;
}

la_status
ll_device_impl::delay(uint64_t cycles)
{
    start_lld_call(this);

    la_status rc = m_default_tr->delay(cycles);
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask)
{
    start_lld_call(this);

    la_status rc = m_default_tr->wait_for_value(reg, equal, val, mask);
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask)
{
    start_lld_call(this);

    la_status rc = m_default_tr->wait_for_value(mem, line, equal, val, mask);
    return_on_error(rc);

    return m_default_tr->commit();
}

la_status
ll_device_impl::refresh_memory(const lld_memory& mem, size_t line)
{
    if (mem.get_block()->get_revision() != get_device_revision()) {
        return LA_STATUS_SUCCESS;
    }

    start_lld_call(this);

    uint32_t width_total_bits = mem.get_desc()->width_total_bits;
    bit_vector bv(0, width_total_bits);
    mem.read_shadow(line, 1 /* count */, bv.byte_array());
    la_status rc = write_memory_raw(mem.get_block_id(), mem.get_desc()->addr + line, width_total_bits, bv);

    return rc;
}

//---------------------------------------------------------------
// Transaction access descriptors
//---------------------------------------------------------------
ll_device::access_desc
ll_device_impl::make_read_register(const lld_register& reg, bool peek, bit_vector& out_bv)
{
    // out_bv is already resized
    access_desc::operation_e op = peek ? access_desc::operation_e::PEEK_REGISTER : access_desc::operation_e::READ_REGISTER;
    access_desc ad = {
        .action = op, .out_val = &out_bv, .in_val = bit_vector(), .reg = &reg,
    };

    return ad;
}

ll_device::access_desc
ll_device_impl::make_write_register(const lld_register& reg, const bit_vector& in_val)
{
    access_desc ad = {
        .action = access_desc::operation_e::WRITE_REGISTER, .out_val = nullptr, .in_val = in_val, .reg = &reg,
    };

    return ad;
}

ll_device::access_desc
ll_device_impl::make_write_register_array(const lld_register_array_container& reg,
                                          size_t first,
                                          size_t count,
                                          const bit_vector& in_bv)
{
    access_desc ad{};
    ad.action = access_desc::operation_e::WRITE_REGISTER_ARRAY;
    ad.in_val = in_bv;
    ad.reg_array = &reg;
    ad.first = first;
    ad.count = count;

    const auto desc = reg.get_desc();
    ad.in_val.resize(desc->width_in_bits);

    return ad;
}

ll_device::access_desc
ll_device_impl::make_read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& in_val)
{
    access_desc ad = {
        .action = access_desc::operation_e::READ_MODIFY_WRITE_REGISTER,
        .out_val = nullptr,
        .in_val = bit_vector(in_val),
        .reg = &reg,
        .mem = nullptr,
        .reg_array = nullptr,
        .first = 0,
        .count = 0,
        .args = {
            .rmw = {
                .msb = msb,
                .lsb = lsb,
            },
        },
    };

    return ad;
}

ll_device::access_desc
ll_device_impl::make_read_memory(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv)
{
    // out_bv is already resized

    access_desc ad = {
        .action = access_desc::operation_e::READ_MEMORY,
        .out_val = &out_bv,
        .in_val = bit_vector(),
        .reg = nullptr,
        .mem = &mem,
        .reg_array = nullptr,
        .first = (la_entry_addr_t)first_entry,
        .count = count,
    };

    return ad;
}

ll_device::access_desc
ll_device_impl::make_write_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_val)
{
    access_desc ad = {
        .action = access_desc::operation_e::WRITE_MEMORY,
        .out_val = nullptr,
        .in_val = in_val,
        .reg = nullptr,
        .mem = &mem,
        .reg_array = nullptr,
        .first = (la_entry_addr_t)first_entry,
        .count = count,
    };

    const auto desc = mem.get_desc();
    ad.in_val.resize(desc->width_total_bits * count);

    return ad;
}

ll_device::access_desc
ll_device_impl::make_read_modify_write_memory(const lld_memory& mem, size_t line, size_t msb, size_t lsb, const bit_vector& in_val)
{
    // Assume that 'out_val' remains valid during the lifetime of the transaction.
    access_desc ad = {
        .action = access_desc::operation_e::READ_MODIFY_WRITE_MEMORY,
        .out_val = nullptr,
        .in_val = bit_vector(in_val),
        .reg = nullptr,
        .mem = &mem,
        .reg_array = nullptr,
        .first = (la_entry_addr_t)line,
        .count = 0,
        .args = {
            .rmw = {
                .msb = msb,
                .lsb = lsb,
            },
        },
    };

    return ad;
}

ll_device::access_desc
ll_device_impl::make_delay(uint64_t cycles)
{
    access_desc ad{};
    ad.action = access_desc::operation_e::DELAY;
    ad.args.delay_cycles = cycles;

    return ad;
}

bool
ll_device_impl::is_block_available(la_block_id_t block_id)
{
    return true;
}

ll_device::access_desc
ll_device_impl::make_wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask)
{
    la_block_id_t block_id = reg.get_block_id();
    la_entry_addr_t addr = reg.get_desc()->addr;

    access_desc ad = {
        .action = access_desc::operation_e::WAIT_FOR_VALUE,
        .out_val = nullptr,
        .in_val = bit_vector(),
        .reg = &reg,
        .mem = nullptr,
        .reg_array = nullptr,
        .first = 0,
        .count = 0,
        .args = {
            .wait_for_value = {
                .block_id = block_id,
                .addr = addr,
                .equal = equal,
                .poll_cnt = UINT8_MAX,
                .val = val,
                .mask = mask,
            },
        },
    };

    return ad;
}

ll_device::access_desc
ll_device_impl::make_wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask)
{
    la_block_id_t block_id = mem.get_block_id();
    la_entry_addr_t addr = mem.get_desc()->addr + line;

    access_desc ad = {
        .action = access_desc::operation_e::WAIT_FOR_VALUE,
        .out_val = nullptr,
        .in_val = bit_vector(),
        .reg = nullptr,
        .mem = &mem,
        .reg_array = nullptr,
        .first = 0,
        .count = 0,
        .args = {
            .wait_for_value = {
                .block_id = block_id,
                .addr = addr,
                .equal = equal,
                .poll_cnt = UINT8_MAX,
                .val = val,
                .mask = mask,
            },
        },
    };

    return ad;
}

std::string
ll_device_impl::get_uio_sysfs_path() const
{
    if (m_dev_type != DEVICE_INTERFACE_PCI) {
        return "";
    }

    char path[LINE_SIZE];

    snprintf(path, LINE_SIZE, "/sys/class/uio/uio%d", m_uio_dev_id);

    return path;
}

std::string
ll_device_impl::get_device_files_path() const
{
    if (m_dev_type != DEVICE_INTERFACE_PCI) {
        return "";
    }

    return get_uio_sysfs_path() + "/device";
}

std::string
ll_device_impl::get_network_interface_file_name(la_slice_id_t slice) const
{
    if (m_dev_type != DEVICE_INTERFACE_PCI) {
        return "";
    }

    char path[LINE_SIZE];

    snprintf(path, LINE_SIZE, "%s/leaba_nic%d", get_device_files_path().c_str(), slice);

    return path;
}

std::string
ll_device_impl::get_network_interface_name(la_slice_id_t slice) const
{
    std::string path = get_network_interface_file_name(slice);
    if (path.empty()) {
        return "";
    }

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        log_err(LLD, "%s: Failed to open %s, errno=%d (%s)", __func__, path.c_str(), errno, strerror(errno));
        return "";
    }

    char line[LINE_SIZE];
    int ret = read(fd, line, LINE_SIZE);
    close(fd);
    if (ret < 0) {
        log_err(LLD, "%s: Failed to read from %s, errno=%d (%s)\n", __func__, path.c_str(), errno, strerror(errno));
        return "";
    }

    char name[LINE_SIZE];
    ret = sscanf(line, "name=%s\\n", name);
    if (ret <= 0) {
        log_err(LLD, "%s: Failed to find interface name, slice=%d, filename='%s'", __func__, slice, path.c_str());
        return "";
    }

    return name;
}

ll_device_impl_sptr
ll_device_impl::sptr()
{
    return static_pointer_cast<ll_device_impl>(shared_from_this());
}

la_status
ll_device_impl::post_restore_interfaces_sanity_checks()
{
    if (m_simulation_mode != simulation_mode_e::NONE && !m_simulator) {
        log_err(LLD, "%s: Simulation mode isn't NONE but simulator device isn't set", __func__);
        return LA_STATUS_ENOTINITIALIZED;
    }

    return LA_STATUS_SUCCESS;
}
