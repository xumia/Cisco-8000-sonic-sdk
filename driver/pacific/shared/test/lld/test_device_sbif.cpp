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

#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <stdio.h>
#include <time.h>

#include "common/stopwatch.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

// Unit test
#include "../../src/lld/access_engine.h"
#include "../../src/lld/ll_device_impl.h"
#include "test_device_common.h"
#include "gtest/gtest.h"

#include "lld/device_simulator.h"
#include "socket_device.h"
#include "socket_device_simulator.h"
/**
 * @file
 * @brief Low-Level driver test
 * This file contains unit tests for testing device context.
 */

class DeviceSbifTest : public ::testing::Test
{
protected:
    // DeviceSbifTest test-case set-up.
    // Called before the first test in this test case.
    static void SetUpTestCase()
    {
        la_device_id_t device_id = 1; // device id this lld is attached to
        s_ll_device
            = std::static_pointer_cast<silicon_one::ll_device_impl>(silicon_one::ll_device::create(device_id, lld_file_path));
        ASSERT_TRUE(s_ll_device->is_valid());

        s_pacific_tree = s_ll_device->get_pacific_tree();
    }

    // DeviceSbifTest test-case tear-down.
    // Called after the last test in this test case.
    static void TearDownTestCase()
    {
    }

    // Per-test setup, executed before each test
    virtual void SetUp()
    {
        return; // XXX

        ASSERT_TRUE(s_ll_device->is_valid());
    }

    // Per-test tear-down, executed after each test
    virtual void TearDown()
    {
    }

    //-----------------------------------------------
    // DeviceSbifTest resources, shared by all tests.
    static silicon_one::ll_device_impl_sptr s_ll_device;    // Device context handle
    static const silicon_one::pacific_tree* s_pacific_tree; // Device tree of logical blocks with registers and memories

    //-----------------
    // Helper functions

    using access_engine_uptr = std::unique_ptr<silicon_one::access_engine>;

    // Prepare external memory to be imported to device and the import command
    void import_prep(std::vector<access_engine_uptr>& acc_eng,
                     int mem_entries,
                     int iterations,
                     uint32_t* external_ram,
                     uint64_t external_ram_addr)
    {
#if 0
        int engines = acc_eng.size();

        // Write to host DMA area
        for (int eng = 0; eng < engines; eng++) {
            for (int i = 0; i < mem_entries; i++) {
                external_ram[i + eng * mem_entries * 2] = i | 0xDEAD0000 | (eng << 16);
            }
        }

        // import commands
        for (int eng = 0; eng < engines; eng++) {
            for (int i = 0; i < iterations; i++) {
                uint64_t ram_addr = external_ram_addr + eng * mem_entries * 4 * 2;
                acc_eng[eng]->encode_cmd_remote(silicon_one::access_engine::command_e::IMPORT,
                                                0 /* buff_addr */,
                                                (ram_addr >> 32) & 0xFFFFFFFF,
                                                ram_addr & 0xFFFFFFFF,
                                                mem_entries);
            }
        }
#endif
    }

    // Prepare export to external memory command
    void export_prep(std::vector<access_engine_uptr>& acc_eng,
                     int mem_entries,
                     int iterations,
                     uint32_t* external_ram,
                     uint64_t external_ram_addr)
    {
#if 0
        int engines = acc_eng.size();

        // export to another location
        for (int eng = 0; eng < engines; eng++) {
            for (int i = 0; i < iterations; i++) {
                uint64_t ram_addr = external_ram_addr + eng * mem_entries * 4 * 2 + mem_entries * 4;
                acc_eng[eng]->encode_cmd_remote(silicon_one::access_engine::command_e::EXPORT,
                                                0 /* buff_addr */,
                                                (ram_addr >> 32) & 0xFFFFFFFF,
                                                (ram_addr & 0xFFFFFFFF),
                                                mem_entries);
            }
        }
#endif
    }

    // Wait till the engine becomes READY
    void wait_engine(silicon_one::access_engine* ae, int max_retries)
    {
        // Wait till engine is ready
        silicon_one::access_engine::state_e stat = silicon_one::access_engine::state_e::BUSY;
        for (int t = 0; t < max_retries && stat == silicon_one::access_engine::state_e::BUSY; t++) {
            stat = ae->update_state();
        }
        ASSERT_EQ(stat, silicon_one::access_engine::state_e::READY); // validate completed successfully
    }

    /**
     * @brief Test SBIF's access engines memories.
     * Write data to all access engine's memories, read those memories and validate values.
     *
     * @param[in]  max_entries  Maximum number of entries to test, if 0, use max available.
     * @param[in]  mem_base     Either command memory or data memory.
     */
    void test_access_engine_mem(int max_entries, const silicon_one::lld_memory_array_container& mem_arr)
    {
        uint32_t tmp;
        unsigned int i, eng;
        silicon_one::lld_memory_desc_t const* mem_arr_desc = mem_arr.get_desc();
        unsigned int mem_entries = mem_arr_desc->entries;
        int start_addr;

        // uint64_t vcs_time[4];
        silicon_one::stopwatch sbif_write_stopwatch, register_read_stopwatch, sbif_read_stopwatch;
        uint32_t total_bytes;

        if (max_entries) {
            mem_entries = max_entries;
        }

        sbif_write_stopwatch.start();

        // Write data into memory
        for (eng = 0; eng < mem_arr_desc->instances; eng++) {
            start_addr = mem_arr[eng]->get_desc()->addr;
            for (i = 0; i < mem_entries; i++) {
                s_ll_device->sbif_write_register(start_addr + i, i | (eng << 16));
            }
        }

        sbif_write_stopwatch.stop();
        register_read_stopwatch.start();

        // Write register to ensure all writes flushed to the device
        s_ll_device->sbif_read_register(s_pacific_tree->sbif->sbif_global_config_reg->get_desc()->addr, &tmp);

        register_read_stopwatch.stop();
        sbif_read_stopwatch.start();

        for (eng = 0; eng < mem_arr_desc->instances; eng++) {
            start_addr = mem_arr[eng]->get_desc()->addr;
            for (i = 0; i < mem_entries; i++) {
                s_ll_device->sbif_read_register(start_addr + i, &tmp);
                EXPECT_EQ(tmp, (i | (eng << 16))) << "Memory entry " << i << " is different";
            }
        }

        sbif_read_stopwatch.stop();

        total_bytes = mem_arr_desc->instances * mem_entries * 4;

        RecordProperty("WriteTP_Mbps", throughput_mbps(sbif_write_stopwatch.get_interval_time(), total_bytes));
        RecordProperty("ReadTP_Mbps", throughput_mbps(sbif_read_stopwatch.get_interval_time(), total_bytes));
    }

    /**
     * @brief Test SBIF access engine command execution.
     * Add WRITE and READ commands and check the results
     */
    void command_exec(const silicon_one::lld_register& reg, uint32_t in_reg_val)
    {
#if 0
        uint16_t block_id = reg.get_block_id();
        uint16_t eng, eng_count;

        eng_count = s_pacific_tree->sbif->acc_eng_go_reg.get_desc()->instances;
        EXPECT_GT(eng_count, (unsigned int)0);

        std::vector<access_engine_uptr> acc_eng(eng_count);

        // Clear GO registers
        for (eng = 0; eng < eng_count; eng++) {
            s_ll_device->sbif_write_register(s_pacific_tree->sbif->acc_eng_go_reg[eng].get_desc()->addr, 0);
            s_ll_device->sbif_write_register(s_pacific_tree->sbif->acc_eng_cmd_ptr_reg[eng].get_desc()->addr, 0);

            // TODO C++14: acc_eng[eng] = make_unique<silicon_one::access_engine>(this, device_tree, engine_id);
            acc_eng[eng] = access_engine_uptr(new silicon_one::access_engine(s_ll_device, s_pacific_tree, eng));
        }

        for (eng = 0; eng < eng_count; eng++) {
            uint32_t val;

            s_ll_device->sbif_read_register(s_pacific_tree->sbif->acc_eng_go_reg[eng].get_desc()->addr, &val);
            ASSERT_EQ(val, 0U) << "GO register of engine " << eng << " not clear";

            s_ll_device->sbif_read_register(s_pacific_tree->sbif->acc_eng_cmd_ptr_reg[eng].get_desc()->addr, &val);
            ASSERT_EQ(val, 0U) << "CMD_PTR register of engine " << eng << " not clear";
        }

        // Test Write and Read
        for (eng = 0; eng < eng_count; eng++) {
            uint32_t data_pos = 0;
            uint32_t data_addr = s_pacific_tree->sbif->access_engine_data_mem[eng].get_desc()->addr;

            s_ll_device->sbif_write_memory(data_addr, data_pos, in_reg_val + eng);

            acc_eng[eng]->encode_cmd_local(silicon_one::access_engine::command_e::WRITE,
                                           data_pos /* buff_addr */,
                                           block_id,
                                           reg.get_desc()->addr,
                                           1 /* count */,
                                           1 /* width */);
            data_pos++;

            // Clear memory - to ensure actually reading into it
            s_ll_device->sbif_write_memory(data_addr, data_pos, 0);
            acc_eng[eng]->encode_cmd_local(silicon_one::access_engine::command_e::READ,
                                           data_pos /* buff_addr */,
                                           block_id,
                                           reg.get_desc()->addr,
                                           1 /* count */,
                                           1 /* width */);

            // Set GO
            s_ll_device->sbif_write_register(s_pacific_tree->sbif->acc_eng_go_reg[eng].get_desc()->addr, 1);

            wait_engine(acc_eng[eng].get(), 3);

            uint32_t tmp = -1U;
            s_ll_device->sbif_read_memory(data_addr, data_pos, &tmp);
            ASSERT_EQ(tmp, in_reg_val + eng) << "Got register value from engine " << eng << " not as written";
        }
#endif
    }
};

// Instantiate static objects
silicon_one::ll_device_impl_sptr DeviceSbifTest::s_ll_device = nullptr;
const silicon_one::pacific_tree* DeviceSbifTest::s_pacific_tree = nullptr;

//-----------------------------------------------------------------------------------------------------

// Test SBIF memories
TEST_F(DeviceSbifTest, DISABLED_Memories)
{
    test_access_engine_mem(0 /* max_entries */, *s_pacific_tree->sbif->access_engine_data_mem);
}

// Test command encoding and execution
TEST_F(DeviceSbifTest, DISABLED_CommandExec)
{
    {
        SCOPED_TRACE("CSMS_SOFT_RESET");
        command_exec(*s_pacific_tree->csms->soft_reset_configuration, 1);
    }
    {
        SCOPED_TRACE("CSMS_SPARE_REG");
        command_exec(*s_pacific_tree->csms->spare_reg, 0x12345678);
    }
}

/**
 * @brief Test import and export commands
 */
TEST_F(DeviceSbifTest, DISABLED_CommandImportExport)
{
#if 0
    // FIXME: access_engine's c'tor takes 'dma_desc' argument.

    uint32_t* external_ram = dma_desc.vaddr;
    uint64_t external_ram_addr = dma_desc.paddr;

    uint16_t engines = s_pacific_tree->sbif->acc_eng_go_reg.get_desc()->instances;
    uint16_t mem_entries = s_pacific_tree->sbif->access_engine_command_mem.get_desc()->entries;
    int max_retries = 80;
    int iterations = 10;

    silicon_one::stopwatch import_stopwatch, export_stopwatch;

    std::vector<access_engine_uptr> acc_eng(engines);

    for (uint16_t eng = 0; eng < engines; eng++) {
        // TODO C++14: acc_eng[eng] = make_unique<silicon_one::access_engine>(this, device_tree, engine_id);
        acc_eng[eng] = access_engine_uptr(new silicon_one::access_engine(s_ll_device, s_pacific_tree, eng));
    }

    import_prep(acc_eng, mem_entries, iterations, external_ram, external_ram_addr);

    import_stopwatch.start();

    // Set GO for all then wait for all
    for (uint16_t eng = 0; eng < engines; eng++) {
        s_ll_device->sbif_write_register(s_pacific_tree->sbif->acc_eng_go_reg[eng].get_desc()->addr, 1);
    }
    for (uint16_t eng = 0; eng < engines; eng++) {
        wait_engine(acc_eng[eng].get(), max_retries);
    }
    import_stopwatch.stop();

    // Read data memory
    for (uint32_t eng = 0; eng < engines; eng++) {
        for (uint32_t i = 0; i < mem_entries; i++) {
            uint32_t tmp = -1U;
            uint32_t data_addr = s_pacific_tree->sbif->access_engine_data_mem[eng].get_desc()->addr;

            s_ll_device->sbif_read_memory(data_addr, i, &tmp);
            ASSERT_EQ(tmp, (i | 0xDEAD0000 | (eng << 16))) << "Data memory in engine " << eng << " at " << i;
        }
    }

    export_prep(acc_eng, mem_entries, iterations, external_ram, external_ram_addr);

    export_stopwatch.start();
    // Set GO for all then wait for all
    for (uint16_t eng = 0; eng < engines; eng++) {
        s_ll_device->sbif_write_register(s_pacific_tree->sbif->acc_eng_go_reg[eng].get_desc()->addr, 1);
    }
    for (uint16_t eng = 0; eng < engines; eng++) {
        wait_engine(acc_eng[eng].get(), max_retries);
    }
    export_stopwatch.stop();

    // read memory and compare
    for (int i = 0; i < mem_entries; i++) {
        ASSERT_EQ(external_ram[i], external_ram[mem_entries + i]) << "RAM at " << i;
    }

    RecordProperty("ImportTP_Mbps", throughput_mbps(import_stopwatch.get_interval_time(), 512 * 4 * iterations * engines));
    RecordProperty("ExportTP_Mbps", throughput_mbps(export_stopwatch.get_interval_time(), 512 * 4 * iterations * engines));
#endif
}
