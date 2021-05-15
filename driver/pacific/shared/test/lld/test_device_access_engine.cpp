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

#include <inttypes.h>
#include <linux/limits.h>
#include <stdio.h>
#include <time.h>

#include "common/bit_vector.h"
#include "common/gen_utils.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

#include "lld/device_simulator.h"
#include "socket_device.h"
#include "socket_device_simulator.h"

// Unit test
#include "../../src/lld/access_engine.h"
#include "../../src/lld/ll_device_impl.h"
#include "test_device_common.h"
#include "gtest/gtest.h"

/**
 * @file
 * @brief Access Engine test
 */

using namespace silicon_one;

static inline void
enc_write(access_engine* ae, const lld_register& reg, uint32_t val)
{
    ae->write(reg.get_block_id(), reg.get_desc()->addr, reg.get_desc()->width, 1 /* count */, &val);
}

static inline void
enc_wait_for_value(access_engine* ae, const lld_register& reg, uint32_t val, uint32_t mask)
{
    uint8_t poll_cnt = 7; // for the purpose of the test we do not want to wait for the failure for too long.
    ae->wait_for_value(reg.get_block_id(), reg.get_desc()->addr, true /* equal */, poll_cnt, val, mask);
}

static inline void
enc_read(access_engine* ae, const lld_register& reg, uint32_t& read_cookie)
{
    ae->read(reg.get_block_id(), reg.get_desc()->addr, reg.get_desc()->width, 1 /* count */, false /* peek */, read_cookie);
}

static inline void
copy_read_result(access_engine* ae, const lld_register& reg, uint32_t read_cookie, uint32_t* out_val)
{
    ae->copy_read_result(read_cookie, reg.get_desc()->width, 1 /* count */, out_val);
}

class AeTest : public ::testing::Test
{
protected:
    // AeTest test-case set-up.
    // Called before the first test in this test case.
    static void SetUpTestCase()
    {
        la_device_id_t device_id = 1; // device id this lld is attached to
        silicon_one::device_simulator* simulator;
        char device_path[PATH_MAX];

        bool is_testdev = (strncmp(lld_file_path, "/dev/testdev", strlen("/dev/testdev")) == 0);

        if (!is_testdev) {
            // /dev/uio0 and the likes
            strncpy(device_path, lld_file_path, sizeof(device_path));
            simulator = nullptr;
        } else {
            if (strstr(lld_file_path, "host=")) {
                // Connect to an existing simulator over socket (e.g. RTL simulator).
                strncpy(device_path, lld_file_path, sizeof(device_path));
            } else if (is_testdev) {
                // Create a dummy simulator and connect to it over socket
                uint16_t port_rw = 0, port_int = 0;
                s_socket_device = silicon_one::socket_device::create(port_rw, port_int);
                port_rw = s_socket_device->get_port_rw();
                port_int = s_socket_device->get_port_int();
                snprintf(device_path,
                         sizeof(device_path),
                         "%s?host=localhost&port_rw=%hu&port_int=%hu",
                         lld_file_path,
                         port_rw,
                         port_int);
            } else {
                fprintf(stderr, "ERROR: unexpected dev path %s\n", lld_file_path);
                ASSERT_TRUE(false);
            }

            simulator = ::create_socket_simulator(device_path);
            ASSERT_TRUE(simulator != nullptr);
        }

        silicon_one::la_platform_cbs platform_cbs{};
        s_ll_device = std::static_pointer_cast<ll_device_impl>(
            silicon_one::ll_device::create(/* device_id */ device_id, device_path, simulator, platform_cbs));

        ASSERT_TRUE(s_ll_device != nullptr);
        // Clean start - reset the access engines. For this test we do not need any resets deeper than this.
        // Called after the last test in this test case.
    }

    // Per-test setup, executed before each test
    virtual void SetUp()
    {
        ASSERT_TRUE(s_ll_device && s_ll_device->is_valid());
    }

    // Per-test tear-down, executed after each test
    virtual void TearDown()
    {
    }

    //-----------------------------------------------
    // AeTest resources, shared by all tests.
    static silicon_one::ll_device_impl_sptr s_ll_device; // Device context handle
    static silicon_one::socket_device* s_socket_device;  // Device-side simulator
    static const silicon_one::pacific_tree* s_lbr;       // Device tree of logical blocks with registers and memories

    void test_reserve_release()
    {
        for (int i = 0; i < 1000; ++i) {
            start_void_lld_call(s_ll_device.get());
            access_engine_uptr ae = s_ll_device->reserve_access_engine();
            EXPECT_NE(ae, nullptr);
            s_ll_device->release_access_engine(move(ae));
        }
    }

    // Test flow:
    //  - Encode a sequence of write+read pairs to the access engine.
    //  - Fire the sequence in one go.
    //  - Stand back and admire the result!
    void test_cif_rw_reg(std::vector<lld_register_sptr>& regs)
    {
        start_void_lld_call(s_ll_device.get());

        access_engine_uptr ae = s_ll_device->reserve_access_engine();
        ASSERT_NE(ae, nullptr);

        uint32_t val_w[16], val_r[16];
        for (size_t i = 0; i < array_size(val_w); ++i) {
            val_w[i] = 0x01010101 * (i + 1); // fill with 1-based multiplier to avoid all-zero values in test
        }

        // Encode a batch of write/read pairs
        std::vector<uint32_t> read_cookies(regs.size());
        for (size_t r = 0; r < regs.size(); ++r) {
            const lld_register_desc_t* rdesc = regs[r]->get_desc();
            ae->write(regs[r]->get_block_id(), rdesc->addr, rdesc->width, 1 /* count */, val_w);
            ae->read(regs[r]->get_block_id(), rdesc->addr, rdesc->width, 1 /* count */, false /* peek */, read_cookies[r]);
        }

        // Go & wait
        la_status rc = ae->flush();
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);

        // Read the results
        for (size_t r = 0; r < regs.size(); ++r) {
            memset(val_r, 0xcc, sizeof(val_r));
            const lld_register_desc_t* rdesc = regs[r]->get_desc();
            ae->copy_read_result(read_cookies[r], rdesc->width, 1 /* count */, val_r);

            bit_vector bv_w(rdesc->width, (uint8_t*)val_w, rdesc->width_in_bits);
            bit_vector bv_r(rdesc->width, (uint8_t*)val_r, rdesc->width_in_bits);

            ASSERT_EQ(bv_w, bv_r);
        }

        s_ll_device->release_access_engine(move(ae));
    }

    void test_wait_for_value(bool positive_test)
    {
        start_void_lld_call(s_ll_device.get());

        // Test flow:
        //  phase 1: batch of 2 commands
        //   - clear interrupt status
        //   - enable interrupt mask
        //
        //  phase 2: batch of 3 commands
        //   - write to an interrupt test reg
        //   - wait on interrupt status reg
        //   - read from interrupt status reg
        //
        // If positive_test is true, wait for the same value that is written
        // and we expect that "wait" succeedes and "read" opcode is executed.
        //
        // If positive_test is false, wait for a value that is different from
        // that is written. It is expected that AE will stop execution of the
        // batch and "read" will not be executed.

        // all registers are 2bit
        lld_register_sptr reg_test = s_lbr->slice[0]->ifg[0]->sch->general_interrupt_register_test;
        lld_register_sptr reg_mask = s_lbr->slice[0]->ifg[0]->sch->general_interrupt_register_mask;
        lld_register_sptr reg_status = s_lbr->slice[0]->ifg[0]->sch->general_interrupt_register;

        access_engine_uptr ae = s_ll_device->reserve_access_engine();
        ASSERT_NE(ae, nullptr);

        // Preparation stage: clear the status and enable the mask
        enc_write(ae.get(), *reg_status, 0);
        enc_write(ae.get(), *reg_mask, 0x3);
        ae->flush();

        uint32_t val_w, val_wait;
        uint32_t read_cookie;

        if (positive_test) {
            // Written and waited-for values are the same
            val_w = val_wait = 0x2;
        } else {
            // Written and waited-for values are different
            val_w = 0x2;
            val_wait = 0x1;
        }

        // (write to 'test') + (wait on 'status') + (read from 'status')
        enc_write(ae.get(), *reg_test, val_w);
        enc_wait_for_value(ae.get(), *reg_status, val_wait, 0x3 /* mask */);
        enc_read(ae.get(), *reg_status, read_cookie);
        la_status rc = ae->flush();

        if (positive_test) {
            ASSERT_EQ(rc, LA_STATUS_SUCCESS);

            uint32_t val_r = 0;
            copy_read_result(ae.get(), *reg_status, read_cookie, &val_r);
            ASSERT_EQ(val_w, val_r);
        } else {
            // Access Engine is expected to enter an error state because of the failure of wait_for_value.
            // Details:
            //   ae::fifo_w == fifo_r + 3, because 'wait' cmd failed and the next cmd in the fifo was not executedi (on normal
            //   completion fifo_w == fifo_r).
            //   ae::status.err == 0x1
            //   ae::status.err_block_id == reg_status.get_block_id()
            ASSERT_EQ(rc, LA_STATUS_EACCES);
        }

        s_ll_device->release_access_engine(std::move(ae));
    }

    void test_delay()
    {
        start_void_lld_call(s_ll_device.get());
        access_engine_uptr ae = s_ll_device->reserve_access_engine();
        ASSERT_NE(ae, nullptr);

        // Delay's resolution is 1 cycle, where 1 cycle == 2ns
        // We do not test the precision of timing against RTL, but we might want to test on real HW.
        la_status rc = ae->delay(1);
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);

        // Go & wait
        rc = ae->flush();
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);

        s_ll_device->release_access_engine(move(ae));
    }

    void test_semaphore_basic()
    {
        start_void_lld_call(s_ll_device.get());
        access_engine_uptr ae = s_ll_device->reserve_access_engine();
        ASSERT_NE(ae, nullptr);

        // out of range
        la_status rc = ae->acquire_semaphore(64);
        ASSERT_EQ(rc, LA_STATUS_EOUTOFRANGE);

        // lock-unlock
        rc = ae->acquire_semaphore(42);
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);
        rc = ae->release_semaphore(42);
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);

        rc = ae->flush();
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);

        // unlock something that was not locked
        rc = ae->release_semaphore(42);
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);
        rc = ae->flush();
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);

        s_ll_device->release_access_engine(move(ae));
    }

    void test_semaphore_double_lock()
    {
        start_void_lld_call(s_ll_device.get());
        access_engine_uptr ae = s_ll_device->reserve_access_engine();
        access_engine_uptr ae2 = s_ll_device->reserve_access_engine();
        ASSERT_NE(ae, nullptr);
        ASSERT_NE(ae2, nullptr);

        ae->acquire_semaphore(42);
        la_status rc = ae->flush();
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);

        ae2->acquire_semaphore(42);
        rc = ae2->flush();
        ASSERT_EQ(rc, LA_STATUS_EBUSY);

        ae->release_semaphore(42);
        rc = ae->flush();
        ASSERT_EQ(rc, LA_STATUS_EBUSY);

        ae2->acquire_semaphore(42);
        rc = ae2->flush();
        ASSERT_EQ(rc, LA_STATUS_SUCCESS);

        s_ll_device->release_access_engine(move(ae2));
        s_ll_device->release_access_engine(move(ae));
    }
};

// Instantiate static objects
silicon_one::ll_device_impl_sptr AeTest::s_ll_device = nullptr;
silicon_one::socket_device* AeTest::s_socket_device = nullptr;
const silicon_one::pacific_tree* AeTest::s_lbr = nullptr;

// Test SBIF memories
TEST_F(AeTest, DISABLED_reserve_release)
{
    test_reserve_release();
}

TEST_F(AeTest, cif_rw_reg_single)
{
    if (s_ll_device->get_device_simulator()) {
        return;
    }

    std::vector<lld_register_sptr> regs(1);

    // 3bit reg
    regs[0] = s_lbr->slice[0]->ifg[0]->sch->mem_protect_interrupt_test;
    test_cif_rw_reg(regs);

    // 33bit
    regs[0] = s_lbr->slice[0]->ifg[0]->sch->ecc_1b_err_interrupt_register_mask;
    test_cif_rw_reg(regs);

    // 128bit
    regs[0] = s_lbr->slice[0]->ifg[0]->sch->spare_reg;
    test_cif_rw_reg(regs);
}

TEST_F(AeTest, cif_rw_reg_batch)
{
    if (s_ll_device->get_device_simulator()) {
        return;
    }

    std::vector<lld_register_sptr> regs;
    regs.push_back(s_lbr->slice[0]->ifg[0]->sch->mem_protect_interrupt_test);
    regs.push_back(s_lbr->slice[0]->ifg[0]->sch->ecc_1b_err_interrupt_register_mask);
    regs.push_back(s_lbr->slice[0]->ifg[0]->sch->spare_reg);

    test_cif_rw_reg(regs);
}

TEST_F(AeTest, cif_rw_reg_batch_wraparound)
{
    if (s_ll_device->get_device_simulator()) {
        return;
    }

    // Command fifo size is just 512 dwords, here we issue enough commands to make the fifo wrap around a few times.
    for (int i = 0; i < 500; ++i) {
        std::vector<lld_register_sptr> regs(0);
        regs.push_back(s_lbr->slice[0]->ifg[0]->sch->mem_protect_interrupt_test);
        regs.push_back(s_lbr->slice[0]->ifg[0]->sch->ecc_1b_err_interrupt_register_mask);
        regs.push_back(s_lbr->slice[0]->ifg[0]->sch->spare_reg);
        test_cif_rw_reg(regs);
    }
}

TEST_F(AeTest, DISABLED_cif_rw_mem)
{
    // TODO
}

TEST_F(AeTest, DISABLED_wait_for_value_positive)
{
    test_wait_for_value(true /* positive test */);
}

TEST_F(AeTest, DISABLED_wait_for_value_negative)
{
    test_wait_for_value(false /* positive_test */);
}

TEST_F(AeTest, DISABLED_delay)
{
    test_delay();
}

TEST_F(AeTest, DISABLED_semaphore)
{
    test_semaphore_basic();
    test_semaphore_double_lock();
}
