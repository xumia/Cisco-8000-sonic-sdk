// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "api/types/la_common_types.h"
#include "common/logger.h"
#include <ctime>
#include <fstream>
#include <mutex>
#include <stdio.h>
#include <thread>

#include "gtest/gtest.h"

using namespace silicon_one;

class LoggerTest : public ::testing::Test
{
protected:
    // LoggerTest test-case set-up.
    // Called before the first test in this test case.
    static void SetUpTestCase()
    {
    }

    // LoggerTest test-case tear-down.
    // Called after the last test in this test case.
    static void TearDownTestCase()
    {
    }

    // Per-test setup, executed before each test
    virtual void SetUp()
    {
    }

    // Per-test tear-down, executed after each test
    virtual void TearDown()
    {
    }

    //-----------------------------------------------
    // LoggerTest resources, shared by all tests.

    //-----------------------------------------------
}; // class LoggerTest

void
LoggerThread(la_device_id_t device_id, double seconds_to_log)
{
    std::time_t start_time = std::time(nullptr);
    while (true) {
        // difftime returns difference in seconds
        double time_elapsed = difftime(std::time(nullptr), start_time);
        if (time_elapsed > seconds_to_log) {
            break;
        }
        logger& instance = logger::instance();
        instance.log(device_id,
                     la_logger_component_e::COMMON,
                     la_logger_level_e::NOTICE,
                     "Current id = %d, current time diff = %lf\n",
                     device_id,
                     time_elapsed);
    }
}

/* Tests simulatneous access to logger by multiple threads while
 * writting to compressed file with zlib API
 */
TEST_F(LoggerTest, TestLogger)
{
    const int THREAD_COUNT = 2;
    const double time_to_log = 10.0;
    std::vector<std::thread*> threads;

    std::ofstream ofs;
    ofs.open("/tmp/test-log.gz", std::ofstream::trunc);
    ofs.close();

    logger::instance().set_log_file("test-log.gz");

    // Turning off stdout output
    logger::instance().set_log_function(nullptr);

    for (la_device_id_t i = 0; i < THREAD_COUNT; i++) {
        threads.push_back(new std::thread(LoggerThread, i, time_to_log));
    }

    for (std::thread* t : threads) {
        t->join();
        delete t;
    }
}
