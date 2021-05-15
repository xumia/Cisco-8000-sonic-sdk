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

#include <iostream>
#include <stdio.h>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

#include "common/la_profile.h"
#include "common/la_profile_database.h"
#include "common/logger.h"
using namespace silicon_one;

union local_time_union {
    la_uint32_t higher_lower[2]; ///< Assembler call stores the timestamp split into two 32-bit integers
    long cycles;                 ///< Time at the start of the API call
};

// faux device

class Device
{

public:
    Device(la_device_id_t id)
    {
        m_id = id;
    }

    la_device_id_t get_id()
    {
        return m_id;
    }

private:
    la_device_id_t m_id;
};

class Component
{
public:
    Component(la_device_id_t id) : m_device(new Device(id))
    {
    }

    void n_baz_api(int n)
    {
        long first = 0;
        long second = 0;
        std::vector<la_uint64_t> results;
        for (int i = 0; i < 50; i++) {
            START_ASM_MEASUREMENT
            fibo(25);
            END_ASM_MEASUREMENT
            // std::cout << "fibo 25 took " << m_end_time.cycles - m_start_time.cycles << " cycles" << std::endl;
            first = m_end_time.cycles - m_start_time.cycles;

            START_ASM_MEASUREMENT
            profiled_fibo(25);
            END_ASM_MEASUREMENT
            // std::cout << "profiled fibo 25 took " << m_end_time.cycles - m_start_time.cycles << " cycles" << std::endl;
            second = m_end_time.cycles - m_start_time.cycles;

            results.push_back(second - first);
            std::cout << "time difference is " << second - first << " cycles\n";
        }
    }

    void no_sync_func()
    {
        start_profiling(no_sync, "testing sync") int a = 40;
        // some trivial work
        for (int i = 0; i < 100; i++) {
            a += 40;
        }
    }

    void func()
    {
        int a = 40;
        for (int i = 0; i < 100; i++) {
            a += a;
        }

        a = 40;
        for (int i = 0; i < 100; i++) {
            a += a;
        }

        return;
    }

    void prof_func()
    {
        start_profiling("scope profiling");
        int a = 40;
        for (int i = 0; i < 100; i++) {
            a += a;
        }
        a = 40;
        for (int i = 0; i < 100; i++) {
            a += a;
        }
        return;
    }
    long seg_prof_func(int x)
    {
        start_profiling(segment_tester, "segment profiling") long a = 40;
        for (int i = 0; i < x * 3; i++) {
            a += a;
        }
        segment_tester.stop();
        start_profiling(second_segment, "second profiling");
        for (int i = 0; i < x; i++) {
            a += a;
        }
        second_segment.stop();
        return a;
    }

    long multi_scope_profiling(long x)
    {
        start_profiling("scope profiling");
        start_profiling("scope profiling 2");
        long a = 40;
        for (int i = 0; i < x; i++) {
            a += a;
        }

        for (int i = 0; i < x; i++) {
            a += a;
        }
        return a;
    }

    long start_time()
    {
        START_ASM_MEASUREMENT
        return m_start_time.cycles;
    }

    long end_time()
    {
        END_ASM_MEASUREMENT
        return m_end_time.cycles;
    }

    long regex_goodexample()
    {
        start_profiling("good_example");
        long a = 0;
        for (int i = 0; i < 5; i++) {
            a += i;
        }
        return a;
    }

    long regex_bad_example()
    {
        start_profiling("bad_example");
        long a = 0;
        for (int i = 0; i < 5; i++) {
            a += i;
        }
        return a;
    }

    ~Component()
    {
        delete m_device;
    }

private:
    Device* m_device;

    int fibo(int n)
    {
        if (n < 2) {
            return 1;
        } else {
            return fibo(n - 1) + fibo(n - 2);
        }
    }

    int profiled_fibo(int n)
    {
        start_profiling("fibonacci") if (n < 2)
        {
            return 1;
        }
        else return fibo(n - 1) + fibo(n - 2);
    }

    int recursive_profiled_fibo(int n)
    {
        if (n < 2) {
            return 1;
        } else
            return recursive_profiled_fibo(n - 1) + recursive_profiled_fibo(n - 2);
    }
    local_time_union m_start_time; ///< Time when the API call started
    local_time_union m_end_time;   ///< Time when the API call exits
};

TEST(Profiler, no_profiling)
{
    Component dev(206);

    int iterations = 1000000;

    long s = dev.start_time();
    for (int i = 0; i < iterations; i++) {
        dev.func();
    }
    long e = dev.end_time();

    long res = e - s;

    std::cout << "total exec time of empty function :" << res << "\n";

    res = res / iterations;

    std::cout << "average exec time of empty function :" << res << "\n";
}

TEST(Profiler, scoped_profiling)
{
    Component dev(207);

    int iterations = 1000000;

    long s = dev.start_time();
    for (int i = 0; i < iterations; i++) {
        dev.prof_func();
    }
    long e = dev.end_time();
    long res = e - s;

    std::cout << "total exec time of scope profiled function :" << res << "\n";

    res = res / iterations;

    std::cout << "average exec time of scope profiled function :" << res << "\n";

    la_profile_database::get_instance().report();
}

TEST(Profiler, multi_scoped_profiling)
{
    Component dev(212);

    int iterations = 1000000;

    long ret;

    long s = dev.start_time();
    for (int i = 0; i < iterations; i++) {
        ret = dev.multi_scope_profiling(100);
    }

    std::cout << "ret: " << ret << "\n";

    long e = dev.end_time();
    long res = e - s;

    std::cout << "total exec time of scope profiled function :" << res << "\n";

    res = res / iterations;

    std::cout << "average exec time of scope profiled function :" << res << "\n";

    la_profile_database::get_instance().report();
}

TEST(Profiler, segment_profiling)
{
    Component dev(211);

    int iterations = 1000000;

    long ret = 0;

    long s = dev.start_time();
    for (int i = 0; i < iterations; i++) {
        ret = dev.seg_prof_func(100);
    }

    std::cout << "ret is : " << ret << "\n";

    long e = dev.end_time();
    long res = e - s;

    std::cout << "total exec time of segment profiled function :" << res << "\n";

    res = res / iterations;

    std::cout << "average exec time of segment profiled function :" << res << "\n";

    la_profile_database::get_instance().report();
}

TEST(Profiler, test_no_sync)
{
    Component comp(208);

    long s = comp.start_time();

    std::vector<std::thread> threads;

    for (int i = 0; i < 10; i++) {
        threads.push_back(std::thread([&comp]() {
            for (int i = 0; i < 100; i++) {
                comp.no_sync_func();
            }
        }));
    }

    for (int i = 0; i < 10; i++) {
        threads[i].join();
    }

    long e = comp.end_time();
    long res = e - s;

    std::cout << "total exec time of (non)synchronized function :" << res << "\n";

    res = res / 1000;

    std::cout << "average exec time of (non)synchronized function :" << res << "\n";

    la_profile_database::get_instance().report();
}

TEST(Profiler, test_regex1)
{
    Component comp(209);
    comp.regex_goodexample();

    std::ostringstream stream;
    la_profile_database::get_instance().report(
        silicon_one::logger::NUM_DEVICES, la_profile_database::sort_criteria_e::NONE, "goodexample", stream);
    std::stringstream str;

    str << "Profile: "
        << "long int Component::regex_goodexample()"
        << ": "
        << "good_example"
        << "\n";
    str << "\tDevice no. "
        << "288"
        << "\n";
    str << "\t\t"
        << "Executions: " << 1;
    str << "\t\t"
        << "Total: " << 22;
    str << "\t\tAVG: " << 22 << "\n";

    EXPECT_EQ(str.str(), str.str());
}

TEST(Profiler, test_regex2)
{
    Component comp(210);
    comp.regex_bad_example();

    std::ostringstream stream;
    la_profile_database::get_instance().report(
        silicon_one::logger::NUM_DEVICES, la_profile_database::sort_criteria_e::NONE, "badexample", stream);
    EXPECT_EQ(stream.str(), "");
}
