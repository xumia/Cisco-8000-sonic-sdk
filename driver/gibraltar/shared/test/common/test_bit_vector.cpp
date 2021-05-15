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

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/bit_vector.h"

#include "gtest/gtest.h"

using namespace silicon_one;

/**
 * @file
 * @brief Low-Level driver test
 * This file contains unit tests for testing access to LBR data.
 */

class BitVectorTest : public ::testing::Test
{
protected:
    // BitVectorTest test-case set-up.
    // Called before the first test in this test case.
    static void SetUpTestCase()
    {
    }

    // BitVectorTest test-case tear-down.
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
    // BitVectorTest resources, shared by all tests.

    //-----------------------------------------------
}; // class BitVectorTest

TEST_F(BitVectorTest, BasicOps)
{
    uint64_t v1 = 0x123456789abcdef0;
    uint64_t v2 = 0xf0f0f0f0f0f0f0f0;
    bool b_val = false;

    bit_vector bv1(v1);
    bit_vector bv2(v2);
    bit_vector bv3("123456789abcdef0");

    bit_vector bv5(b_val);
    bit_vector bv6(true);

    EXPECT_EQ(v1, bv1.get_value());
    EXPECT_EQ(v2, bv2.get_value());
    EXPECT_EQ(v1, bv3.get_value());
    EXPECT_EQ((uint64_t)61, bv1.get_width());
    EXPECT_EQ((uint64_t)64, bv2.get_width());

    EXPECT_EQ((uint64_t)0, bv5.get_width());
    EXPECT_EQ((uint64_t)1, bv6.get_width());

    bit_vector bv4 = bv1;
    EXPECT_EQ(v1, bv4.get_value());

    bv4 = bv1 | bv2;
    EXPECT_EQ(v1 | v2, bv4.get_value());

    bv4 = bv1 & bv2;
    EXPECT_EQ(v1 & v2, bv4.get_value());

    bv4 = bv1 ^ bv2;
    EXPECT_EQ(v1 ^ v2, bv4.get_value());

    bv4 = bv1 << 8;
    EXPECT_EQ(v1 << 8, bv4.get_value());
    EXPECT_EQ((uint64_t)69, bv4.get_width());
}

TEST_F(BitVectorTest, ShiftLeftAndAccumulate)
{
    bit_vector accumulated_bv;
    bit_vector short_bv("abc");
    short_bv.resize(12);

    for (size_t i = 0; i < 7; ++i) {
        accumulated_bv = (short_bv << accumulated_bv.get_width()) | accumulated_bv;
        EXPECT_EQ(accumulated_bv.get_width(), (i + 1) * 12);
    }

    bit_vector expected_bv("abcabcabcabcabcabcabc");
    expected_bv.resize(short_bv.get_width() * 7);

    EXPECT_EQ(expected_bv, accumulated_bv);
}

TEST_F(BitVectorTest, Resize)
{
    bit_vector bv(0x123456789abcdef0, 64);
    uint64_t expected = 0x70;
    bit_vector bv_expected(0x70, 7);

    bv.resize(7);
    EXPECT_EQ((size_t)7, bv.get_width());
    EXPECT_EQ(expected, bv.get_value());
    EXPECT_EQ(bv_expected == bv, true);

    bv = bit_vector("1122334455667788aabbccddeeff0011223", 137);
    EXPECT_EQ((size_t)137, bv.get_width());

    // resize to 6 bits and check that get_value() returns a 6-bit value
    bv.resize(6);
    EXPECT_EQ((uint64_t)0x23, bv.get_value());

    // resize to a larger size, and check that there is no garbage after 6th bit
    bv.resize(64);
    EXPECT_EQ((uint64_t)0x23, bv.get_value());

    bv.resize(64);
    EXPECT_EQ(strcmp(bv.to_string().c_str(), "0000000000000023"), 0);

    bv.resize(65);
    EXPECT_EQ(strcmp(bv.to_string().c_str(), "000000000000000023"), 0);
}

TEST_F(BitVectorTest, BitSet)
{
    uint64_t v1 = 0x123456789abcdef0;
    uint64_t expected = 0x123456789abcfedc;
    bit_vector bv1(v1);

    EXPECT_EQ(v1, bv1.get_value());

    bv1.set_bits(15, 0, 0xfedc);
    EXPECT_EQ(expected, bv1.get_value());
}

TEST_F(BitVectorTest, ByteArray)
{
    uint64_t v1 = 0x123456789abcdef0;
    uint64_t v2 = 0xf0f0f0f0f0f0f0f0;

    uint8_t b1_arr[] = {
        0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
    };
    uint8_t b2_arr[] = {
        0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
    };
    bit_vector bv1(v1);
    bit_vector bv2(v2);

    EXPECT_EQ(v1, bv1.get_value());
    EXPECT_EQ((uint64_t)61, bv1.get_width());
    EXPECT_EQ((uint64_t)8, bv1.get_width_in_bytes());
    uint8_t* bv1_arr = bv1.byte_array();
    for (size_t i = 0; i < bv1.get_width_in_bytes(); i++) {
        EXPECT_EQ(b1_arr[i], bv1_arr[i]) << " failed " << i;
    }

    bv1 = bv1 << 64;
    EXPECT_EQ((uint64_t)125, bv1.get_width());
    EXPECT_EQ((uint64_t)16, bv1.get_width_in_bytes());
    EXPECT_STRCASEEQ("123456789abcdef00000000000000000", bv1.to_string().c_str());

    bv1_arr = bv1.byte_array();
    for (size_t i = 0; i < 8; i++) {
        EXPECT_EQ((uint64_t)0, bv1_arr[i]) << " failed " << i;
    }
    for (size_t i = 8; i < bv1.get_width_in_bytes(); i++) {
        EXPECT_EQ(b1_arr[i - 8], bv1_arr[i]) << " failed " << i;
    }

    bv1 = bv1 | bv2;
    bv1_arr = bv1.byte_array();
    EXPECT_EQ((uint64_t)16, bv1.get_width_in_bytes());
    EXPECT_STRCASEEQ("123456789abcdef0f0f0f0f0f0f0f0f0", bv1.to_string().c_str());
    for (size_t i = 0; i < 8; i++) {
        EXPECT_EQ(b2_arr[i], bv1_arr[i]) << " failed " << i;
    }
    for (size_t i = 8; i < bv1.get_width_in_bytes(); i++) {
        EXPECT_EQ(b1_arr[i - 8], bv1_arr[i]) << " failed " << i;
    }
}

TEST_F(BitVectorTest, all_ones)
{
    size_t width_bits_array[] = {0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 100000};

    for (size_t width_bits : width_bits_array) {
        bit_vector bv = bit_vector::ones(width_bits);
        EXPECT_EQ(bv.get_width(), width_bits) << " failed " << width_bits;
        for (size_t i = 0; i < width_bits; ++i) {
            EXPECT_EQ(bv.bit(i), true) << "failed " << i << ", width_bits=" << width_bits;
        }
    }
}

TEST_F(BitVectorTest, all_ones_range)
{
    size_t width_bits_array[] = {0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 100000};

    for (size_t width_bits : width_bits_array) {
        size_t lsbs[] = {0, width_bits / 2, width_bits - 1 /* ==-1 is deliberately tested */};
        size_t msbs[] = {0, width_bits / 3, width_bits / 2, width_bits - 1 /* ==-1 is deliberately tested */};

        for (size_t lsb : lsbs) {
            for (size_t msb : msbs) {
                if (!width_bits) {
                    continue; // TODO
                }
                bit_vector bv = bit_vector::ones_range(msb, lsb, width_bits);
                EXPECT_EQ(bv.get_width(), width_bits) << " failed " << width_bits;
                if (msb >= lsb) {
                    for (size_t i = lsb; i <= std::min(msb, width_bits); ++i) {
                        EXPECT_EQ(bv.bit(i), true)
                            << "failed " << i << ", lsb=" << lsb << ", msb=" << msb << ", width_bits=" << width_bits;
                    }
                }
            }
        }
    }
}
