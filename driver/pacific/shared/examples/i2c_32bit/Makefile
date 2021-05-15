# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

.PHONY: all clean

CXXFLAGS += -std=c++11 -Wall -Werror

all: i2cget32 i2cset32

i2cget32: i2c_common.cpp i2c_common.h i2cget32.cpp
	$(CXX) $(CXXFLAGS) i2c_common.cpp i2cget32.cpp -o $@

i2cset32: i2c_common.cpp i2c_common.h i2cset32.cpp
	$(CXX) $(CXXFLAGS) i2c_common.cpp i2cset32.cpp -o $@

clean:
	rm -f i2cget32 i2cset32

