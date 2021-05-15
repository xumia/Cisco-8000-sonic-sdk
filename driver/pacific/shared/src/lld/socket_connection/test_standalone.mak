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

CC=/common/pkgs/gcc/4.9.3/bin/gcc
CPP=/common/pkgs/gcc/4.9.3/bin/g++

.PHONY: all test clean

all: lld_conn_device lld_conn_driver

IDIR=../../../include/lld/socket_connection
VPATH=$(IDIR)

lld_conn_lib.so: lld_conn_lib.c lld_conn_lib.h
	$(CC) -I $(IDIR) -Wall -Werror -std=gnu99 -O3 $^ -fpic -shared -o $@

lld_conn_device: lld_conn_lib.so lld_conn_device_main.cpp
	$(CPP) -Wall -Werror -std=c++11 -l pthread -O3 -D LLD_TEST_STANDALONE=1 $^ -Wl,-rpath=. -o $@

lld_conn_driver: lld_conn_lib.so lld_conn_driver_main.cpp
	$(CPP) -Wall -Werror -std=c++11 -l pthread -O3 -D LLD_TEST_STANDALONE=1 $^ -Wl,-rpath=. -o $@

test: lld_conn_device lld_conn_driver
	(./lld_conn_device --as_server 1 &) && (sleep 1) && (./lld_conn_driver --as_server 0) || echo ""

clean:
	rm -f lld_conn_device lld_conn_driver lld_conn_lib.so
