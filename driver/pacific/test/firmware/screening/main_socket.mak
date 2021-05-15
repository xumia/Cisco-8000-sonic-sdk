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

.PHONY: all clean

all: main_socket

DRIVER_DIR = ../../..
CFLAGS = -Wall -Werror -O3 -I $(DRIVER_DIR)/include/lld/socket_connection 
SRCS =  main_socket.cpp screening.cpp
HEADERS = screening.h

lld_conn_lib.o: $(DRIVER_DIR)/src/lld/socket_connection/lld_conn_lib.c
	$(CC) $(CFLAGS) -std=gnu99 -c $< -o $@

main_socket: $(SRCS) lld_conn_lib.o $(HEADERS)
	$(CC) -DSCREENING_DEBUG=1 -DRTL_SIM=1 $(CFLAGS) -Wno-strict-aliasing -std=c++11 $(SRCS) -l pthread lld_conn_lib.o -o $@

clean:
	rm -f main_socket lld_conn_lib.o
