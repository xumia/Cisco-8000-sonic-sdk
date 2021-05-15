# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

include $(MakefileTemplateRoot)/Makefile.module_pre

PKG := nsim_kernel
PKG-TARGETS := libs swiglib py_lib
PKG-PATH := src/nsim_kernel

PKG-COMPILE-PREREQS := $(leaba-module-copied) $(lld-lbrs-configured) | api
PKG-INCLUDE-FLAGS := -I$(BASE_OUTPUT_DIR)/build/shared/src/lld/ -I$(BASE_OUTPUT_DIR)/include -I$(BASE_OUTPUT_DIR)/modules/leaba_module -I$(NSIM_INC_DIR)/ -I$(SHARED_BASE_ROOT)/include/nsim_kernel
PKG-LINK-PREREQS := $(device_simulator_client-slib)
PKG-LINK-LIBS := $(device_simulator_client-slib) -lz -lrt

PKG-SWIG-NAME := nsim_kernel
PKG-SWIG-COMPILE-PREREQS := $(lld-lbrs-configured)
PKG-SWIG-INCLUDE-FLAGS := -Iinclude -Isrc/hw_tables -I$(NSIM_INC_DIR)/ -I$(PKG-PATH)/ -I$(SHARED_BASE_ROOT)/include/nsim_kernel
PKG-SWIG-LINK-PREREQS := $(PKG-LINK-PREREQS)
PKG-SWIG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) $(PKG-LINK-LIBS)
PKG-EXTRA_CSRCS := shared/src/kernel/leaba_nic.c shared/src/kernel/leaba_nic_pacific_specific.c shared/src/kernel/leaba_nic_v2_specific.c shared/src/kernel/packet_dma_wa.c

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets


