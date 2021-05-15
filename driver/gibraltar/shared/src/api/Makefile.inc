# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

api-prereqs := | api-include
api-includes :=  -I$(INCLUDE_OUTPUT_DIR)
api-link-libs := -L$(DLIB_OUTPUT_DIR) -lhld -lapi_serial

PKG := api
PKG-TARGETS := swiglib py_lib
PKG-PATH := shared/src/api

PKG-PY-MODULE-PATH := leaba
PKG-SWIG-NAME := sdk
PKG-SWIG-COMPILE-PREREQS := $(api-prereqs)
PKG-SWIG-INCLUDE-FLAGS := $(api-includes) -I$(SHARED_BASE_ROOT) -I$(SHARED_BASE_ROOT)/include
PKG-SWIG-LINK-PREREQS := $(hld-dlib) $(api-serial-dlib)
PKG-SWIG-LINK-LIBS := $(api-link-libs)

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets
