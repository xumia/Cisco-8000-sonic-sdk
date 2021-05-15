# BEGIN_LEGAL
#
# Copyright (c) 2016, Leaba Semiconductor Ltd. ("Leaba"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Leaba and shall remain at Leaba's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Leaba's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Leaba.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL LEABA BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

include $(MakefileTemplateRoot)/Makefile.module_pre

PKG := jansson
PKG-TARGETS := libs
JANSSON_PATH ?= shared/externals/jansson
PKG-PATH := $(JANSSON_PATH)
PKG-INCLUDE-FLAGS := -I$(JANSSON_PATH)
PKG-C-EXTRA-FLAGS := -DHAVE_STDINT_H -D_CRT_SECURE_NO_WARNINGS -Wno-implicit-fallthrough

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets
