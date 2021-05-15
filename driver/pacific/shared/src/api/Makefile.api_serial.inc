# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

api-serial-prereqs :=  | api-include
api-serial-includes := -I$(INCLUDE_OUTPUT_DIR)

PKG := api-serial
PKG-TARGETS := libs
PKG-PATH := shared/src/api
PKG-INCLUDE-FLAGS = $(api-serial-includes)

PKG-CEREAL-GEN := True
PKG-CEREAL-EXTRA-DIRS := $(wildcard shared/include/api/*)
PKG-CEREAL-PREREQS := $(api-serial-prereqs)
PKG-CEREAL-CONFIG-FILE := serialize_config.cfg
PKG-CEREAL-NUM-OF-GENERATED-FILES := 1

include $(MakefileTemplateRoot)/Makefile.module_vars

# replacing the regular path to the api copied path, so cereal tool will idetify them as part of the module
$(PKG)-cereal-h-files := $(patsubst shared/include/%,$(INCLUDE_OUTPUT_DIR)/%,$($(PKG)-cereal-h-files))
$(PKG)-cereal-module-dirs := $(patsubst shared/include/%,$(INCLUDE_OUTPUT_DIR)/%,$($(PKG)-cereal-module-dirs))

include $(MakefileTemplateRoot)/Makefile.module_targets
