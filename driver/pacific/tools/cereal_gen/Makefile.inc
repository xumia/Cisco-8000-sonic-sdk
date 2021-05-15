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

ifeq ($(ROOT_TOOLS_DIR),)
    $(error ROOT_TOOLS_DIR argument not defined)
endif

PKG := cereal-gen
PKG-TARGETS := app
CEREAL_GEN_RELATIVE_PATH ?= tools/cereal_gen
PKG-PATH := $(CEREAL_GEN_RELATIVE_PATH)
PKG-COMPILE-PREREQS += $(cereal-configured)

PKG-INCLUDE-FLAGS := -I$(LLVM_BASE_DIR)/include

LLVM_LIBS := `$(CLANG_DIR)/llvm-config --libs --system-libs`
LLVM_LIB_DIR := `$(CLANG_DIR)/llvm-config --libdir`

CLANG_LIBTOOLING_LIBS := \
	-lclang \
	-lstdc++ \
	-lclangAST \
	-lclangASTMatchers \
	-lclangAnalysis \
	-lclangBasic \
	-lclangDriver \
	-lclangEdit \
	-lclangFrontend \
	-lclangFrontendTool \
	-lclangLex \
	-lclangParse \
	-lclangSema \
	-lclangEdit \
	-lclangRewrite \
	-lclangRewriteFrontend \
	-lclangStaticAnalyzerFrontend \
	-lclangStaticAnalyzerCheckers \
	-lclangStaticAnalyzerCore \
	-lclangIndex \
	-lclangSerialization \
	-lclangToolingCore \
	-lclangTooling \
	-lclangFormat \
	$(LLVM_LIBS)

PKG-LINK-LIBS := $(CLANG_LIBTOOLING_LIBS)
PKG-CXX-EXTRA-FLAGS := `$(CLANG_DIR)/llvm-config --cxxflags` -UNDEBUG -Wno-non-virtual-dtor
ifeq ($(USE_CLANG), 1)
    # overcoming llvm 4.0.1 bug where llvm-config provides a warning suppression not implemented by clang...
    PKG-CXX-EXTRA-FLAGS := -Wno-unknown-warning-option $(PKG-CXX-EXTRA-FLAGS)
endif

ifeq ($(SERIALIZATION_TOOL_FORCE_NEW_ABI),1)
    PKG-CXX-EXTRA-FLAGS += -D_GLIBCXX_USE_CXX11_ABI=1
endif

ifeq ($(SERIALIZATION_TOOL_FORCE_OLD_ABI),1)
    # use old ABI (the one before gcc 5.0) to compile cereal module. LLVM libraries that are linked in the app should comply also the old ABI
    PKG-CXX-EXTRA-FLAGS += -D_GLIBCXX_USE_CXX11_ABI=0
endif

include $(MakefileTemplateRoot)/Makefile.module_vars

$(PKG)-LINK-FLAGS := $(LINK_FLAGS) -L$(LLVM_LIB_DIR) -Wl,--rpath,$(LLVM_LIB_DIR) -Wl,--rpath,$(FFI_LIB_DIR)
$($(PKG)-app): LINK_FLAGS := $($(PKG)-LINK-FLAGS)

# dummy empty cpp file to be used when activating the tool
$(PKG)-dummy-cpp := $($(PKG)-build-dir)/dummy.cpp
$($(PKG)-dummy-cpp):
	$(SILENT)$(MKDIR) -p $(@D)
	@touch $@

$(PKG)-as-dependency := $($(PKG)-as-dependency) $(cereal-gen-dummy-cpp)


include $(MakefileTemplateRoot)/Makefile.module_targets

