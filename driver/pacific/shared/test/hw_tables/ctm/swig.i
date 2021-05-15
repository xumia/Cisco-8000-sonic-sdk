// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

%module test_hw_tables_ctmcli
%include std_shared_ptr.i
%include std_string.i
%include std_map.i
%include std_vector.i
%include std_list.i
%include "../../../src/hw_tables/swig.i"

%include "common/common_swig_typemaps.i"

%{
#include "ctm/ctm_common.h"
#include "ctm/ctm_common_tcam.h"
#include "ctm/ctm_sram_allocator.h"
#include "ctm/ctm_config.h"
#include "ctm/ctm_config_tcam.h"
#include "ctm/ctm_config_pacific.h"
#include "ctm/ctm_config_gibraltar.h"

using namespace silicon_one;

%}

%shared_ptr(silicon_one::ctm_config_tcam)
%shared_ptr(silicon_one::ctm_config_pacific)
%shared_ptr(silicon_one::ctm_config_gibraltar)

OUTARG_STRUCT_TYPEMAPS(silicon_one::tcam_desc, out_tcam)

%template(tcams_list) std::vector<silicon_one::tcam_desc>;
%template(tcams_vec_vec) std::vector<std::vector<silicon_one::tcam_desc>>;
%template(priority_to_tcams_map) std::map<size_t,std::vector<std::vector<silicon_one::tcam_desc>>,std::greater<size_t>>;
OUT_VECTOR_TYPEMAPS(silicon_one::tcam_desc);

%include "ctm/ctm_common.h"
%include "ctm/ctm_common_tcam.h"
%include "ctm/ctm_sram_allocator.h"
%include "ctm/ctm_config.h"
%include "ctm/ctm_config_tcam.h"
%include "ctm/ctm_config_pacific.h"
%include "ctm/ctm_config_gibraltar.h"
