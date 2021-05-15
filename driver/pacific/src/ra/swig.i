// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


/// SWIG interface file for resource allocation module.

%module racli

%include "lld/swig_typemaps.i"

%include "common/common_swig_typemaps.i"

OUT_ENUM_VECTOR_REF_TYPEMAPS(silicon_one::ctm::logical_table_type_e)
OUTARG_ENUM_TYPEMAPS(size_t, slice)

%include "hw_tables/swig_typemaps.i"
%{
    #include "hw_tables/hw_tables_fwd.h"
    #include "ra/ra_types_fwd.h"
%}
%include std_shared_ptr.i
%shared_ptr(silicon_one::cem)
%shared_ptr(silicon_one::ctm_mgr)
%shared_ptr(silicon_one::ctm_config)
%shared_ptr(silicon_one::ctm_config_tcam)

%include "ra/ra_flow.h"

%{
#include "ra/ra_flow.h"
%}

%include "ra/ra_types_fwd.h"
%include "ctm/ctm_common.h"
%include "ctm/ctm_config.h"
%include "ctm/ctm_config_tcam.h"
%{
using namespace silicon_one;
#include "ctm/ctm_config.h"
#include "ctm/ctm_config_tcam.h"
%}

%inline %{

silicon_one::ctm_config_tcam* ctm_config_to_ctm_config_tcam(silicon_one::ctm_config* config){

        return (silicon_one::ctm_config_tcam*) config;
}
%}
