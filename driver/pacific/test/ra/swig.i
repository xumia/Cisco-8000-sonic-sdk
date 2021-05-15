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

%module test_racli

%include std_string.i
%include std_map.i
%include std_vector.i
%include "../../src/ra/swig.i"

%{
#include "common/la_status.h"
#include "ra/ra_flow.h"
#include "ra/resource_manager.h"
#include "test_ra_flow.h"
#include "sim_provider/sim_provider.h"
#include "ra_sim_provider.h"
#include "ra_device_simulator.h"

#include "ra_enums.h"
#include "engine_block_mapper.h"
#include "ctm/ctm_common.h"
#include "special_tables/ctm_mgr.h"

using silicon_one::bit_vector64_t;
using silicon_one::bit_vector192_t;
using silicon_one::allocator_wrapper;

using namespace silicon_one;

using silicon_one::sim_packet_info_desc;
%}

%template(sim_packet_desc_vector)  std::vector<silicon_one::sim_packet_info_desc>;
%template(size_t_vector)  std::vector<size_t>;

%include "common/bit_vector.i"
//BITVECTOR_TYPEMAPS(bit_vector)

%template(ctm_payload) silicon_one::bit_vector_base<silicon_one::bit_vector_dynamic_storage>;
%template(ctm_key) silicon_one::bit_vector_base<silicon_one::bit_vector_dynamic_storage>;
%template(ctm_mask) silicon_one::bit_vector_base<silicon_one::bit_vector_dynamic_storage>;

%typemap(in) const silicon_one::sim_initial_metadata_map_t& initial_values {
    // Just fool swig to recognize this conversion
    // RA sim provider is not using it anyways
}

%typecheck(SWIG_TYPECHECK_POINTER) const silicon_one::sim_initial_metadata_map_t& {
    $1 = (PyDict_Check($input) == 0) ? 0 : 1;
}

%ignore la_status2str;
%include "common/la_status.h"

%include "api/types/la_common_types.h"
%include "lld/device_simulator.h"
%include "test_ra_flow.h"
%include "sim_provider/sim_provider.h"
%include "ra_sim_provider.h"
%include "ra_device_simulator.h"

%ignore silicon_one::resource_manager::resource_manager;
%include "ra/resource_manager.h"
%extend silicon_one::resource_manager {
    silicon_one::logical_lpm* get_lpm_unmanaged()
    {
        return self->get_lpm().get();
    }
}

%include "ra_enums.h"
%include "engine_block_mapper.h"
%include "ctm/ctm_common.h"
%include "special_tables/ctm_mgr.h"

%pythoncode %{
def get_full_value(self):
    s = self.to_string()
    return 0 if s == '' else int(s, 16)

ctm_payload.get_value = get_full_value
ctm_key.get_value = get_full_value
ctm_mask.get_value = get_full_value
%}

