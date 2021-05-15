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

%feature("flatnested");

%module hw_tablescli

%include "lld/swig_typemaps.i"
%include "hw_tables/swig_typemaps.i"

%include std_shared_ptr.i
%include std_string.i
%include std_map.i
%include std_vector.i

%{

#include "common/la_status.h"
#include "common/logger.h"
#include "hw_tables/lpm_types.h"
#include "hw_tables/logical_lpm.h"
#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/lpm_settings.h"

#include "lpm/logical_lpm_impl.h"
#include "lpm/lpm_distributor.h"
#include "lpm/lpm_distributor_akpg.h"
#include "lpm/lpm_distributor_pacific_gb.h"
#include "lpm/lpm_core.h"
#include "lpm/lpm_hw_index_allocator.h"
#include "lpm/lpm_hw_index_allocator_adapter_hbm.h"
#include "lpm/lpm_hw_index_allocator_adapter_sram.h"
#include "lpm/lpm_hw_index_singles_allocator.h"
#include "lpm/lpm_hw_index_doubles_allocator.h"
#include "lpm/lpm_hw_index_doubles_allocator_pacific.h"
#include "lpm/lpm_bucket_occupancy_utils.h"
#include "lpm/lpm_device_simulator.h"

#include "hw_tables/cem.h"
#include "hw_tables/em_bank.h"
#include "hw_tables/physical_locations.h"
#include "hw_tables/em_core.h"
#include "hw_tables/em_hasher.h"
#include "hw_tables/em_common.h"

#include "lld/ll_device.h"
#include "lld/lld_register.h"
#include "lld/lld_memory.h"

using silicon_one::bit_vector64_t;
using silicon_one::bit_vector192_t;
using silicon_one::allocator_wrapper;

using namespace silicon_one;

%}


%include stdint.i

%include "common/common_swig_typemaps.i"

%include "common/allocator_wrapper.h"

%include "common/bit_vector.i"

%include "common/la_status.h"

%include "common/logger.h"

%inline %{
    void set_logging_level(int severity)
    {
        for (int device_id = 0; device_id <= logger::NUM_DEVICES; device_id++) {
            logger::instance().set_logging_level((la_device_id_t) device_id, silicon_one::la_logger_component_e::TABLES, (la_logger_level_e) severity);
        }
    }
%}


%include "api/types/la_common_types.h"

%include "hw_tables/hw_tables_fwd.h"
%include "hw_tables/lpm_settings.h"

%shared_ptr(silicon_one::logical_lpm_impl)
SHARED_FROM_THIS_TYPEMAPS(silicon_one::lpm_bucket)

OUTARG_VECTOR_TYPEMAPS(silicon_one::lpm_action_desc, out_actions)
OUTARG_BITVECTOR_TYPEMAPS(lpm_key_t, out_hit_key)
OUTARG_ENUM_TYPEMAPS(silicon_one::lpm_payload_t, out_hit_payload)
OUTARG_ENUM_TYPEMAPS(size_t, out_hit_row)
OUTARG_ENUM_TYPEMAPS(bool, out_is_default)
OUTARG_ENUM_TYPEMAPS(int, out_hw_index)
OUTARG_ENUM_TYPEMAPS(size_t, out_count_success)
OUTARG_VECTOR_TYPEMAPS(silicon_one::lpm_action_desc, out_l1_actions)
OUTARG_VECTOR_TYPEMAPS(silicon_one::lpm_action_desc, out_l2_actions)
OUTARG_VECTOR_TYPEMAPS(silicon_one::lpm_action_desc_internal, out_actions)
OUTARG_VECTOR_TYPEMAPS(silicon_one::lpm_action_desc_internal, out_l1_actions)
OUTARG_VECTOR_TYPEMAPS(silicon_one::lpm_action_desc_internal, out_l2_actions)
OUTARG_STRUCT_TYPEMAPS(silicon_one::tcam_cell_location, out_hit_location)
OUTARG_STRUCT_TYPEMAPS(silicon_one::lpm_key_payload, out_key_payload)
OUTARG_STRUCT_TYPEMAPS(silicon_one::distributor_cell_location, out_hit_location)
OUTARG_STRUCT_TYPEMAPS(silicon_one::hbm_physical_location, out_hbm_location)



%template(int_vec) std::vector<int>;

%template(vec_int) std::vector<int, silicon_one::allocator_wrapper<int>>;
%template() silicon_one::vector_alloc<int>;
OUT_ENUM_VECTOR_TYPEMAPS(int)

%template(size_t_vector)  std::vector<size_t>;

%template(vec_size_t) std::vector<size_t, silicon_one::allocator_wrapper<size_t>>;
%template() silicon_one::vector_alloc<size_t>;
OUT_ENUM_VECTOR_TYPEMAPS(size_t)



// LPM types
%include "hw_tables/lpm_types.h"
%include "lpm/lpm_internal_types.h"

%template(lpm_key) silicon_one::bit_vector_base<silicon_one::bit_vector_static_storage<3> >;

%template(lpm_key_payload_vec) std::vector<silicon_one::lpm_key_payload, silicon_one::allocator_wrapper<silicon_one::lpm_key_payload>>;
%template() silicon_one::vector_alloc<silicon_one::lpm_key_payload>;
OUT_VECTOR_TYPEMAPS(silicon_one::lpm_key_payload)

%template(lpm_key_payload_row_vec) std::vector<silicon_one::lpm_key_payload_row, silicon_one::allocator_wrapper<silicon_one::lpm_key_payload_row>>;
%template() silicon_one::vector_alloc<silicon_one::lpm_key_payload_row>;
OUT_VECTOR_TYPEMAPS(silicon_one::lpm_key_payload_row)

%template(int_vec) std::vector<int, silicon_one::allocator_wrapper<int>>;
%template() silicon_one::vector_alloc<int>;
OUT_ENUM_VECTOR_TYPEMAPS(int)

%template(lpm_core_buckets_occupancy_vec) std::vector<silicon_one::core_buckets_occupancy, silicon_one::allocator_wrapper<silicon_one::core_buckets_occupancy>>;
%template() silicon_one::vector_alloc<silicon_one::core_buckets_occupancy>;
OUT_VECTOR_TYPEMAPS(silicon_one::core_buckets_occupancy)

%template(lpm_action_desc_vec_t) std::vector<silicon_one::lpm_action_desc, silicon_one::allocator_wrapper<silicon_one::lpm_action_desc> >;
%template(lpm_implementation_desc_vec) std::vector<silicon_one::lpm_action_desc_internal, silicon_one::allocator_wrapper<silicon_one::lpm_action_desc_internal> >;



// Binary lpm tree and bucketing tree
%include "lpm/binary_lpm_tree.h"
%include "lpm/lpm_bucketing_data.h"

// LPM Node
//NOTE: due to the fact lpm node use tree_node template class, declaring 'shared_prt(lpm_node)' does not work:
//       * the argument of %shared_ptr must be a C++ type (not a C++ template or a SWIG %template)
//       * for example: need to use '%shared_ptr(Result<double>)' instead of '%shared_ptr(DoubleResult)'
//       --> Do not use the following: 'SHARED_FROM_THIS_TYPEMAPS(silicon_one::lpm_node)'
SHARED_FROM_THIS_TYPEMAPS(silicon_one::tree_node<silicon_one::lpm_bucketing_data>)
%template(lpm_node) silicon_one::tree_node<silicon_one::lpm_bucketing_data>;


// Logical LPM
%include "hw_tables/logical_lpm.h"
%include "lpm/logical_lpm_impl.h"

// LPM bucket
%template(lpm_node_vector)  std::vector<silicon_one::lpm_node*>;
%include "lpm/lpm_nodes_bucket.h"
%include "lpm/lpm_buckets_bucket.h"
%include "lpm/lpm_bucket.h"

%extend silicon_one::lpm_bucket {
	PyObject* downcast(silicon_one::lpm_level_e level) {
        PyObject* elem_object;
        if (level == lpm_level_e::L1) {
            silicon_one::lpm_buckets_bucket* casted_obj = static_cast<lpm_buckets_bucket*>(self);
            elem_object = SWIG_NewPointerObj(casted_obj, SWIGTYPE_p_silicon_one__lpm_buckets_bucket, 0);
        } else {
            silicon_one::lpm_nodes_bucket* casted_obj = static_cast<lpm_nodes_bucket*>(self);
            elem_object = SWIG_NewPointerObj(casted_obj, SWIGTYPE_p_silicon_one__lpm_nodes_bucket, 0);
        }
        return elem_object;
	}
}

SHARED_PTR_VEC_TYPEMAPS(silicon_one::lpm_bucket_const_ptr_vec, std::shared_ptr<silicon_one::lpm_bucket>, std::shared_ptr<const silicon_one::lpm_bucket>)

// LPM HBM Cache manager
%include "lpm/lpm_hbm_cache_manager.h"

// LPM tree
//%template(lpm_bucket_vector)  std::vector<std::shared_ptr<const silicon_one::lpm_bucket> >;

%inline %{
    struct tree_lookup_result {
        silicon_one::lpm_key_t key;
        silicon_one::lpm_payload_t payload;
        bool is_valid;
        bool is_default_entry;

        size_t get_width()
        {
            return key.get_width();
        }
    };
%}

%include "lpm/bucketing_tree.h"

%extend silicon_one::bucketing_tree {
    tree_lookup_result find_entry_as_hw(std::string key_str, size_t length, size_t core, lpm_level_e level, size_t hw_bucket_index) const
    {
        silicon_one::lpm_key_t key(key_str, length);

        tree_lookup_result res;

        la_status status = self->lookup(key, core, level, hw_bucket_index, res.key, res.payload, res.is_default_entry);
        if (status == LA_STATUS_SUCCESS) {
            res.is_valid = true;
        } else {
            res.is_valid = false;
        }

        return res;
    }
}

// LPM core tcam
%include "lpm/lpm_core_tcam_allocator.h"

%inline %{
    struct tcam_lookup_result {
        bool valid;
        silicon_one::lpm_key_t key;
        silicon_one::lpm_payload_t payload;
        silicon_one::tcam_cell_location location;
    };
%}

%include "lpm/lpm_core_tcam.h"

%template(lpm_tcam_logical_instruction_t) std::vector<silicon_one::lpm_logical_tcam::logical_instruction, silicon_one::allocator_wrapper<silicon_one::lpm_logical_tcam::logical_instruction> >;
%template() silicon_one::vector_alloc<silicon_one::lpm_logical_tcam::logical_instruction>;

%template(lpm_tcam_hardware_instruction_t) std::vector<silicon_one::lpm_core_tcam::hardware_instruction, silicon_one::allocator_wrapper<silicon_one::lpm_core_tcam::hardware_instruction> >;
%template() silicon_one::vector_alloc<silicon_one::lpm_core_tcam::hardware_instruction>;

%extend silicon_one::lpm_core_tcam {
    tcam_lookup_result find_entry_as_hw(std::string key_str, size_t length) const
    {
        tcam_lookup_result res;
        res.valid = false;
        silicon_one::lpm_key_t key(key_str, length);

        silicon_one::lpm_key_t hit_key;
        silicon_one::lpm_payload_t hit_payload;
        silicon_one::tcam_cell_location hit_location;

        la_status status = self->lookup_tcam_table(key, hit_key, hit_payload, hit_location);

        if (status != LA_STATUS_SUCCESS) {
            return res;
        }

        res.key = hit_key;
        res.payload = hit_payload;
        res.location = hit_location;
        res.valid = true;
        return res;
    }
}

%extend silicon_one::logical_lpm {
    const silicon_one::bucketing_tree* get_tree_unmanaged()
    {
        return self->get_tree().get();
    }
    const silicon_one::lpm_core* get_core_unmanaged(size_t idx)
    {
        return self->get_core(idx).get();
    }
}

// LPM distributor

%inline %{
    struct distributor_lookup_result {
        bool valid;
        silicon_one::lpm_key_t key;
        silicon_one::lpm_payload_t payload;
        silicon_one::distributor_cell_location location;
    };
%}

%include "lpm/lpm_distributor.h"

%template(lpm_key_payload_location_vec) std::vector<silicon_one::lpm_key_payload_location, silicon_one::allocator_wrapper<silicon_one::lpm_key_payload_location>>;
%template() silicon_one::vector_alloc<silicon_one::lpm_key_payload_location>;
OUT_VECTOR_TYPEMAPS(silicon_one::lpm_key_payload_location)

%extend silicon_one::lpm_distributor {
    distributor_lookup_result find_entry_as_hw(std::string key_str, size_t length) const
    {
        distributor_lookup_result res;
        res.valid = false;

        silicon_one::lpm_key_t key(key_str, length);

        silicon_one::lpm_key_t hit_key;
        silicon_one::lpm_payload_t hit_payload;
        silicon_one::distributor_cell_location hit_location;
        la_status status = self->lookup_tcam_table(key, hit_key, hit_payload, hit_location);

        if (status != LA_STATUS_SUCCESS) {
            return res;
        }

        res.key = hit_key;
        res.payload = hit_payload;
        res.location = hit_location;
        res.valid = true;
        return res;
    }
}

// LPM core writer
%template(lpm_entry_vector)  std::vector<silicon_one::lpm_entry>;
%ignore silicon_one::lpm_core_hw_writer::lpm_core_hw_writer;
OUTARG_ENUM_TYPEMAPS(size_t, out_default_payload)

%include "lpm/lpm_core_hw_writer.h"

// LPM core
%include "lpm/lpm_core.h"

%include "lpm/lpm_hw_index_allocator.h"
%include "lpm/lpm_hw_index_allocator_adapter_hbm.h"
%include "lpm/lpm_hw_index_allocator_adapter_sram.h"
%include "lpm/lpm_hw_index_singles_allocator.h"
%include "lpm/lpm_hw_index_doubles_allocator.h"
%include "lpm/lpm_hw_index_doubles_allocator_pacific.h"
%include "lpm/lpm_common.h"
%include "lpm/lpm_bucket_occupancy_utils.h"

%typemap(in, numinputs=0, noblock=1) silicon_one::cem_location& out_location {
    // cem_location typemap (in) out-args
    $1 = new silicon_one::cem_location();
}

%typemap(argout) silicon_one::cem_location& out_location {
    // cem_location typemap (argout) out-args
    if (! PyList_Check($result)) {
        $result = PyList_New(1);
        PyList_SetItem($result, 0, SWIG_From_int(static_cast<int>(result.value())));
    }

    PyObject* obj = SWIG_NewPointerObj($1, $1_descriptor, SWIG_POINTER_OWN);
    PyList_Append($result, obj);

    Py_CLEAR(obj);
}

%include "hw_tables/cem.h"

%include "hw_tables/em_bank.h"

// EM core
%include "hw_tables/physical_locations.h"
%include "hw_tables/em_common.h"
%include "hw_tables/em_core.h"
%include "hw_tables/em_hasher.h"

%template(banks_vector) std::vector<silicon_one::physical_em::bank>;
%template(em_payload) silicon_one::bit_vector_base<silicon_one::bit_vector_dynamic_storage>;
%template(em_key) silicon_one::bit_vector_base<silicon_one::bit_vector_dynamic_storage>;

%pythoncode %{
def get_full_value(self):
    s = self.to_string()
    return 0 if s == '' else int(s, 16)

lpm_key.get_value = get_full_value
em_payload.get_value = get_full_value
em_key.get_value = get_full_value
%}

// LPM HW simulator

%include "lpm/lpm_device_simulator.h"


%newobject silicon_one::create_lpm_device_simulator();
