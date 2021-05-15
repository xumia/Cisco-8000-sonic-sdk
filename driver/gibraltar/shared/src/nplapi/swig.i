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

/// SWIG interface file for Leaba nplapi CLI.

%feature("flatnested");

%module nplapicli

%{

#include "common/bit_vector.h"
#include "common/la_status.h"
#include "common/resource_monitor.h"

#include "nplapi/device_tables.h"

#include "nplapi/npl_constants.h"
#include "nplapi/npl_table.h"
#include "nplapi/npl_ternary_table.h"
#include "nplapi/npl_lpm_table.h"
#include "nplapi/npl_lpm_bulk_types.h"

%}

%rename (resource_monitor) silicon_one::resource_monitor;

%include stdint.i
%include std_shared_ptr.i
%include std_string.i

// suppressing the warnings: Warning 401: Nothing known about base class 'std::enable_shared_from_this<...>
%warnfilter(SWIGWARN_TYPE_UNDEFINED_CLASS) npl_table;
%warnfilter(SWIGWARN_TYPE_UNDEFINED_CLASS) npl_ternary_table;
%warnfilter(SWIGWARN_TYPE_UNDEFINED_CLASS) npl_lpm_table;

%include "api/types/la_common_types.h"

%include "include/common/common_swig_typemaps.i"

///////////////////
/// Table type fields (keys, payloads) often return list of uint64_t
/// which should be treated as single number.
/// Leveraging the fact that PyLong does not have max value limitation.
///////////////////
%typemap(in,noblock=1) uint64_t [ANY] {
    // typemap in uint64_t[]
    $1 = (uint64_t*)malloc($1_dim0 * sizeof(uint64_t));

    _PyLong_AsByteArray((PyLongObject*)$input, (unsigned char*)$1, $1_dim0 * sizeof(uint64_t), 1 /* little endian */, 0 /* is signed */);
}

%typemap(out) uint64_t [ANY] {
    // typemap out uint64_t[]
    PyObject* o = _PyLong_FromByteArray((const unsigned char*)$1, $1_dim0 * sizeof(uint64_t), 1 /* little endian */, 0 /* is signed */);
    $result = o;
}

%typemap(freearg) uint64_t [ANY] {
    // typemap freearg uint64_t[]
    free($1);
}

%include "common/bit_vector.i"
BITVECTOR_TYPEMAPS(bit_vector)
BITVECTOR_TYPEMAPS(bit_vector64_t)
BITVECTOR_TYPEMAPS(bit_vector128_t)
BITVECTOR_TYPEMAPS(bit_vector192_t)
BITVECTOR_TYPEMAPS(bit_vector384_t)

///////////////////
/// NPL tables
///////////////////

// The below macros are to translate table specific translation of type-dependent entries.
// This implementation is twice faster and takes twice less space than template based implementation.
%define npl_table_translate_entry(table_name)
%inline %{
PyObject*
NPL_TABLE_TEMPLATE_SWIG_translate_entry(silicon_one::npl_table<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type entry, swig_type_info* key_info, swig_type_info* value_info)
{
    typedef silicon_one::npl_table<silicon_one::npl_##table_name##_functional_traits_t>::key_type key_t;
    typedef silicon_one::npl_table<silicon_one::npl_##table_name##_functional_traits_t>::value_type value_t;

    PyObject* tuple = PyTuple_New(2);
    PyTuple_SetItem(tuple, 0, SWIG_NewPointerObj(new key_t(entry->key()), key_info, SWIG_POINTER_OWN));
    PyTuple_SetItem(tuple, 1, SWIG_NewPointerObj(new value_t(entry->value()), value_info, SWIG_POINTER_OWN));

    return tuple;
}
%}
%enddef

%define npl_ternary_table_translate_entry(table_name)
%inline %{
PyObject*
NPL_TABLE_TEMPLATE_SWIG_translate_entry(silicon_one::npl_ternary_table<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type entry, swig_type_info* key_info, swig_type_info* value_info)
{
    typedef silicon_one::npl_ternary_table<silicon_one::npl_##table_name##_functional_traits_t>::key_type key_t;
    typedef silicon_one::npl_ternary_table<silicon_one::npl_##table_name##_functional_traits_t>::value_type value_t;

    PyObject* tuple = PyTuple_New(4);
    PyTuple_SetItem(tuple, 0, PyLong_FromLongLong(entry->line()));
    PyTuple_SetItem(tuple, 1, SWIG_NewPointerObj(new key_t(entry->key()), key_info, SWIG_POINTER_OWN));
    PyTuple_SetItem(tuple, 2, SWIG_NewPointerObj(new key_t(entry->mask()), key_info, SWIG_POINTER_OWN));
    PyTuple_SetItem(tuple, 3, SWIG_NewPointerObj(new value_t(entry->value()), value_info, SWIG_POINTER_OWN));

    return tuple;
}
%}
%enddef

%define npl_lpm_table_translate_entry(table_name)
%inline %{
PyObject*
NPL_TABLE_TEMPLATE_SWIG_translate_entry(silicon_one::npl_lpm_table<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type entry, swig_type_info* key_info, swig_type_info* value_info)
{
    typedef silicon_one::npl_lpm_table<silicon_one::npl_##table_name##_functional_traits_t>::key_type key_t;
    typedef silicon_one::npl_lpm_table<silicon_one::npl_##table_name##_functional_traits_t>::value_type value_t;

    PyObject* tuple = PyTuple_New(3);
    PyTuple_SetItem(tuple, 0, SWIG_NewPointerObj(new key_t(entry->key()), key_info, SWIG_POINTER_OWN));
    PyTuple_SetItem(tuple, 1, PyLong_FromLongLong(entry->length()));
    PyTuple_SetItem(tuple, 2, SWIG_NewPointerObj(new value_t(entry->value()), value_info, SWIG_POINTER_OWN));

    return tuple;
}
%}
%enddef

%define NPL_TABLE_TEMPLATE_TYPEMAPS(table_name, table_type)

%shared_ptr(silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>);

%ignore NPL_TABLE_TEMPLATE_SWIG_translate_entry;
##table_type##_translate_entry(##table_name##)

// Typemap to handle tables in device_tables class.
// Constructs Python list of tables, in case device_tables table variable is c-array.
%typemap(out) std::shared_ptr<silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t> > [ANY] {
    // TYPEMAP: NPL_table array return type
    int i;
    $result = PyList_New($1_dim0);
    for (i = 0; i < $1_dim0; i++) {
        auto obj = new std::shared_ptr<silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t> >($1[i]);
        PyObject* elem_object = SWIG_NewPointerObj(SWIG_as_voidptr(obj), $1_descriptor, SWIG_POINTER_OWN);

        PyList_SetItem($result, i, elem_object);
    }
}

// Typemap to handle tables in device_tables class.
// Constructs Python list of tables, in case device_tables table variable is single.
// This way all tables from device_tables are returned as list.
%typemap(out) std::shared_ptr<silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t> >& {
    // TYPEMAP: NPL_table single instance return type
    $result = PyList_New(1);
        auto obj = new std::shared_ptr<silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t> >(*$1);
        PyObject* elem_object = SWIG_NewPointerObj(SWIG_as_voidptr(obj), $1_descriptor, SWIG_POINTER_OWN);
    PyList_SetItem($result, 0, elem_object);
}

////////////////////////////////////
// Typemap to cancel out_entry parameter in SWIG version of table interfaces
%typemap(in,numinputs=0,noblock=1) silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type& out_entry {
    // TYPEMAP: NPL_table out_entry argout
    silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type var_out_entry_temp = nullptr;
    $1 = &var_out_entry_temp;
}

// Typemap to return entry->value instead of entry pointer
%typemap(in,numinputs=0,noblock=1) silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type& out_result_entry {
    // TYPEMAP: NPL_table out_result_entry in
    silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type var_out_result_entry_temp = nullptr;
    $1 = &var_out_result_entry_temp;
}

%typemap(argout) silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type& out_result_entry {
    // TYPEMAP: NPL_table out_result_entry argout
    PyObject *out_object = Py_None;
    if (result == LA_STATUS_SUCCESS && var_out_result_entry_temp != nullptr) {
        // Macro "descriptor" is needed to create SWIG pointers. It  exists only inside typemaps.
        // Since we create pointers in an outer procedures, we need to extract swig_type_info using the macro and pass it to procedures.
        swig_type_info* key_info = $descriptor(silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::key_type*);
        swig_type_info* value_info = $descriptor(silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::value_type*);
        out_object = NPL_TABLE_TEMPLATE_SWIG_translate_entry(var_out_result_entry_temp, key_info, value_info);
    }
    $result = out_object;
}
////////////////////////////////////

////////////////////////////////////
// Typemaps to return output location with status on npl_ternary_table::find* API
%typemap(in,numinputs=0,noblock=1) size_t& out_location {
    // TYPEMAP: NPL_table out_location in
    size_t var_##table_name##_location_temp = (size_t)-1;
    $1 = &var_##table_name##_location_temp;
}

%typemap(argout) size_t& out_location {
    // TYPEMAP: NPL_table out_location argout
    $result = (result == LA_STATUS_SUCCESS) ? PyLong_FromLongLong(*$1) : Py_None;
}
////////////////////////////////////

////////////////////////////////////
// Typemap to return list of entries
%typemap(out) std::vector<silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type> {
    // TYPEMAP: NPL_table out_entries array out
    swig_type_info* key_info = $descriptor(silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::key_type*);
    swig_type_info* value_info = $descriptor(silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::value_type*);

    $result = PyList_New(0);
    for (size_t i=0; i<$1.size(); ++i) {
        silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type curr = $1.at(i);
        PyObject* tuple = NPL_TABLE_TEMPLATE_SWIG_translate_entry(curr, key_info, value_info);
        PyList_Append($result, tuple);
        Py_CLEAR(tuple);
    }
}

%extend silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t> {
    std::vector<silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type> entries(size_t max_entries)
    {
        // extended method entries()
        max_entries = (max_entries) ? max_entries : (size_t)-1;
        max_entries = std::min(max_entries, self->size());
        std::vector<silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type> ret(max_entries, nullptr);
        if (ret.empty()) {
            return ret;
        }
        silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>::entry_pointer_type* buff = &ret[0];
        self->get_entries(buff, max_entries);
        return ret;
    }
}

////////////////////////////////////

%template(npl_##table_name##_t) silicon_one::##table_type##<silicon_one::npl_##table_name##_functional_traits_t>;

%enddef

%include "common/cereal_utils.h"
%include "common/common_fwd.h"
%include "common/resource_monitor.h"
%include "common/la_status.h"
%include "nplapi/npl_enums.h"
%include "nplapi/npl_tables_enum.h"
%include "nplapi/npl_types.h"
%include "nplapi/npl_table_types.h"
%include "nplapi/npl_functional_table_traits.h"

%ignore silicon_one::npl_table::entry;
%ignore silicon_one::npl_table::entry_less;
%ignore silicon_one::npl_table::initialize;
%ignore silicon_one::npl_table::get_entries;
%ignore silicon_one::npl_table::set_entry_value;
%include "nplapi/npl_constants.h"
%include "nplapi/npl_table.h"

%ignore silicon_one::npl_ternary_table::entry;
%ignore silicon_one::npl_ternary_table::initialize;
%ignore silicon_one::npl_ternary_table::get_entry;
%ignore silicon_one::npl_ternary_table::get_entries;
%ignore silicon_one::npl_ternary_table::set_entry_value;
%include "nplapi/npl_ternary_table.h"

%ignore silicon_one::npl_lpm_table::entry;
%ignore silicon_one::npl_lpm_table::entry_less;
%ignore silicon_one::npl_lpm_table::iterator;
%ignore silicon_one::npl_lpm_table::iterator::operator=;
%ignore silicon_one::npl_lpm_table::iterator::operator++;
%ignore silicon_one::npl_lpm_table::initialize;
%ignore silicon_one::npl_lpm_table::get_entries;
%ignore silicon_one::npl_lpm_table::set_entry_value;
%include "nplapi/npl_lpm_table.h"

%include "nplapi/npl_lpm_bulk_types.h"

// Autogenerated NPL_TABLE_TEMPLATE_TYPEMAPS definitions for all NPL tables.
%include "nplapi/nplapi_tables.i"

%include "nplapi/nplapi_tables.h"

%immutable;
%ignore silicon_one::device_tables::initialize_tables;
%include "nplapi/device_tables.h"
%mutable;


