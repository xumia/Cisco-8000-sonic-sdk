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

%{

#include "common/bit_vector.h"

using silicon_one::vector_alloc;
using silicon_one::bit_vector_dynamic_storage;
using silicon_one::bit_vector_static_storage;
using silicon_one::bit_vector;

typedef silicon_one::bit_vector_static_storage<1> bit_vector_static_storage_1;
typedef silicon_one::bit_vector_static_storage<2> bit_vector_static_storage_2;
typedef silicon_one::bit_vector_static_storage<3> bit_vector_static_storage_3;
typedef silicon_one::bit_vector_static_storage<6> bit_vector_static_storage_6;

%}

%define ARG_BITVECTOR_TYPEMAPS(BV_TYPE)

// Typemap converting enum out-arg to Python
%ignore PyObject_to_##BV_TYPE##;

%inline %{
BV_TYPE
PyObject_to_##BV_TYPE##(PyObject* obj)
{
    BV_TYPE ret;
    if (PyUnicode_Check(obj))
    {
        const char* value_string = PyUnicode_AsUTF8(obj);
        ret = BV_TYPE(value_string, strlen(value_string));
    } else if (PyLong_Check(obj)) {
        PyObject* string_object = _PyLong_Format(obj, 16);
        const char* value_string = PyUnicode_AsUTF8(string_object);

        ret = BV_TYPE(value_string);
	Py_CLEAR(string_object);
    } else {
        PyErr_SetString(PyExc_ValueError, "Expected integer or string.");
    }

    return ret;
}
%}

%typemap(in) BV_TYPE, silicon_one::BV_TYPE {
    // bit_vector typemap(in)
    $1 = PyObject_to_##BV_TYPE##($input);
}

%typemap(in) const BV_TYPE&, const silicon_one::BV_TYPE& {
    // bit_vector typemap(in)
    $1 = new BV_TYPE(PyObject_to_##BV_TYPE##($input));
}

%typemap(freearg) const BV_TYPE&, const silicon_one::BV_TYPE& {
    // bit_vector typemap(freearg)
    delete $1;
}

%typemap(out) BV_TYPE, silicon_one::BV_TYPE {
    // bit_vector typemap(out)
    $result = PyLong_FromString($1.to_string().c_str(), nullptr, 16);
}

%typemap(out) silicon_one::BV_TYPE*, const BV_TYPE&, const silicon_one::BV_TYPE& {
    // bit_vector typemap(out)
    $result = PyLong_FromString($1->to_string().c_str(), nullptr, 16);
}

%enddef

%define OUTARG_BITVECTOR_TYPEMAPS(BV_TYPE, ARG)

%typemap(in, numinputs=0, noblock=1) silicon_one::BV_TYPE& ARG (size_t _global_processed_args_count){
    _global_processed_args_count = 0;
    // bit_vector typemap (in) out-args
    $1 = new BV_TYPE();
}

%typemap(argout) silicon_one::BV_TYPE& ARG {
    // bit_vector typemap (argout) out-args
    PyObject* out_object = PyLong_FromString($1->to_string().c_str(), nullptr, 16);

    $result = add_argout_value($result, out_object, _global_processed_args_count);
}

%typemap(freearg) silicon_one::BV_TYPE& ARG {
    // bit_vector typemap (freearg) out-args
    delete $1;
}

%enddef

%define BITVECTOR_TYPEMAPS(BV_TYPE)
ARG_BITVECTOR_TYPEMAPS(BV_TYPE)
OUTARG_BITVECTOR_TYPEMAPS(BV_TYPE, out_bv)
OUTARG_BITVECTOR_TYPEMAPS(BV_TYPE, out_key_bv)
OUTARG_BITVECTOR_TYPEMAPS(BV_TYPE, out_mask_bv)
OUTARG_BITVECTOR_TYPEMAPS(BV_TYPE, out_payload_bv)
OUTARG_BITVECTOR_TYPEMAPS(BV_TYPE, out_value_bv)
%enddef

%include "common/common_swig_typemaps.i"

//without these, swig yells: Warning 389: operator[] ignored (consider using %extend)
%ignore silicon_one::bit_vector::operator=;
%ignore silicon_one::bit_vector::operator[];
%ignore silicon_one::bit_vector_base::operator=;
%ignore silicon_one::bit_vector_base::operator[];
%ignore silicon_one::bit_vector_dynamic_storage::operator=;
%ignore silicon_one::bit_vector_static_storage::operator[];
%ignore silicon_one::bit_vector_dynamic_storage::operator[];

// forbid constructor from already existing data
%ignore silicon_one::bit_vector_base::bit_vector_base(uint64_t*& data, size_t width);

// forbid move constructor
%ignore silicon_one::bit_vector_base::bit_vector_base(bit_vector_base&& other);
%ignore silicon_one::bit_vector_dynamic_storage::bit_vector_dynamic_storage(bit_vector_dynamic_storage &&);

// Avoid name collision with Python builtin 'hash'
%ignore silicon_one::bit_vector_base::hash;

// forbid direct access to the storage buffer
%ignore silicon_one::bit_vector_base<bit_vector_dynamic_storage>::byte_array();
%ignore silicon_one::bit_vector_base<bit_vector_static_storage_1>::byte_array();
%ignore silicon_one::bit_vector_base<bit_vector_static_storage_2>::byte_array();
%ignore silicon_one::bit_vector_base<bit_vector_static_storage_3>::byte_array();
%ignore silicon_one::bit_vector_base<bit_vector_static_storage_6>::byte_array();

%include "common/bit_vector.h"
%template (bit_vector) silicon_one::bit_vector_base<bit_vector_dynamic_storage>;

%template (bit_vector_static_storage_1) silicon_one::bit_vector_static_storage<1>;
%template (bit_vector_static_storage_2) silicon_one::bit_vector_static_storage<2>;
%template (bit_vector_static_storage_3) silicon_one::bit_vector_static_storage<3>;
%template (bit_vector_static_storage_6) silicon_one::bit_vector_static_storage<6>;

%template (bit_vector64_t) silicon_one::bit_vector_base<bit_vector_static_storage_1>;
%template (bit_vector128_t) silicon_one::bit_vector_base<bit_vector_static_storage_2>;
%template (bit_vector192_t) silicon_one::bit_vector_base<bit_vector_static_storage_3>;
%template (bit_vector384_t) silicon_one::bit_vector_base<bit_vector_static_storage_6>;

%pythoncode %{
def get_full_value(self):
    return int(self.to_string(), 16)

bit_vector.get_value = get_full_value
bit_vector64_t.get_value = get_full_value
bit_vector128_t.get_value = get_full_value
bit_vector192_t.get_value = get_full_value
bit_vector384_t.get_value = get_full_value
%}
