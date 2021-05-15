// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

/// SWIG interface file for Leaba low-level driver/CLI.

%module lldcli
%{

#include <string>

#include "api/types/la_common_types.h"
#include "lld/lld_block.h"
#include "lld/lld_storage.h"
#include "lld/lld_register.h"
#include "lld/lld_memory.h"
#include "common/la_status.h"
#include "lld/device_simulator.h"
#include "lld/ll_device.h"
#include "lld/ll_transaction.h"
#include "lld/device_tree.h"
#include "common/logger.h"
#include "common/gen_utils.h"
#include "lld/interrupt_tree.h"

#define LEABA_SWIG_BUFFER_SIZE 160

using namespace silicon_one;

%}

%include stdint.i
%include std_shared_ptr.i
%include std_string.i
%include std_vector.i

namespace std {
   %template(UshortVector) vector<unsigned short>;
}

%shared_ptr(silicon_one::ll_device)
%shared_ptr(silicon_one::lld_block)
%shared_ptr(silicon_one::pacific_tree)
%shared_ptr(silicon_one::gibraltar_tree)

%import "common/cereal_utils.h"
%include "common/common_swig_typemaps.i"

%define ARRAY_CONTAINER_TYPEMAPS(ARRAY_HANDLE_TYPE, HANDLE_TYPE)
//without these, swig yells: Warning 389: operator[] ignored (consider using %extend)
%ignore CONTAINER::operator[];

%typemap(out) ARRAY_HANDLE_TYPE* {
    // TYPEMAP: ARRAY_CONTAINER_FUNCTIONS

    $result = PyList_New(0);
    for (size_t i = 0; i < (*$1)->size(); i++) {
        auto smartresult = new decltype((*(*$1))[i])((*(*$1))[i]);
        PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(smartresult), $descriptor(HANDLE_TYPE*), SWIG_POINTER_OWN);
        PyList_Append($result, obj);
        Py_CLEAR(obj);
    }
}

%enddef

%define CARRAY_SPTR_TYPEMAPS(HANDLE_TYPE)

%typemap(out) HANDLE_TYPE [ANY] {
    $result = PyList_New(0);

    for (size_t i = 0; i < $1_dim0; i++) {
        HANDLE_TYPE* smartresult = new HANDLE_TYPE($1[i]);
        PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(smartresult), $descriptor(HANDLE_TYPE*), SWIG_POINTER_OWN);
        PyList_Append($result, obj);
        Py_CLEAR(obj);
    }
}

%enddef

ARRAY_CONTAINER_TYPEMAPS(silicon_one::lld_register_array_scptr, std::shared_ptr<silicon_one::lld_register>)
ARRAY_CONTAINER_TYPEMAPS(silicon_one::lld_memory_array_scptr, std::shared_ptr<silicon_one::lld_memory>)
ARRAY_CONTAINER_TYPEMAPS(silicon_one::lld_register_array_sptr, std::shared_ptr<silicon_one::lld_register>)
ARRAY_CONTAINER_TYPEMAPS(silicon_one::lld_memory_array_sptr, std::shared_ptr<silicon_one::lld_memory>)

SHARED_PTR_VEC_TYPEMAPS(silicon_one::lld_block::lld_register_vec_t, std::shared_ptr<silicon_one::lld_register>, std::shared_ptr<const silicon_one::lld_register>)
SHARED_PTR_VEC_TYPEMAPS(silicon_one::lld_block::lld_memory_vec_t, std::shared_ptr<silicon_one::lld_memory>, std::shared_ptr<const silicon_one::lld_memory>)
SHARED_PTR_VEC_TYPEMAPS(silicon_one::lld_block::lld_block_vec_t, std::shared_ptr<silicon_one::lld_block>, std::shared_ptr<const silicon_one::lld_block>)

OUTARG_ENUM_VECTOR_TYPEMAPS(uint16_t, out_unit_ids)
OUTARG_ENUM_TYPEMAPS(uint32_t, out_unit_ids_valid)
OUTARG_ENUM_TYPEMAPS(uint32_t, out_valid_mask)
OUTARG_ENUM_TYPEMAPS(bool, out_unit_id_valid)

%shared_ptr(silicon_one::lld_storage)
%shared_ptr(silicon_one::lld_memory)
%shared_ptr(silicon_one::lld_register)

%{

#define DEVICE_TREE_DOWNCAST_MACRO(DEVICE_NAME) \
    { \
        auto casted_obj = std::dynamic_pointer_cast<const silicon_one::DEVICE_NAME##_tree>(device_tree); \
        if (casted_obj != nullptr) { \
            auto smartresult = new std::shared_ptr<const silicon_one::DEVICE_NAME##_tree>(casted_obj); \
            PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(smartresult), SWIGTYPE_p_std__shared_ptrT_silicon_one__##DEVICE_NAME##_tree_t, SWIG_POINTER_OWN); \
            return obj; \
        } \
    }

    PyObject*
    get_downcast_device_tree(silicon_one::lld_block_scptr device_tree) {
        if (device_tree == nullptr) {
            PyErr_SetString(PyExc_ValueError, "Expecting to get the device tree");
            return nullptr;
        }
        DEVICE_TREE_DOWNCAST_MACRO(pacific)
        DEVICE_TREE_DOWNCAST_MACRO(gibraltar)
        PyErr_SetString(PyExc_ValueError, "Got unknown device tree");
        return nullptr;
    }
%}

/****************************************************************************************/
/* Mapping functions that return value is void* parameter to return Python long values. */
/*                                                                                      */
/* TODO: Currently return only key, need to change and return pair of (key,mask)        */
/****************************************************************************************/
%typemap(in,numinputs=0,noblock=1) size_t out_buf_sz, size_t out_val_sz {
    $1 = LEABA_SWIG_BUFFER_SIZE;
}

%typemap(in,numinputs=0,noblock=1) void* out_val, void* out_key, void* out_mask {
    $1 = calloc(LEABA_SWIG_BUFFER_SIZE, 1);
}

%{
//argout helper conversion function
static PyObject *
convert_array_to_string(void* arr) {
    const char hex_str[] = "0123456789ABCDEF";
    char res_str[2*LEABA_SWIG_BUFFER_SIZE + 1];

    uint8_t* res8 = (uint8_t*)arr;

    for (int i = 0; i < LEABA_SWIG_BUFFER_SIZE; i++) {
        res_str[(LEABA_SWIG_BUFFER_SIZE - i) * 2 - 1] = hex_str[res8[i] & 0xF];
        res_str[(LEABA_SWIG_BUFFER_SIZE - i) * 2 - 2] = hex_str[(res8[i] >> 4) & 0xF];
    }
    res_str[2*LEABA_SWIG_BUFFER_SIZE] = 0;

    return PyLong_FromString(res_str, nullptr, 16);
}
%}

%typemap(argout) void* out_val, void* out_key {
    if (error_mode == error_mode_e::EXCEPTION) {
        $result = convert_array_to_string($1);
    } else {
        $result = PyList_New(2);
        PyObject* out_object = (result == LA_STATUS_SUCCESS) ? convert_array_to_string($1) : Py_None;
        PyList_SetItem($result, 0, SWIG_From_int((result.value())));
        PyList_SetItem($result, 1, out_object);
    }
}

%typemap(freearg) void* out_val, void* in_val,
                  void* in_key, void* in_mask, void* out_key, void* out_mask {
    free($1);
}

/*********************************************************************************/
 /* Mapping functions that input value is a void* parameter to input int32 value.
  */
%typemap(in,numinputs=0,noblock=1) size_t in_buf_sz, size_t in_val_sz, size_t key_mask_sz {
    // TODO: verify in_buf_size is smaller than LEABA_SWIG_BUFFER_SIZE.
    $1 = LEABA_SWIG_BUFFER_SIZE;
}

%typemap(in) void* in_val , void* in_key , void* in_mask {
    // Should be done using typemap check
    $1 = calloc(LEABA_SWIG_BUFFER_SIZE, 1);

    const char* value_string = nullptr;

    if (PyUnicode_Check($input))
    {
        value_string = PyUnicode_AsUTF8($input);
    } else if (PyLong_Check($input)) {
        PyObject* string_object = _PyLong_Format($input, 16);
        value_string = PyUnicode_AsUTF8(string_object);
        Py_CLEAR(string_object);
    } else {
        PyErr_SetString(PyExc_ValueError, "Expected integer or string.");

        return nullptr;
    }

    size_t val_len = strlen(value_string);
    unsigned char* byte_vec = (unsigned char*)$1;
    for (size_t i = 2; i < val_len; i++) {
        unsigned char val_letter = value_string[i];
        unsigned char val = (val_letter >= 'a') ? (val_letter - 'a' + 0xa) : (val_letter - '0');

        size_t letter_idx = val_len - 1 - i;
        size_t byte_vec_idx = letter_idx / 2;
        if ((letter_idx % 2) == 1)
            val <<= 4;

        byte_vec[byte_vec_idx] |= val;
    }
}


OUTARG_BOOL_TYPEMAPS(out_valid)

%inline %{
    silicon_one::ll_device_sptr
    ll_device_create(la_device_id_t device_id, const char* device_path)
    {
        return silicon_one::ll_device::create(device_id, device_path);
    }
%}

%include "common/bit_vector.i"

BITVECTOR_TYPEMAPS(bit_vector)

%feature("autodoc", "1");

// without these python yells: Warning 451: Setting a const char * variable may leak memory.
%feature("immutable","1") silicon_one::lld_register_desc_t::desc;
%feature("immutable","1") silicon_one::lld_register_desc_t::name;
%feature("immutable","1") silicon_one::lld_memory_desc_t::desc;
%feature("immutable","1") silicon_one::lld_memory_desc_t::name;
%feature("immutable","1") silicon_one::lld_memory_desc_t::wrapper;
%feature("immutable","1") silicon_one::lld_field_desc::name;

// Template instantiations
%include "api/types/la_common_types.h"
%include "lld/lld_fwd.h"
%include "lld/lld_block.h"

%include "lld/pacific_tree.i"
%include "lld/gibraltar_tree.i"

%include "lld/lld_storage.h"
%include "lld/lld_register.h"
%include "lld/lld_memory.h"
%include "common/la_status.h"
%include "lld/device_simulator.h"
%include "lld/ll_device.h"
%include "lld/ll_transaction.h"
%include "lld/interrupt_tree.h"
%immutable;
%include "lld/pacific_tree.h"
%include "lld/gibraltar_tree.h"
%mutable;
%include "common/logger.h"

%template(lld_block_vector) std::vector<const silicon_one::lld_block*>;
%template(lld_field_desc_vector) std::vector<silicon_one::lld_field_desc>;

%extend silicon_one::ll_device
{
    PyObject*
    get_device_tree_downcast() {
        return get_downcast_device_tree(self->get_device_tree());
    }
}

%inline %{
    void set_logging_level(int device, int severity)
    {
        logger::instance().set_logging_level((la_device_id_t) device, (la_logger_level_e) severity);
    }
%}

%inline %{
    void set_logging_level(int severity)
    {
        for (int device_id = 0; device_id <= logger::NUM_DEVICES; device_id++) {
            logger::instance().set_logging_level((la_device_id_t) device_id, (la_logger_level_e) severity);
        }

    }
%}
