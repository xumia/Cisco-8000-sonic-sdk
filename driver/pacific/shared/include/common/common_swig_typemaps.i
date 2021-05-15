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
#include <iostream>
#include <sstream>
#include "Python.h"
#include "common/la_status.h"
#include "common/allocator_wrapper.h"

// @brief      LeabaExceptions class stores all custom python exceptions, one per error type.
//
// @details    LeabaExceptions is implemented as a singleton class in order to enforce single initialization of same exception in all modules.
//             Ctor is defined as private and getInstance() as static to restrict the instantiation to one object.
class LeabaExceptions : public PyObject
{
    private:
        LeabaExceptions();

    public:
        static LeabaExceptions* getInstance()
        {
            static LeabaExceptions m_exc;

            return &m_exc;
        }

        PyObject* la_status2py_exception(la_status result);

        PyObject* m_base;
        PyObject* m_again;
        PyObject* m_out_of_memory;
        PyObject* m_acces;
        PyObject* m_busy;
        PyObject* m_exist;
        PyObject* m_no_dev;
        PyObject* m_inval;
        PyObject* m_different_devs;
        PyObject* m_resource;
        PyObject* m_not_found;
        PyObject* m_not_implemented;
        PyObject* m_unknown;
        PyObject* m_size;
        PyObject* m_not_initialized;
        PyObject* m_double_fault;
        PyObject* m_out_of_range;

};

LeabaExceptions::LeabaExceptions() {
    m_base = PyErr_NewException("Leaba.BaseException", PyExc_BaseException, NULL /*dict*/);
    m_again = PyErr_NewException("Leaba.AgainException", m_base, NULL /*dict*/);
    m_out_of_memory = PyErr_NewException("Leaba.OutOfMemoryException", m_base, NULL /*dict*/);
    m_acces = PyErr_NewException("Leaba.AccesException", m_base, NULL /*dict*/);
    m_busy = PyErr_NewException("Leaba.BusyException", m_base, NULL /*dict*/);
    m_exist = PyErr_NewException("Leaba.ExistException", m_base, NULL /*dict*/);
    m_no_dev = PyErr_NewException("Leaba.NoDevException", m_base, NULL /*dict*/);
    m_inval = PyErr_NewException("Leaba.InvalException", m_base, NULL /*dict*/);
    m_different_devs = PyErr_NewException("Leaba.DifferentDevsException", m_base, NULL /*dict*/);
    m_resource = PyErr_NewException("Leaba.ResourceException", m_base, NULL /*dict*/);
    m_not_found = PyErr_NewException("Leaba.NotFoundException", m_base, NULL /*dict*/);
    m_not_implemented = PyErr_NewException("Leaba.NotImplementedException", m_base, NULL /*dict*/);
    m_unknown = PyErr_NewException("Leaba.UnknownException", m_base, NULL /*dict*/);
    m_size = PyErr_NewException("Leaba.SizeException", m_base, NULL /*dict*/);
    m_not_initialized = PyErr_NewException("Leaba.NotInitializedException", m_base, NULL /*dict*/);
    m_double_fault = PyErr_NewException("Leaba.DoubleFaultException", m_base, NULL /*dict*/);
    m_out_of_range = PyErr_NewException("Leaba.OutOfRangeException", m_base, NULL /*dict*/);

    // Enlargement of reference counter for each object to prevent core dump (as a result of a reference counter reset).
    // Number of iterations is arbitrary.
    for (int i=0 ; i<20; i++){
        Py_INCREF(m_base);
        Py_INCREF(m_again);
        Py_INCREF(m_out_of_memory);
        Py_INCREF(m_acces);
        Py_INCREF(m_busy);
        Py_INCREF(m_exist);
        Py_INCREF(m_no_dev);
        Py_INCREF(m_inval);
        Py_INCREF(m_different_devs);
        Py_INCREF(m_resource);
        Py_INCREF(m_not_found);
        Py_INCREF(m_not_implemented);
        Py_INCREF(m_unknown);
        Py_INCREF(m_size);
        Py_INCREF(m_not_initialized);
        Py_INCREF(m_double_fault);
        Py_INCREF(m_out_of_range);
    }

}

PyObject* LeabaExceptions::la_status2py_exception(la_status result) {
    if (result == LA_STATUS_EAGAIN){
        return m_again;
    } else if (result == LA_STATUS_EOUTOFMEMORY){
        return m_out_of_memory;
    } else if (result == LA_STATUS_EACCES) {
        return m_acces;
    } else if (result == LA_STATUS_EBUSY){
        return m_busy;
    } else if (result == LA_STATUS_EEXIST){
        return m_exist;
    } else if (result == LA_STATUS_ENODEV){
        return m_no_dev;
    } else if (result == LA_STATUS_EINVAL){
        return m_inval;
    } else if (result == LA_STATUS_EDIFFERENT_DEVS){
        return m_different_devs;
    } else if (result == LA_STATUS_ERESOURCE){
        return m_resource;
    } else if (result == LA_STATUS_ENOTFOUND){
        return m_not_found;
    } else if (result == LA_STATUS_ENOTIMPLEMENTED){
        return m_not_implemented;
    } else if (result == LA_STATUS_EUNKNOWN){
        return m_unknown;
    } else if (result == LA_STATUS_ESIZE){
        return m_size;
    } else if (result == LA_STATUS_ENOTINITIALIZED){
        return m_not_initialized;
    } else if (result == LA_STATUS_EDOUBLE_FAULT){
        return m_double_fault;
    } else if (result == LA_STATUS_EOUTOFRANGE){
        return m_out_of_range;
    }
    return m_base;

}


static LeabaExceptions* LaExceptions = LeabaExceptions::getInstance();

enum class error_mode_e
{
    CODE,
    EXCEPTION,
};

error_mode_e __attribute__((weak)) error_mode = error_mode_e::EXCEPTION;

void write_error_string(size_t accessed_index, size_t last_index)
{
    std::ostringstream error_message_stream;
    error_message_stream << "index-out-of-bounds." << " accessed index=" << accessed_index << " while list size=" << last_index;
    std::string error_message = error_message_stream.str();
    PyErr_SetString(PyExc_IndexError,error_message.c_str());
}

PyObject* add_argout_value(PyObject* current_obj, PyObject* new_obj, size_t& processed_args_count)
{
    if (processed_args_count == 0) {
        processed_args_count ++;
        if (current_obj == Py_None) {
            Py_CLEAR(current_obj);
            return new_obj;
        }
    }

    if (processed_args_count == 1) {
        PyObject* l = PyList_New(1);

        PyList_SetItem(l, 0, current_obj);

        current_obj = l;
    }

    PyList_Append(current_obj, new_obj);

    Py_CLEAR(new_obj);
    processed_args_count ++;
    return current_obj;
}

%}

%init %{
    PyModule_AddObject(m, "BaseException", LaExceptions->m_base);
    PyModule_AddObject(m, "AgainException", LaExceptions->m_again);
    PyModule_AddObject(m, "OutOfMemoryException", LaExceptions->m_out_of_memory);
    PyModule_AddObject(m, "AccesException", LaExceptions->m_acces);
    PyModule_AddObject(m, "BusyException", LaExceptions->m_busy);
    PyModule_AddObject(m, "ExistException", LaExceptions->m_exist);
    PyModule_AddObject(m, "NoDevException", LaExceptions->m_no_dev);
    PyModule_AddObject(m, "InvalException", LaExceptions->m_inval);
    PyModule_AddObject(m, "DifferentDevsException", LaExceptions->m_different_devs);
    PyModule_AddObject(m, "ResourceException", LaExceptions->m_resource);
    PyModule_AddObject(m, "NotFoundException", LaExceptions->m_not_found);
    PyModule_AddObject(m, "NotImplementedException", LaExceptions->m_not_implemented);
    PyModule_AddObject(m, "UnknownException", LaExceptions->m_unknown);
    PyModule_AddObject(m, "SizeException", LaExceptions->m_size);
    PyModule_AddObject(m, "NotInitializedException", LaExceptions->m_not_initialized);
    PyModule_AddObject(m, "DoubleFaultException", LaExceptions->m_double_fault);
    PyModule_AddObject(m, "OutOfRangeException", LaExceptions->m_out_of_range);
%}

%pythoncode %{
    module_name = __name__
    module_swig_name = '_%s' % module_name.split('.')[-1]

    BaseException = eval(module_swig_name + '.BaseException')
    AgainException  = eval(module_swig_name + '.AgainException')
    OutOfMemoryException  = eval(module_swig_name + '.OutOfMemoryException')
    AccesException  = eval(module_swig_name + '.AccesException')
    BusyException  = eval(module_swig_name + '.BusyException')
    ExistException  = eval(module_swig_name + '.ExistException')
    NoDevException  = eval(module_swig_name + '.NoDevException')
    InvalException  = eval(module_swig_name + '.InvalException')
    DifferentDevsException  = eval(module_swig_name + '.DifferentDevsException')
    ResourceException  = eval(module_swig_name + '.ResourceException')
    NotFoundException  = eval(module_swig_name + '.NotFoundException')
    NotImplementedException  = eval(module_swig_name + '.NotImplementedException')
    UnknownException  = eval(module_swig_name + '.UnknownException')
    SizeException  = eval(module_swig_name + '.SizeException')
    NotInitializedException  = eval(module_swig_name + '.NotInitializedException')
    DoubleFaultException  = eval(module_swig_name + '.DoubleFaultException')
    OutOfRangeException  = eval(module_swig_name + '.OutOfRangeException')
%}


enum class error_mode_e
{
    CODE,
    EXCEPTION,
};

%typemap(out) la_status {
    $result = SWIG_From_int(static_cast<int>(result.value()));
    if (error_mode == error_mode_e::EXCEPTION) {
        if (result != LA_STATUS_SUCCESS) {
            PyObject* actual_exc = LaExceptions->la_status2py_exception(result);
            Py_INCREF(actual_exc);
            la_status* result_copy = new la_status(result);
            PyObject* py_status = SWIG_NewPointerObj(SWIG_as_voidptr(result_copy), $descriptor(la_status*), SWIG_POINTER_OWN);
            PyObject_SetAttrString(actual_exc, "status", py_status);
            Py_CLEAR(py_status);
            // This will create a tuple of types integer and string - hence first argument is "(is)"
            // where () is for the tuple, i for an integer and s for a string.
            PyObject* args = Py_BuildValue("(is)", result.value(), result.message().c_str());
            PyErr_SetObject(actual_exc, args);
            Py_DECREF(args);
            SWIG_fail;
        }

        $result = Py_None;
        Py_INCREF($result);
    }
}
%include std_shared_ptr.i
%shared_ptr(la_status_info)
%shared_ptr(la_status_info_e_resource_counter)
%shared_ptr(la_status_info_e_resource_table)

// Typemap converting enum out-arg to Python
%define OUTARG_ENUM_TYPEMAPS(TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) TYPE& ARG (size_t _global_processed_args_count){
    _global_processed_args_count = 0;
    $1 = ($ltype)calloc(1, sizeof($ltype));
}

%typemap(argout) TYPE& ARG {
    PyObject* out_object = SWIG_From_long_SS_long(static_cast<long long>(*$1));

    $result = add_argout_value($result, out_object, _global_processed_args_count);
}

%typemap(freearg) TYPE& ARG {
    free($1);
}

%enddef

// Typemap converting chrono out-arg to Python
%define OUTARG_CHRONO_TYPEMAPS(TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) TYPE& ARG (size_t _global_processed_args_count){
    _global_processed_args_count = 0;
    $1 = ($ltype)calloc(1, sizeof($ltype));
}

%typemap(argout) TYPE& ARG {
    PyObject* out_object = SWIG_From_long_SS_long(static_cast<long long>(($1)->count()));

    $result = add_argout_value($result, out_object, _global_processed_args_count);
}

%typemap(freearg) TYPE& ARG {
    free($1);
}

%enddef

// Typemap converting float out-arg to Python
%define OUTARG_FLOAT_TYPEMAPS(TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) TYPE& ARG (size_t _global_processed_args_count){
    _global_processed_args_count = 0;
    $1 = ($ltype)calloc(1, sizeof($ltype));
}

%typemap(argout) TYPE& ARG {
    PyObject* out_object = PyFloat_FromDouble(static_cast<double>(*$1));

    $result = add_argout_value($result, out_object, _global_processed_args_count);
}

%typemap(freearg) TYPE& ARG {
    free($1);
}

%enddef

// Typemap converting enum out-arg to Python
%define OUTARG_BOOL_TYPEMAPS(ARG)

%typemap(in,numinputs=0,noblock=1) bool& ARG (size_t _global_processed_args_count){
    _global_processed_args_count = 0;
    bool temp_$1 = false;
    $1 = &temp_$1;
}

%typemap(argout) bool& ARG {
    PyObject* out_object = PyBool_FromLong(temp_$1);

    $result = add_argout_value($result, out_object, _global_processed_args_count);
}

%enddef

// Typemap converting enum out-arg to Python when the orignal function does return void.
%define OUTARG_ENUM_TYPEMAPS_VOID(TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) TYPE& ARG {
    $1 = ($ltype)calloc(1, sizeof($ltype));
}

%typemap(argout) TYPE& ARG {
    $result = SWIG_From_int(static_cast<int>(*$1));
}

%typemap(freearg) TYPE& ARG {
    free($1);
}

%enddef


%define OUTARG_ENUM_VECTOR_TYPEMAPS(ELEM_TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) std::vector<ELEM_TYPE>& ARG {
    $1 = new $*ltype();
}

%typemap(argout) std::vector<ELEM_TYPE>& ARG {


    PyObject* struct_list = PyList_New($1->size());
    for(size_t i = 0; i < $1->size(); ++i)
    {
        PyObject* elem_object = SWIG_From_int(static_cast<ELEM_TYPE>($1->at(i)));
        PyList_SetItem(struct_list, i, elem_object);
    }
    if ($result != Py_None) {
        $result = PyList_New(1);
        PyList_SetItem($result, 0, SWIG_From_int(static_cast<int>(result.value())));
        PyList_Append($result, struct_list);
        Py_CLEAR(struct_list);
    } else {
        $result = struct_list;
    }

}

%typemap(freearg) std::vector<ELEM_TYPE>& ARG {
    delete($1);
}

%enddef

%{
template< typename T >
struct LEABA_as_voidptr {
  static void* cast(T arg) {return NULL;}
};

template< typename T >
struct LEABA_as_voidptr< T* > {
    static void* cast(T* arg) {return SWIG_as_voidptr(arg);}
};
%}

%define OUTARG_VECTOR_TYPEMAPS(ELEM_TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) std::vector<ELEM_TYPE>& ARG (size_t _global_processed_args_count), std::vector<ELEM_TYPE, silicon_one::allocator_wrapper<ELEM_TYPE> >& ARG (size_t _global_processed_args_count) {
    _global_processed_args_count = 0;
    $1 = new $*ltype();
}

%typemap(argout) std::vector<ELEM_TYPE>& ARG, std::vector<ELEM_TYPE, silicon_one::allocator_wrapper<ELEM_TYPE> >& ARG {

    PyObject* struct_list = PyList_New($1->size());
    for(size_t i = 0; i < $1->size(); ++i)
    {
        PyObject *elem_object;

        if (std::is_pointer<ELEM_TYPE>::value) {
            elem_object = SWIG_NewPointerObj(LEABA_as_voidptr<ELEM_TYPE>::cast($1->at(i)), $descriptor(ELEM_TYPE), 0);
        } else {
            elem_object = SWIG_NewPointerObj(new ELEM_TYPE($1->at(i)), $descriptor(ELEM_TYPE*), SWIG_POINTER_OWN);
        }

        PyList_SetItem(struct_list, i, elem_object);
    }

    $result = add_argout_value($result, struct_list, _global_processed_args_count);

}

%typemap(freearg) std::vector<ELEM_TYPE>& ARG, std::vector<ELEM_TYPE, silicon_one::allocator_wrapper<ELEM_TYPE> >& ARG {
    delete($1);
}

%enddef

%define OUT_ENUM_VECTOR_TYPEMAPS(ELEM_TYPE)

%typemap(out) std::vector<ELEM_TYPE>, std::vector<ELEM_TYPE> const, std::vector<ELEM_TYPE, silicon_one::allocator_wrapper<ELEM_TYPE> >, std::vector<ELEM_TYPE, silicon_one::allocator_wrapper<ELEM_TYPE> > const {
    PyObject* struct_list = PyList_New(result.size());
    for(size_t i = 0; i < result.size(); ++i)
    {
        PyObject* elem_object = SWIG_From_int(static_cast<ELEM_TYPE>(result.at(i)));
        PyList_SetItem(struct_list, i, elem_object);
    }

    $result = struct_list;
}

%enddef

%define OUT_ENUM_VECTOR_REF_TYPEMAPS(ELEM_TYPE)

%typemap(out) std::vector< ELEM_TYPE,std::allocator< ELEM_TYPE > >& {
    PyObject* struct_list = PyList_New(result->size());
    for(size_t i = 0; i < result->size(); ++i)
    {
        PyObject* elem_object = SWIG_From_int(static_cast<int>(result->at(i)));
        PyList_SetItem(struct_list, i, elem_object);
    }
    $result = struct_list;
}

%enddef

%define OUT_VECTOR_TYPEMAPS(ELEM_TYPE)

%typemap(out) std::vector<ELEM_TYPE>, std::vector<ELEM_TYPE> const, std::vector<ELEM_TYPE, silicon_one::allocator_wrapper<ELEM_TYPE> >, std::vector<ELEM_TYPE, silicon_one::allocator_wrapper<ELEM_TYPE> > const {
    PyObject* struct_list = PyList_New(result.size());
    for(size_t i = 0; i < result.size(); ++i)
    {
        PyObject *elem_object;

        if (std::is_pointer<ELEM_TYPE>::value) {
            elem_object = SWIG_NewPointerObj(LEABA_as_voidptr<ELEM_TYPE>::cast(result.at(i)), $descriptor(ELEM_TYPE), 0);
        } else {
            elem_object = SWIG_NewPointerObj(new ELEM_TYPE(result.at(i)), $descriptor(ELEM_TYPE*), SWIG_POINTER_OWN);
        }

        PyList_SetItem(struct_list, i, elem_object);
    }

    $result = struct_list;
}

%enddef


%define OUTARG_STRUCT_TYPEMAPS(TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) TYPE& ARG (size_t _global_processed_args_count){
    _global_processed_args_count = 0;
    $1 = new $*ltype();
}

%typemap(argout) TYPE& ARG {
    PyObject* out_object = SWIG_NewPointerObj(new $*ltype(*$1), $1_descriptor, SWIG_POINTER_OWN);

    $result = add_argout_value($result, out_object, _global_processed_args_count);
}

%typemap(freearg) TYPE& ARG {
    delete($1);
}

%enddef


%define OUTARG_PTR_FLAGS_TYPEMAPS(TYPE, ARG, FLAGS)

%typemap(in,numinputs=0,noblock=1) TYPE& ARG (size_t _global_processed_args_count){
    _global_processed_args_count = 0;
    $1 = ($ltype)calloc(1, sizeof($*ltype));
}

%typemap(argout) TYPE& ARG{
    PyObject* out_object = SWIG_NewPointerObj(*$1, $*1_descriptor, FLAGS);

    $result = add_argout_value($result, out_object, _global_processed_args_count);
}

%typemap(freearg) TYPE& ARG {
    free($1);
}

%enddef

%define OUTARG_PTR_TYPEMAPS(TYPE, ARG)
OUTARG_PTR_FLAGS_TYPEMAPS(TYPE, ARG, 0)
%enddef

%define OUTARG_OWNED_PTR_TYPEMAPS(TYPE, ARG)
OUTARG_PTR_FLAGS_TYPEMAPS(TYPE, ARG, SWIG_POINTER_OWN)
%enddef

%define ARRAY_HANDLER(TYPE, PY_TO_C, C_TO_PY)

%typemap(in,noblock=1) TYPE [ANY] {
    $1 = ($ltype) calloc($dim0,sizeof($*ltype));
    for (int i = 0; i < $dim0; i++) {
        PyObject *py = PyList_GetItem($input, i);
        $1[i] = PY_TO_C(py);
    }
}

%typemap(arginit, noblock=1) TYPE [ANY] {
  $1 = nullptr;
}

%typemap(out) TYPE [ANY] {
  $result = PyList_New($1_dim0);
  for (int i = 0; i < $1_dim0; i++) {
    PyObject *o = C_TO_PY($1[i]);
    PyList_SetItem($result,i,o);
  }
}

%typemap(freearg) TYPE [ANY] {
  free($1);
}

%enddef

%define ARRAY_FUNCTIONS(TYPE, LEN)
//without these, swig yells: Warning 389: operator[] ignored (consider using %extend)
%ignore TYPE::operator[];

%extend TYPE {
        %exception __getitem__ {
            $action
            if (!result) {
                write_error_string(arg2, LEN);
                return nullptr;
            }
        }

        %exception __setitem__ {
            $action
            if (!result) {
                write_error_string(arg3, LEN);
                return      nullptr;
            }
        }

        TYPE* __getitem__(size_t idx) {
            if ( idx >= LEN ) {
                return nullptr;
            }
            return &(*(self + idx));
        }

        bool __setitem__(const TYPE& other, size_t idx) {
            if ( idx >= LEN ) {
                return false;
            }
            *(self+idx) = other;
            return true;
        }

        Py_ssize_t __len__() const {
            return LEN;
        }
};
%enddef

%define SHARED_PTR_VEC_TYPEMAPS(VECTOR_TYPE, HANDLE_TYPE, CONST_HANDLE_TYPE)

%typemap(out) VECTOR_TYPE {
    $result = PyList_New(0);

    VECTOR_TYPE& vt($1);

    for (size_t i = 0; i < vt.size(); i++) {
        auto smartresult = new CONST_HANDLE_TYPE(vt[i]);
        PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(smartresult), $descriptor(HANDLE_TYPE*), SWIG_POINTER_OWN);
        PyList_Append($result, obj);
        Py_CLEAR(obj);
    }
}

%enddef

%define SHARED_FROM_THIS_TYPEMAPS_COMMON(TYPE, CONST)

%typemap(out) CONST TYPE * {
  std::shared_ptr< CONST TYPE > *smartresult = $1 ? new std::shared_ptr< CONST TYPE >($1->shared_from_this()) : 0;
  %set_output(SWIG_NewPointerObj(%as_voidptr(smartresult), $descriptor(std::shared_ptr< TYPE > *), SWIG_POINTER_OWN));
}

%typemap(varout) CONST TYPE * {
  std::shared_ptr< CONST TYPE > *smartresult = $1 ? new std::shared_ptr< CONST TYPE >($1->shared_from_this()) : 0;
  %set_varoutput(SWIG_NewPointerObj(%as_voidptr(smartresult), $descriptor(std::shared_ptr< TYPE > *), SWIG_POINTER_OWN));
}

%typemap(out) CONST TYPE & {
  std::shared_ptr< CONST TYPE > *smartresult = new std::shared_ptr< CONST TYPE >($1->shared_from_this());
  %set_output(SWIG_NewPointerObj(%as_voidptr(smartresult), $descriptor(std::shared_ptr< TYPE > *), SWIG_POINTER_OWN));
}

%typemap(varout) CONST TYPE & {
  std::shared_ptr< CONST TYPE > *smartresult = new std::shared_ptr< CONST TYPE >(&$1->shared_from_this());
  %set_varoutput(SWIG_NewPointerObj(%as_voidptr(smartresult), $descriptor(std::shared_ptr< TYPE > *), SWIG_POINTER_OWN));
}

%typemap(out) TYPE *CONST& {
  std::shared_ptr< CONST TYPE > *smartresult = new std::shared_ptr< CONST TYPE >(*$1->shared_from_this());
  %set_output(SWIG_NewPointerObj(%as_voidptr(smartresult), $descriptor(std::shared_ptr< TYPE > *), SWIG_POINTER_OWN));
}

%typemap(freearg) TYPE {
  free($1);
}
%enddef

%define SHARED_FROM_THIS_TYPEMAPS(TYPE)
%shared_ptr(TYPE)
SHARED_FROM_THIS_TYPEMAPS_COMMON(TYPE, )
SHARED_FROM_THIS_TYPEMAPS_COMMON(TYPE, const)
%enddef

%typemap(in) std::chrono::seconds {
    if (PyLong_Check($input)) {
        $1 = std::chrono::seconds{PyLong_AsLongLong($input)};
    } else {
        SWIG_exception(SWIG_TypeError, "long expected");
    }
}

%typemap(in) std::chrono::milliseconds {
    if (PyLong_Check($input)) {
        $1 = std::chrono::milliseconds{PyLong_AsLongLong($input)};
    } else {
        SWIG_exception(SWIG_TypeError, "long expected");
    }
}

%typemap(in) std::chrono::microseconds {
    if (PyLong_Check($input)) {
        $1 = std::chrono::microseconds{PyLong_AsLongLong($input)};
    } else {
        SWIG_exception(SWIG_TypeError, "long expected");
    }
}

%typemap(in) std::chrono::nanoseconds {
    if (PyLong_Check($input)) {
        $1 = std::chrono::nanoseconds{PyLong_AsLongLong($input)};
    } else {
        SWIG_exception(SWIG_TypeError, "long expected");
    }
}

%inline %{
    void set_error_mode(error_mode_e mode)
    {
        error_mode = mode;
    }

    error_mode_e get_error_mode()
    {
        return error_mode;
    }
%}

