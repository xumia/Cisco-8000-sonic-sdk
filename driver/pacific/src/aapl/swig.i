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

/// SWIG interface file for Avago AAPL/CLI.

%module aaplcli
%{

#define AAPL_ENABLE_INTERNAL_FUNCTIONS

// Avago AAPL
// AAPL SWIG-only API-s rely on the SWIG preprocessor define.
#define SWIG
#include "aapl.h"
#undef SWIG
#include "aapl_library.h"

%}

%define OUTARG_INTPTR_TYPEMAPS(TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) TYPE *ARG {
    $1 = ($ltype)calloc(1, sizeof($ltype));
}

%typemap(argout) TYPE *ARG {
    PyObject *o, *o2, *o3;
    o = PyInt_FromLong(*$1);
    if ((!$result) || ($result == Py_None)) {
        $result = o;
    } else {
        if (!PyTuple_Check($result)) {
            PyObject *o2 = $result;
            $result = PyTuple_New(1);
            PyTuple_SetItem($result,0,o2);
        }
        o3 = PyTuple_New(1);
        PyTuple_SetItem(o3,0,o);
        o2 = $result;
        $result = PySequence_Concat(o2,o3);
        Py_CLEAR(o2);
        Py_CLEAR(o3);
    }
}

%typemap(freearg) TYPE *ARG {
    free($1);
}

%enddef

%define OUTARG_INTPTR_TYPEUNMAPS(TYPE, ARG)

%typemap(in,numinputs=0,noblock=1) TYPE *ARG;

%typemap(argout) TYPE *ARG;

%typemap(freearg) TYPE *ARG;

%enddef

%define LONG_ARRAY_TYPEMAPS(ARG)

%typemap(arginit, noblock=1) long ARG[ANY] {
  $1 = nullptr;
}

%typemap(in) long ARG[ANY] {
  int i;
  $1 = 0;

  if (!PySequence_Check($input)) {
    PyErr_SetString(PyExc_ValueError, "Expected a sequence");
    SWIG_fail;
  }

  if (PySequence_Length($input) != $1_dim0) {
    PyErr_SetString(PyExc_ValueError, "Size mismatch. Expected $1_dim0 elements");
    SWIG_fail;
  }

  $1 = (long *) calloc($1_dim0, sizeof(long));
  for (i = 0; i < $1_dim0; i++) {
    PyObject *o = PySequence_GetItem($input, i);
    if (PyLong_Check(o)) {
      $1[i] = PyLong_AsLong(o);
    } else if (PyInt_Check(o)) {
      $1[i] = PyInt_AsLong(o);
    } else {
      free($1);
      PyErr_SetString(PyExc_ValueError, "Sequence elements must be longs");
      SWIG_fail;
    }
  }
}

%typemap(argout) long ARG[ANY] {
    $result = PyList_New(2);
    PyObject* out_list = PyList_New($1_dim0);
    for (int i = 0; i < $1_dim0; i++) {
        PyObject *o = PyLong_FromLong($1[i]);
        PyList_SetItem(out_list, i, o);
        Py_CLEAR(o);
    }
    PyList_SetItem($result, 0, SWIG_From_int(static_cast<int>(result)));
    PyList_SetItem($result, 1, out_list);
}

%typemap(freearg) long ARG[ANY] {
   if ($1) free($1);
}

%enddef

%include "stdint.i"

#define EXT extern
#define AAPL_ENABLE_INTERNAL_FUNCTIONS

%feature("autodoc", "1");

// Avago AAPL
%include "aacs_server.h"
%include "aapl_core.h"
%include "aapl_library.h"
%include "aapl.h"

%ignore aapl_mem_addr_to_str;
%ignore aapl_mem_addr_bitfield_to_str;
%include "diag_core.h"

%include "diag.h"
%include "eye.h"
%include "eye_math.h"
%include "hal.h"
%include "hbm.h"
%include "meas.h"
%include "pmd.h"
%include "pmro.h"
%include "sbm.h"
%include "sbus.h"
%include "sensor.h"

LONG_ARRAY_TYPEMAPS(data)

%include "serdes.h"
%include "an.h"

OUTARG_INTPTR_TYPEMAPS(BOOL, tx)
OUTARG_INTPTR_TYPEMAPS(BOOL, rx)
OUTARG_INTPTR_TYPEMAPS(int, tx_width)
OUTARG_INTPTR_TYPEMAPS(int, rx_width)
OUTARG_INTPTR_TYPEMAPS(BOOL, gray_encode)
OUTARG_INTPTR_TYPEMAPS(BOOL, precode)
OUTARG_INTPTR_TYPEMAPS(BOOL, gray_decode)
OUTARG_INTPTR_TYPEMAPS(BOOL, predecode)
%include "serdes_core.h"
OUTARG_INTPTR_TYPEUNMAPS(BOOL, tx)
OUTARG_INTPTR_TYPEUNMAPS(BOOL, rx)
OUTARG_INTPTR_TYPEUNMAPS(int, tx_width)
OUTARG_INTPTR_TYPEUNMAPS(int, rx_width)
OUTARG_INTPTR_TYPEUNMAPS(BOOL, gray_encode)
OUTARG_INTPTR_TYPEUNMAPS(BOOL, precode)
OUTARG_INTPTR_TYPEUNMAPS(BOOL, gray_decode)
OUTARG_INTPTR_TYPEUNMAPS(BOOL, predecode)

%include "serdes_dfe.h"
%include "spico.h"
%ignore avago_plot_get_point;
%ignore avago_serdes_escope_get_point;
%include "escope.h"
