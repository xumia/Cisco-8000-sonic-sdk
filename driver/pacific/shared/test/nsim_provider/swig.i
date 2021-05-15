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

/// SWIG interface file for testing Leaba's high-level driver.

%module test_nsim_providercli

// GIL lock blocks execution, once going into SWIG functions, which prevents multi-threaded execution.
// The below directive removes this lock.
%exception create_and_run_simulator_server {
    Py_BEGIN_ALLOW_THREADS
    $action
    Py_END_ALLOW_THREADS
}

%{

#include "nsim_provider/nsim_provider.h"
#include "nsim_provider/nsim_flow.h"
#include "nsim_provider/nsim_test_flow.h"
#include "nsim_provider/device_simulator_server.h"
#include "nsim/nsim_data_interface.h" // needed for NSIM_LOG...
#include "nsim/nsim_log_interface.h" // needed for DB_TRIGGER_TYPE_...

#include "nsim/nsim.h"

#include <iostream>
#include <string>
#include <map>
#include <list>
#include <vector>

using silicon_one::sim_packet_info_desc;

%}

%include std_string.i
%include std_map.i
%include std_vector.i
%include "common/common_swig_typemaps.i"
%include "utils/list_macros.h"
%include "nsim/nsim_data_interface.h" // needed for NSIM_LOG...
%include "nsim/nsim_log_interface.h" // needed for DB_TRIGGER_TYPE_...

%template(sim_packet_desc_vector)  std::vector<silicon_one::sim_packet_info_desc>;

OUTARG_ENUM_TYPEMAPS(size_t, out_port)

%typemap(in) const silicon_one::sim_initial_metadata_map_t& initial_values {
    if (! PyDict_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expected dictionary.");
        return NULL;
    }

    $1 = new silicon_one::sim_initial_metadata_map_t;

    PyObject *key, *value;
    Py_ssize_t pos = 0;

    while (PyDict_Next($input, &pos, &key, &value)) {
        if (! PyUnicode_Check(key)) {
            PyErr_SetString(PyExc_ValueError, "Key expected to be string.");
            return NULL;
        }

        if (! PyLong_Check(value)) {
            PyErr_SetString(PyExc_ValueError, "Value expected to be long.");
            return NULL;
        }
        PyObject *bytes = PyUnicode_AsUTF8String(key);
        std::string key_string(PyBytes_AsString(bytes));
        Py_CLEAR(bytes);

        PyObject* string_object = _PyLong_Format(value, 16 /* base */);
        bytes = PyUnicode_AsUTF8String(string_object);
        std::string value_string = PyBytes_AsString(bytes);
        Py_CLEAR(bytes);

        $1->insert(make_pair(key_string, value_string));
        Py_CLEAR(string_object);
    }
}

%typecheck(SWIG_TYPECHECK_POINTER) const silicon_one::sim_initial_metadata_map_t& {
    $1 = (PyDict_Check($input) == 0) ? 0 : 1;
}

%typemap(freearg) const silicon_one::sim_initial_metadata_map_t& initial_values {
    delete $1;
}

%include std_string.i
%include std_map.i

%include "utils/list_macros.h"
%include "sim_provider/sim_provider.h"
%include "nsim_provider/nsim_provider.h"
%include "nsim_provider/nsim_flow.h"
%include "nsim_provider/device_simulator_server.h"
%include "nsim_provider/nsim_test_flow.h"

