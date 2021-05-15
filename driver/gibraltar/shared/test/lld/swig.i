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

/// SWIG interface file for testing Leaba low-level driver/CLI.

%module test_lldcli
%{

#include "api/types/la_common_types.h"
#include "socket_device_simulator.h"
#include "socket_device.h"

#define LEABA_SWIG_BUFFER_SIZE 128

using namespace silicon_one;

%}

%include "common/common_swig_typemaps.i"

OUTARG_OWNED_PTR_TYPEMAPS(silicon_one::socket_device*, owned_socket_device)

%inline %{
    la_status
    socket_device_create(uint16_t port_rw, uint16_t port_int, silicon_one::socket_device*& owned_socket_device)
    {
        owned_socket_device = silicon_one::socket_device::create(port_rw, port_int);

        return owned_socket_device ? LA_STATUS_SUCCESS : LA_STATUS_EUNKNOWN;
    }
%}

%include "lld/lld_fwd.h"

%inline %{
    bool
    is_serialization_supported() {
#ifdef ENABLE_SERIALIZATION
        return true;
#else
        return false;
#endif
    }
%}

%inline %{
    bool
    is_clang_compilation() {
#if defined(__GNUC__) && defined(__clang__)
        return true;
#else
        return false;
#endif
    }
%}

#ifdef ENABLE_SERIALIZATION
%{

//#include <cereal/archives/json.hpp>
#include <cereal/archives/binary.hpp>
//#include <cereal/archives/xml.hpp>
#include <cereal/types/memory.hpp>

#include "common/cereal_utils.h"
#include "lld/ll_device.h"
// declaring the relevant serialization functions
template <class Archive>
void
save(Archive& archive, const ll_device& m);
template <class Archive>
void
load(Archive& archive, ll_device& m);

// the following include is added for creating a in/out file stream
#include <fstream>

%}

%inline %{
    bool
    ll_device_serialize_save(silicon_one::ll_device_sptr lld_sptr, const char* serialization_file)
    {
        std::ofstream my_file(serialization_file, CEREAL_OUTPUT_STREAM_MODE_FLAGS);
        CEREAL_UTILS_CREATE_OUTPUT_ARCHIVE(archive, my_file);
        archive(lld_sptr);
        return true;
    }

%}

%inline %{
    silicon_one::ll_device_sptr
    ll_device_serialize_load(const char* serialization_file)
    {
        silicon_one::ll_device_sptr loaded_lld;
        std::ifstream my_file(serialization_file, CEREAL_INPUT_STREAM_MODE_FLAGS);
        cereal_input_archive_class archive(my_file);
        archive(loaded_lld);
        return loaded_lld;
    }

%}
#endif

%include "stdint.i"
%include "std_string.i"

%include "api/types/la_common_types.h"
%include "socket_device_simulator.h"
%include "socket_device.h"
