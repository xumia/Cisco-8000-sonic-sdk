// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifdef ENABLE_SERIALIZATION
#include "common/cereal_utils.h"
#include <cereal/archives/binary.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/archives/xml.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#endif

// the following include is added for creating a in/out file stream
#include <fstream>
#include <memory>

#include "sai_device.h"
#include "sai_qos.h"

namespace silicon_one
{
namespace sai
{
bool
lsai_device_serialize_save(std::shared_ptr<silicon_one::sai::lsai_device> lsai_sptr, const char* serialization_file)
{
#ifdef ENABLE_SERIALIZATION
    std::ofstream my_file(serialization_file);
    CEREAL_UTILS_CREATE_OUTPUT_ARCHIVE(archive, my_file);
    archive(lsai_sptr);
#endif
    return true;
}

bool
lsai_device_serialize_load(std::shared_ptr<silicon_one::sai::lsai_device>& inout, const char* serialization_file)
{
#ifdef ENABLE_SERIALIZATION
    std::ifstream my_file(serialization_file);
    cereal_input_archive_class archive(my_file);
    archive(inout);
#endif
    return true;
}
}
}

#ifdef ENABLE_SERIALIZATION
namespace cereal
{
template <class Archive>
void save(Archive& ar, const sai_qos_map_t& m);
template <class Archive>
void load(Archive& ar, sai_qos_map_t& m);

template <class Archive>
void
save(Archive& ar, const silicon_one::sai::lasai_qos_map_list_t& m)
{
    ar(::cereal::make_nvp("count", m.count));
    for (uint i = 0; i < m.count; i++) {
        ar(m.shared_list.get()[i]);
    }
}
template void save<cereal_output_archive_class>(cereal_output_archive_class& ar, const silicon_one::sai::lasai_qos_map_list_t& m);

template <class Archive>
void
load(Archive& ar, silicon_one::sai::lasai_qos_map_list_t& m)
{
    ar(::cereal::make_nvp("count", m.count));
    if (m.count != 0) {
        m.shared_list = std::shared_ptr<sai_qos_map_t>(new sai_qos_map_t[m.count], std::default_delete<sai_qos_map_t[]>());
        for (uint i = 0; i < m.count; i++) {
            ar(m.shared_list.get()[i]);
        }
        m.list = m.shared_list.get();
    } else {
        m.list = nullptr;
    }
}
template void load<cereal_input_archive_class>(cereal_input_archive_class& ar, silicon_one::sai::lasai_qos_map_list_t& m);
}
#endif
