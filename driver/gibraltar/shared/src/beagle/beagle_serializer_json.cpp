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

#include "beagle/beagle_serializer_json.h"
#include <inttypes.h>

namespace silicon_one
{

la_status
beagle_serializer_json::obj_id2json(obj_id_t root, json_t*& json_root)
{
    if (m_json_objects.find(root) == m_json_objects.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    json_root = m_json_objects.at(root);

    return LA_STATUS_SUCCESS;
}

beagle::beagle_status_t
beagle_serializer_json::insert(obj_id_t parent, const char* key, obj_id_t value)
{
    if (m_json_objects.find(parent) == m_json_objects.end() || m_json_objects.find(value) == m_json_objects.end()) {
        return beagle::beagle_status_t::BGL_EINVAL;
    }

    if (json_object_set_new(m_json_objects[parent], key, m_json_objects[value]) == -1) {
        return beagle::beagle_status_t::BGL_UNEXPECTED_ERROR;
    }

    return beagle::beagle_status_t::BGL_SUCCESS;
}

beagle_serializer_json::obj_id_t
beagle_serializer_json::create_integer(int64_t value)
{
    json_t* json_obj = json_integer(value);

    if (!json_obj) {
        return INV_OBJ_ID;
    }

    m_json_objects[m_obj_counter] = json_obj;

    return m_obj_counter++;
}

beagle_serializer_json::obj_id_t
beagle_serializer_json::create_float(double value)
{
    json_t* json_obj = json_real(value);

    if (!json_obj) {
        return INV_OBJ_ID;
    }

    m_json_objects[m_obj_counter] = json_obj;

    return m_obj_counter++;
}

beagle_serializer_json::obj_id_t
beagle_serializer_json::create_string(const char* value)
{
    json_t* json_obj = json_string(value);

    if (!json_obj) {
        return INV_OBJ_ID;
    }

    m_json_objects[m_obj_counter] = json_obj;

    return m_obj_counter++;
}

beagle_serializer_json::obj_id_t
beagle_serializer_json::create_array()
{
    json_t* json_obj = json_array();

    if (!json_obj) {
        return INV_OBJ_ID;
    }

    m_json_objects[m_obj_counter] = json_obj;

    return m_obj_counter++;
}

beagle::beagle_status_t
beagle_serializer_json::array_append(obj_id_t array, obj_id_t value)
{
    if (m_json_objects.find(array) == m_json_objects.end() || m_json_objects.find(value) == m_json_objects.end()) {
        return beagle::beagle_status_t::BGL_EINVAL;
    }

    if (!json_is_array(m_json_objects.at(array))) {
        return beagle::beagle_status_t::BGL_EINVAL;
    }

    if (json_array_append_new(m_json_objects[array], m_json_objects[value]) == -1) {
        return beagle::beagle_status_t::BGL_UNEXPECTED_ERROR;
    }

    return beagle::beagle_status_t::BGL_SUCCESS;
}

beagle_serializer_json::obj_id_t
beagle_serializer_json::start_proccessing(const char* name)
{
    json_t* new_json_obj = json_object();

    if (!new_json_obj) {
        return INV_OBJ_ID;
    }

    m_json_objects[m_obj_counter] = new_json_obj;

    return m_obj_counter++;
}

beagle_serializer_json::obj_id_t
beagle_serializer_json::finish_proccessing(obj_id_t obj_id, const char* name)
{
    (void)name;

    return obj_id;
}

beagle::beagle_status_t
beagle_serializer_json::copy_array(int32_t* in_array, uint32_t size, obj_id_t out_array)
{
    if (m_json_objects.find(out_array) == m_json_objects.end()) {
        return beagle::beagle_status_t::BGL_EINVAL;
    }

    if (!json_is_array(m_json_objects.at(out_array)) || out_array == INV_OBJ_ID) {
        return beagle::beagle_status_t::BGL_EINVAL;
    }

    beagle::beagle_status_t status;
    for (size_t i = 0; i < size; i++) {
        status = array_append(out_array, create_integer(in_array[i]));
        if (status != beagle::beagle_status_t::BGL_SUCCESS) {
            return status;
        }
    }

    return beagle::beagle_status_t::BGL_SUCCESS;
}
}
