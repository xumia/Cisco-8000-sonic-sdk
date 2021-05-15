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

#ifndef __JSON_UTILS_H__
#define __JSON_UTILS_H__

namespace silicon_one
{
namespace sai
{

///@brief declaration of json_t pointer for specific object name in json files include checking/error message of object type.
#define JSON_GET_OBJ_PTR(_json_obj_ptr, _obj_key, _obj_type, _obj_parent, _where_is_err)                                           \
    _json_obj_ptr = json_object_get(_obj_parent, _obj_key);                                                                        \
    if ((_json_obj_ptr == nullptr) || !json_is_##_obj_type(_json_obj_ptr)) {                                                       \
        sai_log_error(SAI_API_SWITCH, "JSON error on loading object \"%s\" as %s in %s", _obj_key, #_obj_type, _where_is_err);     \
        return LA_STATUS_EINVAL;                                                                                                   \
    }

#define json_is_hex(json) (json_is_integer(json) || json_is_string(json))

#define json_get_media_type_obj(j_media_type, j_parent)                                                                            \
    j_media_type = json_object_get(j_parent, "media_type");                                                                        \
    if (j_media_type == nullptr) {                                                                                                 \
        j_media_type = json_object_get(j_parent, "module_type");                                                                   \
    }

// return integer value if it is a hex string or integer.
inline json_int_t
json_hex_value(json_t* j_obj)
{
    if (json_is_integer(j_obj)) {
        return json_integer_value(j_obj);
    }

    if (json_is_string(j_obj)) {
        return (json_int_t)std::strtoul(json_string_value(j_obj), nullptr, 16);
    }

    return 0;
}
}
}

#endif
