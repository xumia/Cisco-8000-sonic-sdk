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

#ifndef __HLD_UTILS_TEMPLATES_BASE_H__
#define __HLD_UTILS_TEMPLATES_BASE_H__

namespace silicon_one
{

// Pass current ifgs -- use for initial setup before adding ifg dependency
template <typename sender_t, typename recipient_t>
la_status
add_current_ifgs(const sender_t* sender, recipient_t* recipient)
{
    auto ifgs = sender->get_ifgs();
    for (auto it = ifgs.begin(); it != ifgs.end(); ++it) {
        la_status status = recipient->add_ifg(*it);
        if (status != LA_STATUS_SUCCESS) {
            // Possibly legitimate failure due to OOR - rollback
            std::for_each(ifgs.begin(), it, [=](la_slice_ifg ifg) { recipient->remove_ifg(ifg); });
            return status;
        }
    }
    return LA_STATUS_SUCCESS;
}

template <typename sender_t, typename recipient_t>
la_status
add_current_ifgs(const sender_t* sender, const weak_ptr_unsafe<recipient_t>& recipient)
{
    auto ifgs = sender->get_ifgs();
    for (auto it = ifgs.begin(); it != ifgs.end(); ++it) {
        la_status status = recipient->add_ifg(*it);
        if (status != LA_STATUS_SUCCESS) {
            // Possibly legitimate failure due to OOR - rollback
            std::for_each(ifgs.begin(), it, [=](la_slice_ifg ifg) { recipient->remove_ifg(ifg); });
            return status;
        }
    }
    return LA_STATUS_SUCCESS;
}

template <typename sender_t, typename recipient_t>
la_status
remove_current_ifgs(const sender_t* sender, recipient_t* recipient)
{
    for (auto ifg : sender->get_ifgs()) {
        la_status status = recipient->remove_ifg(ifg);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}
template <typename sender_t, typename recipient_t>
la_status
remove_current_ifgs(const weak_ptr_unsafe<sender_t>& sender, weak_ptr_unsafe<recipient_t>& recipient)
{
    for (auto ifg : sender->get_ifgs()) {
        la_status status = recipient->remove_ifg(ifg);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}
template <typename sender_t, typename recipient_t>
la_status
remove_current_ifgs(const sender_t* sender, weak_ptr_unsafe<recipient_t>& recipient)
{
    for (auto ifg : sender->get_ifgs()) {
        la_status status = recipient->remove_ifg(ifg);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}
template <typename sender_t, typename recipient_t>
la_status
remove_current_ifgs(const weak_ptr_unsafe<sender_t>& sender, recipient_t* recipient)
{
    for (auto ifg : sender->get_ifgs()) {
        la_status status = recipient->remove_ifg(ifg);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

template <typename T>
std::string
get_value_type(const T& value)
{
    int status;
    char type_buffer[1024];
    size_t buf_size = sizeof(type_buffer);

    const char* type = abi::__cxa_demangle(typeid(decltype(value)).name(), type_buffer, &buf_size, &status);
    dassert_crit(type == type_buffer, "cxa_demangle name larger than 1024");

    std::stringstream type_str;
    type_str << LOG_DATA_TYPE_START << type << LOG_DATA_TYPE_END;

    return type_str.str();
}

template <typename T>
std::string
get_value_string(T value)
{
    using std::to_string;
    using silicon_one::to_string;

    return get_value_type(static_cast<decltype(value)>(value)) + to_string(value);
}

} // namespace silicon_one

#endif //__HLD_UTILS_TEMPLATES_BASE_H__
