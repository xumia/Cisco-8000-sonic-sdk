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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "system/la_device_impl.h"
#include "system/la_pci_port_base.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/tm_utils.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

constexpr la_mac_port::port_speed_e PCI_PORT_DEFAULT_SPEED = la_mac_port::port_speed_e::E_100G;

la_pci_port_base::la_pci_port_base(const la_device_impl_wptr& device, bool skip_kernel_driver)
    : m_device(device), m_is_active(false), m_speed(PCI_PORT_DEFAULT_SPEED), m_skip_kernel_driver(skip_kernel_driver)
{
}

la_pci_port_base::~la_pci_port_base()
{
}

la_status
la_pci_port_base::initialize(la_object_id_t oid, la_slice_id_t slice, la_ifg_id_t ifg)
{
    m_oid = oid;
    bool using_leaba_nic;
    la_status status = m_device->get_bool_property(la_device_property_e::USING_LEABA_NIC, using_leaba_nic);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "la_pci_port_base::%s: Unknown property", __func__);
        return status;
    }

    if (!using_leaba_nic) {
        log_err(HLD, "la_pci_port_base::%s: PCI ports are not available when leaba NIC driver is not used.", __func__);
        return LA_STATUS_ENODEV;
    }

    m_slice = slice;
    m_ifg = ifg;

    la_uint_t intf_id;
    status = get_intf_id(intf_id);
    return_on_error(status);

    la_interface_scheduler_impl_sptr scheduler;
    status = m_device->create_interface_scheduler(m_slice, m_ifg, intf_id, m_speed, false /* is_fabric */, scheduler);
    return_on_error(status);
    m_scheduler = scheduler;

    status = m_device->m_ifg_schedulers[m_slice][m_ifg]->initialize_interface(intf_id, 1 /* m_pif_count */);
    return_on_error(status);

    status = enable();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_pci_port_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = m_scheduler->set_oqs_enabled(false /* enabled */);
    return_on_error(status);

    status = network_interface_op(port_activation_op_e::DISABLE);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_pci_port_base::type() const
{
    return object_type_e::PCI_PORT;
}

const la_device*
la_pci_port_base::get_device() const
{
    return m_device.get();
    ;
}

la_object_id_t
la_pci_port_base::oid() const
{
    return m_oid;
}

std::string
la_pci_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_pci_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_status
la_pci_port_base::activate()
{
    start_api_call("");

    return do_activate();
}

la_status
la_pci_port_base::do_activate()
{
    la_status status = m_scheduler->set_oqs_enabled(true /* enabled */);
    return_on_error(status);

    status = network_interface_op(port_activation_op_e::ACTIVATE);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "la_pci_port_base::%s failed %s", __func__, la_status2str(status).c_str());
        return status;
    }

    m_is_active = true;

    return LA_STATUS_SUCCESS;
}

la_status
la_pci_port_base::stop()
{
    start_api_call("");

    la_status status = m_scheduler->set_oqs_enabled(false /* enabled */);
    return_on_error(status);

    status = network_interface_op(port_activation_op_e::DEACTIVATE);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "la_pci_port_base::%s failed %s", __func__, la_status2str(status).c_str());
        return status;
    }

    m_is_active = false;

    return LA_STATUS_SUCCESS;
}

la_slice_id_t
la_pci_port_base::get_slice() const
{
    return m_slice;
}

la_ifg_id_t
la_pci_port_base::get_ifg() const
{
    return m_ifg;
}

la_interface_scheduler*
la_pci_port_base::get_scheduler() const
{
    return m_scheduler.get();
}

la_status
la_pci_port_base::get_speed(la_mac_port::port_speed_e& out_speed) const
{
    out_speed = m_speed;

    return LA_STATUS_SUCCESS;
}

la_status
la_pci_port_base::enable()
{
    auto status = network_interface_op(port_activation_op_e::ENABLE);
    if ((status != LA_STATUS_SUCCESS) && !m_device->is_simulated_device()) { // Failure is expected in simulator
        log_err(HLD, "la_pci_port_impl::initialize failed %d\n", status.value());
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_pci_port_base::network_interface_op(port_activation_op_e op) const
{
    const char* codes[] = {
        /* DISABLE */ "0",
        /* ENABLE */ "1",
        /* ACTIVATE */ "A",
        /* DEACTIVATE */ "D",
    };

    /* In case when PCI port is decoupled from kernel driver do nothing */
    if (m_skip_kernel_driver) {
        return LA_STATUS_SUCCESS;
    }

    if ((size_t)op >= array_size(codes)) {
        log_err(HLD, "%s: unknown op %zu", __func__, (size_t)op);
        return LA_STATUS_EINVAL;
    }

    std::string path = m_device->get_ll_device()->get_network_interface_file_name(m_slice);
    if (path.empty()) {
        return LA_STATUS_SUCCESS;
    }

    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) {
        log_err(HLD, "%s: Failed to open %s, errno = %d", __func__, path.c_str(), errno);
        return LA_STATUS_ENOTFOUND;
    }

    const char* val = codes[(size_t)op];

    la_status status = m_device->do_flush();
    return_on_error(status);

    int ret = write(fd, val, strlen(val) + 1);
    close(fd);
    if (ret < 0) {
        log_err(HLD, "%s: Failed to write to file errno=%d", __func__, errno);
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

bool
la_pci_port_base::is_active() const
{
    return m_is_active;
}

la_status
la_pci_port_base::get_inject_count(bool clear_on_read, la_uint64_t& out_count)
{
    return read_inject_counter(clear_on_read, m_slice, m_ifg, out_count);
}

la_status
la_pci_port_base::get_punt_count(bool clear_on_read, la_uint64_t& out_count)
{
    return read_punt_counter(clear_on_read, m_slice, m_ifg, out_count);
}

la_status
la_pci_port_base::get_intf_id(la_uint_t& out_intf_id) const
{
    out_intf_id = HOST_PIF_ID;
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
