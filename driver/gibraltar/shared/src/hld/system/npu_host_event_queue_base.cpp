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

#include "npu_host_event_queue_base.h"
#include "hld_notification_base.h"
#include "nplapi/npl_types.h"
#include "npu/la_bfd_session_base.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

npu_host_event_queue_base::npu_host_event_queue_base(const la_device_impl_wptr& device) : m_device(device)
{
}

npu_host_event_queue_base::~npu_host_event_queue_base()
{
}

void
npu_host_event_queue_base::handle_bfd_packet_event(const bit_vector& event)
{
    npl_bfd_event_queue_table_key_t bfd_event{};
    bfd_event.unpack(event);

    if (bfd_event.oamp_event != NPL_OAMP_EVENT_BFD_FLAG_CHANGE && bfd_event.oamp_event != NPL_OAMP_EVENT_BFD_STATE_CHANGE) {

        log_warning(INTERRUPT, "Unexpected eventq event of type %d", bfd_event.oamp_event);
        return;
    }

    uint32_t id = bfd_event.rmep_id;

    log_debug(INTERRUPT, "BFD event received for id %u", id);

    if (id >= m_device->m_bfd_sessions.size()) {
        log_err(INTERRUPT, "BFD event id %u out of range", id);
        return;
    }

    const auto& session = m_device->m_bfd_sessions[id];
    if (!session) {
        // This is normal if session was deleted before we processed event queue.
        return;
    }

    // Update expected state to hardware
    auto flags = la_bfd_flags{};
    flags.flat = bfd_event.flags_and_state;

    session->set_remote_state(flags);
    // No need to notify the user since they will get notified via punted packet.
}

void
npu_host_event_queue_base::handle_npu_host_packet_event(const bit_vector& event)
{
    switch (event.bits_from_lsb(NPL_NPUH_EVENTQ_ID_SHIFT, NPL_NPUH_EVENTQ_ID_WIDTH).get_value()) {
    case NPL_NPUH_EVENTQ_BFD_ID:
        handle_bfd_packet_event(event);
        break;
    default:
        break;
    }
}

void
npu_host_event_queue_base::handle_npu_host_scanner_event(const bit_vector& event)
{
    // Only bfd implemented
    npl_event_to_send_t v{};
    // NPL structure is defined without ECC and hw register contains ECC.
    // Only initialize with the bits defined in the npl structure.
    int msb = sizeof(npl_event_to_send_t) * 8 - 1;
    v.unpack(event.bits(msb, 0));

    uint32_t id = v.rmep_id;

    if (id >= m_device->m_bfd_sessions.size()) {
        log_err(INTERRUPT, "bfd event id %u out of range", id);
        return;
    }

    const auto& session = m_device->m_bfd_sessions[id];
    if (!session) {
        // This may be normal, e.g. if session was deleted before we processed event queue.
        return;
    }

    la_bfd_discriminator discriminator{};
    la_bfd_session::type_e session_type;
    bool was_armed = false;
    session->handle_timeout(session_type, discriminator, was_armed);

    if (!was_armed) {
        // Since the eventq is polled by the CPU, it can happen when the CPU is busy that we get multiple timeouts for
        // the same session because we were not able to disarm it before the session timed out again.
        // Don't notify the user for multiple timeouts.
        return;
    }

    auto notification_desc = la_notification_desc();
    notification_desc.type = la_notification_type_e::BFD;
    notification_desc.u.bfd.local_discriminator = discriminator;
    notification_desc.u.bfd.cause = la_bfd_notification_cause::TIME_EXCEEDED;

    // Since Echo sessions may share the same local discriminator as other async sessions
    // we differentiate between them based on the diag code.
    if (session_type == la_bfd_session::type_e::ECHO) {
        notification_desc.u.bfd.state_change.diagnostic_code = la_bfd_diagnostic_code_e::ECHO_FUNCTION_FAILED;
    } else {
        notification_desc.u.bfd.state_change.diagnostic_code = la_bfd_diagnostic_code_e::NO_DIAGNOSTIC;
    }

    m_device->get_notificator()->notify(notification_desc, hld_notification_base::notification_pipe_e::CRITICAL);
}

void
npu_host_event_queue_base::handle_npu_host_event(const bit_vector& event)
{
    if (event.bit(0)) {
        handle_npu_host_scanner_event(event);
    } else {
        handle_npu_host_packet_event(event);
    }
}

} // namespace silicon_one
