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

#include "lld/ll_device.h"
#include "system/compound_translator_creator.h"
#include "system/hld_translator_creator.h"
#include "system/la_device_impl.h"

#include "nplapi/nplapi_fwd.h"
#include "nsim_provider/nsim_flow.h"
#include "ra/ra_flow.h"
#include "ra/resource_manager.h"

#include "common/defines.h"
#include "common/logger.h"

#include <memory>

#include "runtime_flexibility_library.h"

using silicon_one::logger;

namespace silicon_one
{
la_status
la_device_impl::create_flow(translator_creator_sptr& creator)
{
    std::vector<npl_context_e> npl_context_slices(NUM_SLICES_WITH_NPUH_PER_DEVICE, NPL_NONE_CONTEXT);

    la_status status = get_npl_contexts(npl_context_slices);
    return_on_error(status);

    std::string path = m_ll_device->get_device_path();

    vector_alloc<translator_creator_sptr> creators_vec;

    std::vector<udk_translation_info_sptr> trans_info(NUM_UDK_TABLES_PER_DEVICE);
    get_acl_key_profile_translation_info(trans_info);

    //***********************
    // Production, RTL flow, or compound NSIM flow with both NSIM+RA translators
    //***********************
    if (path.find("rtl") != std::string::npos || path.find("testdev") == std::string::npos) {
        translator_creator_sptr ra_creator
            = create_ra_translator_creator(m_resource_manager, m_ll_device, npl_context_slices, trans_info);
        if (ra_creator) {
            creators_vec.push_back(ra_creator);
        }
    }
    //***********************
    // NSIM flow
    //***********************
    else if (path.find("/socket/") != std::string::npos) {
        translator_creator_sptr nsim_creator = create_nsim_translator_creator(m_ll_device, npl_context_slices);
        creators_vec.push_back(nsim_creator);
        device_simulator* dsim = m_ll_device->get_device_simulator();

        bool nsim_accurate_scale_model;
        nsim_accurate_scale_model_enabled(nsim_accurate_scale_model);
        if (nsim_accurate_scale_model) {
            translator_creator_sptr ra_creator
                = create_ra_translator_creator(m_resource_manager, m_ll_device, npl_context_slices, trans_info);

            if (ra_creator) {
                creators_vec.push_back(ra_creator);
            }
        }

        if (dsim != nullptr) {
            for (la_slice_id_t sid : get_used_slices()) {
                status = dsim->add_property("NPL_CONTEXT_SLICE_" + std::to_string(sid), std::to_string(npl_context_slices[sid]));
                return_on_error(status);
                log_info(HLD, "%s: set device simulator slice ID %d to context %d", __func__, sid, npl_context_slices[sid]);
            }
            status = dsim->add_property("NPL_CONTEXT_SLICE_" + std::to_string(ASIC_MAX_SLICES_PER_DEVICE_NUM),
                                        std::to_string(NPL_HOST_CONTEXT));
            return_on_error(status);
        } else {
            log_warning(HLD, "%s: device simulator not initialized--cannot set slice contexts", __func__);
        }
    } else {
        log_err(HLD, "%s: not implemented", __func__);
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (creators_vec.empty() == true) {
        log_err(HLD, "%s: cannot create NPL translator, device path %s", __func__, path.c_str());
        return LA_STATUS_ENOTINITIALIZED;
    }

    creator = std::make_shared<compound_translator_creator>(m_ll_device, npl_context_slices, creators_vec);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_nsim_simulator_client(std::string path, device_simulator*& out_sim)
{
    // NSIM device path format: /dev/testdev[<additional identifiers>]/socket/[<host addr>]:port.
    // Examples: /dev/testdev/socket/0.0.0.0:40856
    //           /dev/testdev156027234/socket/0.0.0.0:42390

    if (path.find("/socket/") == std::string::npos || path.find("/dev/testdev") == std::string::npos) {
        return LA_STATUS_SUCCESS;
    }

    log_info(HLD, "%s: path=%s", __func__, path.c_str());

    size_t start = path.find("/socket/") + strlen("/socket/");
    std::string host_and_port = path.substr(start, path.size() - start);

    size_t delim = host_and_port.find(":");
    if (delim == std::string::npos) {
        log_err(HLD, "%s: bad format, path=%s", __func__, path.c_str());
        return LA_STATUS_EINVAL;
    }

    std::string host_ip = host_and_port.substr(0, delim);
    size_t port = std::stoul(host_and_port.substr(delim + 1, host_and_port.size()), nullptr, 10);

    device_simulator* sim = create_nsim_simulator(host_ip.c_str(), port, la_get_version_string());
    if (!sim) {
        return LA_STATUS_EINVAL;
    }

    out_sim = sim;

    return LA_STATUS_SUCCESS;
}
}
