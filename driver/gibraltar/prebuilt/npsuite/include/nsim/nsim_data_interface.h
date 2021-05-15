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

#ifndef __NSIM_DATA_INTERFACE_H__
#define __NSIM_DATA_INTERFACE_H__

#include <list>
#include <map>
#include <string>

#include "utils/nsim_bv.h"
#include "utils/list_macros.h"
#include "nsim_packet_statistics.h"

namespace nsim
{

// clang-format off
#define DB_TRIGGER_TYPE_ENUMS(list_macro) \
    list_macro(DB_TRIGGER_TYPE_RMEP, 0), \
    list_macro(DB_TRIGGER_TYPE_MP, 1),
// clang-format on
enum db_trigger_type_e : uint32_t { DB_TRIGGER_TYPE_ENUMS(LIST_MACRO_FIXED_ENUM_VALUE) };

#ifndef SWIG // Error: 'to_string' is multiply defined in the generated target language module.
//
// Convert db_trigger_type_e to a string
//
static inline const std::string
to_string(const db_trigger_type_e cmd)
{
    static std::vector<std::string> names = {DB_TRIGGER_TYPE_ENUMS(LIST_MACRO_FIXED_ENUM_STRING)};
    if ((size_t)cmd >= names.size()) {
        return std::string("invalid db_trigger_type_e:") + std::to_string(static_cast<int>(cmd));
    }
    return names[static_cast<int>(cmd)];
}
#endif

// clang-format off
#define DB_TRIGGER_MP_TABLE_TYPE_ENUMS(list_macro) \
    list_macro(DB_TRIGGER_MP_TABLE_TYPE_INVALID, 0), \
    list_macro(DB_TRIGGER_MP_TABLE_TYPE_INJECT_CCM, 1), \
    list_macro(DB_TRIGGER_MP_TABLE_TYPE_INJECT_DMM, 2), \
    list_macro(DB_TRIGGER_MP_TABLE_TYPE_INJECT_LMM, 3),
// clang-format on
enum db_trigger_mp_table_type_e : uint32_t { DB_TRIGGER_MP_TABLE_TYPE_ENUMS(LIST_MACRO_FIXED_ENUM_VALUE) };

#ifndef SWIG // Error: 'to_string' is multiply defined in the generated target language module.
//
// Convert db_trigger_mp_table_type_e to a string
//
static inline const std::string
to_string(const db_trigger_mp_table_type_e cmd)
{
    static std::vector<std::string> names = {DB_TRIGGER_MP_TABLE_TYPE_ENUMS(LIST_MACRO_FIXED_ENUM_STRING)};
    if ((size_t)cmd >= names.size()) {
        return std::string("invalid db_trigger_mp_table_type_e:") + std::to_string(static_cast<int>(cmd));
    }
    return names[static_cast<int>(cmd)];
}
#endif

/// packet info
///
/// Packet info is used for input/output packets to/from the simulator
struct nsim_packet_info_t {
    nsim_packet_info_t() : m_packet_data(0), m_slice_id(0), m_ifg(0), m_pif(0), m_should_dump_state(false)
    {
    }

    void set_args(const nsim::bit_vector& bytes, size_t slice_id, size_t ifg, size_t pif)
    {
        m_packet_data = bytes;
        m_slice_id = slice_id;
        m_ifg = ifg;
        m_pif = pif;
    }
    nsim::bit_vector m_packet_data;
    size_t m_slice_id;
    size_t m_ifg;
    size_t m_pif;
    bool m_should_dump_state;
    nsim::packet_statistics_t m_packet_statistics;
};

#ifndef SWIG // avoid redefinition of 'PyObject* _wrap_to_string(PyObject*, PyObject*)'
static inline std::string
to_string(const nsim::nsim_packet_info_t& s)
{
    return "(packet=" + s.m_packet_data.to_string_without_leading_0x() + ", slice=" + std::to_string(s.m_slice_id)
           + ", ifg=" + std::to_string(s.m_ifg) + ", pif=" + std::to_string(s.m_pif) + ")";
}
#endif

struct nsim_db_trigger_info_t {
    nsim_db_trigger_info_t() : m_line_id(0), m_trigger_type(0), m_mp_type(1)
    {
    }

    void set_args(size_t line_id, size_t trigger_type, size_t mp_type)
    {
        m_line_id = line_id;
        m_trigger_type = trigger_type;
        m_mp_type = mp_type;
    }
    size_t m_line_id;
    size_t m_trigger_type;
    size_t m_mp_type;
};

#ifndef SWIG // avoid redefinition of 'PyObject* _wrap_to_string(PyObject*, PyObject*)'
static inline std::string
to_string(const nsim::nsim_db_trigger_info_t& s)
{
    return "(line=" + std::to_string(s.m_line_id) + ", trigger=" + to_string(static_cast<db_trigger_type_e>(s.m_trigger_type))
           + ", mp_type=" + to_string(static_cast<db_trigger_mp_table_type_e>(s.m_mp_type)) + ")";
}
#endif

typedef std::map<std::string, nsim::bit_vector> nsim_name_value_map_t;

class nsim_data_interface
{
public:
    virtual ~nsim_data_interface()
    {
    }

    /// @brief Inject packet into simulation.
    /// Packets are simulated in the order in which they were injected.
    ///
    /// @param[in]  bytes           Packet raw bytes.
    /// @param[in]  initial_values      Set of (name, value) pairs to be updated prior to Format Identification.
    ///
    /// @return true if packet injected successfully, false otherwise.
    virtual bool inject_packet(const nsim_packet_info_t& packet_info, const nsim_name_value_map_t& initial_values) = 0;
    /// @brief Inject packet into simulation.
    /// Packets are simulated in the order in which they were injected.
    ///
    /// @param[in]  struct           Trigger info struct.
    ///
    /// @return true if trigger injected successfully, false otherwise.
    virtual bool inject_db_trigger(const nsim_db_trigger_info_t& trigger_info) = 0;

    /// @brief Sets lrc_fifo trigger to run before next packet
    virtual void trigger_lrc_fifo() = 0;

    virtual std::list<nsim_packet_info_t> get_and_clear_output_packets() = 0;
    /// @brief gets packets from the output queue
    /// Returns after the timeout_in_milliseconds expires or number of the packets
    /// in the output queue is equal to or greater than num_of_packets.
    ///
    /// @return list of packets from the output queue
    virtual std::list<nsim_packet_info_t> get_and_clear_output_packets(size_t timeout_in_milliseconds, size_t num_of_packets) = 0;
    /// Pop n packets from the front of the packet queue.
    virtual std::list<nsim_packet_info_t> get_and_clear_output_packets(size_t num_of_packets) = 0;
    /// @brief gets packets stacked in packet DMA extract queue and clears it.
    /// Returns after the timeout_in_milliseconds expires or number of the packets
    /// in the DMA extract queueis equal to or greater than num_of_packets.
    ///
    /// @return list of packets scheduled to be sent to packet DMA extract engine
    virtual std::list<nsim_packet_info_t> get_and_clear_packet_dma_extract_queue(unsigned ctx_id) = 0;
    /// @return the first N packets that will fit given the packet and byte constraints.
    virtual std::list<nsim_packet_info_t> get_and_clear_packet_dma_extract_n(unsigned ctx_id,
                                                                             uint16_t packets_avail,
                                                                             size_t bytes_avail)
        = 0;
    /// @brief gets packets stacked in packet DMA extract queue and clears it.
    /// @return list of packets scheduled to be sent to packet DMA extract engine
    virtual std::list<nsim_packet_info_t> get_and_clear_packet_dma_extract_queue(unsigned ctx_id,
                                                                                 size_t timeout_in_milliseconds,
                                                                                 size_t num_of_packets)
        = 0;
    /// @brief gets events from event queue and clears it.
    /// Uses the methods described below
    /// @return list of events if the event queue had any and no error had occurred, empty list otherwise.
    virtual std::list<nsim::bit_vector> get_and_clear_event_queue() = 0;
    /// @brief gets a pointer to next address that will be written on the event queue.
    ///
    /// @return valid nsim::bit_vector on success, empty nsim::bit_vector otherwise.
    virtual nsim::bit_vector get_event_queue_write_ptr() = 0;
    /// @brief gets a pointer to beginning of entries available ot read in the event queue.
    /// if eqals to write_ptr - the queue is empty
    /// @return valid nsim::bit_vector on success, empty nsim::bit_vector otherwise.
    virtual nsim::bit_vector get_event_queue_read_ptr() = 0;
    /// @brief performs a lookup in the event queue.
    /// @param[in]  bytes           key of the entry.
    /// @return valid nsim::bit_vector on success, empty nsim::bit_vector otherwise.
    virtual nsim::bit_vector get_event_queue_entry(const nsim::bit_vector& read_address) = 0;
    /// @brief updates read_ptr register value.
    /// @param[in]  bytes           payload to be updated.
    virtual void update_event_queue_read_ptr(nsim::bit_vector& address) = 0;

};
} // namespace nsim

using nsim::nsim_packet_info_t;
using nsim::nsim_db_trigger_info_t;
using nsim::db_trigger_type_e;
using nsim::db_trigger_mp_table_type_e;

#endif
