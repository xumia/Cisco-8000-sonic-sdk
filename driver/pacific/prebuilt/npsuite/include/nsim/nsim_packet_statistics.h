// BEGIN_LEGAL
//
// Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NSIM_PACKET_STATISTICS_H__
#define __NSIM_PACKET_STATISTICS_H__

#include <list>
#include <string>
#include <cassert>
#include <utility>
#include <cstdint>

namespace nsim
{

// Packet statistics for NSIM is a hierarchy of classes that encompasses the paths
// that a packet has taken in the simulator.
//
// Each packet that ingresses the simulator can take multiple passes before egressing
// or being dropped.  Each pass is considered a subset of the full path between RxPP and TxPP.
// Every packet statistics class instance is largely a list of passes.
//
// Each pass is a list of engines.  The path from RxPP to TxPP has multiple execution engines,
// and each one with an executed macro will show up in the engine list.
//
// Each engine has a name, a list of executed macros, and a flag for if it is defined in hardware.npl
// When is_hardware_npl() returns true, it indicates that the engine and macros executed
// by it are written to simulate non-programmable behavior of the hardware, typically the
// connecting pieces between programmable execution engines.
//
// For each macro executed by an engine, we maintain the name of the executed macro and the
// list of database accesses that occurred when it ran.
//
// Each database access maintains the name of the table, the database name, and the incoming and
// outgoing interfaces
class packet_statistics_database_access_t
{
public:
    packet_statistics_database_access_t(){};
    packet_statistics_database_access_t(const std::string& table_name,
                                        const std::string& database_name,
                                        const std::string& incoming_interface,
                                        const std::string& outgoing_interface)
        : m_table_name(table_name),
          m_database_name(database_name),
          m_incoming_interface(incoming_interface),
          m_outgoing_interface(outgoing_interface){};

public:
    std::string m_table_name;
    std::string m_database_name;
    std::string m_incoming_interface;
    std::string m_outgoing_interface;
};

class packet_statistics_macro_t
{
public:
    packet_statistics_macro_t(const std::string& name) : m_macro_name(name){};
    packet_statistics_macro_t(){};
    void insert_table_lookup(const std::string& table_name,
                             const std::string& database_name,
                             const std::string& incoming_interface,
                             const std::string& outgoing_interface)
    {
        m_database_accesses.emplace_back(table_name, database_name, incoming_interface, outgoing_interface);
    };

public:
    std::string m_macro_name;
    std::list<packet_statistics_database_access_t> m_database_accesses;
};

class packet_statistics_engine_t
{
public:
    packet_statistics_engine_t(const std::string& engine_name, bool is_hardware_npl)
        : m_engine_name(engine_name), m_is_hardware_npl(is_hardware_npl){};
    packet_statistics_engine_t() : m_is_hardware_npl(false){};
    void insert_macro(const std::string& name)
    {
        m_executed_macros.emplace_back(name);
    };
    void insert_table_lookup(const std::string& table_name,
                             const std::string& database_name,
                             const std::string& incoming_interface,
                             const std::string& outgoing_interface)
    {
        assert(!m_executed_macros.empty() && "Trying to insert a table lookup into empty macro list!");
        m_executed_macros.back().insert_table_lookup(table_name, database_name, incoming_interface, outgoing_interface);
    };

public:
    std::string m_engine_name;
    bool m_is_hardware_npl;
    std::list<packet_statistics_macro_t> m_executed_macros;
};

class packet_statistics_pass_t
{
public:
    packet_statistics_pass_t(){};

    // insert macro will look at the most recent engine to see if a new engine is needed
    void insert_macro(const std::string& name, const std::string& engine_name, bool is_hardware_npl)
    {
        maybe_insert_engine(engine_name, is_hardware_npl);
        m_engines.back().insert_macro(name);
    };
    void insert_table_lookup(const std::string& table_name,
                             const std::string& database_name,
                             const std::string& incoming_interface,
                             const std::string& outgoing_interface)
    {
        assert(m_engines.empty() == false && "Inserting table lookup into empty stage");
        m_engines.back().insert_table_lookup(table_name, database_name, incoming_interface, outgoing_interface);
    };

private:
    void maybe_insert_engine(const std::string& engine_name, bool is_hardware_npl)
    {
        if (m_engines.empty() || m_engines.back().m_engine_name != engine_name) {
            m_engines.emplace_back(engine_name, is_hardware_npl);
        }
    };

public:
    std::list<packet_statistics_engine_t> m_engines;
};

class packet_statistics_t
{
public:
    packet_statistics_t() : m_thread_id(0), m_packet_id(0){};
    void insert_macro(const std::string& name, const std::string& engine_name)
    {
        insert_macro(name, engine_name, false);
    };
    void insert_hw_npl_control(const std::string& name, const std::string& file_name)
    {
        insert_macro(name, file_name, true);
    };
    void insert_ene_control(const std::string& name)
    {
        insert_macro(name, "ENE", false);
    };
    void insert_table_lookup(const std::string& table_name,
                             const std::string& database_name,
                             const std::string& incoming_interface,
                             const std::string& outgoing_interface)
    {
        assert(m_passes.empty() == false && "Inserting table lookup into empty pass");
        m_passes.back().insert_table_lookup(table_name, database_name, incoming_interface, outgoing_interface);
    };
    void mark_recycle()
    {
        m_passes.emplace_back();
    };
    void clear_stats()
    {
        m_passes.clear();
    };

    void set_ingress_packet_id(uint64_t thread_id, uint64_t packet_id)
    {
        m_thread_id = thread_id;
        m_packet_id = packet_id;
    };

    std::string get_ingress_packet_id() const
    {
        return "ingress_packet:" + std::to_string(m_thread_id) + "_" + std::to_string(m_packet_id);
    };

private:
    void insert_macro(const std::string& name, const std::string& engine_name, bool is_hardware_npl)
    {
        if (m_passes.empty()) {
            m_passes.emplace_back();
        }
        m_passes.back().insert_macro(name, engine_name, is_hardware_npl);
    };

public:
    uint64_t m_thread_id;
    uint64_t m_packet_id;
    std::list<packet_statistics_pass_t> m_passes;
};

} // namespace nsim
#endif
