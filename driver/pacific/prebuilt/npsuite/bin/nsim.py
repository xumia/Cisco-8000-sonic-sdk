#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

from __future__ import print_function

import argparse
import code
import os
import re
import sys
import importlib
import shutil
import atexit
import logging
import time
import types
import traceback
import platform

try:
    if platform.architecture()[0] != "64bit":
        sys.stderr.write(
            "[%s] - Error: Your Python interpreter must support 64bit architecture. Please install "
            "correct version of Python with all necessary packages stated in <NPSUITE_ROOT>/requirements.pip\n" %
            sys.argv[0])
        sys.exit(-1)

    script_path = os.path.dirname(os.path.realpath(__file__))
    kit_lib_path = os.path.join(script_path, '..', 'pylib')
    sys.path += [kit_lib_path]
    python_api_res_folder = os.path.join(script_path, '..', 'res', 'nplc', 'npl_python_api')

except Exception:
    print(traceback.format_exc())

import nsimcli
import distutils.util
import nsim_util


def atexit_destroy(dsim_server):
    if dsim_server is not None:
        dsim_server.destroy()


def import_mod(what):
    mod = importlib.import_module(what)
    if mod is None:
        self.logger.error("Could not import {}".format(what))
        self.exit(1)
    return mod


class nsim:
    npl_path = None
    _nsim_core_impl = None
    #tables = None
    verbosity = False
    metadata_inited = False
    metadata_fields_names = []
    metadata_fields = {}
    state = {}
    output_file = None
    _npl_api_generator = None

    #
    # If set, we will open a DSIM client connection
    #
    _start_dsim_client = False

    #
    # If set, we will start the DSIM server
    #
    _start_dsim_server = False

    #
    # If set, we will open an RPC connection
    #
    _start_rpc_client = False

    #
    # If set this means we have started an RPC client.
    #
    rpc_client = None

    #
    # If set, indicates we wish to start an RPC client and server for nsim.py
    # This behaves identically to the environment variable NSIM_RPC_ENABLE.
    #
    _rpc_enable = False

    #
    # Start a daemon only
    #
    _rpc_start_daemon = False

    #
    # Start a client for the RPC daemon
    #
    _rpc_start_client_for_daemon = False

    #
    # Currently running as a daemon process? The main change here is that we do
    # not exit on client cleaup. The client has to explicitly shut us down.
    #
    _daemon = False
    _server = False

    #
    # If set, this is the remote RPC server to speak to/start.
    #
    _rpc_hostname = None
    _rpc_port = None

    #
    # Performance timing of RPC calls
    #
    _rpc_perf = False

    #
    # Set logging prefix
    #
    def formatter(self, verbosity=logging.INFO):
        format_string = "%(asctime)s.%(msecs)03d "

        #
        # It helps to know which end of the RPC this nsim.py is running on as we can
        # have a client nsim.py that starts the server side nsim.py
        #
        if self._server:
            format_string += "nsim.py (server): "
        elif self._daemon:
            format_string += "nsim.py (daemon): "
        elif self.rpc_client is not None or self._rpc_enable:
            format_string += "nsim.py (client): "
        else:
            format_string += "nsim.py: "

        datefmt = "%d-%m-%Y %H:%M:%S"
        format_string += "%(levelname)4s: "
        format_string += "(pid {}) ".format(os.getpid())
        # format_string += "({}) ".format(self)
        format_string += "%(message)s"
        return logging.Formatter(format_string, datefmt=datefmt)

    #
    # Time a function
    #
    def perf(func):
        def wrap(self, *args, **kwargs):
            if self._rpc_perf:
                tic = time.time()
                ret = func(self, *args, **kwargs)
                toc = time.time()
                self.logger.info('PERF: {:s}() took {:.3f} ms'.format(func.__name__, (toc - tic) * 1000.0))
                return ret
            else:
                return func(self, *args, **kwargs)
        return wrap

    @perf
    def import_mod(self, what):
        self.logger.debug("Importing {}".format(what))
        mod = importlib.import_module(what)
        if mod is None:
            self.logger.error("Could not import {}".format(what))
            self.exit(1)
        self.logger.debug("Imported {}".format(what))
        return mod

    @perf
    def delete_mod(self, what):
        if what in sys.modules:
            self.logger.info("Deleting {}".format(what))
            del sys.modules[what]
            self.logger.info("Deleted {}".format(what))

    #
    # Override local functions so that the nsim.py user ends up calling
    # the remote versions of these functions, completely unaware of the
    # RPC layer in between.
    #
    @perf
    def override_local_methods(self):
        if self._debug:
            self.logger.info("Override local methods")

        self.clear_all_device_state = self.rpc_client.clear_all_device_state
        self.get_and_clear_event_queue = self.rpc_client.get_and_clear_event_queue
        self.get_and_clear_output_packets = self.rpc_client.get_packets
        self.get_device_name = self.rpc_client.get_device_name
        self.get_entry = self.rpc_client.get_entry
        self.get_event_queue_read_ptr = self.rpc_client.get_event_queue_read_ptr
        self.get_event_queue_write_ptr = self.rpc_client.get_event_queue_write_ptr
        self.get_lpm_entry = self.rpc_client.get_lpm_entry
        self.get_num_log_messages = self.rpc_client.get_num_log_messages
        self.get_num_packet_waiting_to_be_injected = self.rpc_client.get_num_packet_waiting_to_be_injected
        self.get_packet = self.rpc_client.get_packet
        self.get_packets = self.rpc_client.get_packets
        self.get_port_config = self.rpc_client.get_port_config
        self.get_release_version = self.rpc_client.get_release_version
        self.get_server_port = self.rpc_client.get_server_port
        self.get_sim = self.get_sim_when_server_is_remote
        self.get_table_id_by_name = self.rpc_client.get_table_id_by_name
        self.get_ternary_entry = self.rpc_client.get_ternary_entry
        self.inject_packet = self.rpc_client.inject_packet_py_api
        self.is_port_up = self.rpc_client.is_port_up
        self.reset_state = self.rpc_client.reset_state
        self.set_expose_npu_host = self.rpc_client.set_expose_npu_host
        self.set_module_file_log_level = self.rpc_client.set_module_file_log_level
        self.set_module_stdout_log_level = self.rpc_client.set_module_stdout_log_level
        self.set_output_file = self.rpc_client.set_output_file
        self.set_oversubscribed_interfaces_detection_mode = self.rpc_client.set_oversubscribed_interfaces_detection_mode
        self.set_slice_context = self.rpc_client.set_slice_context
        self.set_verbosity = self.rpc_client.set_verbosity
        self.step = self.rpc_client.step
        self.step_macro = self.rpc_client.step_macro
        self.step_packet = self.rpc_client.step_packet
        self.trigger_lrc_fifo = self.rpc_client.trigger_lrc_fifo

        #
        # These overrides are to avoid race conditions with tests using a different
        # DSIM client from the RPC
        #
        self.write_register = self.rpc_client.write_register
        self.write_register_by_name = self.rpc_client.write_register_by_name
        self.read_register = self.rpc_client.read_register
        self.read_register_by_name = self.rpc_client.read_register_by_name
        self.write_memory = self.rpc_client.write_memory
        self.read_memory = self.rpc_client.read_memory
        self.read_memory_by_name = self.rpc_client.read_memory_by_name
        self.write_memory_by_name = self.rpc_client.write_memory_by_name
        self.read_modify_write_memory = self.rpc_client.read_modify_write_memory

    #
    # Preserve the original nsim core methods so we can call either them or RPC wrappers.
    # This avoids changes in unit tests that refer specifically to nsim core functions.
    #
    @perf
    def override_nsim_core_methods(self):
        self._nsim_core_impl.orig_get_entry = self._nsim_core_impl.get_entry
        self._nsim_core_impl.get_entry = self.get_entry

        self._nsim_core_impl.orig_get_lpm_entry = self._nsim_core_impl.get_lpm_entry
        self._nsim_core_impl.get_lpm_entry = self.get_lpm_entry

        self._nsim_core_impl.orig_get_ternary_entry = self._nsim_core_impl.get_ternary_entry
        self._nsim_core_impl.get_ternary_entry = self.get_ternary_entry

        self._nsim_core_impl.orig_set_slice_context = self._nsim_core_impl.set_slice_context
        self._nsim_core_impl.set_slice_context = self.set_slice_context

        self._nsim_core_impl.orig_get_table_id_by_name = self._nsim_core_impl.get_table_id_by_name
        self._nsim_core_impl.get_table_id_by_name = self.get_table_id_by_name

    @perf
    def warning_private_method(self):
        raise Exception("Private nsim.py method called")

    #
    # Look at self.args and env settings to determine what to enable
    #
    def process_args(self):
        #
        # Check for debugs first before all other settings, so we can log changes.
        #
        self._debug = nsim_util.getenv_bool("NSIM_RPC_DEBUG_ENABLE", False)
        if self.args._debug:
            self._debug = True

        #
        # Check if we want to performance time RPC calls
        #
        self._rpc_perf = nsim_util.getenv_bool("NSIM_RPC_PERF_ENABLE", False)
        if self.args._rpc_perf:
            self._rpc_perf = True

        #
        # Enable RPC if either NSIM_RPC_ENABLE=1 is set, or if we were started
        # with --rpc-enable
        #
        if self.args.server_status_file != "":
            #
            # This is the SDK spawning nsim.py. Don't spawn a further nsim.py; it actually works, but is a bit of a mind bend.
            #
            pass
        elif os.name != 'nt' and self.args.load_source_from_nsim_archive is None:
            #
            # No "exec" support on windows, so disable RPC
            #
            self._rpc_enable = nsim_util.getenv_bool("NSIM_RPC_ENABLE", self.args._rpc_enable)
            self._start_rpc_client = self._rpc_enable
            self._start_dsim_client = self._rpc_enable

        #
        # NSIM_RPC_DAEMON will cause the server to persist when the client exits.
        #
        self._rpc_start_daemon, self.args._rpc_hostname, self.args._rpc_port = nsim_util.getenv_NSIM_RPC_DAEMON(
            self.args._rpc_hostname, self.args._rpc_port)

        if self.args._rpc_start_daemon:
            self._rpc_start_daemon = True

        if self.args._server:
            self._server = True

        #
        # Starting just the client to connect to an existing daemon?
        #
        self._rpc_start_client_for_daemon = self.args._rpc_start_client_for_daemon
        if self._server or self._rpc_start_client_for_daemon:
            self._start_rpc_client = True

        #
        # Check if NSIM logging is requested from the env
        #
        self.nsim_logging = nsim_util.getenv_bool("ENABLE_NSIM_LOG", True)
        if self.args.disable_logger:
            self.nsim_logging = False

        self._started_remotely = self._server or self._daemon

    #
    # Start the client and have it spawn the server. The server will run
    # within a different process
    #
    @perf
    def start_rpc_client_and_spawn_server(self, additional_params_dic):
        self.logger.info("Starting RPC client and remote server")
        nsim_rpc_client = self.import_mod("nsim_rpc_client")
        self.rpc_client = nsim_rpc_client.context

        #
        # Start the RPC connection
        #
        self.rpc_client.start_client_and_server(
            self.args.source_path, self.args.leaba_defined_path, self.args.device_path, str(additional_params_dic),
            self.args._rpc_hostname,
            self.args._rpc_port,
            self._debug,
            self.nsim_logging,
            self.args.log_file_path,
            self._rpc_perf,
            self._rpc_start_daemon)

        #
        # Override local functions so that the nsim.py user ends up calling
        # the remote versions of these functions, completely unaware of the
        # RPC layer in between.
        #
        self.override_local_methods()

    #
    # Start the client only with the configured host and port information.
    # It is expected that the server has been started already out of band.
    #
    # This code path is used with run_test.py --client
    #
    @perf
    def start_rpc_client_only(self):
        self.logger.info("Starting RPC client only")
        self.logger.error("Starting client only not yet implemented")
        sys.exit(1)

    #
    # Start the server only with the configured host and port information.
    # It is expected that the client has been started already out of band.
    #
    @perf
    def start_rpc_server_only(self):
        self.logger.info("Starting RPC server only")
        self.logger.error("Starting server only not yet implemented")
        sys.exit(1)

    @perf
    def get_server_port(self):
        return self.port_num

    @perf
    def cleanup(self):
        if self._rpc_start_daemon or self._rpc_start_client_for_daemon:
            self.logger.debug('Cleanup ignore')
            return

        self.logger.debug('Cleanup')
        atexit.unregister(atexit_destroy)
        if self._device is not None:
            self._device.destroy()
            self._device = None

    @perf
    def ping(self):
        if self._device is not None:
            if self._debug:
                self.logger.debug('Client ping received')
            self._device.client_keepalive_event()
        else:
            if self._debug:
                self.logger.debug('Client ping received and dropped')

    @perf
    def prepare_output_path(self, path, rm_files=False):
        if os.path.isfile(path):
            self.logger.error('Output path %s already exists, and is a file.' % path)
            nplc_exit_code = 3
            raise Exception

        if os.path.isdir(path):
            if rm_files:
                for elem in os.listdir(path):
                    elem = os.path.join(path, elem)
                    if os.path.isfile(elem):
                        os.unlink(elem)
                    else:
                        shutil.rmtree(elem)
        else:
            os.mkdir(path)

    def wrapper_print(self, string, print_end=None):
        if print_end is not None:
            print(string, end=print_end)
        else:
            print(string)

        if self.output_file is not None:
            if print_end is not None:
                print(string, file=self.output_file, end=print_end)
            else:
                print(string, file=self.output_file)

    @perf
    def create_additional_params_dic(self, args):
        additional_params_dic = {"set_oversubscribed_interfaces_mode": args.set_oversubscribed_interfaces_mode,
                                 "check_port_up_mode": args.check_port_up_mode}

        if args.interfaces is not None:
            for interface_mapping in args.interfaces:
                # DSIM additional param format is "[netif@slice,ifg,pif] = veth"
                port_id, interface_name = str(interface_mapping[0]).split('@', 1)
                netif_port = "netif@" + port_id
                additional_params_dic[netif_port] = interface_name

        if args.num_of_threads != 0:
            additional_params_dic["num_of_threads"] = args.num_of_threads
        if args.simulator_timer_resolution_miliseconds is not None:
            additional_params_dic["simulator_timer_resolution_miliseconds"] = args.simulator_timer_resolution_miliseconds
        if args.num_simulation_seconds_per_hw_second is not None:
            additional_params_dic["num_simulation_seconds_per_hw_second"] = args.num_simulation_seconds_per_hw_second
        if args.disable_log_prefix:
            additional_params_dic["disable_log_prefix"] = 'True'
        if args.enable_packet_dma:
            additional_params_dic["enable_packet_dma"] = 'True'
        if args.mode is not None:
            additional_params_dic["mode"] = args.mode
        if args.disable_npl_assert:
            additional_params_dic["disable_npl_assert"] = 'True'
        if args.enable_asynchronous_logger:
            additional_params_dic["logger_sync_mode"] = 'async'
        else:
            additional_params_dic["logger_sync_mode"] = 'sync'
        if args.max_number_of_clients:
            additional_params_dic["max_number_of_clients"] = args.max_number_of_clients
        if not args.disable_logger:
            nsim_log_file_path = args.log_file_path
            if nsim_log_file_path == '':
                nsim_log_file_path = 'nsim_log.txt'
                self.client_log_file_path = 'client_log.txt'
            additional_params_dic["log_file_name"] = nsim_log_file_path
            if args.log_level is not None:
                additional_params_dic["log_level"] = args.log_level
        if args.log_file_max_size:
            additional_params_dic["log_file_max_size"] = args.log_file_max_size
        if args.log_file_max_files:
            additional_params_dic["log_file_max_files"] = args.log_file_max_files
        if args.enable_log_compression is not None:
            additional_params_dic["enable_log_compression"] = str(args.enable_log_compression)
        if args.thread_name_prefix is not None:
            additional_params_dic["thread_name_prefix"] = args.thread_name_prefix
        if args.log_msg_prefix is not None:
            additional_params_dic["log_msg_prefix"] = args.log_msg_prefix
        if args.enable_macro_execution_flow_logging:
            additional_params_dic["enable_macro_execution_flow_logging"] = 'True'
            if args.macro_execution_flow_log_file_path == '':
                macro_execution_flow_log_file_path = "macro_execution.json"
            else:
                macro_execution_flow_log_file_path = args.macro_execution_flow_log_file_path
            additional_params_dic["macro_execution_flow_log_file_path"] = macro_execution_flow_log_file_path

        #
        # Useful to see the pid when debugging RPC
        #
        if self.rpc_client is not None:
            if "log_msg_prefix" in additional_params_dic:
                additional_params_dic["log_msg_prefix"] = additional_params_dic["log_msg_prefix"] + "(pid {})".format(os.getpid())
            else:
                additional_params_dic["log_msg_prefix"] = "(pid {})".format(os.getpid())

            #
            # When using RPC mode, it is useful to make sure the server exists if some
            # communication error prevents the client from halting it.
            #
            additional_params_dic["set_keepalive_timeout_in_sec"] = "600"
            additional_params_dic["set_keepalive_timeout_abort"] = "true"

        #
        # Merge in the user provided additional params if any
        #
        if args.additional_params_str != "":
            other_dict = eval(args.additional_params_str)  # string to dict
            additional_params_dic.update(other_dict)  # dict merge

        if self._debug:
            for key, value in additional_params_dic.items():
                self.logger.debug("- param: {} = '{}'".format(key, value))

        if args.load_source_from_nsim_archive is not None:
            additional_params_dic["nsim_archive_source"] = args.load_source_from_nsim_archive

        return additional_params_dic

    #
    # Stop just the DSIM server
    #
    @perf
    def stop_server(self):
        self.logger.info('Stopping DSIM server')
        if self._device is not None:
            self._device.destroy()
            self._device = None
            self._nsim_core_impl = None
        if self._debug:
            self.logger.debug('Stopped DSIM server')

    #
    # Start just the DSIM server
    #
    @perf
    def start_server(self, additional_params):
        self.logger.info('Start DSIM server')
        self.stop_server()
        path = ""
        if self.path is not None:
            path = self.path
        leaba_defined_path = ""
        if self.args.leaba_defined_path is not None:
            leaba_defined_path = self.args.leaba_defined_path
        self._device = nsimcli.device_simulator_create_and_run_simulator_server(
            path,
            leaba_defined_path,
            self.socket_address,
            self.port_num,
            self.args.device_path,
            self.additional_params)
        if not self._device:
            raise Exception('Failed to initialize device simulator.')

        sim = self._device.get_nsim()
        self._nsim_core_impl = nsimcli.nsim_core_to_nsim_impl(sim)
        if self._debug:
            self.logger.debug('Started DSIM server')

    def __init__(self, args, command_line_options=[], daemon=False):
        #
        # Save the command line options in case we need to start a server and replay the options
        #
        self.command_line_options = command_line_options
        self.args = args
        self.init(args, command_line_options, daemon)

    @perf
    def init(self, args, command_line_options=[], daemon=False):

        self._client = None
        self.tables = None
        self.parser = None
        self._device = None

        self._daemon = daemon

        self.process_args()

        self.handler = logging.StreamHandler()
        self.handler.setLevel(logging.INFO)
        self.handler.setFormatter(self.formatter(logging.INFO))
        self.handler.setFormatter(self.formatter(logging.DEBUG))
        self.handler.setFormatter(self.formatter(logging.ERROR))

        if self._started_remotely:
            self.logger = logging.getLogger(__name__ + "(remote)")
        else:
            self.logger = logging.getLogger(__name__)

        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        path = args.source_path
        self.script_path = os.path.dirname(os.path.realpath(__file__))
        self.leaba_defined_npl_path = args.leaba_defined_path

        #
        # Need to create additional_params_dic before we spawn the remote DSIM server via RPC
        # as we need to pass on the same arguments
        #
        additional_params_dic = self.create_additional_params_dic(args)

        if not self._started_remotely:
            self.logger.debug('Started locally')
            if self._rpc_start_client_for_daemon:
                #
                # Start the client only
                #
                self.start_rpc_client_only()
            elif self._start_rpc_client:
                try:
                    #
                    # Start the client and have it spawn the server
                    #
                    self.start_rpc_client_and_spawn_server(additional_params_dic)
                except Exception as e:
                    #
                    # If for some reason this fails struggle on. Currently this is used for windows.
                    #
                    self.logger.error('Failed to use RPC, falling back to default, non RPC model: error {}'.format(str(e)))
                    exc_info = sys.exc_info()
                    traceback.print_exception(*exc_info)
                    del exc_info
                    self.rpc_client = None
                    self._start_rpc_client = False
                    self._start_dsim_client = True
                    self._start_dsim_server = True
                    self._rpc_enable = False

            elif self._start_dsim_server:
                #
                # Start the server only
                #
                self.start_rpc_server_only()
            else:
                #
                # This is the default, nsim.py, everything in one process
                #
                self._start_rpc_client = False
                self._start_dsim_client = True
                self._start_dsim_server = True
        else:
            #
            # If started remotely, we only want to start server side code
            #
            self.logger.debug('Started remotely')
            self._start_rpc_client = False
            self._start_dsim_client = False
            self._start_dsim_server = True

        if not args.disable_logger:
            log_file_name = args.log_file_path

            if log_file_name == '':
                self.log_file_path = 'output'
                native_log_file_name = 'nsim_log.txt'
            else:
                self.log_file_path, native_log_file_name = os.path.split(log_file_name)
                if self.log_file_path == '':
                    self.log_file_path = 'output'

            #
            # Make sure and choose a different name for the server so logs do not collide if on the same host.
            #
            if self._started_remotely:
                native_log_file_name = native_log_file_name.replace(".txt", "_server.txt")

            self.prepare_output_path(self.log_file_path)
            log_file = self.log_file_path + "/" + native_log_file_name
            self.logger.info('Dumping log to: ' + log_file)

            if self._started_remotely:
                try:
                    with open(log_file, "w") as f:
                        nsimcli.Logger_InitDefaultLogger(self.log_file_path, True, native_log_file_name)
                except IOError:
                    self.logger.error("Failed to create log file '{}'".format(log_file))
        else:
            self.logger.debug('File logger disabled')

        # nsimcli.Logger_Init(self.log_file_path, True, native_log_file_name)
        if path is None:
            self.wrapper_print('-I-NSIM- Loading code from NSIM archive %s...' % args.load_source_from_nsim_archive)
        else:
            self.wrapper_print('-I-NSIM- Loading code from %s...' % path)
        self.npl_path = path

        #
        # If the DSIM server is running remotely, get the port info for the client.
        #
        if self.rpc_client is not None:
            socket_address, port_num = self.rpc_client.get_server_hostname_and_port()
            self.logger.debug('Remote DSIM server is at {}:{}'.format(socket_address, port_num))
        else:
            socket_address = args.hostname
            port_num = int(args.port_num)

        self.client_log_file_path = ''

        #
        # Save the params for later use in parser or server creation
        #
        self.additional_params = nsimcli.map_string_string(additional_params_dic)

        #
        # Need to start the DSIM server?
        #
        if self._start_dsim_server:
            #
            # If the DSIM server is being started via RPC/nsim.py on the remote end, then
            # the creation of the server here on the local end will fail as we're trying
            # to connect to the same host and port as the server.
            #
            # Ok, but why do we want to do this ? Unfortunately a lot of the table code has
            # requirements that it can access the parser object so we can generare the NPL
            # APIs. Perhaps we need a way to create the NSIM core only without DSIM?
            #
            if self._start_rpc_client:
                port_num = 0

            source_path = ""
            if path is not None:
                source_path = path
            leaba_defined_path = ""
            if self.args.leaba_defined_path is not None:
                leaba_defined_path = self.args.leaba_defined_path

            #
            # Retry to start the server, just in case there is a port collision
            #
            for retry in range(60):
                if self._debug:
                    self.logger.debug("Starting DSIM server '{}:{}'".format(socket_address, port_num))

                self._device = nsimcli.device_simulator_create_and_run_simulator_server(
                    source_path, leaba_defined_path, socket_address, port_num, args.device_path, self.additional_params)

                if not self._device:
                    raise Exception('Failed to initialize DSIM server.')

                if self._device.get_port() == 0:
                    self.logger.error(
                        "Failed to start DSIM server '{}:{}', retry {}".format(
                            socket_address, self._device.get_port(), retry))
                    self._device.destroy()
                    self._device = None
                    time.sleep(5)
                    continue

                self.logger.info("Started DSIM server '{}:{}'".format(socket_address, self._device.get_port()))
                break

            if self._device.get_port() == 0:
                self._device.destroy()
                self._device = None
                self.logger.error("Failed to start DSIM server '{}:{}'".format(socket_address, self._device.get_port()))

            self.path = path
            self.socket_address = socket_address
            self.port_num = self._device.get_port()
            sim = self._device.get_nsim()

            #
            # If someone wants to know the port we chose, save it now
            #
            if self.args.server_status_file != "":
                self.logger.info("Create server output file: {}".format(self.args.server_status_file))
                try:
                    with open(self.args.server_status_file, "w") as server_status_file:
                        server_status_file.write("dsim_server = '{}:{}';".format(socket_address, self._device.get_port()))
                except IOError:
                    self.logger.error("Failed to open DSIM server status file '{}'".format(self.args.server_status_file))
                    self.exit(1)

            self._nsim_core_impl = nsimcli.nsim_core_to_nsim_impl(sim)

            self.override_nsim_core_methods()

            self.sim = self.get_sim()
            if args.expose_npu_host:
                self.sim.set_expose_npu_host()

            # Python garbage collector does not destroy dynamically allocated dsim
            # so we explicitly do it at exit
            if self._device:
                atexit.register(atexit_destroy, self._device)

        if self._start_dsim_client:
            self._local_port = self.get_server_port()
            if self._debug:
                self.logger.debug("Starting DSIM client '{}:{}'".format(socket_address, self._local_port))
            self._client = nsimcli.dsim_client()
            self.logger.info("Started DSIM client '{}:{}'".format(socket_address, self._local_port))
            if self.client_log_file_path != '':
                self._client.set_log_file(self.client_log_file_path, True)
            self._client.initialize(socket_address, self._local_port)

        #
        # Use the existing parser from the server (if we have one)
        #
        if self._nsim_core_impl:
            self.parser = self._nsim_core_impl.get_parser()

        #
        # Create our parser. If we are starting a DSIM server, then we can use the core
        # impl parser. Otherwise, we need to create our own (for example, running as a
        # client with RPC enabled).
        #
        if (self._start_dsim_server or self._rpc_enable) and not self._started_remotely:

            self.logger.info("Create parser")
            use_api_files = True
            create_api_files = True
            gen_api_code = True
            if args.disable_logger:
                args.disable_api_generation = True
                args.api_folder_path = None
                api_folder = None
            elif args.api_folder_path is None:
                api_folder = os.path.join(self.log_file_path, 'nsim_py_api')
            else:
                api_folder = args.api_folder_path

            if self._nsim_core_impl:
                self.my_logger = self._nsim_core_impl.get_logger()

        #
        # If running as a server for the RPC layer, wait until the server stops running
        #
        if self.args.server_status_file != "":
            if self._device is not None:
                while self._device.is_running():
                    self.logger.debug("Sleep")
                    time.sleep(1)

    @perf
    def set_output_file(self, file_path):
        if file_path is None:
            self.output_file = None
            return
        file_name = os.path.realpath(file_path)
        self.wrapper_print(file_name)
        self.output_file = open(file_name, 'w')

    def get_dsim_client(self):
        return self._client

    #
    # get_sim() is not friendly to RPC as it is a bit of a back door. Warn if this
    # is being used in the presence of RPC.
    #
    def get_sim(self):
        if self.rpc_client is None:
            return self._nsim_core_impl
        else:
            raise Exception("Calling get_sim() with RPC is not supported. You need to implement this backend API in RPC")

    #
    # A trick so clients end up calling RPC functions when trying to call n.sim.foo
    #
    def get_sim_when_server_is_remote(self):
        return self

    @perf
    def write_register(self, block_id, reg_address, reg_width, count, in_val):
        return self._client.write_register(block_id, reg_address, reg_width, count, in_val)

    @perf
    def write_register_by_name(self, name, reg_index, reg_width, count, in_val):
        return self._client.write_register_by_name(name, reg_index, reg_width, count, in_val)

    @perf
    def read_register(self, block_id, reg_address, reg_width, count, out_val):
        return self._client.read_register(block_id, reg_address, reg_width, count, out_val)

    @perf
    def read_register_by_name(self, name, reg_index, reg_width, count, out_val):
        return self._client.read_register_by_name(name, reg_index, reg_width, count, out_val)

    @perf
    def write_memory(self, block_id, mem_address, mem_width, mem_entries, in_val):
        return self._client.write_memory(block_id, mem_address, mem_width, mem_entries, in_val)

    @perf
    def read_memory(self, block_id, mem_address, mem_width, mem_entries, out_val):
        return self._client.read_memory(block_id, mem_address, mem_width, mem_entries, out_val)

    @perf
    def read_memory_by_name(self, mem_name, mem_index, mem_entry, mem_width, mem_entries):
        return self._client.read_memory_by_name(mem_name, mem_index, mem_entry, mem_width, mem_entries)

    @perf
    def write_memory_by_name(self, mem_name, mem_index, mem_entry, mem_width, mem_entries, in_val):
        return self._client.write_memory_by_name(mem_name, mem_index, mem_entry, mem_width, mem_entries, in_val)

    @perf
    def read_modify_write_memory(self, block_id, mem_address, mem_width, data_offset, data_width, mem_entries, in_val):
        return self._client.read_modify_write_memory(
            self,
            block_id,
            mem_address,
            mem_width,
            data_offset,
            data_width,
            mem_entries,
            in_val)

    @perf
    def value_returning_step(self, print_location):

        success = self.step()
        if not success:
            self.wrapper_print("unsuccessful step!")
            return False

        return True

    @perf
    def clear_all_device_state(self):
        self._nsim_core_impl.clear_all_device_state()

    @perf
    def get_device_name(self):
        return self._nsim_core_impl.get_device_name()

    @perf
    def step(self):
        return self._nsim_core_impl.step()

    @perf
    def step_macro(self):

        success = self._nsim_core_impl.step_macro()
        if not success:
            self.wrapper_print("unsuccessful step!")
            return False

        return True

    @perf
    def step_packet(self):

        success = self._nsim_core_impl.step_packet()
        if not success:
            self.wrapper_print("unsuccessful step!")
            return False

        return True

    @perf
    def get_packets(self, timeout_in_milliseconds=0, num_of_packets=0):
        out = []
        if num_of_packets == 0:
            packet_infos = self._nsim_core_impl.get_and_clear_output_packets()
        else:
            packet_infos = self._nsim_core_impl.get_and_clear_output_packets(timeout_in_milliseconds, num_of_packets)

        for packet_info in packet_infos:
            packet_data = packet_info.m_packet_data.to_string()[2:]  # trim leading 0x
            out.append((packet_data, packet_info.m_slice_id, packet_info.m_ifg, packet_info.m_pif))
        return out

    @perf
    def get_and_clear_output_packets(self, timeout_in_milliseconds=0, num_of_packets=0):
        return self._nsim_core_impl.get_and_clear_output_packets(timeout_in_milliseconds, num_of_packets)

    @perf
    def set_oversubscribed_interfaces_detection_mode(self, value):
        return self._nsim_core_impl.set_oversubscribed_interfaces_detection_mode(value)

    @perf
    def is_port_up(self, slice_id, ifg, pif):
        return self._nsim_core_impl.is_port_up(slice_id, ifg, pif)

    @perf
    def get_port_config(self, slice_id, ifg, pif):
        return self._nsim_core_impl.get_port_config(slice_id, ifg, pif)

    @perf
    def get_event_queue_write_ptr(self):
        return self._nsim_core_impl.get_event_queue_write_ptr()

    @perf
    def get_event_queue_read_ptr(self):
        return self._nsim_core_impl.get_event_queue_read_ptr()

    @perf
    def get_num_packet_waiting_to_be_injected(self):
        self.logger.info("get_num_packet_waiting_to_be_injected")
        return self._nsim_core_impl.get_num_packet_waiting_to_be_injected()

    @perf
    def get_num_log_messages(self, value):
        return self._nsim_core_impl.get_logger().GetNumLogMessages(value)

    @perf
    def get_entry(self, table_name, instance_index, key_bv, out_payload_bv):
        return self._nsim_core_impl.orig_get_entry(table_name, instance_index, key_bv, out_payload_bv)

    @perf
    def get_lpm_entry(self, table_name, instance_index, key_bv, lpm_length, out_payload_bv):
        return self._nsim_core_impl.orig_get_lpm_entry(table_name, instance_index, key_bv, lpm_length, out_payload_bv)

    @perf
    def get_ternary_entry(self, table_name, instance_index, line, out_key_bv, out_mask_bv, out_payload_bv):
        return self._nsim_core_impl.orig_get_ternary_entry(
            table_name, instance_index, line, out_key_bv, out_mask_bv, out_payload_bv)

    @perf
    def set_slice_context(self, slice_id, context_id):
        return self._nsim_core_impl.orig_set_slice_context(slice_id, context_id)

    @perf
    def get_table_id_by_name(self, name):
        return self._nsim_core_impl.orig_get_table_id_by_name(name)

    @perf
    def reset_state(self):
        if self.rpc_client:
            if self._debug:
                self.logger.debug("Reset state")
            if not self.rpc_client.reset_state():
                self.logger.error("CLient reset state failed")

        if self.tables:
            self.logger.debug("Reset tables")
            self.tables.reset_state()
            self.tables = None

        ret = self._nsim_core_impl.reset_state()
        if not ret:
            self.logger.error("Reset state {} failed".format(name))

        return ret

    @perf
    def inject_packet(self, packet, slice_id, ifg, pif, values={}, dump_state=False):
        if not isinstance(packet, str):
            raise TypeError('packet argument must of type string.')

        pi = nsimcli.nsim_packet_info_t()
        pi.set_args_and_dump(packet, slice_id, ifg, pif, dump_state)
        return self._nsim_core_impl.inject_packet(pi, values)

    @perf
    def packet_dma_enable(self, enable):
        return self._nsim_core_impl.packet_dma_enable(enable)

    @perf
    def inject_db_trigger(self, line_id, trigger_type, table_type):
        ti = nsimcli.nsim_db_trigger_info_t()
        ti.set_args(line_id, trigger_type, table_type)
        if self.rpc_client:
            return self.rpc_client.inject_db_trigger(ti)
        return self._nsim_core_impl.inject_db_trigger(ti)

    @perf
    def trigger_lrc_fifo(self):
        return self._nsim_core_impl.trigger_lrc_fifo()


def to_bool(val):
    return bool(distutils.util.strtobool(val))


def main(command_line_options, started_remotely=False, daemon=False):
    script_path = os.path.dirname(os.path.realpath(__file__))
    trunk_path = os.path.join(script_path, '../../../..')

    argparser = argparse.ArgumentParser(description='NPU simulator')
    argparser.add_argument("--debug", dest='_debug', default=False, action='store_true')
    argparser.add_argument("--perf", dest='_rpc_perf', default=False, action='store_true')

    #
    # RPC args
    #
    argparser.add_argument('--rpc-enable', dest='_rpc_enable', action='store_true', default=False,
                           help="Enable RPC backend")
    argparser.add_argument('--rpc-hostname', dest='_rpc_hostname', action='store', default='',
                           help="The hostname of the remote nsim.py RPC server")
    argparser.add_argument('--rpc-port', dest='_rpc_port', action='store', default=0,
                           help="The port of the remote nsim.py RPC server")
    argparser.add_argument('--client', dest='_rpc_start_client_for_daemon', action='store_true', default=False,
                           help="Connect to a running RPC daemon")
    argparser.add_argument('--server', dest='_server', action='store_true', default=False,
                           help="Start nsim.py as a server only")
    argparser.add_argument('--daemon', dest='_rpc_start_daemon', action='store_true', default=False,
                           help="Start nsim.py as a daemon only")

    argparser.add_argument('--source', dest='source_path',
                           action='store',
                           help='Source path for NPL code')
    argparser.add_argument('--leaba-defined', dest='leaba_defined_path',
                           action='store', help='You must provide a path to leaba_defined directory, or NSIM archive location')
    argparser.add_argument('--device-path', dest='device_path',
                           action='store', default='', help='Device path e.g. /dev/testdev, /dev/spidevm, /dev/uio, /dev/i2c')
    argparser.add_argument('--additional-include-path', dest='additional_include_path',
                           action='store', default=None,
                           help='additional python include path')
    argparser.add_argument('--num-of-threads', dest='num_of_threads',
                           action='store', default='0',
                           help='Number of threads: 0 (default) is debug mode')
    argparser.add_argument('--mode', dest='mode',
                           action='store', default=None,
                           help='Set device mode. Supported only on some devices (e.g. MATILDA_32A for Gibraltar)')
    argparser.add_argument('--prints-to_file', dest='print_file',
                           action='store', default=None,
                           help='print outputs to file in addition to cli')
    argparser.add_argument('--disable-logger', dest='disable_logger',
                           action='store_true', default=False,
                           help='disable logger')
    argparser.add_argument(
        '--log-level',
        dest='log_level',
        action='store',
        default=None,
        help='Set the log level',
        choices=[
            'NSIM_LOG_NONE',
            'NSIM_LOG_TABLE',
            'NSIM_LOG_FULL',
            'NONE',
            'TABLE',
            'FULL',
            '0',
            '3',
            '8'])
    argparser.add_argument('--log-file-path', dest='log_file_path',
                           action='store', default='',
                           help='log file path')
    argparser.add_argument('--disable-api-generation', dest='disable_api_generation',
                           action='store_true', default=False,
                           help='Disable generation of api files')
    argparser.add_argument('--api-folder-path', dest='api_folder_path',
                           action='store', default=None,
                           help='Use this folder for tables api files')
    argparser.add_argument('--expose-npu-host', dest='expose_npu_host',
                           action='store_true', default=False,
                           help='Simulate npu-host as independent slice without rest of the device')
    argparser.add_argument('--set_oversubscribed_interfaces_mode', dest='set_oversubscribed_interfaces_mode',
                           action='store', default='warn',
                           help='Set oversubscribed interfaces mode : warn (default) | drop | disabled')
    argparser.add_argument('--rerun-from-file-path', dest='rerun_path',
                           action='store', default='',
                           help='Load state and last packet from json file - provide file path')
    argparser.add_argument('--disable-log-prefix', dest='disable_log_prefix',
                           action='store_true', default=False,
                           help='Disable time prefix to log file')
    argparser.add_argument('--num_simulation_seconds_per_hw_second', dest='num_simulation_seconds_per_hw_second',
                           action='store_true', default=None,
                           help='Ratio between simulation and hw second - for timer')
    argparser.add_argument('--simulator_timer_resolution_miliseconds', dest='simulator_timer_resolution_miliseconds',
                           action='store_true', default=None,
                           help='Resolution of nsim timer in miliseconds')
    argparser.add_argument('--port-num', dest='port_num', action='store', default='0',
                           help='Port that the DSIM server will be connect to')
    argparser.add_argument('--host', dest='hostname', action='store', default='127.0.0.1',
                           help='Host name that the DSIM server will be connected to. Default is 127.0.0.1')
    argparser.add_argument('--server-status-file', dest='server_status_file', action='store', default="",
                           help='A file which the DSIM server port number will be written into')
    argparser.add_argument('--enable-packet-dma', dest='enable_packet_dma', action='store_true', default=False,
                           help='Enable packet DMA')
    argparser.add_argument('--check-port-up-mode', dest='check_port_up_mode', action='store', default='drop',
                           help='Set check port up mode. Possible options: \
                                 drop (default) - packet is dropped if the port is down \
                                 warn - print warning and continue packet processing \
                                 disable - disable this check')
    argparser.add_argument('--additional-params', dest='additional_params_str', action='store', default='',
                           help="Additional server params e.g. {'check_port_up_mode' : 'warn'}")
    argparser.add_argument(
        '-i',
        '--interface',
        dest='interfaces',
        nargs='+',
        action='append',
        help='Specify slice_id,ifg,pif and interface name to map to. Example: --interface 2,0,4@veth0 --interface 0,1,0@veth3 ...')
    argparser.add_argument('--disable-npl-assert', dest='disable_npl_assert', action='store_true', default=False,
                           help='Disable execution of assert statements')
    argparser.add_argument('--enable-asynchronous-logger', dest='enable_asynchronous_logger', action='store_true', default=False,
                           help='Set the logger mode to asynchronous. Default for nsim.py is synchronous.')
    argparser.add_argument('--max-num-of-client-connections', dest='max_number_of_clients', action='store', default=None,
                           help='Set maximum number of allowed client connections to the DSIM server')
    argparser.add_argument(
        '--log-file-max-size',
        dest='log_file_max_size',
        action='store',
        default=None,
        help='Set maximum size of log, causes intermediate files to be written to disk, and at NSIM exit they are coalesced into a single file')
    argparser.add_argument('--log-file-max-files', dest='log_file_max_files', action='store', default=None,
                           help='Set the maximum number of intermediate log files to create while logging')
    argparser.add_argument('--enable-log-compression', dest='enable_log_compression', action='store', type=to_bool, default=None,
                           help='Enable log compression')
    argparser.add_argument('--thread-name-prefix', dest='thread_name_prefix', action='store', default=None,
                           help='When multithreading, use this instead of PKT for packet processing threads')
    argparser.add_argument(
        '--log-msg-prefix',
        dest='log_msg_prefix',
        action='store',
        default=None,
        help='When logging, add this string as a prefix to every logged message.  \': \' will be appended as a delimiter')
    argparser.add_argument(
        '--enable-macro-execution-flow-logging',
        dest='enable_macro_execution_flow_logging',
        action='store_true',
        default=False,
        help='Output a per-macro execution log including control, context, and engine info, plus on-enter and -exit PD values'
    )
    argparser.add_argument('--macro-execution-flow-log-file-path', dest='macro_execution_flow_log_file_path',
                           action='store', default='',
                           help='macro execution flow log path'
                           )

    argparser.add_argument('--load-source-from-nsim-archive',
                           dest='load_source_from_nsim_archive',
                           action='store',
                           default=None,
                           help='Load source and hardware definitions from specified NSIM Archive')

    args = argparser.parse_args(command_line_options)

    # Use presence or not of the environement variable to determine if we need
    # to validate input args.
    load_source_from_nsim_archive_env = os.getenv("LOAD_SOURCE_FROM_NSIM_ARCHIVE")
    if load_source_from_nsim_archive_env is None:
        if args.load_source_from_nsim_archive is None:
            if args.leaba_defined_path is None or args.source_path is None:
                raise SystemExit("You must provide leaba-defined AND source, when not loading from an NSIM archive")
        else:
            if args.leaba_defined_path is not None or args.source_path is not None:
                raise SystemExit("You must not provide leaba-defined or source, when loading from an NSIM archive")

    if 'PYTHONSTARTUP' in os.environ:
        exec(open(os.environ['PYTHONSTARTUP']).read())

    sys.nsim = nsim(args, command_line_options, daemon)
    if args.print_file is not None:
        sys.nsim.set_output_file(args.print_file)
    sys.path += ['.']

    if args.additional_include_path is not None:
        full_path = os.path.realpath(args.additional_include_path)
        sys.path += [full_path]


def main_wrapper(args, daemon=False):
    main(args, daemon)  # NOTE: main() is called direcly by RPC also


if __name__ == '__main__':
    try:
        main_wrapper(sys.argv[1:])
    except Exception:
        print(traceback.format_exc())
