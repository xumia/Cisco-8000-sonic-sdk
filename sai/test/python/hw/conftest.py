# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import json
import sys
import logging
import os
from pathlib import Path
import pytest
import pprint
# Fishnet
try:
    from tests.conftest import run_code_interact
    from utils.general_utils import get_my_ip_addr  # only needed for Spirent Traffic gen
    from utils.snake_ports import parse_json_into_data, portsr_to_tuple
    from utils.traffic_gen import EpgmTe, InternalTrafficGen, IxiaTe, SimTe, SpirentTe, traffic_generators, XenaTe
    from utils.warm_boot import WarmBootMode
    pytest.has_tgen = True
except BaseException:
    pytest.has_tgen = False
try:
    from utils.boards.stingray.stingray import Stingray
    from utils.boards.blacktip.blacktip import Blacktip
    from utils.boards.board import BaseBoard
except BaseException:
    # no fishnet. load Churchill from bsp package
    from boards.churchill import Churchill

# SAI
import saicli as S
import sai_test_base as st_base
import sai_test_utils as st_utils
import sai_topology
# SAI HW
from sai_hw_utils import leaba_tf_wait, AsicType

sys.LEABA_VALIDATION_PATH = os.getenv('LEABA_VALIDATION_PATH', '')
sys.LEABA_SDK_PATH = os.getenv('LEABA_SDK_PATH', '')

LOG_FORMAT = '%(levelname)s - %(message)s'
logging.basicConfig(filename='./test_framework.log', filemode='w', level=logging.INFO, format=LOG_FORMAT)
logging.getLogger().addHandler(logging.StreamHandler())


def pytest_addoption(parser):
    # attributes copied from fishnet/tests/conftest.py
    parser.addoption("--json", action="store", default="", help="test-bed setup json file")
    parser.addoption("--warm-boot-mode", action="store", default="",
                     help="Warm boot mode indication. Supported: BEFORE_TRAFFIC/DURING_TRAFFIC/BEFORE_TRAFFIC_POST_MOD/"
                          "DURING_TRAFFIC_POST_MOD/SDK_RELOAD_SAVE_PHASE/SDK_RELOAD_RESTORE_PHASE")
    parser.addoption("--asic", action="store", default="GB", choices="[PA, GB]",
                     help="define asic of sim/board {PA-Pacific/GB-Gibraltar")


class hw_sai_device():
    def __init__(self, sai_test_base, board_obj, device_mode = "STANDALONE", is_gb=False):
        print(" - Starting SAI device")
        self.is_gb = is_gb
        self.tb = sai_test_base
        self.device_name = "/dev/uio0"
        self.device_mode = device_mode
        self.slice_modes = None
        self.la_dev = self.tb
        self.packets = []


class nsim_sai_device(hw_sai_device):
    def __init__(self, sai_test_base, board_obj, device_mode = "STANDALONE", is_gb=False):
        super().__init__(sai_test_base, board_obj, device_mode, is_gb)
        print(" - simulation mode ")
        self.device_name = None

    def inject(self, pkt, p_slice, p_ifg, p_pif, num):
        self.tb.inject_network_packet(pkt, p_slice, p_ifg, p_pif)

    def run(self):
        pass  # we do the run together with inject

    def get_output_packet(self):
        ret = self.tb.get_packet()
        if ret[0]:
            pkt = ret[1]
            return [pkt.packet, pkt.slice, pkt.ifg, pkt.pif]
        else:
            return ["", 0, 0, 0]


class RunningObj:
    """Object holding reference to global data used in tests"""

    def __init__(self):
        self.global_dev = {}
        self.json_data = None
        self.ports_obj = [fake_port()]
        self.logger = None
        self.json_apps_data = None
        self.board_obj: BaseBoard = None


# This is needed because in fishnet traffic generator class, it verifies that the port connected
# to the Tgen is up. It uses SDK functions.
class fake_mac:
    def verify_ports_are_up(self, ports="ALL", is_debug=False):
        # in SAI tests, we verify relevant ports are up in other place
        pass


class fake_port():
    # below two functions needed for simulation run
    def inc_tx_cnt(self, key):
        pass

    def inc_rx_cnt(self, key):
        pass


def init_devices(obj: RunningObj, request, is_gb):
    """
    main call routine to initialize the devices in the test bed
    :param obj: the running class holds the reference to the session variables
    :param request:
    :return:
    """

    options = st_base.get_test_options(request)
    obj.sai_test_base = st_base.sai_test_base(options)
    print("\nStarting Device Init")
    if pytest.IS_SIMULATOR:
        obj.global_dev = nsim_sai_device(obj.sai_test_base, obj.board_obj, is_gb=is_gb)
    else:
        obj.global_dev = hw_sai_device(obj.sai_test_base, obj.board_obj, is_gb=is_gb)


def board_support(board_type):
    if pytest.IS_SIMULATOR:
        board_obj = BaseBoard(1.2)
    else:
        if "stingray" in board_type:
            board_obj = Stingray()
        elif "sherman" in board_type:
            board_obj = Sherman(1.2)
        elif "blacktip" in board_type:
            board_obj = Blacktip(1.2, -1.0)
        elif "churchill" in board_type:
            board_obj = Churchill(1.2, -1.0)
        else:
            assert False, "Wrong board type"

    freq = board_obj.device_core_freq
    voltage = board_obj.voltage
    board_obj.set_voltage('VDDC_PS', voltage)
    board_obj.set_core_freq(freq)
    print('Waiting...')
    leaba_tf_wait(5)

    return board_obj


@pytest.fixture(scope='session', autouse=True)
def sessionstart(request):
    pytest.ASIC = request.config.getoption("--asic")
    pytest.DEBUG_MODE = False
    pytest.IS_SIMULATOR = request.config.getoption("--sim")
    pytest.IS_EMULATOR = False
    try:
        pytest.WB_MODE = getattr(WarmBootMode, request.config.getoption('--warm-boot-mode'), WarmBootMode.NONE)
    except BaseException:
        pass
    yield


@pytest.fixture(scope='session')
def init_device_and_ports(sessionstart, request):
    """
    This fixture overrides the tests/init_device_and_ports when running SAI tests
    """
    running = RunningObj()
    # Set logging handler
    running.logger = logging.getLogger('sai_hw_tests')
    fh = logging.FileHandler('./sai_hw_tests.log', 'w')
    fh.setLevel(logging.INFO)
    running.logger.addHandler(fh)
    running.logger.addHandler(logging.StreamHandler())

    request_json = request.config.getoption("--json")
    if request_json != "none":
        with open(request_json) as f:
            json_data = json.load(f)
        print(pprint.pformat(json_data, compact=True, width=160))
        running.json_data = json_data
        board_type = json_data["board-type"].lower()
    else:
        board_type = "churchill"

    asic_type = AsicType(pytest.ASIC)
    running.board_obj = board_support(board_type)

    if asic_type == AsicType.GIBRALTAR:
        is_gb = True
        dev = "blacktip"
    else:
        is_gb = False
        dev = "stingray"

    if request_json != "none":
        msg = "Setup Description:%s" % (running.json_data["description"])
        print(msg)

    init_devices(running, request, is_gb)

    if pytest.IS_SIMULATOR or request_json == "none":
        default_board = dev
        request_config_file = ""
    else:
        default_board = running.json_data["board-type"]
        request_config_file = request_json

    board_type = os.getenv('BOARD_TYPE', default_board)

    # get the absolute path of the config json file
    if request_config_file != "":
        request_config_file = os.path.abspath(request_config_file)

    # Check if 'serdes_params' is located config json file (run command --json file)
    # If there is no 'serdes_params' in config json file, use board_type to get the config file in SAI env.
    # If dv has serdes_params, use it to setup the board and serdes.
    if request_config_file != "" and 'serdes_params' in json_data["devices"]:
        config_file = request_config_file
    else:
        config_file = None

    device = running.global_dev
    running.sai_test_base.setUp(device.device_name, board_type, config_file)
    if pytest.IS_SIMULATOR:
        device.nsim_provider = running.sai_test_base.nsim_provider
        device.nsim = device.nsim_provider

    # define a global pytest variable to call python code interact
    # pytest.interact = run_code_interact

    # wait for all tests to be completed
    print("\nStarting tests...\n")
    yield running

    # Tear down
    print("\nDestroy devices")
    running.sai_test_base.tearDown()


@pytest.fixture(scope='session')
def traffic_gen(request, init_device_and_ports):
    """
    Traffic generator fixture
       - Connects to traffic generator (i.e. Xena, Simulator)
       - Reserve ports
       - Check if links are up
       If fails in either step, the tests will be skipped
    """
    te_data_list = init_device_and_ports.json_data["test-equipment"]

    # Backward compatibility json support
    if isinstance(te_data_list, dict):
        te_data_list = [te_data_list]
    te_list = []
    for te_data in te_data_list:
        # configure join_session parameter to restore existing session
        join_session = is_join_session_wb if pytest.WB_MODE is not WarmBootMode.NONE else \
            lambda *_: False

        # check type of traffic Generator
        if pytest.IS_SIMULATOR and te_data["type"] != "internal":
            print("---- Simulated Traffic Generator ----")
            te = SimTe(init_device_and_ports.global_dev,
                       init_device_and_ports.json_data,
                       init_device_and_ports.ports_obj, join_session=join_session)
        else:
            if te_data["type"] == "xena":
                te = XenaTe(te_data["address"], te_data["user"], debug=pytest.DEBUG_MODE, join_session=join_session)
            elif "spirent" in te_data["type"]:
                session_str = get_my_ip_addr()
                if request.config.getoption('markexpr'):
                    session_str += '-' + request.config.getoption('markexpr')
                te = SpirentTe(
                    te_data["address"],
                    te_data["session_mng_ip"],
                    te_data["user"],
                    session_str=session_str,
                    debug=pytest.DEBUG_MODE, AN='false', join_session=join_session)
            elif te_data["type"] == "ixia":
                te = IxiaTe(te_data["address"], te_data["user"], debug=pytest.DEBUG_MODE)
            elif te_data["type"] == "epgm":
                te = EpgmTe(te_data["address"], te_data["user"], debug=pytest.DEBUG_MODE)
            elif te_data["type"] == "internal":
                te = InternalTrafficGen(list(init_device_and_ports.global_dev.values())[0].la_dev, init_device_and_ports.json_data,
                                        request.config.getoption("--rtl"))
            else:
                pytest.skip("Invalid traffic_generator %s Testing requires Xena/    Spirent " % te_data["type"])
                return
            te.mac_ports = fake_mac()
            te.join_session = join_session
        # reserve ports
        (ports, conn, te_conn, loopbacks) = parse_json_into_data(init_device_and_ports.json_data)
        for port in te_data["ports"]:
            try:
                conn_port = None
                for te_pair in te_conn:
                    if "TE" in te_pair[1]:
                        te_pair.reverse()
                    if port["name"] in te_pair[0]:
                        conn_port = portsr_to_tuple(te_pair[1])
                te.reserve_ports(port["name"], conn_port)
                te.stop_traffic(port["name"])
            except BaseException:
                te.teardown_session()
                pytest.fail("Failed to reserve Traffic_gen port %s" % port["name"])

        # wait for links to change state
        leaba_tf_wait(2)

        te_list.append(te)
    if len(te_list) == 1:
        te = te_list[0]
    else:
        te = traffic_generators(te_list)

    yield te

    # Before session ends, stop all traffic ->
    # avoid the case in which after test failure (or quit/Ctrl+D) traffic gen continue transmit
    te.stop_all_traffic_and_disable_capture(is_capture=False)
    # disconnect session if pkt_gen = Spirent
    te.teardown_session()
