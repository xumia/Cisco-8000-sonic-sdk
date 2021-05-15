# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from leaba import sdk
from leaba import debug
import sim_utils
import lldcli

from enum import Enum
from snake_base import *
from spirent_connector import *

SHUT_ITERATIONS = 1
ITERATION_DELAY = 5  # Time in seconds

BOARD_TYPE = 'examples/sanity/shermanP7_board_config.json'
PARAM_JSON = 'examples/sanity/sherman_serdes_settings.json'
JSON_DEFAULT_DIR = 'test/board/mixes/'

SPIRENT_DEVICE_IP = "10.56.18.242"
SPIRENT_SESSION_MGR_IP = "10.56.18.140"
SPIRENT_PORT = "2/1"

HIGH_BER_NRZ = 0
HIGH_BER_PAM4 = 1e-6
MAX_FEC_BIN_NRZ = 1
MAX_FEC_BIN_PAM4 = 4

DWELL_UP_TIME = 120  # Time in seconds
DWELL_SHUT_TIME = 10  # Time in seconds


class ports_base(snake_base):
    # loop_mode and p2p_ext should be provided in test that inherits this ports_base class
    loop_mode = None
    p2p_ext = None

    class TRAFFIC_MODE(Enum):
        NO_TRAFFIC = 1
        TRAFFIC_AFTER_ACTIVATE = 2
        TRAFFIC_IN_THE_MIDDLE = 3

    class DEVICE_MODE(Enum):
        NETWORK = 1
        LINECARD_2x50 = 2
        LINECARD_4x50 = 3

    def fill_args_from_env_vars(self, ports_mix, device_mode = DEVICE_MODE.NETWORK):
        self.snake.args.loop_mode = self.loop_mode
        self.snake.args.p2p_ext = self.p2p_ext

        board_type = os.getenv("board_type")
        if board_type is None:
            board_type = 'sherman'
        board_ip = os.getenv("board_ip")
        self.board_str = "{}-{}".format(board_ip, board_type)
        json_dir = os.getenv("connectivity_dir")
        if json_dir is None:
            json_dir = JSON_DEFAULT_DIR
        self.snake.args.json_mix = json_dir + '/' + board_type + '/' + ports_mix

        if device_mode is self.DEVICE_MODE.LINECARD_2x50:
            self.snake.args.line_card = True
        elif device_mode is self.DEVICE_MODE.LINECARD_4x50:
            self.snake.args.line_card = True
            self.snake.args.fabric_200g = True

        board_cfg_path = os.getenv("board_cfg_path")
        if board_cfg_path is None:
            board_cfg_path = BOARD_TYPE
        self.snake.args.board_cfg_path = board_cfg_path

        self.snake.args.params_json = os.getenv("serdes_params_json")
        if self.snake.args.params_json is None:
            self.snake.args.params_json = PARAM_JSON

        self.test_iterations = os.getenv("test_iterations")
        if self.test_iterations is None:
            self.test_iterations = SHUT_ITERATIONS
        else:
            self.test_iterations = int(self.test_iterations)
        self.spirent_ip = os.getenv("spirent_ip")
        if self.spirent_ip is None:
            self.spirent_ip = SPIRENT_DEVICE_IP
        self.spirent_session_manager_ip = os.getenv("spirent_session_manager_ip")
        if self.spirent_session_manager_ip is None:
            self.spirent_session_manager_ip = SPIRENT_SESSION_MGR_IP
        self.spirent_port = os.getenv("spirent_port")
        if self.spirent_port is None:
            self.spirent_port = SPIRENT_PORT
        self.reports_dir = os.getenv("REPORTS_DIR")
        if self.reports_dir is None:
            self.reports_dir = "./"
        self.json_reconfig_mix = json_dir + '/' + board_type + '/' + 'reconfig_mix.json'

    def setUp(self):
        super().setUp()
        self.traffic_enabled = False
        self.spirent = None

    def tearDown(self):
        if self.traffic_enabled:
            self.close_spirent()
            self.traffic_enabled = False
        super().tearDown()

    def open_spirent(self):
        try:
            self.spirent = spirent_connector(self.spirent_ip, self.spirent_session_manager_ip, self.spirent_port, self.board_str)
            self.traffic_enabled = True
        except BaseException:
            self.skipTest("Spirent resource is not available")

    def add_data_streams(self):
        self.spirent.add_data_streams(num_streams=1,
                                      gen_type="FIXED",
                                      min_packet_size=500,
                                      max_packet_size=500,
                                      rate_percentage=2,
                                      fixed_frame_length=370)

    def close_spirent(self):
        if self.spirent is not None:
            self.spirent.teardown()
            self.spirent = None
        else:
            print('self.spirent is None!!!')

    def check_mac_fec(self, fec_counters):
        for index, fec_counter in enumerate(fec_counters):
            self.assertEqual(fec_counter['uncw'], 0, 'mac port index {}'.format(index))
            # PAM4 - SerDes Speed 50Gbps
            if fec_counter['serdes_speed'] == 50:
                min_bin = MAX_FEC_BIN_PAM4
                high_ber = HIGH_BER_PAM4
            else:
                min_bin = MAX_FEC_BIN_NRZ
                high_ber = HIGH_BER_NRZ

            for i in range(min_bin, 16):
                self.assertEqual(fec_counter['cw'][i], 0, 'mac port index {} codword index {}'.format(index, i))
            self.assertLessEqual(fec_counter['ber'], high_ber, 'mac port index {}'.format(index))

    def save_mac_fec_counters(self, fec_counters, iteration):
        for fec_counter in fec_counters:
            self.outfile.write(
                "{},{index},{name},{slice},{ifg},{serdes},{ber:.3e},{flr:.3e},{flr_r:.3}, {cw}, {uncw}, {symbol}\n".format(
                    iteration, **fec_counter))

    def shut_no_shut_mac_ports(self, mac_ports):
        for mac_port in mac_ports:
            mac_port.stop()

        all_mac_down = self.snake.mph.wait_mac_ports_down(timeout=DWELL_SHUT_TIME)
        self.assertTrue(all_mac_down, 'mac_up_cnt={} though all ports must be down'.format(self.snake.mph.mac_up_cnt))

        for mac_port in mac_ports:
            mac_port.activate()
            index = self.snake.mph.get_mac_port_idx(mac_port.get_slice(), mac_port.get_ifg(), mac_port.get_first_serdes_id())
            self.snake.mph.mac_time[index]["time_before_activate"] = time.time()

        all_up = self.snake.mph.wait_mac_ports_up(timeout=DWELL_UP_TIME)
        self.assertTrue(all_up, 'mac_up_cnt={}. Some of port link are down'.format(self.snake.mph.mac_up_cnt))
