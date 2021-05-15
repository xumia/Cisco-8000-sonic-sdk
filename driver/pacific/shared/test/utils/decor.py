#!/usr/bin/env python3
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

import os

# prefixes
PACIFIC = "PACIFIC"
GIBRALTAR = "GIBRALTAR"
ASIC5 = "ASIC5"
ASIC6 = "ASIC6"
ASIC4 = "ASIC4"
ASIC3 = "ASIC3"
hw_type = 'NONE'


def is_hw_device():
    return os.getenv('SDK_DEVICE_NAME') == '/dev/uio0'


def set_hw_type():
    global hw_type
    rc = os.system("lspci -d 16c3:abcd 2> /dev/null | grep -q '.*'")
    if rc == 0:
        hw_type = 'PACIFIC'
        return
    rc = os.system("lspci -d 1137:abcd 2> /dev/null | grep -q '.*'")
    if rc == 0:
        hw_type = 'PACIFIC'
        return

    rc = os.system("lspci -d 1137:a001 2> /dev/null | grep -q '.*'")
    if rc == 0:
        hw_type = 'GIBRALTAR'
        return

    rc = os.system("lspci -d 1137:a005 2> /dev/null | grep -q '.*'")
    if rc == 0:
        hw_type = 'ASIC5'
        return

    rc = os.system("lspci -d 1137:a003 2> /dev/null | grep -q '.*'")
    if rc == 0:
        hw_type = 'ASIC3'
        return

    rc = os.system("lspci -d 1137:a004 2> /dev/null | grep -q '.*'")
    if rc == 0:
        hw_type = 'ASIC4'
        return


def is_pacific():
    if 'ASIC' not in os.environ and is_hw_device() and hw_type == 'NONE':
        set_hw_type()

    if hw_type != 'NONE':
        return hw_type == PACIFIC
    return 'ASIC' not in os.environ or os.environ['ASIC'].startswith(PACIFIC)


def is_pacific_A0():
    return is_pacific() and ('ASIC' not in os.environ or os.environ['ASIC'] == 'PACIFIC_A0')


def is_gibraltar():
    if 'ASIC' not in os.environ and is_hw_device() and hw_type == 'NONE':
        set_hw_type()

    return ('ASIC' in os.environ and os.environ['ASIC'].startswith(GIBRALTAR)) or hw_type == GIBRALTAR


def is_asic6():
    if 'ASIC' not in os.environ and is_hw_device() and hw_type == 'NONE':
        set_hw_type()

    return ('ASIC' in os.environ and os.environ['ASIC'].startswith(ASIC6)) or hw_type == ASIC6


def is_asic4():
    if 'ASIC' not in os.environ and is_hw_device() and hw_type == 'NONE':
        set_hw_type()

    return ('ASIC' in os.environ and os.environ['ASIC'].startswith(ASIC4)) or hw_type == ASIC4


def is_asic5():
    if 'ASIC' not in os.environ and is_hw_device() and hw_type == 'NONE':
        set_hw_type()

    return ('ASIC' in os.environ and os.environ['ASIC'].startswith(ASIC5)) or hw_type == ASIC5


def is_asic3():
    if 'ASIC' not in os.environ and is_hw_device() and hw_type == 'NONE':
        set_hw_type()

    return ('ASIC' in os.environ and os.environ['ASIC'].startswith(ASIC3)) or hw_type == ASIC3


def is_hw_pacific():
    return is_hw_device() and is_pacific()


def is_hw_gibraltar():
    return is_hw_device() and is_gibraltar()


def is_hw_asic5():
    return is_hw_device() and is_asic5()


def is_hw_asic6():
    # TODO asic6 not yet supported
    return False


def is_hw_asic3():
    return is_hw_device() and is_asic3()


def is_hw_asic4():
    return is_hw_device() and is_asic4()


def is_hw_kontron_compact_cpu():
    rc = os.system('grep -q "Intel(R) Celeron(R) CPU" /proc/cpuinfo')
    return rc == 0


def is_hw_kontron_basic_cpu():
    rc = os.system('grep -q "Intel(R) Pentium(R) CPU.*D1517" /proc/cpuinfo')
    return rc == 0


def is_run_slow():
    return os.environ.get("RUN_SLOW_TESTS") == "True" or os.environ.get("RUN_SLOW_TESTS") == "1"


def is_skip_slow():
    return os.environ.get("SKIP_SLOW_TESTS") == "True" or os.environ.get("SKIP_SLOW_TESTS") == "1"


def is_valgrind():
    return os.environ.get("IS_VALGRIND") is not None


def is_akpg():
    return (is_asic5() or is_asic6() or is_asic4() or is_asic3())


def is_auto_warm_boot_enabled():
    return os.environ.get("ENABLE_AUTO_WB") == "True" or os.environ.get("ENABLE_AUTO_WB") == "1"


def is_set_leaba_kernel_module_path():
    return os.getenv('LEABA_KERNEL_MODULE_PATH') is not None


def is_matilda(subtype_str = ''):
    if not is_gibraltar():
        return False

    mat_type, _ = get_matilda_model_from_env()
    if len(subtype_str) == 0 or subtype_str == 'any':
        return mat_type not in ['', 'GB']
    # if not one of the predefined types, check if 'subtype_str' is in mat_type
    return mat_type.find(subtype_str) >= 0


def get_matilda_model_from_env():
    mat_str = os.getenv('MATILDA_TEST_MODE_ENV')
    if (mat_str is None) or (mat_str == '') or (mat_str == 'GB'):
        return 'GB', False

    # now check if this is real matilda hw, and seperate the '_hw' postfix from the type string
    ind = mat_str.find('_hw')
    is_real_hardware = ind > 0
    if is_real_hardware:
        mat_str = mat_str[:ind]
    return mat_str, is_real_hardware


def matilda_str_to_int(mat_str, reverse=False):
    options = ['GB', '6.4', '3.2A', '3.2B', '8T_A', '8T_B']
    if reverse:
        return options[mat_str]
    return options.index(mat_str)


def get_device_name():
    if is_pacific():
        return 'pacific'
    if is_gibraltar():
        return 'gibraltar'
    if is_asic5():
        return 'asic5'
    if is_asic6():
        return 'asic6'
    if is_asic4():
        return 'asic4'
    if is_asic3():
        return 'asic3'

    return None


def is_wb_upgrade_rollback_enabled():
    return os.getenv('ENABLE_WB_UPGRADE_ROLLBACK') == "True" or os.getenv('ENABLE_WB_UPGRADE_ROLLBACK') == "1"
