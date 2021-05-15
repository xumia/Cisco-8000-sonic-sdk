#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# Sai debug shell (sds) utility.
# This is the client side of the sai debug shell utility.

import socket
import sys
import threading
import select

HOST = '127.0.0.1'
PORT = 12345

clientTerminate = False


def remoteConnect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    return s


def printCommandResponse(s):
    s.setblocking(0)
    while True:
        response = ''
        if clientTerminate:
            break
        ready = select.select([s], [], [], 2)
        if ready[0]:
            response = s.recv(500).decode()
            if response == '>>> ':
                print(">>>", end='')
            else:
                print(response, end='')
            sys.stdout.flush()


def sendCommand(s, cmd):
    s.send(cmd.encode())


if __name__ == '__main__':
    banner = """
    Before using Debug Shell, ensure following
        1. Set environment variable SAI_DEBUG_PYTHON_SO_PATH=<absolute path of python shared object>
             Example: export SAI_DEBUG_PYTHON_SO_PATH=/usr/lib/x86_64-linux-gnu/libpython3.7m.so
        2. Invoke set on sai attribute SAI_SWITCH_ATTR_SWITCH_SHELL_ENABLE to enable  interactive
           debugging of driver process that uses leaba sdk/sai library.
        3. If debug mode of the process should be turned on by default, then set
           environment variable SAI_SHELL_ENABLE=1 and then start driver process.
        4. Once debug client connects to leaba switch driver process, the shell prints out
           list of sai device object handles, one for each of the device instance
           that the driver process created.
        5. For debugging/programming purposes, object of switches created by driver process
           can be retrieved in 2 ways
            5.1 Inorder to get sdk python object use following call in the debug shell.
                la_device = sdk.la_get_device(0)
                la_device = sdk.la_get_device(1)
                :
            5.2 Retrieve sai-object of a switch instance using following assignemn inside the shell.
                sai_device_0 = globals()['saidev_00']
                sai_device_1 = globals()['saidev_01']
                :
        6. Example command to debug gtest cases when started from inside sdk/sai directory (cd sdk/sai):
           env SAI_SHELL_ENABLE=1 SAI_DEBUG_PYTHON_SO_PATH=<Path To libpython3.7m.so>
               LD_LIBRARY_PATH=<Path to npsuite/lib>:<out/gb_or_pacific/opt3/lib>
               :<../driver/gb_or_pacific/out/noopt-debug/lib>:$LD_LIBRARY_PATH
               PYTHONPATH=out/gb_or_pacific/noopt-debug/pylib:out/noopt-debug/pylib/
               :../driver/gb_or_pacific/out/noopt-debug/pylib:out/pacific/format/test/python
               gdb --args ./out/gb_or_pacific/noopt-debug/bin/app_gtest --gtest_filter='SimFloodTest.P2PTest*'
    """

    print(banner)
    input("Press Enter to continue if all above conditions are satisfied.....")

    s = remoteConnect()

    sendCommand(s, "")
    print(">>>", end='')
    sys.stdout.flush()

    # start command display thread
    t = threading.Thread(target=printCommandResponse, args=(s,))
    t.start()

    while True:
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            break
        if not line:
            break
        sendCommand(s, line)
        if line == "exit()\n" or line == "quit()\n":
            break

    clientTerminate = True
    s.close()
