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
import distutils


def getenv_bool(what, default):
    """
    os.getenv wrapper that handles 0/1/true/false/True/False
    """
    try:
        value = os.getenv(what)
        if value is None or value == "":
            return default
        return distutils.util.strtobool(value)
    except ValueError:
        return default


def getenv_NSIM_RPC_DAEMON(hostname="localhost", port=0):
    """
    NSIM_RPC_DAEMON will cause the server to persist when the client exits.
    """
    enabled = False

    if hostname is None or hostname == "":
        hostname = "localhost"

    NSIM_RPC_DAEMON = os.getenv("NSIM_RPC_DAEMON", "")
    if NSIM_RPC_DAEMON != "":
        err = "NSIM_RPC_DAEMON invalid format. Expecting a boolean value (if host and port are provided via other means) or values '<hostname>:<port>' or '<port>'"
        try:
            enabled = bool(distutils.util.strtobool(NSIM_RPC_DAEMON))
        except ValueError:
            out = NSIM_RPC_DAEMON.split(":")
            if len(out) == 0:
                try:
                    port = int(NSIM_RPC_DAEMON)
                    enabled = True
                except ValueError:
                    raise Exception(err + ": port not an integer")
            elif len(out) == 1:
                try:
                    hostname = "localhost"
                    port = int(out[0])
                    enabled = True
                except ValueError:
                    raise Exception(err + ": port not an integer")
            elif len(out) == 2:
                try:
                    hostname = out[0]
                    port = int(out[1])
                    enabled = True
                except ValueError:
                    raise Exception(err + ": port not an integer")
            else:
                raise Exception(err)

    return (enabled, hostname, port)
