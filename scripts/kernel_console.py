#!/auto/asic-tools/sw/python/3.6.10/bin/python3

"""
Python expect script used to automate connecting to kernel console via telnet

Connects to console server (IP), then clears the applicable line.
Disconnects and connects to <IP>:<port>.
Enters interactive mode and send keepalives every <N> seconds to
avoid disconnection while idly printing kernel output to stdout in the background.

Reroute stdout of this script to a file to create a log.

Example:
kernel_console.py 10.10.10.10 2001 root fakepassword

Python Module Example:
from kernel_console import KernelConsole
...
logger = KernelConsole("10.10.10.10", 2001, "root", "fakepassword")
logger.run("./logfile.txt")
...
logger.terminate()
"""

import pexpect
import argparse
import sys
import time
import signal
from threading import Thread, Event, Lock


class KernelConsole:
    ## Private class data
    __basic_prompts = ["^.*lab.*>$", "^.*lab.*> $", "^.*lab.*#$", "^.*lab.*# $",
                       "^.*con.*>$", "^.*con.*> $", "^.*con.*#$", "^.*con.*# $",
                       "(?i)router>$", "(?i)router> $", "(?i)router#$", "(?i)router# $",
                       "^.*localhost.*#$", "^.*localhost.*# $"]

    ## Private class methods
    def __init__(self, console_ip, port, board_ip, user, psw):
        self.ip = console_ip
        self.port = int(port)
        self.board_verification_ip = str(board_ip)
        self.user = user
        self.psw = psw
        self.__telconn = None
        self.__term_event = Event()
        self.__log_fd = sys.stdout
        self.__thread = None
        self.__lock = Lock()
        signal.signal(signal.SIGINT, self.__terminate_sighandler)
        signal.signal(signal.SIGTERM, self.__terminate_sighandler)


    def __close_telconn(self):
        with self.__lock:
            if self.__telconn:
                self.__telconn.close()
                self.__telconn = None


    # Write to logfile if provided, otherwise write to stdout
    def __logmsg(self, msg):
        self.__log_fd.write(msg)
        self.__log_fd.flush()


    # Detect various login prompt scenarios and provide the needed credentials. Retries on error.
    # Continues once a non-login prompt is seen
    def __login(self):
        login_prompts = ["(?i)localhost login:", "(?i)password:", "(?i)login incorrect", pexpect.TIMEOUT]
        extended = False
        attempts = 5
        while True:
            # 15m timeout to allow for device to boot. Gives up after 5 failed logins to
            # avoid getting stuck
            idx = self.__telconn.expect(login_prompts, 1200)
            if idx == 0:
                # Username prompt
                time.sleep(1)
                self.__telconn.sendline(self.user)
            elif idx == 1:
                # Password prompt
                time.sleep(1)
                self.__telconn.sendline(self.psw)
            elif idx == 2:
                # Login incorrect (retry)
                time.sleep(1)
                attempts -= 1
                if not attempts:
                    self.__logmsg("\nMax retries hit. Login failed.\n")
                    self.__close_telconn()
                    sys.exit(1)
            elif idx == 3:
                self.__logmsg("Error: login timeout exceeded! Giving up.\n")
                sys.exit(1)
            else:
                # Non-login prompt (login success. end loop)
                self.__telconn.sendline('')
                break

            # Only look for non-login prompts after first login prompt
            if not extended:
                login_prompts.extend(self.__basic_prompts)
                extended = True


    # Checks for various non-login prompts and sends the command, if specified. Otherwise,
    # behaves exactly like a regular expect call with variable regex patterns
    def __prompt(self, cmd=None):
        prompts = [pexpect.TIMEOUT]
        prompts.extend(self.__basic_prompts)
        idx = self.__telconn.expect(prompts, 300)
        if idx == 0:
            self.__logmsg("Error: prompt timeout exceeded! Giving up.\n")
            sys.exit(1)

        if cmd:
            self.__telconn.sendline(cmd)

    # Just like __prompt(), except checks if __term_event was set while waiting for a prompt
    # as this could indicate device was shutdown, leading to timeout in expect. Do not print error
    # in this case as we have successfully completed the run on HW.
    def __run_prompt(self, cmd=None):
        prompts = [pexpect.TIMEOUT, pexpect.EOF]
        prompts.extend(self.__basic_prompts)
        idx = self.__telconn.expect(prompts, 300)
        if idx == 0:
            if not self.__term_event.is_set():
                self.__logmsg("Error: Prompt timeout exceeded while running! Device unresponsive? Giving up.\n")
                self.__term_event.clear()
                self.__close_telconn()
                sys.exit(1)
        # EOF idx intentionally not handled. Indicates terminate() was called and exit will
        # occur once function returns

        if cmd:
            self.__telconn.sendline(cmd)

    # Checks for a telnet prompt and sends the specified command (required)
    def __telnet_prompt(self, cmd):
        self.__telconn.expect("telnet>")
        self.__telconn.sendline(cmd)

    # Handles SIGINT/SIGTERM by calling standard terminate API
    def __terminate_sighandler(self, sig, frame):
        self.terminate()


    ## Public class methods

    # Connects to console server and clears telnet line associated with kernel console
    def clear_line(self):
        line = self.port - 2000

        self.__logmsg("Clearing device's console before connecting\n")
        # Connect to console server
        self.__telconn = pexpect.spawn(f"telnet {self.ip}", logfile=self.__log_fd.buffer)
        self.__login()
        self.__prompt("enable")
        self.__login()

        # Clear line for desired port
        self.__prompt(f"clear line {line}")
        self.__telconn.expect(r"\[confirm\]")
        self.__telconn.sendline("\n")

        # Disconnect from console server
        self.__close_telconn()


    # Connects to specified telnet IP/port associated with kernel console. Best practice is to
    # always call clear_console_line first
    def connect(self, clear=False):
        if clear:
            self.clear_line()
        # Connect to desired device console
        self.__logmsg(f"\nConnecting to {self.user}@{self.ip}:{self.port}\n")
        self.__telconn = pexpect.spawn(f"telnet {self.ip} {self.port} -l {self.user}", logfile=self.__log_fd.buffer)
        self.__telconn.expect("Escape character is ")
        time.sleep(1)
        self.__telconn.sendline("\n")

        # Login to device
        self.__login()

        # Verify console is connected to desired board
        self.__prompt("ifconfig")
        idx = self.__telconn.expect([self.board_verification_ip, pexpect.TIMEOUT])
        if idx == 1:
            self.__logmsg(f"\nERROR: Target board IP '{self.board_verification_ip}' was not found in output of ifconfig!\n")
            self.__logmsg("Console IP/port may be incorrect. Please verify device information.\n")
            sys.exit(1)

        # Infinite loop that must be disabled by calling terminate()
        while not self.__term_event.is_set():
            # Send 'date' command every 5m to keep connection alive and to show timestamps
                if not self.__term_event.wait(300):
                    # Only occurs on timeout (term_event not set)
                    self.__telconn.sendline("date")
                    self.__run_prompt()

        # Reset Termination Event
        self.__term_event.clear()

        # Disconnect from console server
        self.__close_telconn()


    # Runs kernel console logger as a thread
    def run(self, logfile=None):
        # Optionally log to file instead of stdout
        if logfile:
            self.__log_fd = open(logfile, 'w')

        # Start background thread
        self.__thread = Thread(target=self.connect, args=(True,))
        self.__thread.start()


    # Breaks connect() out of while loop, ending logging thread
    def terminate(self):
        # Send event to logging thread to tell it to stop
        self.__term_event.set()

        # Terminate telnet to break thread out of expect(). Thread will close descriptor
        with self.__lock:
            if self.__telconn:
                self.__telconn.terminate()

        if self.__thread:
            self.__thread.join()
            self.__thread = None

        if self.__log_fd != sys.stdout:
            self.__log_fd.close()
            self.__log_fd = sys.stdout


## MAIN
if __name__ == "__main__":
    # Process arguments
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('console_ip', help="Console's IP address")
    parser.add_argument('port', help="Console's port", type=int)
    parser.add_argument('board_verification_ip', help="IP address used to verify console is correct")
    parser.add_argument('user', help="Login username")
    parser.add_argument('psw', help="Login password")
    args = parser.parse_args()

    console_logger = KernelConsole(args.console_ip, args.port, args.board_verification_ip, args.user, args.psw)

    # Clear console line
    console_logger.clear_line()

    # Connect to console (blocking)
    console_logger.connect()
