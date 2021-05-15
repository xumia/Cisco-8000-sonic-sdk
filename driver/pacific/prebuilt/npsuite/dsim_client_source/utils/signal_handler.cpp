// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "utils/signal_handler.h"
#include <signal.h>
#include <time.h>
#include <string>
#include <thread>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if defined __linux__
#include <sys/wait.h>
#include <sys/prctl.h>
#include <linux/limits.h>
#endif

#if defined(__APPLE__) && defined(__MACH__)
#include <sys/wait.h>
#include <mach-o/dyld.h>
#endif

#include <fstream> // std::ifstream
#include <string>
#include <sstream>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)

#include <Windows.h>
#include <io.h>
#include <process.h>
#define STDERR_FILENO 2
#define write _write
#define getpid _getpid

static void
sleep(unsigned seconds)
{
    Sleep(seconds * 1000);
}

#define SEM_T HANDLE
#define SEM_FAILED NULL
#define sem_open(nm, flags, mode, init_val) CreateSemaphore(NULL, init_val, 2, NULL)
#define sem_unlink(nm) 0
#define sem_post(sem) !ReleaseSemaphore(sem, 1, NULL)
#define sem_wait(sem) (errno = 0, WaitForSingleObject(sem, INFINITE) != WAIT_OBJECT_0)
#else
#include <unistd.h>
#include <semaphore.h>
#include <fcntl.h> /* For O_* constants */
#define SEM_T sem_t*
#endif

/// How long the signal handler will give other threads to do cleanup before re-raising the signal
#define SIGNAL_HANDLER_SECONDS_BEFORE_RERAISE 7

using namespace npsuite;

/* static member function */
SignalHandler&
SignalHandler::GetInstance()
{
    // initialization guaranteed thread-safe in c++11,
    // Visual Studio 2015 - see "magic statics" on
    // https://docs.microsoft.com/en-us/previous-versions/hh567368(v=vs.140)
    static SignalHandler inst;
    return inst;
}

static volatile SignalHandler::Verbosity verbosity = SignalHandler::Verbosity::DEFAULT;
static volatile sig_atomic_t currentlyHandlingSignal = 0;
static SEM_T waitForMe;
static volatile sig_atomic_t doneRunningCallbacks = 0;
static volatile sig_atomic_t currentlyHandlingSigUser2 = 0;

// This is the function registered with the OS as the signal handler.
// The set of things that it's allowed to do according to the POSIX standard is pretty limited,
// so some of it looks a bit strange.
// For the list of allowed functions, see the signal-safety(7) man page (linux), sigaction(2) man page (MacOS),
// or https://wiki.sei.cmu.edu/confluence/display/c/SIG30-C.+Call+only+asynchronous-safe+functions+within+signal+handlers
// The other three sections regarding signals at https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=87152469
// are also applicable.
static void
TheSignalHandler(int sig)
{
#define WRITE_STD_ERR(msg) write(STDERR_FILENO, msg, sizeof(msg) - 1)

    // If we get another one of this signal, fall back to default behavior
    if (sig != SIGUSR2) {
        signal(sig, SIG_DFL);
    }

    // if we get a different signal while we are already a signal, just re-raise
    if (currentlyHandlingSignal == 0) {
        currentlyHandlingSignal = sig;
        if (sem_post(waitForMe)) {
            if (verbosity >= SignalHandler::Verbosity::ERRORS_ONLY) {
                WRITE_STD_ERR("Signal handler could not post to semaphore to wake up handler thread\n");
            }
            // fall through to re-raise signal
        } else {
            if (verbosity >= SignalHandler::Verbosity::DEFAULT) {
                WRITE_STD_ERR("Caught ");
                if (sig == SIGTERM) {
                    WRITE_STD_ERR("SIGTERM");
                } else if (sig == SIGSEGV) {
                    WRITE_STD_ERR("SIGSEGV");
                } else if (sig == SIGABRT) {
                    WRITE_STD_ERR("SIGABRT");
                } else if (sig == SIGINT) {
                    WRITE_STD_ERR("SIGINT");
                } else if (sig == SIGILL) {
                    WRITE_STD_ERR("SIGILL");
                } else if (sig == SIGFPE) {
                    WRITE_STD_ERR("SIGFPE");
                } else if (sig == SIGUSR2) {
                    WRITE_STD_ERR("SIGUSR2");
                } else {
                    WRITE_STD_ERR("signal");
                }
                if (sig == SIGUSR2) {
                    WRITE_STD_ERR("; dumping transaction information to log.\n");
                } else {
                    WRITE_STD_ERR("; giving other threads a chance to clean up before exiting.\n");
                }
            }
            // unfortunately, nanosleep is not one of the POSIX-approved async-safe functions, so we can only do this
            // in second-resolution.
            time_t t = time(nullptr);
            if (t > 0) {
                time_t targetTime = t + SIGNAL_HANDLER_SECONDS_BEFORE_RERAISE;
                while (!doneRunningCallbacks && (t = time(nullptr)) > 0 && t < targetTime) {
                    sleep(1);
                }
                if (verbosity >= SignalHandler::Verbosity::CHATTY) {
                    if (doneRunningCallbacks) {
                        WRITE_STD_ERR("Signal handler finished running callbacks; proceeding to reraise signal\n");
                    } else {
                        WRITE_STD_ERR(
                            "Signal handler callbacks didn't finish running in time; proceeding to reraise signal anyway\n");
                    }
                }
            } else {
                if (verbosity >= SignalHandler::Verbosity::ERRORS_ONLY) {
                    WRITE_STD_ERR("Error getting time; proceeding to reraise signal\n");
                }
            }
            // fall through to re-raise signal
            if (sig == SIGUSR2) {
                // SIGUSR2 is not fatal for this application, so prepare for another possible loop
                // by resetting these signalling values.
                doneRunningCallbacks = 0;
                currentlyHandlingSignal = 0;
            }
        }
    }

    if (sig != SIGUSR2) {
        if (raise(sig)) {
            if (verbosity >= SignalHandler::Verbosity::ERRORS_ONLY) {
                WRITE_STD_ERR("Signal handler could not re-raise signal\n");
            }
            abort();
        }
    }
}

void
SignalHandler::SetVerbosity(Verbosity v)
{
    verbosity = v;
}

SignalHandler::Verbosity
SignalHandler::GetVerbosity()
{
    return verbosity;
}

SignalHandler::SignalHandler()
{
    // initialize semaphore.  Unfortunately, sem_init is not supported on MacOS,
    // but sem_open is supported on both Mac and Linux
    std::string hopefullyUniqueName = "/npsuite signal sem " + std::to_string(getpid());
    waitForMe = sem_open(hopefullyUniqueName.c_str(), O_CREAT | O_EXCL, 0600, 0);
    if (waitForMe == SEM_FAILED) {
        if (verbosity >= SignalHandler::Verbosity::ERRORS_ONLY)
            perror("SignalHandler sem_open");
        // we could make this a fatal error by calling abort() here, but since the
        // we're only promising best-effort at running the callbacks anyway, it's
        // probably better to just continue without the signal handler.
    } else {
        if (sem_unlink(hopefullyUniqueName.c_str())) {
            if (verbosity >= SignalHandler::Verbosity::ERRORS_ONLY)
                perror("SignalHandler sem_unlink");
        }

// We want to mask all signals from the callback thread, so that it is not the thread
// in which TheSignalHandler is run.  In order to prevent a race condition, the way to
// do that is set the current thread's signal mask (which is inherited by the new thread),
// then reset it after we've created the new thread.  The C++ standard does not specify
// a way to set thread signal masks, so we can only do this on platforms that we know
// use pthreads.
#if defined(__linux__) || defined(__APPLE__)
        sigset_t myMask;
        sigset_t blockAll;
        sigemptyset(&myMask);
        sigfillset(&blockAll);
        pthread_sigmask(SIG_SETMASK, nullptr, &myMask);
        pthread_sigmask(SIG_SETMASK, &blockAll, nullptr);
#endif

        std::thread callbackThread(&SignalHandler::CallbackThreadMain, this);
        callbackThread.detach();

#if defined(__linux__) || defined(__APPLE__)
        // restore signal mask
        pthread_sigmask(SIG_SETMASK, &myMask, nullptr);
#endif

#define INSTALL_HANDLER(sig)                                                                                                       \
    if (signal(sig, TheSignalHandler) == SIG_ERR) {                                                                                \
        if (verbosity >= SignalHandler::Verbosity::ERRORS_ONLY)                                                                    \
            perror("installing signal handler for " #sig);                                                                         \
    }
        // install signal handler
        INSTALL_HANDLER(SIGTERM);
        INSTALL_HANDLER(SIGSEGV);
        INSTALL_HANDLER(SIGABRT);
        INSTALL_HANDLER(SIGINT);
        INSTALL_HANDLER(SIGILL);
        INSTALL_HANDLER(SIGFPE);
        INSTALL_HANDLER(SIGUSR2);
    }
}

SignalHandler::~SignalHandler()
{
    // The singleton has static scope, so this will only be called a process exit.
    // No need to try to clean up anything since, well, the process is going to exit.
}

static SignalHandler::CallbackId_t __CallbackId_counter = 0;

SignalHandler::CallbackId_t
SignalHandler::AddCallback(std::function<void(int)> func)
{
    std::lock_guard<std::mutex> guard(mCallbacksMutex);
    SignalHandler::CallbackId_t id = ++__CallbackId_counter;
    mCallbacks[id] = func;
    return id;
}

void
SignalHandler::RemoveCallback(SignalHandler::CallbackId_t id)
{
    mCallbacks.erase(id);
}

void
SignalHandler::User2HandlerThreadMain()
{
    currentlyHandlingSigUser2 = 1;
    if (verbosity >= SignalHandler::Verbosity::CHATTY) {
        fprintf(stderr, "Running %zu sigusr2 handler callback(s)\n", mCallbacks.size());
    }
    std::lock_guard<std::mutex> guard(mCallbacksMutex);
    // process in reverse order: most recently added callbacks first
    for (auto itr = mCallbacks.rbegin(); itr != mCallbacks.rend(); itr++) {
        (*itr).second(SIGUSR2);
    }
    currentlyHandlingSigUser2 = 0;
}

#if defined(__linux__) || defined(__APPLE__)
static std::vector<std::string>
split(const std::string& str, const char delimiter)
{
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        tokens.push_back(item);
    }

    return tokens;
}

//
// Try to find the given symbol.
//
static std::string
get_symbol_file(std::string sym)
{
    auto NPSUITE_SYMBOLS = getenv("NPSUITE_SYMBOLS");
    if (NPSUITE_SYMBOLS != nullptr) {
        auto symbol_file_name = std::string(NPSUITE_SYMBOLS) + "/" + sym;
        std::ifstream tmp;
        tmp.open(symbol_file_name, std::ios_base::in);
        if (tmp.is_open()) {
            fprintf(stderr, "INFO: Found symbol file: %s\n", symbol_file_name.c_str());
            return symbol_file_name;
        }
    }

    auto NPSUITE_ROOT = getenv("NPSUITE_ROOT");
    if (NPSUITE_ROOT != nullptr) {
        auto symbol_file_name = std::string(NPSUITE_ROOT) + "-symbols/" + sym;
        std::ifstream tmp;
        tmp.open(symbol_file_name, std::ios_base::in);
        if (tmp.is_open()) {
            fprintf(stderr, "INFO: Found symbol file: %s\n", symbol_file_name.c_str());
            return symbol_file_name;
        }
    }

    //
    // Probably too noisy?
    //
    // fprintf(stderr, "INFO: Could not find %s symbol file. Set NPSUITE_SYMBOLS to its path.\n", sym.c_str());
    return "";
}
#endif

//
// Collect the commands neede to invoke a debugger later upon a crash.
//
bool
debugger_get_cmds(std::vector<std::string>& cmds)
{
    const char* prefix = "NSIM: info: cannot enable GDB hooks: ";

#if defined(__linux__) || defined(__APPLE__)
    //
    // Just in case this goes horribly wrong, we can disable it with DISABLE_NSIM_GDB=0
    // The feature is off by default unless built with DEBUG=1
    //
    bool gdb_enabled = false;

#ifdef LEABA_DEBUG
    gdb_enabled = true;
#endif

    auto DISABLE_NSIM_GDB = getenv("DISABLE_NSIM_GDB");
    if (DISABLE_NSIM_GDB != nullptr) {
        if (!strcmp(DISABLE_NSIM_GDB, "true")) {
            gdb_enabled = false;
        } else if (!strcmp(DISABLE_NSIM_GDB, "false")) {
            gdb_enabled = true;
        } else {
            gdb_enabled = !strtol(DISABLE_NSIM_GDB, nullptr, 10);
        }
    }

    if (!gdb_enabled) {
        return true;
    }

    //
    // Small std::string should be ok to avoid malloc (SSO)
    //
    std::string pid(std::to_string(getpid()));

    //
    // Get the real process name
    //
    const size_t max_path = PATH_MAX + 1;
    char program_name[max_path];
    program_name[0] = '\0';

#ifdef __linux__
    int len = readlink("/proc/self/exe", program_name, max_path - 1);
    if (len == -1) {
        fprintf(stderr, "%scannot read /proc/self/exe", prefix);
        return false;
    }

    program_name[len] = '\0';

    //
    // Allow GDB permission to trace us
    //
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

#elif defined __APPLE__
    uint32_t bufsize = max_path;
    int len = _NSGetExecutablePath(program_name, &bufsize);

    if ((size_t)len >= max_path) {
        fprintf(stderr, "%ssymlink too long", prefix);
        return false;
    }
#endif

    //
    // Find GBD in our PATH
    //
    auto path_env = getenv("PATH");
    if (!path_env) {
        fprintf(stderr, "%sPATH not set", prefix);
        return false;
    }

    std::string debugger_name;
    for (auto a_path : split(std::string(path_env), ':')) {
        auto cand_debugger_name = a_path + "/" + "gdb";
        std::ifstream gdb;
        gdb.open(cand_debugger_name, std::ios_base::in);
        if (gdb.is_open()) {
            debugger_name = cand_debugger_name;
            break;
        }
    }

    if (debugger_name.empty()) {
        fprintf(stderr, "%sGDB not found", prefix);
        return false;
    }

    cmds.push_back(debugger_name);

    //
    // Build the command list.
    //
    cmds.push_back("gdb");
    cmds.push_back("--batch");
    cmds.push_back("-n");

    //
    // Add symbols file if we have it?
    //
    auto symbol_file_name = get_symbol_file("libdsim.so.symbol");
    if (!symbol_file_name.empty()) {
        cmds.push_back("-ex");
        cmds.push_back("add-symbol-file " + symbol_file_name);
    }

    //
    // Make sure and add this *after* loading symbols above.
    //
    cmds.push_back("-ex");
    cmds.push_back("thread apply all bt");

    //
    // Add the target name and pid to attach to.
    //
    std::stringstream tmp; // avoid Uninitialised value was created by a stack allocation from std::string(program_name)
    tmp << program_name;
    cmds.push_back(tmp.str());
    cmds.push_back(pid);

    fprintf(stderr, "NSIM: GDB hooks enabled, PID %s\n", pid.c_str());
#endif
    return true;
}

//
// Fork a process and run a debugger within, with the given commands.
//
void
debugger_run(std::vector<std::string>& cmds_in)
{
#if defined(__linux__) || defined(__APPLE__)
    //
    // Try to avoid anything that might allocate memory here.
    //
    static char* cmds_out[20];
    auto cmd_count = 0;
    if (cmds_in.size() >= sizeof(cmds_out) / sizeof(cmds_out[0])) {
        return;
    }

    for (auto& cmd_in : cmds_in) {
        if (cmd_in == "") {
            cmds_out[cmd_count++] = nullptr;
        } else {
            cmds_out[cmd_count++] = (char*)cmd_in.c_str();
        }
    }

    auto child = fork();
    if (!child) {
        //
        // Make sure stdout goes to stderr.
        //
        dup2(STDERR_FILENO, STDOUT_FILENO);

        fprintf(stderr, "Debugger cmd: ");
        for (auto cmd : cmds_out) {
            if (cmd) {
                fprintf(stderr, "%s ", cmd);
            }
        }
        fprintf(stderr, "\n");

        //
        // Spawn GDB and print info on all threads.
        //
        execvp(cmds_out[0], cmds_out + 1);

        //
        // Should never get here.
        //
        assert(false && "GDB failed to exec");
    } else {
        //
        // Wait for GDB to exit
        //
        waitpid(child, nullptr, 0);
    }
#endif
}

void
SignalHandler::CallbackThreadMain()
{
    //
    // Cache the commands we need to launch the debugger later.
    //
    std::vector<std::string> cmd;

    //
    // Not critical if this fails; errors should be already logged witn debugger_get_cmds
    //
    (void)debugger_get_cmds(cmd);

    while (1) {
        while (sem_wait(waitForMe)) {
            if (errno != EINTR) {
                if (verbosity >= SignalHandler::Verbosity::ERRORS_ONLY)
                    perror("SignalHandler CallbackThreadMain sem_wait");
                abort();
            }
        }

        int sig = currentlyHandlingSignal;

        if (sig == SIGUSR2) {
            // We use a dynamically created thread for SIGUSR2 here, because in some circumstances
            // it could take a non-trivial amount of time to dump the current state, and it requires
            // some specific locks that could already be held at the time that the signal is raised.
            if (currentlyHandlingSigUser2 == 0) {
                std::thread callbackThread(&SignalHandler::User2HandlerThreadMain, this);
                callbackThread.detach();
            } else if (verbosity >= SignalHandler::Verbosity::CHATTY) {
                fprintf(stderr, "Not running %zu sigusr2 handler callback(s), currently still running\n", mCallbacks.size());
            }
        } else if (sig != 0) {
            //
            // Run the debugger prior to other callbacks. Probably a good idea?
            //
            if (cmd.size()) {
                if ((sig == SIGSEGV) || (sig == SIGABRT) || (sig == SIGILL) || (sig == SIGFPE)) {
                    fprintf(stderr, "Running debugger\n");
                    debugger_run(cmd);
                }
            }

            if (verbosity >= SignalHandler::Verbosity::CHATTY) {
                fprintf(stderr, "Running %zu signal handler callback(s)\n", mCallbacks.size());
            }
            std::lock_guard<std::mutex> guard(mCallbacksMutex);
            // process in reverse order: most recently added callbacks first
            for (auto itr = mCallbacks.rbegin(); itr != mCallbacks.rend(); itr++) {
                (*itr).second(sig);
            }
        }

        if (verbosity >= SignalHandler::Verbosity::CHATTY) {
            fprintf(stderr, "Done running signal handler callbacks\n");
        }

        doneRunningCallbacks = 1;
    }
}
