#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import atexit
import os
import sys
import decor
import inspect
import pickle
import shutil
import subprocess
import tarfile
import unittest
import urllib.request
import uuid
import json
import gc
from leaba import hldcli
from leaba import sdk
import warm_boot_test_utils as wb_utils
import packet_test_utils


# info passed between processes through 'WB_VARIABLES' environment variable,
# which happens every time test process is reloaded
if 'WB_VARIABLES' in os.environ:
    wb_variables = eval(os.getenv('WB_VARIABLES'))
else:
    # default values
    wb_variables = {
        'is_replay_mode': False,  # whether test process is executing in replay mode
        'sdk_objs_metadata_file_name': None,  # path to file with created SDK objects' metadata
        'wb_serialization_file_name': None,  # path to file with serialized SDK
        'nsim_state_file_name': None,  # path to file with serialized NSIM state
        'is_first_run': True,  # whether test process is running first time (not reloaded yet with os.execve())
        'wb_pythonpath': None,  # PYTHONPATH of process that will be loaded after WB disconnect call
        'wb_ld_library_path': None,  # LD_LIBRARY_PATH of process that will be loaded after WB disconnect
        'wb_base_output_dir': None,  # BASE_OUTPUT_DIR of process that will be loaded after WB disconnect
        'wb_replay_cwd': None,  # current working directory in WB replay mode
        'wb_upgrade_enabled': False,  # whether WB upgrade is enabled
        'wb_rollback_enabled': False,  # whether WB rollback is enabled
        'wb_base_version_from_tar_location': None,  # location of SDK release extracted from tarball
        'wb_cnt': 0,  # counts WB calls from the tests, incremented in WB disconnect
        'pre_wb': True,  # flag that indicates whether warm_boot_disconnect has not been executed yet
        'post_wb': False,  # flag that indicates whether warm_boot_reconnect has been executed
    }


# path JSON file containing base SDK version location
base_version_filename = os.path.join(os.getenv('BASE_OUTPUT_DIR'), 'res/wb_base_sdk_version.json')

# global pointer to la_device
la_device = None

# debug flag, set to 1 to print more details
DEBUG = 0


def wb_info_print(msg: str):
    print('=== WB:', msg)


def wb_debug_print(msg: str):
    if DEBUG:
        wb_info_print(msg)


def get_base_sdk_version_path(base_version_json):
    """
    Get base SDK location from the WB base SDK version JSON file.

    Args:
        base_version_json: Path to WB base SDK version JSON file

    Returns:
        Path to base SDK version if JSON file contains valid entry for current device;
        None object otherwise.
    """

    wb_info_print('Reading base SDK release location from the file {}'.format(base_version_json))
    with open(base_version_json, 'r') as fd:
        json_dict = json.load(fd)
        device_name = decor.get_device_name()

        if device_name not in json_dict:
            return None

        return json_dict[device_name]


def get_new_path_env_var(env_var_val, path_end, new_base_output_dir) -> str:
    """
    Calculates and returns new value of path environment variables to allow reloading
    process with new SDK version. New environment variables will point to new base output
    dir instead of current one.

    Args:
        env_var_val: Old value of environment variable
        path_end: All paths in env var that end with path_end will be updated
        new_base_output_dir: Path to base output dir

    Returns:
        New value of environment variable, containing paths in new_base_output_dir.
    """

    base_output_dir = os.path.abspath(os.getenv('BASE_OUTPUT_DIR'))
    new_env_var_val = ''
    for path in env_var_val.split(':'):
        abs_path = os.path.abspath(path)
        if abs_path.endswith(path_end) and abs_path.startswith(base_output_dir):
            rel_path = abs_path[len(base_output_dir) + 1:]
            new_path = os.path.join(new_base_output_dir, rel_path)
            new_env_var_val += ':{}'.format(new_path)
        else:
            new_env_var_val += ':{}'.format(abs_path)

    return new_env_var_val


def get_function_caller_src_file_and_lineno(frame):
    """
    Get info about file and line number from which specific function was called.

    Args:
        frame: Function's Frame object

    Returns:
        String in format '<file>:<lineno>'
    """

    found_frame = False
    for frame_info in inspect.stack():
        if found_frame:
            return '{}:{}'.format(frame_info.filename, frame_info.lineno)
        if frame_info.frame == frame:
            found_frame = True
    return None


def extract_base_sdk(base_version_location) -> str:
    """
    Extracts base SDK.

    Args:
        base_version_location: Path to base SDK release

    Returns:
        Path to extraced base SDK release
    """

    if os.path.isdir(base_version_location):
        # base version file contains path to extracted SDK release
        wb_info_print('Base SDK version is at dir {}'.format(base_version_location))
        return base_version_location

    # base version file contains path to tarball that needs to be extracted
    tarball_basename = os.path.basename(base_version_location)
    extracted_base_version_dirname = os.path.basename(base_version_location)[:-len('.tar.gz')]
    extract_location = '/tmp/wb_base_release-{}'.format(uuid.uuid4())
    os.mkdir(extract_location)
    base_version_dir_fullpath = os.path.join(extract_location, extracted_base_version_dirname)

    if base_version_location.startswith(('http://', 'https://')):
        # tarball needs to be downloaded first
        download_destination = os.path.join(extract_location, tarball_basename)
        wb_info_print('Downloading base SDK tarball from {} to {}'.format(base_version_location, download_destination))
        urllib.request.urlretrieve(base_version_location, download_destination)
        base_version_location = download_destination

    # extract tarball
    wb_info_print('Extracting SDK release from {} to {}'.format(base_version_location, base_version_dir_fullpath))
    tarball = tarfile.open(base_version_location)
    tarball.extractall(extract_location)
    tarball.close()

    wb_variables['wb_base_version_from_tar_location'] = extract_location
    base_version_base_output_dir = os.path.join(base_version_dir_fullpath, 'driver')
    return base_version_base_output_dir


def get_base_version_base_output_dir():
    """
    Get base output dir of base SDK version. If SDK is not upgradeable, exception is raised.
    """

    # first check if current SDK version is 'upgradeable';
    # SDK is considered non-upgradeable if base version JSON file does not exist or does not contain
    # valid entry for current device
    if not os.path.exists(base_version_filename):
        raise Exception('SDK is not upgradeable! JSON file {} does not exist'.format(base_version_filename))

    base_version_location = get_base_sdk_version_path(base_version_filename)
    if base_version_location is None or base_version_location == '':
        raise Exception(
            'SDK is not upgradeable! JSON file {} does not have valid entry for {} device'.format(
                base_version_filename, decor.get_device_name()))

    # check if location to extracted SDK is set through env var
    if 'BASE_VERSION_BASE_OUTPUT_DIR' in os.environ:
        return os.getenv('BASE_VERSION_BASE_OUTPUT_DIR')

    # extract base SDK from the location extracted from JSON version file
    base_output_dir = extract_base_sdk(base_version_location)
    return base_output_dir


def set_up_wb_upgrade():
    """
    Function that sets up environment for WB upgrade.
    """

    if not decor.is_wb_upgrade_rollback_enabled():
        wb_info_print('Environment variable ENABLE_WB_UPGRADE_ROLLBACK is not set, skipping set up for WB upgrade')
        return

    # raise an exception if rollback has been already enabled
    if wb_variables['wb_rollback_enabled']:
        raise Exception('WB rollback has already been enabled, cannot enable WB upgrade!')

    if not wb_variables['is_first_run']:
        return

    wb_info_print('Setting up SDK upgrade environment')

    # get base output dir of base SDK version
    base_version_base_output_dir = get_base_version_base_output_dir()

    wb_info_print('Setting new environment variables')
    base_version_pythonpath = get_new_path_env_var(os.getenv('PYTHONPATH'), ('/pylib', '/pylib/'), base_version_base_output_dir)
    base_version_ld_library_path = get_new_path_env_var(
        os.getenv('LD_LIBRARY_PATH'), ('/lib', '/lib/'), base_version_base_output_dir)
    curr_version_pythonpath = os.getenv('PYTHONPATH')
    curr_version_ld_library_path = os.getenv('LD_LIBRARY_PATH')
    curr_version_base_output_dir = os.getenv('BASE_OUTPUT_DIR')

    # set env variables for the process re-run
    base_version_env = os.environ.copy()
    base_version_env['PYTHONPATH'] = base_version_pythonpath
    base_version_env['LD_LIBRARY_PATH'] = base_version_ld_library_path
    base_version_env['BASE_OUTPUT_DIR'] = base_version_base_output_dir

    wb_variables['wb_pythonpath'] = curr_version_pythonpath
    wb_variables['wb_ld_library_path'] = curr_version_ld_library_path
    wb_variables['wb_base_output_dir'] = curr_version_base_output_dir
    wb_variables['wb_replay_cwd'] = os.getcwd()
    wb_variables['is_first_run'] = False
    wb_variables['wb_upgrade_enabled'] = True

    # dictionary with WB info variables is passed to reloaded process through env var
    base_version_env['WB_VARIABLES'] = str(wb_variables)

    # re-run process to load base version SDK
    wb_info_print('Reloading process to load base SDK')
    argv = sys.argv.copy()
    argv[0] = os.path.abspath(argv[0])
    # _sdk.so has lib dir path 'out/opt<opt-level>[-debug]/lib' embedded in 'rpath' which has
    # higher priority then LD_LIBRARY_PATH when searching for dependencies; so adding new SDK's
    # lib path to LD_LIBRARY_PATH may not be enought to load new SDK, that's why also working
    # directory is changed to new SDK
    os.chdir(base_version_base_output_dir)
    os.execve(sys.executable, [sys.executable] + argv, base_version_env)


def set_up_wb_rollback():
    """
    Function that sets up environment for WB rollback.
    """

    if not decor.is_wb_upgrade_rollback_enabled():
        wb_info_print('Environment variable ENABLE_WB_UPGRADE_ROLLBACK is not set, skipping set up for WB rollback')
        return

    # raise an exception if upgrade has been already enabled
    if wb_variables['wb_upgrade_enabled']:
        raise Exception('WB upgrade has already been enabled, cannot enable WB rollback!')

    if not wb_variables['is_first_run']:
        return

    wb_info_print('Setting up SDK rollback environment')

    # get base output dir of base SDK version
    base_version_base_output_dir = get_base_version_base_output_dir()

    wb_info_print('Setting new environment variables')
    base_version_pythonpath = get_new_path_env_var(os.getenv('PYTHONPATH'), ('/pylib', '/pylib/'), base_version_base_output_dir)
    base_version_ld_library_path = get_new_path_env_var(
        os.getenv('LD_LIBRARY_PATH'), ('/lib', '/lib/'), base_version_base_output_dir)

    # set env variables for the process re-run
    wb_variables['wb_pythonpath'] = base_version_pythonpath
    wb_variables['wb_ld_library_path'] = base_version_ld_library_path
    wb_variables['wb_base_output_dir'] = base_version_base_output_dir
    wb_variables['wb_replay_cwd'] = base_version_base_output_dir
    wb_variables['is_first_run'] = False
    wb_variables['wb_rollback_enabled'] = True


CREATOR_METHODS = (
    'create',
)
MUTATOR_METHODS = (
    'acquire',
    'activate',
    'add',
    'adjust',
    'allocate',
    'append',
    'apply',
    'arm',
    'attach',
    'capture',
    'clear',
    'deactivate',
    'deallocate',
    'delete',
    'detach',
    'die_ieee1500_write',
    'disable',
    'disarm',
    'disconnect',
    'dram_buffer_write',
    'enable',
    'erase',
    'flush',
    'initialize',
    'insert',
    'ipv4_route_bulk_updates',
    'ipv6_route_bulk_updates',
    'load',
    'modify',
    'open',
    'pop',
    'push',
    'reconfigure',
    'reconnect',
    'register_read_cb',
    'release',
    'remove',
    'reserve',
    'restore',
    'replace',
    'run',
    'set',
    'start',
    'stop',
    'trigger',
    'tune',
    'tx_refresh',
    'upload',
    'warm_boot_',
    'write',
)


# Helper classes that store metadata about SDK objects created in test. This
# metadata is used to restore SDK objects in replay mode, when new version
# of SDK is loaded.
class SdkObjsMetadata:

    class SdkObjMetadata:

        def __init__(self, function_name, caller_info, metadata):
            self.function_name = function_name
            self.caller_info = caller_info
            self.metadata = metadata

        def get_function_name(self):
            return self.function_name

        def get_caller_info(self):
            return self.caller_info

        def get_metadata(self):
            return self.metadata

    def __init__(self):
        self.next_idx = 0
        self.objs_info = []

    def add_obj_metadata(self, function_name, caller_info, metadata):
        self.objs_info.append(self.SdkObjMetadata(function_name, caller_info, metadata))

    def get_next_obj_info(self):
        obj_info = self.objs_info[self.next_idx]
        self.next_idx += 1
        return obj_info

    def reset_next_idx(self):
        self.next_idx = 0


# load metadata needed for restoring SDK objects in replay mode
#
# create_objects_info:
# This is collection which stores info about each object created in first pass (before WB invocation).
# On every creation of la_object, pair (<create-method-caller-info>, <oid>) is added to collection.
# <create-method-caller-info> represents location from which creator method is called, in format
# '<file-name>:<line-no>'.
# This collection is used in methods for creating la_object objects in replay mode. In replay mode,
# SDK objects are not created again, they are restored from de-serialized SDK based on <oid> read
# from the collection.
#
# device_get_objects_info:
# This is collection which stores info about objects that are returned by la_device.get_objects()
# in first pass (before WB invocation). On every call to get_objects(), pair (<la_objects-caller-info>, <list-of-oid's>)
# is added to collection. <la_objects-caller-info> represents location from which get_objects() is called,
# in format '<file-name>:<line-no>'.
# This collection is used in la_device.get_objects() calls in replay mode. Original la_device.get_objects()
# is not called in replay mode, because it might not return expected objects, as this method would be
# executed on de-serialized SDK. Instead of that, objects are fetched based on list of oid's from the
# collection, and returned as the result of la_device.get_objects()
#
if wb_variables['is_replay_mode']:
    sdk_objs_metadata_filename = wb_variables['sdk_objs_metadata_file_name']
    wb_info_print('Restoring SDK objects\' metadata from file {}'.format(sdk_objs_metadata_filename))
    with open(sdk_objs_metadata_filename, 'rb') as fd:
        (create_objects_info, device_get_objects_info) = pickle.load(fd)
        create_objects_info.reset_next_idx()
        device_get_objects_info.reset_next_idx()
else:
    create_objects_info = SdkObjsMetadata()
    device_get_objects_info = SdkObjsMetadata()


def get_sdk_obj_metadata_file_name() -> str:
    return wb_utils.get_tmp_file_name('.sdk_objs_metadata')


def get_nsim_state_file_name() -> str:
    return wb_utils.get_tmp_file_name('.nsim_state')


def remove_wb_file_from_env(var_name):
    if var_name not in wb_variables:
        return

    file_name = wb_variables[var_name]
    if file_name and os.path.exists(file_name):
        wb_debug_print('Removing tmp file {}'.format(file_name))
        os.remove(file_name)
        wb_variables[var_name] = None


def remove_wb_files_from_env():
    remove_wb_file_from_env('sdk_objs_metadata_file_name')
    remove_wb_file_from_env('wb_serialization_file_name')
    remove_wb_file_from_env('nsim_state_file_name')


def get_base_sdk_version_string():
    """
    Get version string of base SDK by spawning a process that loads base SDK and
    prints value returned by sdk.la_get_version_string().

    Returns:
        Base SDK version string.
    """
    # launch subprocess to query base SDK version string
    cmd = []
    cmd.append(sys.executable)
    cmd.append('-c')
    cmd.append('from leaba import sdk; print(sdk.la_get_version_string())')

    process_env = os.environ.copy()
    process_env['PYTHONPATH'] = wb_variables['wb_pythonpath']
    process_env['LD_LIBRARY_PATH'] = wb_variables['wb_ld_library_path']
    process_env['BASE_OUTPUT_DIR'] = wb_variables['wb_base_output_dir']

    # need to change working directory to workaround 'rpath' in binary files
    cwd = os.getcwd()
    os.chdir('/tmp')
    wb_info_print('Getting base SDK version string')
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=process_env)
    (stdout_data, stderr_data) = process.communicate()
    if process.returncode:
        wb_info_print('Error when trying to get base SDK version string:\n{}'.format(stderr_data.decode().strip()))
        raise Exception('Could not get base SDK version string!')
    os.chdir(cwd)

    return stdout_data.decode().strip()


def is_called_from_functions(functions):
    """
    Checks if current call stack contains any function specified by input argument.

    Args:
        functions: List of functions' names.

    Returns:
        True if call stack contains any function name from the argument.
        False otherwise.
    """
    for frame_info in inspect.stack():
        if frame_info.function in functions:
            return True
    return False


def warm_boot_disconnect(uut_provider):
    """
    Function responsible for disconnecting and serializing SDK (and NSIM state), and then
    reloading test process to load new version of SDK. In replay mode, this function
    restores NSIM state.
    """

    la_dev = uut_provider.device
    is_nsim_device = not decor.is_hw_device()

    if wb_variables['is_replay_mode']:

        if wb_variables['wb_upgrade_enabled']:
            wb_info_print('Upgraded to SDK version \'{}\''.format(sdk.la_get_version_string()))
        elif wb_variables['wb_rollback_enabled']:
            wb_info_print('Rolled back to SDK version \'{}\''.format(sdk.la_get_version_string()))
        else:
            raise Exception('Neither one of upgrade/rollback was selected! Please call set_up_wb_(upgrade|rollback)() '
                            'at the beginning of your test file.')

        # remove tmp files from the environment and disable replay mode
        wb_info_print('Removing tmp files and disabling replay mode')
        remove_wb_files_from_env()
        wb_variables['is_replay_mode'] = False
        wb_variables['pre_wb'] = False
    else:
        wb_variables['wb_cnt'] += 1

        if wb_variables['wb_cnt'] > 1:
            raise Exception('Having more than 1 WB upgrade/rollback calls per test file is not supported!')

        if wb_variables['wb_upgrade_enabled']:
            wb_info_print('Upgrading from SDK version \'{}\''.format(sdk.la_get_version_string()))
        elif wb_variables['wb_rollback_enabled']:
            wb_info_print('Rolling back from SDK version \'{}\''.format(sdk.la_get_version_string()))
        else:
            raise Exception('Neither upgrade/rollback was selected! Please call set_up_wb_(upgrade|rollback)() '
                            'at the beginning of your test file.')

        replay_env_vars = os.environ.copy()

        # disconnect SDK
        wb_info_print('Disconnecting SDK')
        la_dev.flush()
        la_dev.warm_boot_disconnect()

        # serialize SDK
        warm_boot_filename = wb_utils.get_warm_boot_file_name()
        if wb_variables['wb_rollback_enabled']:
            base_sdk_version = get_base_sdk_version_string()
            wb_info_print('Version of base SDK is {}'.format(base_sdk_version))

            wb_info_print('Serializing SDK before rollback')
            try:
                sdk.la_warm_boot_rollback_save_and_destroy(la_dev, base_sdk_version, warm_boot_filename, True)
            except sdk.BaseException:
                warm_boot_reconnect(uut_provider)
                raise
        else:
            wb_info_print('Serializing SDK before upgrade')
            sdk.la_warm_boot_save_and_destroy(la_dev, warm_boot_filename, True)

        wb_variables['wb_serialization_file_name'] = warm_boot_filename

        # save NSIM state if needed
        if is_nsim_device:
            nsim_provider = uut_provider.nsim_provider
            nsim_state_filename = get_nsim_state_file_name()
            wb_info_print('Saving NSIM state to file {}'.format(nsim_state_filename))
            nsim_provider.dump_config_to_file(nsim_state_filename)
            wb_variables['nsim_state_file_name'] = nsim_state_filename

        # save SDK objects' metadata file
        sdk_objs_metadata_filename = get_sdk_obj_metadata_file_name()
        wb_info_print('Saving SDK objects\' metadata to file {}'.format(sdk_objs_metadata_filename))
        with open(sdk_objs_metadata_filename, 'wb') as fd:
            pickle.dump((create_objects_info, device_get_objects_info), fd)
        wb_variables['sdk_objs_metadata_file_name'] = sdk_objs_metadata_filename

        # don't do ASIC restart on replay
        if 'ASIC_RESTART_SCRIPT' in replay_env_vars:
            del replay_env_vars['ASIC_RESTART_SCRIPT']

        # set env vars to load another version of SDK
        wb_replay_cwd = wb_variables['wb_replay_cwd']
        replay_env_vars['PYTHONPATH'] = wb_variables['wb_pythonpath']
        replay_env_vars['LD_LIBRARY_PATH'] = wb_variables['wb_ld_library_path']
        replay_env_vars['BASE_OUTPUT_DIR'] = wb_variables['wb_base_output_dir']

        wb_variables['wb_replay_cwd'] = None
        wb_variables['wb_pythonpath'] = None
        wb_variables['wb_ld_library_path'] = None
        wb_variables['wb_base_output_dir'] = None

        # restart process with replay mode enabled
        wb_info_print('Restarting test\'s process, enabling replay mode')
        wb_variables['is_replay_mode'] = True

        # dictionary with WB info variables is passed to reloaded process through env var
        replay_env_vars['WB_VARIABLES'] = str(wb_variables)

        argv = sys.argv.copy()
        argv[0] = os.path.abspath(argv[0])
        os.chdir(wb_replay_cwd)
        os.execve(sys.executable, [sys.executable] + argv, replay_env_vars)

    uut_provider.warm_boot_disconnected = True


def warm_boot_reconnect(uut_provider):
    """
    Function that reconnects SDK to the device.
    """

    if wb_variables['is_replay_mode']:
        return

    la_dev = uut_provider.device
    wb_info_print('Reconnecting SDK')
    la_dev.warm_boot_reconnect()
    uut_provider.warm_boot_disconnected = False
    wb_variables['post_wb'] = True
    wb_variables['pre_wb'] = False


def warm_boot(uut_provider):
    """
    Top level function for invoking WB.
    """

    warm_boot_disconnect(uut_provider)
    warm_boot_reconnect(uut_provider)


def load_nsim_state(device_path):
    """
    Restores state of NSIM with the given device path.
    """

    if decor.is_hw_device():
        return

    nsim_provider = None
    nsim_state_filename = wb_variables['nsim_state_file_name']

    from uut_provider import nsim_device
    gc.collect()
    for obj in gc.get_objects():
        if isinstance(obj, nsim_device) and obj.device_path == device_path:
            nsim_provider = obj.nsim_provider
            break

    if not nsim_provider:
        raise Exception('Could not find NSIM provider!')

    if not nsim_state_filename:
        raise Exception('Cannot load NSIM state, the state was not saved properly')

    if not os.path.exists(nsim_state_filename):
        raise Exception('Cannot load NSIM state, state file {} does not exist'.format(nsim_state_filename))

    if nsim_state_filename and os.path.exists(nsim_state_filename):
        wb_info_print('Loading NSIM state from file {}'.format(nsim_state_filename))
        nsim_provider.read_config_from_file(nsim_state_filename, update_table_entry_if_exists=True)


def la_object_getattribute(self, name):
    """
    Function that wraps __getattribute__ method of la_object SDK objects. It creates wrappers
    that intercept calls to these objects' creator/mutator methods, enabling us to collect metadata
    needed for restoring state of SDK objects in replay mode, when test procees has loaded new SDK.

    Original methods are wrapped only if 'pre_wb' flag is True. This flag is reset when warm_boot_disconnect()
    in 'replay mode' is finished.
    """

    attr = object.__getattribute__(self, name)

    if wb_variables['pre_wb'] and callable(attr) and not name.startswith('__') and name not in ['type']:

        if name.startswith(CREATOR_METHODS):
            class CreatorMethodWrapper:
                """
                Wrapper for creator methods pre-defined in CREATOR_METHODS.

                On first execution of the test, for each created object, metadata containing
                creator method name, creator method's caller info, oid is added to create_objects_info.

                In replay mode, objects are restored from deserialized SDK based on oid from the metadata,
                if current creator method name and current current creator method's caller info match expected values.
                """

                def __init__(self, la_obj, attr):
                    self.la_obj = la_obj
                    self.attr = attr

                def __call__(self, *args, **kwargs):
                    orig_function_name = '{}.{}'.format(self.la_obj.__class__.__name__, self.attr.__name__)
                    my_caller_info = get_function_caller_src_file_and_lineno(inspect.currentframe())
                    wb_debug_print(
                        'Calling creator method {}(), replay mode = {}'.format(
                            orig_function_name, wb_variables['is_replay_mode']))

                    if wb_variables['is_replay_mode']:
                        obj_creation_info = create_objects_info.get_next_obj_info()
                        expected_function_name = obj_creation_info.get_function_name()
                        expected_caller_info = obj_creation_info.get_caller_info()
                        oid = obj_creation_info.get_metadata()

                        if orig_function_name != expected_function_name or my_caller_info != expected_caller_info:
                            raise Exception('Internal error! SDK objects\' creation order in replay mode does '
                                            'not match first pass')

                        wb_debug_print('Restoring la_object with oid={}'.format(oid))
                        obj = la_device.get_object(oid).downcast()
                        wb_debug_print('Restored la_object {}'.format(obj))
                        return obj
                    else:
                        obj = self.attr(*args, **kwargs)
                        oid = obj.oid()
                        wb_debug_print('Created la_object {} with oid={}'.format(obj, oid))
                        create_objects_info.add_obj_metadata(orig_function_name, my_caller_info, oid)
                        return obj

            return CreatorMethodWrapper(self, attr)

        elif name.startswith(MUTATOR_METHODS):
            class MutatorMethodWrapper:
                """
                Wrapper for mutator methods pre-defined in MUTATOR_METHODS.

                On first execution of the test, mutator method is called.

                In replay mode, mutator method is ignored because it has already
                changed the state of object in the first pass.
                """

                def __init__(self, la_obj, attr):
                    self.la_obj = la_obj
                    self.attr = attr

                def __call__(self, *args, **kwargs):
                    wb_debug_print('Calling mutator method {}.{}(), replay mode = {}'.format(
                        self.la_obj.__class__.__name__, self.attr.__name__, wb_variables['is_replay_mode']))
                    if wb_variables['is_replay_mode']:
                        wb_debug_print('Skipping mutator method execution')
                        return
                    else:
                        wb_debug_print('Executing mutator method')
                        return self.attr(*args, **kwargs)

            return MutatorMethodWrapper(self, attr)

        elif self.type() == sdk.la_object.object_type_e_DEVICE and name == 'get_objects':
            class GetObjectsWrapper:
                """
                Wrapper for la_device.get_objects() method.

                On first execution of the test, method name (la_device.get_objects), method caller info and
                oid's of returned objects are stored to collection device_get_objects_info.

                In replay mode, returned objects are fetched by oid's saved in device_get_objects_info, if
                current method's caller info matches expected value.
                """

                def __init__(self, la_obj, attr):
                    self.la_obj = la_obj
                    self.attr = attr

                def __call__(self, *args, **kwargs):
                    orig_function_name = '{}.{}'.format(self.la_obj.__class__.__name__, self.attr.__name__)
                    my_caller_info = get_function_caller_src_file_and_lineno(inspect.currentframe())
                    wb_debug_print('Calling {}(), replay mode = {}'.format(orig_function_name, wb_variables['is_replay_mode']))

                    if wb_variables['is_replay_mode']:
                        obj_info = device_get_objects_info.get_next_obj_info()
                        expected_function_name = obj_info.get_function_name()
                        expected_caller_info = obj_info.get_caller_info()
                        oids = obj_info.get_metadata()

                        if orig_function_name != expected_function_name or my_caller_info != expected_caller_info:
                            raise Exception('Internal error! Order of calls to la_device.get_objects() in replay mode '
                                            'does not match first pass')

                        wb_debug_print('Restoring la_object objects with oid\'s: {}'.format(oids))
                        objs = [la_device.get_object(oid).downcast() for oid in oids]
                        wb_debug_print('Restored la_object objects: {}'.format(objs))
                        return objs
                    else:
                        objs = self.attr(*args, **kwargs)
                        oids = [obj.oid() for obj in objs]
                        wb_debug_print('Returning la_object objects {} with oid\'s = {}'.format(objs, oids))
                        device_get_objects_info.add_obj_metadata(orig_function_name, my_caller_info, oids)
                        return objs

            return GetObjectsWrapper(self, attr)

        elif self.type() == sdk.la_object.object_type_e_DEVICE and name == 'destroy' and not is_called_from_functions(('tearDown', 'tearDownClass')):
            class DestroyObjWrapper:
                """
                Wrapper for la_device.destroy(la_object). Raises an exception if destroy() is called before
                invoking WB.
                """

                def __init__(self, la_obj, attr):
                    self.la_obj = la_obj
                    self.attr = attr

                def __call__(self, *args, **kwargs):
                    wb_debug_print('Calling {}.{}({})'.format(self.la_obj.__class__.__name__, self.attr.__name__, args))

                    raise Exception(
                        'Explicit destroying of SDK object before invoking WB upgrade/rollback is not supported by test infra! '
                        'Please remove all \'destroy\' calls before WB invocation')

            return DestroyObjWrapper(self, attr)

    return attr


def la_create_device(*args, **kwargs):
    """
    Wrapper for la_create_device function.

    In replay mode, this function deserializes SDK from the file and restores la_device object.
    """

    wb_debug_print('Calling sdk.la_create_device(), replay mode = {}'.format(wb_variables['is_replay_mode']))
    if wb_variables['is_replay_mode']:
        global la_device
        device_path = args[0]

        # load NSIM state if needed
        load_nsim_state(device_path)

        wb_filename = wb_variables['wb_serialization_file_name']
        wb_debug_print('Restoring la_device object from serialization file {}, device_path={}'.format(wb_filename, device_path))
        la_device = sdk.la_warm_boot_restore(device_path, wb_filename)
        wb_debug_print('Restored la_device object {}'.format(la_device))
        return la_device
    else:
        la_dev = orig_la_create_device(*args, **kwargs)
        wb_debug_print('Created la_device object {}'.format(la_dev))
        return la_dev


class FunctionDisableWrapper:
    """
    Wrapper for methods that we want to ignore in replay mode.
    """

    def __init__(self, orig_func):
        self.orig_func = orig_func

    def __call__(self, *args, **kwargs):
        # don't do anything in replay mode
        if wb_variables['is_replay_mode']:
            return
        else:
            return self.orig_func(*args, **kwargs)


# patch '__getattribute__' method of la_object classes
la_object_classes = [t[1] for t in inspect.getmembers(sdk, inspect.isclass) if hasattr(t[1], 'oid')]
la_object_classes += [t[1] for t in inspect.getmembers(hldcli, inspect.isclass) if hasattr(t[1], 'oid')]
for la_object_class in la_object_classes:
    setattr(la_object_class, '__getattribute__', la_object_getattribute)

# patch sdk.la_create_device method
orig_la_create_device = sdk.la_create_device
sdk.la_create_device = la_create_device

# patch 'run_*' methods of packet_test_utils, in order to skip them when in replay mode
for name, function in inspect.getmembers(packet_test_utils, inspect.isfunction):
    if name.startswith('run_'):
        # replace all references to 'run_*' functions from 'packet_test_utils' with wrapper methods
        # references to these functions can exist if they are imported before importing this module, example:
        #    from packet_test_utils import *
        #    import warm_boot_upgrade_rollback_test_utils
        function_refs = wb_utils.get_obj_referrers(function, [id(inspect.currentframe())])
        for ref_info in function_refs:
            wb_utils.update_single_referrer(ref_info.referrer, ref_info.ref_key, FunctionDisableWrapper(function))

        setattr(packet_test_utils, name, FunctionDisableWrapper(function))


# remove tmp WB files and unpacked base SDK release on module unload
@atexit.register
def cleanup():
    remove_wb_files_from_env()
    # do this only if we are unpacking tarball! don't do it if location in version file points to SDK dir!
    base_version_location = wb_variables['wb_base_version_from_tar_location']
    if base_version_location and os.path.exists(base_version_location) and os.path.isdir(base_version_location):
        # spawn detached process to remove dir with extraced base SDK when THIS process is finished;
        # if base SDK is currently loaded in this process, then trying to remove base SDK dir from this
        # process would fail, as some files are still in use

        py_cmd = '''
import os
import psutil
import shutil
import time

num_tries = 0
while psutil.pid_exists({}) and num_tries < 100:
    time.sleep(0.1)
    num_tries += 1
shutil.rmtree(\'{}\')
        '''.format(os.getpid(), base_version_location)

        subprocess.Popen([sys.executable, '-c', py_cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
