#!/common/pkgs/python/3.6.10/bin/python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# SW repository sanity script. 
#
# Uploads all changes in the current repository to a sanity branch,
# then launches a Jenkins run.
#
# Yair, February 2016

from __future__ import print_function

import argparse
import getpass
import os
import re
import shlex
import sys
from datetime import datetime

if sys.version_info.major == 2:
    import urllib
else:
    import urllib.request

sanity_branch_template = 'sanity/%s_%s'
jenkins_url_template = 'http://jenkins.leaba.local/job/%(os)ssdk-sanity/buildWithParameters?SANITY_NAME=%(name)s&SANITY_BRANCH=%(branch)s&SANITY_URL=%(repo)s&SANITY_TARGET=%(target)s&MAILTO=%(user)s&token=build'

script_file = os.path.realpath(__file__)

script_path = os.path.dirname(script_file)
harness_path = os.path.normpath(os.path.join(script_path, '..', 'harness'))

sys.path += [harness_path]

import runner

def run_and_check_retcode(cmd):
    (retcode, out, err) = runner.run_command(shlex.split(cmd, posix=False))
    if retcode != 0:
        print('Error running command <%s> (ret = %d)' % (cmd, retcode))
        print(err)
        sys.exit(1)
    return out

def get_git_repo(sanity, remote_name):
    cmd = 'git config --get remote.%s.url' % remote_name
    out = run_and_check_retcode(cmd)
    return out.split('\n')[0]

def get_branch_name(sanity_name):
    return sanity_branch_template % (getpass.getuser(), sanity_name)

def git_local_branch_exists(branch):
    cmd = 'git rev-parse --verify %s' % branch
    (retcode, out, err) = runner.run_command(shlex.split(cmd, posix=False))
    return retcode == 0

def git_remote_branch_exists(remote_name, branch):
    cmd = 'git ls-remote --heads %s %s' % (remote_name, branch)
    out = run_and_check_retcode(cmd)
    return re.match('([0-9a-f]{40})[ \t]*refs\/.*', out) is not None

def git_upload(remote_name, branch, allow_untracked=False):
    cmd = 'git status --porcelain'
    out = run_and_check_retcode(cmd)
    local_repo_clean = True
    if out != '':
        lines = out.split('\n')
        staged     = list(filter(lambda x: re.match('^[A-Z]  .*', x), lines))
        not_staged = list(filter(lambda x: re.match('^ [A-Z] .*', x), lines))
        untracked  = list(filter(lambda x: re.match('^\?\? .*', x), lines))
        if not_staged:
            print('The following files are not staged. Either commit them or stash them')
            print('\n'.join(not_staged))
            local_repo_clean = False
        if staged:
            print('The following files are staged for commit. Please commit them')
            print('\n'.join(staged))
            local_repo_clean = False
        if untracked and not allow_untracked:
            print('The following files are not tracked. Either commit them, delete them, or add them to .gitignore')
            print('\n'.join(untracked))
            local_repo_clean = False
    if not local_repo_clean:
        sys.exit(1)

    if git_local_branch_exists(branch):
        cmd = 'git branch -D %s' % branch
        run_and_check_retcode(cmd)

    if git_remote_branch_exists(remote_name, branch):
        cmd = 'git push %s --delete %s' % (remote_name, branch)
        run_and_check_retcode(cmd)

    cmd = 'git push %s HEAD:%s' % (remote_name, branch)
    run_and_check_retcode(cmd)

parser = argparse.ArgumentParser(description='Launch a sanity run for current changes.')
parser.add_argument('-n', '--name', dest='sanity_name', action='store', required=True, help='Run name.')
parser.add_argument('-t', '--target', dest='sanity_target', action='store', required=False, default='sanity', help='Target to run.')
parser.add_argument('-o', '--os', dest='os', action='store', required=False, default='linux', help='Operating system to run on ("windows" or "linux" or, by default, "both").')
parser.add_argument('-U', '--allow-untracked', dest='allow_untracked', action='store_true', required=False, default=False, help='Allow untracked files')
parser.add_argument('--remote-name', dest='remote_name', action='store', default='origin', help='Name of remote repository')

args = parser.parse_args()

if args.os == 'both':
    os_list = [ 'windows', 'linux' ]
elif args.os == 'windows' or args.os == 'linux':
    os_list = [ args.os ]
else:
    print('Unknown operating system: %s', args.os)

source_path = os.path.realpath(os.path.join(script_path, '..'))

cwd = os.getcwd()
os.chdir(source_path)

# Upload changes to branch
sanity_branch = get_branch_name(args.sanity_name)
repo = get_git_repo(args.sanity_name, args.remote_name)

git_upload(args.remote_name, sanity_branch, args.allow_untracked)

print('Uploaded %s to %s (branch %s)' % (source_path, repo, sanity_branch))

# Trigger Jenkins sanity run on the sanity branch
params = { 'user' : getpass.getuser(),
           'branch' : sanity_branch,
           'repo' : repo,
           'name' : args.sanity_name,
           'target' : args.sanity_target }

for a_os in os_list:
    if a_os == 'windows':
        params['os'] = 'win-'
    else:
        params['os'] = ''

    jenkins_url = jenkins_url_template % params

    if sys.version_info.major == 2:
        connection = urllib.urlopen(jenkins_url)
    else:
        connection = urllib.request.urlopen(jenkins_url)

    if not connection:
        print('Failed to connect to Jenkins URL at %s' % jenkins_url)
        sys.exit(1)

    code = connection.getcode()
    if not code in [200, 201]:
        print('Jenkins returned HTTP status code %d.' % code)
        print('Message:')
        print(connection.readlines())

        sys.exit(1)

    print('Sanity launched successfully on %s at %s' % (a_os, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

os.chdir(cwd)

sys.exit(0)

