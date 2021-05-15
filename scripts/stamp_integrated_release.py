#!/auto/asic-tools/sw/python/3.6.10/bin/python3
#
# The script reads the CHANGES file of a given branch. SDK source repository is provided through Jenkins configuration.
# It parses version numbers and the CDETS committed in that version.  
# Adds sdk integrated release to all CDETS
# This script can accept optional arguments: 
#   all -  scrub the entire CHANGES file and fix/stamp integrated release of CDETS  committed in every release (only if not stamped already).
#   release - CDETS belong to that specific release will be handled. 
#   latest - recent release will be considered.
#

import re
import os
import sys
import argparse

CHANGE_FILE = './CHANGES'

def stamp_integrated_release_to_cdet(cdet, current_version):
    if not cdet:
       return

    cdet = cdet.strip()
    check_filed = '/usr/cisco/bin/findcr  -i '+cdet +'  -w Integrated-releases'
    fds = os.popen(check_filed).read().strip();

    existing_versions = 'None'
    if fds:
      existing_versions = str(fds)

    print('   '+cdet+' - existing integrated-releases:'+ str(fds))
    if current_version not in fds:
        add_release_cmd = 'sudo /usr/cisco/bin/fixcr -i '+cdet+' Integrated-releases SDK-'+current_version
        print('      *** '+add_release_cmd);
        os.system(add_release_cmd)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Stamp integrated release version to SDK CDETS ')
    parser.add_argument('-release', '--release', required=False,
                        help='options : <version> | latest | all')

    args = parser.parse_args()

    #By default stamp CDETS of the latest release
    version_str = 'latest'

    if args.release:
        input_ver_str = args.release.strip()

        #validate input parameter
        is_input_version_valid = re.search("[0-9]\.[0-9\.]{0,10}", input_ver_str)
        if is_input_version_valid or input_ver_str == 'all' or input_ver_str == 'latest':
            version_str = input_ver_str

    print("\nInput release version: " + version_str)

    current_version = None
    latest_done = False
    requested_version_done = False

    datafile = iter(open(CHANGE_FILE, 'r'))
    for line in datafile:
        version = re.search("\A[0-9]\.[0-9\.]{0,10}", line)

        ln = line.strip().replace("-", "")
        cdet = re.search(r'^CSC(\D{2}\d{5})', ln.strip())

        if version:
            if (version_str == 'latest' and latest_done == True) or requested_version_done == True:
                  break

            if (version_str != 'all' and version_str != 'latest' and version_str != version.group(0)):
                # Input is release specified, skip until requested version is found
                continue

            current_version = version.group(0)

            print('-----------------------------------------------------------------')
            print('Release : '+ current_version)
            print('CDETS: ')

            if version_str == version.group(0):
               requested_version_done = True

            if not latest_done:
                  latest_done = True
    
        elif cdet:
           if current_version:
               stamp_integrated_release_to_cdet(cdet.group(0), current_version)

