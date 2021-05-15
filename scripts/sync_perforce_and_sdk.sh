#!/bin/bash
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

##############################################################################################
# Login to perforce server, create local perforce working set and create a SDK
# branch and apply perforce commit(s) to it
#
# Single perforce commit:
#    - Get the change id (commit) and the message from perforce repository
#    - Create SDK branch with name p4_lbr_gb_<commit-id>. Example:p4_lbr_gb_710701
#    - Get LBR files from diffs and copy them over to SDK repo 
#    - Commit the changes with commit message. Example commit message:
#        710701 - fix the ftre offset fot 1.15
#
# More than one perforce commits:
#    - Get all change ids and messages from perforce repository
#    - Create SDK branch with name p4_lbr_gb-<first-commit-id>-<last-commit-id>.
#        Example:  p4_lbr_gb_710701-718130
#    - Get the LBR files of diffs of all commits and copy them over to SDK repo
#    - Commit everything in ONE commit with the commit messages. 
#        Example commit message:
#           710701 - fix the ftre offset fot 1.15
#           712893 - itemize field
#           718130 - Mathilda support
##############################################################################################

# Global variables
p4='/auto/asic-tools/bin/p4'
perforce_username=''
perforce_port=''
sdk_device=''
perforce_commit_id=''
base_commit_file=''
sdk_device_lbr_dir=''
perforce_stream=''
email_id=''
job_url=''
branch_name_prefix='perforce-lbr'
workspace_dir='/tmp/perforce'
tmp_commit_list="${workspace_dir}/commit_id_list.txt"
tmp_commit_msg="${workspace_dir}/commit_msg.txt"

function usage
{
    echo "Usage: $0 [-u <perforce userid>] [-p <perforce port>]
          [-c <perforce commit id>]
          [-f <perforce base commit id in file>]
          [-d <sdk device name>] [-l <Path to SDK device folder>]
          [-r <Path to perforce LBR repo>]
          [-b <branch name prefix>]
          [-e <email ids (from,to) for notification>]
          [-j <Jenkins job url>]" 1>&2;
    echo "Example: $0 -u <userid> -p 'ssl:asic-p4-cae01:1666' -d gibraltar
                   -l 'devices/gibraltar/lbr.pd_ver_2.0'
                   -r '/asic/cagbb/gibraltar/trunk/design'
                   -c 708949
                   -b 'perforce_lbr_gb'"
}

while getopts ":u:p:c:f:d:j:l:r:b:e:h" o;
   do
      case "${o}" in
          c)
               perforce_commit_id=${OPTARG}
               ;;
          f)
               base_commit_file=${OPTARG}
               ;;
          u)
               perforce_username=${OPTARG}
               ;;
          p)
               perforce_port=${OPTARG}
               ;;
          d)
               sdk_device=${OPTARG}
               ;;
          l)
               sdk_device_lbr_dir=${OPTARG}
               ;;
          r)
               perforce_stream="/${OPTARG}/..."
               ;;
          b)
               branch_name=${OPTARG}
               ;;
          e)
               email_id=${OPTARG}
               ;;
          j)
               job_url=${OPTARG}
               ;;
          *)
               usage
               exit 1
               ;;
      esac
   done

function validate_args
{
    valid=true
    if [ -z $perforce_username ]; then
        echo "*** Missing perforce username"
        valid=false
    fi

    if [ -z $perforce_port ]; then
        echo "*** Missing perforce port"
        valid=false
    fi

    if [ -z $sdk_device ]; then
        echo "*** Missing SDK device name"
        valid=false
    fi

    if [ -z $sdk_device_lbr_dir ]; then
        echo "*** Missing Path to SDK device folder"
        valid=false
    fi

    if [ -z $perforce_commit_id ] && [ -z $base_commit_file ]; then
        echo "*** Missing commit id or base commit id file"
        valid=false
    fi

    if [ -z $perforce_stream ]; then
       echo "*** Missing path to perforce repo"
       valid=false
    fi

    if [ "$valid" = false ]; then
       usage
       exit 1
    fi

    if [ -z $branch_name ]; then
         #Use default prefix with device name
         branch_name_prefix="$branch_name_prefix-$sdk_device"
    else
         branch_name_prefix=${branch_name}
    fi
}

function perforce_login
{
    echo "Perforce login"
    $p4 trust -y
    if [ ! -z $perforce_password ]; then
       echo $perforce_password | $p4 login
    else
       $p4 login
    fi
}

function perforce_logout
{
    echo "Perforce logout"
    $p4 logout
}

function perforce_create_client
{
    echo "Creating perforce client:$P4CLIENT"
    $p4 -d ${device_lbr_dir} client $P4CLIENT
}

function perforce_delete_client
{
    #unlock the client
    $p4 client -o | sed -e "s/locked/unlocked/g" | $p4 client -i

    #Delete the client
    echo "Deleteing perforce client:$P4CLIENT"
    $p4 client -d $P4CLIENT
}

function perforce_sync_workspace 
{
    echo "Sync perforce LBRs to local workspace"
    sync_output=$($p4 sync ${perforce_stream}.lbr 2>&1)
}
function perforce_get_base_commit
{
   if [ ! -z $base_commit_file ]; then
       base_commit_id=$(cat $base_commit_file)
       if [ ! -z $base_commit_id ]; then
          echo $base_commit_id
       fi
   fi
}

function perforce_get_commit_ids
{
   ids=''
   if [ ! -z $perforce_commit_id ]; then
        echo "$perforce_commit_id|$ids" > $tmp_commit_list
   else
      base_commit=$(perforce_get_base_commit)
      echo "Recent perforce commits:"
      changelist="$($p4 changes -m20 @${P4CLIENT} | cut -d" " -f2,4 2>&1)"
      echo "$changelist" | { while IFS= read -r commit;
          do echo $commit;
             IFS=' ' read -r -a array <<< "$commit";
             len="${#array[@]}";
             changelist_id="${array[len-2]}";

             if [ $changelist_id -gt $base_commit ]; then
                  ids="${changelist_id}|$ids"
             fi
 
          done;
          echo "$ids" > $tmp_commit_list
      }
   fi
}

function send_email_notification
{
    if [ -z $email_id ]; then
        exit 0
    fi

    commit_info=$(git log --name-status HEAD^..HEAD)

    SUBJECT="SDK repository commit: [perforce][${sdk_branch_name}]"

    IFS=',' read -r -a email_ids <<< "$email_id";
    SENDER="${email_ids[0]}"
    RECEIVER="${email_ids[1]}"

    recent_unmerged_commits="$(git branch -r --no-merged origin/master | grep ${branch_name_prefix})"
    unmerged_branches="Recent unmerged commits:\n$recent_unmerged_commits"
    TEXT="$commit_info\n\nlogs:$job_url\n\n$unmerged_branches"
    MAIL_TXT="Subject: $SUBJECT\nFrom: $SENDER\nTo: $RECEIVER\n\n$TEXT"
    echo -e $MAIL_TXT | /usr/sbin/sendmail -t
    echo "Email notitication has been sent"
    exit 0
}

function prepare_workspace
{
   device_lbr_dir=${workspace_dir}/${sdk_device}
   mkdir  $workspace_dir
   mkdir ${device_lbr_dir}
   echo "perforce workspace $workspace_dir"
}

function perforce_workspace_cleanup
{
   echo "Removing workspace $workspace_dir"
   rm -rf $workspace_dir
}

validate_args

export P4USER=$perforce_username
export P4PORT=$perforce_port
export P4CLIENT='perforce-lbr-'${sdk_device}
export P4EDITOR=true

perforce_login

prepare_workspace

perforce_create_client

perforce_sync_workspace

perforce_get_commit_ids

commit_ids=$(cat $tmp_commit_list)
IFS='|' read -r -a commits_arr <<< "$commit_ids";
len="${#commits_arr[@]}";
if [ $len -gt 0 ] && [ ! -z $commits_arr[0] ]; then
    branch_suffix="${commits_arr[0]}"
    if [ $len -gt 1 ] && [ ! -z ${commits_arr[$len-1]} ] ; then
        branch_suffix=${branch_suffix}-${commits_arr[$len-1]}
    fi
else
    echo "*** No new commits found"

    perforce_delete_client

    perforce_logout

    perforce_workspace_cleanup

    exit 1
fi

sdk_branch_name="${branch_name_prefix}-${branch_suffix}"

echo "*** Creating git branch: $sdk_branch_name"

git checkout -b $sdk_branch_name

# Copy modified LBRs of a commit into git branch and collect
# commit messages of all perforce commits
last_commit=''
for cid in "${commits_arr[@]}"
   do
       files="$($p4 -ztag describe $cid | grep depotFile | cut -d" " -f3)"
 
       echo "$files" | while IFS= read -r line ;
              do 
                   echo $line; IFS='/' read -r -a array <<< "$line"
                   len="${#array[@]}"
                   if [ $len > 3 ]; then
                      file_lbr_dir=${array[len-3]}/${array[len-2]}
                      file_lbr_file=${array[len-1]}
                      #Find and replace LBRs
                      find "$sdk_device_lbr_dir" -name "$file_lbr_file" -exec cp "${device_lbr_dir}/$line" {} \;
                   fi
              done
                
       commit_message="${cid} - $($p4 -ztag describe $cid  | grep "desc" | cut -c 10-)"
       echo "$commit_message" >> $tmp_commit_msg 
       last_commit=${cid}
   done

# Commit LBRs to git branch
echo "*** Perforce commits being committed to SDK:"
cat "$tmp_commit_msg"

git status -uno

git branch

git add "$sdk_device_lbr_dir"

git commit -F "$tmp_commit_msg"

# Create environment variale for branch name by writing into a file
# to be used by Jenkins job to push the branch to remote repo
if [ ! -z $job_url ]; then
    echo sdk_branch_name=${sdk_branch_name} > propsfile
else
    echo "Push branch"
    git push origin $sdk_branch_name
fi

# Cache the last known commit id in a file which will
# be used while polling, by periodic job for next commit
if [ ! -z $last_commit ]; then
    if [ ! -z $base_commit_file ]; then
        echo $last_commit > ${base_commit_file} || echo "Failed to update base commit id in ${base_commit_file}"
    fi
fi

perforce_delete_client

perforce_logout

perforce_workspace_cleanup

send_email_notification
