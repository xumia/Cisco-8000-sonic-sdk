#!/bin/bash

export AUTO_ASIC_GIT_CMD=/auto/asic-tools/sw/git/2.17.1/bin/git
export LOCAL_COMMON_GIT_CMD=/common/pkgs/git/2.17.1/bin/git
unset GIT_CMD

## Must Set GIT_CMD before anything else
if [ -f "$AUTO_ASIC_GIT_CMD" ]; then
    export GIT_CMD=$AUTO_ASIC_GIT_CMD
elif [ -f "$LOCAL_COMMON_GIT_CMD" ]; then
    export GIT_CMD=$LOCAL_COMMON_GIT_CMD
else
    echo "Error: Supported Git versions not found."
    echo "Supported Git versions:"
    echo " - $AUTO_ASIC_GIT_CMD"
    echo " - $LOCAL_COMMON_GIT_CMD"
    exit 1
fi

export MASTER_BRANCH="master"
export CURRENT_BRANCH=`$GIT_CMD symbolic-ref --short HEAD`
export HAS_STAGED_FILES=`$GIT_CMD diff --cached | wc -l`
export MSG_FILE=.commit_msg.txt
export MAIN_MSG="Empty Commit - Used to re-run Jenkins Tests"
unset SUB_MSG


usage () {
    cat >&2 << EOF
usage: `basename $0` options
       -m<message>    Additional Message for the empty commit
                        Default: $MAIN_MSG
       -b<branch>     Remote branch to push the empty commit to
                        Default: $CURRENT_BRANCH
EOF
}

while getopts "b:m:h" opt; do
    case $opt in
       b ) export CURRENT_BRANCH=${OPTARG}
           ;;
       m ) export SUB_MSG=${OPTARG}
           ;;
       h ) usage
           exit 0
           ;;
       * ) usage
           exit 1
           ;;
    esac
done

if [ "$CURRENT_BRANCH" != "$MASTER_BRANCH" ]; then
    if [ "$HAS_STAGED_FILES" != "0" ]; then
        echo "Error: This workspace has staged files."
        echo "Please remove any staged files, and then run again."

        echo " "
        echo "Staged Files:"
        $GIT_CMD diff --cached --name-only
        echo " "
        echo "Exiting..."
        exit 2
    fi

    if [ -f $MSG_FILE ]; then
        rm -f $MSG_FILE
    fi
    touch $MSG_FILE

    echo $MAIN_MSG > $MSG_FILE
    if [ ! -z "$SUB_MSG" ]; then
        echo " " >> $MSG_FILE
        echo $SUB_MSG >> $MSG_FILE
    fi

    export CMD="$GIT_CMD commit -F $MSG_FILE --allow-empty"
    echo " "
    echo "Running: $CMD"
    echo "    with commit message:"
    echo "------"
    cat $MSG_FILE
    echo "------"
    echo " "
    $CMD

    export CMD="$GIT_CMD push origin $CURRENT_BRANCH"
    echo " "
    echo "Running: $CMD"
    echo " "
    $CMD

    rm $MSG_FILE
else
    echo "ERROR: You are not allowed to use this script with the $MASTER_BRANCH branch."
    echo "Exiting..."
    exit 1
fi
