###################
# TEST $1 = <test_name>  $2 = <log_dir>
###################

#break test_poll
#break test_assert_brk

# setup the test
call $1()
continue

if (test_status == 0) system touch $2/$1.SUCCESS
quit

