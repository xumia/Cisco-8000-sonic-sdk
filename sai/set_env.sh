if ( $?OPT ) then
    setenv TEMP_OPT $OPT
else
    setenv TEMP_OPT noopt-debug
endif

if ( $?SDK_ROOT ) then
   setenv TEMP_SDK_ROOT $SDK_ROOT
   setenv SDK_OUTPUT_DIR ${SDK_ROOT}/driver/
else
    setenv TEMP_SDK_ROOT `pwd`/..
    unsetenv SDK_OUTPUT_DIR
endif

if ( $?ASIC ) then
   if ( $ASIC == "GIBRALTAR_A0" || $ASIC == "GIBRALTAR_A1" ) then
       setenv TEMP_DEV gibraltar
   else
       setenv TEMP_DEV pacific
   endif
else
    setenv TEMP_DEV pacific
endif

# pacific full_router currently used for GB also
setenv NSIM_SOURCE_PATH ${TEMP_SDK_ROOT}/npl/cisco_router/
setenv LD_LIBRARY_PATH out/${TEMP_DEV}/${TEMP_OPT}/lib:/common/pkgs/gcc/4.9.4/lib64:/common/pkgs/gcc/4.9.4/:${TEMP_SDK_ROOT}/driver/${TEMP_DEV}/out/${TEMP_OPT}/lib
setenv BASE_OUTPUT_DIR ${TEMP_SDK_ROOT}/driver/${TEMP_DEV}/out/${TEMP_OPT}/
setenv PYTHONPATH out/${TEMP_DEV}/${TEMP_OPT}/pylib/:${TEMP_SDK_ROOT}/driver/${TEMP_DEV}/out/${TEMP_OPT}/pylib:`pwd`/test/python/
setenv NSIM_LEABA_DEFINED_FOLDER ${TEMP_SDK_ROOT}/npl/${TEMP_DEV}/leaba_defined/

unsetenv TEMP_OPT
unsetenv TEMP_SDK_ROOT
unsetenv TEMP_DEV
