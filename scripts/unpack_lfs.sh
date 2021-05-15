#!/bin/bash
echo "Uncompressing large prebuilt binary files."
echo ./driver/pacific/prebuilt/build/shared/src/nplapi/swig_wrap.cxx
gzip -d ./driver/pacific/prebuilt/build/shared/src/nplapi/swig_wrap.cxx
echo ./driver/pacific/prebuilt/build/shared/src/nplapi/swig_wrap.o
gzip -d ./driver/pacific/prebuilt/build/shared/src/nplapi/swig_wrap.o
echo ./driver/gibraltar/prebuilt/build/shared/src/nplapi/swig_wrap.cxx
gzip -d ./driver/gibraltar/prebuilt/build/shared/src/nplapi/swig_wrap.cxx
echo ./driver/gibraltar/prebuilt/build/shared/src/nplapi/swig_wrap.o
gzip -d ./driver/gibraltar/prebuilt/build/shared/src/nplapi/swig_wrap.o
