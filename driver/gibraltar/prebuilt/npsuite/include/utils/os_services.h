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

#ifndef __OS_SERVICES_H__
#define __OS_SERVICES_H__

namespace OSServices
{

typedef void* SharedLibraryHandleT;

/// @file
/// @brief OS service utilities.

/// Load shared library and return a handle on success.
///
/// @param[in]  libname     Library to load.
///
/// @return     Shared library handle on success, NULL otherwise.
SharedLibraryHandleT LoadSharedLibrary(const char* libname);

/// Get function pointer from loaded shared library.
///
/// @param[in]  handle      Handle to shared library, acquired through #LoadSharedLibrary.
/// @param[in]  funcname    Name of function to locate in library.
///
/// @return     Function pointer is symbol is found in library, NULL otherwise.
void* SharedLibraryGetSymbol(SharedLibraryHandleT handle, const char* funcname);

/// Unload shared library.
///
/// @param[in]  handle      Handle to shared library, acquired through #LoadSharedLibrary.
///
/// @retval     true        Library unloaded successfully.
/// @retval     false       Unable to load library.
bool UnloadSharedLibrary(SharedLibraryHandleT handle);
} // namespace OSServices

#endif
