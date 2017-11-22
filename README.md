# MacHTTP
A very basic C++ class for making HTTP requests on 68k classic Macs. Supports both HTTP and HTTPS (TLS 1.2) 
communication via a single set of functions.

MacHTTP is designed to be built with the [Retro68 GCC cross-compiler](https://github.com/autc04/Retro68).

See the MacHttpTest application for an example of usage.

## Building & Installing

MacHTTP requires Retro68 for compilation, and the following libraries:

* [MacTCPHelper](https://github.com/antscode/MacTCPHelper)
* [mbedtls-Mac-68k](https://github.com/antscode/mbedtls-Mac-68k)

First build and install the above libraries, then execute these commands from the top level of the MacHTTP directory:

    cd ..
    mkdir MacHTTP-build
    cd MacHTTP-build
    cmake ../MacHTTP -DCMAKE_TOOLCHAIN_FILE=<<YOUR_PATH_TO_Retro68-build>>/toolchain/m68k-apple-macos/cmake/retro68.toolchain.cmake
    make install

This will build and install the library and headers into the m68k-apple-macos toolchain.

The MacHttpTest application will be in the MacHTTP-build directory.