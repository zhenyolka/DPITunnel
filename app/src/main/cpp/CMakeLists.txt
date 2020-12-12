# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DTLS_AMALGAMATION")

add_library( # Sets the name of the library.
        dpi-bypass

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        dns.cpp
        dpi-bypass.cpp
        fileIO.cpp
        hostlist.cpp
        packet.cpp
        socket.cpp
        sni.cpp
        sni_cert_gen.cpp)

add_library( # Sets the name of the library.
        tun2http

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        tun2http/dhcp.c
        tun2http/dns.c
        tun2http/http.c
        tun2http/icmp.c
        tun2http/ip.c
        tun2http/session.c
        tun2http/tcp.c
        tun2http/tls.c
        tun2http/tun2http.c
        tun2http/udp.c
        tun2http/util.c
        )

add_library( # Sets the name of the library.
        tlse

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        tlse/tlse.c
        tlse/curve25519.c
        )

# Add log library
find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)
include_directories(
        dpi-bypass
        "${PROJECT_SOURCE_DIR}/rapidjson/include"
        "${PROJECT_SOURCE_DIR}/tlse"
        "${PROJECT_SOURCE_DIR}/crypto"
        "${PROJECT_SOURCE_DIR}/openssl/include"
)
include_directories(
        tun2http
        "${PROJECT_SOURCE_DIR}/tun2http"
)

target_link_libraries( # Specifies the target library.
        dpi-bypass

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib}
        tlse
        "${PROJECT_SOURCE_DIR}/openssl/${ANDROID_ABI}/lib/libcrypto.a"
        "${PROJECT_SOURCE_DIR}/openssl/${ANDROID_ABI}/lib/libssl.a")

target_link_libraries( # Specifies the target library.
        tun2http

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib})