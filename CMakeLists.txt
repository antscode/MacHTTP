cmake_minimum_required(VERSION 2.8)

# See: https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
SET(CMAKE_CXX_FLAGS "-Ofast")

# Set HTTPS_ENABLED to OFF if you don't require https communication
SET(HTTPS_ENABLED ON)

# If debugging is enabled in the mbedtls library, then enable debugging here
# ADD_DEFINITIONS (-DMBEDTLS_DEBUG="ON")

add_library(MacHTTP STATIC
	HttpClient.h
	HttpClient.cpp
	HttpResponse.h
	HttpResponse.cpp
	Uri.h
	Uri.cpp
	http_parser.h
	http_parser.c
	yuarel.c
	yuarel.h
)

IF(${HTTPS_ENABLED})
	ADD_DEFINITIONS (-DHTTPS_ENABLED)
	target_link_libraries(MacHTTP mbedtls mbedx509 mbedcrypto MacTCPHelper)
ELSE()
	target_link_libraries(MacHTTP MacTCPHelper)
ENDIF()

add_application(MacHTTPTest
	MacHttpTest.cpp
	size.r
	CONSOLE
)

target_link_libraries(MacHTTPTest MacHTTP)

install(TARGETS MacHTTP
    DESTINATION "lib"
)

install(FILES HttpClient.h HttpResponse.h Uri.h http_parser.h
    DESTINATION "include/machttp"
)
