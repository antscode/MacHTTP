cmake_minimum_required(VERSION 3.5)

# See: https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
SET(CMAKE_CXX_FLAGS "-Ofast")

# Set SSL_ENABLED to OFF if you don't require https communication
SET(SSL_ENABLED OFF)

# If debugging is enabled in the mbedtls library, then enable debugging here
# ADD_DEFINITIONS (-DMBEDTLS_DEBUG="ON")

add_library(MacHTTP STATIC
	HttpClient.h
	HttpClient.cpp
	SimpleHttpClient.h
	SimpleHttpClient.cpp
	HttpResponse.h
	HttpResponse.cpp
	Uri.h
	Uri.cpp
	http_parser.h
	http_parser.c
	yuarel.c
	yuarel.h
)

IF(${SSL_ENABLED})
	ADD_DEFINITIONS (-DSSL_ENABLED)
	target_link_libraries(MacHTTP mbedtls mbedx509 mbedcrypto MacTCPHelper)
ELSE()
	target_link_libraries(MacHTTP MacTCPHelper)
ENDIF()

# Some options to make things smaller
set_target_properties(MacHTTP PROPERTIES COMPILE_OPTIONS -ffunction-sections)
set_target_properties(MacHTTP PROPERTIES LINK_FLAGS "-Wl,-gc-sections")

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
