cmake_minimum_required(VERSION 2.8)

# See: https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
SET(CMAKE_CXX_FLAGS "-Ofast")

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

target_link_libraries(MacHTTP mbedtls mbedx509 mbedcrypto MacTCPHelper)

add_application(MacHTTPTest
	MacHTTPTest.cpp
	size.r
	CONSOLE
)

target_link_libraries(MacHTTPTest MacHTTP)

install(TARGETS MacHTTP
    DESTINATION "lib"
)

install(FILES HttpClient.h HttpResponse.h http_parser.h
    DESTINATION "include/machttp"
)