#ifndef __HTTP_CLIENT__
#define __HTTP_CLIENT__
#endif

#ifndef __HTTP_RESPONSE_
#include "HttpResponse.h"
#endif

#ifndef __URI_
#include "Uri.h"
#endif

// Disabled strict HTTP parsing to improve performance
#ifndef HTTP_PARSER_STRICT
#define HTTP_PARSER_STRICT 0
#endif

#ifndef http_parser_h
extern "C"
{
	#include "http_parser.h"
}
#endif

#include <mbedtls/ssl_ciphersuites.h>

class HttpClient
{
public:
	HttpClient();
	HttpClient(std::string baseUri);
	HttpResponse Get(std::string requestUri);
	void SetProxy(std::string host, int port);
	void SetCipherSuite(int cipherSuite);
	void SetDebugLevel(int debugLevel);

private:
	std::string _baseUri;
	std::string _proxyHost;
	int _proxyPort;
	int _debugLevel;
	void Init(std::string baseUri);
	Uri GetUri(std::string requestUri);
	std::string GetRemoteHost(Uri uri);
	int GetRemotePort(Uri uri);
	void Connect(Uri uri, unsigned long stream);
	HttpResponse Request(Uri uri, std::string request);
	HttpResponse HttpRequest(Uri uri, std::string request);
	HttpResponse HttpsRequest(Uri uri, std::string request);
	HttpResponse CheckRedirect(Uri uri, HttpResponse response);
	void InitParser(HttpResponse* response, http_parser* parser, http_parser_settings* settings);
	int _overrideCipherSuite;
	int _cipherSuites[14] =
	{
		MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
		MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
		MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
		MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		0
	};
};

static int on_header_field_callback(http_parser* parser, const char *at, size_t length);
static int on_header_value_callback(http_parser* parser, const char *at, size_t length);
static int on_body_callback(http_parser* parser, const char *at, size_t length);
static int on_status_callback(http_parser* parser, const char *at, size_t length);
static int on_message_complete_callback(http_parser* parser);

#ifdef MBEDTLS_DEBUG
static void ssl_debug(void *ctx, int level, const char *file, int line, const char *str);
#endif