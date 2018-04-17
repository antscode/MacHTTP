#ifndef __HTTP_CLIENT__
#define __HTTP_CLIENT__

#include "HttpResponse.h"
#include "Uri.h"
#include <functional>

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

#ifdef HTTPS_ENABLED
extern "C"
{
	#include <mbedtls/net_sockets.h>
	#include <mbedtls/debug.h>
	#include <mbedtls/ssl.h>
	#include <mbedtls/entropy.h>
	#include <mbedtls/ctr_drbg.h>
	#include <mbedtls/error.h>
	#include <mbedtls/certs.h>
	#include <mbedtls/ssl_ciphersuites.h>
}
#endif

class HttpClient
{
public:
	enum RequestStatus
	{
		Idle,
		Waiting,
		Running
	};
	
	HttpClient();
	HttpClient(std::string baseUri);
	void Get(std::string requestUri, std::function<void(HttpResponse)> onComplete);
	void Post(std::string requestUri, std::string content, std::function<void(HttpResponse)> onComplete);
	void SetProxy(std::string host, int port);
	void SetCipherSuite(int cipherSuite);
	void SetDebugLevel(int debugLevel);
	void ProcessRequests();
	void CancelRequest();
	RequestStatus GetStatus();
	void InitThread();

private:
	std::string _baseUri;
	std::string _proxyHost;
	Uri _uri;
	std::string _request;
	RequestStatus _status;
	HttpResponse _response;
	std::function<void(HttpResponse)> _onComplete;
	int _proxyPort;
	int _debugLevel;
	bool _cancel;

	void Init(std::string baseUri);
	Uri GetUri(std::string requestUri);
	std::string GetRemoteHost(Uri uri);
	int GetRemotePort(Uri uri);
	void Connect(Uri uri, unsigned long stream);
	void Request(Uri uri, std::string request, std::function<void(HttpResponse)> onComplete);
	bool DoRedirect();
	void InitParser();
	static void Yield();
	void HttpRequest();

	http_parser _parser;
	http_parser_settings _settings;

	unsigned long _stream;
	
	bool Connect();
	bool Request();
	bool Response();
	void NetClose();

	const char* _cRequest;

	#ifdef HTTPS_ENABLED
	mbedtls_net_context _server_fd;
	mbedtls_ssl_context _ssl;
	mbedtls_ssl_config _conf;
	mbedtls_x509_crt _cacert;
	mbedtls_entropy_context _entropy;
	mbedtls_ctr_drbg_context _ctr_drbg;
	
	void HttpsRequest();
	bool SslConnect();
	bool SslHandshake();
	bool SslVerifyCert();
	bool SslRequest();
	bool SslResponse();
	void SslClose();

	int _overrideCipherSuite[2] = { 0, 0 };
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
	#endif // HTTPS_ENABLED
};

static int on_header_field_callback(http_parser* parser, const char *at, size_t length);
static int on_header_value_callback(http_parser* parser, const char *at, size_t length);
static int on_body_callback(http_parser* parser, const char *at, size_t length);
static int on_status_callback(http_parser* parser, const char *at, size_t length);
static int on_message_complete_callback(http_parser* parser);

#ifdef MBEDTLS_DEBUG
static void ssl_debug(void *ctx, int level, const char *file, int line, const char *str);
#endif

#endif