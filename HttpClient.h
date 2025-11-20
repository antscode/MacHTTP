#ifndef __HTTP_CLIENT__
#define __HTTP_CLIENT__

#include "HttpResponse.h"
#include "Uri.h"
#include <functional>

#include "SimpleHttpClient.h"

using namespace std;

// Disabled strict HTTP parsing to improve performance
#ifndef HTTP_PARSER_STRICT
#define HTTP_PARSER_STRICT 0
#endif

#ifdef SSL_ENABLED
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

class HttpClient : public SimpleHttpClient
{
public:
	HttpClient();
	HttpClient(string baseUri);
	void SetCipherSuite(int cipherSuite);
	void ProcessRequests();
	void InitThread() override;

private:
	static const int BUF_SIZE = 8192;
	std::function<void(HttpResponse&)> _onComplete;

	void Init(string baseUri) override;
	int GetRemotePort(const Uri& uri) override;
	void Connect(const Uri& uri, unsigned long stream) override;
	void Request(const Uri& uri, const string& request, function<void(HttpResponse&)> onComplete) override;
	static void Yield();

	bool Connect() override;
	bool Request() override;
	bool Response() override;
	void NetClose() override;

	#ifdef SSL_ENABLED
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
	#endif // SSL_ENABLED
};

#ifdef MBEDTLS_DEBUG
static void ssl_debug(void *ctx, int level, const char *file, int line, const char *str);
#endif

#endif