#include <ctype.h>
#include <string.h>

extern "C"
{
	#include <mbedtls/net_sockets.h>
	#include <mbedtls/debug.h>
	#include <mbedtls/ssl.h>
	#include <mbedtls/entropy.h>
	#include <mbedtls/ctr_drbg.h>
	#include <mbedtls/error.h>
	#include <mbedtls/certs.h>
	#include <MacTCP.h>
	#include <mactcp/CvtAddr.h>
	#include <mactcp/TCPHi.h>
}

#include "HttpClient.h"

HttpClient::HttpClient()
{ 
	Init("");
}

HttpClient::HttpClient(std::string baseUri)
{
	Init(baseUri);
}

/* Public functions */
void HttpClient::SetProxy(std::string host, int port)
{
	_proxyHost = host;
	_proxyPort = port;
}

HttpResponse HttpClient::Get(std::string requestUri)
{
	try
	{
		Uri uri = GetUri(requestUri);

		std::string getRequest =
			"GET " + uri.ToString() + " HTTP/1.1\r\n" +
			"Host: " + uri.Host + "\r\n" +
			"User-Agent: MacHTTP\r\n" +
			"Connection: close\r\n\r\n";

		return Request(uri, getRequest);
	}
	catch (const std::invalid_argument& e)
	{
		HttpResponse response;
		response.ErrorMsg = e.what();
		return response;
	}
}

void HttpClient::SetDebugLevel(int debugLevel)
{
	_debugLevel = debugLevel;
}

void HttpClient::SetCipherSuite(int cipherSuite)
{
	_overrideCipherSuite = cipherSuite;
}

/* Private functions */
void HttpClient::Init(std::string baseUri)
{
	_baseUri = baseUri;
	_proxyHost = "";
	_proxyPort = 0;
	_debugLevel = 0;
	_overrideCipherSuite = 0;
}

void HttpClient::Connect(Uri uri, unsigned long stream)
{
	HttpResponse response;

	std::string request =
		"CONNECT " + uri.Host + ":443 HTTP/1.1\r\n" +
		"Host: " + uri.Host + ":443\r\n" +
		"User-Agent: MacHTTP\r\n" +
		"Connection: close\r\n\r\n";

	SendData(stream, (Ptr)request.c_str(), (unsigned short)strlen(request.c_str()), false);
}

Uri HttpClient::GetUri(std::string requestUri)
{
	if (!Uri::IsAbsolute(requestUri))
	{
		requestUri = _baseUri + requestUri;
	}

	return Uri(requestUri);
}

HttpResponse HttpClient::Request(Uri uri, std::string request)
{
	if (uri.Scheme == "https" && _proxyHost == "")
	{
		return HttpsRequest(uri, request);
	}
	else
	{
		return HttpRequest(uri, request);
	}
}

void HttpClient::InitParser(HttpResponse* response, http_parser* parser, http_parser_settings* settings)
{
	// Set parser data
	parser->data = (void*)response;

	// Parser settings
	memset(settings, 0, sizeof(*settings));
	settings->on_status = on_status_callback;
	settings->on_header_field = on_header_field_callback;
	settings->on_header_value = on_header_value_callback;
	settings->on_message_complete = on_message_complete_callback;
	settings->on_body = on_body_callback;

	http_parser_init(parser, HTTP_RESPONSE);
}

HttpResponse HttpClient::CheckRedirect(Uri uri, HttpResponse response)
{
	if (response.StatusCode == 302 && response.Headers.count("Location") > 0)
	{
		std::string location = response.Headers["Location"];

		if (!Uri::IsAbsolute(location))
		{
			location = uri.Scheme + "://" + uri.Host + location;
		}

		// Perform 302 redirect
		return Get(location);
	}

	return response;
}

std::string HttpClient::GetRemoteHost(Uri uri)
{
	if (_proxyHost != "")
	{
		return _proxyHost;
	}
	else
	{
		return uri.Host;
	}
}

int HttpClient::GetRemotePort(Uri uri)
{
	if (_proxyPort > 0)
	{
		return _proxyPort;
	}
	else if(uri.Scheme == "https")
	{
		return 443;
	}

	return 80;
}

HttpResponse HttpClient::HttpRequest(Uri uri, std::string request)
{
	OSErr err;
	unsigned long ipAddress;
	unsigned long stream;
	struct http_parser parser;
	http_parser_settings settings;
	size_t parsed;
	unsigned char buf[8192];
	unsigned short dataLength;
	int ret;
	HttpResponse response;

	// Open the network driver
	err = InitNetwork();
	if (err != noErr)
	{
		response.ErrorMsg = "InitNetwork returned " + std::to_string(err);
		return response;
	}

	// Get remote IP
	err = ConvertStringToAddr((char*)GetRemoteHost(uri).c_str(), &ipAddress);
	if (err != noErr)
	{
		response.ErrorMsg = "ConvertStringToAddr returned " + std::to_string(err);
		return response;
	}

	// Open a TCP stream
	err = CreateStream(&stream, 16384);
	if (err != noErr)
	{
		response.ErrorMsg = "CreateStream returned " + std::to_string(err);
		return response;
	}

	// Open a connection
	err = OpenConnection(stream, ipAddress, GetRemotePort(uri), 20);
	if (err == noErr) {
		if (uri.Scheme == "https" && _proxyHost != "")
		{
			// First issue CONNECT request to open SSl tunnel via proxy
			Connect(uri, stream);
		}

		// Send the request
		err = SendData(stream, (Ptr)request.c_str(), (unsigned short)strlen(request.c_str()), false);
		if (err == noErr)
		{
			// Init http parser
			InitParser(&response, &parser, &settings);

			// Read the response
			do
			{
				dataLength = sizeof(buf) - 1;
				err = RecvData(stream, (Ptr)&buf, &dataLength, false);
				ret = http_parser_execute(&parser, &settings, (const char*)&buf, dataLength);

				if (ret < 0)
				{
					response.ErrorMsg = "http_parser_execute returned " + std::to_string(ret);
					return response;
				}
			} while (!response.MessageComplete);
		}
		else
		{
			response.ErrorMsg = "SendData returned " + std::to_string(err);
			return response;
		}

		CloseConnection(stream);
	}
	else
	{
		response.ErrorMsg = "OpenConnection returned " + std::to_string(err);
		return response;
	}

	ReleaseStream(stream);

	response.Success = true;

	return CheckRedirect(uri, response);
}

HttpResponse HttpClient::HttpsRequest(Uri uri, std::string request)
{
	int ret, len;
	mbedtls_net_context server_fd;
	uint32_t flags;
	unsigned char buf[8192];
	const char *pers = "HttpClient";
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	struct http_parser parser;
	http_parser_settings settings;
	size_t parsed;
	HttpResponse response;

#ifdef MBEDTLS_DEBUG
	mbedtls_debug_set_threshold(_debugLevel);
#endif

	/* Initialize the RNG and the session data */
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		response.ErrorMsg = "mbedtls_ctr_drbg_seed returned " + std::to_string(ret);
		return response;
	}

	/* Initialize certificates */
	/* ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_test_cas_pem,
		mbedtls_test_cas_pem_len);
	if (ret < 0)
	{
		response.ErrorMsg = "mbedtls_x509_crt_parse returned " + std::to_string(ret);
		return response;
	} */

	/* Start the connection */
	
	// mbedtls_net_connect modifies the remote host (strips subdomain), so we work off a copy
	std::string remoteHost = GetRemoteHost(uri).c_str();

	if ((ret = mbedtls_net_connect(&server_fd, remoteHost.c_str(), std::to_string(GetRemotePort(uri)).c_str(), MBEDTLS_NET_PROTO_TCP)) != 0)
	{
		response.ErrorMsg = "mbedtls_net_connect returned " + std::to_string(ret);
		return response;
	}

	/* Setup stuff */
	if ((ret = mbedtls_ssl_config_defaults(&conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		response.ErrorMsg = "mbedtls_ssl_config_defaults returned " + std::to_string(ret);
		return response;
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); // BAD BAD BAD! No remote certificate verification (requires root cert)
	//mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

#ifdef MBEDTLS_DEBUG
	mbedtls_ssl_conf_dbg(&conf, ssl_debug, stdout);
#endif

	if (_overrideCipherSuite > 0)
	{
		int cipherSuites[] =
		{
			_overrideCipherSuite,
			0
		};

		mbedtls_ssl_conf_ciphersuites(&conf, cipherSuites);
	}
	else
	{
		// Use default cipher suites
		mbedtls_ssl_conf_ciphersuites(&conf, _cipherSuites);
	}

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
	{
		response.ErrorMsg = "mbedtls_ssl_setup returned " + std::to_string(ret);
		return response;
	}

	// Work off a copy
	std::string hostname = uri.Host.c_str();
	if ((ret = mbedtls_ssl_set_hostname(&ssl, hostname.c_str())) != 0)
	{
		response.ErrorMsg = "mbedtls_ssl_set_hostname returned " + std::to_string(ret);
		return response;
	} 

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	/* Handshake */
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			response.ErrorMsg = "mbedtls_ssl_handshake returned " + std::to_string(ret);
			return response;
		}
	}

	/* Verify the server certificate */
	/* if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
	{
	    char vrfy_buf[512];
	    // mbedtls_printf( " failed\n" );

	    mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
	    // mbedtls_printf( "%s\n", vrfy_buf );
		return -1;
	} */

	/* Write the GET request */
	const char* req = request.c_str();
	while ((ret = mbedtls_ssl_write(&ssl, (const unsigned char*)req, strlen(req))) <= 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			response.ErrorMsg = "mbedtls_ssl_write returned " + std::to_string(ret);
			return response;
		}
	}

	len = ret;
	
	// Init http parser
	InitParser(&response, &parser, &settings);

	/* Read the HTTP response */
	do
	{
		len = sizeof(buf) - 1;
		memset(buf, 0, sizeof(buf));
		ret = mbedtls_ssl_read(&ssl, buf, len);
		ret = http_parser_execute(&parser, &settings, (const char*)buf, ret);

		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
		{
			break;
		}

		if (ret < 0)
		{
			response.ErrorMsg = "http_parser_execute returned " + std::to_string(ret);
			return response;
		}
	}
	while(!response.MessageComplete);

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_net_free(&server_fd);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	response.Success = true;

	return CheckRedirect(uri, response);
}

static int on_body_callback(http_parser* parser, const char *at, size_t length) 
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->Content += std::string(at);
	return 0;
}

static int on_header_field_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;

	std::string header = std::string(at);
	int delim = header.find(":");
	std::string headerName = header.substr(0, delim);

	response->Headers.insert(std::pair<std::string, std::string>(headerName, ""));
	response->CurrentHeader = headerName;

	return 0;
}

static int on_header_value_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;

	std::string header = std::string(at);
	int delim = header.find("\n");
	std::string headerVal = header.substr(0, delim - 1);

	response->Headers[response->CurrentHeader] = headerVal;

	return 0;
}

static int on_message_complete_callback(http_parser* parser) 
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->MessageComplete = true;
	return 0;
}

static int on_status_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->StatusCode = parser->status_code;
	return 0;
}

#ifdef MBEDTLS_DEBUG
static void ssl_debug(void *ctx, int level,
	const char *file, int line,
	const char *str)
{
	((void)level);

	FILE *fp;
	fp = fopen("Mac Volume:log.txt", "a");

	if (fp)
	{
		fprintf(fp, "%s:%04d: %s", file, line, str);
		fflush(fp);
	}

	fclose(fp);
}
#endif