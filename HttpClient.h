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
#include "http_parser.h"
#endif

class HttpClient
{
public:
	HttpClient();
	HttpClient(std::string baseUri);
	HttpResponse Get(std::string requestUri);

private:
	std::string _baseUri;
	Uri GetUri(std::string requestUri);
	HttpResponse Request(Uri uri, std::string request);
	HttpResponse HttpRequest(Uri uri, std::string request);
	HttpResponse HttpsRequest(Uri uri, std::string request);
	HttpResponse CheckRedirect(HttpResponse response);
	void InitParser(HttpResponse* response, http_parser* parser, http_parser_settings* settings);
};

static int on_header_field_callback(http_parser* parser, const char *at, size_t length);
static int on_header_value_callback(http_parser* parser, const char *at, size_t length);
static int on_body_callback(http_parser* parser, const char *at, size_t length);
static int on_status_callback(http_parser* parser, const char *at, size_t length);
static int on_message_complete_callback(http_parser* parser);