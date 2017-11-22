#ifndef __HTTP_CLIENT__
#define __HTTP_CLIENT__
#endif

#ifndef __HTTP_RESPONSE_
#include "HttpResponse.h"
#endif

// Disabled strict HTTP parsing to improve performance
#ifndef HTTP_PARSER_STRICT
#define HTTP_PARSER_STRICT 0
#endif

#ifndef http_parser_h
#include "http_parser.h"
#endif

#pragma once
class HttpClient
{
public:
	HttpClient(std::string baseUri);
	HttpResponse Get(std::string requestUri);
	int OnMessageComplete(http_parser* p);
	int OnBody(http_parser* parser, const char *at, size_t length);

private:
	std::string _host;
	bool _https;
	bool _messageComplete;
	HttpResponse _response;
	HttpResponse Request(std::string request);
	HttpResponse HttpRequest(std::string request);
	HttpResponse HttpsRequest(std::string request);
	bool IsHttps(std::string requestUri);
	std::string GetHost(std::string requestUri);
};

static int on_body_callback(http_parser* parser, const char *at, size_t length);
static int on_message_complete_callback(http_parser* parser);