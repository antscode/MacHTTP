#ifndef __HTTP_RESPONSE__
#define __HTTP_RESPONSE__
#endif

#include <string>
#include <map>

enum HttpResponseErrorCode
{
	ConnectionError,
	SSLError
};

#pragma once
class HttpResponse
{
public:
	HttpResponse();
	bool Success;
	bool MessageComplete;
	unsigned int StatusCode;
	HttpResponseErrorCode ErrorCode;
	std::string ErrorMsg;
	std::string Content;
	std::map<std::string, std::string> Headers;
	std::string CurrentHeader;
};
