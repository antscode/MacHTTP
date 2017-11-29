#ifndef __HTTP_RESPONSE__
#define __HTTP_RESPONSE__
#endif

#include <string>
#include <map>

#pragma once
class HttpResponse
{
public:
	HttpResponse();
	bool Success;
	bool MessageComplete;
	unsigned int StatusCode;
	std::string ErrorMsg;
	std::string Content;
	std::map<std::string, std::string> Headers;
	std::string CurrentHeader;
};
