#ifndef __HTTP_RESPONSE__
#define __HTTP_RESPONSE__
#endif

#include <string>

#pragma once
class HttpResponse
{
public:
	HttpResponse();
	bool Success;
	std::string ErrorMsg;
	std::string Content;
};

