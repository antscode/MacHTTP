#ifndef __HTTP_RESPONSE__
#define __HTTP_RESPONSE__

#include <string>
#include <map>

using namespace std;

enum HttpResponseErrorCode
{
	ConnectionError,
	ConnectionTimeout,
	SSLError
};

#pragma once
class HttpResponse
{
public:
	HttpResponse();
	void Reset();
	bool Success;
	bool MessageComplete;
	unsigned int StatusCode;
	HttpResponseErrorCode ErrorCode;
	string ErrorMsg;
	string Content;
	map<string, string> Headers;
	string CurrentHeader;
};

#endif