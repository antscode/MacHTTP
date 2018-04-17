#include "HttpResponse.h"

HttpResponse::HttpResponse()
{
	Reset();
}

void HttpResponse::Reset()
{
	Success = false;
	ErrorMsg = "";
	Content = "";
	StatusCode = -1;
	MessageComplete = false;
	Headers.clear();
	CurrentHeader = "";
}