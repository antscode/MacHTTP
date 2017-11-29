#include "HttpResponse.h"

HttpResponse::HttpResponse()
{
	Success = false;
	ErrorMsg = "";
	Content = "";
	StatusCode = -1;
	MessageComplete = false;
}