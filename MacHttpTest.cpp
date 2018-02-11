#include <stdio.h>
#include <string.h>
#include <mbedtls/ssl_ciphersuites.h>
#include "HttpClient.h"

#define arraylen(arr) ((int) (sizeof (arr) / sizeof (arr)[0]))

std::string _requests[6][3] = 
{
	{ "Small http request", "http", "/status/418" },
	{ "Big http request", "http", "/html" },
	{ "302 redirect", "http", "/redirect-to?url=/status/418" },
	{ "Small https request", "https", "/status/418" },
	{ "Big https request", "https", "/html" },
	{ "302 redirect (https)", "https", "/redirect-to?url=/status/418" }
};

bool _doRequest = true;
int _curRequest = 0;
HttpClient _httpClient;

void DoRequest(std::string title, std::string protocol, std::string path);
void OnResponse(HttpResponse response);

int main()
{
	// Set the lowest cipher suite that the server accepts to maximise performance
	//_httpClient.SetCipherSuite(MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA);

	while (_curRequest < arraylen(_requests))
	{
		if (_doRequest)
		{
			DoRequest(_requests[_curRequest][0], _requests[_curRequest][1], _requests[_curRequest][2]);
		}

		_httpClient.ProcessRequests();
	}

	printf("All done!\n");
	getchar(); getchar();
	return 0;
}

void DoRequest(std::string title, std::string protocol, std::string path)
{
	std::string host = protocol + "://httpbin.org";
	std::string absoluteUri = host + path;

	printf("%s (press return)...\n", title.c_str());
	fflush(stdout);
	getchar(); getchar();

	printf("%s says:\n\n", absoluteUri.c_str());

	_httpClient.Get(absoluteUri, OnResponse);
	_doRequest = false;
}

void OnResponse(HttpResponse response)
{
	printf("Status: %d\n\n", response.StatusCode);

	if (response.Success)
	{
		printf("Headers:\n\n");

		for (std::map<std::string, std::string>::iterator it = response.Headers.begin(); it != response.Headers.end(); ++it)
		{
			printf("%s: %s\n", it->first.c_str(), it->second.c_str());
		}

		printf("\n\nContent:\n\n");

		printf("%s\n\n", response.Content.c_str());
	}
	else
	{
		printf("ERROR: %s\n\n", response.ErrorMsg.c_str());
	}

	_curRequest++;
	_doRequest = true;
}