#include <stdio.h>
#include <string.h>
#include <vector>
#include <mbedtls/ssl_ciphersuites.h>
#include "HttpClient.h"

using namespace std;

#define arraylen(arr) ((int) (sizeof (arr) / sizeof (arr)[0]))

string _requests[4][3] = 
{
	{ "Small http request", "http://httpbin.org/status/418", "false" },
	{ "Big http request", "http://httpbin.org/html", "false" },
	{ "302 redirect", "http://httpbin.org/redirect-to?url=/status/418", "false" },
	{ "Image", "http://www.pvsm.ru/images/2018/09/30/umelec-sozdal-WiFi-modul-dlya-Macintosh-SE-30-modeli-1989-goda-2.jpg", "true" }
};

bool _doRequest = true;
int _curRequest = 0;
HttpClient _httpClient;

void DoRequest(string& title, string& url);
void OnResponse(HttpResponse& response);

int main()
{
	#ifdef SSL_ENABLED
	// Set the lowest cipher suite that the server accepts to maximise performance
	_httpClient.SetCipherSuite(MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA);
	#endif

	while (_curRequest < arraylen(_requests))
	{
		if (_doRequest)
		{
			DoRequest(_requests[_curRequest][0], _requests[_curRequest][1]);
		}

		_httpClient.ProcessRequests();
	}

	printf("All done!\n");
	getchar(); getchar();
	return 0;
}

void WriteImage(string& msg)
{
	FILE *fp;
	fp = fopen("Mac HD (68K):mac.jpg", "wb");

	if (fp)
	{
		vector<char> v(msg.begin(), msg.end());
		char* ca = &v[0];
		fwrite(ca, 1, msg.size(), fp);
		fclose(fp);
	}
}

void DoRequest(string& title, string& url)
{
	printf("%s (press return)...\n", title.c_str());
	fflush(stdout);
	getchar(); getchar();

	printf("%s says:\n\n", url.c_str());

	_httpClient.Get(url, OnResponse);
	_doRequest = false;
}

void OnResponse(HttpResponse& response)
{
	printf("Status: %d\n\n", response.StatusCode);

	if (response.Success)
	{
		printf("Headers:\n\n");

		for (map<string, string>::iterator it = response.Headers.begin(); it != response.Headers.end(); ++it)
		{
			printf("%s: %s\n", it->first.c_str(), it->second.c_str());
		}

		if (_requests[_curRequest][2] == "true")
		{
			printf("\n\n(Image downloaded)\n\n");
			WriteImage(response.Content);
		}
		else
		{
			printf("\n\nContent:\n\n");

			printf("%s\n\n", response.Content.c_str());
		}
	}
	else
	{
		printf("ERROR: %s\n\n", response.ErrorMsg.c_str());
	}

	_curRequest++;
	_doRequest = true;
}