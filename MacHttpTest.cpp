#include <stdio.h>
#include <string.h>
#include "HttpClient.h"

void DoRequest(std::string title, std::string protocol, std::string path);

int main()
{
	DoRequest("1 of 6: Small http request", "http", "/status/418");
	DoRequest("2 of 6: Big http request", "http", "/html");
	DoRequest("3 of 6: 302 redirect", "http", "/redirect-to?url=/status/418");
	DoRequest("4 of 6: Small https request", "https", "/status/418");
	DoRequest("5 of 6: Big https request", "https", "/html");
	DoRequest("6 of 6: 302 redirect (https)", "https", "/redirect-to?url=/status/418");

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

	HttpClient httpClient(host);
	HttpResponse response = httpClient.Get(path);

	printf("%s says:\n\n", absoluteUri.c_str());

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
}