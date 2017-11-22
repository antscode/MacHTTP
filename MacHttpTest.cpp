#include <stdio.h>
#include <string.h>
#include "HttpClient.h"

void DoRequest(std::string title, std::string protocol, std::string path);

int main()
{
	DoRequest("1 of 4: Small http request", "http", "/status/418");
	DoRequest("2 of 4: Big http request", "http", "/html");
	DoRequest("3 of 4: Small https request", "https", "/status/418");
	DoRequest("4 of 4: Big https request", "https", "/html");

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

	if (response.Success)
	{
		printf("%s\n\n", response.Content.c_str());
	}
	else
	{
		printf("ERROR: %s\n\n", response.ErrorMsg.c_str());
	}
}