#include <ctype.h>
#include <string.h>
#include <stdexcept>
#include <algorithm>
#include "Uri.h"

extern "C"
{
	#include "yuarel.h"
}

Uri::Uri()
{ }

Uri::Uri(string uriStr)
{
	struct yuarel url;

	Scheme = "";
	Host = "";
	Path = "";

	memset(&url, 0, sizeof(struct yuarel));
	if (yuarel_parse(&url, (char*)uriStr.c_str()) == -1)
	{
		throw invalid_argument("Invalid uri");
	}

	if (url.scheme != NULL)
		Scheme = string(url.scheme);

	if (url.host != NULL)
		Host = string(url.host);

	if (url.path != NULL)
	{
		Path = string(url.path);

		if (url.query != NULL)
		{
			Path += "?" + string(url.query);
		}

		if (Path.length() == 0 || (Path.length() > 0 && Path.substr(0, 1) != "/"))
		{
			Path = "/" + Path;
		}
	}
}

string Uri::ToString()
{
	return Scheme + "://" + Host + Path;
}

bool Uri::IsAbsolute(string uriStr)
{
	// To lowercase for comparison
	transform(uriStr.begin(), uriStr.end(), uriStr.begin(), ::tolower);

	return uriStr.find("http") == 0;
}