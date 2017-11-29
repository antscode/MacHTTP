#include <ctype.h>
#include <string.h>
#include <stdexcept>
#include <algorithm>
#include "Uri.h"
#include "yuarel.h"

Uri::Uri(std::string uriStr)
{
	struct yuarel url;

	Scheme = "";
	Host = "";
	Path = "";

	memset(&url, 0, sizeof(struct yuarel));
	if (yuarel_parse(&url, (char*)uriStr.c_str()) == -1)
	{
		throw std::invalid_argument("Invalid uri");
	}

	if (url.scheme != NULL)
		Scheme = std::string(url.scheme);

	if (url.host != NULL)
		Host = std::string(url.host);

	if (url.path != NULL)
	{
		Path = std::string(url.path);

		if (url.query != NULL)
		{
			Path += "?" + std::string(url.query);
		}

		if (Path.length() > 0 && Path.substr(0, 1) != "/")
		{
			Path = "/" + Path;
		}
	}
}

bool Uri::IsAbsolute(std::string uriStr)
{
	// To lowercase for comparison
	std::transform(uriStr.begin(), uriStr.end(), uriStr.begin(), ::tolower);

	return uriStr.find("http") == 0;
}