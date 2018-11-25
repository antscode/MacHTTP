#include <ctype.h>
#include <string.h>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
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

string Uri::Encode(const string &value) 
{
	ostringstream escaped;
	escaped.fill('0');
	escaped << hex;

	for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
		string::value_type c = (*i);

		// Keep alphanumeric and other accepted characters intact
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			escaped << c;
			continue;
		}

		// Any other characters are percent-encoded
		escaped << uppercase;
		escaped << '%' << setw(2) << int((unsigned char)c);
		escaped << nouppercase;
	}

	return escaped.str();
}