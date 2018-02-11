#ifndef __URI__
#define __URI__
#endif

#include <string>

class Uri
{
public:
	Uri();
	Uri(std::string uriStr);
	std::string Scheme;
	std::string Host;
	std::string Path;
	std::string ToString();
	static bool IsAbsolute(std::string uriStr);
};

