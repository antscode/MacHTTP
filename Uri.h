#ifndef __URI__
#define __URI__
#endif

#include <string>

class Uri
{
public:
	Uri(std::string uriStr);
	std::string Scheme;
	std::string Host;
	std::string Path;
};

