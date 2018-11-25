#ifndef __URI__
#define __URI__

#include <string>

using namespace std;

class Uri
{
public:
	Uri();
	Uri(string uriStr);
	string Scheme;
	string Host;
	string Path;
	string ToString();
	static bool IsAbsolute(string uriStr);
	static string Encode(const string &value);
};

#endif