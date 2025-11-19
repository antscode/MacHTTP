
#include "SimpleHttpClient.h"


#include <ctype.h>
#include <string.h>

#include <stdexcept>
#include <stdio.h>

extern "C"
{
	#include <MacTCP.h>
	#include <Threads.h>
	#include <mactcp/CvtAddr.h>
	#include <mactcp/TCPHi.h>
}

void ThreadEntry(void* param);

SimpleHttpClient::SimpleHttpClient()
{
	Init("");
}

SimpleHttpClient::SimpleHttpClient(string baseUri)
{
	Init(baseUri);
}

/* Public functions */
void SimpleHttpClient::SetProxy(string host, int port)
{
	_proxyHost = host;
	_proxyPort = port;
}

void SimpleHttpClient::Get(const string& requestUri, function<void(HttpResponse&)> onComplete)
{
	try
	{
		Uri uri = GetUri(requestUri);

		Get(uri, onComplete);
	}
	catch (const invalid_argument& e)
	{
		HttpResponse response;
		response.ErrorMsg = e.what();
		onComplete(response);
	}
}

void SimpleHttpClient::Get(const Uri& requestUri, function<void(HttpResponse&)> onComplete)
{
	string getRequest =
		"GET " + requestUri.Path + " HTTP/1.1\r\n" +
		"Host: " + requestUri.Host + "\r\n" +
		GetAuthHeader() +
		"User-Agent: MacHTTP\r\n\r\n";

	Request(requestUri, getRequest, onComplete);
}

void SimpleHttpClient::Post(const string& requestUri, const string& content, function<void(HttpResponse&)> onComplete)
{
	try
	{
		Uri uri = GetUri(requestUri);

		Post(uri, content, onComplete);
	}
	catch (const invalid_argument& e)
	{
		HttpResponse response;
		response.ErrorMsg = e.what();
		onComplete(response);
	}
}

void SimpleHttpClient::Post(const Uri& requestUri, const string& content, function<void(HttpResponse&)> onComplete)
{
	string method = "POST";
	PutPost(requestUri, method, content, onComplete);
}

void SimpleHttpClient::Put(const Uri& requestUri, const string& content, function<void(HttpResponse&)> onComplete)
{
	string method = "PUT";
	PutPost(requestUri, method, content, onComplete);
}

void SimpleHttpClient::PutPost(const Uri& requestUri, const string& method, const string& content, function<void(HttpResponse&)> onComplete)
{
	string request =
		method + " " + requestUri.Path + " HTTP/1.1\r\n" +
		"Host: " + requestUri.Host + "\r\n" +
		GetAuthHeader() +
		"User-Agent: MacHTTP\r\n" +
		"Content-Length: " + to_string(content.length()) + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		content;

	Request(requestUri, request, onComplete);
}

void SimpleHttpClient::SetDebugLevel(int debugLevel)
{
	_debugLevel = debugLevel;
}

void SimpleHttpClient::SetStunnel(string host, int port)
{
	_stunnelHost = host;
	_stunnelPort = port;
}

void SimpleHttpClient::SetAuthorization(string authorization)
{
	_authorization = authorization;
}

/* Private functions */
void SimpleHttpClient::Init(string baseUri)
{
	MaxApplZone();

	_baseUri = baseUri;
	_proxyHost = "";
	_stunnelHost = "";
	_authorization = "";
	_proxyPort = 0;
	_stunnelPort = 0;
	_debugLevel = 0;
	_status = Idle;
	InitParser();
}

void SimpleHttpClient::Yield()
{
	YieldToAnyThread();
}

string SimpleHttpClient::GetAuthHeader()
{
	if (_authorization != "")
	{
		return "Authorization: " + _authorization + "\r\n";
	}

	return "";
}

void SimpleHttpClient::Connect(const Uri& uri, unsigned long stream)
{
	HttpResponse response;

	string request =
		"CONNECT " + uri.Host + ":443 HTTP/1.1\r\n" +
		"Host: " + uri.Host + ":443\r\n" +
		"User-Agent: MacHTTP\r\n\r\n";

	SendData(
		stream,
		(Ptr)request.c_str(),
		(unsigned short)strlen(request.c_str()),
		false,
		(GiveTimePtr)Yield,
		&_cancel);
}

Uri SimpleHttpClient::GetUri(const string& requestUri)
{
	if (!Uri::IsAbsolute(requestUri))
	{
		string absUri = _baseUri + requestUri;
		return Uri(absUri);
	}

	return Uri(requestUri);
}

void SimpleHttpClient::CancelRequest()
{
	if (_status != Idle)
	{
		_cancel = true;
	}
}

void SimpleHttpClient::Request(const Uri& uri, const string& request, function<void(HttpResponse&)> onComplete)
{
	_uri = uri;
	_request = request;
	_onComplete = onComplete;
	_cRequest = NULL;
	_cancel = false;
	_response.Reset();
	_status = Waiting;

	// Reset http parser
	memset(&_parser, 0, sizeof(_parser));
	_parser.data = (void*)&_response;
	http_parser_init(&_parser, HTTP_RESPONSE);


	SimpleHttpClient* httpClient = (SimpleHttpClient*)this;

	httpClient->InitThread();
}

void ThreadEntry(void* param)
{
	SimpleHttpClient* httpClient = (SimpleHttpClient*)param;

	httpClient->InitThread();
}

void SimpleHttpClient::InitThread()
{
	_status = Running;

	if (_uri.Scheme == "http" ||
		(_stunnelHost != "" && _uri.Scheme == "https"))
	{
		HttpRequest();
	}
}

SimpleHttpClient::RequestStatus SimpleHttpClient::GetStatus()
{
	return _status;
}

void SimpleHttpClient::ProcessRequests()
{
	YieldToAnyThread();
}

void SimpleHttpClient::HttpRequest()
{
	if (Connect())
		if (Request())
			Response();

	NetClose();
}

void SimpleHttpClient::InitParser()
{
	// Set parser data
	_parser.data = (void*)&_response;

	// Parser settings
	memset(&_settings, 0, sizeof(_settings));
	_settings.on_status = on_status_callback;
	_settings.on_header_field = on_header_field_callback;
	_settings.on_header_value = on_header_value_callback;
	_settings.on_message_complete = on_message_complete_callback;
	_settings.on_body = on_body_callback;
}

bool SimpleHttpClient::DoRedirect()
{
	if (_response.Success && _response.StatusCode == 302 && _response.Headers.count("Location") > 0)
	{
		string location = _response.Headers["Location"];

		if (!Uri::IsAbsolute(location))
		{
			location = _uri.Scheme + "://" + _uri.Host + location;
		}

		// Perform 302 redirect
		Get(location, _onComplete);
		return true;
	}

	return false;
}

string SimpleHttpClient::GetRemoteHost(const Uri& uri)
{
	if (_proxyHost != "")
	{
		return _proxyHost;
	}
	else
	{
		return uri.Host;
	}
}

int SimpleHttpClient::GetRemotePort(const Uri& uri)
{
	if (_proxyPort > 0)
	{
		return _proxyPort;
	}
	else if(uri.Scheme == "https")
	{
		return 443;
	}

	return 80;
}

bool SimpleHttpClient::Connect()
{
	OSErr err;
	unsigned long ipAddress;

	// Open the network driver
	err = InitNetwork();
	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "InitNetwork returned " + to_string(err);
		return false;
	}

	// Get remote IP
	char* hostname = _stunnelHost != "" ? (char*)_stunnelHost.c_str() : (char*)GetRemoteHost(_uri).c_str();
	err = ConvertStringToAddr(hostname, &ipAddress, (GiveTimePtr)Yield);
	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "ConvertStringToAddr returned " + to_string(err) + " for hostname " + string(hostname);
		return false;
	}

	// Open a TCP stream
	err = CreateStream(&_stream, BUF_SIZE, (GiveTimePtr)Yield, &_cancel);
	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "CreateStream returned " + to_string(err);
		return false;
	}

	// Open a connection
	err = OpenConnection(_stream, ipAddress, _stunnelPort > 0 ? _stunnelPort : GetRemotePort(_uri), 0, (GiveTimePtr)Yield, &_cancel);
	if (err == noErr) {
		if (_uri.Scheme == "https" && _proxyHost != "")
		{
			// First issue CONNECT request to open SSl tunnel via proxy
			Connect(_uri, _stream);
		}
	}
	else
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "OpenConnection returned " + to_string(err);
		return false;
	}

	// Connect success, move to next status
	return true;
}

bool SimpleHttpClient::Request()
{
	// Send the request
	OSErr err = SendData(
		_stream,
		(Ptr)_request.c_str(),
		(unsigned short)strlen(_request.c_str()),
		false,
		(GiveTimePtr)Yield,
		&_cancel);

	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "SendData returned " + to_string(err);
		return false;
	}

	// Request complete, move to next status
	return true;
}

bool SimpleHttpClient::Response()
{
	unsigned char buf[BUF_SIZE];
	unsigned short dataLength;
	int ret;

	while (true)
	{
		dataLength = sizeof(buf) - 1;
		memset(buf, 0, sizeof(buf));

		OSErr err = RecvData(
			_stream,
			(Ptr)&buf, &dataLength,
			false,
			(GiveTimePtr)Yield,
			&_cancel);

		ret = http_parser_execute(&_parser, &_settings, (const char*)&buf, dataLength);

		if (_response.MessageComplete || err == connectionClosing)
		{
			// Read response complete
			_response.Success = true;
			break;
		}

		if (ret < 0)
		{
			_response.ErrorCode = ConnectionError;
			_response.ErrorMsg = "http_parser_execute returned " + to_string(ret);
			return false;
		}
	}

	return true;
}

void SimpleHttpClient::NetClose()
{
	CloseConnection(_stream, (GiveTimePtr)Yield, &_cancel);
	ReleaseStream(_stream, (GiveTimePtr)Yield, &_cancel);

	if (!DoRedirect())
	{
		_status = Idle;
		if (!_cancel)
		{
			_onComplete(_response);
		}
		else
		{
			_cancel = false;
		}
	}
}

int SimpleHttpClient::on_body_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->Content.append(at, length);
	return 0;
}

int SimpleHttpClient::on_header_field_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;

	string header = string(at);
	int delim = header.find(":");
	string headerName = header.substr(0, delim);

	response->Headers.insert(pair<string, string>(headerName, ""));
	response->CurrentHeader = headerName;

	return 0;
}

int SimpleHttpClient::on_header_value_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;

	string header = string(at);
	int delim = header.find("\n");
	string headerVal = header.substr(0, delim - 1);

	response->Headers[response->CurrentHeader] = headerVal;

	if (response->CurrentHeader == "Content-Length")
	{
		response->Content.reserve(stoi(headerVal));
	}

	return 0;
}

int SimpleHttpClient::on_message_complete_callback(http_parser* parser)
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->MessageComplete = true;
	return 0;
}

int SimpleHttpClient::on_status_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->StatusCode = parser->status_code;
	return 0;
}
