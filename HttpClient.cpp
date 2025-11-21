#include "HttpClient.h"

#include <ctype.h>
#include <string.h>

#include <stdexcept>
#include <stdio.h>

extern "C"
{
	#include <MacTCP.h>
	#include <mactcp/CvtAddr.h>
	#include <mactcp/TCPHi.h>
}

HttpClient::HttpClient()
{
	Init("");
}

HttpClient::HttpClient(string baseUri)
{
	Init(baseUri);
}

/* Public functions */
void HttpClient::SetProxy(string host, int port)
{
	_proxyHost = host;
	_proxyPort = port;
}

void HttpClient::Get(const string& requestUri, function<void(HttpResponse&)> onComplete)
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

void HttpClient::Get(const Uri& requestUri, function<void(HttpResponse&)> onComplete)
{
	string getRequest =
		"GET " + requestUri.Path + " HTTP/1.1\r\n" +
		"Host: " + requestUri.Host + "\r\n" +
		GetAuthHeader() +
		"User-Agent: MacHTTP\r\n\r\n";

	Request(requestUri, getRequest, onComplete);
}

void HttpClient::Post(const string& requestUri, const string& content, function<void(HttpResponse&)> onComplete)
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

void HttpClient::Post(const Uri& requestUri, const string& content, function<void(HttpResponse&)> onComplete)
{
	string method = "POST";
	PutPost(requestUri, method, content, onComplete);
}

void HttpClient::Put(const Uri& requestUri, const string& content, function<void(HttpResponse&)> onComplete)
{
	string method = "PUT";
	PutPost(requestUri, method, content, onComplete);
}

void HttpClient::ExecuteOnWaiting() {
	if (!g_onWaiting)
		g_onWaiting = []{};

	g_onWaiting();
}

void HttpClient::PutPost(const Uri& requestUri, const string& method, const string& content, function<void(HttpResponse&)> onComplete)
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

void HttpClient::SetDebugLevel(int debugLevel)
{
	_debugLevel = debugLevel;
}

void HttpClient::SetStunnel(string host, int port)
{
	_stunnelHost = host;
	_stunnelPort = port;
}

void HttpClient::SetAuthorization(string authorization)
{
	_authorization = authorization;
}

void HttpClient::SetGlobalOnWaiting(std::function<void()> onWaiting) {
	g_onWaiting = onWaiting;
}

/* Private functions */
void HttpClient::Init(string baseUri)
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

string HttpClient::GetAuthHeader()
{
	if (_authorization != "")
	{
		return "Authorization: " + _authorization + "\r\n";
	}

	return "";
}

void HttpClient::Connect(const Uri& uri, unsigned long stream)
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
		(GiveTimePtr)ExecuteOnWaiting,
		&_cancel);
}

Uri HttpClient::GetUri(const string& requestUri)
{
	if (!Uri::IsAbsolute(requestUri))
	{
		string absUri = _baseUri + requestUri;
		return Uri(absUri);
	}

	return Uri(requestUri);
}

void HttpClient::CancelRequest()
{
	if (_status != Idle)
	{
		_cancel = true;
	}
}

void HttpClient::Request(const Uri& uri, const string& request, function<void(HttpResponse&)> onComplete)
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

	this->InitThread();
}

void HttpClient::InitThread()
{
	_status = Running;

	if (_uri.Scheme == "http" ||
		(_stunnelHost != "" && _uri.Scheme == "https"))
	{
		HttpRequest();
	}
}

HttpClient::RequestStatus HttpClient::GetStatus()
{
	return _status;
}

void HttpClient::HttpRequest()
{
	if (Connect())
		if (Request())
			Response();

	NetClose();
}

void HttpClient::InitParser()
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

bool HttpClient::DoRedirect()
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

string HttpClient::GetRemoteHost(const Uri& uri)
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

int HttpClient::GetRemotePort(const Uri& uri)
{
	if (_proxyPort > 0)
	{
		return _proxyPort;
	}

	return 80;
}

bool HttpClient::Connect()
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
	err = ConvertStringToAddr(hostname, &ipAddress, (GiveTimePtr)ExecuteOnWaiting);
	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "ConvertStringToAddr returned " + to_string(err) + " for hostname " + string(hostname);
		return false;
	}

	// Open a TCP stream
	err = CreateStream(&_stream, BUF_SIZE, (GiveTimePtr)ExecuteOnWaiting, &_cancel);
	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "CreateStream returned " + to_string(err);
		return false;
	}

	// Open a connection
	err = OpenConnection(_stream, ipAddress, _stunnelPort > 0 ? _stunnelPort : GetRemotePort(_uri), 0, (GiveTimePtr)ExecuteOnWaiting, &_cancel);
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

bool HttpClient::Request()
{
	// Send the request
	OSErr err = SendData(
		_stream,
		(Ptr)_request.c_str(),
		(unsigned short)strlen(_request.c_str()),
		false,
		(GiveTimePtr)ExecuteOnWaiting,
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

bool HttpClient::Response()
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
			(GiveTimePtr)ExecuteOnWaiting,
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

void HttpClient::NetClose()
{
	CloseConnection(_stream, (GiveTimePtr)ExecuteOnWaiting, &_cancel);
	ReleaseStream(_stream, (GiveTimePtr)ExecuteOnWaiting, &_cancel);

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

int HttpClient::on_body_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->Content.append(at, length);
	return 0;
}

int HttpClient::on_header_field_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;

	string header = string(at);
	int delim = header.find(":");
	string headerName = header.substr(0, delim);

	response->Headers.insert(pair<string, string>(headerName, ""));
	response->CurrentHeader = headerName;

	return 0;
}

int HttpClient::on_header_value_callback(http_parser* parser, const char *at, size_t length)
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

int HttpClient::on_message_complete_callback(http_parser* parser)
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->MessageComplete = true;
	return 0;
}

int HttpClient::on_status_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->StatusCode = parser->status_code;
	return 0;
}
