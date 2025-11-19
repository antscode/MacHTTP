

#ifndef MACHTTP_SIMPLEHTTPCLIENT_HPP
#define MACHTTP_SIMPLEHTTPCLIENT_HPP

#include "HttpResponse.h"
#include "Uri.h"
#include <functional>

using namespace std;

// Disabled strict HTTP parsing to improve performance
#ifndef HTTP_PARSER_STRICT
#define HTTP_PARSER_STRICT 0
#endif

#ifndef http_parser_h
extern "C"
{
#include "http_parser.h"
}
#endif

class SimpleHttpClient {
public:
    enum RequestStatus
    {
        Idle,
        Waiting,
        Running
    };

    SimpleHttpClient();
    SimpleHttpClient(string baseUri);
    void Get(const string& requestUri, std::function<void(HttpResponse&)> onComplete);
    void Post(const string& requestUri, const string& content, std::function<void(HttpResponse&)> onComplete);
    void Get(const Uri& requestUri, std::function<void(HttpResponse&)> onComplete);
    void Post(const Uri& requestUri, const string& content, std::function<void(HttpResponse&)> onComplete);
    void Put(const Uri& requestUri, const string& content, function<void(HttpResponse&)> onComplete);
    void SetProxy(string host, int port);
    void SetCipherSuite(int cipherSuite);
    void SetDebugLevel(int debugLevel);
    void SetStunnel(string host, int port);
    void SetAuthorization(string authorization);
    void ProcessRequests();
    void CancelRequest();
    RequestStatus GetStatus();
    void InitThread();

    static int on_header_field_callback(http_parser* parser, const char *at, size_t length);
    static int on_header_value_callback(http_parser* parser, const char *at, size_t length);
    static int on_body_callback(http_parser* parser, const char *at, size_t length);
    static int on_status_callback(http_parser* parser, const char *at, size_t length);
    static int on_message_complete_callback(http_parser* parser);

private:
    static const int BUF_SIZE = 8192;
    string _baseUri;
    string _proxyHost;
    string _stunnelHost;
    string _authorization;
    Uri _uri;
    string _request;
    RequestStatus _status;
    HttpResponse _response;
    std::function<void(HttpResponse&)> _onComplete;
    int _proxyPort;
    int _stunnelPort;
    int _debugLevel;
    bool _cancel;

    void Init(string baseUri);
    Uri GetUri(const string& requestUri);
    string GetRemoteHost(const Uri& uri);
    int GetRemotePort(const Uri& uri);
    void Connect(const Uri& uri, unsigned long stream);
    void PutPost(const Uri& requestUri, const string& httpMethod, const string& content, function<void(HttpResponse&)> onComplete);
    void Request(const Uri& uri, const string& request, function<void(HttpResponse&)> onComplete);
    bool DoRedirect();
    void InitParser();
    static void Yield();
    void HttpRequest();
    string GetAuthHeader();

    http_parser _parser;
    http_parser_settings _settings;

    unsigned long _stream;

    bool Connect();
    bool Request();
    bool Response();
    void NetClose();

    const char* _cRequest;
};


#endif //MACHTTP_SIMPLEHTTPCLIENT_HPP