#ifndef MACHTTP_HTTPCLIENT
#define MACHTTP_HTTPCLIENT

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

class HttpClient {
public:
    enum RequestStatus
    {
        Idle,
        Waiting,
        Running
    };

    HttpClient();
    explicit HttpClient(string baseUri);

    void Get(const string& requestUri, std::function<void(HttpResponse&)> onComplete);
    void Post(const string& requestUri, const string& content, std::function<void(HttpResponse&)> onComplete);
    void Get(const Uri& requestUri, std::function<void(HttpResponse&)> onComplete);
    void Post(const Uri& requestUri, const string& content, std::function<void(HttpResponse&)> onComplete);
    void Put(const Uri& requestUri, const string& content, function<void(HttpResponse&)> onComplete);

    void SetProxy(string host, int port);
    void SetDebugLevel(int debugLevel);
    void SetStunnel(string host, int port);
    void SetAuthorization(string authorization);

    static void SetGlobalOnWaiting(std::function<void()> onWaiting);

    void CancelRequest();
    RequestStatus GetStatus();
    virtual void InitThread();

    static int on_header_field_callback(http_parser* parser, const char *at, size_t length);
    static int on_header_value_callback(http_parser* parser, const char *at, size_t length);
    static int on_body_callback(http_parser* parser, const char *at, size_t length);
    static int on_status_callback(http_parser* parser, const char *at, size_t length);
    static int on_message_complete_callback(http_parser* parser);

protected:
    http_parser _parser;
    http_parser_settings _settings;

    HttpResponse _response;
    string _baseUri;
    string _proxyHost;
    string _stunnelHost;
    string _request;
    Uri _uri;
    RequestStatus _status;
    unsigned long _stream;
    int _stunnelPort;
    std::function<void(HttpResponse&)> _onComplete;
    const char* _cRequest;
    bool _cancel;

    Uri GetUri(const string& requestUri);
    virtual void Init(string baseUri);
    virtual int GetRemotePort(const Uri& uri);
    string GetRemoteHost(const Uri& uri);
    virtual void Connect(const Uri& uri, unsigned long stream);
    virtual void Request(const Uri& uri, const string& request, function<void(HttpResponse&)> onComplete);
    bool DoRedirect();
    virtual void HttpRequest();

    virtual bool Connect();
    virtual bool Request();
    virtual bool Response();
    virtual void NetClose();

private:
    static const int BUF_SIZE = 8192;
    string _authorization;
    int _proxyPort;
    int _debugLevel;

    inline static function<void()> g_onWaiting;
    static void ExecuteOnWaiting();

    void PutPost(const Uri& requestUri, const string& httpMethod, const string& content, function<void(HttpResponse&)> onComplete);
    void InitParser();
    string GetAuthHeader();
};


#endif //MACHTTP_HTTPCLIENT
