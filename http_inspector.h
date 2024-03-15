#ifndef HTTP_INSPECTOR_H
#define HTTP_INSPECTOR_H
#include <winsock2.h>
#include <chrono>
#include <deque>
#include <string>

class HTTPRequestInspector {
  private:
    WSADATA wsaData;
    SOCKET serverSocket, clientSocket;
    struct sockaddr_in serverAddr;
    int port;

    std::deque<std::chrono::steady_clock::time_point> requestTimestamps;
    const int MAX_REQUESTS_PER_SECOND = 100;
    const std::chrono::seconds DETECTION_WINDOW = std::chrono::seconds(10);

    void handleFileUpload(const std::string& boundary, std::string& reqBody);
    bool forwardFileUpload(const std::string& boundary, const std::string& filename, const std::string& fileContent);
    bool forwardResponse(char *buffer, int bytesReceived);

  public:
    HTTPRequestInspector(int port);
    ~HTTPRequestInspector();

    bool startListening();
    void inspectRequests();
};

#endif