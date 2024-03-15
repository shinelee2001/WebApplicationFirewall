#include "http_inspector.h"
#include <iostream>
#include <algorithm>
#include <vector>
#include <cctype>
#include <fstream>
#include <sstream>

const char *DESTINATION_SERVER = "127.0.0.1";
constexpr int DESTINATION_PORT = 5002;

const int BUFFER_MAX = 4096;

void printResponse(const std::string res)
{
    std::cout << "Http response is:\n=============================================================\n"
              << res << "\n============================================================="
              << std::endl;
}

bool isSQLInjection(const std::string request)
{
    // convert request to lowercase
    std::string lowercaseRequest = request;
    std::transform(lowercaseRequest.begin(),
                   lowercaseRequest.end(),
                   lowercaseRequest.begin(),
                   [](unsigned char c)
                   { return std::tolower(c); });

    // SQL injection keywords
    std::vector<std::string> sqlKeywords = {
        "select", "insert", "update", "delete", "drop", "alter", "truncate", "union", "join", "exec", "declare", "xp_"};

    // check if any of the SQL keywords are present in the request
    for (const auto &keyword : sqlKeywords)
    {
        if (lowercaseRequest.find(keyword) != std::string::npos)
        {
            return true;
        }
    }

    return false;
}

HTTPRequestInspector::HTTPRequestInspector(int port) : port{port} {}

HTTPRequestInspector::~HTTPRequestInspector()
{
    // close socket
    closesocket(serverSocket);

    // close winsock
    WSACleanup();
}

bool HTTPRequestInspector::startListening()
{
    // winsock init with version 2.2
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return false;
    }

    // create server socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET)
    {
        std::cerr << "Failed to create server socket" << std::endl;
        WSACleanup();
        return false;
    }

    // Configure server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(port);

    // binding
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Binding failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    // listening
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        std::cerr << "Listening failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    std::cout << "Server listneing on port: " << port << "..." << std::endl;
    return true;
}

bool HTTPRequestInspector::forwardResponse(char *buffer, int bytesReceived)
{
    // create socket for the dest server
    SOCKET destinationSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (destinationSocket == INVALID_SOCKET)
    {
        std::cerr << "Failed to create destination socket" << std::endl;
        return false;
    }

    // configure the dest server
    sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(DESTINATION_SERVER);
    destAddr.sin_port = htons(DESTINATION_PORT);

    // connect to dest server
    if (connect(destinationSocket, (struct sockaddr *)&destAddr, sizeof(destAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Failed to connect to destination server" << std::endl;
        return false;
    }

    // forward request
    int bytesSent = send(destinationSocket, buffer, bytesReceived, 0);
    if (bytesSent == SOCKET_ERROR)
    {
        std::cerr << "Failed to send request to destination server" << std::endl;
        closesocket(destinationSocket);
        return false;
    }

    // receive and forward response
    while (true)
    {
        char resBuffer[BUFFER_MAX];
        // receive response from the dest server
        int res = recv(destinationSocket, resBuffer, sizeof(resBuffer), 0);
        if (res == SOCKET_ERROR)
        {
            std::cerr << "Failed to receive response from destiantion server" << std::endl;
            closesocket(destinationSocket);
            return false;
        }

        if (res == 0)
        {
            break;
        }
        std::string httpresponse{resBuffer, res};
        printResponse(httpresponse);

        // send the response back to the client
        bytesSent = send(clientSocket, resBuffer, res, 0);
        if (bytesSent == SOCKET_ERROR)
        {
            std::cerr << "Failed to send response to client" << std::endl;
            closesocket(destinationSocket);
            return false;
        }
    }

    closesocket(destinationSocket);
    return true;
}

bool HTTPRequestInspector::forwardFileUpload(const std::string& boundary, const std::string& filename, const std::string& fileContent) {
    // create socket for the dest server
    SOCKET destinationSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (destinationSocket == INVALID_SOCKET)
    {
        std::cerr << "Failed to create destination socket" << std::endl;
        return false;
    }

    // configure the dest server
    sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(DESTINATION_SERVER);
    destAddr.sin_port = htons(DESTINATION_PORT);

    // connect to dest server
    if (connect(destinationSocket, (struct sockaddr *)&destAddr, sizeof(destAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Failed to connect to destination server" << std::endl;
        return false;
    }

    // prepare HTTP request with the file content
    std::ostringstream reqStream;
    reqStream << "POST /upload HTTP/1.1\r\n";
    reqStream << "Content-Type: multipart/form-data; boundary=" << boundary << "\r\n";
    reqStream << "Content-Disposition: form-data; name=\"file\"; filename=\"" << filename << "\"\r\n";
    reqStream << "\r\n";
    reqStream << fileContent << "\r\n";
    reqStream << "--" << boundary << "--\r\n";

    std::string httpRequest = reqStream.str();

    // forward request
    int bytesSent = send(destinationSocket, httpRequest.c_str(), httpRequest.size(), 0);
    if (bytesSent == SOCKET_ERROR) {
        std::cerr << "Failed to send request to destination server" << std::endl;
        closesocket(destinationSocket);
        return false;
    }

    // receive and forward response
    while (true)
    {
        char resBuffer[BUFFER_MAX];
        // receive response from the dest server
        int res = recv(destinationSocket, resBuffer, sizeof(resBuffer), 0);
        if (res == SOCKET_ERROR)
        {
            std::cerr << "Failed to receive response from destiantion server" << std::endl;
            closesocket(destinationSocket);
            return false;
        }

        if (res == 0)
        {
            break;
        }
        std::string httpresponse{resBuffer, res};
        printResponse(httpresponse);

        // send the response back to the client
        bytesSent = send(clientSocket, resBuffer, res, 0);
        if (bytesSent == SOCKET_ERROR)
        {
            std::cerr << "Failed to send response to client" << std::endl;
            closesocket(destinationSocket);
            return false;
        }
    }

    closesocket(destinationSocket);
    return true;

}

void HTTPRequestInspector::handleFileUpload(const std::string &boundary, std::string &reqBody)
{
    // split the reqBody into parts using the boundary
    std::vector<std::string> parts;
    size_t pos = reqBody.find(boundary);
    while (pos != std::string::npos)
    {
        // extract the multipart requst
        parts.push_back(reqBody.substr(0, pos));
        reqBody = reqBody.substr(pos + boundary.size());
        pos = reqBody.find(boundary);
    }

    // iterate through parts to find file uploads
    for (const auto &part : parts)
    {
        // find the part containing file data
        if (part.find("Content-Disposition: form-data;") != std::string::npos)
        {
            // extract filename
            size_t filenamePos = part.find("filename=\"");
            if (filenamePos != std::string::npos)
            {
                filenamePos += 10; // length of "filename=\""
                size_t filenameEnd = part.find("\"", filenamePos);
                std::string filename = part.substr(filenamePos, filenameEnd - filenamePos);

                // extract file content
                size_t contentPos = part.find("\r\n\r\n") + 4;
                std::string fileContent = part.substr(contentPos);

                // forward the file to the dest server
                this->forwardFileUpload(boundary, filename, fileContent);
            }
        }
    }
}


void HTTPRequestInspector::inspectRequests()
{
    struct sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[BUFFER_MAX];

    while (true)
    {
        // connect client
        clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET)
        {
            std::cerr << "Accept failed" << std::endl;
            closesocket(serverSocket);
            WSACleanup();
            return;
        }

        ////////////////////////////////////////
        //         DoS Attack check           //
        ////////////////////////////////////////

        // Record request timestamp
        requestTimestamps.push_back(std::chrono::steady_clock::now());

        // remove old timestamps
        while (!requestTimestamps.empty() && std::chrono::steady_clock::now() - requestTimestamps.front() > DETECTION_WINDOW)
        {
            requestTimestamps.pop_front();
        }

        // check if request rate exceeds threshold
        if (requestTimestamps.size() > MAX_REQUESTS_PER_SECOND)
        {
            std::cerr << "Possible DoS attack detected from: " << inet_ntoa(clientAddr.sin_addr) << ":" << ntohs(clientAddr.sin_port) << std::endl; // Corrected spelling of "detected"
            // close client socket when detected
            closesocket(clientSocket);
            continue;
        }

        ////////////////////////////////////////
        //           end DoS Attack           //
        ////////////////////////////////////////

        // receive data from client
        int bytesReceived = recv(clientSocket, buffer, BUFFER_MAX, 0);
        if (bytesReceived == SOCKET_ERROR)
        {
            std::cerr << "Failed to receive request from client" << std::endl;
            closesocket(clientSocket);
            continue; // Continue to next iteration
        }

        // inspect HTTP request
        std::string httpRequest(buffer, bytesReceived); // Use received bytes to construct string
        std::cout << "Http request is:\n=============================================================\n"
                << httpRequest << "\n=============================================================" << std::endl;

        // check if it requests about file uploading. That is:
        // check if the request is of the POST method with multipart/form-data
        if (httpRequest.find("POST") != std::string::npos && httpRequest.find("multipart/form-data") != std::string::npos) {
            // extract boundary
            size_t boundaryPos = httpRequest.find("boundary=");
            if (boundaryPos != std::string::npos) {
                std::string boundary = "--" + httpRequest.substr(boundaryPos + 9, 70);
                this->handleFileUpload(boundary, httpRequest);
            }
        } else {

            ////////////////////////////////////////
            //        SQL injection check         //
            ////////////////////////////////////////

            if (isSQLInjection(httpRequest))
            {
                std::cerr << "SQL Injection detected in request from: " << inet_ntoa(clientAddr.sin_addr) << ":" << ntohs(clientAddr.sin_port) << std::endl;
                closesocket(clientSocket);
                continue;
            }

            ////////////////////////////////////////
            //      end SQL injection check       //
            ////////////////////////////////////////
            
            this->forwardResponse(buffer, bytesReceived);
        }

        closesocket(clientSocket); // Close client socket after handling request
    }
}