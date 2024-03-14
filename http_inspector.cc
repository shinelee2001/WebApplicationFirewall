#include "http_inspector.h"
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <cctype>

const char *DESTINATION_SERVER = "127.0.0.1";
constexpr int DESTINATION_PORT = 5002;

const int BUFFER_MAX = 4096;

void printResponse(const std::string res) {
    std::cout << "Http response is:\n=============================================================\n" 
    << res << "\n=============================================================" 
    << std::endl;
}

bool isSQLInjection(const std::string request) {
    // convert request to lowercase
    std::string lowercaseRequest = request;
    std::transform(lowercaseRequest.begin(), lowercaseRequest.end(), lowercaseRequest.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // SQL injection keywords
    std::vector<std::string> sqlKeywords = {
        "select", "insert", "update", "delete", "drop", "alter", "truncate", "union", "join", "exec", "declare", "xp_"
    };

    // check if any of the SQL keywords are present in the request
    for (const auto& keyword : sqlKeywords) {
        if (lowercaseRequest.find(keyword) != std::string::npos) {
            return true;
        }
    }

    return false;
}

HTTPRequestInspector::HTTPRequestInspector(int port): port{port} {}

HTTPRequestInspector::~HTTPRequestInspector() {
    // close socket
    closesocket(serverSocket);

    // close winsock
    WSACleanup();
}

bool HTTPRequestInspector::startListening() {
    // winsock init
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return false;
    }

    // create server socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create server socket" << std::endl;
        WSACleanup();
        return false;
    }

    // Configure server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(port);

    // Binding
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Binding failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    // Listening
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listening failed" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    std::cout << "Server listneing on port: " << port << "..." << std::endl;
    return true;
}

bool HTTPRequestInspector::forwardResponse(char *buffer, int bytesReceived) {
    // create socket for the dest server
    SOCKET destinationSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (destinationSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create destination socket" << std::endl;
        return false;
    }

    // configure the dest server
    sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(DESTINATION_SERVER);
    destAddr.sin_port = htons(DESTINATION_PORT);

    // connect to dest server
    if (connect(destinationSocket, (struct sockaddr*)&destAddr, sizeof(destAddr)) == SOCKET_ERROR) {
        std::cerr << "Failed to connect to destination server" << std::endl;
        return false;
    }

    // forward request
    int bytesSent = send(destinationSocket, buffer, bytesReceived, 0);
    if (bytesSent == SOCKET_ERROR) {
        std::cerr << "Failed to send request to destination server" << std::endl;
        closesocket(destinationSocket);
        return false;
    }

    // receive and forward response
    while (true) {
        char resBuffer[BUFFER_MAX];
        // receive response from the dest server
        int res = recv(destinationSocket, resBuffer, sizeof(resBuffer), 0);
        if (res == SOCKET_ERROR) {
            std::cerr << "Failed to receive response from destiantion server" << std::endl;
            closesocket(destinationSocket);
            return false;
        }

        if (res == 0) {
            break;
        }
        std::string httpresponse{resBuffer, res};
        printResponse(httpresponse);

        // send the response back to the client
        bytesSent = send(clientSocket, resBuffer, res, 0);
        if (bytesSent == SOCKET_ERROR) {
            std::cerr << "Failed to send response to client" << std::endl;
            closesocket(destinationSocket);
            return false;
        }
    }

    closesocket(destinationSocket);
    return true;
}


void HTTPRequestInspector::inspectRequests() {
    struct sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[1024];

    while(true) {
        // connect client
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accpet failed" << std::endl;
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
        while (!requestTimestamps.empty() && std::chrono::steady_clock::now() - requestTimestamps.front() > DETECTION_WINDOW) {
            requestTimestamps.pop_front();
        }

        // check if request rate exceeds threshold
        if (requestTimestamps.size() > MAX_REQUESTS_PER_SECOND) {
            std::cerr << "Possible DoS attack dtected from: " << inet_ntoa(clientAddr.sin_addr) << ":" << ntohs(clientAddr.sin_port) << std::endl;
            // close client socket when detected
            closesocket(clientSocket);
            continue;
        }

        ////////////////////////////////////////
        //           end DoS Attack           //
        ////////////////////////////////////////

        // receive data from client
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived == SOCKET_ERROR) {
            std::cerr << "Failed to receive request from client" << std::endl;
        }

        // inspect HTTP request
        std::string httpRequest{buffer};
        std::cout << "Http request is:\n=============================================================\n" << httpRequest << "\n=============================================================" << std::endl;

        ////////////////////////////////////////
        //        SQL injection check         //
        ////////////////////////////////////////

        if (isSQLInjection(httpRequest)) {
            std::cerr << "SQL Injection detected in request from: " << inet_ntoa(clientAddr.sin_addr) << ":" << ntohs(clientAddr.sin_port) << std::endl;
            closesocket(clientSocket);
            continue;
        }

        ////////////////////////////////////////
        //      end SQL injection check       //
        ////////////////////////////////////////

        this->forwardResponse(buffer, bytesReceived);
    }
}