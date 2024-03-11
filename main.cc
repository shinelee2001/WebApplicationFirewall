#include <iostream>
#include <winsock2.h>
#include "http_inspector.h"

#pragma comment(lib, "ws2_32.lib")

int main() {
    int port;
    std::cout << "Enter the port number: " << std::endl;
    std::cin >> port;
    HTTPRequestInspector inspector(port);

    if (!inspector.startListening()) {
        std::cerr << "Failed to start listening on port: " << port << std::endl;
        return 1;
    }

    inspector.inspectRequests();

    return 0;
}
