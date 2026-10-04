#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

int main(int argc, char* argv[]) {
    // Arguments: [server_address] [port]
    // Defaults: 127.0.0.1, 8080
    std::string server_addr = "127.0.0.1";
    int port = 8080;

    if (argc >= 2) {
        server_addr = argv[1];
    }
    if (argc >= 3) {
        port = std::atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            std::cerr << "Error: invalid port: " << argv[2] << std::endl;
            return 1;
        }
    }

    // 1. Create a socket
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error: socket(): " << std::strerror(errno) << std::endl;
        return 1;
    }

    // 2. Resolve the server address (supports hostnames and IPv4)
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    std::string port_str = std::to_string(port);
    int gai = ::getaddrinfo(server_addr.c_str(), port_str.c_str(),
        &hints, &result);
    if (gai != 0) {
        std::cerr << "Error: getaddrinfo(): " << gai_strerror(gai) << std::endl;
        ::close(sock);
        return 1;
    }

    // 3. Connect
    bool connected = false;
    for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        if (::connect(sock, ptr->ai_addr, ptr->ai_addrlen) == 0) {
            connected = true;
            break;
        }
    }
    ::freeaddrinfo(result);

    if (!connected) {
        std::cerr << "Error: cannot connect to " << server_addr
            << ":" << port
            << " - " << std::strerror(errno) << std::endl;
        ::close(sock);
        return 1;
    }

    std::cout << "Connected to " << server_addr << ":" << port << std::endl;
    std::cout << "Enter a message (type 'exit' or an empty line to quit)"
        << std::endl;

    // 4. Send/receive loop
    std::string line;
    while (true) {
        std::cout << "> " << std::flush;
        if (!std::getline(std::cin, line)) {
            // EOF on stdin (e.g. Ctrl+D)
            std::cout << "EOF on stdin, exiting." << std::endl;
            break;
        }

        if (line.empty() || line == "exit" || line == "quit") {
            std::cout << "Exiting." << std::endl;
            break;
        }

        // Send the whole line
        ssize_t sent_total = 0;
        ssize_t line_size = static_cast<ssize_t>(line.size());
        while (sent_total < line_size) {
            ssize_t sent = ::send(sock,
                line.data() + sent_total,
                line_size - sent_total,
                0);
            if (sent <= 0) {
                std::cerr << "Error: send(): "
                    << std::strerror(errno) << std::endl;
                ::close(sock);
                return 1;
            }
            sent_total += sent;
        }

        // Read exactly the same number of bytes back (echo protocol)
        std::string response(line_size, '\0');
        ssize_t recv_total = 0;
        while (recv_total < line_size) {
            ssize_t received = ::recv(sock,
                &response[recv_total],
                line_size - recv_total,
                0);
            if (received == 0) {
                std::cerr << "Server closed the connection" << std::endl;
                ::close(sock);
                return 0;
            }
            if (received < 0) {
                std::cerr << "Error: recv(): "
                    << std::strerror(errno) << std::endl;
                ::close(sock);
                return 1;
            }
            recv_total += received;
        }

        std::cout << "< Echo: " << response << std::endl;
    }

    // 5. Graceful shutdown
    ::shutdown(sock, SHUT_RDWR);
    ::close(sock);
    return 0;
}