// client.cpp
// Компиляция (MSVC):  cl /std:c++17 /EHsc client.cpp ws2_32.lib
// Компиляция (MinGW): g++ -std=c++17 client.cpp -o client.exe -lws2_32
// Запуск: client.exe <адрес_сервера> [порт]  (по умолчанию порт 8080)

#include <iostream>
#include <string>
#include <cstring>
#include <thread>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// RAII-обёртка для Winsock
class WinsockInit {
public:
    WinsockInit() {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            throw std::runtime_error("WSAStartup failed: " +
                std::to_string(result));
        }
    }
    ~WinsockInit() { WSACleanup(); }
};

void EnableANSI() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    setlocale(LC_ALL, "Russian");
}

int main(int argc, char* argv[]) {

    EnableANSI();

    std::string server_addr = "127.0.0.1";
    int port = 8080;
    if (port <= 0 || port > 65535) {
        std::cerr << "Некорректный порт" << std::endl;
        return 1;
    }

    try {
        WinsockInit wsa;

        // 1. Создаём сокет
        SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            std::cerr << "Ошибка socket(): " << WSAGetLastError() << std::endl;
            return 1;
        }

        // 2. Разрешаем адрес сервера (поддерживает DNS-имена и IPv4)
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* result = nullptr;
        std::string port_str = std::to_string(port);
        int gai = ::getaddrinfo(server_addr.c_str(), port_str.c_str(),
            &hints, &result);
        if (gai != 0) {
            std::cerr << "Ошибка getaddrinfo(): " << gai << std::endl;
            ::closesocket(sock);
            return 1;
        }

        // 3. Подключаемся
        bool connected = false;
        for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
            if (::connect(sock, ptr->ai_addr,
                static_cast<int>(ptr->ai_addrlen)) == 0) {
                connected = true;
                break;
            }
        }
        ::freeaddrinfo(result);

        if (!connected) {
            std::cerr << "Не удалось подключиться к " << server_addr
                << ":" << port
                << " (код: " << WSAGetLastError() << ")" << std::endl;
            ::closesocket(sock);
            return 1;
        }

        std::cout << "Подключено к " << server_addr << ":" << port << std::endl;
        //std::cout << "Введите сообщение (для выхода: 'exit' или пустая строка)"
        //    << std::endl;

        // 4. Цикл обмена
        std::string line = "test";
        while (true) {
//            std::cout << "> ";
//            std::getline(std::cin, line);

            if (line.empty() || line == "exit" || line == "quit") {
                std::cout << "Завершение работы." << std::endl;
                break;
            }

            // Отправляем
            int sent = ::send(sock, line.c_str(),
                static_cast<int>(line.size()), 0);
            if (sent == SOCKET_ERROR) {
                std::cerr << "Ошибка send(): " << WSAGetLastError() << std::endl;
                break;
            }

            // Принимаем эхо (ровно столько же байт, сколько отправили)
            std::string response(line.size(), '\0');
            int total_received = 0;
            while (total_received < sent) {
                int received = ::recv(sock,
                    &response[total_received],
                    sent - total_received, 0);
                if (received == 0) {
                    std::cerr << "Сервер закрыл соединение" << std::endl;
                    ::closesocket(sock);
                    return 0;
                }
                if (received == SOCKET_ERROR) {
                    std::cerr << "Ошибка recv(): "
                        << WSAGetLastError() << std::endl;
                    ::closesocket(sock);
                    return 1;
                }
                total_received += received;
            }

            std::cout << "< Эхо: " << response << std::endl;
        }

        ::closesocket(sock);
    }
    catch (const std::exception& e) {
        std::cerr << "Исключение: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}