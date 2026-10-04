// server.cpp
// Компиляция: g++ -std=c++17 -pthread server.cpp -o server
// Запуск: ./server [порт]  (по умолчанию 8080)

#include <iostream>
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
#include <csignal>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static std::atomic<bool> g_running{ true };
static int g_listen_sock = -1;

void signal_handler(int) {
    g_running = false;
    if (g_listen_sock != -1) {
        ::shutdown(g_listen_sock, SHUT_RDWR);
        ::close(g_listen_sock);
        g_listen_sock = -1;
    }
}

// Обработка одного клиента
void handle_client(int client_sock, sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    int client_port = ntohs(client_addr.sin_port);

    std::cout << "[+] CLient connected: " << client_ip
        << ":" << client_port
        << " (fd=" << client_sock << ")" << std::endl;

    constexpr size_t BUF_SIZE = 4096;
    char buffer[BUF_SIZE];

    while (g_running) {
        ssize_t received = ::recv(client_sock, buffer, BUF_SIZE, 0);
        if (received == 0) {
            std::cout << "[-] Client " << client_ip << ":" << client_port
                << " disconnected" << std::endl;
            break;
        }
        if (received < 0) {
            std::cerr << "[!] Error recv from " << client_ip << ":" << client_port
                << ": " << std::strerror(errno) << std::endl;
            break;
        }

        // Эхо: отправляем обратно то же самое
        ssize_t sent_total = 0;
        while (sent_total < received) {
            ssize_t sent = ::send(client_sock,
                buffer + sent_total,
                received - sent_total,
                0);
            if (sent <= 0) {
                std::cerr << "[!] Error send to client " << client_ip
                    << ":" << client_port << ": "
                    << std::strerror(errno) << std::endl;
                ::close(client_sock);
                return;
            }
            sent_total += sent;
        }

        std::cout << "[<] " << client_ip << ":" << client_port
            << " -> " << received << " bytes (echo)"
            << std::endl;
    }

    ::close(client_sock);
}

int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "ru_RU.UTF-8");

    int port = 8080;

    // Обработка Ctrl+C
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGPIPE, SIG_IGN); // игнорируем SIGPIPE при обрыве соединения

    // 1. Создаём сокет
    g_listen_sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_sock < 0) {
        std::cerr << "Ошибка socket(): " << std::strerror(errno) << std::endl;
        return 1;
    }

    // Разрешаем повторное использование адреса
    int opt = 1;
    if (::setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR,
        &opt, sizeof(opt)) < 0) {
        std::cerr << "Ошибка setsockopt(): " << std::strerror(errno) << std::endl;
        ::close(g_listen_sock);
        return 1;
    }

    std::string bind_addr = "127.0.0.1";

    // 2. Заполняем адрес привязки
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Специальные случаи: "*" или "any" -> INADDR_ANY (все интерфейсы)
    if (bind_addr == "*" || bind_addr == "any" || bind_addr == "0.0.0.0") {
        server_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr = "0.0.0.0 (все интерфейсы)";
    }
    else {
        // Преобразуем строку в бинарный IPv4-адрес
        if (::inet_pton(AF_INET, bind_addr.c_str(),
            &server_addr.sin_addr) != 1) {
            std::cerr << "Некорректный IPv4-адрес для привязки: "
                << bind_addr << std::endl;
            std::cerr << "Примеры: 127.0.0.1, 192.168.1.50, 0.0.0.0"
                << std::endl;
            ::close(g_listen_sock);
            return 1;
        }
    }

    if (::bind(g_listen_sock,
        reinterpret_cast<sockaddr*>(&server_addr),
        sizeof(server_addr)) < 0) {
        std::cerr << "Ошибка bind(): " << std::strerror(errno) << std::endl;
        ::close(g_listen_sock);
        return 1;
    }

    // 3. Слушаем
    if (::listen(g_listen_sock, SOMAXCONN) < 0) {
        std::cerr << "Ошибка listen(): " << std::strerror(errno) << std::endl;
        ::close(g_listen_sock);
        return 1;
    }

    std::cout << "Echo server start on " << bind_addr << ":" << port << std::endl;
    std::cout << "Press Ctrl + C to stop" << std::endl;

    // 4. Принимаем клиентов
    while (g_running) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_sock = ::accept(g_listen_sock,
            reinterpret_cast<sockaddr*>(&client_addr),
            &client_len);
        if (client_sock < 0) {
            if (!g_running) break; // сокет закрыт по сигналу
            std::cerr << "Error accept(): " << std::strerror(errno) << std::endl;
            continue;
        }

        // Каждый клиент обрабатывается в отдельном потоке
        std::thread(handle_client, client_sock, client_addr).detach();
    }

    std::cout << "Сервер остановлен." << std::endl;
    return 0;
}