/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

// Exercise real accept/handshake callbacks in fresh XLIO processes. The driver
// has no worker threads; the server has eight and each independent client one.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <spawn.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

extern char **environ;

static const unsigned int CLIENTS = 8;
static const unsigned int CONNECTIONS = 512;

static void require(bool ok, const char *operation)
{
    if (!ok) {
        throw std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
    }
}

struct address {
    sockaddr_storage value = {};
    socklen_t length = 0;

    address(const char *ip, const char *port)
    {
        addrinfo hints = {}, *result = nullptr;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        const int rc = getaddrinfo(ip, port, &hints, &result);
        if (rc != 0) {
            throw std::runtime_error(gai_strerror(rc));
        }
        length = result->ai_addrlen;
        std::memcpy(&value, result->ai_addr, length);
        freeaddrinfo(result);
    }

    sockaddr *ptr() { return reinterpret_cast<sockaddr *>(&value); }
};

static int serve(const char *ip, bool nonblocking)
{
    address local(ip, "0");
    const int listener = socket(local.value.ss_family, SOCK_STREAM, 0);
    require(listener >= 0, "server socket");
    require(bind(listener, local.ptr(), local.length) == 0, "server bind");
    require(listen(listener, CONNECTIONS) == 0, "listen");
    require(getsockname(listener, local.ptr(), &local.length) == 0, "getsockname");
    const unsigned short port = local.value.ss_family == AF_INET
        ? ntohs(reinterpret_cast<sockaddr_in *>(local.ptr())->sin_port)
        : ntohs(reinterpret_cast<sockaddr_in6 *>(local.ptr())->sin6_port);

    int epfd = -1;
    if (nonblocking) {
        require(fcntl(listener, F_SETFL, O_NONBLOCK) == 0, "nonblocking listener");
        epfd = epoll_create1(EPOLL_CLOEXEC);
        require(epfd >= 0, "epoll_create1");
        epoll_event event = {};
        event.events = EPOLLIN;
        event.data.fd = listener;
        require(epoll_ctl(epfd, EPOLL_CTL_ADD, listener, &event) == 0, "epoll_ctl");
    }
    // The controller starts clients only after the listener is ready.
    std::cout << port << std::endl;

    unsigned int accepted = 0;
    while (accepted < CONNECTIONS) {
        if (nonblocking) {
            epoll_event event = {};
            require(epoll_wait(epfd, &event, 1, 10000) == 1, "listener readiness");
        }
        do {
            const int fd = accept(listener, nullptr, nullptr);
            if (nonblocking && fd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
            require(fd >= 0, "accept");
            char request = 0;
            require(recv(fd, &request, 1, 0) == 1 && request == 'Q', "server receive");
            require(send(fd, "R", 1, MSG_NOSIGNAL) == 1, "server send");
            require(close(fd) == 0, "server close");
            ++accepted;
        } while (nonblocking && accepted < CONNECTIONS);
    }
    if (epfd >= 0) {
        close(epfd);
    }
    close(listener);
    return 0;
}

static int connect_burst(const char *client_ip, const char *server_ip, const char *port)
{
    address local(client_ip, "0"), peer(server_ip, port);
    std::vector<int> sockets;
    // Keep all sockets alive until every client finishes connecting. The
    // controller releases stdin only after the server accepted the whole batch,
    // preventing another client from reusing a port still in server TIME_WAIT.
    for (unsigned int index = 0; index < CONNECTIONS / CLIENTS; ++index) {
        const int fd = socket(peer.value.ss_family, SOCK_STREAM, 0);
        require(fd >= 0, "client socket");
        require(bind(fd, local.ptr(), local.length) == 0, "client bind");
        require(connect(fd, peer.ptr(), peer.length) == 0, "connect");
        require(send(fd, "Q", 1, MSG_NOSIGNAL) == 1, "client send");
        sockets.push_back(fd);
    }
    for (int fd : sockets) {
        char response = 0;
        require(recv(fd, &response, 1, 0) == 1 && response == 'R', "client receive");
    }
    char release;
    ssize_t rc;
    do {
        rc = read(STDIN_FILENO, &release, 1);
    } while (rc < 0 && errno == EINTR);
    require(rc == 0, "client release barrier");
    for (int fd : sockets) {
        close(fd);
    }
    return 0;
}

class children {
public:
    ~children()
    {
        for (pid_t pid : pids) {
            if (pid > 0) {
                kill(pid, SIGKILL);
                while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
                }
            }
        }
    }

    void start(const std::vector<std::string> &args, int workers, int ready_pipe = -1,
               int release_pipe = -1)
    {
        std::vector<std::string> environment;
        for (char **item = environ; *item; ++item) {
            if (std::strncmp(*item, "XLIO_INLINE_CONFIG=", 19) != 0) {
                environment.emplace_back(*item);
            }
        }
        environment.push_back("XLIO_INLINE_CONFIG=performance.threading.worker_threads=" +
                              std::to_string(workers));
        std::vector<char *> argv, envp;
        for (const auto &arg : args) {
            argv.push_back(const_cast<char *>(arg.c_str()));
        }
        argv.push_back(nullptr);
        for (auto &item : environment) {
            envp.push_back(&item[0]);
        }
        envp.push_back(nullptr);
        posix_spawn_file_actions_t actions;
        require(posix_spawn_file_actions_init(&actions) == 0, "spawn actions");
        if (ready_pipe >= 0) {
            require(posix_spawn_file_actions_adddup2(&actions, ready_pipe, STDOUT_FILENO) == 0,
                    "spawn stdout");
        }
        if (release_pipe >= 0) {
            require(posix_spawn_file_actions_adddup2(&actions, release_pipe, STDIN_FILENO) == 0,
                    "spawn stdin");
        }
        pid_t pid = -1;
        const int rc =
            posix_spawn(&pid, args[0].c_str(), &actions, nullptr, argv.data(), envp.data());
        posix_spawn_file_actions_destroy(&actions);
        errno = rc;
        require(rc == 0, "posix_spawn");
        pids.push_back(pid);
    }

    void wait_all(int release_pipe)
    {
        for (auto &pid : pids) {
            int status = 0;
            pid_t rc;
            do {
                rc = waitpid(pid, &status, 0);
            } while (rc < 0 && errno == EINTR);
            require(rc == pid, "waitpid");
            pid = -1;
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                throw std::runtime_error("accept worker helper child failed: status=" +
                                         std::to_string(status));
            }
            if (release_pipe >= 0) {
                // The first child is the server. All clients retain their bound
                // sockets until it successfully accepts every connection.
                close(release_pipe);
                release_pipe = -1;
            }
        }
    }

private:
    std::vector<pid_t> pids;
};

int main(int argc, char **argv)
{
    try {
        if (argc == 4 && std::strcmp(argv[1], "server") == 0) {
            return serve(argv[2], std::strcmp(argv[3], "nonblocking") == 0);
        }
        if (argc == 5 && std::strcmp(argv[1], "client") == 0) {
            return connect_burst(argv[2], argv[3], argv[4]);
        }
        require(argc == 4, "arguments: client-ip server-ip blocking|nonblocking");
        int ready[2];
        require(pipe2(ready, O_CLOEXEC) == 0, "ready pipe");
        children processes;
        processes.start({argv[0], "server", argv[2], argv[3]}, 8, ready[1]);
        close(ready[1]);
        FILE *port_stream = fdopen(ready[0], "r");
        require(port_stream != nullptr, "fdopen");
        unsigned short port = 0;
        const int fields = fscanf(port_stream, "%hu", &port);
        fclose(port_stream);
        require(fields == 1 && port != 0, "server ready");
        int release[2];
        require(pipe2(release, O_CLOEXEC) == 0, "release pipe");
        for (unsigned int index = 0; index < CLIENTS; ++index) {
            processes.start({argv[0], "client", argv[1], argv[2], std::to_string(port)}, 1, -1,
                            release[0]);
        }
        close(release[0]);
        processes.wait_all(release[1]);
        std::cout << "completed " << CONNECTIONS << " connections" << std::endl;
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
