/*
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "util/tx_snapshot.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <new>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace tx_snapshot {
namespace {
constexpr unsigned event_limit = 100000;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
pthread_once_t init = PTHREAD_ONCE_INIT;
pthread_t writer;
message *head = nullptr;
message *tail = nullptr;
message *inherited_tail = nullptr;
bool started = false;
bool stopping = false;

// Serializes fd creation/close with fork, independently of producers.
pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER;
int fd = -1;

bool write_all(const char *line, size_t size)
{
    while (size) {
        ssize_t n = syscall(SYS_write, fd, line, size);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            perror("XLIO TX snapshot write");
            return false;
        }
        line += n;
        size -= static_cast<size_t>(n);
    }
    return true;
}

bool print_record(unsigned number, const message &msg)
{
    constexpr char hex[] = "0123456789abcdef";
    constexpr size_t group_size = 16;
    char line[2 * limit + (limit - 1) / group_size + 160];
    int n = snprintf(line, sizeof(line), "%05u %s pid=%ld qp=%u wqe=%u ", number, msg.event,
                     (long)getpid(), msg.qp, msg.wqe);
    if (msg.api_send) {
        n += snprintf(line + n, sizeof(line) - n, "requested_bytes=%zu ", msg.requested);
    }
    n += snprintf(line + n, sizeof(line) - n, "storage=%s bytes=%zu hex=", msg.storage, msg.size);
    for (size_t i = 0; i < msg.size; ++i) {
        if (i && i % group_size == 0) {
            line[n++] = ' ';
        }
        line[n++] = hex[msg.bytes[i] >> 4];
        line[n++] = hex[msg.bytes[i] & 15];
    }
    line[n++] = '\n';
    return write_all(line, n);
}

void *consume(void *)
{
    pthread_mutex_lock(&file_lock);
    char path[80];
    snprintf(path, sizeof(path), "/tmp/xlio-tx-%ld-XXXXXX.log", (long)getpid());
    fd = mkostemps(path, 4, O_CLOEXEC);
    if (fd < 0) {
        perror(path);
    }
    pthread_mutex_unlock(&file_lock);
    bool writable = fd >= 0;
    unsigned count = 0;
    pthread_mutex_lock(&lock);
    for (;;) {
        while (!head && !stopping) {
            pthread_cond_wait(&ready, &lock);
        }
        if (!head) {
            break;
        }
        // Leave the in-flight message reachable across fork until it is consumed.
        message *msg = head;
        bool inherited = inherited_tail != nullptr;
        pthread_mutex_unlock(&lock);
        if (!inherited && writable && count < event_limit) {
            writable = print_record(count, *msg);
            if (writable && ++count == event_limit) {
                constexpr char footer[] = "99999 Stopped recording due to size\n";
                write_all(footer, sizeof(footer) - 1);
            }
        }
        pthread_mutex_lock(&lock);
        head = msg->next;
        if (!head) {
            tail = nullptr;
        }
        if (msg == inherited_tail) {
            inherited_tail = nullptr;
        }
        delete msg;
    }
    pthread_mutex_unlock(&lock);
    pthread_mutex_lock(&file_lock);
    if (fd >= 0) {
        syscall(SYS_close, fd);
        fd = -1;
    }
    pthread_mutex_unlock(&file_lock);
    return nullptr;
}

void shutdown_writer()
{
    pthread_mutex_lock(&lock);
    stopping = true;
    bool join = started;
    pthread_cond_signal(&ready);
    pthread_mutex_unlock(&lock);
    if (join) {
        pthread_join(writer, nullptr);
    }
}

void prepare_fork()
{
    pthread_mutex_lock(&file_lock);
    pthread_mutex_lock(&lock);
}

void finish_fork()
{
    pthread_mutex_unlock(&lock);
    pthread_mutex_unlock(&file_lock);
}

void child_fork()
{
    if (fd >= 0) {
        syscall(SYS_close, fd);
        fd = -1;
    }
    inherited_tail = tail;
    started = false;
    stopping = false;
    ready = PTHREAD_COND_INITIALIZER;
    finish_fork();
}

void initialize()
{
    pthread_atfork(prepare_fork, finish_fork, child_fork);
    atexit(shutdown_writer);
}
} // namespace

message *allocate()
{
    int saved = errno;
    auto *msg = new (std::nothrow) message;
    errno = saved;
    return msg;
}

void enqueue(message *msg)
{
    int saved = errno;
    pthread_once(&init, initialize);
    pthread_mutex_lock(&lock);
    if (!stopping && !started) {
        started = pthread_create(&writer, nullptr, consume, nullptr) == 0;
    }
    if (started && !stopping) {
        msg->next = nullptr;
        if (tail) {
            tail->next = msg;
        } else {
            head = msg;
            pthread_cond_signal(&ready);
        }
        tail = msg;
    } else {
        delete msg;
    }
    pthread_mutex_unlock(&lock);
    errno = saved;
}
} // namespace tx_snapshot
