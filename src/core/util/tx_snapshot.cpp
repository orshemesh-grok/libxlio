/*
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "util/tx_snapshot.h"

#include <algorithm>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <cinttypes>
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
    char line[2 * limit + (limit - 1) / group_size + 640];
    int n = snprintf(line, sizeof(line), "%05u %s pid=%ld qp=%u wqe=%u ", number, msg.event,
                     (long)getpid(), msg.qp, msg.wqe);
    if (msg.nfields) {
        for (unsigned i = 0; i < msg.nfields; ++i) {
            field f;
            memcpy(&f, msg.bytes + i * sizeof(f), sizeof(f));
            n += snprintf(line + n, sizeof(line) - n, "%s=%" PRIu64 " ", f.name, f.value);
        }
        n += snprintf(line + n, sizeof(line) - n, "%s\n", msg.bytes + msg.nfields * sizeof(field));
        return write_all(line, n);
    }
    if (msg.cq_record) {
        n += snprintf(line + n, sizeof(line) - n, "cqn=%u cq_ci=%u ", msg.cqn, msg.cq_ci);
    }
    if (msg.api_send) {
        n += snprintf(line + n, sizeof(line) - n, "requested_bytes=%zu ", msg.requested);
    }
    if (msg.dm_copy) {
        const auto &d = msg.copy;
        n += snprintf(line + n, sizeof(line) - n,
                      "sge=%d sge_count=%d frame_offset=%zu host=0x%" PRIxPTR
                      " dm_handle=%u dm_offset=0x%zx lkey=0x%x allocation=%zu logical_len=%zu "
                      "copy_len=%zu copy_rc=%d read_len=%zu read_rc=%d ",
                      d.site.sge, d.site.sge_count, d.site.frame_offset, d.host, d.handle,
                      d.dm_offset, d.lkey, d.allocation, d.logical_length, d.copy_length, d.copy_rc,
                      d.read_length, d.read_rc);
    }
    if (msg.stage) {
        n += snprintf(line + n, sizeof(line) - n, "stage=%s offset=%zu total=%zu ", msg.stage,
                      msg.offset, msg.total);
        if (msg.segment >= 0) {
            n += snprintf(line + n, sizeof(line) - n,
                          "segment=%d addr=0x%" PRIx64 " lkey=0x%x read_len=%zu read_rc=%d ",
                          msg.segment, msg.address, msg.lkey, msg.read_length, msg.read_rc);
        }
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

bool read_dm()
{
    static const bool enabled = [] {
        const char *v = getenv("XLIO_TX_SNAPSHOT_SKIP_DM_READBACK");
        return !v || strcmp(v, "1") != 0;
    }();
    return enabled;
}

void metadata(const char *event, unsigned qp, unsigned wqe, std::initializer_list<field> fields,
              const char *description)
{
    auto *msg = allocate();
    if (!msg) {
        return;
    }
    size_t used = fields.size() * sizeof(field);
    if (used >= limit || !used) {
        delete msg;
        return;
    }
    msg->qp = qp;
    msg->wqe = wqe;
    msg->event = event;
    msg->nfields = fields.size();
    memcpy(msg->bytes, fields.begin(), used);
    size_t n = strnlen(description, limit - used - 1);
    memcpy(msg->bytes + used, description, n);
    msg->bytes[used + n] = 0;
    enqueue(msg);
}

void raw_entry(const char *event, unsigned qp, unsigned wqe, const uint8_t *ring, size_t ring_size,
               size_t start, size_t length, unsigned cqn, unsigned ci)
{
    for (size_t offset = 0; offset < length; offset += limit) {
        auto *msg = allocate();
        if (!msg) {
            return;
        }
        msg->event = event;
        msg->stage = event;
        msg->cq_record = strcmp(event, "TX_CQE") == 0;
        msg->cqn = cqn;
        msg->cq_ci = ci;
        msg->qp = qp;
        msg->wqe = wqe;
        msg->storage = "queue";
        msg->api_send = false;
        msg->total = length;
        msg->offset = offset;
        msg->size = std::min(limit, length - offset);
        size_t pos = (start + offset) % ring_size;
        size_t first = std::min(msg->size, ring_size - pos);
        memcpy(msg->bytes, ring + pos, first);
        memcpy(msg->bytes + first, ring, msg->size - first);
        enqueue(msg);
    }
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
