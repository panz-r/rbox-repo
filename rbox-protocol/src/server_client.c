/*
 * server_client.c - Client connection tracking for rbox-protocol server
 *
 * Layer 5: Client connection tracking
 * - Track active client file descriptors
 * - Add/remove client connections
 * - Close all clients on shutdown
 * - Per-client send queues with lock-free MPSC
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <time.h>
#include <errno.h>
#include "rbox_protocol.h"
#include "server_internal.h"
#include "server_client.h"

/* epoll helper */
static int epoll_del(int epoll_fd, int fd) {
    struct epoll_event ev = {0};
    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);
}

/* ============================================================
 * CLIENT FD TRACKING
 * ============================================================ */

void client_fd_add(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = malloc(sizeof(*entry));
    if (!entry) return;
    entry->fd = fd;
    entry->pending_request = NULL;
    entry->header_start_time = 0;
    entry->waiting_for_header = 0;
    entry->last_activity = time(NULL);
    entry->prev = NULL;

    rbox_send_node_t *dummy = malloc(sizeof(*dummy));
    if (!dummy) {
        free(entry);
        return;
    }
    dummy->entry = NULL;
    atomic_store_explicit(&dummy->next, NULL, memory_order_relaxed);
    atomic_store_explicit(&entry->send_queue.head, dummy, memory_order_relaxed);
    atomic_store_explicit(&entry->send_queue.tail, dummy, memory_order_relaxed);

    pthread_mutex_lock(&server->client_fd_mutex);
    entry->next = server->client_fds;
    if (server->client_fds) {
        server->client_fds->prev = entry;
    }
    server->client_fds = entry;
    server->active_client_count++;
    pthread_mutex_unlock(&server->client_fd_mutex);
}

void client_fd_remove(rbox_server_handle_t *server, int fd) {
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->fd == fd) {
            if (entry->prev) {
                entry->prev->next = entry->next;
            } else {
                server->client_fds = entry->next;
            }
            if (entry->next) {
                entry->next->prev = entry->prev;
            }
            free(entry->send_queue.head);
            free(entry);
            server->active_client_count--;
            break;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&server->client_fd_mutex);
}

void client_fd_close_all(rbox_server_handle_t *server) {
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->pending_request) {
            server_request_free(entry->pending_request);
            entry->pending_request = NULL;
        }
        rbox_server_send_entry_t *send_entry;
        while ((send_entry = send_queue_dequeue(entry)) != NULL) {
            if (send_entry->request) {
                send_entry->request->fd = -1;
                server_request_free(send_entry->request);
            }
            send_pool_put(server, send_entry);
        }
        close(entry->fd);
        rbox_client_fd_entry_t *next = entry->next;
        free(entry->send_queue.head);
        free(entry);
        entry = next;
    }
    server->client_fds = NULL;
    server->active_client_count = 0;
    pthread_mutex_unlock(&server->client_fd_mutex);
}

/* ============================================================
 * SEND QUEUE - Lock-free MPSC per-client queues
 * ============================================================ */

/* Lock-free enqueue for per-client send queue (Michael & Scott MPSC) */
int send_queue_enqueue(rbox_client_fd_entry_t *client, rbox_server_send_entry_t *entry) {
    rbox_send_node_t *node = malloc(sizeof(*node));
    if (!node) return -1;
    node->entry = entry;
    atomic_store_explicit(&node->next, NULL, memory_order_relaxed);

    rbox_send_node_t *tail, *next;
    while (1) {
        tail = atomic_load_explicit(&client->send_queue.tail, memory_order_acquire);
        next = atomic_load_explicit(&tail->next, memory_order_acquire);
        if (next == NULL) {
            if (atomic_compare_exchange_weak_explicit(&tail->next, &next, node,
                                                      memory_order_release, memory_order_relaxed)) {
                atomic_compare_exchange_strong_explicit(&client->send_queue.tail, &tail, node,
                                                        memory_order_release, memory_order_relaxed);
                break;
            }
        } else {
            atomic_compare_exchange_weak_explicit(&client->send_queue.tail, &tail, next,
                                                  memory_order_release, memory_order_relaxed);
        }
    }
    return 0;
}

/* Lock-free dequeue for per-client send queue - consumer (server thread) only */
rbox_server_send_entry_t *send_queue_dequeue(rbox_client_fd_entry_t *client) {
    rbox_send_node_t *head, *next;
    while (1) {
        head = atomic_load_explicit(&client->send_queue.head, memory_order_acquire);
        next = atomic_load_explicit(&head->next, memory_order_acquire);
        if (next == NULL) {
            return NULL;
        }
        if (atomic_compare_exchange_weak_explicit(&client->send_queue.head, &head, next,
                                                  memory_order_acquire, memory_order_relaxed)) {
            rbox_server_send_entry_t *entry = next->entry;
            free(head);
            return entry;
        }
    }
}

/* Peek at the first entry in the queue without removing it.
 * Returns NULL if queue is empty. */
rbox_server_send_entry_t *send_queue_peek(rbox_client_fd_entry_t *client) {
    rbox_send_node_t *head = atomic_load_explicit(&client->send_queue.head, memory_order_acquire);
    rbox_send_node_t *next = atomic_load_explicit(&head->next, memory_order_acquire);
    if (next == NULL) {
        return NULL;
    }
    return next->entry;
}

/* Clean up any send queue entries for a closed fd - drain the lock-free queue */
void cleanup_pending_sends(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    if (!entry) return;

    rbox_server_send_entry_t *send_entry;
    while ((send_entry = send_queue_dequeue(entry)) != NULL) {
        if (send_entry->request) {
            send_entry->request->fd = -1;
            server_request_free(send_entry->request);
        }
        send_pool_put(server, send_entry);
    }

    entry->waiting_for_header = 0;
    entry->header_start_time = 0;
}

/* Centralized function to close a client connection and free all associated resources */
void client_connection_close(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    if (!entry) return;

    if (entry->pending_request) {
        server_request_free(entry->pending_request);
        entry->pending_request = NULL;
    }

    cleanup_pending_sends(server, fd);

    epoll_del(server->epoll_fd, fd);
    close(fd);
    client_fd_remove(server, fd);
}

/* ============================================================
 * CLIENT FD LOOKUP
 * ============================================================ */

rbox_client_fd_entry_t *client_fd_find(rbox_server_handle_t *server, int fd) {
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->fd == fd) {
            pthread_mutex_unlock(&server->client_fd_mutex);
            return entry;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&server->client_fd_mutex);
    return NULL;
}

/* ============================================================
 * PUBLIC API (for compatibility)
 * ============================================================ */

void rbox_server_client_add(rbox_server_handle_t *server, int fd) {
    client_fd_add(server, fd);
}

void rbox_server_client_remove(rbox_server_handle_t *server, int fd) {
    client_fd_remove(server, fd);
}

void rbox_server_client_close_all(rbox_server_handle_t *server) {
    client_fd_close_all(server);
}

int rbox_server_client_count(const rbox_server_handle_t *server) {
    if (!server) return 0;
    pthread_mutex_lock((pthread_mutex_t *)&server->client_fd_mutex);
    int count = server->active_client_count;
    pthread_mutex_unlock((pthread_mutex_t *)&server->client_fd_mutex);
    return count;
}