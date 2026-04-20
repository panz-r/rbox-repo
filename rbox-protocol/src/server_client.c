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

/* epoll helper - defined in server.c, declared in server_internal.h */
extern int epoll_del(int epoll_fd, int fd);

/* Time helper - defined in server.c */
extern uint64_t get_time_ms(void);

/* ============================================================
 * CLIENT FD TRACKING
 * ============================================================ */

int client_fd_add(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = malloc(sizeof(*entry));
    if (!entry) {
        close(fd);
        return -1;
    }
    entry->fd = fd;
    entry->pending_request = NULL;
    entry->valid = 1;
    entry->last_activity = get_time_ms();
    entry->header_bytes_read = 0;
    entry->prev = NULL;

    rbox_send_node_t *dummy = malloc(sizeof(*dummy));
    if (!dummy) {
        free(entry);
        close(fd);
        return -1;
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
    atomic_fetch_add(&server->active_client_count, 1);
    pthread_mutex_unlock(&server->client_fd_mutex);
    return 0;
}

void client_fd_remove(rbox_server_handle_t *server, int fd) {
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->fd == fd) {
            if (entry->pending_request) {
                server_request_free(entry->pending_request);
                entry->pending_request = NULL;
            }
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
            atomic_fetch_sub(&server->active_client_count, 1);
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
        epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, entry->fd, NULL);
        close(entry->fd);
        rbox_client_fd_entry_t *next = entry->next;
        free(entry->send_queue.head);
        free(entry);
        entry = next;
    }
    server->client_fds = NULL;
    atomic_store(&server->active_client_count, 0);
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

/* Clean up any send queue entries - caller must hold client_fd_mutex */
void cleanup_pending_sends_locked(rbox_server_handle_t *server, rbox_client_fd_entry_t *client) {
    rbox_server_send_entry_t *send_entry;
    while ((send_entry = send_queue_dequeue(client)) != NULL) {
        if (send_entry->request) {
            send_entry->request->fd = -1;
            server_request_free(send_entry->request);
        }
        send_pool_put(server, send_entry);
    }
}

/* Centralized function to close a client connection and free all associated resources.
 * Called from server thread only - no external callers, no locking needed. */
void client_connection_close(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = client_fd_find_unlocked(server, fd);
    if (!entry) return;
    client_connection_close_locked(server, entry);
}

/* Close a client connection - takes entry directly to avoid redundant lookup.
 * Called from server thread only - no external callers, no locking needed. */
void client_connection_close_locked(rbox_server_handle_t *server, rbox_client_fd_entry_t *entry) {
    if (!entry) return;
    int fd = entry->fd;

    /* Mark as closed/invalid before any other operations */
    entry->valid = 0;
    entry->pending_request = NULL;

    cleanup_pending_sends_locked(server, entry);

    /* Cancel any active timer for this fd */
    rbox_timer_remove(server->timer_heap, fd);

    epoll_del(server->epoll_fd, fd);
    close(fd);

    /* Remove from client list - caller holds mutex, so use _unlocked variant */
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
    atomic_fetch_sub(&server->active_client_count, 1);
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

/* Find client entry by fd - caller must hold client_fd_mutex */
rbox_client_fd_entry_t *client_fd_find_unlocked(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->fd == fd) {
            return entry;
        }
        entry = entry->next;
    }
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
    int count = atomic_load(&server->active_client_count);
    pthread_mutex_unlock((pthread_mutex_t *)&server->client_fd_mutex);
    return count;
}