/*
 * server_client.c - Client connection tracking for rbox-protocol server
 *
 * Layer 5: Client connection tracking
 */

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "rbox_protocol.h"
#include "server_internal.h"
#include "server_client.h"

void rbox_server_client_add(rbox_server_handle_t *server, int fd) {
    if (!server || fd < 0) return;
    rbox_client_fd_entry_t *entry = malloc(sizeof(*entry));
    if (!entry) return;
    entry->fd = fd;
    pthread_mutex_lock(&server->client_fd_mutex);
    entry->next = server->client_fds;
    server->client_fds = entry;
    server->active_client_count++;
    pthread_mutex_unlock(&server->client_fd_mutex);
}

void rbox_server_client_remove(rbox_server_handle_t *server, int fd) {
    if (!server || fd < 0) return;
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t **prev = &server->client_fds;
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->fd == fd) {
            *prev = entry->next;
            free(entry);
            server->active_client_count--;
            break;
        }
        prev = &entry->next;
        entry = entry->next;
    }
    pthread_mutex_unlock(&server->client_fd_mutex);
}

void rbox_server_client_close_all(rbox_server_handle_t *server) {
    if (!server) return;
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        close(entry->fd);
        rbox_client_fd_entry_t *next = entry->next;
        free(entry);
        entry = next;
    }
    server->client_fds = NULL;
    server->active_client_count = 0;
    pthread_mutex_unlock(&server->client_fd_mutex);
}

int rbox_server_client_count(const rbox_server_handle_t *server) {
    if (!server) return 0;
    pthread_mutex_lock((pthread_mutex_t *)&server->client_fd_mutex);
    int count = server->active_client_count;
    pthread_mutex_unlock((pthread_mutex_t *)&server->client_fd_mutex);
    return count;
}