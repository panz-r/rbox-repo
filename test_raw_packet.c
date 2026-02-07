#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define ROBO_MAGIC 0x524F424F
#define ROBO_VERSION 3

int main() {
    printf("Testing raw socket packet send...\n");
    
    // Create socket
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    
    // Connect to server
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/readonlybox.sock", sizeof(addr.sun_path) - 1);
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }
    
    printf("Connected to server\n");
    
    // Build a simple packet
    char packet[256];
    size_t pos = 0;
    
    // Magic
    uint32_t magic = ROBO_MAGIC;
    memcpy(packet + pos, &magic, 4);
    pos += 4;
    
    // Version
    uint32_t version = ROBO_VERSION;
    memcpy(packet + pos, &version, 4);
    pos += 4;
    
    // Client UUID (16 bytes) - use same pattern as client library
    for (int i = 0; i < 8; i++) {
        packet[8 + i] = (i * 0x11) & 0xFF;  // First 8 bytes from timestamp/pid
    }
    for (int i = 8; i < 16; i++) {
        packet[8 + i] = 0xCC;  // Rest is random-ish
    }
    pos += 16;
    
    // Request UUID (16 bytes)
    for (int i = 0; i < 16; i++) {
        packet[24 + i] = (i * 0x22) & 0xFF;
    }
    pos += 16;
    
    // Server UUID (16 bytes, zeroed)
    memset(packet + pos, 0, 16);
    pos += 16;
    
    // ID (1 = REQUEST)
    uint32_t id = 1;
    memcpy(packet + pos, &id, 4);
    pos += 4;
    
    // Argc (2)
    uint32_t argc = 2;
    memcpy(packet + pos, &argc, 4);
    pos += 4;
    
    // Envc (1)
    uint32_t envc = 1;
    memcpy(packet + pos, &envc, 4);
    pos += 4;
    
    // Command
    strcpy(packet + pos, "vim");
    pos += strlen("vim") + 1;
    
    // Arg: --version
    strcpy(packet + pos, "--version");
    pos += strlen("--version") + 1;
    
    // Args terminator
    packet[pos++] = '\0';
    
    // Env: TEST=test
    strcpy(packet + pos, "TEST=test");
    pos += strlen("TEST=test") + 1;
    
    // Envs terminator
    packet[pos++] = '\0';
    
    printf("Packet size: %zu bytes\n", pos);
    printf("Header bytes: ");
    for (size_t i = 0; i < 68 && i < pos; i++) {
        printf("%02x ", (unsigned char)packet[i]);
    }
    printf("\n");
    
    printf("Sending packet...\n");
    
    ssize_t sent = send(fd, packet, pos, 0);
    printf("Sent %zd bytes\n", sent);
    
    // Wait for response
    char resp[256];
    ssize_t received = recv(fd, resp, sizeof(resp), 0);
    printf("Received %zd bytes from server\n", received);
    
    close(fd);
    return 0;
}
