#include <stdio.h>
#include <stdlib.h>
#include "rbox_protocol.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <packet_file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);
    
    char *buf = malloc(len);
    if (!buf) {
        fclose(f);
        return 1;
    }
    
    size_t read = fread(buf, 1, len, f);
    fclose(f);
    
    if (read != (size_t)len) {
        free(buf);
        return 1;
    }
    
    rbox_decoded_header_t h;
    rbox_decode_header(buf, len, &h);
    
    printf("valid=%d\n", h.valid);
    
    free(buf);
    return h.valid ? 0 : 1;
}