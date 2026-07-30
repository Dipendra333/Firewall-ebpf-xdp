#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

#define PINNED_MAP_PATH "/sys/fs/bpf/ip_block_map"

void print_usage(const char *prog_name) {
    printf("Usage:\n");
    printf("  %s add <IP_ADDRESS>   - Add an IP to the blocklist\n", prog_name);
    printf("  %s del <IP_ADDRESS>   - Remove an IP from the blocklist\n", prog_name);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];
    const char *ip_str = argv[2];

    // 1. Convert IP string (e.g. "192.168.1.100") to 32-bit network byte order
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Error: Invalid IPv4 address '%s'\n", ip_str);
        return 1;
    }
    __u32 key = addr.s_addr; // __u32 key for the map

    // 2. Open the pinned eBPF map file descriptor
    int ip_map_fd = bpf_obj_get(PINNED_MAP_PATH);
    if (ip_map_fd < 0) {
        perror("Error opening pinned map at " PINNED_MAP_PATH);
        fprintf(stderr, "Make sure the XDP program is loaded and the map is pinned.\n");
        return 1;
    }

    // 3. Handle 'add' or 'del' command
    if (strcmp(action, "add") == 0) {
        __u8 drop_flag = 1; // Value stored in map
        
        // BPF_ANY will create the key if it doesn't exist or update it if it does
        if (bpf_map_update_elem(ip_map_fd, &key, &drop_flag, BPF_ANY) < 0) {
            perror("Failed to add IP to blocklist map");
            return 1;
        }
        printf("Successfully blocked IP: %s\n", ip_str);

    } else if (strcmp(action, "del") == 0) {
        if (bpf_map_delete_elem(ip_map_fd, &key) < 0) {
            perror("Failed to remove IP from blocklist map (IP might not exist)");
            return 1;
        }
        printf("Successfully unblocked IP: %s\n", ip_str);

    } else {
        fprintf(stderr, "Error: Unknown action '%s'\n", action);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}

