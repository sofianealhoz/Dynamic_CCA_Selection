#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct log_event {
    __u64 timestamp;
    __u32 remote_ip;
    __u32 op;
    __u32 event_type;
    __u32 ret_code;
    char cca_name[16];
};

// Codes d'événements
#define EVENT_SOCKOPS           1
#define EVENT_PASSIVE_EST       2
#define EVENT_ALREADY_CONFIG    3
#define EVENT_FIRST_CONNECTION  4
#define EVENT_RULE_FOUND        5
#define EVENT_RULE_NOT_FOUND    6
#define EVENT_BEFORE_CHANGE     7
#define EVENT_AFTER_CHANGE      8
#define EVENT_SUCCESS           9
#define EVENT_FAILED           10

static volatile int stop = 0;

const char* event_type_to_string(__u32 event_type) {
    switch(event_type) {
        case EVENT_SOCKOPS:           return "sockops_event";
        case EVENT_PASSIVE_EST:       return "passive_established";
        case EVENT_ALREADY_CONFIG:    return "already_configured";
        case EVENT_FIRST_CONNECTION:  return "first_connection";
        case EVENT_RULE_FOUND:        return "cca_rule_found";
        case EVENT_RULE_NOT_FOUND:    return "no_cca_rule_found";
        case EVENT_BEFORE_CHANGE:     return "before_cca_change";
        case EVENT_AFTER_CHANGE:      return "after_cca_change";
        case EVENT_SUCCESS:           return "cca_applied_successfully";
        case EVENT_FAILED:            return "cca_apply_failed";
        default:                      return "unknown_event";
    }
}

void sig_handler(int sig) {
    printf("\nStopping BPF log reader...\n");
    stop = 1;
}

int handle_event(void *ctx, void *data, size_t len) {
    struct log_event *event = (struct log_event *)data;
    
    double timestamp_ms = (double)event->timestamp / 1000000.0;
    
    struct in_addr addr = {.s_addr = event->remote_ip};
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    
    const char* event_name = event_type_to_string(event->event_type);
    
    printf("[%.3f ms] %s (IP: %s, op: %u", 
           timestamp_ms, event_name, ip_str, event->op);
    
    if (event->cca_name[0] != '\0') {
        printf(", CCA: %s", event->cca_name);
    }
    
    if (event->ret_code != 0) {
        printf(", ret: %d", event->ret_code);
    }
    
    printf(")\n");
    fflush(stdout);
    
    return 0;
}

int main(int argc, char *argv[]) {
    printf("🔍 BPF Log Reader - Ring Buffer Mode\n");
    printf("Press Ctrl+C to stop\n\n");
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    int map_fd = bpf_obj_get("/sys/fs/bpf/log_events");
    if (map_fd < 0) {
        fprintf(stderr, "❌ Failed to open ring buffer: %s\n", strerror(errno));
        fprintf(stderr, "Make sure load_sock_ops is running with ring buffer support\n");
        return 1;
    }
    
    printf("✅ Ring buffer opened successfully\n");
    
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "❌ Failed to create ring buffer\n");
        close(map_fd);
        return 1;
    }
    
    printf("📊 Waiting for BPF events...\n\n");
    
    while (!stop) {
        int ret = ring_buffer__poll(rb, 100);
        if (ret < 0 && ret != -EINTR) {
            fprintf(stderr, "❌ Error polling: %d\n", ret);
            break;
        }
    }
    
    ring_buffer__free(rb);
    close(map_fd);
    printf("✅ Stopped\n");
    return 0;
}