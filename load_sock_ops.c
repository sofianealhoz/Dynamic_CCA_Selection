#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <arpa/inet.h> 

#define DEBUGFS "/sys/kernel/debug/tracing/"

struct connection_tuple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

void init_map(int map_fd)
{
    __u32 common_ip = 0x7F000001;  // 127.0.0.1
    __u16 common_src_port = 5001;
    
    struct {
        struct connection_tuple key;
        char value[16];
    } entries[] = {
        {{ common_ip, common_ip, common_src_port, 0 }, "reno"},
        {{ common_ip, common_ip, common_src_port, 5004 }, "cubic"},
        {{ common_ip, common_ip, common_src_port, 5005 }, "illinois"},
        {{ common_ip, common_ip, common_src_port, 5006 }, "vegas"},
        {{ common_ip, common_ip, common_src_port, 5007 }, "bbr"},
        {{ common_ip, common_ip, common_src_port, 5008 }, "westwood"},
        {{ common_ip, common_ip, common_src_port, 5009 }, "highspeed"},
        {{ common_ip, common_ip, common_src_port, 5010 }, "hybla"},
        {{ common_ip, common_ip, common_src_port, 5011 }, "scalable"},
        {{ common_ip, common_ip, common_src_port, 5012 }, "yeah"},
        {{ common_ip, common_ip, common_src_port, 5013 }, "dctcp"},
    };
    
    int i;
    for (i = 0; i < sizeof(entries)/sizeof(entries[0]); i++) {
        if (bpf_map_update_elem(map_fd, &entries[i].key, entries[i].value, BPF_ANY)) {
            fprintf(stderr, "Failed to update map for %s: %s\n", 
                    entries[i].value, strerror(errno));
        }
    }
    
    printf("Map initialized with %d entries\n", i);
}

void read_trace_pipe(void)
{
    int trace_fd;

    trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0)
        return;

    while (1) {
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf));
        if (sz > 0) {
            buf[sz] = 0;
            puts(buf);
        }
    }
    
    close(trace_fd);
}

int main(int argc, char **argv)
{
    int logFlag = 0;
    int error = 0;
    char *cg_path;
    char fn[500];
    char *prog;
    int cg_fd;
    struct bpf_object *obj;
    int prog_fd;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s [-l] <cgroup_path> <program>\n", argv[0]);
        return 1;
    }
    
    if (!strcmp(argv[1], "-l")) {
        logFlag = 1;
        if (argc < 4) {
            fprintf(stderr, "Usage with logging: %s -l <cgroup_path> <program>\n", argv[0]);
            return 1;
        }
    }

    prog = argv[argc - 1];
    cg_path = argv[argc - 2];
    
    if (strlen(prog) > 480) {
        fprintf(stderr, "ERROR: program name too long (> 480 chars)\n");
        return 3;
    }
    
    cg_fd = open(cg_path, O_DIRECTORY, O_RDONLY);
    if (cg_fd < 0) {
        fprintf(stderr, "ERROR: failed to open cgroup path: %s\n", strerror(errno));
        return 2;
    }

    if (!strcmp(prog + strlen(prog) - 2, ".o"))
        strcpy(fn, prog);
    else
        sprintf(fn, "%s_kern.o", prog);
        
    if (logFlag)
        printf("loading bpf file: %s\n", fn);
    
    obj = bpf_object__open_file(fn, NULL);
    if (!obj) {
        printf("ERROR: bpf_object__open_file failed for: %s\n", fn);
        return 4;
    }

    if (bpf_object__load(obj)) {
        printf("ERROR: bpf_object__load failed\n");
        bpf_object__close(obj);
        return 4;
    }

    struct bpf_program *bpf_prog = bpf_object__find_program_by_name(obj, "bpf_basertt");
    if (!bpf_prog) {
        printf("ERROR: bpf_object__find_program_by_name failed\n");
        bpf_object__close(obj);
        return 4;
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (logFlag)
        printf("TCP BPF Loaded %s\n", fn);

    struct bpf_map *key_cong_map = bpf_object__find_map_by_name(obj, "key_cong_map");
    if (!key_cong_map) {
        printf("ERROR: could not find required maps\n");
        bpf_object__close(obj);
        return 4;
    }
    
    int key_cong_map_fd = bpf_map__fd(key_cong_map);
    
    init_map(key_cong_map_fd);
    
    error = bpf_prog_attach(prog_fd, cg_fd, BPF_CGROUP_SOCK_OPS, 0);
    if (error) {
        printf("ERROR: bpf_prog_attach: %d (%s)\n",
               error, strerror(errno));
        bpf_object__close(obj);
        return 5;
    }
    else if (logFlag) {
        int ret_from_fork;
        if ((ret_from_fork = fork()) == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        }
        else if (ret_from_fork == 0) {
            printf("enter read trace pipe\n");
            read_trace_pipe();
            exit(0);
        }
    }
    
    printf("Program attached successfully. Press Ctrl+C to detach and exit.\n");
    
    while (1) {
        sleep(1);
    }
    
    bpf_object__close(obj);
    return error;
}
