#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
//#include <bpf/bpf.h>
//#include "bpf_load.h"
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

#define DEBUGFS "/sys/kernel/debug/tracing"
////
////
////
////

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
	////

	
	if (!strcmp(argv[1], "-l"))
	{
		logFlag = 1;
		////
	}

	prog = argv[argc - 1];
	cg_path = argv[argc - 2];
	if (strlen(prog) > 480)
	{
		fprintf(stderr, "ERROR: program name too long (> 480 chars)\n");
		return 3;
	}
	cg_fd = open(cg_path, O_DIRECTORY, O_RDONLY);

	if (!strcmp(prog + strlen(prog) - 2, ".o"))
		strcpy(fn, prog);
	else
		sprintf(fn, "%s_kern.o", prog);
	if (logFlag)
		printf("loading bpf file:%s\n", fn);
	

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

	struct bpf_map *cong_map = bpf_object__find_map_by_name(obj, "cong_map");
   	struct bpf_map *ip_cong_map = bpf_object__find_map_by_name(obj, "ip_cong_map");
    
    	if (!cong_map || !ip_cong_map) {
      	  printf("ERROR: could not find required maps\n");
       	  bpf_object__close(obj);
       	  return 4;
   	}
    
   	int cong_map_fd = bpf_map__fd(cong_map);
    	int ip_cong_map_fd = bpf_map__fd(ip_cong_map);
    
    	// Attacher le programme
    	error = bpf_prog_attach(prog_fd, cg_fd, BPF_CGROUP_SOCK_OPS, 0);
    	if (error) {
        	printf("ERROR: bpf_prog_attach: %d (%s)\n",
               	       error, strerror(errno));
                bpf_object__close(obj);
                return 5;
        }
	else if (logFlag)
	{
		int ret_from_fork;
		if ((ret_from_fork = fork()) == -1)
		{
			perror("fork");
			exit(EXIT_FAILURE);
		}
		////
		else
		{
			printf("enter read trace pip\n");
			read_trace_pipe();
			bpf_object__close(obj);
			return 0;

		}
	}
	
	bpf_object__close(obj);
	return error;
}
