# Makefile for BPF Policy Engine

CC = gcc
CLANG = clang
CFLAGS = -O2 -g
BPF_FLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I.

BPF_OBJS = netaccess_enforcer.bpf.o \
           child_process_mapper.bpf.o \
           process_mapper.bpf.o \
           process_remover.bpf.o \
           filewrite_enforcer.bpf.o \
           filecreate_enforcer.bpf.o

BPF_SKELS = $(BPF_OBJS:.bpf.o=.skel.h)

USER_PROGS = dom_ip_updater parser attach_lsm_loader detach_lsm_remover

MAPS = dom_map ip_map loc_ip_map block_env_arr inodepolicy_map \
       proc_policy_map allow_wdir_map proc_map

.PHONY: all clean maps bpf user attach run_parser

all: maps bpf user attach

maps:
	@echo "[INFO] Initializing BPF filesystem and required maps"
	mkdir -p /sys/fs/bpf
	mount -t bpf bpffs /sys/fs/bpf || true
	@for m in $(MAPS); do \
		bpftool map show pinned /sys/fs/bpf/$$m >/dev/null 2>&1 || \
		{ \
			if [ "$$m" = "dom_map" ]; then \
				bpftool map create /sys/fs/bpf/$$m type hash key 256 value 4 entries 64 name $$m; \
			elif [ "$$m" = "ip_map" ]; then \
				bpftool map create /sys/fs/bpf/$$m type hash key 4 value 4 entries 8192 name $$m; \
			elif [ "$$m" = "loc_ip_map" ]; then \
				bpftool map create /sys/fs/bpf/$$m type hash key 4 value 4 entries 20 name $$m; \
			elif [ "$$m" = "block_env_arr" ]; then \
				bpftool map create /sys/fs/bpf/$$m type hash key 32 value 4 entries 16 name $$m; \
			elif [ "$$m" = "inodepolicy_map" ]; then \
				bpftool map create /sys/fs/bpf/$$m type hash key 16 value 4 entries 64 name $$m; \
			elif [ "$$m" = "proc_policy_map" ]; then \
				bpftool map create /sys/fs/bpf/$$m type hash key 16 value 4 entries 4096 name $$m; \
			elif [ "$$m" = "allow_wdir_map" ]; then \
				bpftool map create /sys/fs/bpf/$$m type hash key 16 value 4 entries 64 name $$m; \
			elif [ "$$m" = "proc_map" ]; then \
				bpftool map create /sys/fs/bpf/$$m type hash key 4 value 4 entries 4096 name $$m; \
			fi; \
		}; \
	done

bpf:
	@echo "[INFO] Compiling BPF programs and generating skeleton headers"
	$(CLANG) $(BPF_FLAGS) -c netaccess_enforcer.bpf.c -o netaccess_enforcer.bpf.o
	bpftool gen skeleton netaccess_enforcer.bpf.o > netaccess_enforcer.skel.h

	$(CLANG) $(BPF_FLAGS) -c child_process_mapper.bpf.c -o child_process_mapper.bpf.o
	bpftool gen skeleton child_process_mapper.bpf.o > child_process_mapper.skel.h

	$(CLANG) $(BPF_FLAGS) -c process_mapper.bpf.c -o process_mapper.bpf.o
	bpftool gen skeleton process_mapper.bpf.o > process_mapper.skel.h

	$(CLANG) $(BPF_FLAGS) -c process_remover.bpf.c -o process_remover.bpf.o
	bpftool gen skeleton process_remover.bpf.o > process_remover.skel.h

	$(CLANG) $(BPF_FLAGS) -c filewrite_enforcer.bpf.c -o filewrite_enforcer.bpf.o
	bpftool gen skeleton filewrite_enforcer.bpf.o > filewrite_enforcer.skel.h

	$(CLANG) $(BPF_FLAGS) -c filecreate_enforcer.bpf.c -o filecreate_enforcer.bpf.o
	bpftool gen skeleton filecreate_enforcer.bpf.o > filecreate_enforcer.skel.h

user: bpf
	@echo "[INFO] Building user-space components"
	$(CC) $(CFLAGS) dom_ip_updater.c -o dom_ip_updater -ljson-c -lbpf
	$(CC) $(CFLAGS) parser.c -o parser -ljson-c -lbpf
	$(CC) $(CFLAGS) attach_lsm_loader.c -o attach_lsm_loader -lelf -lbpf
	$(CC) $(CFLAGS) detach_lsm_remover.c -o detach_lsm_remover -lelf -lbpf


run_parser: user
	@echo "[INFO] Executing configuration parser"
	./parser ./config.json

attach: run_parser
	@echo "[INFO] Attaching LSM enforcement programs"
	./attach_lsm_loader

clean:
	@echo "[INFO] Cleaning environment and removing generated artifacts"

	./detach_lsm_remover
	@if [ -d /var/log/dom_ip_updater ]; then \
		echo "  - Removing log directory contents"; \
		rm -f /var/log/dom_ip_updater/*; \
		rmdir /var/log/dom_ip_updater 2>/dev/null || true; \
	fi

	@echo "  - Updating crontab to remove last managed entry"; \
	tmp=$$(mktemp); \
	crontab -l 2>/dev/null | sed '$$d' > $$tmp; \
	crontab $$tmp 2>/dev/null || true; \
	rm -f $$tmp;

	@echo "[INFO] Removing build outputs"
	@rm -f *.o *.bpf.o *.skel.h $(USER_PROGS)
	@echo "[INFO] Cleanup completed successfully"

