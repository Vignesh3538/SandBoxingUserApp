# Architecture

This document describes the internal architecture of the eBPF-based application-sandboxing system.  
The system enforces policies on selected user applications using **BPF LSM (Linux Security Module) hooks**, shared **BPF maps**, and a set of **userspace managers**.

---

## 1. Components Overview

The system consists of three major components:

1. **BPF Data Structures (Maps)**  
   Shared sructure used by both userspace managers and kernel-space eBPF programs, created and pinned during make time.

2. **Userspace Parsers / Initializers / Refreshers**  
   Responsible for configuration file parsing, map initialization, DNS refresh, loading and unloading eBPF programs.

3. **eBPF Programs**  
   Gets loaded and attached to LSM hook points. Enforce policy at runtime at kernel level.

---

## 2. BPF Data Structures

These maps form the core policy datastore for the sandbox.  
All maps are pinned under `/sys/fs/bpf/`.

### BPF Maps Table

| BPF Map Name       | Key          | Value        | Accessed By              | Functionality |
|--------------------|------------------|--------------------|---------------------------|---------------|
| `inodepolicy_map`  | inode, dev number     | app path   | Userspace managers, kernel  | Maps executable path for sandbox identification |
| `proc_map`         | tgid        | count          | Kernel only               | Tracks the tgids belonging to sandboxed applications |
| `dom_map`          | domain name      | allowed flag  | Userspace managers only     | List of allowed domains for network access |
| `loc_ip_map`       | IPv4             | allowed flag       | Userspace managers, kernel  | To permit local ips regardless of port |
| `allow_wdir_map`   | inode, dev number   | allowed flag       | Userspace managers, kernel              | Defines allowed write/create directories |
| `ip_map`           | IPv4             | allowed flag       | Userspace managers, kernel   | Whitelisted remote IP addresses for sandboxed apps |
| `block_env_arr`    | env var name           | denied flag      | User space managers, kernel         | Environment variables to be blocked for sandboxed apps |

---

## 3. Userspace Components

### a) Parser / Initializer
- Parses `config.json`.
- Initializes all BPF maps with:
  - Application paths
  - Allowed directories
  - Allowed domain names
  - Blocked env vars
- Launches the IP updater.

### b) `dom_ip_updater`
- Performs DNS lookups for all entries in `dom_map`.
- Updates new IPs in `ip_map`.
- Runs:
  - Once during initialization
  - Every hour via cron (for dynamic IP changes).

### c) `attach_lsm_loader`
- Loads all eBPF `.bpf.o` / `.skel.h` files:
  - `process_mapper`
  - `process_remover`
  - `filewrite_enforcer`
  - `filecreate_enforcer`
  - `netaccess_enforcer`
  - `child_process_mapper`
- Reuses already-pinned BPF maps across all programs.
- Attaches each program to the appropriate LSM hook.
- Pins all links at `/sys/fs/bpf/...`.

### d) `detach_lsm_remover`
- Unpins all pinned BPF links.
- Unloads all programs.
- Removes pinned maps.

---

## 4. eBPF Programs

Each eBPF program runs at a specific LSM hook and enforces policy using the shared maps.

### eBPF Program Table

| eBPF Program Name        | LSM Hook Point     | Maps Accessed                     | Functionality |
|-------------------------|--------------------|-----------------------------------|---------------|
| `process_mapper`        | `bprm_check_security`       | `inodepolicy_map`, `proc_map`, `block_env_arr` | Marks new tgids when sandboxed app executes, blocks when it has access to  denied env vars  |
| `process_remover`       | `task_free`        | `proc_map`                        | Updates/removes tgids when the task exits |
| `filewrite_enforcer`    | `file_open`  | `proc_map`, `allow_wdir_map`      | Blocks write attempts to disallowed directories |
| `filecreate_enforcer`   | `inode_create`     | `proc_map`, `allow_wdir_map`      | Blocks creation of files in disallowed directories |
| `netaccess_enforcer`    | `socket_connect`   | `proc_map`, `ip_map`, `loc_ip_map` | Blocks outbound connections to non-whitelisted IPs and ports other than 80 and 443 |
| `child_process_mapper`  | `task_alloc`       | `proc_map`                        | Propagates sandboxing from parent to child task |

---

## 5. Implementation Notes

- All eBPF code is compiled using **Clang**  
  Produces verifiable, portable BPF bytecode.

- Policy changes do **not** require ebpf program rebuilds.  
  Only the maps are updated dynamically.

 

---

