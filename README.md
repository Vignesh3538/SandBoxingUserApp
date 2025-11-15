# <div align="center">**BPF LSM Based Application Sandboxing**</div>
<p align="center">
  <img src="https://img.shields.io/badge/Kernel-Linux%20Only-black?style=flat&logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/BPF--LSM%20Support-Required-critical?style=flat" />
  <img src="https://img.shields.io/badge/Status-Demo%20%2F%20POC-yellow?style=flat" />
</p>

## ⚠️ **Important Notes**
> **This project loads eBPF programs into the Linux kernel and attaches them to LSM security hooks.**  
> **This modifies kernel behavior at runtime.**
>
> - It enforces sandbox rules  
> - It can block file writes, process execution, network activity  
> - It affects all matching processes on the system  
> - Requires **root** permissions  
> - Requires a kernel with **BPF-LSM support**  

---

## **Getting Started with eBPF**

eBPF allows writing safe programs supporting dynamic in-kernel execution without recompiling or patching the kernel.  
It enables security enforcement, and per-process sandboxing.  
With BPF-LSM hooks, we can enforce custom security policies efficiently.

---

## **Policy Configuration**

A JSON configuration file is available at **/src/config.json**.  
It defines things like:

- Applications to be sandboxed
- Allowed write directories  
- Allowed network domains  
- Denied env vars  

The parser reads this file and populates BPF maps accordingly.

---

## **Demo Setup**

### **1. Verify Kernel Support**

Required kernel options: BPF, LSM stacking.  
Check using grep:
```bash
grep BPF /boot/config-$(uname -r)
grep LSM /boot/config-$(uname -r)
```
The line "CONFIG_BPF_LSM=y" implies your kernel supports BPF LSM.

Boot parameters must contain:

`lsm=lockdown,capability,landlock,yama,bpf,apparmor`

(If missing, update `/etc/default/grub`, run `sudo update-grub`, and reboot.)

---

### **2. Install Dependencies**

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential clang llvm libelf-dev libbpf-dev \
    bpftool libjson-c-dev pkg-config make git jq \
    linux-headers-$(uname -r)
```
    
---
### **3. Build the Project**

```bash
git clone https://github.com/Vignesh3538/SandBoxingUserApp.git
cd src
make
```
---
### **4. Test the policies**
Run any application given in json file normally.
BPF-LSM hooks will:

- Allow or deny file creation
- Allow or deny file writes
- Allow or deny socket connections
- Allow or deny executing application when it has access to env vars needed to be secured 

You can observe decisions via:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
---
### **5. Clean the environment**
```bash
make clean
```
