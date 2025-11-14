sudo apt-get update
sudo apt-get install -y \
    build-essential clang llvm libelf-dev libbpf-dev \
    bpftool libjson-c-dev pkg-config make git jq \
    linux-headers-$(uname -r)

