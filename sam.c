#include <unistd.h>
int main() {
    execl("/bin/ls", "ls", NULL);
    return 0;
}

