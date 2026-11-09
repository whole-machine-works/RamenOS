/* Linux host controls for the optional PID-1 snapshot helpers; never boots a guest. */
#define STORE0_PCI_SNAPSHOT 1
#define main store0_guest_main
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
#include "virtio_blk_flush_oracle_capture.c"
#pragma GCC diagnostic pop
#undef main
#include <assert.h>

int main(void) {
    assert(valid_pci_bdf("0000:00:01.0"));
    assert(valid_pci_bdf("ffff:ff:1f.7"));
    assert(!valid_pci_bdf("0000:00:20.0"));
    assert(!valid_pci_bdf("0000:00:01.8"));
    assert(!valid_pci_bdf("0000:00:01.0x"));
    assert(!valid_pci_bdf("0000:00:0A.0"));
    assert(valid_pci_bdf("0000:00:01.0"));
    char temp[] = "/tmp/store0-pci-test-XXXXXX";
    assert(mkdtemp(temp));
    int dir = open(temp, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(dir >= 0);
    unsigned char input[256], output[256];
    for (unsigned i = 0; i < sizeof(input); i++) input[i] = (unsigned char)i;
    int fd = openat(dir, "config", O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, input, 255) == 255 && close(fd) == 0);
    assert(!read_pci_config(dir, output, false));
    fd = openat(dir, "config", O_WRONLY | O_TRUNC);
    assert(fd >= 0 && write(fd, input, sizeof(input)) == (ssize_t)sizeof(input));
    assert(close(fd) == 0 && read_pci_config(dir, output, false));
    assert(memcmp(input, output, sizeof(input)) == 0);
    assert(unlinkat(dir, "config", 0) == 0);
    assert(symlinkat("/dev/zero", dir, "config") == 0);
    assert(!read_pci_config(dir, output, false));
    assert(unlinkat(dir, "config", 0) == 0);
    fd = openat(dir, "config", O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, input, sizeof(input)) == (ssize_t)sizeof(input));
    assert(close(fd) == 0 && read_pci_config(dir, output, false));
    assert(unlinkat(dir, "config", 0) == 0 && close(dir) == 0 && rmdir(temp) == 0);
    return 0;
}
