/* Bounded PID-1 Linux Oracle producer. This is not native RamenOS device IO. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#ifdef STORE0_PCI_SNAPSHOT
#include <limits.h>
#endif
#include <linux/fs.h>
#include <linux/reboot.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/io.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define CMDLINE_MAX 4096u
#define DISK_BYTES UINT64_C(4194304)
#define SECTOR_BYTES 512u
#define TEST_OFFSET 4096
#define PREFIX "RAMEN_STORE0_ORACLE_V0 "
#define MARKER_PORT 0xe9u

static const char *phase;
static char nonce[33];
static unsigned sequence;
static bool serial_ok = true;
static int disk = -1;
static _Alignas(4096) unsigned char data[4096];
static _Alignas(4096) unsigned char intended[4096];

static unsigned char marker_read(void) {
    unsigned char value;
    __asm__ volatile("inb %w1, %0" : "=a"(value) : "Nd"((unsigned short)MARKER_PORT) : "memory");
    return value;
}

static void marker_write(unsigned char value) {
    __asm__ volatile("outb %0, %w1" : : "a"(value), "Nd"((unsigned short)MARKER_PORT) : "memory");
}

static void poweroff(void) {
    (void)syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                  LINUX_REBOOT_CMD_POWER_OFF, NULL);
    for (;;) pause();
}

/* Exactly one bounded write per row; a failed or short serial write is fatal. */
static bool emit(const char *fields, ...) {
    char line[2048];
    va_list args;
    int used = snprintf(line, sizeof(line), PREFIX "{\"seq\":%u,\"nonce\":\"%s\",\"phase\":\"%s\",",
                        sequence + 1, nonce, phase);
    if (used < 0 || (size_t)used >= sizeof(line)) goto failed;
    va_start(args, fields);
    int count = vsnprintf(line + used, sizeof(line) - (size_t)used, fields, args);
    va_end(args);
    if (count < 0 || (size_t)count >= sizeof(line) - (size_t)used) goto failed;
    size_t length = (size_t)used + (size_t)count;
    if (length + 2 >= sizeof(line)) goto failed;
    line[length++] = '}';
    line[length++] = '\n';
    if (write(STDOUT_FILENO, line, length) != (ssize_t)length) goto failed;
    sequence++;
    return true;
failed:
    serial_ok = false;
    return false;
}

static void done(const char *reason) {
    int close_result = 0;
    int close_error = 0;
    bool had_disk = disk >= 0;
    if (had_disk) {
        errno = 0;
        close_result = close(disk);
        close_error = close_result == -1 ? errno : 0;
        disk = -1;
        if (close_result != 0 && strcmp(reason, "ok") == 0) reason = "close_failed";
    }
    if (serial_ok && phase != NULL) {
        if (emit("\"kind\":\"terminal\",\"reason\":\"%s\",\"close_attempted\":%s,\"close_return\":%d,\"close_errno\":%d",
                 reason, had_disk ? "true" : "false", close_result, close_error)) {
            (void)emit("\"kind\":\"completion\",\"outcome\":\"%s\"",
                       strcmp(reason, "ok") == 0 ? "ok" : "error");
        }
    }
    poweroff();
}

static bool prepare_dir(const char *path) {
    return mkdir(path, 0755) == 0 || errno == EEXIST;
}

static bool cmdline(void) {
    char line[CMDLINE_MAX + 1];
    int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t length = read(fd, line, sizeof(line));
    char extra;
    ssize_t rest = length >= 0 ? read(fd, &extra, 1) : -1;
    int closed = close(fd);
    if (length <= 0 || (size_t)length > CMDLINE_MAX || rest != 0 || closed != 0) return false;
    line[length] = '\0';
    if (memchr(line, '\0', (size_t)length) != NULL) return false;
    unsigned phases = 0, nonces = 0;
    char *save = NULL;
    for (char *token = strtok_r(line, " \t\r\n", &save); token != NULL;
         token = strtok_r(NULL, " \t\r\n", &save)) {
        static const char phase_key[] = "ramen_store0_phase=";
        static const char nonce_key[] = "ramen_store0_nonce=";
        if (strcmp(token, "ramen_store0_phase") == 0 ||
            strcmp(token, "ramen_store0_nonce") == 0) return false;
        if (strncmp(token, phase_key, sizeof(phase_key) - 1) == 0) {
            const char *value = token + sizeof(phase_key) - 1;
            phases++;
            if (strcmp(value, "write") == 0) phase = "write";
            else if (strcmp(value, "reopen") == 0) phase = "reopen";
            else return false;
        } else if (strncmp(token, nonce_key, sizeof(nonce_key) - 1) == 0) {
            const char *value = token + sizeof(nonce_key) - 1;
            nonces++;
            if (strlen(value) != 32) return false;
            for (size_t i = 0; i < 32; i++) {
                if (!((value[i] >= '0' && value[i] <= '9') ||
                      (value[i] >= 'a' && value[i] <= 'f'))) return false;
            }
            memcpy(nonce, value, 33);
        }
    }
    return phases == 1 && nonces == 1;
}

static bool sysfs_device_matches(dev_t device) {
    char content[64];
    int fd = open("/sys/class/block/vda/dev", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t length = read(fd, content, sizeof(content));
    int closed = close(fd);
    if (length <= 0 || (size_t)length >= sizeof(content) || closed != 0) return false;
    content[length] = '\0';
    unsigned major_num, minor_num;
    int consumed = 0;
    if (sscanf(content, "%u:%u%n", &major_num, &minor_num, &consumed) != 2 ||
        consumed <= 0 || (content[consumed] != '\n' && content[consumed] != '\0') ||
        (content[consumed] == '\n' && content[consumed + 1] != '\0')) return false;
    return major_num == major(device) && minor_num == minor(device);
}

#ifdef STORE0_PCI_SNAPSHOT
/* This opt-in observer follows the admitted vda device, never a guessed BDF. */
static bool valid_pci_bdf(const char *name) {
    if (strlen(name) != 12 || name[4] != ':' || name[7] != ':' || name[10] != '.') return false;
    for (size_t i = 0; i < 12; i++) {
        if (i == 4 || i == 7 || i == 10) continue;
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return false;
    }
    return (name[8] == '0' || name[8] == '1') && name[11] <= '7';
}

static bool read_pci_config(int dir, unsigned char config[256], bool mark) {
    int fd = openat(dir, "config", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    if (mark) marker_write(0x16);
    ssize_t count = pread(fd, config, 256, 0);
    if (mark) marker_write(0x96);
    int closed = close(fd);
    return count == 256 && closed == 0;
}

static bool same_dev_file(int dir, dev_t expected) {
    char content[64];
    int fd = openat(dir, "dev", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t count = read(fd, content, sizeof(content));
    int closed = close(fd);
    if (count <= 0 || (size_t)count >= sizeof(content) || closed != 0) return false;
    content[count] = '\0';
    unsigned maj, min;
    int n = 0;
    if (sscanf(content, "%u:%u%n", &maj, &min, &n) != 2 || n <= 0 ||
        (content[n] != '\n' && content[n] != '\0') ||
        (content[n] == '\n' && content[n + 1] != '\0')) return false;
    return maj == major(expected) && min == minor(expected);
}

static bool emit_pci_snapshot(dev_t expected) {
    char path[PATH_MAX], subsystem[PATH_MAX], link[64];
    unsigned char config[256];
    int root = -1, current = -1;
    bool ok = false;
    if (realpath("/sys/class/block/vda", path) == NULL ||
        strncmp(path, "/sys/devices/", sizeof("/sys/devices/") - 1) != 0) return false;
    root = open("/sys/devices", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    current = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0 || current < 0 || !same_dev_file(current, expected)) goto out;
    struct stat root_st;
    if (fstat(root, &root_st) != 0) goto out;
    for (unsigned depth = 0; depth < 64; depth++) {
        struct stat current_st;
        if (fstat(current, &current_st) != 0) goto out;
        if (current_st.st_dev == root_st.st_dev && current_st.st_ino == root_st.st_ino) break;
        int n = snprintf(link, sizeof(link), "/proc/self/fd/%d/subsystem", current);
        if (n < 0 || (size_t)n >= sizeof(link)) goto out;
        char *name = strrchr(path, '/');
        if (name == NULL) goto out;
        errno = 0;
        char *resolved = realpath(link, subsystem);
        if (resolved == NULL && (errno != ENOENT || valid_pci_bdf(name + 1))) goto out;
        if (resolved != NULL && strcmp(subsystem, "/sys/bus/pci") == 0) {
            if (!valid_pci_bdf(name + 1) || !read_pci_config(current, config, true)) goto out;
            static const char digits[] = "0123456789abcdef";
            char hex[513], row[768];
            for (size_t i = 0; i < sizeof(config); i++) {
                hex[2 * i] = digits[config[i] >> 4];
                hex[2 * i + 1] = digits[config[i] & 15];
            }
            hex[512] = '\0';
            n = snprintf(row, sizeof(row), "RAMEN_STORE0_PCI_V0 {\"nonce\":\"%s\",\"phase\":\"reopen\",\"bdf\":\"%s\",\"config_hex\":\"%s\"}\n", nonce, name + 1, hex);
            if (n <= 0 || (size_t)n >= sizeof(row)) goto out;
            if (write(STDOUT_FILENO, row, (size_t)n) != n) { serial_ok = false; goto out; }
            ok = true;
            goto out;
        }
        char *slash = strrchr(path, '/');
        if (slash == NULL || slash == path) goto out;
        *slash = '\0';
        int parent = openat(current, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (parent < 0) goto out;
        if (close(current) != 0) { close(parent); current = -1; goto out; }
        current = parent;
    }
out:
    if (current >= 0 && close(current) != 0) ok = false;
    if (root >= 0 && close(root) != 0) ok = false;
    return ok;
}
#endif

static void hex512(char out[SECTOR_BYTES * 2 + 1], const unsigned char *bytes) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < SECTOR_BYTES; i++) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    out[SECTOR_BYTES * 2] = '\0';
}

static bool all_equal(const unsigned char *bytes, unsigned char expected) {
    for (size_t i = 0; i < SECTOR_BYTES; i++) if (bytes[i] != expected) return false;
    return true;
}

static const char *read_sector(const char *operation, unsigned char expected,
                               unsigned char before, unsigned char after) {
    if (!emit("\"kind\":\"before\",\"operation\":\"%s\"", operation)) return "serial_failed";
    marker_write(before);
    errno = 0;
    ssize_t result = pread(disk, data, SECTOR_BYTES, TEST_OFFSET);
    int error = result == -1 ? errno : 0;
    marker_write(after);
    if (result == (ssize_t)SECTOR_BYTES) {
        char payload[SECTOR_BYTES * 2 + 1];
        hex512(payload, data);
        if (!emit("\"kind\":\"after\",\"operation\":\"%s\",\"return\":%jd,\"errno\":%d,\"payload_hex\":\"%s\"",
                  operation, (intmax_t)result, error, payload)) return "serial_failed";
    } else if (!emit("\"kind\":\"after\",\"operation\":\"%s\",\"return\":%jd,\"errno\":%d,\"payload_hex\":null",
                     operation, (intmax_t)result, error)) return "serial_failed";
    if (result != (ssize_t)SECTOR_BYTES) return "read_failed";
    return all_equal(data, expected) ? "ok" : "payload_mismatch";
}

int main(void) {
    if (getpid() != 1) {
        static const char denial[] = "RAMEN_STORE0_ORACLE_V0: non_pid1_denied\n";
        if (write(STDERR_FILENO, denial, sizeof(denial) - 1) < 0) return 2;
        return 2;
    }
    if (!prepare_dir("/proc") || mount("proc", "/proc", "proc", 0, NULL) != 0 || !cmdline()) poweroff();
#ifdef STORE0_PCI_SNAPSHOT
    if (strcmp(phase, "reopen") != 0) done("snapshot_requires_reopen");
#endif
    if (ioperm(MARKER_PORT, 1, 1) != 0 || marker_read() != 0xe9) done("marker_unavailable");
    if (!prepare_dir("/sys") || mount("sysfs", "/sys", "sysfs", 0, NULL) != 0 ||
        !prepare_dir("/dev") || mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) != 0) done("mount_failed");
    for (unsigned i = 0; i < 200; i++) {
        struct stat st;
        if (lstat("/dev/vda", &st) == 0) break;
        if (i == 199) done("device_missing");
        (void)usleep(100000);
    }
    disk = open("/dev/vda", (strcmp(phase, "write") == 0 ? O_RDWR : O_RDONLY) |
                O_CLOEXEC | O_NOFOLLOW | O_DIRECT);
    if (disk < 0) done("device_open_failed");
    struct stat st;
    int logical_size = 0;
    uint64_t bytes = 0;
    if (fstat(disk, &st) != 0 || !S_ISBLK(st.st_mode) || !sysfs_device_matches(st.st_rdev) ||
        ioctl(disk, BLKSSZGET, &logical_size) != 0 || ioctl(disk, BLKGETSIZE64, &bytes) != 0 ||
        logical_size != (int)SECTOR_BYTES || bytes != DISK_BYTES) done("device_identity_failed");
    if (!emit("\"kind\":\"device\",\"major\":%u,\"minor\":%u,\"sector_size\":%d,\"total_bytes\":%" PRIu64,
              major(st.st_rdev), minor(st.st_rdev), logical_size, bytes)) done("serial_failed");
#ifdef STORE0_PCI_SNAPSHOT
    if (!emit_pci_snapshot(st.st_rdev)) done("pci_snapshot_failed");
#endif
    if (strcmp(phase, "reopen") == 0) done(read_sector("pread_reopen", 0xa9, 0x15, 0x95));
    const char *reason = read_sector("pread_baseline", 0x55, 0x11, 0x91);
    if (strcmp(reason, "ok") != 0) done(reason);
    memset(intended, 0xa9, SECTOR_BYTES);
    char payload[SECTOR_BYTES * 2 + 1];
    hex512(payload, intended);
    if (!emit("\"kind\":\"before\",\"operation\":\"pwrite_new\",\"payload_hex\":\"%s\"", payload)) done("serial_failed");
    marker_write(0x12);
    errno = 0;
    ssize_t result = pwrite(disk, intended, SECTOR_BYTES, TEST_OFFSET);
    int error = result == -1 ? errno : 0;
    marker_write(0x92);
    if (!emit("\"kind\":\"after\",\"operation\":\"pwrite_new\",\"return\":%jd,\"errno\":%d", (intmax_t)result, error)) done("serial_failed");
    if (result != (ssize_t)SECTOR_BYTES) done("write_failed");
    if (!emit("\"kind\":\"before\",\"operation\":\"fsync\"")) done("serial_failed");
    marker_write(0x13);
    errno = 0;
    int flushed = fsync(disk);
    error = flushed == -1 ? errno : 0;
    marker_write(0x93);
    if (!emit("\"kind\":\"after\",\"operation\":\"fsync\",\"return\":%d,\"errno\":%d", flushed, error)) done("serial_failed");
    if (flushed != 0) done("fsync_failed");
    done(read_sector("pread_after", 0xa9, 0x14, 0x94));
}
