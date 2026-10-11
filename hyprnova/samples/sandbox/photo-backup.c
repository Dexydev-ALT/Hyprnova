/* Sandbox fixture: a BENIGN control. A slow, low-entropy "photo backup"
 * helper. It must run to completion without a single alert: mass-modify alone
 * at backup speed, text payloads, no dropper primitives, no hidden writes.
 *
 * Build: cc -O0 -o photo-backup photo-backup.c
 */
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *kText =
    "photo index entry: date=2024-10-10 camera=alpha7 iso=200 f/2.8\n"
    "keywords: family, sunset, holiday. location: garden.\n";

int main(void) {
    puts("[photo-backup] syncing library...");
    mkdir("/tmp/sbx/library", 0755);
    for (int i = 0; i < 12; ++i) {
        char path[256];
        snprintf(path, sizeof(path), "/tmp/sbx/library/album-%02d.txt", i);
        FILE *f = fopen(path, "w");
        if (f) {
            for (int row = 0; row < 40; ++row) fputs(kText, f);
            fclose(f);
        }
        struct timespec ts = {0, 400000000};
        nanosleep(&ts, NULL);   /* slow: real backup speed */
        printf("[photo-backup] copied album-%02d\n", i);
        fflush(stdout);
    }
    puts("[photo-backup] sync complete, exiting cleanly.");
    return 0;
}
