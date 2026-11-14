/*
 * AEGIS-LOOP REVIEW/TRAINING FIXTURE - intentionally vulnerable demo program.
 *
 * This file exists ONLY as a target for defensive code-review testing. It is
 * not meant to be compiled, deployed, or used for anything else. Each issue
 * is marked with a REVIEW FIXTURE comment so reviewers (human or agent) can
 * verify recall.
 */
#include <stdio.h>
#include <string.h>

/* REVIEW FIXTURE: hardcoded credential - must be flagged by review. */
#define ADMIN_PASSWORD "Sup3rSecret!"

int main(int argc, char **argv) {
    char buf[64];
    char msg[128];

    if (argc < 2) {
        printf("usage: %s <name>\n", argv[0]);
        return 1;
    }

    /* REVIEW FIXTURE: stack buffer overflow - unbounded strcpy into buf. */
    strcpy(buf, argv[1]);

    /* REVIEW FIXTURE: snprintf misuse - user input used as the format string. */
    snprintf(msg, sizeof(msg), argv[1]);

    printf("%s\n%s\n", buf, msg);
    return 0;
}
