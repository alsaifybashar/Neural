/* Minimal, self-contained CWE-121 / SEI CERT STR31-C sample: a
 * stack-based buffer overflow via an unbounded strcpy(). Modeled on the
 * shape of NIST Juliet Test Suite cases (one bad() function containing
 * the flaw, kept small deliberately for offline unit testing without a
 * full Juliet checkout). */

#include <stdio.h>
#include <string.h>

void bad_copy_username(const char *input) {
    char buf[16];
    /* FLAW: strcpy() does not bound the copy to sizeof(buf), so an
     * `input` longer than 15 characters overflows `buf`. This is the
     * line CodeChecker's cert-str31-c checker flags. */
    strcpy(buf, input);
    printf("user: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        bad_copy_username(argv[1]);
    }
    return 0;
}
