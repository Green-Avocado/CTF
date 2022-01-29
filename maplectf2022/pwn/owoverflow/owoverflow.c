#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define FLAG_LEN 32

char flag[FLAG_LEN];

void win() {
    FILE* flagfile = fopen("flag.txt", "r");

    if (flagfile == NULL) {
        puts("Error: flag.txt does not exist, contact an admin!");
        exit(1);
    }

    fgets(flag, FLAG_LEN, flagfile);
    puts(flag);
}

void vuln() {
    char expected_username[32] = "maple_bacon_user";
    char username[32];
    char expected_password[32];
    char password[32];

    // get random string for expected password
    getentropy(expected_password, sizeof(expected_password) - 1);

    // ensure no null bytes in expected password
    for (unsigned int i = 0; i < sizeof(expected_password) - 1; i++) {
        expected_password[i] |= 1;
    }

    printf("username: ");
    gets(username);

    printf("password: ");
    gets(password);

    if (strncmp(expected_username, username, 16) != 0) {
        puts("Invalid username");
        exit(0);
    }

    if (strcmp(expected_password, password) != 0) {
        puts("Invalid password");
        exit(0);
    }

    win();
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    vuln();

    return 0;
}
