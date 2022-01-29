#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FLAG_LEN 64
#define ADMIN_ID 0xdeadbeef

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
    char* name = malloc(64);
    int* id = malloc(sizeof(int));

    puts("Hello, what is your name?");

    fgets(name, 0x64, stdin);

    for (int i = 0; i < 64; i++) {
        if (name[i] == '\n') {
            name[i] = '\0';
        }
    }

    if (*id == ADMIN_ID) {
        win();
    } else {
        printf("Sorry %s, your ID (%x) does not match the admin ID (%x)\n", name, *id, ADMIN_ID);
    }
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    vuln();

    return 0;
}
