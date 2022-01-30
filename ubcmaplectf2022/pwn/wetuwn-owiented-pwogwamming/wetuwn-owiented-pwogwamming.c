#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FLAG_LEN 32

char flag[FLAG_LEN];
bool rawrxd = false;
bool uwu = false;
bool owo = false;

void win() {
    FILE* flagfile = fopen("flag.txt", "r");

    if (flagfile == NULL) {
        puts("Error: flag.txt does not exist, contact an admin!");
        exit(1);
    }

    fgets(flag, FLAG_LEN, flagfile);

    if (rawrxd && (uwu && owo)) {
        puts(flag);
    } else {
        puts("oh nyo youw e-expwoit has faiwed *sweats*");
    }
}

void A() {
    uwu = true;
    puts("uwu");
}

void B() {
    if (uwu) {
        owo = true;
        puts("owo");
    }
}

void C(int secwet) {
    if (secwet == 0xdeadbeef) {
        rawrxd = true;
        puts("rawrxd");
    }
}

void vuln() {
    char input[100];

    puts("uwu owo rawrxd");
    fgets(input, 0x100, stdin);
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    vuln();

    return 0;
}
