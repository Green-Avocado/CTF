#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FLAG_LEN 64

char flag[FLAG_LEN];

void get_flag(char* flag) {
    FILE* flagfile = fopen("flag.txt", "r");

    if (flagfile == NULL) {
        puts("Error: flag.txt does not exist, contact an admin!");
        exit(1);
    }

    fgets(flag, FLAG_LEN, flagfile);
}

void vuln() {
    char* flag = malloc(FLAG_LEN);
    get_flag(flag);

    char name[64];

    puts("What's your name?");
    fgets(name, sizeof name / sizeof name[0], stdin);

    printf("Hello ");
    printf(name);
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    vuln();

    return 0;
}
