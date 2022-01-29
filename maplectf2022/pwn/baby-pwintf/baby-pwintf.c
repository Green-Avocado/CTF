#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FLAG_LEN 64

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
    char* input = malloc(16);
    int* rating = malloc(4);

    fgets(input, 16, stdin);
    *rating = input[0] % 11;

    puts("Your name is:");
    printf(input);

    printf("I rate your name %d / 10\n", *rating);

    if (*rating == 0x1337) {
        puts("Nice name! here's a flag:");
        win();
    }
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    puts("Tell me your name and I'll rate it!");
    vuln();

    return 0;
}
