#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FLAG_LEN 32

char flag[FLAG_LEN];

void win() {
    puts(flag);
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    char name[32];

    FILE* flagfile = fopen("flag.txt", "r");

    if (flagfile == NULL) {
        puts("Error: could not read flag file");
        exit(1);
    }

    fgets(flag, FLAG_LEN, flagfile);

    puts("What's your name?");
    gets(name);
    printf("Hello %s! Let's go to %p\n", name, __builtin_return_address(0));

    return 0;
}
