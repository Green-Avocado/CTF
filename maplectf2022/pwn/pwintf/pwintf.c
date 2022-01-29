#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    puts("Wewcome b-back?!! Peopwe wewe t-twying t-to hack my pwogwam, so I stopped putting the x3 fwag in memowy ÚwÚ");
    while(1) {
        char* input = malloc(0x100);

        fgets(input, 0x100, stdin);

        printf(input);

        free(input);
    }
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    vuln();

    return 0;
}
