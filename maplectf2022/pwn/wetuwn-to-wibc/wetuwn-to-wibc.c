#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define FLAG_LEN 64

char flag[FLAG_LEN];

void send_feedback(char* feedback) {
    // lol u think my code works?
}

void vuln() {
    unsigned long long uwus[9] = { 42, 8, 5, 3, 2, 1, 1, 1, 1 };

    puts("0: Vie");
    puts("1: Jason");
    puts("2: gKai");
    puts("3: rctcwyvrn");
    puts("4: woof");
    puts("5: ko");
    puts("6: Filip");
    puts("7: Daniel");
    puts("8: James Riddell");
    puts("-1: Quit");

    while (1) {
        int input;

        printf("\nIndex: ");
        scanf(" %d", &input);

        if (input == -1) {
            break;
        }

        if (input >= 0 && input < sizeof uwus) {
            printf("This UwU'er has UwU'ed %llu times!\n", uwus[input]);
        } else {
            puts("Error: index out of bounds.");
        }
    }

    char comment[0x100];

    puts("Thanks for using my UwU Counter! What did you think?");

    // I stole this from stack overflow
    char c;
    while ((c = getchar()) != '\n' && c != EOF) { }

    gets(comment);
    send_feedback(comment);

    puts("Thank you for your feedback!");
}

int main() {
    puts("  _   _          _   _    ____                  _            \n | | | |_      _| | | |  / ___|___  _   _ _ __ | |_ ___ _ __ \n | | | \\ \\ /\\ / / | | | | |   / _ \\| | | | '_ \\| __/ _ \\ '__|\n | |_| |\\ V  V /| |_| | | |__| (_) | |_| | | | | ||  __/ |   \n  \\___/  \\_/\\_/  \\___/   \\____\\___/ \\__,_|_| |_|\\__\\___|_|   \n ");

    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    vuln();

    return 0;
}
