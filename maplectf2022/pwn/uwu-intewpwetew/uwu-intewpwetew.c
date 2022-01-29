#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FLAG_LEN 64
#define INPUT_LEN 0x100
#define DATA_LEN 0x100

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


void print_remaining_and_exit(char* input, int index) {
    printf("Remaining input: ");
    puts(&input[index]);
    exit(0);
}

void vuln() {
    char* input = malloc(INPUT_LEN);
    fgets(input, INPUT_LEN, stdin);

    for (unsigned i = 0; i < INPUT_LEN; i++) {
        if (input[i] == '\n') {
            input[i] = '\0';
            break;
        }
    }

    int data[DATA_LEN] = {0};
    int pointer = 0;
    char instruction[3];

    for (unsigned i = 0; i < INPUT_LEN; i++) {
        if (i % 4 != 3) {
            instruction[i % 4] = input[i];
        } else if (input[i] != ' ') {
            if (input[i] == '\0') {
                break;
            }

            printf("Error: expected space, got %c\n", input[i]);
            print_remaining_and_exit(input, i);
        }

        if (i % 4 == 2) {
            if (instruction[1] != 'w') {
                printf("Error: invalid instruction (%c%c%c)\n", instruction[0], instruction[1], instruction[2]);
                print_remaining_and_exit(input, i);
            }

            if (instruction[0] != instruction[2] && !(instruction[0] == '>' && instruction[2] == '<')) {
                printf("Error: invalid instruction (%c%c%c)\n", instruction[0], instruction[1], instruction[2]);
                print_remaining_and_exit(input, i);
            }

            switch (instruction[0]) {
                case 'O':
                    pointer++;
                    if (pointer > DATA_LEN) {
                        printf("Error: out of bounds\n");
                        print_remaining_and_exit(input, i);
                    }
                    break;
                case 'o':
                    pointer--;
                    if (pointer > DATA_LEN) {
                        printf("Error: out of bounds\n");
                        print_remaining_and_exit(input, i);
                    }
                    break;
                case 'U':
                    data[pointer]++;
                    break;
                case 'Q':
                    data[pointer]--;
                    break;
                case '@':
                    printf("\npointer: %d\ndata: %d\n", pointer, data[pointer]);
                    break;
                case '>':
                    printf("\nInput: ");
                    scanf(" %d", &data[pointer]);
                    break;
                default:
                    printf("Error: invalid instruction (%c%c%c)\n", instruction[0], instruction[1], instruction[2]);
                    print_remaining_and_exit(input, i);
                    break;
            }
        }
    }
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    puts("me wwote an intewpwetew fow da uwu wanguage");
    puts("Ex: \"@w@ OwO @w@ UwU @w@ QwQ @w@ owo @w@ >w< @w@\"");
    puts("Send me your cowode:");
    vuln();

    return 0;
}
