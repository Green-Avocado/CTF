#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FLAG_COST 13371337
#define UWU_COST 16
#define FLAG_LEN 32

int balance;
char flag[FLAG_LEN];

void buyFlag() {
    if (balance < FLAG_COST) {
        puts("You don't have enough money :(");
        return;
    }

    balance -= FLAG_COST;
    puts(flag);
}

void buyUwus() {
    puts("How many uwus do you want to buy?");

    int num;
    scanf(" %d", &num);

    if (num < 0) {
        puts("You can't buy negative uwus >:(");
        return;
    }

    int newBalance = balance - (num * UWU_COST);
    
    if (newBalance < 0) {
        puts("You don't have enough money :(");
        printf("Your new balance would be $%d\n", newBalance);
        return;
    }

    balance = newBalance;

    printf("You bought %d uwus\n", num);
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    balance = 100;

    FILE* flagfile = fopen("flag.txt", "r");

    if (flagfile == NULL) {
        puts("Error: could not open flag file");
        exit(1);
    }

    fgets(flag, FLAG_LEN, flagfile);

    char option;
    while(1) {
        printf("[1] Buy flag ($%d)\n", FLAG_COST);
        printf("[2] Buy uwus ($%d)\n", UWU_COST);
        printf("Your balance: %d\n", balance);

        scanf(" %c", &option);

        switch(option) {
            case 'q':
                break;
            case '1':
                buyFlag();
                break;
            case '2':
                buyUwus();
                break;
        }
    }

    return 0;
}
