#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

typedef void student_func();

int read_shellcode(char * dest, int length) {
    char * hex_str = malloc(length*2+1);
    ssize_t n_bytes = read(0,hex_str,length*2);
    for (ssize_t i=0;i<n_bytes/2;i++){
        if (!sscanf(&hex_str[i*2],"%2hhx",&dest[i])) {
            return 0;
        };
    }
    free(hex_str);
    return 1;
}

int final_exam(void * func) {
    puts("code submitted.");
    return 0;
}

void init_chall() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
}

int main() {
    init_chall();
    char * func = mmap((void*)0x2333000,0x1000,7,0x21,0,0);
    char * feedback = malloc(0x18);
    char name[8];
    long exam_id = (long) &name;
    printf("======== Final Exam (Your Exam ID: 0x%lx)========\n",exam_id);
    puts("Enter your name: ");
    read(0,&name[0],0xc);
    printf("Good luck on your final, %s",name);
    puts("please put your function shellcode here: ");
    if (!read_shellcode(func,2)) {
        puts("fail to read shellcode, please check your shellcode");
        exit(-1);
    };
    final_exam((void *)func);
    puts("pleas give us feedback about this course: ");
    read(0,feedback,0x18);
    puts("feedback submitted: ");
    printf(feedback);
    // exit final environment
    exit(0);
    return 0;
}