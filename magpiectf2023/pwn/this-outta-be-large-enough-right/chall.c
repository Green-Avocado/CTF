#include <stdio.h>
#include <stdlib.h>
__asm__(".symver realpath,realpath@GLIBC_2.0.5");
void win(){
    printf("Here is your flag:\n");
    exit(0);
}
void vuln(){
  char buf[56];
  gets(buf);
}
int main(){
  vuln();
  return 0;
}
