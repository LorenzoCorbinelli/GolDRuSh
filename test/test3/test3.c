#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *vuln(char *str, int x) {
  char *buf = (char *) malloc(16);
  if (x > 48)
    strncpy(buf, str, x);
  printf("%d", x);
}

int main(int argc, char **argv) {
  if(argc > 2) {
    int x = atoi(argv[2]) - 10;
    vuln(argv[1], x);
  }
}
