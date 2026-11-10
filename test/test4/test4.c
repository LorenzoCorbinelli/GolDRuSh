#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *vuln(char *str) {
  char *buf = (char *) malloc(16);
  int len = strlen(str);
  strncpy(buf, str, len);
}

int main(int argc, char **argv) {
  if(argc > 1) {
    vuln(argv[1]);
  }
}
