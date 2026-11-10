#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *vuln(char *str, int len) {
  char *buf = (char *) malloc(16);

  if (str[8] == 'y') {
    strncpy(buf, str, len);
  }
}

void *cncp(char *str) {
  int n = strlen(str);

  if (str[7] == 'x') { 
    vuln(str, n); 
  }
}

int main(int argc, char **argv) {
  if(argc > 1)
	  cncp(argv[1]);
}
