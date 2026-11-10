#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *vuln(char *str, char *str2, int len, int len2) {
  char *buf = (char *) malloc(16);
  char *buf2 = (char *) malloc(16);
  if (str[8] == 'y') {
    strncpy(buf, str, len);
    strncpy(buf2, str2, len2);
  }
}

void *cncp(char *str, char *str2) {
  int n = strlen(str);
  int n2 = strlen(str2);
  if (str[7] == 'x' && str2[7] == 'z') { 
    vuln(str, str2, n, n2); 
  }
}

int main(int argc, char **argv) {
  if(argc > 2)
	  cncp(argv[1], argv[2]);
}
