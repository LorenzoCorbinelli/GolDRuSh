#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vuln(char *str) {
  char *buf = (char *) malloc(16);
  int len = strlen(str);
  if (str[8] == 'y') {
    strncpy(buf, str, len);
  }
}

void cncp(char *str, char *str2) {
  char *buf = (char *) malloc(16);
  int n2 = strlen(str2);
  if (str[7] == 'x' && str2[7] == 'z') { 
    strncpy(buf, str2, n2);
  }
}
