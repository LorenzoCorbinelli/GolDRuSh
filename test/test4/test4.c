#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vuln(char *str, int len) {
  char *buf = (char *) malloc(16);
  if(str[0] == 'A' && str[1] == 'B')
  	strncpy(buf, str, len);
  free(buf);
  if(str[3] == 'Z')
  	free(buf);
}

int main(int argc, char **argv) {
  if(argc > 1) {
    int len = strlen(argv[1]);
    vuln(argv[1], len);
  }
}
