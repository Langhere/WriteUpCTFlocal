#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void setup(){
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}


void ini_flag(){
  printf("\nKELLAAZZZ BANGG\n");
  system("/bin/bash");
}

void ini_vuln(){
  char katakata[72];
  
  printf("\nKata-kata untuk hari ini:");
  gets(katakata);
  printf("\nTerimakasih atas kata-katanya");
}

int main(){
  setup();
  ini_vuln();

  return 0;
}