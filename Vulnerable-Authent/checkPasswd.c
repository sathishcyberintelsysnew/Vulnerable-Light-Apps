#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int check_authentication(char *password){

  char password_buffer[16];
  int auth=0;
  strcpy(password_buffer, password);
  if(strcmp(password_buffer, "aig8Eew8io3d")== 0)
    auth=1;
  return auth;
}

int main(int argc, char *argv[]){
  int i;
  if(argc < 2){
    printf("Usage: %s <password>\n", argv[0]);
    exit(0);
  }
  if(check_authentication(argv[1])){
      printf("Good Password ;)\n");    
  } else {
      printf("Ah ah ah, you didn't say the magic word.\n");
  }
}
