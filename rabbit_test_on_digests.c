#include <stdio.h>
#include "gdef.h"
#include "swrite.h"
#include "bbattery.h"

int main(){

    FILE* fp = fopen("hashes.bin", "r");
    
      if(fp == NULL){
          printf("Hashes File Not Found!\n");
          return -1;
      }
    
      fseek(fp, 0L, SEEK_END);
    
      int res = ftell(fp);
    
      fclose(fp);
    
    swrite_Basic = FALSE;
    bbattery_RabbitFile ("hashes.bin", res * 8);
    
    return 0;
    
}
