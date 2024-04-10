#include <stdio.h>


#include <string.h>
 
int main ()
{
   char str1[15];
   char str2[15];
   char str3[15];
   char str4[15];
   char str5[15];
   char str6[15];
   char str7[15];
   char str8[15];
   int ret,ret1,ret2,ret3;
 
 
   strcpy(str1, "abcdef");
   strcpy(str2, "ABCDEF");
 
   ret = strcmp(str1, str2);
   strcpy(str3, "abcdsdf");
   strcpy(str4, "ggCffF");
   ret1 = strcmp(str3, str4);
   strcpy(str5, "ffef");
   strcpy(str6, "123EF");
   ret2 = strcmp(str5, str6);
   strcpy(str7, "ddddef");
   strcpy(str8, "pppp");
   ret3 = strcmp(str7, str8);
   if(ret < 0)
   {
      printf("1\n");
   }
   else if(ret > 0)
   {
      printf("2\n");
   }
   else
   {
      printf("3\n");
   }
   if(ret1 < 0)
   {
      printf("1\n");
   }  
   if(ret2 < 0)
   {
      printf("1\n");
   }     
   if(ret3 < 0)
   {
      printf("1\n");
   }  
    
   return(0);
}

