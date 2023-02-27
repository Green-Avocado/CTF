#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
void main()
{
	char flag[120];
	setvbuf ( stdout, NULL , _IONBF , 0 );
	char Test[20];

	//random number based on the current time.
	//YOU WILL NEVER GUESS THE PASSWORD. HAHAHAHAHHAH
    srand(time(0));
	sprintf(Test, "%d",rand());	
	
	
    char input[20];
    printf("Enter something?");
    scanf("%s",input);

	//Check password
	if (strncmp(Test,input,20) == 0)
	{
		FILE *f = fopen("flag.txt","r");
		
		fgets(flag,100,f);
		
		printf("Password is correct! Here is your flag: %s", flag);
	}
	

}