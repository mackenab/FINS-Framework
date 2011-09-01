/**
 * @file getMAC_Address.c
 *
 *  @date Jun 11, 2010
 *      @author Abdallah Abdallah
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void getMAC_Address(unsigned char macAddress[])

{

	FILE *fs2;
	char buffering[100];
	char buffering2[18];

	char *macat;
	int i,j;
	int check=0;
	i=0;
	j=0;
	/*	fs2 = fopen ("macaddress","r");
       if ( fs2 != NULL )
       {
    	   fclose (fs2);
    	   system ("rm macaddress");

       }

       else
       {fclose(fs2);}
	 */
	system ("rm macaddress");
	system ("ifconfig >> macaddress");
	fs2 = fopen ("macaddress","r");
	if ( fs2 == NULL )
	{
		printf("coud not open the MAC address file");
		exit(1);
	}
	while(!feof(fs2))
	{
		fgets(buffering,100,fs2);
		macat=strstr(buffering,"wlan0     Link encap:Ethernet  HWaddr ");

		if (macat != NULL)
		{

			check = 1;
			break;
			strncpy(buffering2,macat+38,17);

		}

	}
	fclose (fs2);
	if (check)
	{
		strncpy(buffering2,macat+38,17);
		strcat(buffering2,"\0");

	}
	else
	{
		puts("MAC Address DOES NOT EXIST OR NOT IN PASSED FILE");
		exit(1);

	}

	while (i < 17)
	{
		if (buffering2 [i] != ':' )
		{
			macAddress[j] = buffering2[i];
			j=j+1;
		}
		else {}
		i=i+1;
	}
	macAddress[j]='\0';


}


void getDevice_MACAddress(unsigned char macAddress[],unsigned char *dev)

{

	FILE *fs2;
	char buffering[100];
	char buffering2[18];

	char *macat;
	unsigned char *searchToken;
	int i,j;
	int check=0;
	i=0;
	j=0;
	searchToken = (unsigned char *)malloc(100);
	strcat(searchToken,dev);
	strcat(searchToken,"     Link encap:Ethernet  HWaddr ");
	fs2 = fopen ("macaddress","r");

	/*	if ( fs2 != NULL )
		   {
			   fclose (fs2);
			   system ("rm macaddress");

		   }

		   else
		   {
		   }
	 */

	system ("rm macaddress");
	system ("ifconfig >> macaddress");
	fs2 = fopen ("macaddress","r");
	if ( fs2 == NULL )
	{
		printf("coud not open the MAC address file");
		exit(1);
	}

	while(!feof(fs2))
	{
		fgets(buffering,100,fs2);
		macat=strstr(buffering,searchToken);

		if (macat != NULL)
		{

			check = 1;
			break;
			strncpy(buffering2,macat+38,17);

		}

	}
	fclose (fs2);
	if (check)
	{
		strncpy(buffering2,macat+38,17);
		strcat(buffering2,"\0");

	}
	else
	{
		puts("MAC Address DOES NOT EXIST OR NOT IN PASSED FILE");
		exit(1);

	}

	while (i < 17)
	{
		if (buffering2 [i] != ':' )
		{
			macAddress[j] = buffering2[i];
			j=j+1;
		}
		else {}
		i=i+1;
	}
	macAddress[j]='\0';



} // end of  function
