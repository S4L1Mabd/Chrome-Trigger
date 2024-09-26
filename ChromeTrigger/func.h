#pragma once
#include <windows.h>
#include<bcrypt.h>
#include <ntstatus.h>

/* Notice :  the structs and the functions algorithm of AES Encryption  is from maldev accademy */


void readBufferContent(HANDLE hProcess, LPVOID pBuffer, SIZE_T size);
void XorEncrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey);


#define IVSIZE 16
#define KEYSIZE 32

#define NT_SUCCESS(Status) (((NTSTATUS)(Status) >= 0))


typedef struct _AES {
	PBYTE pPlainText; // base address of the plain text data 
	DWORD dwPlainSize; // size of the plain text data
	PBYTE pCipherText; // base address of the encrypted data
	DWORD dwCipherSize; // size of it (this can change from dwPlainSize in case there was padding)
	PBYTE pKey; // the 32 byte key
	PBYTE pIv; // the 16 byte iv
} AES, * PAES;

BOOL Decryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize);
BOOL InstallAesDecryption(PAES pAes);

BOOL AesDecrypt(PBYTE pCipherText, DWORD dwCipherSize, PBYTE pKey, PBYTE pIv, PBYTE* pPlainText, DWORD* dwPlainTextSize);

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);





