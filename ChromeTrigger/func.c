#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include "func.h"
#include <time.h>
#include <ntstatus.h>

#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>

#define KEYSIZE 32   // 32 bytes for AES-256
#define IVSIZE 16    // 16 bytes for AES block size (CBC mode)
void readBufferContent(HANDLE hProcess, LPVOID pBuffer, SIZE_T size) {
    // Buffer to hold the data read from the target process
    BYTE* buffer = (BYTE*)malloc(size);
    if (buffer == NULL) {
        printf("Memory allocation failed.\n");
        return;
    }

    SIZE_T bytesRead;
    // Read memory from the target process
    if (ReadProcessMemory(hProcess, pBuffer, buffer, size, &bytesRead)) {
        printf("Read %zu bytes from the target process:\n", bytesRead);
        // Print the content in a readable format (hexadecimal)
        for (SIZE_T i = 0; i < bytesRead; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");
    }
    else {
        printf("ReadProcessMemory failed. Error: %lu\n", GetLastError());
    }

    // Clean up
    free(buffer);
}
void XorEncrypt(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {

    int i = 0;

    for (i = 0; i < sShellcodeSize; i++) {

        pShellcode[i] = pShellcode[i] ^ bKey;

    }
}
/*BOOL AesDecrypt(PBYTE pCipherText, DWORD dwCipherSize, PBYTE pKey, PBYTE pIv, PBYTE* pPlainText, DWORD* dwPlainTextSize) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD dwBlockLen = 0, dwData = 0, dwKeyObjectSize = 0;
    PBYTE pbKeyObject = NULL, pbOutput = NULL;

    BOOL bResult = FALSE;

    // Open an algorithm handle.
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        goto cleanup;
    }

    // Set the chaining mode (CBC).
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("BCryptSetProperty failed: 0x%x\n", status);
        goto cleanup;
    }

    // Determine the size of the key object.
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwKeyObjectSize, sizeof(dwKeyObjectSize), &dwData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("BCryptGetProperty (BCRYPT_OBJECT_LENGTH) failed: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate memory for the key object.
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwKeyObjectSize);
    if (pbKeyObject == NULL) {
        printf("HeapAlloc failed for pbKeyObject\n");
        goto cleanup;
    }

    // Generate the key handle.
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, dwKeyObjectSize, pKey, KEYSIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("BCryptGenerateSymmetricKey failed: 0x%x\n", status);
        goto cleanup;
    }

    // Get the block length for the algorithm.
    status = BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockLen, sizeof(dwBlockLen), &dwData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("BCryptGetProperty (BCRYPT_BLOCK_LENGTH) failed: 0x%x\n", status);
        goto cleanup;
    }

    if (dwBlockLen != IVSIZE) {
        printf("Invalid IV length: %d\n", dwBlockLen);
        goto cleanup;
    }

    // Determine the size of the decrypted data.
    status = BCryptDecrypt(hKey, pCipherText, dwCipherSize, NULL, pIv, IVSIZE, NULL, 0, dwPlainTextSize, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        printf("BCryptDecrypt (size determination) failed: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate memory for the decrypted data.
    pbOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *dwPlainTextSize);
    if (pbOutput == NULL) {
        printf("HeapAlloc failed for pbOutput\n");
        goto cleanup;
    }

    // Perform the actual decryption.
    status = BCryptDecrypt(hKey, pCipherText, dwCipherSize, NULL, pIv, IVSIZE, pbOutput, *dwPlainTextSize, dwPlainTextSize, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        printf("BCryptDecrypt failed: 0x%x\n", status);
        goto cleanup;
    }

    *pPlainText = pbOutput;  // Set the output plaintext
    bResult = TRUE;           // Indicate success

cleanup:
    if (hKey) {
        BCryptDestroyKey(hKey);
    }
    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (!bResult && pbOutput != NULL) {
        HeapFree(GetProcessHeap(), 0, pbOutput);
    }
    if (pbKeyObject != NULL) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }

    return bResult;
}*/

/* BOOL InstallAesDecryption(PAES pAes) {
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    ULONG cbResult = NULL;
    DWORD dwBlockSize = NULL;

    DWORD cbKeyObject = NULL;
    PBYTE pbKeyObject = NULL;
    PBYTE pbPlainText = NULL;
    DWORD cbPlainText = NULL;
    NTSTATUS STATUS = 0;
    // Intializing "hAlgorithm" as AES algorithm Handle
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    8 / 20;
    // Getting the size of the key object variable pbKeyObject. This is used by  the BCryptGenerateSymmetricKey function later
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n",
            STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n",
            STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Checking if block size is 16 bytes
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Allocating memory for the key object 
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n",
            STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Generating the key object from the AES key "pAes->pKey". The output willbe saved in pbKeyObject of size cbKeyObject
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject,
        cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    9 / 20;
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // Running BCryptDecrypt first time with NULL output parameters to retrievethe size of the output buffer which is saved in cbPlainText
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Allocating enough memory for the output buffer, cbPlainText
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Running BCryptDecrypt again with pbPlainText as the output buffer
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
_EndOfFunc:
    if (hKeyHandle)
        BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
    10 / 20;
}*/
/* BOOL Decryption(IN PVOID pCipher, IN DWORD CipherSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlain, OUT DWORD* PlainSize) {

    if (pCipher == NULL || CipherSize == NULL || pKey == NULL || pIv == NULL) {
        return FALSE;
    }
    // Intializing the struct

    AES aes = {
    .pKey = pKey,
    .pIv = pIv,
    .pCipherText = pCipher,
    .dwCipherSize = CipherSize
    };
    if (!InstallAesDecryption(&aes)) {
        return FALSE;
    }
    // Saving output
    *pPlain = aes.pPlainText;
    *PlainSize = aes.dwPlainSize;
    return TRUE;
}*/

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

    printf("unsigned char %s[] = {", Name);
    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0)
            printf("\n\t");

        if (i < Size - 1) {
            printf("0x%0.2X, ", Data[i]);
        }
        else {
            printf("0x%0.2X ", Data[i]);
        }
        printf("};\t");

    }
}
