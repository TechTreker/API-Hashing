#include <windows.h>
#include <stdio.h>
#include <winternl.h>

unsigned int hashFunction(const char* str) {
	unsigned int hash = 216613626U;
	for (const char* ptr = str; *ptr; ptr++) {
		hash ^= (unsigned int)(*ptr);
		hash *= 16777619;
	}
	return hash;
}

FARPROC getProcAddressReplacement(IN HMODULE hModule, IN UINT apiHashNumber) {

	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeaders->e_lfanew);
	IMAGE_OPTIONAL_HEADER optHeaders = ntHeaders->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + optHeaders.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD functionNameArr = (PDWORD)((BYTE*)hModule + exportDir->AddressOfNames);
	PDWORD functionAddrArr = (PDWORD)((BYTE*)hModule + exportDir->AddressOfFunctions);
	PWORD functionOrdArr = (PWORD)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
		CHAR* pFunctionName = (CHAR*)((BYTE*)hModule + functionNameArr[i]);
		unsigned int hashedValue = hashFunction(pFunctionName);
		// For debug purposes. 
		//printf("[+] Checking function: %s Hash: %x\n", pFunctionName, hashedValue); 
		if (hashedValue == apiHashNumber) {
			FARPROC functionAddress = (FARPROC)((BYTE*)hModule + functionAddrArr[functionOrdArr[i]]);
			// For debug purposes
			//printf("[+] Match found for hash %x at address 0x%p\n", apiHashNumber, functionAddress);
			return functionAddress;
		}

	}
	return NULL;

}

typedef LPVOID(WINAPI* fnVirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
	);

typedef BOOL(WINAPI* fnVirtualFree)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD dwFreeType
	);

BOOL PoC(IN HMODULE kernel32Mod, IN unsigned int virtAllocHash, IN unsigned int virtualFreeHash) {

	fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)getProcAddressReplacement(kernel32Mod, virtAllocHash);
	fnVirtualFree pVirtualFree = (fnVirtualFree)getProcAddressReplacement(kernel32Mod, virtualFreeHash);

	LPVOID memoryAlloc = pVirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (memoryAlloc) {
		printf("[+] VirtualAlloc success using it's Hashed value at location 0x%p\n", memoryAlloc);
		pVirtualFree(memoryAlloc, 0, MEM_RELEASE);
	}
	else {
		printf("[-] Virtual Alloc failed\n");
	}

	return TRUE;
}


int main() {

	HMODULE kernel32 = LoadLibraryA("kernel32.dll");

	if (!kernel32) {
		printf("\t[-] Failed to load kernel32.dll\n");
		return -1;
	}

	unsigned int virtAllocHash = hashFunction("VirtualAlloc");
	unsigned int virtFreeHash = hashFunction("VirtualFree");

	printf("\n############################ API Hashes ############################\n");
	printf("[+] VirtualAlloc hash is: %x\n", virtAllocHash);
	printf("[+] VirtualFree hash is: %x\n\n", virtFreeHash);

	printf("############################ Address Resolutions ############################\n");
	printf("[+] Address for VirtualAlloc using GetProcAddressReplacement & API hasing: 0x%p\n", getProcAddressReplacement(kernel32, virtAllocHash));
	printf("[+] Address for VirtualAlloc using GetProcAddress: 0x%p\n\n", GetProcAddress(kernel32, "VirtualAlloc"));

	printf("[+] Absolute Address for VirtualFree using GetProcAddressReplacement & API hasing: 0x%p\n", getProcAddressReplacement(kernel32, virtFreeHash));
	printf("[+] Absolute Address for VirtualFree using GetProcAddress: 0x%p\n\nS", GetProcAddress(kernel32, "VirtualFree"));

	printf("############################ PoC ############################\n");
	if (!PoC(kernel32, virtAllocHash, virtFreeHash)) {
		printf("\t[-] PoC failed to allocate memory. Error: %d", GetLastError());
		return -1;
	}

	return 0;
}