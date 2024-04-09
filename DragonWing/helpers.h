#pragma once

#include <stdio.h>
#include <Windows.h>

typedef BOOL(WINAPI* tVirtualProtect)(IN LPVOID lpAddress,IN SIZE_T dwSize,IN DWORD flNewProtect,OUT PDWORD lpflOldProtect);
typedef LPVOID(WINAPI* tVirtualAlloc)(IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD flAllocationType, IN DWORD flProtect);
typedef BOOL(WINAPI* tCreateTimerQueueTimer)(OUT PHANDLE phNewTimer, IN HANDLE TimerQueue, IN WAITORTIMERCALLBACK Callback, IN PVOID Parameter, IN DWORD DueTime, IN DWORD Period, IN ULONG Flags);
typedef PVOID (WINAPI* tAddVectoredExceptionHandler)(IN ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
typedef HMODULE (WINAPI* tLoadLibraryA) (LPCSTR lpLibFileName);
typedef HMODULE (WINAPI* tLoadLibraryW) (LPCWSTR lpLibFileName);
typedef BOOLEAN(NTAPI* tRtlAddFunctionTable)(IN PRUNTIME_FUNCTION FunctionTable, IN DWORD EntryCount, IN DWORD64 BaseAddress);

tLoadLibraryA pLoadLibraryA = NULL;

typedef struct _PE_HEADERS
{
	PBYTE                    pFileBuffer;
	DWORD                    dwFileSize;

	PIMAGE_NT_HEADERS        pImgNtHdrs;
	PIMAGE_SECTION_HEADER    pImgSecHdr;

	PIMAGE_DATA_DIRECTORY    pEntryImportDataDir;
	PIMAGE_DATA_DIRECTORY    pEntryBaseRelocDataDir;
	PIMAGE_DATA_DIRECTORY    pEntryTLSDataDir;
	PIMAGE_DATA_DIRECTORY    pEntryExceptionDataDir;
	PIMAGE_DATA_DIRECTORY    pEntryExportDataDir;

	BOOL                     bIsDLLFile;
} PE_HEADERS, *PPE_HEADERS;

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef BOOL(WINAPI* MAIN)();

typedef struct _USTRING {
	DWORD Length;
	DWORD MaximumLength;
	unsigned char* Buffer;
} USTRING, *PUSTRING;

typedef NTSTATUS(WINAPI* pSystemFunction032)(PUSTRING uStrBuffer, PUSTRING uStrKey);

HMODULE hlpGetModuleHandle(IN LPCWSTR sModuleName)
{
	PPEB pPeb = (PPEB)(__readgsqword(0x60));


	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);

	PLIST_ENTRY pListHead = (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pListNode = (PLIST_ENTRY)pListHead->Flink;

    do
    {
        if (lstrcmpiW(pDte->FullDllName.Buffer, sModuleName) == 0)
        {
            return (HMODULE) pDte->Reserved2[0];
        }

		pDte = (PLDR_DATA_TABLE_ENTRY)(pListNode->Flink);
		pListNode = (PLIST_ENTRY)pListNode->Flink;
	} while (pListNode != pListHead);

    return NULL;
}

FARPROC hlpGetProcAddress(IN HMODULE hModule, IN LPCSTR lpApiName)
{
	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER pImgDosHeader = (PIMAGE_DOS_HEADER)pBase;

	if (pImgDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;


	PIMAGE_NT_HEADERS pImgNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pImgDosHeader->e_lfanew);

	IMAGE_OPTIONAL_HEADER imgOptionalHeader = pImgNtHeaders->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + imgOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD AddressOfNamesArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD AddressOfFunctionsArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD AddressOfOrdinalsArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
	PVOID pFunctionAddress = NULL;

	for (int i = 0; i < pImgExportDir->NumberOfFunctions; i++)
	{
		CHAR* pFuncName = (CHAR*)(pBase + AddressOfNamesArray[i]);
		WORD wFuncOrdinal = AddressOfOrdinalsArray[i];


		if (strcmp(lpApiName, pFuncName) == 0)
		{
			pFunctionAddress = (PVOID)(pBase + AddressOfFunctionsArray[AddressOfOrdinalsArray[i]]);
			break;
		}
	}

	if ((PBYTE)pFunctionAddress >= (PBYTE)pImgExportDir && ( (PBYTE)pFunctionAddress < (PBYTE)pImgExportDir + imgOptionalHeader.DataDirectory->Size))
	{
		char* sFwdDll = _strdup((char*)pFunctionAddress);
		if (!sFwdDll)
			return NULL;

		char* sFwdFunc = strchr(sFwdDll, '.');
		*sFwdFunc = '\0';
		sFwdFunc++;

		if (pLoadLibraryA == NULL)
		{
			pLoadLibraryA = (tLoadLibraryA)hlpGetProcAddress(hlpGetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
			if (pLoadLibraryA == NULL)
				return NULL;
		}

		HMODULE hFwdDll = pLoadLibraryA(sFwdDll);
		if (!hFwdDll)
			return NULL;

		pFunctionAddress = hlpGetProcAddress(hFwdDll, sFwdFunc);
		free(sFwdDll);
	}
	return (FARPROC) pFunctionAddress;
}