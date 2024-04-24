#include "helpers.h"
tLoadLibraryA pLoadLibraryA = NULL;

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

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++)
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