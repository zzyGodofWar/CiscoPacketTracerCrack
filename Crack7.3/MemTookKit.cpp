#include "pch.h"
#include <Windows.h>


typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	//PPEB_LDR_DATA32 Ldr;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
} PEB32, *PPEB32;

typedef struct _PEB64 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	ULONGLONG Mutant;
	ULONGLONG ImageBaseAddress;
	ULONGLONG Ldr;
	ULONGLONG  ProcessParameters;
	ULONGLONG SubSystemData;
} PEB64, *PPEB64;


typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0
}PROCESSINFOCLASS;


typedef struct _PROCESS_BASIC_INFORMATION32 {
	ULONG ExitStatus;
	ULONG PebBaseAddress;
	ULONG AffinityMask;
	ULONG BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32, *PPROCESS_BASIC_INFORMATION32;


typedef struct _PROCESS_BASIC_INFORMATION64 {
	ULONG ExitStatus;
	ULONGLONG PebBaseAddress;
	ULONGLONG AffinityMask;
	ULONGLONG BasePriority;
	ULONGLONG UniqueProcessId;
	ULONGLONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

typedef struct _STRING32 {
	USHORT   Length;
	USHORT   MaximumLength;
	ULONG  Buffer;
} STRING32;
typedef STRING32 UNICODE_STRING32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	ULONG LoadedImports;
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
	LIST_ENTRY32 ForwarderLinks;
	LIST_ENTRY32 ServiceTagLinks;
	LIST_ENTRY32 StaticLinks;
	ULONG ContextInformation;
	ULONG OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _STRING64 {
	USHORT   Length;
	USHORT   MaximumLength;
	ULONGLONG  Buffer;
} STRING64;
typedef STRING64 UNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONGLONG DllBase;
	ULONGLONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks;
	ULONGLONG SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	ULONGLONG LoadedImports;
	ULONGLONG EntryPointActivationContext;
	ULONGLONG PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	ULONGLONG ContextInformation;
	ULONGLONG OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _PEB_LDR_DATA64 {
	ULONG Length;
	UCHAR Initialized;
	ULONGLONG SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONGLONG EntryInProgress;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

#define CONTAINING_RECORD64(address, type, field) ((ULONGLONG)(address) - (ULONG_PTR)(&((type *)0)->field))
#define CONTAINING_Add_RECORD64(address, type, field) ((ULONGLONG)(address) + (ULONG_PTR)(&((type *)0)->field))

ULONG(NTAPI *NtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	) = NULL;

ULONG(NTAPI *NtWow64QueryInformationProcess64)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	) = NULL;

ULONG(NTAPI *NtWow64ReadVirtualMemory64)(
	HANDLE hProcess,
	ULONGLONG lpBaseAddress,
	PVOID lpBuffer,
	ULONGLONG nSize,
	PVOID lpNumberOfBytesRead
	) = NULL;

ULONG(NTAPI *NtWow64WriteVirtualMemory64)(
	HANDLE hProcess,
	ULONGLONG lpBaseAddress,
	PVOID lpBuffer,
	ULONGLONG nSize,
	PVOID lpNumberOfBytesRead
	) = NULL;

ULONG(NTAPI *NtWow64AllocateVirtualMemory64)( 
	HANDLE   ProcessHandle,
	PVOID   BaseAddress,
	ULONGLONG ZeroBits,
	PVOID   RegionSize,
	ULONG   AllocationType,
	ULONG   Protection
	) = NULL;



BOOL InitializeNtFunction() {
	HMODULE hNt = GetModuleHandle(L"ntdll");
	if (!hNt) {
		hNt = LoadLibrary(L"ntdll");
	}
	if (!hNt) {
		return FALSE;
	}

	*(PVOID*)&NtQueryInformationProcess = GetProcAddress(hNt, "NtQueryInformationProcess");
	*(PVOID*)&NtWow64QueryInformationProcess64 = GetProcAddress(hNt, "NtWow64QueryInformationProcess64");
	*(PVOID*)&NtWow64ReadVirtualMemory64 = GetProcAddress(hNt, "NtWow64ReadVirtualMemory64");
	*(PVOID*)&NtWow64WriteVirtualMemory64 = GetProcAddress(hNt, "NtWow64WriteVirtualMemory64");
	*(PVOID*)&NtWow64AllocateVirtualMemory64 = GetProcAddress(hNt, "NtWow64AllocateVirtualMemory64");
	return TRUE;
}

ULONG GetProcessModuleHandle32(HANDLE pHandle,LPWCH lpModuleName) {

	PROCESS_BASIC_INFORMATION32 pbi;
	ULONG ret;
	if (NtQueryInformationProcess(pHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &ret)) {
		return 0;
	}

	PEB32 peb;
	SIZE_T read;
	ReadProcessMemory(pHandle, (PVOID)pbi.PebBaseAddress, &peb, sizeof(peb), &read);

	if (NULL == lpModuleName || lpModuleName[0] == 0) {
		return peb.ImageBaseAddress;
	}
	
	PEB_LDR_DATA32 pebLdr;
	ReadProcessMemory(pHandle, (PVOID)peb.Ldr, &pebLdr, sizeof(pebLdr), &read);
	
	ULONG pListEntryStart, pListEntryEnd;
	LIST_ENTRY32 ListEntryData;
	ULONG pLdrDataEntry;
	LDR_DATA_TABLE_ENTRY32 LdrDataEntry;

	pListEntryStart = pListEntryEnd = pebLdr.InMemoryOrderModuleList.Flink;

	WCHAR *textBuffer;

	do
	{
		pLdrDataEntry = (ULONG)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);

		ReadProcessMemory(pHandle, (PVOID)pLdrDataEntry, &LdrDataEntry, sizeof(LdrDataEntry), &read);
		
		if (LdrDataEntry.FullDllName.Buffer && LdrDataEntry.BaseDllName.Buffer) {

			textBuffer = new WCHAR[LdrDataEntry.BaseDllName.Length/2+1]();
			ReadProcessMemory(pHandle, (PVOID)LdrDataEntry.BaseDllName.Buffer, textBuffer, LdrDataEntry.BaseDllName.Length, &read);

			if (!_wcsicmp(textBuffer, lpModuleName)) {
				delete[]textBuffer;

				return LdrDataEntry.DllBase;
			}

			delete[]textBuffer;
			
		}

		ReadProcessMemory(pHandle, (PVOID)pListEntryStart, &ListEntryData, sizeof(ListEntryData), &read);
		
		pListEntryStart = ListEntryData.Flink;

	} while (pListEntryStart != pListEntryEnd);

	return NULL;
}

ULONGLONG GetProcessModuleHandle64(HANDLE pHandle, LPWCH lpModuleName) {

	PROCESS_BASIC_INFORMATION64 pbi;
	ULONG ret;
	if (NtWow64QueryInformationProcess64(pHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &ret)) {
		return 0;
	}

	PEB64 peb;
	ULONGLONG read;
	NtWow64ReadVirtualMemory64(pHandle, pbi.PebBaseAddress, &peb, sizeof(peb), &read);

	if (NULL == lpModuleName || lpModuleName[0] == 0) {
		return peb.ImageBaseAddress;
	}

	PEB_LDR_DATA64 pebLdr;
	NtWow64ReadVirtualMemory64(pHandle, peb.Ldr, &pebLdr, sizeof(pebLdr), &read);

	ULONGLONG pListEntryStart, pListEntryEnd;
	LIST_ENTRY64 ListEntryData;
	ULONGLONG pLdrDataEntry;
	LDR_DATA_TABLE_ENTRY64 LdrDataEntry;

	pListEntryStart = pListEntryEnd = pebLdr.InMemoryOrderModuleList.Flink;

	WCHAR *textBuffer;

	do
	{
		pLdrDataEntry = (ULONGLONG)CONTAINING_RECORD64(pListEntryStart, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);

		NtWow64ReadVirtualMemory64(pHandle, pLdrDataEntry, &LdrDataEntry, sizeof(LdrDataEntry), &read);

		if (LdrDataEntry.FullDllName.Buffer && LdrDataEntry.BaseDllName.Buffer) {

			textBuffer = new WCHAR[LdrDataEntry.BaseDllName.Length / 2 + 1]();
			NtWow64ReadVirtualMemory64(pHandle, LdrDataEntry.BaseDllName.Buffer, textBuffer, LdrDataEntry.BaseDllName.Length, &read);

			if (!_wcsicmp(textBuffer, lpModuleName)) {
				delete[]textBuffer;

				return LdrDataEntry.DllBase;
			}

			delete[]textBuffer;

		}

		NtWow64ReadVirtualMemory64(pHandle, pListEntryStart, &ListEntryData, sizeof(ListEntryData), &read);

		pListEntryStart = ListEntryData.Flink;

	} while (pListEntryStart != pListEntryEnd);

	return NULL;
}

ULONGLONG GetProcAddress64(HANDLE pHandle, ULONGLONG hModule, LPCSTR lpProcName) {

	ULONGLONG dosHeader, ntHeader;
	WORD wdata;
	DWORD ddata;
	ULONGLONG qdata;
	ULONGLONG rsize;
	ULONGLONG CurCalcAddr;

	dosHeader = hModule;
	CurCalcAddr = CONTAINING_Add_RECORD64(dosHeader, IMAGE_DOS_HEADER, e_magic);
	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &wdata, sizeof(WORD), &rsize);
	if (wdata != IMAGE_DOS_SIGNATURE) {
		return 0;
	}
	
	CurCalcAddr = CONTAINING_Add_RECORD64(dosHeader, IMAGE_DOS_HEADER, e_lfanew);
	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &ddata, sizeof(LONG), &rsize);

	ntHeader = dosHeader + ddata;
	CurCalcAddr = CONTAINING_Add_RECORD64(ntHeader, IMAGE_NT_HEADERS64, Signature);
	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &ddata, sizeof(DWORD), &rsize);
	if (ddata != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	CurCalcAddr = ntHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &wdata, sizeof(WORD), &rsize);
	if (wdata != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return NULL;
	}

	IMAGE_DATA_DIRECTORY dir_export;
	CurCalcAddr = CONTAINING_Add_RECORD64(CurCalcAddr, IMAGE_OPTIONAL_HEADER64, DataDirectory);

	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &dir_export, sizeof(IMAGE_DATA_DIRECTORY), &rsize);
	if (!dir_export.VirtualAddress){
		return NULL;
	}
	
	CurCalcAddr = dosHeader + dir_export.VirtualAddress;
	IMAGE_EXPORT_DIRECTORY ntExportTable;

	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &ntExportTable, sizeof(IMAGE_EXPORT_DIRECTORY), &rsize);


	DWORD NamedFunctionCount = ntExportTable.NumberOfNames;
	ULONGLONG NamedFunctionAddrList = dosHeader + ntExportTable.AddressOfFunctions;
	ULONGLONG NamedFunctionNameList = dosHeader + ntExportTable.AddressOfNames;
	ULONGLONG NamedFunctionHintList = dosHeader + ntExportTable.AddressOfNameOrdinals;
	
	CHAR NamedFunctionName[128];

	ULONGLONG TargetFuncAddr = NULL;

	if (!NamedFunctionCount) {
		return TargetFuncAddr;
	}

	ULONG left = 0;
	ULONG right = NamedFunctionCount - 1;
	ULONG mid = (left + right) / 2;
	int value;


	CurCalcAddr = NamedFunctionNameList + left * 4;
	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &ddata, sizeof(DWORD), &rsize);
	CurCalcAddr = dosHeader + ddata;
	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &NamedFunctionName, sizeof(NamedFunctionName), &rsize);

	value = strcmp(lpProcName, NamedFunctionName);
	if (value < 0) {
		return TargetFuncAddr;
	}
	else if (value == 0) {
		CurCalcAddr = NamedFunctionHintList + 2 * left;
		NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &wdata, sizeof(WORD), &rsize);

		CurCalcAddr = NamedFunctionAddrList + 4 * wdata;
		NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &ddata, sizeof(DWORD), &rsize);

		TargetFuncAddr = dosHeader + ddata;
		return TargetFuncAddr;
	}

	CurCalcAddr = NamedFunctionNameList + right * 4;
	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &ddata, sizeof(DWORD), &rsize);
	CurCalcAddr = dosHeader + ddata;
	NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &NamedFunctionName, sizeof(NamedFunctionName), &rsize);
	value = strcmp(lpProcName, NamedFunctionName);
	if (value > 0) {
		return TargetFuncAddr;
	}
	else if (value == 0) {
		CurCalcAddr = NamedFunctionHintList + 2 * right;
		NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &wdata, sizeof(WORD), &rsize);

		CurCalcAddr = NamedFunctionAddrList + 4 * wdata;
		NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &ddata, sizeof(DWORD), &rsize);

		TargetFuncAddr = dosHeader + ddata;
		return TargetFuncAddr;
	}

	

	while (left <= right) {
		
		CurCalcAddr = NamedFunctionNameList + mid * 4;
		NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &ddata, sizeof(DWORD), &rsize);
		CurCalcAddr = dosHeader + ddata;
		NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &NamedFunctionName, sizeof(NamedFunctionName), &rsize);
		value = strcmp(lpProcName, NamedFunctionName);
		if (value == 0) {
			CurCalcAddr = NamedFunctionHintList + 2 * mid;
			NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &wdata, sizeof(WORD), &rsize);

			CurCalcAddr = NamedFunctionAddrList + 4 * wdata;
			NtWow64ReadVirtualMemory64(pHandle, CurCalcAddr, &ddata, sizeof(DWORD), &rsize);

			TargetFuncAddr = dosHeader + ddata;
			return TargetFuncAddr;
		}
		else if (value > 0) {
			left = mid + 1;
		}
		else if (value < 0) {
			right = mid - 1;
		}
		mid = (left + right) / 2;
	}

	return TargetFuncAddr;
}