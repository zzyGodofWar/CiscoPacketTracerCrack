// pch.h: 这是预编译标头文件。
// 下方列出的文件仅编译一次，提高了将来生成的生成性能。
// 这还将影响 IntelliSense 性能，包括代码完成和许多代码浏览功能。
// 但是，如果此处列出的文件中的任何一个在生成之间有更新，它们全部都将被重新编译。
// 请勿在此处添加要频繁更新的文件，这将使得性能优势无效。

#ifndef PCH_H
#define PCH_H

// 添加要在此处预编译的标头
#include "framework.h"
#include <locale>
#include <iostream>
#pragma comment(lib, "version.lib")

extern WCHAR *gProcImageName;
extern WCHAR *gProcImageName2;
extern WCHAR gImagePath[512];
extern DWORD gImageVersion;
extern WORD gImageBit;

#define ENGZZY1 L"2D6E1C6E0F6E0D6E056E4E6E2C6E176E4E6E286E076E146E146E176E636E646E5C6E5E6E5C6E5C6E406E5A6E406E5F6E5E6E"
#define ENGZZY2 L"EF95EF95EC95D295FA95F195FA95F395C295F495E79598959F95A795A595A795A795BB95A195BB95A495A595"

#endif //PCH_H

BOOL InitializeNtFunction();
ULONG GetProcessModuleHandle32(HANDLE pHandle, LPWCH lpModuleName);
ULONGLONG GetProcessModuleHandle64(HANDLE pHandle, LPWCH lpModuleName);
ULONGLONG GetProcAddress64(HANDLE pHandle, ULONGLONG hModule, LPCSTR lpProcName);

extern ULONG(NTAPI *NtWow64ReadVirtualMemory64)(
	HANDLE hProcess,
	ULONGLONG lpBaseAddress,
	PVOID lpBuffer,
	ULONGLONG nSize,
	PVOID lpNumberOfBytesRead
	);

extern ULONG(NTAPI *NtWow64WriteVirtualMemory64)(
	HANDLE hProcess,
	ULONGLONG lpBaseAddress,
	PVOID lpBuffer,
	ULONGLONG nSize,
	PVOID lpNumberOfBytesRead
	);

extern ULONG(NTAPI *NtWow64AllocateVirtualMemory64)(
	HANDLE   ProcessHandle,
	PVOID   BaseAddress,
	ULONGLONG ZeroBits,
	PVOID   RegionSize,
	ULONG   AllocationType,
	ULONG   Protection
	);


WCHAR * EncryTextW(const WCHAR * src);

WCHAR * DecryTextW(const WCHAR * src);

//
//typedef struct PATCHDATA{
//	CHAR
//	PVOID AddrOffset;
//	UCHAR PatchSize;
//	UCHAR PatchCode[64];
//}PATCHDATA;