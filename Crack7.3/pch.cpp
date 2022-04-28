// pch.cpp: 与预编译标头对应的源文件

#include "pch.h"

WCHAR *gProcImageName = L"BAEA8BEA89EA81EA8FEA9EEABEEA98EA8BEA89EA8FEA98EADDEAC4EA8FEA92EA8FEA";
WCHAR *gProcImageName2 = L"ABFB9AFB98FB90FB9EFB8FFBAFFB89FB9AFB98FB9EFB89FBD5FB9EFB83FB9EFB";
WCHAR gImagePath[512];
DWORD gImageVersion;
WORD gImageBit;

WCHAR* EncryTextW(const WCHAR *src) {
	DWORD len = wcslen(src);
	WCHAR *temp = new WCHAR[4 * len + 1]();
	UCHAR* value;
	UCHAR bit;
	UCHAR srcbit;
	for (int i = 0; i < len; i++) {
		value = (UCHAR*)&src[i];
		for (int n = 0; n < 2; n++) {
			srcbit = ~value[n];
			srcbit ^= ((len % 16) << 4) + (len % 12);
			bit = srcbit / 16;
			temp[i * 4 + n * 2] = L'0' + (bit > 9 ? (L'A' + bit - 10 - L'0') : bit);
			bit = srcbit % 16;
			temp[i * 4 + n * 2 + 1] = L'0' + (bit > 9 ? (L'A' + bit - 10 - L'0') : bit);
		}
	}
	return temp;
}

WCHAR* DecryTextW(const WCHAR *src) {
	DWORD len = wcslen(src);
	WCHAR *temp = new WCHAR[len / 4 + 1]();
	UCHAR value[2];
	UCHAR bit;
	for (int i = 0; i < len / 4; i++) {
		for (int n = 0; n < 2; n++) {
			bit = 0;
			bit += src[i * 4 + n * 2] > L'9' ? (src[i * 4 + n * 2] - L'A' + 10) : (src[i * 4 + n * 2] - L'0');
			bit *= 16;
			bit += src[i * 4 + n * 2 + 1] > L'9' ? (src[i * 4 + n * 2 + 1] - L'A' + 10) : (src[i * 4 + n * 2 + 1] - L'0');
			bit ^= ((len / 4 % 16) << 4) + (len / 4 % 12);
			bit = ~bit;
			value[n] = bit;
		}
		temp[i] = *(WCHAR*)value;
	}
	return temp;
}