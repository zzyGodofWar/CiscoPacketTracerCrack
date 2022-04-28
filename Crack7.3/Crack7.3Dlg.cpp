
// Crack7.3Dlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "Crack7.3.h"
#include "Crack7.3Dlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CCrack73Dlg 对话框



CCrack73Dlg::CCrack73Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MAINWIN_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCrack73Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CHECK1, ckCrack);
	DDX_Control(pDX, IDC_LABEL1, labVer);
	DDX_Control(pDX, IDC_LABEL2, labMe);
	DDX_Control(pDX, IDC_LABEL3, lab_qq);
	DDX_Control(pDX, IDC_BUTTON1, btnStart);
}

BEGIN_MESSAGE_MAP(CCrack73Dlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CCrack73Dlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CCrack73Dlg 消息处理程序

void CALLBACK TimerCallback(HWND hWnd, UINT uMsg, UINT idEvent, DWORD dwTime);
CStatic *labelMe;
CStatic *labelQQ;


BOOL CCrack73Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	ckCrack.SetCheck(1);
	// TODO: 在此添加额外的初始化代码

	btnStart.EnableWindow(0);
	DWORD size = GetFileVersionInfoSize(gImagePath, NULL);
	if (!size) {
		MessageBox(L"获取文件版本信息失败，请重新启动",L"启动异常",0);
		return FALSE;
	}

	BYTE *verData = new BYTE[size];
	GetFileVersionInfo(gImagePath, NULL, size, verData);

	LPVOID lpBuffer;
	UINT uLength;
	if (!VerQueryValue(verData, L"\\", &lpBuffer, &uLength)) {
		MessageBox(L"获取文件版本信息失败，请重新启动", L"启动异常", 0);
		return FALSE;
	}

	btnStart.EnableWindow(1);
	gImageVersion = ((VS_FIXEDFILEINFO*)lpBuffer)->dwProductVersionMS;
	
	HANDLE hfile = CreateFile(gImagePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

	IMAGE_DOS_HEADER dosHeader = { 0 };
	DWORD finalSize;
	
	SetFilePointer(hfile, 0, 0, FILE_BEGIN);
	ReadFile(hfile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &finalSize, NULL);

	finalSize = dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	SetFilePointer(hfile, finalSize, 0, FILE_BEGIN);

	WORD ntMagic;
	ReadFile(hfile, &ntMagic, sizeof(ntMagic), &finalSize, NULL);
	CloseHandle(hfile);

	switch (ntMagic) {
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		break;
	default:
		MessageBox(L"错误的程序版本", L"启动异常", 0);
		return FALSE;
	}

	WCHAR buf[256];
	wsprintfW(buf, L"当前思科模拟器版本：%d.%d (x%d)", gImageVersion >> 16 & 0xFFFF, gImageVersion & 0xFFFF ,
		ntMagic==IMAGE_NT_OPTIONAL_HDR32_MAGIC?86:64);

	gImageBit = ntMagic;
	labVer.SetWindowTextW(buf);

	labelMe = &labMe;
	labelQQ = &lab_qq;

	SetTimer('ZZZY', 1500, TimerCallback);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE

	
}

WCHAR *QQtext = L"7F2E7F2E142E1C2E182E1E2E172E192E1D2E1D2E1A2E1C2E172E";

void CALLBACK TimerCallback(HWND hWnd,UINT uMsg,UINT idEvent,DWORD dwTime) {

	static char b = 0;
	b = !b;
	WCHAR *text;
	if (b) {
		text =  DecryTextW(ENGZZY2);
	}
	else {
		text = DecryTextW(ENGZZY1);
	}
	labelMe->SetWindowTextW(text);
	delete[]text;
	text = DecryTextW(QQtext);
	labelQQ->SetWindowTextW(text);
	delete[]text;
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CCrack73Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CCrack73Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

BYTE X64Enter[] = { 0x6A, 0x33, 0xE8, 0, 0, 0, 0, 0x83, 0x04, 0x24, 0x05, 0xCB };
BYTE X64Leave[] = {  0xE8, 0, 0, 0, 0, 0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x0D, 0xCB , 0xC3 };


BYTE X64ZwProtectVirtualMemory[] = { 0x48, 0x83, 0xEC, 0x28,
0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0x7F,
0x48, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0x7F,
0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0x7F,
0x49, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0x7F,
0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0x7F,
0x48, 0x89, 0x44, 0x24, 0x20,
0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
0xFF, 0xD0,
0x48, 0x83, 0xC4, 0x28 };


ULONG Wow64NtProtectVirtualMemory(HANDLE hProcess, ULONGLONG lpAddres, ULONGLONG cSize, ULONG newProtect , PULONG oldProtect) {
	static ULONG (__stdcall*ShellZwProtectVirtualMemory)() = 0;
	if (!ShellZwProtectVirtualMemory) {
		*(PVOID*)&ShellZwProtectVirtualMemory = VirtualAlloc(NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		ULONG pos = 0;

		memmove((char*)ShellZwProtectVirtualMemory + pos, X64Enter, sizeof(X64Enter));
		pos += sizeof(X64Enter);

		memmove((char*)ShellZwProtectVirtualMemory + pos, X64ZwProtectVirtualMemory, sizeof(X64ZwProtectVirtualMemory));
		pos += sizeof(X64ZwProtectVirtualMemory);

		memmove((char*)ShellZwProtectVirtualMemory + pos, X64Leave, sizeof(X64Leave));
		pos += sizeof(X64Leave);


		HANDLE hP = OpenProcess(PROCESS_ALL_ACCESS, 0, GetCurrentProcessId());

		*(ULONGLONG*)((char*)ShellZwProtectVirtualMemory + sizeof(X64Enter) + 46) = 
			GetProcAddress64(hP, GetProcessModuleHandle64(hP, L"ntdll.dll"), "NtProtectVirtualMemory");

		CloseHandle(hP);
	}

	*(ULONG*)((char*)ShellZwProtectVirtualMemory + sizeof(X64Enter) + 7) = (ULONG)hProcess;

	*(PVOID*)((char*)ShellZwProtectVirtualMemory + sizeof(X64Enter) + 14) = &lpAddres;

	*(PVOID*)((char*)ShellZwProtectVirtualMemory + sizeof(X64Enter) + 21) = &cSize;

	*(ULONG*)((char*)ShellZwProtectVirtualMemory + sizeof(X64Enter) + 28) = newProtect;

	*(PVOID*)((char*)ShellZwProtectVirtualMemory + sizeof(X64Enter) + 35) = oldProtect;

	return ShellZwProtectVirtualMemory();

}

void DoPatchWork(int version) {
	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION processInformation = { 0 };

	WCHAR folderPath[512];
	wcscpy_s(folderPath, gImagePath);
	for (int i = wcslen(folderPath); i >= 0;i--) {
		if (folderPath[i]==L'\\') {
			folderPath[i] = 0;
			break;
		}
	}

	CreateProcess(gImagePath,NULL,
		NULL,NULL,FALSE,CREATE_SUSPENDED,NULL, folderPath,
		&startupInfo, &processInformation);

	ULONGLONG BaseAddr;
	if (version & 1) {
		BaseAddr = GetProcessModuleHandle32(processInformation.hProcess, NULL);
	}
	else {
		BaseAddr = GetProcessModuleHandle64(processInformation.hProcess, NULL);
	}

	//printf("%llX\n", BaseAddr);

	//ResumeThread(processInformation.hThread);
	//Sleep(500);
	//SuspendThread(processInformation.hThread);

	if (version == 1) {
		ULONGLONG tmpAddr = BaseAddr + 0x16F32EF;
		BYTE code[] = { 0xe9,0x83,0x05,0,0,0x90 };
		SIZE_T finalSize;
		ULONG oldp;

		VirtualProtectEx(processInformation.hProcess, (PVOID)tmpAddr, sizeof(code), PAGE_EXECUTE_READWRITE, &oldp);
		WriteProcessMemory(processInformation.hProcess, (PVOID)tmpAddr, &code, sizeof(code), &finalSize);
	}
	else if(version == 2){
		ULONGLONG tmpAddr = BaseAddr + 0x1E71D16;
		BYTE code[] = { 0xe9,0xa9,0x06,0,0,0x90 };
		ULONGLONG finalSize;
		ULONGLONG rsize = sizeof(code);

		Wow64NtProtectVirtualMemory(processInformation.hProcess, tmpAddr, sizeof(code), PAGE_EXECUTE_READWRITE, (PULONG)&finalSize);
		NtWow64WriteVirtualMemory64(processInformation.hProcess, tmpAddr, &code, sizeof(code), &finalSize);

		//printf("%llX\n", finalSize);

	}else if (version == 4) {
		ULONGLONG tmpAddr = BaseAddr + 0x21815A8;
		BYTE code[] = { 0xe9,0x62,0x09,0,0,0x90 };
		ULONGLONG finalSize;
		ULONG rsize = sizeof(code);

		Wow64NtProtectVirtualMemory(processInformation.hProcess, tmpAddr, sizeof(code), PAGE_EXECUTE_READWRITE, (PULONG)&finalSize);
		NtWow64WriteVirtualMemory64(processInformation.hProcess, tmpAddr, &code, sizeof(code), &finalSize);
	}

	//packettracer7.exe + 0x1E71D16
	//0000000141E71D16 | 0F84 A8060000            | je packettracer7.141E723C4              |
	
	//0000000141E71D16 | E9 A9060000 | jmp packettracer7.141E723C4 |
	//0000000141E71D1B | 90 | nop |

	//MessageBox(0, 0, 0, 0);

	ResumeThread(processInformation.hThread);
	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);

}

void CCrack73Dlg::OnBnClickedButton1()
{
	if (gImageVersion != (7 << 16 | 3)) {
		if (gImageVersion != (8 << 16 | 0)) {
			MessageBox(L"当前思科模拟器版本不在支持列表！", L"启动失败", 0);
			return;
		}
	}

	switch (gImageBit) {
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		DoPatchWork(1);
		break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		if (gImageVersion == (7 << 16 | 3)) {
			DoPatchWork(2);
		}
		else {
			DoPatchWork(4);
		}
		break;
	default:
		MessageBox(L"非法的程序版本", L"启动异常", 0);
		return;
	}

	ExitProcess(0);
}
