﻿
// Crack7.3.cpp: 定义应用程序的类行为。
//

#include "pch.h"
#include "framework.h"
#include "Crack7.3.h"
#include "Crack7.3Dlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CMainWinApp

BEGIN_MESSAGE_MAP(CMainWinApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CMainWinApp 构造

CMainWinApp::CMainWinApp()
{
	// TODO: 在此处添加构造代码，
	// 将所有重要的初始化放置在 InitInstance 中
}


// 唯一的 CMainWinApp 对象

CMainWinApp theApp;


// CMainWinApp 初始化

BOOL CMainWinApp::InitInstance()
{
	// 如果一个运行在 Windows XP 上的应用程序清单指定要
	// 使用 ComCtl32.dll 版本 6 或更高版本来启用可视化方式，
	//则需要 InitCommonControlsEx()。  否则，将无法创建窗口。
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// 将它设置为包括所有要在应用程序中使用的
	// 公共控件类。
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	setlocale(LC_CTYPE, "");

	WCHAR curPath[256];
	if (!GetCurrentDirectory(256, curPath)) {
		MessageBox(NULL, L"启动错误，请重试", L"致命错误", 0);
		return FALSE;
	}

	HANDLE qHandle;
	WCHAR *exeName = DecryTextW(gProcImageName);
	WCHAR tempPath[512];

	wsprintfW(tempPath, L"%s\\bin\\%s", curPath, exeName);
	
	qHandle = CreateFile(tempPath, GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (INVALID_HANDLE_VALUE == qHandle) {
		wsprintfW(tempPath, L"%s\\%s", curPath, exeName);
		qHandle = CreateFile(tempPath, GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
		if (INVALID_HANDLE_VALUE == qHandle) {

			exeName = DecryTextW(gProcImageName2);
			wsprintfW(tempPath, L"%s\\bin\\%s", curPath, exeName);
			qHandle = CreateFile(tempPath, GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
			if (INVALID_HANDLE_VALUE == qHandle) {
				wsprintfW(tempPath, L"%s\\%s", curPath, exeName);
				qHandle = CreateFile(tempPath, GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
				if (INVALID_HANDLE_VALUE == qHandle) {
					MessageBox(NULL, L"请将程序放到 思科模拟器 根目录 或 bin 目录下执行", L"启动失败", 0);
					//return FALSE;
				}
			}
		}
	}
	

	InitializeNtFunction();

	//HANDLE hP = OpenProcess(PROCESS_ALL_ACCESS, 0, GetCurrentProcessId());
	//TRACE("\n%llX\n", GetBaseAddress64(hP));
	
	delete[]exeName;
	wcscpy_s(gImagePath, tempPath);
	CloseHandle(qHandle);

	/*AllocConsole();
	FILE* outStrem;
	freopen_s(&outStrem, "conout$", "w", stdout);*/

	//printf("%llX\n", GetProcessModuleHandle64(hP, L"ntdll.dll"));

	//printf("%llX\n", GetProcAddress64(hP,GetProcessModuleHandle64(hP, L"ntdll.dll"),"NtProtectVirtualMemory"));

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	// 创建 shell 管理器，以防对话框包含
	// 任何 shell 树视图控件或 shell 列表视图控件。
	CShellManager *pShellManager = new CShellManager;

	// 激活“Windows Native”视觉管理器，以便在 MFC 控件中启用主题
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	// 标准初始化
	// 如果未使用这些功能并希望减小
	// 最终可执行文件的大小，则应移除下列
	// 不需要的特定初始化例程
	// 更改用于存储设置的注册表项
	// TODO: 应适当修改该字符串，
	// 例如修改为公司或组织名
	//SetRegistryKey(_T("应用程序向导生成的本地应用程序"));

	CCrack73Dlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	
	// 删除上面创建的 shell 管理器。
	if (pShellManager != nullptr)
	{
		delete pShellManager;
	}

#if !defined(_AFXDLL) && !defined(_AFX_NO_MFC_CONTROLS_IN_DIALOGS)
	ControlBarCleanUp();
#endif

	// 由于对话框已关闭，所以将返回 FALSE 以便退出应用程序，
	//  而不是启动应用程序的消息泵。
	return FALSE;
}

