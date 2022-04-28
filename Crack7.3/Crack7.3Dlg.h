
// Crack7.3Dlg.h: 头文件
//

#pragma once


// CCrack73Dlg 对话框
class CCrack73Dlg : public CDialogEx
{
// 构造
public:
	CCrack73Dlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MAINWIN_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CButton ckCrack;
	CStatic labVer;
	afx_msg void OnBnClickedButton1();
	CStatic labMe;
	CStatic lab_qq;
	CButton btnStart;
};
