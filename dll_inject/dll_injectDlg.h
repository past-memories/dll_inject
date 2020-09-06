
// MFCApplication1Dlg.h : 头文件
//

#pragma once
#include "afxeditbrowsectrl.h"
#include "afxwin.h"
#define BUFFER_SIZE 1024
#define MAX_MSG_LENGTH 1024
typedef struct _tagSystemEventLogInfo
{
	int Sys_EventType;
	CString Sys_EventCategory;
	CString Sys_EventDate;
	CString Sys_EventTime;
	CString Sys_EventID;
	CString Sys_EventSource;
	CString Sys_ComputerName;
	CString Sys_ComputerUser;
	CString Sys_EventDesc;
	CString Sys_EventData;
}tagSystemEventLogInfo;

struct NtCreateThreadExBuffer
{
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
};
// CMFCApplication1Dlg 对话框
class CMFCApplication1Dlg : public CDialogEx
{
// 构造
public:
	CMFCApplication1Dlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCAPPLICATION1_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:

	CMFCEditBrowseCtrl m_edit;
	CListBox m_list;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedButton1();
	/*BOOL RemoteLibrary(HANDLE hProcess, LPCSTR lpFileName);*/
	BOOL UnInjectDll3(HANDLE hProcess, LPCWSTR lpcwDllPath, DWORD dwProcessId);
	BOOL UnInjectDll4(HANDLE hProcess, LPCSTR lpcwDllPath, DWORD dwProcessId);
	bool UnInjectDll(const LPCSTR ptszDllFile, DWORD dwProcessId);
	afx_msg void OnBnClickedButton2();
	BOOL RemoteLibrary1(HANDLE hProcess, LPCTSTR lpFileName);
	bool UnInjectDll1(const LPCTSTR ptszDllFile, DWORD dwProcessId);
	CMFCEditBrowseCtrl m_close;
	BOOL EnableDebugPrivilege();
	BOOL IsVistaOrLater();
	HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf);
	BOOL  CMFCApplication1Dlg::InjectDll(DWORD dwProcessId, LPCWSTR lpcwDllPath);
	UINT CMFCApplication1Dlg::ThreadProc(LPVOID lpVoid);
	UINT CMFCApplication1Dlg::ThreadProc1(LPVOID lpVoid);
};
typedef HMODULE(WINAPI * LoadLIB)(LPCWSTR lp);