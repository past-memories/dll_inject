
// MFCApplication1Dlg.cpp : 实现文件
//

#include "stdafx.h"
#include "dll_inject.h"
#include "dll_injectDlg.h"
#include "afxdialogex.h"
#include<TlHelp32.h>
#include <windows.h>
#include <sstream>
#include <fstream>
#include<psapi.h>
#include "afxcmn.h"
#include<winnt.h>
#include<windef.h>
#include<bcrypt.h>
#include"struct.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
//#pragma warning(disable:2664)

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

DWORD g_dwPID = 0;
WCHAR g_szDllPath[MAX_PATH] = { 0 };//用做线程参数
typedef NTSTATUS (WINAPI* LPFUN_NtCreateThreadEx)( 
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
    IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer);

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedButton1A();
	CListCtrl m_systemlog_list;
	virtual BOOL OnInitDialog();
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_systemlog_list);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
	ON_BN_CLICKED(IDOK, &CAboutDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BUTTONA1, &CAboutDlg::OnBnClickedButton1A)
END_MESSAGE_MAP()


// CMFCApplication1Dlg 对话框



CMFCApplication1Dlg::CMFCApplication1Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MFCAPPLICATION1_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCApplication1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MFCEDITBROWSE1, m_edit);
	DDX_Control(pDX, IDC_LIST1, m_list);

	DDX_Control(pDX, IDC_MFCEDITBROWSE2, m_close);
}

BEGIN_MESSAGE_MAP(CMFCApplication1Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CMFCApplication1Dlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCApplication1Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCApplication1Dlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CMFCApplication1Dlg 消息处理程序

BOOL CMFCApplication1Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码


	// TODO: 在此添加额外的初始化代码


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMFCApplication1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCApplication1Dlg::OnPaint()
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
HCURSOR CMFCApplication1Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMFCApplication1Dlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	/*CDialogEx::OnOK();*/
	m_list.ResetContent();
	//创建进程快照
	EnableDebugPrivilege();
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
		AfxMessageBox(_T("快照失败"));
		return;
	}
	PROCESSENTRY32 pe;//结构体指针变量
	pe.dwSize = sizeof(pe);

	if (Process32First(hProcessSnapshot, &pe) == FALSE) {//将查询到的进程信息保存到结构体中
		AfxMessageBox(_T("进程返回失败"));
	}
	TCHAR szChar[MAX_PATH];
	TCHAR *weishu;
	do {
		SYSTEM_INFO pi;
		GetNativeSystemInfo(&pi);
		if (pi.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);//PROCESS_QUERY_INFORMATION
			if (hProcess == NULL) {
				continue;

			}
		
					BOOL wow64;
					if (IsWow64Process(hProcess, &wow64) == FALSE) {
						AfxMessageBox(_T("判断进程bit失败！"));
						return;
					}
					//可能存在虚拟机，所以要判断是否安装的虚拟机程序
					if (wow64)
					{
						//32位
						weishu = _T("32");
					}
					else {
						//64位
						weishu = _T("64");
					}
				}
				else if (pi.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
					//32位
					weishu = _T("32");
				}
				else {
					//其他
					weishu = _T("error");
				}
				_stprintf(szChar, _T("(%s)%s%6d"), weishu, pe.szExeFile,pe.th32ProcessID);
		/*_stprintf(szChar, _T("%s"), pe.szExeFile);*/
			int iListIndex = m_list.AddString(szChar);
			m_list.SetItemData(iListIndex, pe.th32ProcessID);
		
	} while (Process32Next(hProcessSnapshot, &pe));
	
}
char lpfile[MAX_PATH];
void CMFCApplication1Dlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	CString str;
	m_edit.GetWindowText(str);
	//loadlibrary  成功则返回所在模块的句柄
	
	int LIndex = m_list.GetCurSel();
	int nPID = m_list.GetItemData(LIndex);
	g_dwPID = nPID;
	HANDLE hProcess = NULL;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nPID);
	if (hProcess == NULL) {
		AfxMessageBox(_T("进程加载失败"));
	}
	EnableDebugPrivilege();


#ifdef _WIN64

	 /* n = RemoteLibrary(hProcess, str);*/
	USES_CONVERSION;
	LPWSTR pwStr = new wchar_t[str.GetLength() + 1];
	wcscpy(pwStr, T2W((LPCTSTR)str));
	for (int i = 0; i < wcslen(pwStr); i++) {
		g_szDllPath[i] = pwStr[i];
	}
	g_szDllPath[wcslen(pwStr)] = '\0';
	
	if (InjectDll(nPID, pwStr))
	{
		::MessageBox(NULL, "注入成功", ":)", MB_ICONINFORMATION);
	}
	else
	{
		::MessageBox(NULL, "注入失败！", "失败", MB_ICONERROR);
	}
	/*demoNtCreateThreadEx(str, nPID);*/
#else

	if (InjectDll(nPID, str))
	{
		::MessageBox(NULL, L"注入成功",L":)", MB_ICONINFORMATION);
	}
	else
	{
		::MessageBox(NULL, L"注入失败！", L"失败", MB_ICONERROR);
	}
	
	/*int n = RemoteLibrary1(hProcess, str);*/
#endif

    
	
}



//BOOL CMFCApplication1Dlg::RemoteLibrary(HANDLE hProcess, LPCSTR lpFileName)
//{
//	BOOL fResult;
//	TOKEN_PRIVILEGES tkp;
//	HANDLE hToken;
//	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
//	{
//		MessageBox(_T("OpenProcessToken failed!")); //获得进程句柄失败
//	}
//	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid); //获得本地机唯一的标识
//	tkp.PrivilegeCount = 1;
//	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); //调整获得的权限
//	if (GetLastError() != ERROR_SUCCESS)
//	{
//		MessageBox(_T("AdjustTokenPrivileges enable failed!")); //修改权限失败
//	}
//
//	LPVOID pvoid = VirtualAllocEx(hProcess, NULL, (lstrlen(lpFileName) + 1) * sizeof(char), MEM_COMMIT, PAGE_READWRITE);
//	BOOL yes = WriteProcessMemory(hProcess, pvoid, lpFileName, (strlen(lpFileName) + 1) * sizeof(char), NULL);
//	/*BOOL no = ReadProcessMemory(hProcess, pvoid,(LPVOID) lpFileName, lstrlenW(lpFileName)*2+1, NULL);*/
//	/*int n = lstrlenW(lpFileName) + 1;*/
//	/*OutputDebugString();*/
//
//	LPTHREAD_START_ROUTINE pfThread = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(_T("Kernel32.dll")), "LoadLibraryA");
//	//LPTHREAD_START_ROUTINE  指向一个函数，该函数通知宿主某个线程已开始执行。
//	DWORD dwThreaddLL;
//	HANDLE handle = CreateRemoteThread(hProcess, NULL, 0, pfThread, pvoid, 0, &dwThreaddLL);
//
//
//	WaitForSingleObject(handle, INFINITE);
//	DWORD ExitCode;
//
//	CloseHandle(handle);
//	CloseHandle(hProcess);
//	VirtualFreeEx(hProcess, pvoid, 0, MEM_RELEASE);
//	BOOL or1 = GetExitCodeThread(handle, &ExitCode);
//	DWORD it = GetLastError();
//
//	return ExitCode;
//
//
//
//	if (handle == NULL) {
//		AfxMessageBox(_T("sss"));
//
//	}
//	/*FreeLibrary(hmodule);*/
//}
BOOL CMFCApplication1Dlg::RemoteLibrary1(HANDLE hProcess, LPCTSTR lpFileName)
{
	EnableDebugPrivilege();

	LPVOID pvoid = VirtualAllocEx(hProcess, NULL, (_tcslen(lpFileName) + 1) * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pvoid, lpFileName, (_tcslen(lpFileName) + 1) * sizeof(WCHAR), NULL);
	HMODULE hmodule = LoadLibrary(_T("Kernel32.dll"));
	LPTHREAD_START_ROUTINE pfThread = (LPTHREAD_START_ROUTINE)GetProcAddress(hmodule, "LoadLibraryW");
	//LPTHREAD_START_ROUTINE  指向一个函数，该函数通知宿主某个线程已开始执行。
	DWORD dwThreaddLL;
	HANDLE handle = CreateRemoteThread(hProcess, NULL, 0, pfThread, pvoid, 0, &dwThreaddLL);
	FreeLibrary(hmodule);
	WaitForSingleObject(handle, INFINITE);
	DWORD ExitCode;

	CloseHandle(handle);
	CloseHandle(hProcess);
	VirtualFreeEx(hProcess, pvoid, 0, MEM_RELEASE);
	BOOL or1 = GetExitCodeThread(handle, &ExitCode);
	DWORD it = GetLastError();

	return ExitCode;
}

void CAboutDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnOK();
}



void CAboutDlg::OnBnClickedButton1A()
{
	// TODO: 在此添加控件通知处理程序代码


}
//BOOL RemoteFreeLibrary(DWORD dwProcessID,LPCWSTR lpszDll);

BOOL CAboutDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化


	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
char sz[MAX_PATH];

void CMFCApplication1Dlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码

	bool ret;
	CString str;
	m_close.GetWindowText(str);
	//loadlibrary  成功则返回所在模块的句柄

	int LIndex = m_list.GetCurSel();
	int nPID = m_list.GetItemData(LIndex);
	g_dwPID = nPID;
	HANDLE hProcess = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nPID);
	if (hProcess == NULL) {
		AfxMessageBox(_T("进程加载失败"));
	}
	EnableDebugPrivilege();
#ifdef _WIN64
	//USES_CONVERSION;
	//LPWSTR pwStr = new wchar_t[str.GetLength() + 1];
	//wcscpy(pwStr, T2W((LPCTSTR)str));
	//for (int i = 0; i < wcslen(pwStr); i++) {
	//	g_szDllPath[i] = pwStr[i];
	//}
	//g_szDllPath[wcslen(pwStr)] = '\0';
	 ret = UnInjectDll4(hProcess,str, nPID);
#else
	 ret = UnInjectDll3(hProcess, str,nPID);
#endif // !_WIN64

	
	if (!ret) {
		MessageBox(_T("卸载dll失败"));
		return;
	}
	MessageBox(_T("成功卸载"));
}




bool CMFCApplication1Dlg::UnInjectDll(const LPCSTR ptszDllFile, DWORD dwProcessId)
{
	// 参数无效  
	if (!EnableDebugPrivilege())
	{
		MessageBox(_T("提权失败"));
		return FALSE;
	}
	if (NULL == ptszDllFile || 0 == ::strlen(ptszDllFile))
	{
		return false;
	}
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	// 获取模块快照  
	hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hModuleSnap)
	{
		return false;
	}
	MODULEENTRY32 me32;
	memset(&me32, 0, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	// 开始遍历  
	if (FALSE == ::Module32First(hModuleSnap, &me32))
	{
		::CloseHandle(hModuleSnap);
		return false;
	}
	// 遍历查找指定模块  
	bool isFound = false;
	do
	{
#ifdef _WIN64



	isFound =(0 == ::_tcsicmp(me32.szModule,ptszDllFile) || 0 == ::_tcsicmp(me32.szExePath,ptszDllFile));
#else

#endif
		if (isFound) // 找到指定模块  
		{
			break;
		}
	} while (TRUE == ::Module32Next(hModuleSnap, &me32));
	::CloseHandle(hModuleSnap);
	if (false == isFound)
	{
		return false;
	}
	// 获取目标进程句柄  
	hProcess = ::OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		return false;
	}
	// 从 Kernel32.dll 中获取 FreeLibrary 函数地址  
	LPTHREAD_START_ROUTINE lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "FreeLibrary");
	if (NULL == lpThreadFun)
	{
		::CloseHandle(hProcess);
		return false;
	}
	// 创建远程线程调用 FreeLibrary  
	hThread = ::CreateRemoteThread(hProcess, NULL, 0, lpThreadFun, me32.modBaseAddr /* 模块地址 */, 0, NULL);
	if (NULL == hThread)
	{
		::CloseHandle(hProcess);
		return false;
	}
	// 等待远程线程结束  
	::WaitForSingleObject(hThread, INFINITE);
	// 清理  
	::CloseHandle(hThread);
	::CloseHandle(hProcess);
	return true;
}
bool CMFCApplication1Dlg::UnInjectDll1(const LPCTSTR ptszDllFile, DWORD dwProcessId)
{
	// 参数无效  
	if (!EnableDebugPrivilege())
	{
		MessageBox(_T("提权失败"));
		return FALSE;
	}
	if (NULL == ptszDllFile || 0 == ::_tcslen(ptszDllFile))
	{
		return false;
	}
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	// 获取模块快照  
	hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hModuleSnap)
	{
		return false;
	}
	MODULEENTRY32 me32;
	memset(&me32, 0, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	// 开始遍历  
	if (FALSE == ::Module32First(hModuleSnap, &me32))
	{
		::CloseHandle(hModuleSnap);
		return false;
	}
	// 遍历查找指定模块  
	bool isFound = false;
	do
	{
		isFound = (0 == ::_tcsicmp(me32.szModule, ptszDllFile) || 0 == ::_tcsicmp(me32.szExePath, ptszDllFile));
		if (isFound) // 找到指定模块  
		{
			break;
		}
	} while (TRUE == ::Module32Next(hModuleSnap, &me32));
	::CloseHandle(hModuleSnap);
	if (false == isFound)
	{
		return false;
	}
	// 获取目标进程句柄  
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		return false;
	}
	// 从 Kernel32.dll 中获取 FreeLibrary 函数地址  
	LPTHREAD_START_ROUTINE lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32.dll")), "FreeLibrary");
	if (NULL == lpThreadFun)
	{
		::CloseHandle(hProcess);
		return false;
	}
	// 创建远程线程调用 FreeLibrary  
	hThread = ::CreateRemoteThread(hProcess, NULL, 0, lpThreadFun, me32.modBaseAddr /* 模块地址 */, 0, NULL);
	if (NULL == hThread)
	{
		::CloseHandle(hProcess);
		return false;
	}
	// 等待远程线程结束  
	::WaitForSingleObject(hThread, INFINITE);
	// 清理  
	::CloseHandle(hThread);
	::CloseHandle(hProcess);
	return true;
}

BOOL CMFCApplication1Dlg::EnableDebugPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	/*HANDLE hh = OpenProcess(PROCESS_ALL_ACCESS, FALSE, );*/
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return(FALSE);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
	if (GetLastError() != ERROR_SUCCESS)
		return FALSE;

	return TRUE;
}

BOOL CMFCApplication1Dlg::IsVistaOrLater()
{
	OSVERSIONINFO osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);
	if (osvi.dwMajorVersion >= 6)
		return TRUE;
	return FALSE;
}
HANDLE CMFCApplication1Dlg::MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
	HANDLE hThread = NULL;
	FARPROC pFunc = NULL;
	if (IsVistaOrLater())// Vista, 7, Server2008
	{
		pFunc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
#ifdef _WIN64
		((_NtCreateThreadEx64)pFunc)(&hThread, 0x1FFFFF, NULL, hProcess, pThreadProc, pRemoteBuf, FALSE, NULL, NULL, NULL, NULL);
#else
		((LPFUN_NtCreateThreadEx)pFunc)(&hThread, 0x1FFFFF, NULL, hProcess, pThreadProc, pRemoteBuf, FALSE, NULL, NULL, NULL, NULL);
#endif // _WIN64

		
		if (hThread == NULL)
		{

			return NULL;
		}
	}
	else// 2000, XP, Server2003
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
		if (hThread == NULL)
		{

			return NULL;
		}
	}
	if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE))
	{

		return NULL;
	}
	return hThread;
}
BOOL  CMFCApplication1Dlg::InjectDll(DWORD dwProcessId, LPCWSTR lpcwDllPath)
{
	BOOL bRet = FALSE;
	HANDLE hProcess = NULL, hThread = NULL;
	LPVOID pCode = NULL;
	LPVOID pThreadData = NULL;
	__try
	{
		/*if (!EnableDebugPrivilege())
		{
		
			return -1;
		}*/
		//打开目标进程;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
		DWORD dwError = GetLastError();
		if (hProcess == NULL)
			__leave;
		//申请空间，把我们的代码和数据写入目标进程空间里;
		//写入数据;
		THREAD_DATA data;
		HMODULE hNtdll = GetModuleHandleW(L"Kernel32.dll");
		 LoadLIB loadlib = (LoadLIB)GetProcAddress(hNtdll, "LoadLibraryW");
		
		
		data.DllPath = NULL;
		data.Flags = 0;
		data.ModuleHandle = INVALID_HANDLE_VALUE;
		pThreadData = VirtualAllocEx(hProcess, NULL, sizeof(WCHAR)*(wcslen(lpcwDllPath)+1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pThreadData == NULL)
			__leave;
		BOOL bWriteOK = WriteProcessMemory(hProcess, pThreadData, lpcwDllPath, sizeof(WCHAR)*(wcslen(lpcwDllPath) + 1), NULL);
		if (!bWriteOK)
			__leave;
	

		if (!bWriteOK)
			__leave;
		
		//创建远程线程，把ThreadProc作为线程起始函数，pThreadData作为参数;
		hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)loadlib, pThreadData);
		if (hThread == NULL)
			__leave;
		//等待完成;
		WaitForSingleObject(hThread, INFINITE);
		GetDlgItem(IDC_BUTTON1)->EnableWindow(TRUE);
		bRet = TRUE;
	}
	__finally
	{
		if (pThreadData != NULL)
			VirtualFreeEx(hProcess, pThreadData, 0, MEM_RELEASE);
		if (pCode != NULL)
			VirtualFreeEx(hProcess, pCode, 0, MEM_RELEASE);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (hProcess != NULL)
			CloseHandle(hProcess);
	}

	return bRet;
}

BOOL  CMFCApplication1Dlg::UnInjectDll3(HANDLE hProcess, LPCWSTR lpcwDllPath,DWORD dwProcessId)
{
	BOOL bRet = FALSE;
	HANDLE hThread = NULL;
	LPVOID pCode = NULL;
	LPVOID pThreadData = NULL;
	
		if (!EnableDebugPrivilege())
		{

		return -1;
		}
		DWORD dwError = GetLastError();

		if (hProcess == NULL)
			return FALSE;


		//找到指定模块
		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		

		// 获取模块快照  
		hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (INVALID_HANDLE_VALUE == hModuleSnap)
		{
			return false;
		}
		MODULEENTRY32 me32;
		memset(&me32, 0, sizeof(MODULEENTRY32));
		me32.dwSize = sizeof(MODULEENTRY32);
		// 开始遍历  
		if (FALSE == ::Module32First(hModuleSnap, &me32))
		{
			::CloseHandle(hModuleSnap);
			return false;
		}
		// 遍历查找指定模块  
		bool isFound = false;
		
		do
		{
#ifdef _WIN64

#else
			isFound = (0 == ::_tcsicmp(me32.szModule, lpcwDllPath) || 0 == ::_tcsicmp(me32.szExePath, lpcwDllPath));

#endif // _WIN64
	
			if (isFound) // 找到指定模块  
			{
				break;
			}
		} while (TRUE == ::Module32Next(hModuleSnap, &me32));
		::CloseHandle(hModuleSnap);
		if (false == isFound)
		{
			return false;
		}
		//申请空间，把我们的代码和数据写入目标进程空间里;
		//写入数据;
		THREAD_DATA data;
		HMODULE hNtdll = GetModuleHandleW(L"Kernel32.dll");
		LoadLIB loadlib = (LoadLIB)GetProcAddress(hNtdll, "FreeLibrary");


		data.DllPath = NULL;
		data.Flags = 0;
		data.ModuleHandle = INVALID_HANDLE_VALUE;
		//创建远程线程，把ThreadProc作为线程起始函数，pThreadData作为参数;
		hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)loadlib,me32.modBaseAddr);
		if (hThread == NULL)
			return FALSE;
		//等待完成;
		WaitForSingleObject(hThread, INFINITE);
		GetDlgItem(IDC_BUTTON1)->EnableWindow(TRUE);
		bRet = TRUE;
	
		VirtualFreeEx(hProcess, pThreadData, 0, MEM_RELEASE);

		VirtualFreeEx(hProcess, pCode, 0, MEM_RELEASE);
		
		CloseHandle(hThread);
	
		CloseHandle(hProcess);
	

	return bRet;
}
BOOL  CMFCApplication1Dlg::UnInjectDll4(HANDLE hProcess, LPCSTR lpcwDllPath, DWORD dwProcessId)
{
	BOOL bRet = FALSE;
	HANDLE hThread = NULL;
	LPVOID pCode = NULL;
	LPVOID pThreadData = NULL;

	if (!EnableDebugPrivilege())
	{

		return -1;
	}
	DWORD dwError = GetLastError();

	if (hProcess == NULL)
		return FALSE;


	//找到指定模块
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;


	// 获取模块快照  
	hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hModuleSnap)
	{
		return false;
	}
	MODULEENTRY32 me32;
	memset(&me32, 0, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	// 开始遍历  
	if (FALSE == ::Module32First(hModuleSnap, &me32))
	{
		::CloseHandle(hModuleSnap);
		return false;
	}
	// 遍历查找指定模块  
	bool isFound = false;

	do
	{

#ifdef _WIN64
		isFound = (0 == ::_tcsicmp(me32.szModule, (LPCSTR)lpcwDllPath) || 0 == ::_tcsicmp(me32.szExePath, (LPCSTR)lpcwDllPath));
#else

#endif // _WIN64


		


		if (isFound) // 找到指定模块  
		{
			break;
		}
	} while (TRUE == ::Module32Next(hModuleSnap, &me32));
	::CloseHandle(hModuleSnap);
	if (false == isFound)
	{
		return false;
	}
	//申请空间，把我们的代码和数据写入目标进程空间里;
	//写入数据;
	THREAD_DATA data;
	HMODULE hNtdll = GetModuleHandleW(L"Kernel32.dll");
	LoadLIB loadlib = (LoadLIB)GetProcAddress(hNtdll, "FreeLibrary");


	data.DllPath = NULL;
	data.Flags = 0;
	data.ModuleHandle = INVALID_HANDLE_VALUE;
	//创建远程线程，把ThreadProc作为线程起始函数，pThreadData作为参数;
	hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)loadlib, me32.modBaseAddr);
	if (hThread == NULL)
		return FALSE;
	//等待完成;
	WaitForSingleObject(hThread, INFINITE);
	GetDlgItem(IDC_BUTTON1)->EnableWindow(TRUE);
	bRet = TRUE;




	VirtualFreeEx(hProcess, pThreadData, 0, MEM_RELEASE);

	VirtualFreeEx(hProcess, pCode, 0, MEM_RELEASE);

	CloseHandle(hThread);

	CloseHandle(hProcess);


	return bRet;
}
UINT CMFCApplication1Dlg::ThreadProc(LPVOID lpVoid)
{
#ifdef _WIN64
	if (InjectDll(g_dwPID, g_szDllPath))
	{
		::MessageBox(NULL, "注入成功", ":)", MB_ICONINFORMATION);
	}
	else
	{
		::MessageBox(NULL, "注入失败！", "失败", MB_ICONERROR);
	}
	GetDlgItem(IDC_BUTTON1)->EnableWindow(FALSE);
	return 0;



#else
	if (InjectDll(g_dwPID, g_szDllPath))
	{
		::MessageBox(NULL, L"注入成功", L":)", MB_ICONINFORMATION);
	}
	else
	{
		::MessageBox(NULL, L"注入失败！", L"失败", MB_ICONERROR);
	}
	GetDlgItem(IDC_BUTTON1)->EnableWindow(FALSE);
	return 0;
#endif // _WIN64
}
