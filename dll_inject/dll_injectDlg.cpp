
// MFCApplication1Dlg.cpp : ʵ���ļ�
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

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

DWORD g_dwPID = 0;
WCHAR g_szDllPath[MAX_PATH] = { 0 };//�����̲߳���
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

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CMFCApplication1Dlg �Ի���



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


// CMFCApplication1Dlg ��Ϣ�������

BOOL CMFCApplication1Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������


	// TODO: �ڴ���Ӷ���ĳ�ʼ������


	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CMFCApplication1Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CMFCApplication1Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMFCApplication1Dlg::OnBnClickedOk()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	/*CDialogEx::OnOK();*/
	m_list.ResetContent();
	//�������̿���
	EnableDebugPrivilege();
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
		AfxMessageBox(_T("����ʧ��"));
		return;
	}
	PROCESSENTRY32 pe;//�ṹ��ָ�����
	pe.dwSize = sizeof(pe);

	if (Process32First(hProcessSnapshot, &pe) == FALSE) {//����ѯ���Ľ�����Ϣ���浽�ṹ����
		AfxMessageBox(_T("���̷���ʧ��"));
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
						AfxMessageBox(_T("�жϽ���bitʧ�ܣ�"));
						return;
					}
					//���ܴ��������������Ҫ�ж��Ƿ�װ�����������
					if (wow64)
					{
						//32λ
						weishu = _T("32");
					}
					else {
						//64λ
						weishu = _T("64");
					}
				}
				else if (pi.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
					//32λ
					weishu = _T("32");
				}
				else {
					//����
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
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString str;
	m_edit.GetWindowText(str);
	//loadlibrary  �ɹ��򷵻�����ģ��ľ��
	
	int LIndex = m_list.GetCurSel();
	int nPID = m_list.GetItemData(LIndex);
	g_dwPID = nPID;
	HANDLE hProcess = NULL;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nPID);
	if (hProcess == NULL) {
		AfxMessageBox(_T("���̼���ʧ��"));
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
		::MessageBox(NULL, "ע��ɹ�", ":)", MB_ICONINFORMATION);
	}
	else
	{
		::MessageBox(NULL, "ע��ʧ�ܣ�", "ʧ��", MB_ICONERROR);
	}
	/*demoNtCreateThreadEx(str, nPID);*/
#else

	if (InjectDll(nPID, str))
	{
		::MessageBox(NULL, L"ע��ɹ�",L":)", MB_ICONINFORMATION);
	}
	else
	{
		::MessageBox(NULL, L"ע��ʧ�ܣ�", L"ʧ��", MB_ICONERROR);
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
//		MessageBox(_T("OpenProcessToken failed!")); //��ý��̾��ʧ��
//	}
//	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid); //��ñ��ػ�Ψһ�ı�ʶ
//	tkp.PrivilegeCount = 1;
//	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); //������õ�Ȩ��
//	if (GetLastError() != ERROR_SUCCESS)
//	{
//		MessageBox(_T("AdjustTokenPrivileges enable failed!")); //�޸�Ȩ��ʧ��
//	}
//
//	LPVOID pvoid = VirtualAllocEx(hProcess, NULL, (lstrlen(lpFileName) + 1) * sizeof(char), MEM_COMMIT, PAGE_READWRITE);
//	BOOL yes = WriteProcessMemory(hProcess, pvoid, lpFileName, (strlen(lpFileName) + 1) * sizeof(char), NULL);
//	/*BOOL no = ReadProcessMemory(hProcess, pvoid,(LPVOID) lpFileName, lstrlenW(lpFileName)*2+1, NULL);*/
//	/*int n = lstrlenW(lpFileName) + 1;*/
//	/*OutputDebugString();*/
//
//	LPTHREAD_START_ROUTINE pfThread = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(_T("Kernel32.dll")), "LoadLibraryA");
//	//LPTHREAD_START_ROUTINE  ָ��һ���������ú���֪ͨ����ĳ���߳��ѿ�ʼִ�С�
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
	//LPTHREAD_START_ROUTINE  ָ��һ���������ú���֪ͨ����ĳ���߳��ѿ�ʼִ�С�
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
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CDialogEx::OnOK();
}



void CAboutDlg::OnBnClickedButton1A()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������


}
//BOOL RemoteFreeLibrary(DWORD dwProcessID,LPCWSTR lpszDll);

BOOL CAboutDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��


	return TRUE;  // return TRUE unless you set the focus to a control
				  // �쳣: OCX ����ҳӦ���� FALSE
}
char sz[MAX_PATH];

void CMFCApplication1Dlg::OnBnClickedButton2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	bool ret;
	CString str;
	m_close.GetWindowText(str);
	//loadlibrary  �ɹ��򷵻�����ģ��ľ��

	int LIndex = m_list.GetCurSel();
	int nPID = m_list.GetItemData(LIndex);
	g_dwPID = nPID;
	HANDLE hProcess = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nPID);
	if (hProcess == NULL) {
		AfxMessageBox(_T("���̼���ʧ��"));
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
		MessageBox(_T("ж��dllʧ��"));
		return;
	}
	MessageBox(_T("�ɹ�ж��"));
}




bool CMFCApplication1Dlg::UnInjectDll(const LPCSTR ptszDllFile, DWORD dwProcessId)
{
	// ������Ч  
	if (!EnableDebugPrivilege())
	{
		MessageBox(_T("��Ȩʧ��"));
		return FALSE;
	}
	if (NULL == ptszDllFile || 0 == ::strlen(ptszDllFile))
	{
		return false;
	}
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	// ��ȡģ�����  
	hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hModuleSnap)
	{
		return false;
	}
	MODULEENTRY32 me32;
	memset(&me32, 0, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	// ��ʼ����  
	if (FALSE == ::Module32First(hModuleSnap, &me32))
	{
		::CloseHandle(hModuleSnap);
		return false;
	}
	// ��������ָ��ģ��  
	bool isFound = false;
	do
	{
#ifdef _WIN64



	isFound =(0 == ::_tcsicmp(me32.szModule,ptszDllFile) || 0 == ::_tcsicmp(me32.szExePath,ptszDllFile));
#else

#endif
		if (isFound) // �ҵ�ָ��ģ��  
		{
			break;
		}
	} while (TRUE == ::Module32Next(hModuleSnap, &me32));
	::CloseHandle(hModuleSnap);
	if (false == isFound)
	{
		return false;
	}
	// ��ȡĿ����̾��  
	hProcess = ::OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		return false;
	}
	// �� Kernel32.dll �л�ȡ FreeLibrary ������ַ  
	LPTHREAD_START_ROUTINE lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "FreeLibrary");
	if (NULL == lpThreadFun)
	{
		::CloseHandle(hProcess);
		return false;
	}
	// ����Զ���̵߳��� FreeLibrary  
	hThread = ::CreateRemoteThread(hProcess, NULL, 0, lpThreadFun, me32.modBaseAddr /* ģ���ַ */, 0, NULL);
	if (NULL == hThread)
	{
		::CloseHandle(hProcess);
		return false;
	}
	// �ȴ�Զ���߳̽���  
	::WaitForSingleObject(hThread, INFINITE);
	// ����  
	::CloseHandle(hThread);
	::CloseHandle(hProcess);
	return true;
}
bool CMFCApplication1Dlg::UnInjectDll1(const LPCTSTR ptszDllFile, DWORD dwProcessId)
{
	// ������Ч  
	if (!EnableDebugPrivilege())
	{
		MessageBox(_T("��Ȩʧ��"));
		return FALSE;
	}
	if (NULL == ptszDllFile || 0 == ::_tcslen(ptszDllFile))
	{
		return false;
	}
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	// ��ȡģ�����  
	hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hModuleSnap)
	{
		return false;
	}
	MODULEENTRY32 me32;
	memset(&me32, 0, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	// ��ʼ����  
	if (FALSE == ::Module32First(hModuleSnap, &me32))
	{
		::CloseHandle(hModuleSnap);
		return false;
	}
	// ��������ָ��ģ��  
	bool isFound = false;
	do
	{
		isFound = (0 == ::_tcsicmp(me32.szModule, ptszDllFile) || 0 == ::_tcsicmp(me32.szExePath, ptszDllFile));
		if (isFound) // �ҵ�ָ��ģ��  
		{
			break;
		}
	} while (TRUE == ::Module32Next(hModuleSnap, &me32));
	::CloseHandle(hModuleSnap);
	if (false == isFound)
	{
		return false;
	}
	// ��ȡĿ����̾��  
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		return false;
	}
	// �� Kernel32.dll �л�ȡ FreeLibrary ������ַ  
	LPTHREAD_START_ROUTINE lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32.dll")), "FreeLibrary");
	if (NULL == lpThreadFun)
	{
		::CloseHandle(hProcess);
		return false;
	}
	// ����Զ���̵߳��� FreeLibrary  
	hThread = ::CreateRemoteThread(hProcess, NULL, 0, lpThreadFun, me32.modBaseAddr /* ģ���ַ */, 0, NULL);
	if (NULL == hThread)
	{
		::CloseHandle(hProcess);
		return false;
	}
	// �ȴ�Զ���߳̽���  
	::WaitForSingleObject(hThread, INFINITE);
	// ����  
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
		//��Ŀ�����;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
		DWORD dwError = GetLastError();
		if (hProcess == NULL)
			__leave;
		//����ռ䣬�����ǵĴ��������д��Ŀ����̿ռ���;
		//д������;
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
		
		//����Զ���̣߳���ThreadProc��Ϊ�߳���ʼ������pThreadData��Ϊ����;
		hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)loadlib, pThreadData);
		if (hThread == NULL)
			__leave;
		//�ȴ����;
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


		//�ҵ�ָ��ģ��
		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		

		// ��ȡģ�����  
		hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (INVALID_HANDLE_VALUE == hModuleSnap)
		{
			return false;
		}
		MODULEENTRY32 me32;
		memset(&me32, 0, sizeof(MODULEENTRY32));
		me32.dwSize = sizeof(MODULEENTRY32);
		// ��ʼ����  
		if (FALSE == ::Module32First(hModuleSnap, &me32))
		{
			::CloseHandle(hModuleSnap);
			return false;
		}
		// ��������ָ��ģ��  
		bool isFound = false;
		
		do
		{
#ifdef _WIN64

#else
			isFound = (0 == ::_tcsicmp(me32.szModule, lpcwDllPath) || 0 == ::_tcsicmp(me32.szExePath, lpcwDllPath));

#endif // _WIN64
	
			if (isFound) // �ҵ�ָ��ģ��  
			{
				break;
			}
		} while (TRUE == ::Module32Next(hModuleSnap, &me32));
		::CloseHandle(hModuleSnap);
		if (false == isFound)
		{
			return false;
		}
		//����ռ䣬�����ǵĴ��������д��Ŀ����̿ռ���;
		//д������;
		THREAD_DATA data;
		HMODULE hNtdll = GetModuleHandleW(L"Kernel32.dll");
		LoadLIB loadlib = (LoadLIB)GetProcAddress(hNtdll, "FreeLibrary");


		data.DllPath = NULL;
		data.Flags = 0;
		data.ModuleHandle = INVALID_HANDLE_VALUE;
		//����Զ���̣߳���ThreadProc��Ϊ�߳���ʼ������pThreadData��Ϊ����;
		hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)loadlib,me32.modBaseAddr);
		if (hThread == NULL)
			return FALSE;
		//�ȴ����;
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


	//�ҵ�ָ��ģ��
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;


	// ��ȡģ�����  
	hModuleSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hModuleSnap)
	{
		return false;
	}
	MODULEENTRY32 me32;
	memset(&me32, 0, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	// ��ʼ����  
	if (FALSE == ::Module32First(hModuleSnap, &me32))
	{
		::CloseHandle(hModuleSnap);
		return false;
	}
	// ��������ָ��ģ��  
	bool isFound = false;

	do
	{

#ifdef _WIN64
		isFound = (0 == ::_tcsicmp(me32.szModule, (LPCSTR)lpcwDllPath) || 0 == ::_tcsicmp(me32.szExePath, (LPCSTR)lpcwDllPath));
#else

#endif // _WIN64


		


		if (isFound) // �ҵ�ָ��ģ��  
		{
			break;
		}
	} while (TRUE == ::Module32Next(hModuleSnap, &me32));
	::CloseHandle(hModuleSnap);
	if (false == isFound)
	{
		return false;
	}
	//����ռ䣬�����ǵĴ��������д��Ŀ����̿ռ���;
	//д������;
	THREAD_DATA data;
	HMODULE hNtdll = GetModuleHandleW(L"Kernel32.dll");
	LoadLIB loadlib = (LoadLIB)GetProcAddress(hNtdll, "FreeLibrary");


	data.DllPath = NULL;
	data.Flags = 0;
	data.ModuleHandle = INVALID_HANDLE_VALUE;
	//����Զ���̣߳���ThreadProc��Ϊ�߳���ʼ������pThreadData��Ϊ����;
	hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)loadlib, me32.modBaseAddr);
	if (hThread == NULL)
		return FALSE;
	//�ȴ����;
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
		::MessageBox(NULL, "ע��ɹ�", ":)", MB_ICONINFORMATION);
	}
	else
	{
		::MessageBox(NULL, "ע��ʧ�ܣ�", "ʧ��", MB_ICONERROR);
	}
	GetDlgItem(IDC_BUTTON1)->EnableWindow(FALSE);
	return 0;



#else
	if (InjectDll(g_dwPID, g_szDllPath))
	{
		::MessageBox(NULL, L"ע��ɹ�", L":)", MB_ICONINFORMATION);
	}
	else
	{
		::MessageBox(NULL, L"ע��ʧ�ܣ�", L"ʧ��", MB_ICONERROR);
	}
	GetDlgItem(IDC_BUTTON1)->EnableWindow(FALSE);
	return 0;
#endif // _WIN64
}
