#include <stdio.h>
#include <Windows.h>
#include <Tlhelp32.h>
DWORD GetProcessIdByName(LPCTSTR lpszProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof pe;

	if (Process32First(hSnapshot, &pe))
	{
		do {
			if (lstrcmpi(lpszProcessName, pe.szExeFile) == 0)
			{
				CloseHandle(hSnapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return 0;
}
char path[] = "C:\\Users\\Black Sheep\\source\\repos\\CreateRemoteThread\\x64\\Release\\TestDll.dll";

int main()
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, GetProcessIdByName((LPCTSTR)"notepad.exe"));
    
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, lpBaseAddress, path, sizeof(path), NULL);
    LPTHREAD_START_ROUTINE pLoadlibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pLoadlibrary, lpBaseAddress, 0, 0);
    return 0;
}
