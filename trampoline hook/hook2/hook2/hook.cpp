#include <iostream>
#include <wchar.h>
#include <Windows.h>

BYTE g_pOriginBytes[5] = { 0, };

BOOL hook(LPCSTR szDllName, LPCSTR szFuncName, PROC newFunc) {
	FARPROC OrigFunc;
	PBYTE pByte;
	BYTE pBuf[5] = { 0xe9, 0, };
	DWORD dwOldProtect, dwAddress;
	OrigFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)OrigFunc;
	if (pByte[0] == 0xE9)
		return FALSE;
	VirtualProtect((LPVOID)OrigFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(g_pOriginBytes, OrigFunc, 5);
	dwAddress = (DWORD)newFunc - (DWORD)OrigFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);
	memcpy(OrigFunc, pBuf, 5);
	VirtualProtect((LPVOID)OrigFunc, 5, dwOldProtect, &dwOldProtect);
	return TRUE;
}

BOOL unhook(LPCSTR szDllName, LPCSTR szFuncName) {
	FARPROC pFunc;
	DWORD dwOldProtect;
	
	pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(pFunc, g_pOriginBytes, 5);
	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);
	return TRUE;
}

BOOL WINAPI MyMessageBox() {
	MessageBox(NULL, L"Hooking", L"Hello", MB_OK);
	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		hook("USER32.DLL", "MessageBoxA", (PROC)MyMessageBox);
		break;
	case DLL_PROCESS_DETACH:
		unhook("USER32.DLL", "MessageBoxA");
		break;
	}
	return TRUE;
}