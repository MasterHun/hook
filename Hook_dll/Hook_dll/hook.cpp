#include <Windows.h>
#include <stdio.h>

FARPROC g_pOriginFunc = NULL;

BOOL WINAPI MyMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
	MessageBoxA(NULL, "Hacked", "Hooking", MB_OK);
	return TRUE;
}

BOOL Hook_IAT(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew) {
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImport;
	PIMAGE_THUNK_DATA pThunk;
	PBYTE pAddr;
	DWORD dwProtect, dwRVA;
	hMod = GetModuleHandle(NULL);

	pAddr = (PBYTE)hMod;
	pAddr += *((DWORD *)&pAddr[0x3C]);
	dwRVA = *((DWORD*)&pAddr[0x80]);

	pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);
	for (; pImport->Name; pImport++) {
		szLibName = (LPCSTR)((DWORD)hMod + pImport->Name);
		if (!_stricmp(szLibName, szDllName)) {
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImport->FirstThunk);
			for (; pThunk->u1.Function; pThunk++) {
				if (pThunk->u1.Function == (DWORD)pfnOrg) {
					VirtualProtect((LPVOID)&pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwProtect);
					pThunk->u1.Function = (DWORD)pfnNew;
					VirtualProtect((LPVOID)&pThunk->u1.Function, 4, dwProtect, &dwProtect);
					return TRUE;
				}
			}
		}
	}
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		g_pOriginFunc = GetProcAddress(GetModuleHandle(L"User32.dll"), "MessageBoxA");
		Hook_IAT("User32.dll", g_pOriginFunc, (PROC)MyMessageBox);
		break;
	case DLL_PROCESS_DETACH:
		Hook_IAT("User32.dll", (PROC)MyMessageBox, g_pOriginFunc);
		break;
	}
	return TRUE;
}