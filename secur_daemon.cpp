#include <iostream>
#include <tchar.h>
#include <aclapi.h>
#include <sstream>
#include <iterator>
#include <winbase.h>
#include <fileapi.h>
#include <winsvc.h>

using namespace std;

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

#define SERVICE_NAME  (LPSTR)(_T("Secure Daemon"))

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

int _tmain(int argc, TCHAR* argv[])
{
    SERVICE_TABLE_ENTRY ServiceTable[] =
            {
                    {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
                    {NULL, NULL}
            };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
    {
        return GetLastError();
    }

    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    DWORD Status = E_FAIL;

    // Register our service control handler with the SCM
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

    if (g_StatusHandle == NULL) return;

    // Tell the service controller we are starting
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        OutputDebugString(_T(
                                  "SecureDaemon: ServiceMain: SetServiceStatus returned error"));
    }

    // Create a service stop event to wait on later
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL)
    {
        // Tell service controller we are stopped and exit
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
        {
            OutputDebugString(_T(
                                      "SecureDaemon: ServiceMain: SetServiceStatus returned error"));
        }
        return;
    }

    // Tell the service controller we are started
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        OutputDebugString(_T(
                                  "SecureDaemon: ServiceMain: SetServiceStatus returned error"));
    }

    // Start a thread that will perform the main task of the service
    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, argv, 0, NULL);

    // Wait until our worker thread exits signaling that the service needs to stop
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(g_ServiceStopEvent);

    // Tell the service controller we are stopped
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        OutputDebugString(_T(
                                  "SecureDaemon: ServiceMain: SetServiceStatus returned error"));
    }
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
    if (CtrlCode == SERVICE_CONTROL_STOP) {
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            return;

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 4;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
            OutputDebugString(_T(
                                      "SecureDaemon: ServiceCtrlHandler: SetServiceStatus returned error"));
        }

        // This will signal the worker thread to start shutting down
        SetEvent(g_ServiceStopEvent);
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
    const char* custom_log_name = "ServiceWorkerThread";
    HANDLE event_log = RegisterEventSource(NULL, (LPCSTR)custom_log_name);

    TCHAR *path_to_dir = ((TCHAR**)lpParam)[1];

    ReportEvent(event_log, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&path_to_dir), NULL);

    HANDLE file = CreateFile(path_to_dir,
                             FILE_LIST_DIRECTORY,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL,
                             OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                             NULL);
    if (file == INVALID_HANDLE_VALUE) {
        const char *msgbuf = "CreateFile Error";
        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);
        ExitProcess(GetLastError());
    };

    const char *msgbuf = "Directory Opened";
    ReportEvent(event_log, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);

    OVERLAPPED overlapped;
    overlapped.hEvent = CreateEvent(NULL, FALSE, 0, NULL);

    uint8_t change_buf[1024];
    BOOL success = ReadDirectoryChangesW(
            file, change_buf, 1024, TRUE,
            FILE_NOTIFY_CHANGE_LAST_ACCESS,
            NULL, &overlapped, NULL);

    if (!success) {
        const char *msgbuf = "ReadDirectoryChangesW Error";
        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);
        ExitProcess(GetLastError());
    }

    const char *msgbuf1 = "ReadDirectory1";
    ReportEvent(event_log, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf1), NULL);

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
        //DWORD result = WaitForSingleObject(overlapped.hEvent, 0);
        DWORD bytes = 0;
        BOOL result = GetOverlappedResult(file, &overlapped, &bytes, false);
        if (!bytes && GetLastError() != ERROR_IO_INCOMPLETE) {
            const char *msgbuf1 = "GetOverlappedResult Error";
            ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf1), NULL);
        }
        if (bytes) {
            const char *msgbuf = "WAIT HAPPENED!";
            ReportEvent(event_log, EVENTLOG_WARNING_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);

            DWORD bytes_transferred;
            //GetOverlappedResult(file, &overlapped, &bytes_transferred, FALSE);

            auto *event = (FILE_NOTIFY_INFORMATION*)change_buf;

            for (;;) {
                //DWORD name_len = event->FileNameLength / sizeof(wchar_t);
                const char *msgbuf = "We're in FOR";
                ReportEvent(event_log, EVENTLOG_WARNING_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);
                switch (event->Action) {
                    case FILE_ACTION_MODIFIED: {
                        const char *msgbuf = "File opened";
                        ReportEvent(event_log, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);
                        //wprintf(L"    Modified: %.*s\n", name_len, event->FileName);
                    } break;

                    default: {
                        const char *msgbuf = "Unknown action!";
                        ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);
                        //printf("Unknown action!\n");
                    } break;
                }

                // Are there more events to handle?
                if (event->NextEntryOffset) {
                    *((uint8_t**)&event) += event->NextEntryOffset;
                } else {
                    break;
                }
            }

            // Queue the next event
            success = ReadDirectoryChangesW(
                file, change_buf, 1024, TRUE,
                FILE_NOTIFY_CHANGE_LAST_ACCESS,
                NULL, &overlapped, NULL);

            if (!success) {
                const char *msgbuf = "ReadDirectoryChangesW Error";
                ReportEvent(event_log, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (LPCSTR*)(&msgbuf), NULL);
                ExitProcess(GetLastError());
            }
        }

        // Do other loop stuff here...
    }
    return ERROR_SUCCESS;
}