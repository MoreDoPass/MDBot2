#include "ProcessManager.h"
#include <windows.h>
#include <tlhelp32.h>
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(processManagerLog, "core.processmanager")

std::vector<ProcessInfo> ProcessManager::findProcessesByName(const std::wstring& processName)
{
    std::vector<ProcessInfo> processes;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        qCWarning(processManagerLog) << "Не удалось получить снимок процессов (CreateToolhelp32Snapshot)";
        return processes;
    }
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0)
            {
                processes.push_back({pe.th32ProcessID, std::wstring(pe.szExeFile)});
            }
        } while (Process32NextW(hSnap, &pe));
    }
    else
    {
        qCWarning(processManagerLog) << "Process32FirstW вернул ошибку";
    }
    CloseHandle(hSnap);
    qCInfo(processManagerLog) << "Найдено процессов:" << processes.size();
    return processes;
}
