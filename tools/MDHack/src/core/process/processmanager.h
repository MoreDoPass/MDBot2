#pragma once
#include <vector>
#include <string>
#include <cstdint>

struct ProcessInfo {
    uint32_t pid;
    std::wstring name;
};

class ProcessManager {
public:
    static std::vector<ProcessInfo> findProcessesByName(const std::wstring& processName);
private:
    ProcessManager() = delete; // Статический класс
};