#include "teleport.h"
#include <QThread>
#include <cmath>
#include <Windows.h>

// Функция для отправки нажатия или отжатия клавиши в окно WoW по HWND
void sendKeyToWoW(HWND hwnd, WORD vk, bool press)
{
    if (!hwnd) return;
    if (press)
        PostMessage(hwnd, WM_KEYDOWN, vk, 0);
    else
        PostMessage(hwnd, WM_KEYUP, vk, 0);
}

struct FindWoWWindowData
{
    DWORD pid;
    HWND found;
};

BOOL CALLBACK FindWoWWindowProc(HWND hwnd, LPARAM lParam)
{
    auto* data = reinterpret_cast<FindWoWWindowData*>(lParam);
    DWORD winPid = 0;
    GetWindowThreadProcessId(hwnd, &winPid);
    if (winPid == data->pid)
    {
        char className[128] = {0};
        GetClassNameA(hwnd, className, sizeof(className));
        if (strcmp(className, "GxWindowClassD3d") == 0 || strcmp(className, "GxWindowClass") == 0)
        {
            data->found = hwnd;
            return FALSE;  // нашли — останавливаем перебор
        }
    }
    return TRUE;
}

HWND findWoWWindow(DWORD pid)
{
    FindWoWWindowData data{pid, nullptr};
    EnumWindows(FindWoWWindowProc, reinterpret_cast<LPARAM>(&data));
    return data.found;
}

void Teleport::setPositionStepwise(float tx, float ty, float tz, float step, AppContext& ctx)
{
    if (step <= 0) step = 10.0f;
    float x = m_player.getX();
    float y = m_player.getY();
    float z = m_player.getZ();
    uintptr_t playerStruct = m_player.getBase();

    float dx = tx - x;
    float dy = ty - y;
    float dz = tz - z;
    float dist = std::sqrt(dx * dx + dy * dy + dz * dz);
    int steps = static_cast<int>(dist / step);
    if (steps < 1) steps = 1;

    // Получаем HWND окна WoW по PID из AppContext
    HWND hwnd = findWoWWindow(ctx.getPid());

    // Получаем виртуальный код клавиши 'D' (на англ. раскладке)
    const WORD vkD = 0x44;  // 'D'
    bool press = true;
    for (int i = 1; i <= steps; ++i)
    {
        float nx = x + dx * i / steps;
        float ny = y + dy * i / steps;
        float nz = z + dz * i / steps;
        m_player.setX(nx);
        m_player.setY(ny);
        m_player.setZ(nz);
        ctx.resetMoveStepFlag();
        while (ctx.getMoveStepFlag() != 1)
        {
            sendKeyToWoW(hwnd, vkD, press);
            press = !press;
            QThread::msleep(5);
        }
    }
    // После завершения цикла — полное нажатие "d": нажать и отпустить
    sendKeyToWoW(hwnd, vkD, true);
    sendKeyToWoW(hwnd, vkD, false);
}
