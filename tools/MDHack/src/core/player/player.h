#pragma once
#include "core/MemoryManager/MemoryManager.h"
#include <cstdint>

// Смещения координат в структуре игрока WoW 3.3.5a
struct PlayerOffsets
{
    static constexpr uintptr_t X = 0x798;
    static constexpr uintptr_t Y = 0x79C;
    static constexpr uintptr_t Z = 0x7A0;
};

// Класс для работы со структурой игрока WoW 3.3.5a
class Player
{
   public:
    Player(MemoryManager& mem, uintptr_t structAddr);

    float getX() const;
    float getY() const;
    float getZ() const;

    void setX(float value);
    void setY(float value);
    void setZ(float value);

    uintptr_t getBase() const;
    void setBase(uintptr_t addr);

   private:
    MemoryManager& memory;
    uintptr_t base;
    float readFloat(uintptr_t addr) const;
    void writeFloat(uintptr_t addr, float val);
};
