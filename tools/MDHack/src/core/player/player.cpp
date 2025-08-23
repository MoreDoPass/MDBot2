#include "core/player/player.h"

Player::Player(MemoryManager& mem, uintptr_t structAddr) : memory(mem), base(structAddr) {}

/**
 * @brief Читает значение float из памяти целевого процесса.
 * @details Использует шаблонный метод readMemory<float> из MDBot2::MemoryManager.
 * @param addr Адрес, по которому нужно прочитать значение.
 * @return Прочитанное значение float, или 0.0f в случае ошибки.
 */
float Player::readFloat(uintptr_t addr) const
{
    float val = 0.0f;
    // Вызываем шаблонный метод, он принимает адрес и ССЫЛКУ на переменную, куда писать.
    // Третий аргумент (размер) ему не нужен, он вычисляется автоматически через sizeof(T).
    if (!memory.readMemory<float>(addr, val))
    {
        // В случае ошибки чтения можно добавить логирование, если понадобится
        // qCWarning(logPlayer) << "Failed to read float at address" << Qt::hex << addr;
    }
    return val;
}

/**
 * @brief Записывает значение float в память целевого процесса.
 * @details Использует шаблонный метод writeMemory<float> из MDBot2::MemoryManager.
 * @param addr Адрес, по которому нужно записать значение.
 * @param val Значение float для записи.
 */
void Player::writeFloat(uintptr_t addr, float val)
{
    // Вызываем шаблонный метод, он принимает адрес и ЗНАЧЕНИЕ для записи.
    if (!memory.writeMemory<float>(addr, val))
    {
        // В случае ошибки записи можно добавить логирование
        // qCWarning(logPlayer) << "Failed to write float at address" << Qt::hex << addr;
    }
}

float Player::getX() const
{
    return readFloat(base + PlayerOffsets::X);
}

float Player::getY() const
{
    return readFloat(base + PlayerOffsets::Y);
}

float Player::getZ() const
{
    return readFloat(base + PlayerOffsets::Z);
}

void Player::setX(float value)
{
    writeFloat(base + PlayerOffsets::X, value);
}

void Player::setY(float value)
{
    writeFloat(base + PlayerOffsets::Y, value);
}

void Player::setZ(float value)
{
    writeFloat(base + PlayerOffsets::Z, value);
}

uintptr_t Player::getBase() const
{
    return base;
}

void Player::setBase(uintptr_t addr)
{
    base = addr;
}