#pragma once

#include <cstddef>  // For size_t
#include <QVector3D>

namespace MapEditor
{
namespace PlayerCore
{

// Скопировано из MDBot2/src/core/Bot/Character/Character.h
// (или актуальные значения для WoW Sirus 3.3.5a)
struct PlayerCoordinateOffsets
{
    size_t posX = 0x798;  ///< Смещение X координаты
    size_t posY = 0x79C;  ///< Смещение Y координаты
    size_t posZ = 0x7A0;  ///< Смещение Z координаты
    // Если нужны другие смещения от того же базового указателя для MapEditor,
    // можно добавить их сюда.
};

// Структура для хранения координат, используемая в MapEditor
// struct PlayerPositionData
// {
//     float x = 0.0f;
//     float y = 0.0f;
//     float z = 0.0f;
// };
// Вместо PlayerPositionData будем использовать QVector3D напрямую

}  // namespace PlayerCore
}  // namespace MapEditor