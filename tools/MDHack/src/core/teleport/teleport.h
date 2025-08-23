#pragma once
#include "core/player/player.h"
#include "core/appcontext.h"

// Класс для пошаговой телепортации игрока в WoW 3.3.5a
class Teleport
{
   public:
    Teleport(Player& player) : m_player(player) {}

    // Пошаговый телепорт: перемещает игрока к цели по шагам
    void setPositionStepwise(float x, float y, float z, float step, AppContext& ctx);

    float getX() const
    {
        return m_player.getX();
    }
    float getY() const
    {
        return m_player.getY();
    }
    float getZ() const
    {
        return m_player.getZ();
    }

   private:
    Player& m_player;
};
