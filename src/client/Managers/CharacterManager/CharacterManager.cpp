#include "CharacterManager.h"
#include "shared/Structures/Offsets.h"
#include "client/Managers/GameObjectManager.h"
#include "shared/Structures/Player.h"     // Нужен для reinterpret_cast<Unit*> и доступа к полям
#include "shared/Structures/Cooldowns.h"  // Нужен для структуры CooldownInfoNode
#include <windows.h>                      // Нужен для OutputDebugStringA и __try/__except

CharacterManager::CharacterManager()
{
    // Конструктор. Пока пустой, но готов для будущей инициализации.
}

void CharacterManager::update(SharedData* sharedData, uintptr_t playerPtr)
{
    // Проверяем, валиден ли указатель на нашего игрока.
    // Если CharacterHook еще не сработал, playerPtr будет равен 0.
    if (playerPtr == 0)
    {
        // Обязательно очищаем данные, чтобы "мозг" не работал с мусором с прошлого тика.
        memset(&sharedData->player, 0, sizeof(PlayerData));
        return;
    }

    try
    {
        // --- БЛОК 1: Чтение базовых данных из структур игры ---
        Unit* playerUnit = reinterpret_cast<Unit*>(playerPtr);

        // Заполняем основные поля в нашей структуре PlayerData
        sharedData->player.baseAddress = playerPtr;
        sharedData->player.guid = playerUnit->guid;
        sharedData->player.position = playerUnit->m_movement.position;
        sharedData->player.orientation = playerUnit->m_movement.orientation;

        // Читаем данные из вложенной структуры pUnitProperties.
        // Обязательно проверяем указатель на валидность.
        if (playerUnit->pUnitProperties)
        {
            sharedData->player.Health = playerUnit->pUnitProperties->currentHealth;
            sharedData->player.maxHealth = playerUnit->pUnitProperties->maxHealth;
            sharedData->player.Mana = playerUnit->pUnitProperties->currentMana;
            sharedData->player.maxMana = playerUnit->pUnitProperties->maxMana;
            // --- Чтение дополнительных ресурсов ---
            // Читаем Ярость. В памяти она хранится умноженной на 10 (например, 374),
            // поэтому мы делим на 10, чтобы получить нормальное значение (37).
            sharedData->player.Rage = playerUnit->pUnitProperties->currentRage / 10;

            // Читаем Энергию. Она хранится 1 к 1, деление не требуется.
            sharedData->player.Energy = playerUnit->pUnitProperties->currentEnergy;

            // Читаем Силу Рун. Аналогично Ярости, хранится * 10.
            sharedData->player.RunicPower = playerUnit->pUnitProperties->currentRunicPower / 10;
            sharedData->player.level = playerUnit->pUnitProperties->level;
            sharedData->player.flags = playerUnit->pUnitProperties->flags;
            uint64_t high = playerUnit->pUnitProperties->targetGuid_high;
            uint64_t low = playerUnit->pUnitProperties->targetGuid_low;
            sharedData->player.targetGuid = (high << 32) | low;
        }
        else
        {
            // Если pUnitProperties по какой-то причине стал невалидным (например, во время выхода из игры),
            // мы должны обнулить зависимые поля, чтобы избежать некорректного поведения бота.
            sharedData->player.Health = 0;
            sharedData->player.maxHealth = 0;
            sharedData->player.Mana = 0;
            sharedData->player.maxMana = 0;
            sharedData->player.Rage = 0;
            sharedData->player.Energy = 0;
            sharedData->player.RunicPower = 0;
            sharedData->player.level = 0;
            sharedData->player.flags = 0;
        }
        if (playerUnit->castID != 0)
        {
            sharedData->player.isCasting = true;
            sharedData->player.castingSpellId = playerUnit->castSpellId;
        }
        else
        {
            sharedData->player.isCasting = false;
            sharedData->player.castingSpellId = 0;
        }
        uint64_t autoAttackHigh = playerUnit->autoAttackTargetGuid_high;
        uint64_t autoAttackLow = playerUnit->autoAttackTargetGuid_low;
        sharedData->player.autoAttackTargetGuid = (autoAttackHigh << 32) | autoAttackLow;

        // === 2. ВЫЗЫВАЕМ ВНЕШНИЙ ИНСТРУМЕНТ ДЛЯ ЧТЕНИЯ АУР ===
        // Мы обращаемся к классу GameObjectManager напрямую, чтобы вызвать его статический метод.
        GameObjectManager::readUnitAuras(playerUnit,                    // Указатель на нашего персонажа
                                         sharedData->player.auras,      // "Мешочек" для ID аур из PlayerData
                                         sharedData->player.auraCount,  // Счетчик аур из PlayerData
                                         MAX_AURAS_PER_UNIT);           // Максимальный размер "мешочка"

        // --- БЛОК 3: Чтение уникальных данных (кулдауны) из другой области памяти ---
        // Вызываем наш приватный метод, который теперь является частью этого класса.
        this->readPlayerCooldowns(sharedData->player);

        // --- БЛОК 4: ЧТЕНИЕ СПЕЦИФИЧНЫХ ДЛЯ КЛАССА РЕСУРСОВ (РУНЫ) ---
        // Надо ли делать сделать проверку на класс или всегда читать
        // Этот блок читает данные из статической области памяти, а не из структуры игрока.
        // Поэтому он может выполняться независимо от playerPtr, но для консистентности
        // данных делаем это здесь же, внутри общего try/except блока.
        const volatile uint32_t* runeMaskPtr =
            reinterpret_cast<const volatile uint32_t*>(Offsets::RUNE_STATUS_MASK_ADDR);
        // Разыменовываем указатель и читаем 4 байта (DWORD) с состоянием рун.
        // `volatile` используется как лучшая практика, чтобы компилятор не кэшировал это значение,
        // так как оно постоянно изменяется самим игровым клиентом.
        sharedData->player.runeStatusMask = *runeMaskPtr;
    }
    catch (...)
    {
        // Аварийный обработчик на случай, если структура игрока в памяти
        // будет повреждена или изменится во время чтения.
        OutputDebugStringA(
            "MDBot_Client: CRITICAL - Exception in CharacterManager::update. PlayerData will be cleared.");
        memset(&sharedData->player, 0, sizeof(PlayerData));
    }
}

void CharacterManager::readPlayerCooldowns(PlayerData& playerData)
{
    // В начале каждого вызова мы сбрасываем все данные о кулдаунах.
    // Это гарантирует, что мы не будем работать с "протухшей" информацией с прошлого тика.
    playerData.activeCooldownCount = 0;
    playerData.isGcdActive = false;

    // Статические адреса, которые мы нашли в клиенте для доступа к списку кулдаунов.
    const uintptr_t POINTER_TO_LAST_NODE = 0x00D3F5B0;
    const uintptr_t GAME_TICK_COUNT_ADDR = 0x00B1D618;

    // Используем __try/__except для защиты от падений, если игра изменит
    // структуру списка в момент нашего чтения.
    __try
    {
        // Читаем текущее время игры (количество тиков) ОДИН РАЗ, чтобы все расчеты
        // в этом цикле были согласованы.
        uint32_t currentTime = *(uint32_t*)GAME_TICK_COUNT_ADDR;

        // Получаем адрес самого нового узла в двусвязном списке кулдаунов.
        uintptr_t pLastNodeAddress = *(uintptr_t*)POINTER_TO_LAST_NODE;

        // Проверяем, не пуст ли список. Если указатель на последний узел
        // указывает сам на себя, значит, активных кулдаунов нет.
        if (pLastNodeAddress == POINTER_TO_LAST_NODE || pLastNodeAddress == 0)
        {
            return;  // Выходим из функции, данные уже сброшены в 'false' и '0'.
        }

        // Начинаем обход списка с самого нового узла.
        CooldownInfoNode* pCurrent = (CooldownInfoNode*)pLastNodeAddress;
        int safetyCounter = 0;  // Предохранитель от бесконечных циклов на случай повреждения списка.

        // Идем по списку НАЗАД (через указатель pPrev), пока не вернемся к "голове" списка.
        while (pCurrent != nullptr && (uintptr_t)pCurrent != POINTER_TO_LAST_NODE && safetyCounter < 50)
        {
            // Внутренний __try для защиты от чтения одного "испорченного" узла.
            // Это позволяет продолжить обход, даже если один узел окажется невалидным.
            __try
            {
                CooldownInfoNode* pPrevNode = pCurrent->pPrev;

                // ЗАДАЧА А: ИЩЕМ БОЕВОЙ ГЛОБАЛЬНЫЙ КУЛДАУН (ГКД)
                // Ищем специальный узел-маркер ГКД по его "магическому числу" 133.
                if (pCurrent->TypeGlobalCooldown == 133 && pCurrent->globalCooldown > 0)
                {
                    // Если нашли, вычисляем, прошло ли время ГКД.
                    if ((currentTime - pCurrent->startTime) < pCurrent->globalCooldown)
                    {
                        playerData.isGcdActive = true;
                    }
                }

                // ЗАДАЧА Б: ИЩЕМ ОБЫЧНЫЕ КУЛДАУНЫ СПОСОБНОСТЕЙ
                uint32_t duration = 0;
                // Сначала проверяем личный кулдаун.
                if (pCurrent->spellCooldown > 0)
                {
                    duration = pCurrent->spellCooldown;
                }
                // Если его нет, проверяем категорийный (например, у всех гранат общая категория).
                else if (pCurrent->categoryCooldown > 0)
                {
                    duration = pCurrent->categoryCooldown;
                }

                // Если мы нашли узел с обычным кулдауном, и он еще не прошел...
                if (duration > 0 && (currentTime - pCurrent->startTime) < duration)
                {
                    // ...добавляем его в наш массив для "мозга" бота.
                    if (playerData.activeCooldownCount < MAX_PLAYER_COOLDOWNS)
                    {
                        SpellCooldown& cd = playerData.activeCooldowns[playerData.activeCooldownCount];
                        cd.spellId = pCurrent->spellId;
                        cd.startTime = pCurrent->startTime;
                        cd.duration = duration;
                        playerData.activeCooldownCount++;
                    }
                }

                // Переходим к следующему (предыдущему в списке) узлу.
                pCurrent = pPrevNode;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Если один из узлов оказался "битым", просто прерываем цикл,
                // чтобы не рисковать дальше. Собранные данные все еще будут полезны.
                OutputDebugStringA(
                    "MDBot_Client: CRITICAL - Access violation during cooldown list traversal. Aborting scan.");
                break;
            }
            safetyCounter++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Если произошел сбой на самом начальном этапе (например, игра выгружается),
        // гарантируем, что у "мозга" будут чистые данные.
        OutputDebugStringA(
            "MDBot_Client: CRITICAL - Exception in initial phase of readPlayerCooldowns. Data will be invalid.");
        playerData.activeCooldownCount = 0;
        playerData.isGcdActive = false;
    }
}