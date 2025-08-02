#include "Character.h"
#include <QLoggingCategory>
#include <cstring>

Q_LOGGING_CATEGORY(characterLog, "mdbot.character")

Character::Character(MemoryManager* memoryManager, QObject* parent) : QObject(parent), m_memoryManager(memoryManager)
{
    try
    {
        // Выделяем память в run.exe для хранения указателя на структуру персонажа
        m_savePtrAddress = m_memoryManager->allocMemory(sizeof(uintptr_t));
        if (!m_savePtrAddress)
        {
            qCCritical(characterLog) << "Не удалось выделить память для хранения указателя на структуру персонажа!";
            return;
        }
        qCInfo(characterLog) << "Выделена память для указателя на структуру персонажа по адресу:" << Qt::hex
                             << m_savePtrAddress;

        // Создаём и устанавливаем CharacterHook
        m_hook = new CharacterHook(0x4FA64E, m_memoryManager, reinterpret_cast<uintptr_t>(m_savePtrAddress));
        if (!m_hook->install())
        {
            qCCritical(characterLog) << "Не удалось установить CharacterHook!";
            delete m_hook;
            m_hook = nullptr;
        }
        else
        {
            qCInfo(characterLog) << "CharacterHook успешно установлен на функцию 0x4FA64E";
        }
    }
    catch (const std::exception& ex)
    {
        qCCritical(characterLog) << "Ошибка при создании Character:" << ex.what();
    }
}

Character::~Character()
{
    try
    {
        if (m_hook)
        {
            m_hook->uninstall();
            delete m_hook;
            m_hook = nullptr;
            qCInfo(characterLog) << "CharacterHook снят и удалён";
        }
        if (m_savePtrAddress)
        {
            m_memoryManager->freeMemory(m_savePtrAddress);
            qCInfo(characterLog) << "Освобождена память для указателя на структуру персонажа по адресу:" << Qt::hex
                                 << m_savePtrAddress;
            m_savePtrAddress = nullptr;
        }
    }
    catch (const std::exception& ex)
    {
        qCCritical(characterLog) << "Ошибка при уничтожении Character:" << ex.what();
    }
}

void Character::setBaseAddress(uintptr_t address)
{
    if (m_baseAddress == address || !address) return;
    m_baseAddress = address;
    qCInfo(characterLog) << "Установлен новый базовый адрес структуры персонажа:" << Qt::hex << address;
    updateFromMemory();
}

bool Character::updateFromMemory()
{
    if (!m_memoryManager)
    {
        qCCritical(characterLog) << "MemoryManager не инициализирован!";
        return false;
    }
    if (!m_savePtrAddress)
    {
        qCCritical(characterLog) << "Не выделена память для указателя на структуру персонажа!";
        return false;
    }
    // Читаем указатель на структуру персонажа из выделенной памяти
    uintptr_t newBase = 0;
    if (!m_memoryManager->readMemory(reinterpret_cast<uintptr_t>(m_savePtrAddress), newBase))
    {
        qCWarning(characterLog) << "Не удалось прочитать указатель на структуру персонажа из памяти!";
        return false;
    }
    if (newBase && newBase != m_baseAddress)
    {
        setBaseAddress(newBase);
    }

    try
    {
        CharacterData newData = m_data;
        bool ok = true;
        bool hasDataChanged = false;

        // Чтение данных из структуры персонажа
        if (m_baseAddress)
        {
            ok &= m_memoryManager->readMemory(m_baseAddress + m_offsets.level, newData.level);
            ok &= m_memoryManager->readMemory(m_baseAddress + m_offsets.health, newData.health);
            ok &= m_memoryManager->readMemory(m_baseAddress + m_offsets.maxHealth, newData.maxHealth);
            ok &= m_memoryManager->readMemory(m_baseAddress + m_offsets.mana, newData.mana);
            ok &= m_memoryManager->readMemory(m_baseAddress + m_offsets.maxMana, newData.maxMana);
            ok &= m_memoryManager->readMemory(m_baseAddress + m_offsets.posX, newData.posX);
            ok &= m_memoryManager->readMemory(m_baseAddress + m_offsets.posY, newData.posY);
            ok &= m_memoryManager->readMemory(m_baseAddress + m_offsets.posZ, newData.posZ);
        }
        else
        {
            qCWarning(characterLog) << "Базовый адрес структуры персонажа не получен, часть данных не будет обновлена.";
        }

        // Чтение глобальных данных
        uintptr_t moduleBase = m_memoryManager->getMainModuleBaseAddress();
        if (moduleBase)
        {
            ok &= m_memoryManager->readMemory(moduleBase + m_globalOffsets.mapId, newData.mapId);
        }
        else
        {
            qCWarning(characterLog) << "Не удалось получить базовый адрес главного модуля, MapID не будет обновлен.";
            ok = false;
        }

        if (!ok)
        {
            qCWarning(characterLog) << "Не все данные персонажа удалось прочитать из памяти!";
        }

        if (memcmp(&m_data, &newData, sizeof(CharacterData)) != 0)
        {
            m_data = newData;
            emit dataChanged(m_data);
            qCDebug(characterLog) << "Данные персонажа обновлены: Level:" << m_data.level << "HP:" << m_data.health
                                  << "/" << m_data.maxHealth << "Pos:" << m_data.posX << m_data.posY << m_data.posZ
                                  << "MapID:" << m_data.mapId;
        }
        return ok;
    }
    catch (const std::exception& e)
    {
        qCCritical(characterLog) << "Исключение при обновлении данных персонажа:" << e.what();
        return false;
    }
}

Vector3 Character::GetPosition() const
{
    return Vector3(m_data.posX, m_data.posY, m_data.posZ);
}

uint32_t Character::GetMapId() const
{
    return m_data.mapId;
}
