#ifndef HOOK_H
#define HOOK_H

#include <cstdint>
#include <QByteArray>
#include <QString>

/**
 * @brief Абстрактный базовый класс для всех хуков.
 * Наследуйте этот класс для реализации специфичных хуков в модулях.
 */
class Hook
{
   protected:
    uintptr_t m_address = 0;     ///< Адрес, на который ставится хук
    QByteArray m_originalBytes;  ///< Оригинальные байты по адресу
    bool m_installed = false;    ///< Флаг установленного хука

   public:
    explicit Hook(uintptr_t address) : m_address(address) {}
    virtual ~Hook() = default;

    /**
     * @brief Установить хук
     * @return true, если успешно
     */
    virtual bool install() = 0;

    /**
     * @brief Снять хук
     * @return true, если успешно
     */
    virtual bool uninstall() = 0;

    /**
     * @brief Проверить, установлен ли хук
     * @return true, если хук установлен
     */
    bool isInstalled() const
    {
        return m_installed;
    }

    /**
     * @brief Получить адрес хука
     */
    uintptr_t address() const
    {
        return m_address;
    }

    /**
     * @brief Получить оригинальные байты
     */
    const QByteArray& originalBytes() const
    {
        return m_originalBytes;
    }

    /**
     * @brief Получить строковое описание хука (можно переопределить)
     */
    virtual QString description() const
    {
        return QString("Base Hook at 0x%1").arg(m_address, 0, 16);
    }
};

#endif  // HOOK_H