#pragma once
#include <QWidget>
#include <QLoggingCategory>
#include "core/Bot/Character/Character.h"  // Нужен для указателя m_character

// Прямые объявления, чтобы не подключать лишние заголовки .h файлов
class QLabel;
class QPushButton;

Q_DECLARE_LOGGING_CATEGORY(logCharacterWidget)

/**
 * @class CharacterWidget
 * @brief Виджет для отображения информации о персонаже по требованию.
 * @details Этот виджет предоставляет кнопку "Обновить", при нажатии на которую
 *          он обращается к "живым" данным объекта Character и отображает их.
 *          Он больше не использует сигналы или таймеры для автоматического обновления.
 */
class CharacterWidget : public QWidget
{
    Q_OBJECT

   public:
    /**
     * @brief Конструктор.
     * @param character Указатель на объект персонажа, за которым будет следить виджет.
     * @param parent Родительский виджет.
     */
    explicit CharacterWidget(Character* character, QWidget* parent = nullptr);
    ~CharacterWidget() override;

   private slots:
    /**
     * @brief Слот, вызываемый при нажатии на кнопку "Обновить".
     * @details Запускает процесс обновления всех элементов интерфейса.
     */
    void onRefreshClicked();

   private:
    /**
     * @brief Обновляет все элементы интерфейса на основе "живых" данных из Character.
     */
    void updateUi();

    /**
     * @brief Логирует ошибку и показывает ее пользователю.
     * @param message Текст ошибки.
     */
    void logError(const QString& message);

    // --- Поля виджета ---
    Character* m_character;  // Указатель на наш источник данных

    // Элементы GUI
    QLabel* m_guidLabel;
    QLabel* m_levelLabel;
    QLabel* m_healthLabel;
    QLabel* m_manaLabel;
    QLabel* m_positionLabel;
    QLabel* m_aurasLabel;          // <-- Новое поле для отображения аур
    QLabel* m_cooldownsLabel;      // <-- Новое поле для отображения кулдаунов
    QPushButton* m_refreshButton;  // <-- Наша новая кнопка
};