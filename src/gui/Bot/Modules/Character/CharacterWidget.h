#pragma once
#include <QWidget>
#include <QLoggingCategory>
#include "core/Bot/Character/Character.h"  // Убедись, что путь правильный

// Прямые объявления для уменьшения зависимостей
class QLabel;
class QPushButton;
class QCheckBox;
class QTimer;

Q_DECLARE_LOGGING_CATEGORY(logCharacterWidget)

/**
 * @class CharacterWidget
 * @brief Виджет для отображения информации о персонаже.
 * @details Этот виджет подписывается на сигнал dataChanged от объекта Character
 *          и асинхронно обновляет отображаемую информацию.
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
     * @brief Слот, вызываемый при изменении данных персонажа.
     * @param data Новые данные персонажа.
     */
    void onCharacterDataChanged(const CharacterData& data);

   private:
    /**
     * @brief Обновляет все элементы интерфейса на основе предоставленных данных.
     * @param data Актуальные данные персонажа.
     */
    void updateUi(const CharacterData& data);

    /**
     * @brief Логирует ошибку и показывает ее пользователю.
     * @param message Текст ошибки.
     */
    void logError(const QString& message);

    // --- Поля, которые были удалены ---
    // QPushButton* m_updateButton;
    // QCheckBox* m_autoUpdateCheck;
    // QTimer* m_autoUpdateTimer;
    // MovementManager* m_movementManager;

    // --- Поля, которые остались ---
    Character* m_character;
    QLabel* m_nameLabel;
    QLabel* m_levelLabel;
    QLabel* m_healthLabel;
    QLabel* m_manaLabel;
    QLabel* m_positionLabel;
    QLabel* m_mapIdLabel;
    QLabel* m_stateLabel;
};