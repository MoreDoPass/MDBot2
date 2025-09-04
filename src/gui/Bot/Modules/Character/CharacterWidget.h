#pragma once

#include <QWidget>
#include <QLoggingCategory>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QTimer>
#include "core/Bot/Character/Character.h"
#include "core/Bot/Movement/MovementManager.h"  // Добавляем MovementManager

/**
 * @brief Категория логирования для CharacterWidget.
 */
Q_DECLARE_LOGGING_CATEGORY(logCharacterWidget)

/**
 * @brief Виджет для отображения и управления данными персонажа WoW.
 *
 * Отображает основные характеристики персонажа, поддерживает ручное и автоматическое обновление.
 */
class CharacterWidget : public QWidget
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор CharacterWidget.
     * @param character Указатель на объект Character.
     * @param movementManager Указатель на объект MovementManager для отправки команд.
     * @param parent Родительский виджет.
     */
    explicit CharacterWidget(Character* character, MovementManager* movementManager, QWidget* parent = nullptr);
    ~CharacterWidget() override;

   private slots:
    /**
     * @brief Слот для ручного обновления данных персонажа.
     */
    void onUpdateClicked();
    /**
     * @brief Слот для автообновления данных персонажа.
     */
    void onAutoUpdateTimeout();
    /**
     * @brief Слот для обработки изменения данных персонажа.
     * @param data Новые данные персонажа.
     */
    void onCharacterDataChanged(const CharacterData& data);

   private:
    Character* m_character = nullptr;
    MovementManager* m_movementManager = nullptr;
    QLabel* m_nameLabel = nullptr;
    QLabel* m_levelLabel = nullptr;
    QLabel* m_healthLabel = nullptr;
    QLabel* m_manaLabel = nullptr;
    QLabel* m_positionLabel = nullptr;
    QLabel* m_mapIdLabel = nullptr;
    QLabel* m_stateLabel = nullptr;
    QPushButton* m_updateButton = nullptr;
    QCheckBox* m_autoUpdateCheck = nullptr;
    QTimer* m_autoUpdateTimer = nullptr;

    /**
     * @brief Обновляет отображение данных персонажа в UI.
     * @param data Данные персонажа.
     */
    void updateUi(const CharacterData& data);
    /**
     * @brief Логирует ошибку отображения.
     * @param message Сообщение об ошибке.
     */
    void logError(const QString& message);
};