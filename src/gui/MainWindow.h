// ФАЙЛ: src/gui/MainWindow.h

#pragma once

#include <QMainWindow>
#include <QMap>
#include "core/Bot/Bot.h"
#include "gui/ProcessManager/ProcessListDialog.h"

// Прямые объявления
class ProfileManager;
class PartyManager;
class BotWidget;
class QSplitter;
class QTreeWidget;
class QTreeWidgetItem;
class QStackedWidget;

class MainWindow : public QMainWindow
{
    Q_OBJECT
   public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

   private slots:
    // --- Старые слоты, которые остаются ---
    void onAddProcess();
    void onShowLogWindow();
    void onCreatePartyClicked();

    // --- Новые слоты для работы с деревом ---
    /**
     * @brief Вызывается при клике на элемент в дереве навигации.
     * @details Определяет, на какой элемент кликнули (бот или группа),
     *          и переключает QStackedWidget на соответствующий виджет.
     */
    void onNavItemClicked(QTreeWidgetItem* item, int column);

    /**
     * @brief Показывает контекстное меню (правый клик) для элементов дерева.
     * @details Позволяет удалять ботов, расформировывать группы и т.д.
     */
    void showNavContextMenu(const QPoint& pos);

   private:
    // --- Новая структура GUI ---
    QSplitter* m_mainSplitter = nullptr;
    QTreeWidget* m_navTree = nullptr;
    QStackedWidget* m_contentStack = nullptr;

    // --- Корневые элементы дерева для организации ---
    QTreeWidgetItem* m_partiesRoot = nullptr;
    QTreeWidgetItem* m_soloBotsRoot = nullptr;

    // --- Вспомогательные методы для обновления дерева ---
    /**
     * @brief Создает BotWidget, добавляет его в стек и в дерево навигации.
     * @param bot Указатель на созданный объект Bot.
     */
    void addBotToTree(Bot* bot);

    /**
     * @brief Создает PartyWidget, добавляет его в стек и в дерево навигации.
     * @param party Указатель на созданный объект PartyManager.
     */
    void addPartyToTree(PartyManager* party);

    // --- Менеджеры и мастер-списки (без изменений) ---
    ProfileManager* m_profileManager = nullptr;
    QMap<qint64, Bot*> m_bots;
    QList<PartyManager*> m_parties;
};