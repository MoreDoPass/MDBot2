#pragma once
#include <QWidget>
#include <QMap>  // <-- Используем для удобного хранения ссылок на элементы
#include "core/Bot/Settings/GatheringSettings.h"

// Прямые объявления
class QLineEdit;
class QPushButton;
class QTreeWidget;      // <-- ЗАМЕНА: QTreeWidget вместо QListWidget
class QTreeWidgetItem;  // <-- Нужно для работы с элементами дерева

class GatheringWidget : public QWidget
{
    Q_OBJECT
   public:
    explicit GatheringWidget(QWidget* parent = nullptr);

    GatheringSettings getSettings() const;

   private slots:
    void onBrowseClicked();

    /**
     * @brief Слот, который вызывается при изменении состояния чекбокса в дереве.
     * @details Обрабатывает логику "родитель-потомок". Если кликнуть по "Горному делу",
     *          то выделятся/снимутся все дочерние руды.
     * @param item Элемент, по которому кликнули.
     * @param column Колонка (в нашем случае всегда 0).
     */
    void onItemChanged(QTreeWidgetItem* item, int column);

   private:
    QLineEdit* m_profilePathLineEdit;
    QPushButton* m_browseButton;
    QTreeWidget* m_resourceTreeWidget;  // <-- ЗАМЕНА

    // Карта для быстрого доступа к родительским элементам ("Горное дело", "Травничество")
    // Ключ - std::string (например, "mining"), значение - указатель на элемент дерева.
    QMap<QString, QTreeWidgetItem*> m_categoryItems;
};