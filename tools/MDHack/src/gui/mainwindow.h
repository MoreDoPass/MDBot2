#pragma once

#include <QMainWindow>
#include "processlistdialog.h"
#include "core/appcontext.h"
#include "core/locations/locationmanager.h"
#include <QAbstractNativeEventFilter>

// Прямые объявления, чтобы не включать лишние заголовки
class QTreeWidget;
class QTreeWidgetItem;

// --- Подключаем windows.h последним, чтобы избежать конфликтов ---
#if defined(Q_OS_WIN)
#include <windows.h>
#endif

class MainWindow : public QMainWindow
{
    Q_OBJECT
   public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

   public slots:
    void onSelectProcess();

   private slots:
    void onTreeContextMenu(const QPoint& pos);
    void onTreeChanged();
    void onTreeItemDoubleClicked(QTreeWidgetItem* item, int column);
    void onTeleportToTargetHotkeyPressed();

   protected:
    bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override;

   private:
    /**
     * @brief Обновляет внешний вид элемента дерева (иконку и подсказку) в зависимости от наличия описания.
     * @param item Указатель на элемент, который нужно обновить.
     */
    void updateItemAppearance(QTreeWidgetItem* item);

    /**
     * @brief Рекурсивно обходит все элементы дерева и обновляет их внешний вид.
     * @param parentItem Родительский элемент, с которого начать обход.
     */
    void updateAllItemsAppearance(QTreeWidgetItem* parentItem);

    AppContext* appContext = nullptr;
    QTreeWidget* treeWidget = nullptr;
    LocationManager locationManager;

    const int HOTKEY_ID_TELEPORT_TO_TARGET = 1;
};