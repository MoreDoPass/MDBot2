#include <QMainWindow>
#include "processlistdialog.h"
#include "core/appcontext.h"
#include <qtreewidget.h>
#include "core/locations/locationmanager.h"
#include <QAbstractNativeEventFilter>  // Для обработки сообщений Windows
#include <windows.h>
class MainWindow : public QMainWindow
{
    Q_OBJECT
   public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

   public slots:
    void onSelectProcess();

   private slots:
    void onTreeContextMenu(const QPoint& pos);
    void onTreeChanged();
    void onTreeItemDoubleClicked(QTreeWidgetItem* item, int column);

    /**
     * @brief [НОВЫЙ СЛОТ] Слот, который выполняется при нажатии хоткея телепорта к цели.
     * @details Выполняет всю логику: получает цель, ее координаты и вызывает TeleportExecutor.
     */
    void onTeleportToTargetHotkeyPressed();

   protected:
    /**
     * @brief [НОВЫЙ МЕТОД] Перехватывает нативные события окна (сообщения Windows).
     * @details Мы используем его для отлова сообщения WM_HOTKEY, которое система
     *          посылает нашему окну при нажатии зарегистрированного глобального хоткея.
     * @param eventType Тип события (для Windows это "windows_generic_MSG").
     * @param message Указатель на структуру сообщения (в нашем случае MSG*).
     * @param result Указатель на результат обработки.
     * @return true, если мы обработали событие и оно не должно идти дальше.
     */
    bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override;

   private:
    AppContext* appContext = nullptr;  // Контекст выбранного процесса
    QTreeWidget* treeWidget = nullptr;
    LocationManager locationManager;

    /**
     * @brief [НОВАЯ ПЕРЕМЕННАЯ] Уникальный идентификатор нашего хоткея.
     * @details Нужен для функций RegisterHotKey и UnregisterHotKey.
     */
    const int HOTKEY_ID_TELEPORT_TO_TARGET = 1;
};
