#include <QMainWindow>
#include "processlistdialog.h"
#include "core/appcontext.h"
#include <qtreewidget.h>
#include "core/locations/locationmanager.h"

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

   private:
    AppContext* appContext = nullptr;  // Контекст выбранного процесса
    QTreeWidget* treeWidget = nullptr;
    LocationManager locationManager;
};
