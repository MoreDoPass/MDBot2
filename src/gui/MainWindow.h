#pragma once
#include <QMainWindow>
#include <QTabWidget>
#include <QMenuBar>
#include <QLoggingCategory>
#include "gui/ProcessManager/ProcessListDialog.h"
#include "gui/Logging/LogWindow.h"
#include "core/ProfileManager/ProfileManager.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
   public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

   private slots:
    void onAddProcess();
    void onShowLogWindow();

   private:
    QTabWidget* tabWidget = nullptr;
    ProfileManager* m_profileManager = nullptr;
    void addProcessTab(const ProcessInfo& info, const QString& computerName);
};