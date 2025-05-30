#pragma once

#include <QDialog>
#include <vector>
// Относительный путь к ProcessManager.h из tools/MapEditor/src/gui/ProcessSelectionDialog/
// Если ProcessManager.h находится в MDBot2/src/core/ProcessManager/ProcessManager.h
// то путь будет примерно ../../../../core/ProcessManager/ProcessManager.h
// Убедись, что этот путь правильный для твоей системы сборки (CMakeLists.txt)
// #include "ProcessManager/ProcessManager.h" // <--- НЕПРАВИЛЬНЫЙ ПУТЬ
#include "ProcessManager/ProcessManager.h"  // <--- ПРЕДПОЛАГАЕМЫЙ ПРАВИЛЬНЫЙ ПУТЬ

QT_BEGIN_NAMESPACE
namespace Ui
{
class ProcessSelectionDialog;
}
QT_END_NAMESPACE

class QComboBox;
class QPushButton;

class ProcessSelectionDialog : public QDialog
{
    Q_OBJECT

   public:
    // Передаем список процессов в конструктор
    explicit ProcessSelectionDialog(const std::vector<ProcessInfo> &processes, QWidget *parent = nullptr);
    ~ProcessSelectionDialog();

    ProcessInfo getSelectedProcess() const;  // Возвращает выбранный ProcessInfo
    bool isProcessSelected() const;          // Был ли процесс успешно выбран

   private slots:
    void onOkButtonClicked();
    void onCancelButtonClicked();

   private:
    void populateProcessList();

    QComboBox *m_processComboBox;
    QPushButton *m_okButton;
    QPushButton *m_cancelButton;

    const std::vector<ProcessInfo> &m_processes;  // Ссылка на внешний список процессов
    ProcessInfo m_selectedProcess;                // Копия выбранного процесса
    bool m_processSelected = false;
};