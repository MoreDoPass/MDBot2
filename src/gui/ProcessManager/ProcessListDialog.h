#pragma once
#include <QDialog>
#include <vector>
#include "core/ProcessManager/ProcessManager.h"

class QListWidget;
class QPushButton;
class QLineEdit;
class QLabel;

/**
 * @brief Диалог выбора процесса WoW (например, run.exe)
 */
class ProcessListDialog : public QDialog
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор
     * @param parent Родительский виджет
     */
    explicit ProcessListDialog(QWidget* parent = nullptr);
    /**
     * @brief Получить выбранный процесс
     * @return Структура ProcessInfo
     */
    ProcessInfo selectedProcess() const;

    /**
     * @brief Получить имя компьютера, введенное пользователем.
     * @return QString с именем.
     */
    QString computerName() const;

   private slots:
    void refreshProcessList();
    void acceptSelection();

   private:
    void updateProcessList();
    QListWidget* listWidget;
    QPushButton* refreshButton;
    QPushButton* okButton;
    QLineEdit* m_computerNameEdit;  ///< Поле для ввода имени компьютера
    std::vector<ProcessInfo> processes;
    int selectedRow = -1;
};