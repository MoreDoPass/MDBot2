#pragma once
#include <QDialog>
#include <QVector>
#include "core/process/processmanager.h"

class QListWidget;
class QPushButton;

class ProcessListDialog : public QDialog {
    Q_OBJECT
public:
    explicit ProcessListDialog(QWidget *parent = nullptr);
    ProcessInfo selectedProcess() const;

private slots:
    void refreshProcessList();
    void acceptSelection();

private:
    void updateProcessList();
    QListWidget *listWidget;
    QPushButton *refreshButton;
    QPushButton *okButton;
    std::vector<ProcessInfo> processes;
    int selectedRow = -1;
};
