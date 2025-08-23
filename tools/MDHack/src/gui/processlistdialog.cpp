#include "processlistdialog.h"
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>

ProcessListDialog::ProcessListDialog(QWidget *parent) : QDialog(parent)
{
    setWindowTitle("Выбор процесса WoW (run.exe)");
    resize(400, 300);

    listWidget = new QListWidget(this);
    refreshButton = new QPushButton("Обновить", this);
    okButton = new QPushButton("OK", this);
    okButton->setEnabled(false);

    QHBoxLayout *buttonLayout = new QHBoxLayout;
    buttonLayout->addWidget(refreshButton);
    buttonLayout->addWidget(okButton);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(listWidget);
    mainLayout->addLayout(buttonLayout);
    setLayout(mainLayout);

    connect(refreshButton, &QPushButton::clicked, this, &ProcessListDialog::refreshProcessList);
    connect(okButton, &QPushButton::clicked, this, &ProcessListDialog::acceptSelection);
    connect(listWidget, &QListWidget::currentRowChanged,
            [this](int row)
            {
                selectedRow = row;
                okButton->setEnabled(row >= 0);
            });

    refreshProcessList();
}

void ProcessListDialog::refreshProcessList()
{
    updateProcessList();
    listWidget->clear();
    for (const auto &proc : processes)
    {
        listWidget->addItem(QString::fromStdWString(proc.name) + QString(" (PID: %1)").arg(proc.pid));
    }
    okButton->setEnabled(false);
    selectedRow = -1;
}

void ProcessListDialog::acceptSelection()
{
    if (selectedRow >= 0 && selectedRow < static_cast<int>(processes.size()))
    {
        accept();
    }
    else
    {
        QMessageBox::warning(this, "Ошибка", "Пожалуйста, выберите процесс.");
    }
}

ProcessInfo ProcessListDialog::selectedProcess() const
{
    if (selectedRow >= 0 && selectedRow < static_cast<int>(processes.size())) return processes[selectedRow];
    return {0, L""};
}

void ProcessListDialog::updateProcessList()
{
    processes = ProcessManager::findProcessesByName(L"run.exe");
}
