#include "processlistdialog.h"
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QLabel>     // <-- ДОБАВЛЕНО
#include <QLineEdit>  // <-- ДОБАВЛЕНО

ProcessListDialog::ProcessListDialog(QWidget* parent) : QDialog(parent)
{
    setWindowTitle("Выбор процесса WoW (run.exe)");
    resize(400, 300);

    listWidget = new QListWidget(this);

    // --- Новые виджеты для имени компьютера ---
    QLabel* nameLabel = new QLabel("Имя компьютера (оставить пустым, если не нужно):", this);
    m_computerNameEdit = new QLineEdit(this);
    m_computerNameEdit->setPlaceholderText("DESKTOP-RANDOM");  // Пример для пользователя

    refreshButton = new QPushButton("Обновить", this);
    okButton = new QPushButton("OK", this);
    okButton->setEnabled(false);

    QHBoxLayout* buttonLayout = new QHBoxLayout;
    buttonLayout->addWidget(refreshButton);
    buttonLayout->addWidget(okButton);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(listWidget);
    mainLayout->addWidget(nameLabel);           // <-- ДОБАВЛЕНО
    mainLayout->addWidget(m_computerNameEdit);  // <-- ДОБАВЛЕНО
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
    for (const auto& proc : processes)
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

/**
 * @brief Получить имя компьютера, введенное пользователем.
 * @return QString с именем компьютера. Может быть пустым.
 */
QString ProcessListDialog::computerName() const
{
    return m_computerNameEdit->text();
}

void ProcessListDialog::updateProcessList()
{
    processes = ProcessManager::findProcessesByName(L"run.exe");
}
