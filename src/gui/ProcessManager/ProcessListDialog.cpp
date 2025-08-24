#include "ProcessListDialog.h"
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QLoggingCategory>
#include <QLineEdit>
#include <QLabel>
#include <random>

namespace
{
// Вспомогательная функция для генерации случайного имени
QString generateRandomName()
{
    const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    const int randomStringLength = 12;

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, possibleCharacters.length() - 1);

    QString randomString;
    for (int i = 0; i < randomStringLength; ++i)
    {
        randomString.append(possibleCharacters.at(distribution(generator)));
    }
    return randomString;
}
}  // namespace

ProcessListDialog::ProcessListDialog(QWidget* parent) : QDialog(parent)
{
    setWindowTitle("Выбор процесса и настройка");
    resize(400, 350);

    listWidget = new QListWidget(this);
    refreshButton = new QPushButton("Обновить", this);
    okButton = new QPushButton("OK", this);
    okButton->setEnabled(false);

    // --- Новые элементы ---
    auto* nameLabel = new QLabel("Имя компьютера (оставить пустым для пропуска):", this);
    m_computerNameEdit = new QLineEdit(this);
    m_computerNameEdit->setPlaceholderText("Например, GARIKSUCHKABOY");

    QHBoxLayout* buttonLayout = new QHBoxLayout;
    buttonLayout->addWidget(refreshButton);
    buttonLayout->addWidget(okButton);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(new QLabel("1. Выберите процесс:", this));
    mainLayout->addWidget(listWidget);
    mainLayout->addWidget(nameLabel);
    mainLayout->addWidget(m_computerNameEdit);
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

    // При выборе процесса, подставляем сгенерированное имя для удобства
    connect(listWidget, &QListWidget::itemSelectionChanged, this,
            [this]()
            {
                if (!processes.empty() && selectedRow >= 0)
                {
                    m_computerNameEdit->setText(generateRandomName());
                }
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

QString ProcessListDialog::computerName() const
{
    return m_computerNameEdit->text();
}

void ProcessListDialog::updateProcessList()
{
    try
    {
        processes = ProcessManager::findProcessesByName(L"run.exe");
    }
    catch (const std::exception& ex)
    {
        qCWarning(processManagerLog) << "Ошибка поиска процессов:" << ex.what();
        processes.clear();
    }
}
