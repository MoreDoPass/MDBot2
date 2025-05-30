#include "ProcessSelectionDialog.h"
#include <QComboBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLoggingCategory>

// Предполагаем, что ProcessManager.h корректно подключен в ProcessSelectionDialog.h
// и ProcessInfo определен там.

Q_LOGGING_CATEGORY(mapEditorDialogLog, "tools.mapeditor.gui.dialog")  // Для логирования в этом файле, если понадобится

ProcessSelectionDialog::ProcessSelectionDialog(const std::vector<ProcessInfo> &processes, QWidget *parent)
    : QDialog(parent),
      m_processes(processes)  // Инициализируем ссылку на вектор процессов
      ,
      m_selectedProcess({0, L""})  // Инициализируем selectedProcess значением по умолчанию
      ,
      m_processSelected(false)
{
    setWindowTitle(tr("Выбор процесса игры"));

    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    QLabel *infoLabel = new QLabel(tr("Выберите процесс 'run.exe':"), this);
    mainLayout->addWidget(infoLabel);

    m_processComboBox = new QComboBox(this);
    mainLayout->addWidget(m_processComboBox);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    m_okButton = new QPushButton(tr("OK"), this);
    m_cancelButton = new QPushButton(tr("Отмена"), this);

    populateProcessList();

    buttonLayout->addStretch();
    buttonLayout->addWidget(m_okButton);
    buttonLayout->addWidget(m_cancelButton);
    mainLayout->addLayout(buttonLayout);

    setLayout(mainLayout);

    connect(m_okButton, &QPushButton::clicked, this, &ProcessSelectionDialog::onOkButtonClicked);
    connect(m_cancelButton, &QPushButton::clicked, this, &ProcessSelectionDialog::onCancelButtonClicked);
}

ProcessSelectionDialog::~ProcessSelectionDialog()
{
    // Qt автоматически удалит дочерние виджеты
}

void ProcessSelectionDialog::populateProcessList()
{
    m_processComboBox->clear();
    if (m_processes.empty())
    {
        m_processComboBox->addItem(tr("Процессы 'run.exe' не найдены"));
        m_processComboBox->setEnabled(false);
        m_okButton->setEnabled(false);
    }
    else
    {
        for (size_t i = 0; i < m_processes.size(); ++i)
        {
            const auto &process = m_processes[i];
            QString displayText =
                QString::fromStdWString(process.name) + tr(" (PID: ") + QString::number(process.pid) + ")";
            m_processComboBox->addItem(displayText, static_cast<int>(i));
        }
        m_processComboBox->setEnabled(true);
        m_okButton->setEnabled(true);
        if (m_processComboBox->count() > 0)
        {
            m_processComboBox->setCurrentIndex(0);
        }
    }
}

void ProcessSelectionDialog::onOkButtonClicked()
{
    if (m_processComboBox->count() > 0 && m_processComboBox->currentIndex() != -1)
    {
        int selectedIndex = m_processComboBox->currentData().toInt();

        if (selectedIndex >= 0 && static_cast<size_t>(selectedIndex) < m_processes.size())
        {
            m_selectedProcess = m_processes[selectedIndex];
            m_processSelected = true;
            qCDebug(mapEditorDialogLog) << "Выбран процесс:" << QString::fromStdWString(m_selectedProcess.name)
                                        << "PID:" << m_selectedProcess.pid;
            accept();
            return;
        }
        else
        {
            qCWarning(mapEditorDialogLog) << "Некорректный индекс процесса из QComboBox:" << selectedIndex;
        }
    }
    else
    {
        qCWarning(mapEditorDialogLog) << "Кнопка ОК нажата, но процесс не выбран или список пуст.";
    }
    m_processSelected = false;
}

void ProcessSelectionDialog::onCancelButtonClicked()
{
    m_processSelected = false;
    reject();
}

ProcessInfo ProcessSelectionDialog::getSelectedProcess() const
{
    return m_selectedProcess;
}

bool ProcessSelectionDialog::isProcessSelected() const
{
    return m_processSelected;
}

// Для использования QVariant::fromValue(ProcessInfo) и data.value<ProcessInfo>()
// необходимо зарегистрировать ProcessInfo с помощью Q_DECLARE_METATYPE.
// Это нужно сделать где-то в глобальной области видимости, например, в ProcessManager.h или перед первым
// использованием. Q_DECLARE_METATYPE(ProcessInfo) Если ProcessInfo находится в неймспейсе, то
// Q_DECLARE_METATYPE(Namespace::ProcessInfo) Если ProcessManager.h из другой библиотеки, то лучше это сделать в .h
// файле нашего диалога или в .cpp перед первым использованием. В данном случае, можно добавить в
// ProcessSelectionDialog.h до объявления класса: #include "core/ProcessManager/ProcessManager.h" (уже есть)
// Q_DECLARE_METATYPE(ProcessInfo);
//
// Однако, так как ProcessInfo - это простая структура, и мы её используем между компонентами
// одного приложения, можно обойтись и без Q_DECLARE_METATYPE, если мы будем хранить, например, индекс
// и получать PID из исходного вектора `processes`, переданного в `populateProcessList`.
// Но использование QVariant::fromValue/value<T> более типобезопасно и удобно.
// Для простоты сейчас я оставлю этот комментарий, но для правильной работы с QVariant
// регистрация метатипа необходима, если ProcessInfo не является одним из встроенных Qt типов.
//
// В ProcessManager.h структура ProcessInfo уже определена.
// Добавьте Q_DECLARE_METATYPE(ProcessInfo) в конец файла ProcessManager.h или
// в ProcessSelectionDialog.h перед включением ProcessManager.h, если это вызывает проблемы.
// Более простой вариант для начала - хранить только PID (uint32_t) в QVariant, если имя не нужно дальше.
// Но раз у нас ProcessInfo, то лучше ее и хранить.
//
// Давайте предположим, что Q_DECLARE_METATYPE(ProcessInfo) будет добавлен в ProcessManager.h

// Q_DECLARE_METATYPE(ProcessInfo)