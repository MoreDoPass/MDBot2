// --- НАЧАЛО ФАЙЛА gui/Bot/Modules/Grinding/GrindingWidget.cpp ---
#include "GrindingWidget.h"
#include "core/ProfileManager/ProfileManager.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QGroupBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QLoggingCategory>

// Создаем отдельную категорию логирования для этого виджета
Q_LOGGING_CATEGORY(logGrindingWidget, "mdbot.gui.grindingwidget")

GrindingWidget::GrindingWidget(ProfileManager* profileManager, QWidget* parent)
    : QWidget(parent), m_profileManager(profileManager)  // <-- 2. Инициализируем наш указатель
{
    Q_ASSERT(m_profileManager != nullptr);  // Проверка, что нам передали валидный менеджер

    auto* mainLayout = new QVBoxLayout(this);

    // --- Группа 1: Настройки профиля (маршрута) ---
    auto* profileGroup = new QGroupBox(tr("Профиль гринда"));  // Изменил заголовок для ясности
    auto* formLayout = new QFormLayout();
    m_profilePathLineEdit = new QLineEdit(this);
    m_profilePathLineEdit->setReadOnly(true);  // Пользователь не должен сам вписывать путь
    m_browseButton = new QPushButton(tr("Обзор..."), this);
    auto* profileLayout = new QHBoxLayout();
    profileLayout->addWidget(m_profilePathLineEdit);
    profileLayout->addWidget(m_browseButton);
    formLayout->addRow(tr("Файл профиля:"), profileLayout);
    profileGroup->setLayout(formLayout);
    mainLayout->addWidget(profileGroup);

    // --- Группа 2: Настройки целей для гринда ---
    auto* targetsGroup = new QGroupBox(tr("Цели (можно редактировать)"));
    auto* targetsLayout = new QFormLayout();
    m_npcIdsLineEdit = new QLineEdit(this);
    m_npcIdsLineEdit->setPlaceholderText(tr("ID через запятую, например: 123, 456, 789"));
    targetsLayout->addRow(tr("ID мобов:"), m_npcIdsLineEdit);
    targetsGroup->setLayout(targetsLayout);
    mainLayout->addWidget(targetsGroup);

    mainLayout->addStretch(1);
    setLayout(mainLayout);
    connect(m_browseButton, &QPushButton::clicked, this, &GrindingWidget::onBrowseClicked);
}

GrindingSettings GrindingWidget::getSettings() const
{
    GrindingSettings settings;
    // 1. Получаем путь к профилю (так же, как в GatheringWidget)
    settings.profilePath = m_profilePathLineEdit->text();
    qCInfo(logGrindingWidget) << "Providing settings. Profile path:" << settings.profilePath;

    // 2. Получаем строку с ID мобов из QLineEdit
    const QString npcIdsString = m_npcIdsLineEdit->text();
    std::vector<int> parsedIds;

    // 3. Парсим строку
    // Разбиваем строку "123, 456, 789" на список строк {"123", " 456", " 789"}
    const QStringList idList = npcIdsString.split(',', Qt::SkipEmptyParts);

    for (const QString& idStr : idList)
    {
        bool conversionOk = false;
        // Убираем лишние пробелы и пытаемся преобразовать в число
        const int id = idStr.trimmed().toInt(&conversionOk);

        if (conversionOk)
        {
            parsedIds.push_back(id);
        }
        else
        {
            qCWarning(logGrindingWidget) << "Could not parse NPC ID:" << idStr << "- skipping.";
        }
    }

    settings.npcIdsToGrind = parsedIds;
    qCInfo(logGrindingWidget) << "Providing NPC IDs to grind, count:" << parsedIds.size();

    // 4. Возвращаем полностью заполненную структуру
    return settings;
}

void GrindingWidget::onBrowseClicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, tr("Выбрать файл профиля гринда"), "",
                                                    tr("JSON профили (*.json);;Все файлы (*)"));

    if (filePath.isEmpty())
    {
        return;  // Пользователь нажал "Отмена"
    }

    // Обращаемся к менеджеру для загрузки и парсинга профиля
    const auto profile = m_profileManager->getGrindingProfile(filePath);

    // Проверяем, что профиль успешно загрузился
    if (!profile)
    {
        qCWarning(logGrindingWidget) << "Failed to load grinding profile from" << filePath
                                     << ". It might be invalid or of the wrong type.";
        m_profilePathLineEdit->clear();
        m_npcIdsLineEdit->clear();
        // Тут можно было бы показать QMessageBox с ошибкой, но пока ограничимся логом
        return;
    }

    qCInfo(logGrindingWidget) << "Successfully loaded profile:" << profile->profileName;

    // 1. Заполняем поле с путем к профилю
    m_profilePathLineEdit->setText(filePath);

    // 2. Конвертируем vector<int> с ID мобов в строку "123, 456, ..."
    QStringList idStringList;
    for (int id : profile->mobIdsToGrind)
    {
        idStringList.append(QString::number(id));
    }
    const QString idsString = idStringList.join(", ");

    // 3. Заполняем поле с ID мобов
    m_npcIdsLineEdit->setText(idsString);
    qCInfo(logGrindingWidget) << "Populated UI with" << profile->mobIdsToGrind.size() << "mob IDs.";
}
// --- КОНЕЦ ФАЙЛА gui/Bot/Modules/Grinding/GrindingWidget.cpp ---