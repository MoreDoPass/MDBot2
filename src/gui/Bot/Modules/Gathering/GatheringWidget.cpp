#include "GatheringWidget.h"
#include "core/Database/ResourceDatabase.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QGroupBox>
#include <QLineEdit>
#include <QPushButton>
#include <QTreeWidget>  // <-- ЗАМЕНА
#include <QHeaderView>  // <-- Для красивого отображения
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(logGatheringWidget, "mdbot.gui.gatheringwidget")  // <-- Категория логирования

GatheringWidget::GatheringWidget(QWidget* parent) : QWidget(parent)
{
    auto* mainLayout = new QVBoxLayout(this);

    // --- Настройки профиля (без изменений) ---
    auto* profileGroup = new QGroupBox(tr("Маршрут"));
    auto* formLayout = new QFormLayout();
    m_profilePathLineEdit = new QLineEdit(this);
    m_browseButton = new QPushButton(tr("Обзор..."), this);
    auto* profileLayout = new QHBoxLayout();
    profileLayout->addWidget(m_profilePathLineEdit);
    profileLayout->addWidget(m_browseButton);
    formLayout->addRow(tr("Файл профиля:"), profileLayout);
    profileGroup->setLayout(formLayout);
    mainLayout->addWidget(profileGroup);

    // --- Группа выбора ресурсов для сбора (теперь с деревом) ---
    auto* resourceGroup = new QGroupBox(tr("Что собирать?"));
    auto* resourceLayout = new QVBoxLayout();
    m_resourceTreeWidget = new QTreeWidget(this);
    m_resourceTreeWidget->setHeaderLabel(tr("Ресурсы"));
    m_resourceTreeWidget->header()->setSectionResizeMode(QHeaderView::Stretch);  // Растягиваем колонку
    resourceLayout->addWidget(m_resourceTreeWidget);
    resourceGroup->setLayout(resourceLayout);
    mainLayout->addWidget(resourceGroup);

    // --- ЗАПОЛНЯЕМ ДЕРЕВО ИЗ БАЗЫ ДАННЫХ ---
    const auto& allResources = ResourceDatabase::getInstance().getAllResources();
    for (const auto& resource : allResources)
    {
        // 1. Находим или создаем родительский элемент (категорию)
        QString categoryKey = QString::fromStdString(resource.skill);
        if (categoryKey.isEmpty()) categoryKey = "other";

        QTreeWidgetItem* categoryItem = nullptr;
        if (!m_categoryItems.contains(categoryKey))
        {
            // Создаем красивое имя для категории
            QString categoryName = categoryKey;
            if (categoryKey == "mining")
                categoryName = tr("Горное дело");
            else if (categoryKey == "herbalism")
                categoryName = tr("Травничество");

            categoryItem = new QTreeWidgetItem(m_resourceTreeWidget, {categoryName});
            // --- ИСПРАВЛЕНИЕ ЗДЕСЬ: Убираем автоматическое управление состоянием ---
            categoryItem->setFlags(categoryItem->flags() |
                                   Qt::ItemIsUserCheckable);  // <-- БЫЛО: | Qt::ItemIsAutoTristate
            categoryItem->setCheckState(0, Qt::Unchecked);
            m_categoryItems[categoryKey] = categoryItem;
        }
        else
        {
            categoryItem = m_categoryItems[categoryKey];
        }

        // 2. Создаем дочерний элемент (конкретный ресурс)
        auto* resourceItem = new QTreeWidgetItem(categoryItem, {QString::fromStdString(resource.displayName)});
        resourceItem->setFlags(resourceItem->flags() | Qt::ItemIsUserCheckable);
        resourceItem->setCheckState(0, Qt::Unchecked);

        // 3. САМОЕ ГЛАВНОЕ: Сохраняем ID прямо в элементе.
        // Мы преобразуем вектор ID в строку "1731,2055,3763", чтобы легко хранить и читать.
        QString idsString;
        for (int id : resource.objectEntryIds)
        {
            idsString += QString::number(id) + ",";
        }
        if (!idsString.isEmpty()) idsString.chop(1);  // Удаляем последнюю запятую
        resourceItem->setData(0, Qt::UserRole, idsString);
    }

    setLayout(mainLayout);

    connect(m_browseButton, &QPushButton::clicked, this, &GatheringWidget::onBrowseClicked);
    // Подключаем наш новый слот для обработки кликов по чекбоксам
    connect(m_resourceTreeWidget, &QTreeWidget::itemChanged, this, &GatheringWidget::onItemChanged);
}

GatheringSettings GatheringWidget::getSettings() const
{
    GatheringSettings settings;
    settings.profilePath = m_profilePathLineEdit->text();
    // Добавляем логирование, чтобы видеть, какие настройки мы отдаем
    qCInfo(logGatheringWidget) << "Providing settings. Profile path:" << settings.profilePath;

    std::vector<int> selectedIds;

    // --- СОБИРАЕМ ID С ОТМЕЧЕННЫХ ЭЛЕМЕНТОВ ---
    // Итерируемся по категориям ("mining", "herbalism", ...)
    for (auto it = m_categoryItems.constBegin(); it != m_categoryItems.constEnd(); ++it)
    {
        QTreeWidgetItem* categoryItem = it.value();
        // Итерируемся по дочерним элементам (ресурсам)
        for (int i = 0; i < categoryItem->childCount(); ++i)
        {
            QTreeWidgetItem* resourceItem = categoryItem->child(i);
            // Если на элементе стоит галочка
            if (resourceItem->checkState(0) == Qt::Checked)
            {
                // Достаем нашу строку "1731,2055,3763"
                QString idsString = resourceItem->data(0, Qt::UserRole).toString();
                // Разбиваем ее по запятой и добавляем ID в наш общий список
                for (const QString& idStr : idsString.split(',', Qt::SkipEmptyParts))
                {
                    selectedIds.push_back(idStr.toInt());
                }
            }
        }
    }
    settings.nodeIdsToGather = selectedIds;
    qCInfo(logGatheringWidget) << "Providing node IDs to gather, count:" << selectedIds.size();
    return settings;
}

void GatheringWidget::onItemChanged(QTreeWidgetItem* item, int column)
{
    // Блокируем сигналы, чтобы избежать рекурсивных вызовов
    const QSignalBlocker blocker(m_resourceTreeWidget);

    // Если это родительский элемент ("Горное дело")
    if (item->childCount() > 0)
    {
        // Устанавливаем всем дочерним элементам то же состояние, что и у родителя
        Qt::CheckState state = item->checkState(column);
        for (int i = 0; i < item->childCount(); ++i)
        {
            item->child(i)->setCheckState(column, state);
        }
    }
    else  // Если это дочерний элемент
    {
        // Обновляем состояние родителя
        QTreeWidgetItem* parent = item->parent();
        if (parent)
        {
            int checkedCount = 0;
            for (int i = 0; i < parent->childCount(); ++i)
            {
                if (parent->child(i)->checkState(column) == Qt::Checked)
                {
                    checkedCount++;
                }
            }

            if (checkedCount == 0)
            {
                parent->setCheckState(column, Qt::Unchecked);
            }
            else if (checkedCount == parent->childCount())
            {
                parent->setCheckState(column, Qt::Checked);
            }
            else
            {
                parent->setCheckState(column, Qt::PartiallyChecked);
            }
        }
    }
}

void GatheringWidget::onBrowseClicked()
{
    // --- ИСПРАВЛЕНИЕ ЗДЕСЬ ---
    // Меняем фильтр по умолчанию на JSON, чтобы было удобно выбирать профили.
    QString filePath =
        QFileDialog::getOpenFileName(this, tr("Выбрать файл профиля"), "", tr("JSON профили (*.json);;Все файлы (*)"));
    if (!filePath.isEmpty())
    {
        m_profilePathLineEdit->setText(filePath);
        // Добавляем логирование, чтобы сразу видеть выбранный файл
        qCInfo(logGatheringWidget) << "User selected profile path:" << filePath;
    }
}