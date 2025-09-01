#include "DebugWidget.h"
#include "core/Bot/Bot.h"  // Нужен для указателя m_bot
#include <QVBoxLayout>
#include <QPushButton>
#include <QTableView>
#include <QStandardItemModel>
#include <QHeaderView>  // Для настройки заголовков таблицы

Q_LOGGING_CATEGORY(logDebugWidget, "mdbot.gui.debugwidget")

DebugWidget::DebugWidget(Bot* bot, QWidget* parent) : QWidget(parent), m_bot(bot)
{
    m_refreshButton = new QPushButton(tr("Обновить"), this);
    m_objectsTable = new QTableView(this);
    m_objectsModel = new QStandardItemModel(this);

    m_objectsTable->setModel(m_objectsModel);
    m_objectsModel->setHorizontalHeaderLabels({tr("GUID"), tr("Тип"), tr("Позиция (X, Y, Z)")});
    m_objectsTable->horizontalHeader()->setStretchLastSection(true);
    m_objectsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(m_refreshButton);
    layout->addWidget(m_objectsTable);
    setLayout(layout);

    // --- ОЖИВЛЯЕМ КНОПКУ ---
    // Соединяем нажатие кнопки с нашим новым слотом
    connect(m_refreshButton, &QPushButton::clicked, this, &DebugWidget::onRefreshClicked);

    qCInfo(logDebugWidget) << "DebugWidget created.";
}

DebugWidget::~DebugWidget()
{
    qCInfo(logDebugWidget) << "DebugWidget destroyed.";
}

void DebugWidget::onRefreshClicked()
{
    qCDebug(logDebugWidget) << "Refresh button clicked. Emitting request signal.";
    emit refreshRequested();
}

void DebugWidget::onDebugDataReady(const SharedData& data)
{
    qCDebug(logDebugWidget) << "Received data from Bot. Updating table with" << data.visibleObjectCount << "objects.";

    // 1. Очищаем старые данные
    m_objectsModel->clear();

    // 2. Восстанавливаем заголовки (clear() их удаляет)
    m_objectsModel->setHorizontalHeaderLabels({tr("GUID"), tr("Тип"), tr("Позиция (X, Y, Z)")});

    // 3. Заполняем таблицу новыми данными
    for (int i = 0; i < data.visibleObjectCount; ++i)
    {
        const GameObjectInfo& obj = data.visibleObjects[i];

        // Создаем элементы для каждой ячейки в строке
        auto* guidItem = new QStandardItem(QString("0x%1").arg(obj.guid, 16, 16, QChar('0')));
        auto* typeItem = new QStandardItem(QString::number(obj.type));
        auto* posItem = new QStandardItem(QStringLiteral("(%1, %2, %3)")
                                              .arg(obj.position.x, 0, 'f', 2)
                                              .arg(obj.position.y, 0, 'f', 2)
                                              .arg(obj.position.z, 0, 'f', 2));

        // Добавляем строку в модель
        m_objectsModel->appendRow({guidItem, typeItem, posItem});
    }
}