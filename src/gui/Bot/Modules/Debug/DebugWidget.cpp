#include "DebugWidget.h"
#include "core/Bot/Bot.h"
#include <QVBoxLayout>
#include <QPushButton>
#include <QTableView>
#include <QStandardItemModel>
#include <QHeaderView>
#include <QMenu>  // <-- ДОБАВЛЕНО: для контекстного меню

Q_LOGGING_CATEGORY(logDebugWidget, "mdbot.gui.debugwidget")

DebugWidget::DebugWidget(Bot* bot, QWidget* parent) : QWidget(parent), m_bot(bot)
{
    m_refreshButton = new QPushButton(tr("Обновить"), this);
    m_objectsTable = new QTableView(this);
    m_objectsModel = new QStandardItemModel(this);

    m_objectsTable->setModel(m_objectsModel);
    m_objectsModel->setHorizontalHeaderLabels(
        {tr("GUID"), tr("Тип"), tr("Entry ID"), tr("Позиция (X, Y, Z)"), tr("Ауры (ID)")});
    m_objectsTable->horizontalHeader()->setStretchLastSection(true);
    m_objectsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // --- НОВЫЙ КОД: Включаем контекстное меню ---
    m_objectsTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_objectsTable, &QTableView::customContextMenuRequested, this, &DebugWidget::showContextMenu);
    // --- КОНЕЦ НОВОГО КОДА ---

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(m_refreshButton);
    layout->addWidget(m_objectsTable);
    setLayout(layout);

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

    // --- НОВЫЙ КОД: Сохраняем данные ---
    m_lastReceivedData = data;
    // --- КОНЕЦ НОВОГО КОДА ---

    m_objectsModel->clear();
    m_objectsModel->setHorizontalHeaderLabels(
        {tr("GUID"), tr("Тип"), tr("Entry ID"), tr("Позиция (X, Y, Z)"), tr("Ауры (ID)")});

    for (int i = 0; i < data.visibleObjectCount; ++i)
    {
        const GameObjectInfo& obj = data.visibleObjects[i];
        auto* guidItem = new QStandardItem(QString("0x%1").arg(obj.guid, 16, 16, QChar('0')));
        auto* typeItem = new QStandardItem(QString::number(static_cast<uint32_t>(obj.type)));
        auto* entryIdItem = new QStandardItem(QString::number(obj.entryId));  // <-- ДОБАВЛЯЕМ НОВЫЙ ЭЛЕМЕНТ
        auto* posItem = new QStandardItem(QStringLiteral("(%1, %2, %3)")
                                              .arg(obj.position.x, 0, 'f', 2)
                                              .arg(obj.position.y, 0, 'f', 2)
                                              .arg(obj.position.z, 0, 'f', 2));
        // 1. Формируем строку с ID аур
        QString aurasString;
        if (obj.auraCount > 0)
        {
            QStringList auraIds;
            for (int j = 0; j < obj.auraCount; ++j)
            {
                auraIds.append(QString::number(obj.auras[j]));
            }
            aurasString = auraIds.join(", ");  // Соединяем ID через запятую: "123, 456, 789"
        }

        // 2. Создаем элемент для таблицы
        auto* aurasItem = new QStandardItem(aurasString);
        // --- КОНЕЦ НОВОГО КОДА ---

        // 4. Добавляем новый элемент в строку таблицы
        m_objectsModel->appendRow({guidItem, typeItem, entryIdItem, posItem, aurasItem});
    }
}

// --- НОВЫЙ МЕТОД ---
void DebugWidget::showContextMenu(const QPoint& pos)
{
    // Получаем индекс элемента, по которому кликнули
    QModelIndex index = m_objectsTable->indexAt(pos);
    if (!index.isValid())
    {
        return;  // Кликнули не по элементу
    }

    // Получаем номер строки
    int row = index.row();
    if (row >= m_lastReceivedData.visibleObjectCount)
    {
        return;  // Данные устарели, строки нет
    }

    // Получаем информацию о нашем объекте
    const GameObjectInfo& selectedObject = m_lastReceivedData.visibleObjects[row];

    QMenu contextMenu(this);
    QAction* moveToAct = contextMenu.addAction(tr("Подойти к объекту"));

    // Соединяем действие с лямбда-функцией, которая вызовет движение
    connect(moveToAct, &QAction::triggered, this,
            [this, selectedObject]()
            {
                if (m_bot && m_bot->movementManager())
                {
                    qCInfo(logDebugWidget)
                        << "Sending MoveTo command for object GUID" << Qt::hex << selectedObject.guid;
                    m_bot->movementManager()->moveTo(selectedObject.position);
                }
                else
                {
                    qCCritical(logDebugWidget) << "Cannot send MoveTo command: Bot or MovementManager is null!";
                }
            });

    // Показываем меню в точке, где был клик
    contextMenu.exec(m_objectsTable->viewport()->mapToGlobal(pos));
}