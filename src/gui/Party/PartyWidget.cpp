#include "PartyWidget.h"
#include "core/PartyManager/PartyManager.h"
#include "core/Bot/Bot.h"  // Нужно для доступа к processId() и processName()
#include <QVBoxLayout>
#include <QTableView>
#include <QStandardItemModel>
#include <QHeaderView>
#include <QMenu>  // <-- Нужно для контекстного меню
#include <QComboBox>

// Константа для хранения указателя в модели, чтобы избежать "магических чисел"
constexpr int BotPtrRole = Qt::UserRole + 1;

Q_LOGGING_CATEGORY(logPartyWidget, "gui.partywidget")

PartyWidget::PartyWidget(PartyManager* partyManager, QWidget* parent) : QWidget(parent), m_partyManager(partyManager)
{
    qCInfo(logPartyWidget) << "Creating PartyWidget with data table...";

    auto* layout = new QVBoxLayout(this);

    // 1. Создаем модель, таблицу и делегата
    m_tableModel = new QStandardItemModel(this);
    m_membersTable = new QTableView(this);
    m_membersTable->setModel(m_tableModel);

    // 2. Настраиваем внешний вид таблицы
    m_tableModel->setHorizontalHeaderLabels({"Имя (PID)", "Роль", "Лидер"});
    m_membersTable->horizontalHeader()->setStretchLastSection(true);
    m_membersTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_membersTable->verticalHeader()->hide();

    // Возвращаем политику и connect на саму таблицу.
    // Это более надежный способ, который будет работать для всей строки,
    // включая ячейки с другими виджетами.
    m_membersTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_membersTable, &QTableView::customContextMenuRequested, this, &PartyWidget::onShowContextMenu);

    layout->addWidget(m_membersTable);
    setLayout(layout);

    // 5. Подключаем наш слот обновления к сигналу от PartyManager
    connect(m_partyManager, &PartyManager::partyUpdated, this, &PartyWidget::refreshPartyView);

    // 6. Выполняем первое обновление, чтобы заполнить таблицу
    refreshPartyView();

    qCInfo(logPartyWidget) << "PartyWidget created and connected to PartyManager.";
}

PartyWidget::~PartyWidget()
{
    qCInfo(logPartyWidget) << "PartyWidget destroyed.";
}

void PartyWidget::refreshPartyView()
{
    // Очищаем таблицу, но сохраняем указатели на виджеты (комбобоксы)
    // чтобы потом их можно было безопасно удалить
    QList<QWidget*> oldWidgets;
    for (int row = 0; row < m_tableModel->rowCount(); ++row)
    {
        QWidget* w = m_membersTable->indexWidget(m_tableModel->index(row, 1));
        if (w)
        {
            oldWidgets.append(w);
        }
    }

    m_tableModel->setRowCount(0);

    // Безопасно удаляем старые комбобоксы
    for (QWidget* widget : oldWidgets)
    {
        widget->deleteLater();
    }

    const QList<Bot*> members = m_partyManager->members();

    for (Bot* bot : members)
    {
        if (!bot) continue;

        PartyMemberSettings settings = m_partyManager->getMemberSettings(bot);

        auto* nameItem = new QStandardItem(QString("%1 [%2]").arg(bot->processName()).arg(bot->processId()));
        nameItem->setData(QVariant::fromValue(bot), BotPtrRole);
        nameItem->setEditable(false);  // <-- ИЗМЕНЕНИЕ №1: Явно запрещаем редактирование имени

        // Пустая ячейка-заглушка под комбобокс
        auto* rolePlaceholderItem = new QStandardItem();

        QString leaderString = (m_partyManager->leader() == bot) ? "⭐" : "";
        auto* leaderItem = new QStandardItem(leaderString);
        leaderItem->setTextAlignment(Qt::AlignCenter);
        leaderItem->setEditable(false);  // <-- ИЗМЕНЕНИЕ №2: Явно запрещаем редактирование ячейки лидера

        // Сначала добавляем строку с заглушкой
        int newRow = m_tableModel->rowCount();
        m_tableModel->appendRow({nameItem, rolePlaceholderItem, leaderItem});

        // А теперь создаем и настраиваем ComboBox
        auto* roleComboBox = new QComboBox(m_membersTable);
        roleComboBox->addItem("Не назначена", QVariant::fromValue(PartyRole::Unassigned));
        roleComboBox->addItem("Танк", QVariant::fromValue(PartyRole::Tank));
        roleComboBox->addItem("Лекарь", QVariant::fromValue(PartyRole::Healer));
        roleComboBox->addItem("Боец", QVariant::fromValue(PartyRole::Damage));

        // Устанавливаем текущую роль
        roleComboBox->setCurrentIndex(roleComboBox->findData(QVariant::fromValue(settings.role)));

        // Соединяем сигнал изменения напрямую с PartyManager
        connect(roleComboBox, &QComboBox::currentIndexChanged, this,
                [this, bot](int index)
                {
                    QVariant data = qobject_cast<QComboBox*>(sender())->itemData(index);
                    if (data.canConvert<PartyRole>())
                    {
                        PartyRole newRole = data.value<PartyRole>();
                        // ВАЖНО: Мы НЕ используем silent=true.
                        // PartyManager сообщит об изменении, и вся таблица ПЕРЕРИСУЕТСЯ.
                        // Это просто, надежно и решает все проблемы с рассинхроном.
                        m_partyManager->setMemberRole(bot, newRole);
                    }
                });

        // Вставляем готовый ComboBox в ячейку
        m_membersTable->setIndexWidget(m_tableModel->index(newRow, 1), roleComboBox);
    }
    qCDebug(logPartyWidget) << "Party view refreshed. Member count:" << members.size();
}

void PartyWidget::onShowContextMenu(const QPoint& pos)
{
    // Получаем индекс ячейки, по которой кликнули
    QModelIndex index = m_membersTable->indexAt(pos);
    if (!index.isValid())
    {
        qCDebug(logPartyWidget) << "Context menu requested on invalid area.";
        return;  // Кликнули не по ячейке
    }

    // Получаем указатель на бота, который мы ранее сохранили в модели
    Bot* selectedBot = getBotFromIndex(index);
    if (!selectedBot)
    {
        qCWarning(logPartyWidget) << "Could not retrieve Bot pointer from model index.";
        return;  // Не смогли получить бота
    }

    qCDebug(logPartyWidget) << "Context menu requested for bot" << selectedBot->processId();

    // Создаем меню
    QMenu contextMenu(this);

    // --- Действие "Сделать лидером" ---
    // Делаем его неактивным, если бот уже является лидером
    QAction* setLeaderAction = contextMenu.addAction("Сделать лидером");
    if (m_partyManager->leader() == selectedBot)
    {
        setLeaderAction->setEnabled(false);
    }
    // Соединяем сигнал triggered с лямбда-функцией, вызывающей метод PartyManager
    connect(setLeaderAction, &QAction::triggered, this,
            [this, selectedBot]()
            {
                qCInfo(logPartyWidget) << "Action: Set Leader for bot" << selectedBot->processId();
                m_partyManager->setLeader(selectedBot);
            });

    contextMenu.addSeparator();

    // --- Действие "Удалить из группы" ---
    QAction* removeAction = contextMenu.addAction("Удалить из группы");
    connect(removeAction, &QAction::triggered, this,
            [this, selectedBot]()
            {
                qCInfo(logPartyWidget) << "Action: Remove bot" << selectedBot->processId() << "from party.";
                m_partyManager->removeBot(selectedBot);
            });

    // Отображаем меню в глобальных координатах курсора
    contextMenu.exec(m_membersTable->viewport()->mapToGlobal(pos));
}

Bot* PartyWidget::getBotFromIndex(const QModelIndex& index) const
{
    if (!index.isValid())
    {
        return nullptr;
    }
    // Получаем индекс первого столбца (где мы храним данные) для строки, по которой кликнули
    QModelIndex nameItemIndex = m_tableModel->index(index.row(), 0);
    // Извлекаем данные по нашей кастомной роли
    QVariant data = m_tableModel->data(nameItemIndex, BotPtrRole);

    // Проверяем, что данные можно преобразовать обратно в Bot* и возвращаем
    if (data.canConvert<Bot*>())
    {
        return data.value<Bot*>();
    }

    return nullptr;
}

void PartyWidget::forceRefresh()
{
    qCDebug(logPartyWidget) << "Force refresh requested from outside.";
    refreshPartyView();
}