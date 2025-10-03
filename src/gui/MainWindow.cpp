// ФАЙЛ: src/gui/MainWindow.cpp

#include "gui/MainWindow.h"
#include "gui/Logging/LogWindow.h"
#include "gui/Bot/BotWidget.h"
#include "gui/Party/PartyWidget.h"
#include "core/PartyManager/PartyManager.h"
#include <QSplitter>
#include <QTreeWidget>
#include <QStackedWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QMenuBar>
#include <QHeaderView>
#include <QMenu>
#include <QLoggingCategory>
#include "core/ProfileManager/ProfileManager.h"

Q_LOGGING_CATEGORY(mainWindowLog, "gui.mainwindow")

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle("MDBot2 Main Window");
    resize(1024, 768);  // Увеличим размер окна для нового интерфейса

    // --- Создание меню (без изменений) ---
    m_profileManager = new ProfileManager(this);
    QMenuBar* menuBar = new QMenuBar(this);
    QMenu* processMenu = menuBar->addMenu("Процессы");
    QAction* addProcessAction = processMenu->addAction("Добавить процесс");
    QMenu* groupMenu = menuBar->addMenu("Группа");
    QAction* createPartyAction = groupMenu->addAction("Создать группу");
    QMenu* logMenu = menuBar->addMenu("Логи");
    QAction* showLogAction = logMenu->addAction("Открыть лог");
    setMenuBar(menuBar);
    connect(addProcessAction, &QAction::triggered, this, &MainWindow::onAddProcess);
    connect(createPartyAction, &QAction::triggered, this, &MainWindow::onCreatePartyClicked);
    connect(showLogAction, &QAction::triggered, this, &MainWindow::onShowLogWindow);

    // --- НАЧАЛО ПЕРЕСТРОЙКИ GUI ---

    // 1. Создаем сплиттер, который разделит окно на две части
    m_mainSplitter = new QSplitter(Qt::Horizontal, this);

    // 2. Создаем дерево навигации (левая часть)
    m_navTree = new QTreeWidget(m_mainSplitter);
    m_navTree->setHeaderLabel("Навигация");
    m_navTree->header()->setSectionResizeMode(QHeaderView::Stretch);

    // 3. Создаем "колоду виджетов" для контента (правая часть)
    m_contentStack = new QStackedWidget(m_mainSplitter);

    // 4. Добавляем дерево и колоду в сплиттер
    m_mainSplitter->addWidget(m_navTree);
    m_mainSplitter->addWidget(m_contentStack);
    m_mainSplitter->setSizes({250, 750});  // Начальные размеры левой и правой части

    // 5. Устанавливаем сплиттер как центральный виджет
    setCentralWidget(m_mainSplitter);

    // 6. Создаем корневые "папки" в дереве
    m_partiesRoot = new QTreeWidgetItem(m_navTree, {"Группы"});
    m_soloBotsRoot = new QTreeWidgetItem(m_navTree, {"Одиночные боты"});
    m_partiesRoot->setExpanded(true);
    m_soloBotsRoot->setExpanded(true);

    // 7. Подключаем сигналы и слоты для нового GUI
    connect(m_navTree, &QTreeWidget::itemClicked, this, &MainWindow::onNavItemClicked);
    m_navTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_navTree, &QTreeWidget::customContextMenuRequested, this, &MainWindow::showNavContextMenu);

    // --- КОНЕЦ ПЕРЕСТРОЙКИ GUI ---

    qCInfo(mainWindowLog) << "Main window and new tree-based UI initialized.";
    LogWindow::appendLog("Main window started.");
}

MainWindow::~MainWindow()
{
    // ДОБАВЬ ЭТУ СТРОКУ:
    // Проходимся по всем ботам в нашей карте и удаляем их.
    qDeleteAll(m_bots);
}

void MainWindow::onAddProcess()
{
    // Этот метод почти не меняется. Вместо addProcessTab вызываем addBotToTree
    try
    {
        ProcessListDialog dlg(this);
        if (dlg.exec() == QDialog::Accepted)
        {
            ProcessInfo info = dlg.selectedProcess();
            QString computerName = dlg.computerName();

            if (info.pid != 0)
            {
                if (m_bots.contains(info.pid))
                {
                    QMessageBox::warning(this, "Внимание", "Бот для этого процесса уже добавлен.");
                    return;
                }

                Bot* bot =
                    new Bot(static_cast<qint64>(info.pid), QString::fromStdWString(info.name), computerName, nullptr);
                m_bots.insert(info.pid, bot);
                qCInfo(mainWindowLog) << "Bot object created and added to master list. PID:" << info.pid;

                // Вместо создания вкладки, добавляем бота в дерево
                addBotToTree(bot);
            }
        }
    }
    catch (const std::exception& ex)
    {
        qCCritical(mainWindowLog) << "Error adding process:" << ex.what();
        QMessageBox::critical(this, "Error", "Failed to add process: " + QString::fromUtf8(ex.what()));
    }
}

void MainWindow::addBotToTree(Bot* bot)
{
    // Создаем виджет для бота
    BotWidget* botWidget = new BotWidget(bot, m_profileManager, this);

    // Добавляем виджет в "колоду" и получаем его индекс
    int widgetIndex = m_contentStack->addWidget(botWidget);

    // Создаем элемент дерева для этого бота
    QString itemName = QString("%1 [%2]").arg(bot->processName()).arg(bot->processId());
    QTreeWidgetItem* botItem = new QTreeWidgetItem(m_soloBotsRoot, {itemName});

    // САМОЕ ВАЖНОЕ: Сохраняем в элементе дерева индекс его виджета в "колоде"
    botItem->setData(0, Qt::UserRole, widgetIndex);
    // Также сохраним PID для легкого доступа
    botItem->setData(0, Qt::UserRole + 1, bot->processId());
}

void MainWindow::addPartyToTree(PartyManager* party)
{
    // 1. Создаем виджет-дашборд для нашей группы
    PartyWidget* partyWidget = new PartyWidget(party, this);

    // 2. Добавляем его в "колоду" и запоминаем его индекс
    int widgetIndex = m_contentStack->addWidget(partyWidget);

    // 3. Создаем родительский элемент для группы в дереве навигации
    QString partyName = QString("Группа %1").arg(m_parties.size());
    QTreeWidgetItem* partyItem = new QTreeWidgetItem(m_partiesRoot, {partyName});
    partyItem->setData(0, Qt::UserRole, widgetIndex);                     // Сохраняем индекс виджета
    partyItem->setData(0, Qt::UserRole + 2, QVariant::fromValue(party));  // Сохраняем указатель на PartyManager
    partyItem->setExpanded(true);
}

void MainWindow::onNavItemClicked(QTreeWidgetItem* item, int column)
{
    if (!item || !item->parent())  // Игнорируем клики по корневым элементам
        return;

    // Достаем из элемента дерева индекс виджета, который мы там сохранили
    bool ok;
    int widgetIndex = item->data(0, Qt::UserRole).toInt(&ok);
    if (ok)
    {
        // --- НАЧАЛО ИЗМЕНЕНИЙ ---

        // 1. Получаем указатель на виджет, который мы собираемся показать
        QWidget* widgetToShow = m_contentStack->widget(widgetIndex);
        if (!widgetToShow) return;

        // 2. Проверяем, является ли этот виджет нашим PartyWidget
        PartyWidget* partyWidget = qobject_cast<PartyWidget*>(widgetToShow);
        if (partyWidget)
        {
            // 3. Если да - отдаем ему прямую команду обновиться ПЕРЕД показом
            qCDebug(mainWindowLog) << "Switching to PartyWidget, forcing it to refresh.";
            partyWidget->forceRefresh();
        }

        // 4. И только теперь переключаем "колоду" на уже обновленный виджет
        m_contentStack->setCurrentWidget(widgetToShow);

        // --- КОНЕЦ ИЗМЕНЕНИЙ ---
    }
}

void MainWindow::showNavContextMenu(const QPoint& pos)
{
    QTreeWidgetItem* item = m_navTree->itemAt(pos);
    if (!item || !item->parent()) return;

    QMenu contextMenu(this);
    qint64 pid = item->data(0, Qt::UserRole + 1).toLongLong();
    Bot* bot = m_bots.value(pid, nullptr);

    // Если это элемент бота
    if (bot)
    {
        // Если бот одиночный
        if (item->parent() == m_soloBotsRoot)
        {
            // Создаем подменю для добавления в существующие группы
            QMenu* addToPartyMenu = contextMenu.addMenu("Добавить в группу");
            if (m_parties.isEmpty())
            {
                addToPartyMenu->setEnabled(false);  // Некуда добавлять
            }
            else
            {
                for (PartyManager* party : qAsConst(m_parties))
                {
                    // Находим элемент дерева для этой группы
                    QTreeWidgetItem* partyItem = nullptr;
                    for (int i = 0; i < m_partiesRoot->childCount(); ++i)
                    {
                        if (m_partiesRoot->child(i)->data(0, Qt::UserRole + 2).value<PartyManager*>() == party)
                        {
                            partyItem = m_partiesRoot->child(i);
                            break;
                        }
                    }
                    if (partyItem)
                    {
                        QAction* partyAction = addToPartyMenu->addAction(partyItem->text(0));
                        connect(partyAction, &QAction::triggered, this,
                                [=]()
                                {
                                    party->addBot(bot);
                                    // Перемещаем элемент дерева
                                    m_soloBotsRoot->removeChild(item);
                                    partyItem->addChild(item);
                                    qCInfo(mainWindowLog) << "Bot" << pid << "moved to party" << partyItem->text(0);
                                });
                    }
                }
            }
        }
        // Если бот в группе
        else
        {
            QAction* removeFromPartyAction = contextMenu.addAction("Исключить из группы");
            connect(removeFromPartyAction, &QAction::triggered, this,
                    [=]()
                    {
                        // Находим, в какой группе состоит бот
                        QTreeWidgetItem* partyItem = item->parent();
                        PartyManager* party = partyItem->data(0, Qt::UserRole + 2).value<PartyManager*>();
                        if (party)
                        {
                            party->removeBot(bot);
                            // Перемещаем элемент дерева обратно в "Одиночные боты"
                            partyItem->removeChild(item);
                            m_soloBotsRoot->addChild(item);
                            qCInfo(mainWindowLog) << "Bot" << pid << "moved back to solo bots.";
                        }
                    });
        }

        contextMenu.addSeparator();
    }

    // Общее действие для всех - удаление
    QAction* deleteAction = contextMenu.addAction("Отключить/Расформировать");
    connect(deleteAction, &QAction::triggered, this,
            [=]()
            {
                // ... (здесь будет общая логика удаления для ботов и групп) ...
                QMessageBox::information(this, "В разработке", "Функция удаления будет добавлена позже.");
            });

    contextMenu.exec(m_navTree->mapToGlobal(pos));
}

void MainWindow::onCreatePartyClicked()
{
    QList<Bot*> soloBots;
    for (Bot* bot : m_bots.values())
    {
        bool isInParty = false;
        for (PartyManager* party : qAsConst(m_parties))
        {
            if (party->members().contains(bot))
            {
                isInParty = true;
                break;
            }
        }
        if (!isInParty)
        {
            soloBots.append(bot);
        }
    }

    // --- НАЧАЛО ИСПРАВЛЕНИЙ ---

    // 1. Создаем логический объект группы
    PartyManager* newParty = new PartyManager(this);
    m_parties.append(newParty);

    // 2. СРАЗУ ЖЕ создаем для него GUI. Внутри конструктора PartyWidget
    //    произойдет connect, и он начнет слушать сигналы.
    addPartyToTree(newParty);

    // 3. И только ТЕПЕРЬ, когда GUI готов и слушает, добавляем ботов.
    //    Каждый вызов addBot() отправит сигнал partyUpdated(), который
    //    PartyWidget теперь гарантированно поймает.
    for (Bot* bot : soloBots)
    {
        newParty->addBot(bot);
    }

    // 4. Назначаем лидера (это тоже вызовет partyUpdated() и обновит GUI)
    if (!soloBots.isEmpty())
    {
        newParty->setLeader(soloBots.first());
    }

    // --- КОНЕЦ ИСПРАВЛЕНИЙ ---

    qCInfo(mainWindowLog) << "New party created with" << soloBots.size() << "members.";
}

void MainWindow::onShowLogWindow()
{
    LogWindow::instance()->show();
    LogWindow::instance()->raise();
    LogWindow::instance()->activateWindow();
}