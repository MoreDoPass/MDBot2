#include "mainwindow.h"
#include "processlistdialog.h"
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <qmessagebox.h>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QInputDialog>
#include <QMenu>
#include "core/player/player.h"
#include "core/teleport/teleport.h"
#include <QMessageBox>
#include <QMouseEvent>
#include <qspinbox.h>
#include <QLabel>

#include "core/player/player.h"
#include "core/teleport/teleport.h"  // Этот класс больше не нужен напрямую, но оставим для контекста
#include "core/Bot/GameObjectManager/Structures/GameObject.h"
#include "core/Utils/Vector.h"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    setWindowTitle("MDHack - WoW 3.3.5a Teleport Hack");
    resize(600, 400);

    QMenu *processMenu = menuBar()->addMenu("Процесс");
    QAction *selectProcessAction = new QAction("Выбрать WoW (run.exe)...", this);
    processMenu->addAction(selectProcessAction);
    connect(selectProcessAction, &QAction::triggered, this, &MainWindow::onSelectProcess);

    // --- TreeWidget для точек телепорта ---
    treeWidget = new QTreeWidget(this);
    treeWidget->setHeaderLabel("Точки телепорта");
    treeWidget->setSortingEnabled(false);
    treeWidget->setDragDropMode(QAbstractItemView::InternalMove);  // Drag&Drop
    treeWidget->setDefaultDropAction(Qt::MoveAction);
    treeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    setCentralWidget(treeWidget);
    locationManager.loadFromFile("locations.json", treeWidget);

    // --- ДОБАВЛЯЕМ РЕГИСТРАЦИЮ ХОТКЕЯ ---
    // Регистрируем глобальный хоткей F2.
    // MOD_NOREPEAT - чтобы хоткей не срабатывал постоянно, если клавиша зажата.
    // VK_F2 - виртуальный код клавиши F2.
    // this->winId() - получаем "дескриптор окна" (HWND) из Qt.
    bool hotkeyRegistered = RegisterHotKey(reinterpret_cast<HWND>(this->winId()), HOTKEY_ID_TELEPORT_TO_TARGET,
                                           0 /* без модификаторов */, VK_F2);

    if (hotkeyRegistered)
    {
        // Используем Qt логирование для вывода информации
        qInfo() << "Hotkey F2 for 'Teleport to Target' registered successfully.";
    }
    else
    {
        qWarning() << "Failed to register hotkey F2. It might be already in use by another application.";
        // Можно показать пользователю сообщение, если это критично
        QMessageBox::warning(this, "Ошибка хоткея",
                             "Не удалось зарегистрировать горячую клавишу F2. "
                             "Возможно, она уже используется другой программой.");
    }

    connect(treeWidget, &QTreeWidget::customContextMenuRequested, this, &MainWindow::onTreeContextMenu);
    connect(treeWidget->model(), &QAbstractItemModel::rowsMoved, this, &MainWindow::onTreeChanged);
    connect(treeWidget, &QTreeWidget::itemDoubleClicked, this, &MainWindow::onTreeItemDoubleClicked);
}

MainWindow::~MainWindow()
{
    // --- ДОБАВЛЯЕМ СНЯТИЕ РЕГИСТРАЦИИ ХОТКЕЯ ---
    // Очень важно снимать регистрацию хоткея при закрытии программы.
    UnregisterHotKey(reinterpret_cast<HWND>(this->winId()), HOTKEY_ID_TELEPORT_TO_TARGET);
    qInfo() << "Hotkey F2 unregistered.";

    // unique_ptr сам удалит appContext, но если ты используешь сырой указатель, его надо удалять
    if (appContext)
    {
        delete appContext;
        appContext = nullptr;
    }
}

void MainWindow::onSelectProcess()
{
    ProcessListDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted)
    {
        ProcessInfo info = dlg.selectedProcess();
        if (info.pid != 0)
        {
            // Если уже был контекст — удаляем его
            if (appContext)
            {
                delete appContext;
                appContext = nullptr;
            }
            // Создаём новый контекст и подключаемся к процессу
            appContext = new AppContext();
            if (appContext->attachToProcess(info.pid, info.name))
            {
                // Успешно подключились — теперь можно работать с памятью, хуками и т.д.
                QMessageBox::information(this, "Успех", "Процесс успешно выбран!");
                // Здесь можно активировать элементы интерфейса, связанные с работой с процессом
            }
            else
            {
                QMessageBox::critical(this, "Ошибка", "Не удалось открыть процесс!");
                delete appContext;
                appContext = nullptr;
            }
        }
    }
}

// --- ПКМ по точке ---
void MainWindow::onTreeContextMenu(const QPoint &pos)
{
    QTreeWidgetItem *item = treeWidget->itemAt(pos);
    QMenu menu(this);
    QAction *addAction = menu.addAction("Добавить точку");
    QAction *editAction = nullptr;
    QAction *delAction = nullptr;
    if (item)
    {
        editAction = menu.addAction("Редактировать точку");
        delAction = menu.addAction("Удалить точку");
    }
    QAction *chosen = menu.exec(treeWidget->viewport()->mapToGlobal(pos));
    if (chosen == delAction && item)
    {
        delete item;
        locationManager.saveToFile("locations.json", treeWidget);
    }
    else if (chosen == addAction)
    {
        if (!appContext)
        {
            QMessageBox::warning(this, "Ошибка", "Сначала выберите процесс WoW!");
            return;
        }
        auto playerOpt = appContext->getPlayer();
        float px = 0, py = 0, pz = 0;
        if (playerOpt)
        {
            px = playerOpt->getX();
            py = playerOpt->getY();
            pz = playerOpt->getZ();
        }
        // Создаём диалог с полями для имени и координат
        QDialog dlg(this);
        dlg.setWindowTitle("Добавить точку");
        QVBoxLayout *layout = new QVBoxLayout(&dlg);
        QLineEdit *nameEdit = new QLineEdit(&dlg);
        nameEdit->setPlaceholderText("Имя точки");
        QDoubleSpinBox *xSpin = new QDoubleSpinBox(&dlg);
        QDoubleSpinBox *ySpin = new QDoubleSpinBox(&dlg);
        QDoubleSpinBox *zSpin = new QDoubleSpinBox(&dlg);
        xSpin->setRange(-1000000, 1000000);
        xSpin->setDecimals(2);
        xSpin->setValue(px);
        ySpin->setRange(-1000000, 1000000);
        ySpin->setDecimals(2);
        ySpin->setValue(py);
        zSpin->setRange(-1000000, 1000000);
        zSpin->setDecimals(2);
        zSpin->setValue(pz);
        layout->addWidget(new QLabel("Имя точки:", &dlg));
        layout->addWidget(nameEdit);
        layout->addWidget(new QLabel("Координата X:", &dlg));
        layout->addWidget(xSpin);
        layout->addWidget(new QLabel("Координата Y:", &dlg));
        layout->addWidget(ySpin);
        layout->addWidget(new QLabel("Координата Z:", &dlg));
        layout->addWidget(zSpin);
        QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
        layout->addWidget(buttonBox);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
        if (dlg.exec() == QDialog::Accepted)
        {
            QString name = nameEdit->text();
            if (name.isEmpty()) return;
            QTreeWidgetItem *newItem = nullptr;
            if (item)
            {
                newItem = new QTreeWidgetItem(item);
                item->setExpanded(true);
            }
            else
            {
                newItem = new QTreeWidgetItem(treeWidget);
            }
            newItem->setText(0, name);
            newItem->setData(0, Qt::UserRole, xSpin->value());
            newItem->setData(0, Qt::UserRole + 1, ySpin->value());
            newItem->setData(0, Qt::UserRole + 2, zSpin->value());
            locationManager.saveToFile("locations.json", treeWidget);
        }
    }
    else if (chosen == editAction && item)
    {
        bool ok;
        QString name =
            QInputDialog::getText(this, "Редактировать имя", "Новое имя:", QLineEdit::Normal, item->text(0), &ok);
        if (!ok || name.isEmpty()) return;
        double x = QInputDialog::getDouble(this, "Редактировать X", "X:", item->data(0, Qt::UserRole).toDouble(),
                                           -10000, 10000, 2, &ok);
        if (!ok) return;
        double y = QInputDialog::getDouble(this, "Редактировать Y", "Y:", item->data(0, Qt::UserRole + 1).toDouble(),
                                           -10000, 10000, 2, &ok);
        if (!ok) return;
        double z = QInputDialog::getDouble(this, "Редактировать Z", "Z:", item->data(0, Qt::UserRole + 2).toDouble(),
                                           -10000, 10000, 2, &ok);
        if (!ok) return;
        item->setText(0, name);
        item->setData(0, Qt::UserRole, x);
        item->setData(0, Qt::UserRole + 1, y);
        item->setData(0, Qt::UserRole + 2, z);
        locationManager.saveToFile("locations.json", treeWidget);
    }
}

// --- Drag&Drop: сохраняем после перемещения ---
void MainWindow::onTreeChanged()
{
    locationManager.saveToFile("locations.json", treeWidget);
}

// --- Двойной клик по точке: телепорт ---
void MainWindow::onTreeItemDoubleClicked(QTreeWidgetItem *item, int /*column*/)
{
    // --- 1. Проверяем базовые условия ---
    if (!item)
    {
        // Просто выходим, если клик был не по элементу.
        return;
    }

    if (!appContext || !appContext->isAttached())
    {
        QMessageBox::warning(this, "Ошибка", "Сначала выберите процесс WoW!");
        return;
    }

    try
    {
        // --- 2. Получаем все необходимые данные для телепортации ---

        // Получаем исполнителя телепортации из AppContext.
        TeleportExecutor *executor = appContext->getTeleportExecutor();
        if (!executor)
        {
            QMessageBox::critical(this, "Критическая ошибка", "TeleportExecutor не был создан!");
            return;
        }

        // Получаем текущий базовый адрес игрока.
        // Используем std::optional, чтобы безопасно обработать случай, когда указатель еще не получен.
        auto playerOpt = appContext->getPlayer();
        if (!playerOpt)
        {
            QMessageBox::warning(this, "Ошибка",
                                 "Адрес игрока ещё не получен! "
                                 "Подождите пару секунд после выбора процесса и попробуйте снова.");
            return;
        }
        uintptr_t playerBaseAddress = playerOpt->getBase();

        // Получаем адрес буфера для флага (куда хук пишет '1').
        uintptr_t flagBufferAddress = appContext->getTeleportFlagBufferAddress();

        // Получаем PID процесса.
        DWORD pid = appContext->getPid();

        // Получаем целевые координаты из данных элемента дерева.
        float targetX = static_cast<float>(item->data(0, Qt::UserRole).toDouble());
        float targetY = static_cast<float>(item->data(0, Qt::UserRole + 1).toDouble());
        float targetZ = static_cast<float>(item->data(0, Qt::UserRole + 2).toDouble());

        // --- 3. Вызываем метод телепортации ---
        // Передаем ему всю собранную информацию.
        // Вся сложная логика (ожидание флага, нажатие клавиш) теперь инкапсулирована внутри executor.

        // Выполняем телепортацию
        bool success = executor->setPositionStepwise(playerBaseAddress, pid, flagBufferAddress, targetX, targetY,
                                                     targetZ, 10.0f /* шаг */);

        if (success)
        {
            qInfo() << "Успех", "Телепортация завершена!";
        }
        else
        {
            QMessageBox::warning(this, "Ошибка телепортации",
                                 "Не удалось выполнить телепортацию. "
                                 "Проверьте логи для получения детальной информации.");
        }
    }
    catch (const std::exception &ex)
    {
        // Обрабатываем возможные исключения
        QMessageBox::critical(this, "Критическая ошибка", "Произошло исключение: " + QString::fromUtf8(ex.what()));
    }
}

bool MainWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
    // Убеждаемся, что это событие Windows
    if (eventType == "windows_generic_MSG")
    {
        // Приводим указатель к типу сообщения Windows
        MSG *msg = static_cast<MSG *>(message);

        // Проверяем, является ли это сообщение нажатием хоткея
        if (msg->message == WM_HOTKEY)
        {
            // Проверяем, что это НАШ хоткей по его ID
            if (msg->wParam == HOTKEY_ID_TELEPORT_TO_TARGET)
            {
                qDebug() << "Hotkey F2 pressed!";
                onTeleportToTargetHotkeyPressed();  // Вызываем нашу логику
                *result = 0;
                return true;  // Сообщаем, что мы обработали это событие
            }
        }
    }
    // Если это не наше событие, передаем его на обработку базовому классу
    return QMainWindow::nativeEvent(eventType, message, result);
}

/**
 * @brief Слот, который выполняется при нажатии хоткея телепорта к цели.
 */
void MainWindow::onTeleportToTargetHotkeyPressed()
{
    try
    {
        // 1. Проверяем, что мы подключены к процессу
        if (!appContext || !appContext->isAttached())
        {
            QMessageBox::warning(this, "Ошибка", "Сначала выберите процесс WoW!");
            return;
        }

        // 2. Получаем "сырой" указатель на объект цели из AppContext.
        // Это просто адрес в памяти игры, мы не можем его использовать напрямую.
        GameObject *targetPtrInGame = appContext->getTargetObject();
        if (!targetPtrInGame)
        {
            QMessageBox::information(this, "Нет цели", "Пожалуйста, выберите цель в игре.");
            return;
        }

        // --- ВОТ КЛЮЧЕВОЕ ИЗМЕНЕНИЕ ---

        // 3. Создаем ЛОКАЛЬНУЮ переменную в MDHack, куда мы скопируем данные из игры.
        GameObject targetData;

        // 4. Используем MemoryManager, чтобы прочитать всю структуру объекта из памяти игры
        //    в нашу локальную переменную targetData.
        //    appContext->getPlayer() возвращает optional, нам нужен сам MemoryManager.
        //    Давай предположим, что у AppContext есть метод getMemoryManager().
        //    Если его нет, его нужно будет добавить.
        if (!appContext->getMemoryManager()->readMemory(reinterpret_cast<uintptr_t>(targetPtrInGame), targetData))
        {
            QMessageBox::warning(this, "Ошибка", "Не удалось прочитать данные цели из памяти игры!");
            return;
        }

        // 5. Теперь мы работаем с БЕЗОПАСНОЙ ЛОКАЛЬНОЙ копией данных - targetData.
        //    Краша больше не будет.
        const Vector3 &targetPos = targetData.position;
        qInfo() << "Target found. GUID:" << targetData.guid << "Position:" << targetPos.x << targetPos.y << targetPos.z;

        // 6. Получаем остальные компоненты, как и раньше
        TeleportExecutor *executor = appContext->getTeleportExecutor();
        if (!executor)
        {
            QMessageBox::critical(this, "Критическая ошибка", "TeleportExecutor не был создан!");
            return;
        }

        auto playerOpt = appContext->getPlayer();
        if (!playerOpt)
        {
            QMessageBox::warning(this, "Ошибка", "Адрес игрока ещё не получен!");
            return;
        }

        bool success = executor->setPositionStepwise(playerOpt->getBase(), appContext->getPid(),
                                                     appContext->getTeleportFlagBufferAddress(), targetPos.x,
                                                     targetPos.y, targetPos.z, 10.0f /* шаг */);

        if (success)
        {
            qInfo() << "Teleport to target finished successfully!";
        }
        else
        {
            QMessageBox::warning(this, "Ошибка телепортации", "Не удалось выполнить телепортацию.");
        }
    }
    catch (const std::exception &e)
    {
        QMessageBox::critical(this, "Критическая ошибка", "Произошло исключение: " + QString::fromUtf8(e.what()));
    }
}