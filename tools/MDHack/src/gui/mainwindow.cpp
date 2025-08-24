#include "mainwindow.h"
#include "processlistdialog.h"
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QMessageBox>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QInputDialog>
#include <QDialogButtonBox>
#include <QDebug>
#include <QStyle>
#include <QDoubleSpinBox>
#include <QLabel>
#include <QDialog>

#include "core/player/player.h"
#include "core/Bot/GameObjectManager/Structures/GameObject.h"
#include "core/Utils/Vector.h"

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle("MDHack - WoW 3.3.5a Teleport Hack");
    resize(600, 400);

    QMenu* processMenu = menuBar()->addMenu("Процесс");
    QAction* selectProcessAction = new QAction("Выбрать WoW (run.exe)...", this);
    processMenu->addAction(selectProcessAction);
    connect(selectProcessAction, &QAction::triggered, this, &MainWindow::onSelectProcess);

    treeWidget = new QTreeWidget(this);
    treeWidget->setHeaderLabel("Точки телепорта");
    treeWidget->setSortingEnabled(false);
    treeWidget->setDragDropMode(QAbstractItemView::InternalMove);
    treeWidget->setDefaultDropAction(Qt::MoveAction);
    treeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    setCentralWidget(treeWidget);

    locationManager.loadFromFile("locations.json", treeWidget);
    updateAllItemsAppearance(treeWidget->invisibleRootItem());

    bool hotkeyRegistered =
        RegisterHotKey(reinterpret_cast<HWND>(this->winId()), HOTKEY_ID_TELEPORT_TO_TARGET, 0, VK_F2);

    if (hotkeyRegistered)
    {
        qInfo() << "Hotkey F2 for 'Teleport to Target' registered successfully.";
    }
    else
    {
        qWarning() << "Failed to register hotkey F2. It might be already in use by another application.";
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
    UnregisterHotKey(reinterpret_cast<HWND>(this->winId()), HOTKEY_ID_TELEPORT_TO_TARGET);
    qInfo() << "Hotkey F2 unregistered.";

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
        QString computerName = dlg.computerName();  // <-- ПОЛУЧАЕМ ИМЯ ИЗ ДИАЛОГА

        if (info.pid != 0)
        {
            if (appContext)
            {
                delete appContext;
                appContext = nullptr;
            }
            appContext = new AppContext();

            // Передаем имя компьютера в appContext
            if (appContext->attachToProcess(info.pid, info.name, computerName))
            {
                QMessageBox::information(this, "Успех", "Процесс успешно выбран!");
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

void MainWindow::onTreeContextMenu(const QPoint& pos)
{
    QTreeWidgetItem* item = treeWidget->itemAt(pos);
    QMenu menu(this);

    QAction* addAction = menu.addAction("Добавить точку...");
    QAction* editAction = nullptr;
    QAction* delAction = nullptr;
    QAction* descAction = nullptr;

    if (item)
    {
        editAction = menu.addAction("Редактировать точку...");
        delAction = menu.addAction("Удалить точку");
        menu.addSeparator();

        const int descriptionRole = Qt::UserRole + 3;
        bool hasDescription =
            item->data(0, descriptionRole).isValid() && !item->data(0, descriptionRole).toString().isEmpty();
        descAction = menu.addAction(hasDescription ? "Редактировать описание..." : "Добавить описание...");
    }

    QAction* chosen = menu.exec(treeWidget->viewport()->mapToGlobal(pos));

    if (chosen == delAction && item)
    {
        delete item;
        locationManager.saveToFile("locations.json", treeWidget);
    }
    else if (chosen == descAction && item)
    {
        const int descriptionRole = Qt::UserRole + 3;
        bool ok;
        QString currentDescription = item->data(0, descriptionRole).toString();
        QString newDescription =
            QInputDialog::getMultiLineText(this, "Редактировать описание", "Описание:", currentDescription, &ok);
        if (ok)
        {
            item->setData(0, descriptionRole, newDescription);
            updateItemAppearance(item);
            locationManager.saveToFile("locations.json", treeWidget);
        }
    }
    else if (chosen == addAction)
    {
        if (!appContext || !appContext->isAttached())
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

        QDialog dlg(this);
        dlg.setWindowTitle("Добавить точку");
        auto* layout = new QVBoxLayout(&dlg);
        auto* nameEdit = new QLineEdit(&dlg);
        auto* xSpin = new QDoubleSpinBox(&dlg);
        auto* ySpin = new QDoubleSpinBox(&dlg);
        auto* zSpin = new QDoubleSpinBox(&dlg);
        auto* descEdit = new QLineEdit(&dlg);

        nameEdit->setPlaceholderText("Имя точки");
        descEdit->setPlaceholderText("Описание (необязательно)");
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
        layout->addWidget(new QLabel("Описание:", &dlg));
        layout->addWidget(descEdit);
        layout->addWidget(new QLabel("Координата X:", &dlg));
        layout->addWidget(xSpin);
        layout->addWidget(new QLabel("Координата Y:", &dlg));
        layout->addWidget(ySpin);
        layout->addWidget(new QLabel("Координата Z:", &dlg));
        layout->addWidget(zSpin);

        auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
        layout->addWidget(buttonBox);
        connect(buttonBox, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

        if (dlg.exec() == QDialog::Accepted)
        {
            QString name = nameEdit->text();
            if (name.isEmpty()) return;

            QTreeWidgetItem* newItem = item ? new QTreeWidgetItem(item) : new QTreeWidgetItem(treeWidget);
            if (item) item->setExpanded(true);

            newItem->setText(0, name);
            newItem->setData(0, Qt::UserRole, xSpin->value());
            newItem->setData(0, Qt::UserRole + 1, ySpin->value());
            newItem->setData(0, Qt::UserRole + 2, zSpin->value());
            newItem->setData(0, Qt::UserRole + 3, descEdit->text());

            updateItemAppearance(newItem);
            locationManager.saveToFile("locations.json", treeWidget);
        }
    }
    else if (chosen == editAction && item)
    {
        bool ok;
        const int descRole = Qt::UserRole + 3;

        QString name =
            QInputDialog::getText(this, "Редактировать имя", "Новое имя:", QLineEdit::Normal, item->text(0), &ok);
        if (!ok || name.isEmpty()) return;

        double x = QInputDialog::getDouble(this, "Редактировать X", "X:", item->data(0, Qt::UserRole).toDouble(),
                                           -1000000, 1000000, 2, &ok);
        if (!ok) return;
        double y = QInputDialog::getDouble(this, "Редактировать Y", "Y:", item->data(0, Qt::UserRole + 1).toDouble(),
                                           -1000000, 1000000, 2, &ok);
        if (!ok) return;
        double z = QInputDialog::getDouble(this, "Редактировать Z", "Z:", item->data(0, Qt::UserRole + 2).toDouble(),
                                           -1000000, 1000000, 2, &ok);
        if (!ok) return;

        QString desc = QInputDialog::getMultiLineText(this, "Редактировать описание",
                                                      "Описание:", item->data(0, descRole).toString(), &ok);
        if (!ok) return;

        item->setText(0, name);
        item->setData(0, Qt::UserRole, x);
        item->setData(0, Qt::UserRole + 1, y);
        item->setData(0, Qt::UserRole + 2, z);
        item->setData(0, descRole, desc);

        updateItemAppearance(item);
        locationManager.saveToFile("locations.json", treeWidget);
    }
}

void MainWindow::onTreeChanged()
{
    locationManager.saveToFile("locations.json", treeWidget);
}

void MainWindow::onTreeItemDoubleClicked(QTreeWidgetItem* item, int /*column*/)
{
    if (!item) return;
    if (!item->data(0, Qt::UserRole).isValid()) return;

    if (!appContext || !appContext->isAttached())
    {
        QMessageBox::warning(this, "Ошибка", "Сначала выберите процесс WoW!");
        return;
    }

    try
    {
        TeleportExecutor* executor = appContext->getTeleportExecutor();
        auto playerOpt = appContext->getPlayer();

        if (!executor || !playerOpt)
        {
            QMessageBox::critical(this, "Критическая ошибка", "Компоненты не инициализированы!");
            return;
        }

        float targetX = static_cast<float>(item->data(0, Qt::UserRole).toDouble());
        float targetY = static_cast<float>(item->data(0, Qt::UserRole + 1).toDouble());
        float targetZ = static_cast<float>(item->data(0, Qt::UserRole + 2).toDouble());

        executor->setPositionStepwise(playerOpt->getBase(), appContext->getPid(),
                                      appContext->getTeleportFlagBufferAddress(), targetX, targetY, targetZ, 10.0f);
    }
    catch (const std::exception& ex)
    {
        QMessageBox::critical(this, "Критическая ошибка", "Произошло исключение: " + QString::fromUtf8(ex.what()));
    }
}

bool MainWindow::nativeEvent(const QByteArray& eventType, void* message, qintptr* result)
{
    if (eventType == "windows_generic_MSG")
    {
        MSG* msg = static_cast<MSG*>(message);
        if (msg->message == WM_HOTKEY && msg->wParam == HOTKEY_ID_TELEPORT_TO_TARGET)
        {
            qDebug() << "Hotkey F2 pressed!";
            onTeleportToTargetHotkeyPressed();
            *result = 0;
            return true;
        }
    }
    return QMainWindow::nativeEvent(eventType, message, result);
}

void MainWindow::onTeleportToTargetHotkeyPressed()
{
    try
    {
        if (!appContext || !appContext->isAttached())
        {
            QMessageBox::warning(this, "Ошибка", "Сначала выберите процесс WoW!");
            return;
        }

        GameObject* targetPtrInGame = appContext->getTargetObject();
        if (!targetPtrInGame)
        {
            QMessageBox::information(this, "Нет цели", "Пожалуйста, выберите цель в игре.");
            return;
        }

        GameObject targetData;
        if (!appContext->getMemoryManager()->readMemory(reinterpret_cast<uintptr_t>(targetPtrInGame), targetData))
        {
            QMessageBox::warning(this, "Ошибка", "Не удалось прочитать данные цели из памяти игры!");
            return;
        }

        const Vector3& targetPos = targetData.position;
        qInfo() << "Target found. GUID:" << targetData.guid << "Position:" << targetPos.x << targetPos.y << targetPos.z;

        TeleportExecutor* executor = appContext->getTeleportExecutor();
        auto playerOpt = appContext->getPlayer();

        if (!executor || !playerOpt)
        {
            QMessageBox::critical(this, "Критическая ошибка", "Компоненты не инициализированы!");
            return;
        }

        qInfo() << "Starting teleport to target...";
        bool success = executor->setPositionStepwise(playerOpt->getBase(), appContext->getPid(),
                                                     appContext->getTeleportFlagBufferAddress(), targetPos.x,
                                                     targetPos.y, targetPos.z, 10.0f);
        if (success)
        {
            qInfo() << "Teleport to target finished successfully!";
        }
        else
        {
            QMessageBox::warning(this, "Ошибка телепортации", "Не удалось выполнить телепортацию.");
        }
    }
    catch (const std::exception& e)
    {
        QMessageBox::critical(this, "Критическая ошибка", "Произошло исключение: " + QString::fromUtf8(e.what()));
    }
}

void MainWindow::updateItemAppearance(QTreeWidgetItem* item)
{
    if (!item) return;

    const int descriptionRole = Qt::UserRole + 3;
    QVariant descriptionData = item->data(0, descriptionRole);

    if (descriptionData.isValid() && !descriptionData.toString().isEmpty())
    {
        QIcon infoIcon = this->style()->standardIcon(QStyle::SP_MessageBoxInformation);
        item->setIcon(0, infoIcon);
        item->setToolTip(0, descriptionData.toString());
    }
    else
    {
        item->setIcon(0, QIcon());
        item->setToolTip(0, "");
    }
}

void MainWindow::updateAllItemsAppearance(QTreeWidgetItem* parentItem)
{
    if (!parentItem) return;
    for (int i = 0; i < parentItem->childCount(); ++i)
    {
        QTreeWidgetItem* child = parentItem->child(i);
        updateItemAppearance(child);
        if (child->childCount() > 0)
        {
            updateAllItemsAppearance(child);
        }
    }
}