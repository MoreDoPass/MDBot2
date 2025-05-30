#include "MpqManagerWidget.h"
#include "../../core/WoWFileParser/MpqManager.h"

#include <QVBoxLayout>
#include <QLabel>       // Для информационных сообщений, если нужно
#include <QHeaderView>  // Для настройки заголовков QTreeView
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QMessageBox>  // Для вывода ошибок пользователю
#include <QMenu>        // Для контекстного меню
#include <QAction>      // Для действий в меню
#include <QFileDialog>  // Для диалога сохранения

// Если понадобится логгирование для этого виджета:
// Q_LOGGING_CATEGORY(mpqWidgetLog, "gui.mpqwidget")
Q_LOGGING_CATEGORY(mpqManagerWidgetLog, "gui.mpqwidget")

MpqManagerWidget::MpqManagerWidget(MpqManager* mpqManager, QWidget* parent)
    : QWidget(parent),
      m_treeView(new QTreeView(this)),
      m_mpqManager(mpqManager),
      m_fileSystemModel(new QStandardItemModel(this)),
      m_archivesListWidget(new QListWidget(this)),
      m_mpqRootNode(new MpqVirtualDir("/"))
{
    setupUi();

    if (!m_mpqManager)
    {
        // Важно: setMpqManager должен вызываться ПОСЛЕ setupUi,
        // чтобы виджеты уже существовали, когда setMpqManager попытается их обновить.
        // Однако, если mpqManager изначально null, то populateView не должен вызываться.
        // В данном случае, конструктор просто запоминает mpqManager,
        // а setMpqManager (если будет вызван извне) или populateView (если mpqManager не null)
        // уже корректно обработают состояние.
        qCWarning(mpqManagerWidgetLog) << "MpqManagerWidget constructed with nullptr MpqManager.";
    }
    // setMpqManager(m_mpqManager); // Можно вызвать здесь, чтобы сразу отобразить состояние, или ожидать внешнего
    // вызова
    populateView();  // Вызываем populateView, чтобы отобразить начальное состояние
}

MpqManagerWidget::~MpqManagerWidget()
{
    clearVirtualFileSystemRecursive(m_mpqRootNode);
    // m_mpqRootNode будет nullptr после clearVirtualFileSystemRecursive, если он был не null
    // delete m_mpqRootNode; // Уже удаляется в clearVirtualFileSystemRecursive
}

void MpqManagerWidget::setupUi()
{
    qCDebug(mpqManagerWidgetLog) << "Setting up UI for MpqManagerWidget";
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Виджет для списка открытых архивов
    QLabel* archivesLabel = new QLabel("Открытые MPQ архивы:", this);
    mainLayout->addWidget(archivesLabel);
    m_archivesListWidget->setMaximumHeight(100);  // Ограничиваем высоту
    mainLayout->addWidget(m_archivesListWidget);

    // Дерево файлов из MPQ
    QLabel* filesLabel = new QLabel("Содержимое архивов:", this);
    mainLayout->addWidget(filesLabel);
    m_treeView->setModel(m_fileSystemModel);
    QStringList headers = {"Имя файла/папки", "Размер", "Источник (MPQ)"};
    m_fileSystemModel->setHorizontalHeaderLabels(headers);
    m_treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_treeView->setContextMenuPolicy(Qt::CustomContextMenu);
    mainLayout->addWidget(m_treeView);

    setLayout(mainLayout);

    // Соединяем сигнал для контекстного меню
    connect(m_treeView, &QTreeView::customContextMenuRequested, this,
            &MpqManagerWidget::onTreeViewContextMenuRequested);
}

void MpqManagerWidget::populateView()
{
    m_fileSystemModel->clear();
    m_archivesListWidget->clear();

    if (!m_mpqManager || !m_mpqManager->isInitialized())
    {
        qCWarning(mpqManagerWidgetLog) << "populateView: MpqManager is null or not initialized.";

        QList<QStandardItem*> errorRowItems;
        QStandardItem* messageItem = new QStandardItem("MPQ менеджер не инициализирован или нет открытых архивов.");
        errorRowItems.append(messageItem);
        // Ожидается 3 колонки, как определено в setupUi
        for (int i = 1; i < 3; ++i)
        {  // Используем константу 3
            errorRowItems.append(new QStandardItem(""));
        }
        m_fileSystemModel->appendRow(errorRowItems);

        m_archivesListWidget->addItem("MPQ менеджер не инициализирован.");
        // Применяем растягивание колонки здесь, когда модель уже имеет структуру
        if (m_fileSystemModel->columnCount() > 0)
        {  // Убедимся, что колонки есть
            m_treeView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
        }
        return;
    }

    QList<HANDLE> archiveHandles = m_mpqManager->getOpenedArchiveHandles();
    if (archiveHandles.isEmpty())
    {
        m_archivesListWidget->addItem("Нет открытых MPQ архивов.");
    }
    else
    {
        for (HANDLE handle : archiveHandles)
        {
            QString archiveName = m_mpqManager->getArchiveNameByHandle(handle);
            m_archivesListWidget->addItem(archiveName.isEmpty()
                                              ? QString("Архив (хендл %1)").arg(reinterpret_cast<quintptr>(handle))
                                              : archiveName);
        }
    }

    clearVirtualFileSystemRecursive(m_mpqRootNode);
    m_mpqRootNode = new MpqVirtualDir("/");

    buildVirtualFileSystem();

    if (m_mpqRootNode && (!m_mpqRootNode->subDirs.isEmpty() || !m_mpqRootNode->files.isEmpty()))
    {
        populateModelFromVirtualFsRecursive(m_mpqRootNode, m_fileSystemModel->invisibleRootItem());
    }
    else
    {
        QList<QStandardItem*> emptyMessageRowItems;
        QStandardItem* messageItem =
            new QStandardItem("Не удалось загрузить структуру файлов из MPQ или архивы пусты.");
        emptyMessageRowItems.append(messageItem);
        // Ожидается 3 колонки, как определено в setupUi
        for (int i = 1; i < 3; ++i)
        {  // Используем константу 3
            emptyMessageRowItems.append(new QStandardItem(""));
        }
        m_fileSystemModel->appendRow(emptyMessageRowItems);

        qCWarning(mpqManagerWidgetLog) << "Virtual file system is empty after build or archives are empty.";
    }
    m_treeView->expandToDepth(0);
    // Применяем растягивание колонки здесь, когда модель уже имеет структуру
    if (m_fileSystemModel->columnCount() > 0)
    {  // Убедимся, что колонки есть
        m_treeView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    }
}

void MpqManagerWidget::clearVirtualFileSystemRecursive(MpqVirtualDir* node)
{
    if (!node) return;
    qDeleteAll(node->subDirs.values());
    node->subDirs.clear();
    node->files.clear();
    // Если node это m_mpqRootNode, то сам m_mpqRootNode не удаляем здесь,
    // а только его содержимое. Сам m_mpqRootNode удаляется в деструкторе или при пересоздании.
    if (node != m_mpqRootNode)
    {  // Удаляем только дочерние узлы, а не сам корень, если он передан
        delete node;
    }
}

void MpqManagerWidget::buildVirtualFileSystem()
{
    if (!m_mpqManager || !m_mpqManager->isInitialized())
    {
        qCWarning(mpqManagerWidgetLog)
            << "buildVirtualFileSystem: MpqManager is null or not initialized. Cannot build FS.";
        return;
    }

    QList<HANDLE> archiveHandles = m_mpqManager->getOpenedArchiveHandles();
    if (archiveHandles.isEmpty())
    {
        qCInfo(mpqManagerWidgetLog) << "buildVirtualFileSystem: No archives to process for virtual FS.";
        return;
    }
    qCDebug(mpqManagerWidgetLog) << "Building virtual file system for" << archiveHandles.size() << "archives.";

    SFILE_FIND_DATA findData;
    const char* listFileMask = "(listfile)";

    for (HANDLE hArchive : archiveHandles)
    {
        if (!hArchive || hArchive == INVALID_HANDLE_VALUE) continue;
        HANDLE hFind = SFileFindFirstFile(hArchive, listFileMask, &findData, nullptr);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                QString filePath = QString::fromLatin1(findData.cFileName).replace("\\", "/");
                addPathToVirtualFS(filePath, hArchive, findData.dwFileSize);
            } while (SFileFindNextFile(hFind, &findData));
            SFileFindClose(hFind);
        }
        else
        {
            qCWarning(mpqManagerWidgetLog)
                << "Failed to find files in archive, handle:" << hArchive << "Error:" << GetLastError();
        }
    }
}

void MpqManagerWidget::addPathToVirtualFS(const QString& filePath, HANDLE archiveHandle, quint32 fileSize)
{
    QStringList pathParts = filePath.split('/', Qt::SkipEmptyParts);
    if (pathParts.isEmpty())
    {
        qCWarning(mpqManagerWidgetLog) << "Empty path received in addPathToVirtualFS:" << filePath;
        return;
    }

    MpqVirtualDir* currentNode = m_mpqRootNode;
    for (int i = 0; i < pathParts.size() - 1; ++i)
    {
        currentNode = currentNode->findOrCreateSubDir(pathParts[i]);
    }

    const QString& fileName = pathParts.last();
    bool fileExists = false;
    for (const auto& existingFile : currentNode->files)
    {
        if (existingFile.name == fileName && existingFile.sourceArchive == archiveHandle)
        {
            fileExists = true;
            break;
        }
    }

    if (!fileExists)
    {
        MpqVirtualFile fileEntry;
        fileEntry.name = fileName;
        fileEntry.sourceArchive = archiveHandle;
        fileEntry.fileSize = fileSize;
        currentNode->files.append(fileEntry);
    }
}

void MpqManagerWidget::populateModelFromVirtualFsRecursive(MpqVirtualDir* dirNode, QStandardItem* parentModelItem)
{
    if (!dirNode || !parentModelItem)
    {
        qCWarning(mpqManagerWidgetLog) << "populateModelFromVirtualFsRecursive: dirNode or parentModelItem is null.";
        return;
    }

    QStringList sortedDirNames = dirNode->subDirs.keys();
    std::sort(sortedDirNames.begin(), sortedDirNames.end());

    for (const QString& dirName : sortedDirNames)
    {
        MpqVirtualDir* subDir = dirNode->subDirs.value(dirName);
        if (subDir)
        {
            QList<QStandardItem*> dirRowItems;
            QStandardItem* dirItem = new QStandardItem(dirName);
            dirItem->setEditable(false);
            dirItem->setData(false, Qt::UserRole);  // Флаг, что это не файл

            QStandardItem* dirSizeItem = new QStandardItem("--");
            dirSizeItem->setEditable(false);
            QStandardItem* dirSourceItem = new QStandardItem("--");
            dirSourceItem->setEditable(false);

            dirRowItems << dirItem << dirSizeItem << dirSourceItem;
            parentModelItem->appendRow(dirRowItems);
            populateModelFromVirtualFsRecursive(subDir, dirItem);
        }
    }

    QList<MpqVirtualFile> sortedFiles = dirNode->files;
    std::sort(sortedFiles.begin(), sortedFiles.end(),
              [](const MpqVirtualFile& a, const MpqVirtualFile& b) { return a.name < b.name; });

    for (const MpqVirtualFile& fileInfo : sortedFiles)
    {
        QList<QStandardItem*> fileRowItems;
        QStandardItem* fileItem = new QStandardItem(fileInfo.name);
        fileItem->setEditable(false);
        fileItem->setData(true, Qt::UserRole);  // Флаг, что это файл
        // Сохраняем полный путь к файлу для извлечения
        // Для этого нам нужно восстановить путь от корня до текущего dirNode + fileInfo.name
        // Это будет сложно сделать здесь без передачи полного пути.
        // Проще будет сохранить полный путь в MpqVirtualFile при создании.
        // Пока оставим так, или сохраним только имя файла для простоты,
        // а извлечение будет искать по имени во всех архивах.
        // Для правильного извлечения из КОНКРЕТНОГО архива, нужен полный путь.
        // Предположим, что fileInfo.name - это уже полный путь внутри архива.
        fileItem->setData(fileInfo.name, Qt::UserRole + 1);

        QStandardItem* fileSizeItem = new QStandardItem(QString::number(fileInfo.fileSize) + " B");
        fileSizeItem->setEditable(false);
        fileSizeItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);

        QString archiveName = m_mpqManager->getArchiveNameByHandle(fileInfo.sourceArchive);
        if (archiveName.isEmpty())
        {
            archiveName = QString("Архив (HANDLE: %1)").arg(reinterpret_cast<quintptr>(fileInfo.sourceArchive));
        }
        QStandardItem* fileSourceItem = new QStandardItem(archiveName);
        fileSourceItem->setEditable(false);

        fileRowItems << fileItem << fileSizeItem << fileSourceItem;
        parentModelItem->appendRow(fileRowItems);
    }
}

void MpqManagerWidget::setMpqManager(MpqManager* mpqManager)
{
    qCDebug(mpqManagerWidgetLog) << "setMpqManager called. New manager:" << (mpqManager ? "Valid" : "Null")
                                 << "Initialized:" << (mpqManager && mpqManager->isInitialized());
    m_mpqManager = mpqManager;
    populateView();  // Перезаполняем виджет с новым менеджером
}

void MpqManagerWidget::onTreeViewContextMenuRequested(const QPoint& pos)
{
    qCDebug(mpqManagerWidgetLog) << "Context menu requested at" << pos;
    if (!m_mpqManager || !m_mpqManager->isInitialized())
    {
        qCDebug(mpqManagerWidgetLog) << "MpqManager not ready, ignoring context menu.";
        return;
    }

    QModelIndex index = m_treeView->indexAt(pos);
    if (!index.isValid()) return;

    QStandardItem* item = m_fileSystemModel->itemFromIndex(index);
    // Проверяем, является ли элемент файлом (мы установили UserRole в true для файлов)
    if (item && item->data(Qt::UserRole).toBool())
    {
        QMenu contextMenu(this);
        QAction* extractAction = contextMenu.addAction("Извлечь файл");
        connect(extractAction, &QAction::triggered, this, &MpqManagerWidget::onExtractFileAction);
        contextMenu.exec(m_treeView->viewport()->mapToGlobal(pos));
    }
}

void MpqManagerWidget::onExtractFileAction()
{
    qCDebug(mpqManagerWidgetLog) << "Extract file action triggered.";
    if (!m_mpqManager || !m_mpqManager->isInitialized())
    {
        QMessageBox::warning(this, "Ошибка извлечения", "MPQ менеджер не инициализирован.");
        return;
    }

    QModelIndex currentIndex = m_treeView->currentIndex();
    if (!currentIndex.isValid())
    {
        QMessageBox::information(this, "Извлечение файла", "Файл не выбран.");
        return;
    }

    QStandardItem* item = m_fileSystemModel->itemFromIndex(currentIndex);
    if (!item || !item->data(Qt::UserRole).toBool())  // Убеждаемся, что это файл
    {
        QMessageBox::information(this, "Извлечение файла", "Пожалуйста, выберите файл для извлечения (не директорию).");
        return;
    }

    // Получаем полный внутренний путь к файлу, сохраненный ранее
    QString internalFilePath = item->data(Qt::UserRole + 1).toString();
    if (internalFilePath.isEmpty())
    {
        qCWarning(mpqManagerWidgetLog) << "Cannot extract: internal file path is empty for item:" << item->text();
        QMessageBox::warning(this, "Ошибка извлечения", "Внутренний путь к файлу не найден.");
        return;
    }

    QByteArray fileContent;
    if (m_mpqManager->loadFile(internalFilePath, fileContent))
    {
        QString fileName = QFileInfo(internalFilePath).fileName();  // Получаем только имя файла для диалога сохранения
        QString savePath = QFileDialog::getSaveFileName(this, "Сохранить файл как", fileName);

        if (!savePath.isEmpty())
        {
            QFile outFile(savePath);
            if (outFile.open(QIODevice::WriteOnly))
            {
                qint64 bytesWritten = outFile.write(fileContent);
                outFile.close();
                if (bytesWritten == fileContent.size())
                {
                    QMessageBox::information(
                        this, "Успех", QString("Файл '%1' успешно сохранен.").arg(QFileInfo(savePath).fileName()));
                }
                else
                {
                    QMessageBox::warning(
                        this, "Ошибка сохранения",
                        QString("Не удалось полностью записать файл '%1'.").arg(QFileInfo(savePath).fileName()));
                }
            }
            else
            {
                QMessageBox::warning(
                    this, "Ошибка сохранения",
                    QString("Не удалось открыть файл для записи: %1\n%2").arg(savePath).arg(outFile.errorString()));
            }
        }
        // Если savePath пустой (пользователь отменил), ничего не делаем
    }
    else
    {
        QMessageBox::warning(this, "Ошибка извлечения",
                             QString("Не удалось загрузить файл '%1' из MPQ архивов.").arg(internalFilePath));
    }
}
