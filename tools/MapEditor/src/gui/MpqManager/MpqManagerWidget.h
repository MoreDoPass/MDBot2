#ifndef MPQMANAGERWIDGET_H
#define MPQMANAGERWIDGET_H

#include <QWidget>
#include <QTreeView>
#include <QStandardItemModel>
#include <QLoggingCategory>
#include <QMap>
#include <QListWidget>

// Для HANDLE и других типов StormLib
#include <StormLib.h>

// Forward declaration для MpqManager, чтобы избежать циклической зависимости
// Полное определение будет в .cpp файле, где оно необходимо.
class MpqManager;

// Объявление категории логирования должно быть здесь, до определения класса
Q_DECLARE_LOGGING_CATEGORY(mpqManagerWidgetLog)

class MpqManagerWidget : public QWidget
{
    Q_OBJECT

   public:
    explicit MpqManagerWidget(MpqManager* mpqManager, QWidget* parent = nullptr);
    ~MpqManagerWidget();  // Объявление деструктора

    void populateView();
    void setMpqManager(MpqManager* mpqManager);

   private slots:
    void onTreeViewContextMenuRequested(const QPoint& pos);
    void onExtractFileAction();

   private:
    QTreeView* m_treeView;
    MpqManager* m_mpqManager;               // Указатель на внешний менеджер (не владеем)
    QStandardItemModel* m_fileSystemModel;  // Будем использовать QStandardItemModel для простоты
    QListWidget* m_archivesListWidget = nullptr;

    // Структуры для построения виртуальной файловой системы
    struct MpqVirtualFile
    {
        QString name;
        HANDLE sourceArchive;  // Из какого архива этот файл (для информации)
        quint32 fileSize = 0;
        // Другие свойства, если нужны (флаги, время...)
    };

    struct MpqVirtualDir
    {
        QString name;
        QMap<QString, MpqVirtualDir*> subDirs;
        QList<MpqVirtualFile> files;

        MpqVirtualDir(QString n = QString()) : name(n) {}
        ~MpqVirtualDir()
        {
            qDeleteAll(subDirs.values());  // qDeleteAll безопасен для пустого списка
            subDirs.clear();
        }

        MpqVirtualDir* findOrCreateSubDir(const QString& dirName)
        {
            if (!subDirs.contains(dirName))
            {
                subDirs[dirName] = new MpqVirtualDir(dirName);
            }
            return subDirs[dirName];
        }
    };

    MpqVirtualDir* m_mpqRootNode = nullptr;  // Корень виртуальной файловой системы

    void setupUi();
    void buildVirtualFileSystem();  // Заполняет m_mpqRootNode
    void populateModelFromVirtualFsRecursive(MpqVirtualDir* dirNode,
                                             QStandardItem* parentModelItem);  // Заполняет модель из m_mpqRootNode
    void clearVirtualFileSystemRecursive(MpqVirtualDir* node);                 // Рекурсивная очистка m_mpqRootNode

    void addPathToVirtualFS(const QString& filePath, HANDLE archiveHandle, quint32 fileSize);
};

#endif  // MPQMANAGERWIDGET_H