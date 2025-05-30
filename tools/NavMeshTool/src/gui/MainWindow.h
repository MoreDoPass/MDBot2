#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

// Предварительные объявления для указателей на члены Qt Designer UI, если будем использовать .ui файлы
QT_BEGIN_NAMESPACE
namespace Ui
{
class MainWindow;
}
QT_END_NAMESPACE

class MpqManager;  // Предварительное объявление, если будем использовать указатель/ссылку

class MainWindow : public QMainWindow
{
    Q_OBJECT

   public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

   private slots:
    void openMpqArchive();  // Слот для открытия MPQ архива
                            // Другие слоты для обработки действий пользователя

   private:
    // Если будем использовать Qt Designer для UI
    Ui::MainWindow *ui;

    // Экземпляр MpqManager
    MpqManager *m_mpqManager;

    // Другие приватные методы и члены
    void setupUiElements();  // Метод для настройки UI, если не используется .ui файл
    void createMenus();
    void createActions();
    void createStatusBar();
};
#endif  // MAINWINDOW_H
