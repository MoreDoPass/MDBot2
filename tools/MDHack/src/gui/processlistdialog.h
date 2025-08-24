#pragma once
#include <QDialog>
#include <QVector>
#include "core/process/processmanager.h"

// Прямые объявления, чтобы не включать лишние заголовки
class QListWidget;
class QPushButton;
class QLineEdit;  // <-- ДОБАВЛЕНО

/**
 * @brief Диалоговое окно для выбора процесса игры из списка.
 * @details Показывает все найденные процессы "run.exe", позволяет
 *          указать имя компьютера для подмены и возвращает выбранный
 *          PID и указанное имя.
 */
class ProcessListDialog : public QDialog
{
    Q_OBJECT
   public:
    /**
     * @brief Конструктор.
     * @param parent Родительский виджет.
     */
    explicit ProcessListDialog(QWidget* parent = nullptr);

    /**
     * @brief Получить информацию о выбранном процессе (PID и имя).
     * @return ProcessInfo - структура с данными процесса.
     */
    ProcessInfo selectedProcess() const;

    /**
     * @brief Получить имя компьютера, введенное пользователем.
     * @return QString с именем компьютера. Может быть пустым.
     */
    QString computerName() const;

   private slots:
    /**
     * @brief Обновляет список процессов, перечитывая их из системы.
     */
    void refreshProcessList();

    /**
     * @brief Обрабатывает нажатие кнопки "OK", закрывая диалог.
     */
    void acceptSelection();

   private:
    /**
     * @brief Внутренний метод для получения списка процессов от ProcessManager.
     */
    void updateProcessList();

    QListWidget* listWidget;
    QPushButton* refreshButton;
    QPushButton* okButton;
    QLineEdit* m_computerNameEdit;  ///< <-- ДОБАВЛЕНО: Поле для ввода имени компьютера
    std::vector<ProcessInfo> processes;
    int selectedRow = -1;
};