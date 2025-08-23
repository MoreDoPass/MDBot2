#pragma once
#include <QString>
#include <QTreeWidget>

// Класс для управления точками телепорта (загрузка/сохранение из JSON, работа с деревом)
class LocationManager
{
   public:
    LocationManager();
    ~LocationManager();

    // Загрузить структуру точек из файла
    bool loadFromFile(const QString& filename, QTreeWidget* treeWidget);
    // Сохранить структуру точек в файл
    bool saveToFile(const QString& filename, QTreeWidget* treeWidget);

    // TODO: методы для добавления/удаления/редактирования точек через API
    // (например, addLocation, removeLocation, updateLocation)

   private:
    // TODO: можно хранить внутреннее представление точек (например, QJsonObject), если потребуется
};

// Пример использования:
// LocationManager locManager;
// locManager.loadFromFile("locations.json", treeWidget);
// locManager.saveToFile("locations.json", treeWidget);