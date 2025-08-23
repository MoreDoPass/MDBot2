#include "locationmanager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

// --- НОВАЯ, ПРАВИЛЬНАЯ ЛОГИКА С МАССИВАМИ ---

void buildTree(const QJsonArray& jsonArray, QTreeWidgetItem* parentItem);

/**
 * @brief Рекурсивно читает JSON-узел (объект) и строит его представление в дереве.
 */
void buildTreeFromObject(const QJsonObject& jsonObj, QTreeWidgetItem* parentItem)
{
    auto* newItem = new QTreeWidgetItem(parentItem);

    // 1. Устанавливаем имя из поля "name"
    if (jsonObj.contains("name") && jsonObj["name"].isString())
    {
        newItem->setText(0, jsonObj["name"].toString());
    }

    // 2. Устанавливаем координаты из полей "x", "y", "z"
    if (jsonObj.contains("x") && jsonObj.contains("y") && jsonObj.contains("z"))
    {
        newItem->setData(0, Qt::UserRole, jsonObj["x"].toDouble());
        newItem->setData(0, Qt::UserRole + 1, jsonObj["y"].toDouble());
        newItem->setData(0, Qt::UserRole + 2, jsonObj["z"].toDouble());
    }

    // 3. Если есть дети (в виде массива), рекурсивно строим их
    if (jsonObj.contains("children") && jsonObj["children"].isArray())
    {
        buildTree(jsonObj["children"].toArray(), newItem);
    }
}

/**
 * @brief Рекурсивно читает JSON-массив и строит его представление в дереве.
 */
void buildTree(const QJsonArray& jsonArray, QTreeWidgetItem* parentItem)
{
    for (const QJsonValue& value : jsonArray)
    {
        if (value.isObject())
        {
            buildTreeFromObject(value.toObject(), parentItem);
        }
    }
}

/**
 * @brief Рекурсивно обходит QTreeWidget и создает соответствующий JSON-массив.
 */
QJsonArray buildJson(QTreeWidgetItem* parentItem)
{
    QJsonArray jsonArray;
    for (int i = 0; i < parentItem->childCount(); ++i)
    {
        QTreeWidgetItem* child = parentItem->child(i);
        QJsonObject childNode;

        // 1. Сохраняем имя в поле "name"
        childNode["name"] = child->text(0);

        // 2. Сохраняем координаты, если они есть
        if (child->data(0, Qt::UserRole).isValid())
        {
            childNode["x"] = child->data(0, Qt::UserRole).toDouble();
            childNode["y"] = child->data(0, Qt::UserRole + 1).toDouble();
            childNode["z"] = child->data(0, Qt::UserRole + 2).toDouble();
        }

        // 3. Рекурсивно сохраняем детей
        if (child->childCount() > 0)
        {
            childNode["children"] = buildJson(child);
        }

        jsonArray.append(childNode);
    }
    return jsonArray;
}

// --- Методы класса ---

bool LocationManager::loadFromFile(const QString& filename, QTreeWidget* treeWidget)
{
    QFile file(filename);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        treeWidget->clear();
        return false;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonDocument doc = QJsonDocument::fromJson(data);
    // Теперь корневой элемент должен быть МАССИВОМ
    if (!doc.isArray())
    {
        treeWidget->clear();
        return false;
    }

    treeWidget->clear();
    buildTree(doc.array(), treeWidget->invisibleRootItem());
    return true;
}

bool LocationManager::saveToFile(const QString& filename, QTreeWidget* treeWidget)
{
    // Результатом buildJson теперь будет массив
    QJsonArray rootArray = buildJson(treeWidget->invisibleRootItem());

    QJsonDocument doc(rootArray);
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        return false;
    }
    // Используем tojson(Compact), чтобы не раздувать файл
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();
    return true;
}

LocationManager::LocationManager() {}
LocationManager::~LocationManager() {}