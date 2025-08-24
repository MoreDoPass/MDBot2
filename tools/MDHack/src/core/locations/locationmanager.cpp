#include "locationmanager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QLoggingCategory>

// Создаем категорию логирования для этого файла
Q_LOGGING_CATEGORY(logLocManager, "mdhack.locationmanager")

// --- НОВАЯ, ПРАВИЛЬНАЯ ЛОГИКА С ВЕРСИОНИРОВАНИЕМ ---

// Определяем константы для ключей JSON и ролей данных, чтобы избежать опечаток
namespace LocationKeys
{
const QString Name = "name";
const QString Description = "description";  // <--- Новый ключ
const QString X = "x";
const QString Y = "y";
const QString Z = "z";
const QString Children = "children";
const QString Version = "version";
const QString Locations = "locations";
}  // namespace LocationKeys

namespace LocationRoles
{
const int RoleX = Qt::UserRole;
const int RoleY = Qt::UserRole + 1;
const int RoleZ = Qt::UserRole + 2;
const int RoleDescription = Qt::UserRole + 3;  // <--- Новая роль для данных
}  // namespace LocationRoles

void buildTree(const QJsonArray& jsonArray, QTreeWidgetItem* parentItem);

/**
 * @brief Рекурсивно читает JSON-узел (объект) и строит его представление в дереве.
 */
void buildTreeFromObject(const QJsonObject& jsonObj, QTreeWidgetItem* parentItem)
{
    auto* newItem = new QTreeWidgetItem(parentItem);

    if (jsonObj.contains(LocationKeys::Name))
    {
        newItem->setText(0, jsonObj[LocationKeys::Name].toString());
    }

    if (jsonObj.contains(LocationKeys::X) && jsonObj.contains(LocationKeys::Y) && jsonObj.contains(LocationKeys::Z))
    {
        newItem->setData(0, LocationRoles::RoleX, jsonObj[LocationKeys::X].toDouble());
        newItem->setData(0, LocationRoles::RoleY, jsonObj[LocationKeys::Y].toDouble());
        newItem->setData(0, LocationRoles::RoleZ, jsonObj[LocationKeys::Z].toDouble());
    }

    // Пытаемся прочитать описание. Если его нет - ничего страшного.
    if (jsonObj.contains(LocationKeys::Description))
    {
        newItem->setData(0, LocationRoles::RoleDescription, jsonObj[LocationKeys::Description].toString());
    }

    if (jsonObj.contains(LocationKeys::Children) && jsonObj[LocationKeys::Children].isArray())
    {
        buildTree(jsonObj[LocationKeys::Children].toArray(), newItem);
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

        childNode[LocationKeys::Name] = child->text(0);

        if (child->data(0, LocationRoles::RoleX).isValid())
        {
            childNode[LocationKeys::X] = child->data(0, LocationRoles::RoleX).toDouble();
            childNode[LocationKeys::Y] = child->data(0, LocationRoles::RoleY).toDouble();
            childNode[LocationKeys::Z] = child->data(0, LocationRoles::RoleZ).toDouble();
        }

        // Сохраняем описание, только если оно есть и не пустое
        QVariant descData = child->data(0, LocationRoles::RoleDescription);
        if (descData.isValid() && !descData.toString().isEmpty())
        {
            childNode[LocationKeys::Description] = descData.toString();
        }

        if (child->childCount() > 0)
        {
            childNode[LocationKeys::Children] = buildJson(child);
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
        qCWarning(logLocManager) << "Could not open locations file for reading:" << filename;
        return false;
    }

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    treeWidget->clear();

    // --- УМНЫЙ ЗАГРУЗЧИК ---
    if (doc.isArray())  // Если это старый формат (Версия 1)
    {
        qCInfo(logLocManager) << "Loading old format (v1) locations file.";
        buildTree(doc.array(), treeWidget->invisibleRootItem());
    }
    else if (doc.isObject())  // Если это новый формат (Версия 2)
    {
        qCInfo(logLocManager) << "Loading new format (v2) locations file.";
        QJsonObject rootObj = doc.object();
        if (rootObj.contains(LocationKeys::Locations) && rootObj[LocationKeys::Locations].isArray())
        {
            buildTree(rootObj[LocationKeys::Locations].toArray(), treeWidget->invisibleRootItem());
        }
    }
    else  // Неизвестный формат
    {
        qCWarning(logLocManager) << "Unknown format for locations.json. Should be an object or an array.";
        return false;
    }

    return true;
}

bool LocationManager::saveToFile(const QString& filename, QTreeWidget* treeWidget)
{
    QJsonArray locationsArray = buildJson(treeWidget->invisibleRootItem());

    // Создаем корневой объект-обертку
    QJsonObject rootObject;
    rootObject[LocationKeys::Version] = 2;  // Всегда сохраняем как Версию 2
    rootObject[LocationKeys::Locations] = locationsArray;

    QJsonDocument doc(rootObject);
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        qCCritical(logLocManager) << "Could not open locations file for writing:" << filename;
        return false;
    }
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();
    qCInfo(logLocManager) << "Locations saved to file:" << filename;
    return true;
}

LocationManager::LocationManager() {}
LocationManager::~LocationManager() {}