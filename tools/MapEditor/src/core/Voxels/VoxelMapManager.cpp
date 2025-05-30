#include "VoxelMapManager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>  // Для qCInfo, qCWarning и т.д.

Q_LOGGING_CATEGORY(voxelMapManagerLog, "mapeditor.voxelmapmanager")

VoxelMapManager::VoxelMapManager()
{
    // Конструктор может быть пустым или инициализировать что-либо, если это необходимо
    qCInfo(voxelMapManagerLog) << "VoxelMapManager created.";
}

bool VoxelMapManager::loadVoxelMap(const QString& filePath, VoxelMap& outVoxelMap)
{
    qCInfo(voxelMapManagerLog) << "Attempting to load VoxelMap from:" << filePath;
    outVoxelMap.clear();  // Очищаем карту перед загрузкой

    QFile loadFile(filePath);
    if (!loadFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qCWarning(voxelMapManagerLog) << "Failed to open file for reading:" << filePath << loadFile.errorString();
        return false;
    }

    QByteArray saveData = loadFile.readAll();
    loadFile.close();

    QJsonParseError parseError;
    QJsonDocument loadDoc = QJsonDocument::fromJson(saveData, &parseError);

    if (parseError.error != QJsonParseError::NoError)
    {
        qCWarning(voxelMapManagerLog) << "Failed to parse JSON from file:" << filePath << parseError.errorString();
        return false;
    }

    if (!loadDoc.isObject())
    {
        qCWarning(voxelMapManagerLog) << "JSON document is not an object:" << filePath;
        return false;
    }

    QJsonObject rootObject = loadDoc.object();

    // 1. Загрузка метаданных
    if (!rootObject.contains("origin") || !rootObject["origin"].isObject() ||
        !rootObject.contains("dimensions_voxels") || !rootObject["dimensions_voxels"].isObject() ||
        !rootObject.contains("voxel_size") || !rootObject["voxel_size"].isDouble() ||
        !rootObject.contains("voxels_data") || !rootObject["voxels_data"].isArray())
    {
        qCWarning(voxelMapManagerLog) << "Missing or invalid metadata in VoxelMap file:" << filePath;
        return false;
    }

    QJsonObject originObj = rootObject["origin"].toObject();
    QVector3D origin(originObj["x"].toDouble(), originObj["y"].toDouble(), originObj["z"].toDouble());

    QJsonObject dimensionsObj = rootObject["dimensions_voxels"].toObject();
    QVector3D dimensions(dimensionsObj["x"].toDouble(), dimensionsObj["y"].toDouble(), dimensionsObj["z"].toDouble());

    float voxelSize = static_cast<float>(rootObject["voxel_size"].toDouble());

    // Проверка на корректность размеров перед инициализацией
    if (dimensions.x() <= 0 || dimensions.y() <= 0 || dimensions.z() <= 0 || voxelSize <= 0.0f)
    {
        qCWarning(voxelMapManagerLog) << "Invalid map dimensions or voxel size in file:" << filePath;
        return false;
    }

    outVoxelMap.initialize(origin, dimensions, voxelSize,
                           VoxelState::UNKNOWN);  // Инициализируем с UNKNOWN, потом заполним

    // 2. Загрузка данных вокселей
    QJsonArray voxelsArray = rootObject["voxels_data"].toArray();
    int expectedTotalVoxels = static_cast<int>(dimensions.x() * dimensions.y() * dimensions.z());

    if (voxelsArray.size() != expectedTotalVoxels)
    {
        qCWarning(voxelMapManagerLog) << "Voxel data size mismatch. Expected:" << expectedTotalVoxels
                                      << "Got:" << voxelsArray.size();
        outVoxelMap.clear();  // Очищаем, т.к. данные некорректны
        return false;
    }

    int currentIdx = 0;
    for (int z = 0; z < dimensions.z(); ++z)
    {
        for (int y = 0; y < dimensions.y(); ++y)
        {
            for (int x = 0; x < dimensions.x(); ++x)
            {
                if (currentIdx < voxelsArray.size())
                {
                    VoxelState state = static_cast<VoxelState>(voxelsArray.at(currentIdx++).toInt());
                    outVoxelMap.setVoxelState(x, y, z, state);
                }
                else
                {
                    // Этого не должно произойти, если проверка размера прошла
                    qCWarning(voxelMapManagerLog) << "Ran out of voxel data during loading.";
                    outVoxelMap.clear();
                    return false;
                }
            }
        }
    }

    if (!outVoxelMap.isInitialized())
    {
        qCWarning(voxelMapManagerLog) << "VoxelMap failed to initialize after loading attempt from:" << filePath;
        return false;
    }

    qCInfo(voxelMapManagerLog) << "Successfully loaded VoxelMap from:" << filePath;
    return true;
}

bool VoxelMapManager::saveVoxelMap(const QString& filePath, const VoxelMap& voxelMap)
{
    qCInfo(voxelMapManagerLog) << "Attempting to save VoxelMap to:" << filePath;

    if (!voxelMap.isInitialized())
    {
        qCWarning(voxelMapManagerLog) << "Attempt to save an uninitialized VoxelMap. Aborting.";
        return false;
    }

    QJsonObject rootObject;

    // 1. Сохранение метаданных
    QJsonObject originObj;
    originObj["x"] = voxelMap.getOrigin().x();
    originObj["y"] = voxelMap.getOrigin().y();
    originObj["z"] = voxelMap.getOrigin().z();
    rootObject["origin"] = originObj;

    QJsonObject dimensionsObj;
    dimensionsObj["x"] = voxelMap.getDimensionsInVoxels().x();
    dimensionsObj["y"] = voxelMap.getDimensionsInVoxels().y();
    dimensionsObj["z"] = voxelMap.getDimensionsInVoxels().z();
    rootObject["dimensions_voxels"] = dimensionsObj;

    rootObject["voxel_size"] = voxelMap.getVoxelSize();

    // 2. Сохранение данных вокселей
    QJsonArray voxelsArray;
    int width = voxelMap.getWidthInVoxels();
    int height = voxelMap.getHeightInVoxels();
    int depth = voxelMap.getDepthInVoxels();

    for (int z = 0; z < depth; ++z)
    {
        for (int y = 0; y < height; ++y)
        {
            for (int x = 0; x < width; ++x)
            {
                voxelsArray.append(static_cast<int>(voxelMap.getVoxelState(x, y, z)));
            }
        }
    }
    rootObject["voxels_data"] = voxelsArray;

    QJsonDocument saveDoc(rootObject);
    QByteArray jsonData = saveDoc.toJson(QJsonDocument::Indented);  // Indented для читаемости

    QFile saveFile(filePath);
    if (!saveFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        qCWarning(voxelMapManagerLog) << "Failed to open file for writing:" << filePath << saveFile.errorString();
        return false;
    }

    if (saveFile.write(jsonData) == -1)
    {
        qCWarning(voxelMapManagerLog) << "Failed to write data to file:" << filePath << saveFile.errorString();
        saveFile.close();
        return false;
    }

    saveFile.close();
    qCInfo(voxelMapManagerLog) << "Successfully saved VoxelMap to:" << filePath;
    return true;
}

// Пример реализации createNewVoxelMap, если она понадобится в менеджере
/*
VoxelMap VoxelMapManager::createNewVoxelMap(const QVector3D& origin, const QVector3D& dimensions, float voxelSize,
VoxelState initialState)
{
    qCInfo(voxelMapManagerLog) << "Creating new VoxelMap with Origin:" << origin << "Dimensions:" << dimensions <<
"Voxel Size:" << voxelSize; VoxelMap newMap; newMap.initialize(origin, dimensions, voxelSize, initialState); if
(!newMap.isInitialized()) { qCWarning(voxelMapManagerLog) << "Failed to initialize new VoxelMap.";
        // Можно вернуть пустую карту или выбросить исключение
    }
    return newMap;
}
*/
