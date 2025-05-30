#include "VoxelMap.h"
#include <QDebug>  // Для qWarning, qInfo и т.д.

Q_LOGGING_CATEGORY(voxelMapLog, "mapeditor.voxelmap")

VoxelMap::VoxelMap() : m_voxelSize(1.0f), m_isInitialized(false)
{
    // Конструктор по умолчанию, инициализация минимальна.
    // Основная настройка происходит в initialize().
}

void VoxelMap::initialize(const QVector3D& origin, const QVector3D& mapDimensionsInVoxels, float voxelSize,
                          VoxelState initialState)
{
    if (voxelSize <= 0.0f)
    {
        qCWarning(voxelMapLog) << "Voxel size must be positive. Initialization failed.";
        m_isInitialized = false;
        return;
    }
    if (mapDimensionsInVoxels.x() <= 0 || mapDimensionsInVoxels.y() <= 0 || mapDimensionsInVoxels.z() <= 0)
    {
        qCWarning(voxelMapLog) << "Map dimensions in voxels must be positive. Initialization failed.";
        m_isInitialized = false;
        return;
    }

    m_origin = origin;
    m_dimensionsInVoxels = mapDimensionsInVoxels;
    m_voxelSize = voxelSize;

    int totalVoxels = static_cast<int>(m_dimensionsInVoxels.x() * m_dimensionsInVoxels.y() * m_dimensionsInVoxels.z());
    try
    {
        m_voxelsData.resize(totalVoxels);
        m_voxelsData.fill(initialState);
    }
    catch (const std::bad_alloc& e)
    {
        qCritical(voxelMapLog) << "Failed to allocate memory for voxel data (" << totalVoxels
                               << " voxels):" << e.what();
        m_isInitialized = false;
        m_voxelsData.clear();  // Освобождаем, если что-то было выделено частично
        return;
    }

    m_isInitialized = true;
    qCInfo(voxelMapLog) << "VoxelMap initialized: Origin" << m_origin << "Dims" << m_dimensionsInVoxels << "VoxelSize"
                        << m_voxelSize << "TotalVoxels" << totalVoxels;
}

int VoxelMap::getFlatIndex(int x, int y, int z) const
{
    if (!isValidVoxelIndex(x, y, z))
    {
        return -1;  // Индексы вне диапазона
    }
    // W * H * Z + W * Y + X
    // В нашем случае: Depth * Height * z_coord + Depth * y_coord + x_coord неверно
    // Правильно для порядка X, Y, Z (ширина, высота, глубина):
    // (z * height * width) + (y * width) + x
    // или (z * num_voxels_in_XY_plane) + (y * num_voxels_in_X_row) + x
    return static_cast<int>((z * m_dimensionsInVoxels.y() * m_dimensionsInVoxels.x()) + (y * m_dimensionsInVoxels.x()) +
                            x);
}

bool VoxelMap::isValidVoxelIndex(int x, int y, int z) const
{
    if (!m_isInitialized) return false;
    return x >= 0 && x < m_dimensionsInVoxels.x() && y >= 0 && y < m_dimensionsInVoxels.y() && z >= 0 &&
           z < m_dimensionsInVoxels.z();
}

VoxelState VoxelMap::getVoxelState(int x, int y, int z) const
{
    if (!m_isInitialized)
    {
        // qCWarning(voxelMapLog) << "Attempted to get voxel state from uninitialized map.";
        return VoxelState::UNKNOWN;  // Или выбросить исключение
    }
    int flatIndex = getFlatIndex(x, y, z);
    if (flatIndex == -1)  // getFlatIndex уже проверяет isValidVoxelIndex
    {
        // qCWarning(voxelMapLog) << "Attempted to get voxel state with invalid indices:" << x << y << z;
        return VoxelState::UNKNOWN;  // Возвращаем UNKNOWN для невалидных индексов
    }
    return m_voxelsData.at(flatIndex);
}

bool VoxelMap::setVoxelState(int x, int y, int z, VoxelState state)
{
    if (!m_isInitialized)
    {
        qCWarning(voxelMapLog) << "Attempted to set voxel state on uninitialized map.";
        return false;
    }
    int flatIndex = getFlatIndex(x, y, z);
    if (flatIndex == -1)
    {
        // qCWarning(voxelMapLog) << "Attempted to set voxel state with invalid indices:" << x << y << z;
        return false;  // Индексы вне диапазона
    }
    m_voxelsData[flatIndex] = state;
    return true;
}

bool VoxelMap::worldToVoxel(const QVector3D& worldPos, int& voxelX, int& voxelY, int& voxelZ) const
{
    if (!m_isInitialized || m_voxelSize == 0.0f)
    {
        // qCWarning(voxelMapLog) << "Attempted worldToVoxel on uninitialized map or zero voxel size.";
        return false;
    }

    QVector3D localPos = worldPos - m_origin;

    voxelX = static_cast<int>(floor(localPos.x() / m_voxelSize));
    voxelY = static_cast<int>(floor(localPos.y() / m_voxelSize));
    voxelZ = static_cast<int>(floor(localPos.z() / m_voxelSize));

    return isValidVoxelIndex(voxelX, voxelY, voxelZ);
}

bool VoxelMap::voxelToWorld(int voxelX, int voxelY, int voxelZ, QVector3D& worldPos) const
{
    if (!isValidVoxelIndex(voxelX, voxelY, voxelZ))
    {
        // qCWarning(voxelMapLog) << "Attempted voxelToWorld with invalid indices:" << voxelX << voxelY << voxelZ;
        return false;
    }
    // Возвращаем координату центра вокселя
    worldPos.setX(m_origin.x() + (static_cast<float>(voxelX) + 0.5f) * m_voxelSize);
    worldPos.setY(m_origin.y() + (static_cast<float>(voxelY) + 0.5f) * m_voxelSize);
    worldPos.setZ(m_origin.z() + (static_cast<float>(voxelZ) + 0.5f) * m_voxelSize);
    return true;
}

VoxelState VoxelMap::getVoxelState(const QVector3D& worldPos) const
{
    if (!m_isInitialized) return VoxelState::UNKNOWN;
    int vx, vy, vz;
    if (worldToVoxel(worldPos, vx, vy, vz))
    {
        return getVoxelState(vx, vy, vz);
    }
    // qCWarning(voxelMapLog) << "Attempted to get voxel state for world position outside map bounds:" << worldPos;
    return VoxelState::UNKNOWN;  // Точка вне карты
}

bool VoxelMap::setVoxelState(const QVector3D& worldPos, VoxelState state)
{
    if (!m_isInitialized) return false;
    int vx, vy, vz;
    if (worldToVoxel(worldPos, vx, vy, vz))
    {
        return setVoxelState(vx, vy, vz, state);
    }
    // qCWarning(voxelMapLog) << "Attempted to set voxel state for world position outside map bounds:" << worldPos;
    return false;  // Точка вне карты
}

void VoxelMap::clear()
{
    m_voxelsData.clear();
    m_origin = QVector3D();
    m_dimensionsInVoxels = QVector3D();
    m_voxelSize = 1.0f;
    m_isInitialized = false;
    qCInfo(voxelMapLog) << "VoxelMap cleared.";
}
