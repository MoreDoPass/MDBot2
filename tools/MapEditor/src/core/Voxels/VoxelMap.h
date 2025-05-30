#ifndef VOXELMAP_H
#define VOXELMAP_H

#include <QVector>
#include <QVector3D>
#include <QString>
#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(voxelMapLog)

/**
 * @brief Определяет возможные состояния вокселя.
 */
enum class VoxelState : quint8  // Используем quint8 для экономии памяти
{
    UNKNOWN = 0,            // Состояние неизвестно (начальное)
    FREE_GROUND,            // Проходимая земля
    FREE_AIR,               // Проходимый воздух (для полетов)
    FREE_WATER,             // Проходимая вода
    OBSTACLE_SOLID,         // Непроходимое твердое препятствие (стена, потолок, пол)
    OBSTACLE_DESTRUCTIBLE,  // Разрушаемое препятствие
    INTEREST_POINT,         // Точка интереса (например, моб, ресурс)
    PLAYER_PATH             // Воксель, являющийся частью текущего пути игрока (для отладки)
    // Можно добавлять другие состояния по мере необходимости
};

/**
 * @brief Класс для представления и управления воксельной картой.
 *
 * Хранит 3D сетку вокселей, каждый из которых имеет определенное состояние.
 * Предоставляет методы для доступа к вокселям, их изменения,
 * а также для преобразования между мировыми координатами и индексами вокселей.
 */
class VoxelMap
{
   public:
    /**
     * @brief Конструктор по умолчанию.
     * Создает пустую и неинициализированную карту.
     */
    VoxelMap();

    /**
     * @brief Инициализирует воксельную карту.
     * @param origin Мировая координата (X, Y, Z) угла карты, соответствующего вокселю (0,0,0).
     * @param mapDimensions Размеры карты в количестве вокселей по каждой оси (width, height, depth).
     * @param voxelSize Размер одного вокселя в мировых единицах (например, метрах).
     * @param initialState Начальное состояние для всех вокселей.
     */
    void initialize(const QVector3D& origin, const QVector3D& mapDimensionsInVoxels, float voxelSize,
                    VoxelState initialState = VoxelState::UNKNOWN);

    /**
     * @brief Получает состояние вокселя по его индексам.
     * @param x Индекс вокселя по оси X.
     * @param y Индекс вокселя по оси Y.
     * @param z Индекс вокселя по оси Z.
     * @return Состояние вокселя. Возвращает VoxelState::UNKNOWN, если индексы выходят за пределы карты.
     */
    VoxelState getVoxelState(int x, int y, int z) const;

    /**
     * @brief Устанавливает состояние вокселя по его индексам.
     * @param x Индекс вокселя по оси X.
     * @param y Индекс вокселя по оси Y.
     * @param z Индекс вокселя по оси Z.
     * @param state Новое состояние вокселя.
     * @return true, если установка прошла успешно, false - если индексы выходят за пределы карты.
     */
    bool setVoxelState(int x, int y, int z, VoxelState state);

    /**
     * @brief Получает состояние вокселя по мировым координатам.
     * @param worldPos Мировая координата точки.
     * @return Состояние вокселя, в котором находится точка. Возвращает VoxelState::UNKNOWN, если точка вне карты.
     */
    VoxelState getVoxelState(const QVector3D& worldPos) const;

    /**
     * @brief Устанавливает состояние вокселя по мировым координатам.
     * @param worldPos Мировая координата точки.
     * @param state Новое состояние вокселя.
     * @return true, если установка прошла успешно, false - если точка вне карты.
     */
    bool setVoxelState(const QVector3D& worldPos, VoxelState state);

    /**
     * @brief Преобразует мировую координату в индексы вокселя.
     * @param worldPos Мировая координата.
     * @param[out] voxelX Индекс вокселя по X (выходной параметр).
     * @param[out] voxelY Индекс вокселя по Y (выходной параметр).
     * @param[out] voxelZ Индекс вокселя по Z (выходной параметр).
     * @return true, если мировая координата находится внутри границ карты, иначе false.
     */
    bool worldToVoxel(const QVector3D& worldPos, int& voxelX, int& voxelY, int& voxelZ) const;

    /**
     * @brief Преобразует индексы вокселя в мировую координату центра вокселя.
     * @param voxelX Индекс вокселя по X.
     * @param voxelY Индекс вокселя по Y.
     * @param voxelZ Индекс вокселя по Z.
     * @param[out] worldPos Мировая координата центра вокселя (выходной параметр).
     * @return true, если индексы вокселя находятся внутри границ карты, иначе false.
     */
    bool voxelToWorld(int voxelX, int voxelY, int voxelZ, QVector3D& worldPos) const;

    /**
     * @brief Проверяет, находятся ли индексы вокселя в пределах карты.
     * @param x Индекс вокселя по оси X.
     * @param y Индекс вокселя по оси Y.
     * @param z Индекс вокселя по оси Z.
     * @return true, если индексы корректны, иначе false.
     */
    bool isValidVoxelIndex(int x, int y, int z) const;

    /**
     * @brief Очищает карту, сбрасывая все состояния и размеры.
     */
    void clear();

    // --- Геттеры ---
    float getVoxelSize() const
    {
        return m_voxelSize;
    }
    QVector3D getDimensionsInVoxels() const
    {
        return m_dimensionsInVoxels;
    }
    QVector3D getOrigin() const
    {
        return m_origin;
    }
    bool isInitialized() const
    {
        return m_isInitialized;
    }
    int getWidthInVoxels() const
    {
        return static_cast<int>(m_dimensionsInVoxels.x());
    }
    int getHeightInVoxels() const
    {
        return static_cast<int>(m_dimensionsInVoxels.y());
    }
    int getDepthInVoxels() const
    {
        return static_cast<int>(m_dimensionsInVoxels.z());
    }

   private:
    /**
     * @brief Рассчитывает одномерный индекс для доступа к m_voxelsData из 3D индексов.
     * @param x Индекс вокселя по оси X.
     * @param y Индекс вокселя по оси Y.
     * @param z Индекс вокселя по оси Z.
     * @return Одномерный индекс или -1, если входные индексы некорректны.
     */
    int getFlatIndex(int x, int y, int z) const;

    QVector3D m_origin;              // Мировая координата (X, Y, Z) вокселя (0,0,0)
    QVector3D m_dimensionsInVoxels;  // Размеры карты в количестве вокселей (width, height, depth)
    float m_voxelSize = 1.0f;        // Размер одного вокселя (предполагается кубический)

    QVector<VoxelState> m_voxelsData;  // Одномерный массив для хранения состояний всех вокселей

    bool m_isInitialized = false;
};

#endif  // VOXELMAP_H
