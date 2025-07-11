#include "WMOProcessor.h"
#include "core/MpqManager/MpqManager.h"
#include <QLoggingCategory>
#include <QMatrix4x4>
#include <QVector3D>

// Объявляем, что будем использовать эту категорию.
// Само определение находится в NavMeshGenerator.cpp
Q_DECLARE_LOGGING_CATEGORY(logNavMeshGenerator)

namespace
{
// Константы для расчетов.
constexpr float TILE_SIZE = 1600.0f / 3.0f;
constexpr float MAP_CHUNK_SIZE = TILE_SIZE * 32.0f;
}  // namespace

namespace NavMesh
{
namespace Processors
{

WmoProcessor::WmoProcessor(MpqManager& mpqManager) : m_mpqManager(mpqManager) {}

void WmoProcessor::process(const NavMeshTool::ADT::ADTData& adtData, std::unordered_set<uint32_t>& processedIds,
                           std::vector<float>& worldVertices, std::vector<int>& worldTriangleIndices)
{
    // Проходим по каждому определению WMO, размещенному на этом ADT
    for (const auto& wmoDef : adtData.modfDefs)
    {
        // 1. Проверяем, обрабатывали ли мы уже этот объект
        if (processedIds.count(wmoDef.uniqueId))
        {
            continue;  // Этот WMO с таким ID уже был построен, пропускаем.
        }

        // 2. Получаем имя файла WMO
        if (wmoDef.nameId >= adtData.wmoPaths.size())
        {
            qWarning(logNavMeshGenerator) << "Invalid WMO nameId:" << wmoDef.nameId;
            continue;
        }
        const std::string& wmoPath = adtData.wmoPaths[wmoDef.nameId];

        // 3. Читаем корневой WMO файл
        std::vector<unsigned char> wmoBuffer;
        if (!m_mpqManager.readFile(wmoPath, wmoBuffer))
        {
            qWarning(logNavMeshGenerator) << "Could not read WMO file:" << QString::fromStdString(wmoPath);
            continue;
        }

        // 4. Создаем fileProvider для парсера, чтобы он мог догружать доп. файлы
        auto fileProvider = [this, &wmoPath](const std::string& filePath) -> std::optional<std::vector<unsigned char>>
        {
            std::string fullPath = filePath;
            if (filePath.find('\\') == std::string::npos && filePath.find('/') == std::string::npos)
            {
                std::string wmoDir;
                const auto last_slash = wmoPath.find_last_of("/\\");
                if (std::string::npos != last_slash)
                {
                    wmoDir = wmoPath.substr(0, last_slash + 1);
                }
                fullPath = wmoDir + filePath;
            }

            std::string pathForMpq = fullPath;
            const auto extPos = pathForMpq.rfind('.');
            if (extPos != std::string::npos)
            {
                if (_stricmp(pathForMpq.c_str() + extPos, ".MDX") == 0 ||
                    _stricmp(pathForMpq.c_str() + extPos, ".MDL") == 0)
                {
                    pathForMpq.replace(extPos, 4, ".M2");
                }
            }

            std::vector<unsigned char> buffer;
            if (m_mpqManager.readFile(pathForMpq, buffer))
            {
                return buffer;
            }
            if (pathForMpq != fullPath)
            {
                if (m_mpqManager.readFile(fullPath, buffer))
                {
                    return buffer;
                }
            }
            return std::nullopt;
        };

        // 5. Парсим WMO
        auto wmoDataOpt = m_wmoParser.parse(wmoPath, wmoBuffer, fileProvider);
        if (!wmoDataOpt)
        {
            qWarning(logNavMeshGenerator) << "Could not parse WMO file:" << QString::fromStdString(wmoPath);
            continue;
        }

        // 6. Трансформация и добавление геометрии с использованием матричного подхода.
        // Этот код основан на примере с wowdev.wiki для MDDF/MODF чанков.
        const auto& wmoData = *wmoDataOpt;
        const size_t vertexOffset = worldVertices.size() / 3;

        // Создаем матрицу трансформации для этого WMO.
        QMatrix4x4 placementMatrix;

        // 1. Преобразуем координаты из Y-up системы ADT в мировую.
        // wowdev: "The position field in MODF is in Y-up coordinate system..."
        // "To get a proper positioning you need to translate those values to world coordinate system
        // by substracting them x and z from 17,066." (17066.666 is 32 * TILE_SIZE)
        // ВАЖНО: position.y из файла - это ВЫСОТА, а не координата на плоскости.
        // Согласно таблице на wowdev, оси в MODF-чанке соответствуют мировым осям следующим образом:
        // MODF Z (North-South)-> World X
        // MODF X (West-East) -> World Y
        // MODF Y (Up)        -> World Z
        const float worldX = MAP_CHUNK_SIZE - wmoDef.position.z;
        const float worldY = MAP_CHUNK_SIZE - wmoDef.position.x;
        const float worldZ = wmoDef.position.y;

        // Порядок вызовов для QMatrix4x4 важен, т.к. она использует post-multiplication.
        // Чтобы получить финальную матрицу World = Translate * Rotate,
        // нужно сначала применить перенос, а затем вращение.

        // 1. Перенос (Translate)
        placementMatrix.translate(worldX, worldY, worldZ);

        // 2. Вращение (Rotate)
        // Углы вращения из файла применяются к соответствующим мировым осям.
        // rotation.y (Yaw)   -> вращение вокруг мировой оси Z (Up)
        // rotation.x (Pitch) -> вращение вокруг мировой оси Y (West-East)
        // rotation.z (Roll)  -> вращение вокруг мировой оси X (North-South)
        placementMatrix.rotate(wmoDef.rotation.y, 0, 0, 1);  // Yaw   вокруг мировой Z
        placementMatrix.rotate(wmoDef.rotation.x, 0, 1, 0);  // Pitch вокруг мировой Y
        placementMatrix.rotate(wmoDef.rotation.z, 1, 0, 0);  // Roll  вокруг мировой X

        // Наконец, применяем эту матрицу ко всем вершинам WMO.
        for (const auto& wmoVert : wmoData.vertices)
        {
            // Сначала преобразуем вершину из локальной системы координат модели WMO в мировую систему.
            // WMO X (N->S) -> World -X
            // WMO Y (W->E) -> World -Y
            // WMO Z (Up)   -> World +Z
            QVector3D vert(-wmoVert.x, -wmoVert.y, wmoVert.z);

            // Затем применяем к ней матрицу трансформации (поворот и перенос).
            QVector3D transformedVert = placementMatrix.map(vert);

            worldVertices.push_back(transformedVert.x());
            worldVertices.push_back(transformedVert.y());
            worldVertices.push_back(transformedVert.z());
        }

        for (int index : wmoData.indices)
        {
            worldTriangleIndices.push_back(static_cast<int>(vertexOffset + index));
        }

        // 7. Помечаем этот ID как обработанный
        processedIds.insert(wmoDef.uniqueId);
    }
}

}  // namespace Processors
}  // namespace NavMesh
