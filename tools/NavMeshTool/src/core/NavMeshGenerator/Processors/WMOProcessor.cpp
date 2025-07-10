#include "WMOProcessor.h"
#include "core/MpqManager/MpqManager.h"
#include <QLoggingCategory>

// Объявляем, что будем использовать эту категорию.
// Само определение находится в NavMeshGenerator.cpp
Q_DECLARE_LOGGING_CATEGORY(logNavMeshGenerator)

namespace
{
// Константы для расчетов. Можно было бы вынести в общее место, но пока оставим здесь.
constexpr float TILE_SIZE = 1600.0f / 3.0f;
constexpr float MAP_CHUNK_SIZE = TILE_SIZE * 32.0f;
constexpr float PI = 3.1415926535f;

// Вспомогательная структура для 3D-вектора
struct Vec3
{
    float x, y, z;
};
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

        // 6. Трансформация и добавление геометрии
        const auto& wmoData = *wmoDataOpt;
        const size_t vertexOffset = worldVertices.size() / 3;

        const float posX = MAP_CHUNK_SIZE - wmoDef.position.y;
        const float posY = MAP_CHUNK_SIZE - wmoDef.position.x;
        const float posZ = wmoDef.position.z;

        const float rotX_rad = wmoDef.rotation.y * (PI / 180.0f);
        const float rotY_rad = wmoDef.rotation.z * (PI / 180.0f);
        const float rotZ_rad = wmoDef.rotation.x * (PI / 180.0f);

        for (const auto& wmoVert : wmoData.vertices)
        {
            Vec3 vert = {-wmoVert.y, -wmoVert.x, wmoVert.z};

            float newX = vert.x * cos(rotZ_rad) - vert.y * sin(rotZ_rad);
            float newY = vert.x * sin(rotZ_rad) + vert.y * cos(rotZ_rad);
            vert.x = newX;
            vert.y = newY;

            newX = vert.x * cos(rotY_rad) + vert.z * sin(rotY_rad);
            float newZ = -vert.x * sin(rotY_rad) + vert.z * cos(rotY_rad);
            vert.x = newX;
            vert.z = newZ;

            newY = vert.y * cos(rotX_rad) - vert.z * sin(rotX_rad);
            newZ = vert.y * sin(rotX_rad) + vert.z * cos(rotX_rad);
            vert.y = newY;
            vert.z = newZ;

            worldVertices.push_back(vert.x + posX);
            worldVertices.push_back(vert.y + posY);
            worldVertices.push_back(vert.z + posZ);
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
