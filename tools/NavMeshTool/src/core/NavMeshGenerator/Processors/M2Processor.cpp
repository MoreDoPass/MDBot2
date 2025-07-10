#include "M2Processor.h"
#include "core/MpqManager/MpqManager.h"
#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(logNavMeshGenerator)

namespace
{
constexpr float TILE_SIZE = 1600.0f / 3.0f;
constexpr float MAP_CHUNK_SIZE = TILE_SIZE * 32.0f;
constexpr float PI = 3.1415926535f;

struct Vec3
{
    float x, y, z;
};
}  // namespace

namespace NavMesh
{
namespace Processors
{

M2Processor::M2Processor(MpqManager& mpqManager) : m_mpqManager(mpqManager) {}

void M2Processor::process(const NavMeshTool::ADT::ADTData& adtData, std::unordered_set<uint32_t>& processedIds,
                          std::vector<float>& worldVertices, std::vector<int>& worldTriangleIndices)
{
    for (const auto& m2Def : adtData.mddfDefs)
    {
        if (processedIds.count(m2Def.uniqueId))
        {
            continue;
        }

        if (m2Def.nameId >= adtData.doodadPaths.size())
        {
            qWarning(logNavMeshGenerator) << "Invalid M2 nameId:" << m2Def.nameId;
            continue;
        }
        const std::string& m2Path = adtData.doodadPaths[m2Def.nameId];

        std::string pathForMpq = m2Path;
        const auto extPos = pathForMpq.rfind('.');
        if (extPos != std::string::npos)
        {
            if (_stricmp(pathForMpq.c_str() + extPos, ".MDX") == 0 ||
                _stricmp(pathForMpq.c_str() + extPos, ".MDL") == 0)
            {
                pathForMpq.replace(extPos, 4, ".M2");
            }
        }

        std::vector<unsigned char> m2Buffer;
        if (!m_mpqManager.readFile(pathForMpq, m2Buffer))
        {
            if (pathForMpq != m2Path && m_mpqManager.readFile(m2Path, m2Buffer))
            {
            }
            else
            {
                qWarning(logNavMeshGenerator) << "Could not read M2 file:" << QString::fromStdString(m2Path)
                                              << "(tried as" << QString::fromStdString(pathForMpq) << ")";
                continue;
            }
        }

        auto m2DataOpt = m_m2Parser.parse(m2Buffer);
        if (!m2DataOpt)
        {
            qWarning(logNavMeshGenerator) << "Could not parse M2 file:" << QString::fromStdString(pathForMpq);
            continue;
        }

        const auto& m2Data = *m2DataOpt;
        const size_t vertexOffset = worldVertices.size() / 3;

        const float posX = MAP_CHUNK_SIZE - m2Def.position.y;
        const float posY = MAP_CHUNK_SIZE - m2Def.position.x;
        const float posZ = m2Def.position.z;

        const float rotX_rad = m2Def.rotation.y * (PI / 180.0f);
        const float rotY_rad = m2Def.rotation.z * (PI / 180.0f);
        const float rotZ_rad = m2Def.rotation.x * (PI / 180.0f);

        const float scaleFactor = static_cast<float>(m2Def.scale) / 1024.0f;

        for (const auto& m2Vert : m2Data.vertices)
        {
            Vec3 vert = {-m2Vert.y, -m2Vert.x, m2Vert.z};

            vert.x *= scaleFactor;
            vert.y *= scaleFactor;
            vert.z *= scaleFactor;

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

        for (int index : m2Data.indices)
        {
            worldTriangleIndices.push_back(static_cast<int>(vertexOffset + index));
        }

        processedIds.insert(m2Def.uniqueId);
    }
}

}  // namespace Processors
}  // namespace NavMesh
