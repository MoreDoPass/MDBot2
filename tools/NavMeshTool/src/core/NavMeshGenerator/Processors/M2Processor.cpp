#include "M2Processor.h"
#include "core/MpqManager/MpqManager.h"
#include <QLoggingCategory>
#include <QMatrix4x4>
#include <QVector3D>

Q_DECLARE_LOGGING_CATEGORY(logNavMeshGenerator)

namespace
{
constexpr float TILE_SIZE = 1600.0f / 3.0f;
constexpr float MAP_CHUNK_SIZE = TILE_SIZE * 32.0f;
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

        // Трансформация и добавление геометрии M2 с использованием матричного подхода.
        // Алгоритм полностью основан на рабочем JS-коде, предоставленном пользователем.
        // Ошибка в предыдущих попытках была в неверном порядке применения матричных операций.
        // QMatrix4x4 использует pre-multiplication (M = M_new * M_old), как и glMatrix,
        // поэтому порядок вызовов должен быть идентичен JS-коду.
        const auto& m2Data = *m2DataOpt;
        const size_t vertexOffset = worldVertices.size() / 3;

        const float posx = MAP_CHUNK_SIZE - m2Def.position.x;
        const float posy = m2Def.position.y;
        const float posz = MAP_CHUNK_SIZE - m2Def.position.z;

        QMatrix4x4 placementMatrix;  // Создаем единичную матрицу

        // 1. Начальный поворот для коррекции системы координат
        placementMatrix.rotate(90.0f, 1, 0, 0);  // rotateX
        placementMatrix.rotate(90.0f, 0, 1, 0);  // rotateY

        // 2. Перенос (Translate)
        placementMatrix.translate(posx, posy, posz);

        // 3. Вращения объекта (Roll, Pitch, Yaw)
        placementMatrix.rotate(m2Def.rotation.y - 270.0f, 0, 1, 0);  // rotateY
        placementMatrix.rotate(-m2Def.rotation.x, 0, 0, 1);          // rotateZ
        placementMatrix.rotate(m2Def.rotation.z - 90.0f, 1, 0, 0);   // rotateX

        // 4. Масштабирование (Scale)
        const float scaleFactor = static_cast<float>(m2Def.scale) / 1024.0f;
        placementMatrix.scale(scaleFactor);

        for (const auto& m2Vert : m2Data.vertices)
        {
            // С новой матрицей трансформации вершины, вероятно, не требуют предварительного преобразования.
            QVector3D vert(m2Vert.x, m2Vert.y, m2Vert.z);
            QVector3D transformedVert = placementMatrix.map(vert);

            worldVertices.push_back(transformedVert.x());
            worldVertices.push_back(transformedVert.y());
            worldVertices.push_back(transformedVert.z());
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
