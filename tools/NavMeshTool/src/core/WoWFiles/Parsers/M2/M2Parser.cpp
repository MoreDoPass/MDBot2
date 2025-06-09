#include "M2Parser.h"

#include <QLoggingCategory>

#include <cstring>
#include <string>
#include <vector>

Q_LOGGING_CATEGORY(logM2Parser, "navmesh.m2parser")

namespace NavMeshTool::M2
{

std::optional<CollisionGeometry> Parser::parse(const std::vector<unsigned char>& dataBuffer) const
{
    if (dataBuffer.size() < sizeof(M2Header))
    {
        qCWarning(logM2Parser) << "Buffer size is too small for an M2 header. Size:" << dataBuffer.size();
        return std::nullopt;
    }

    const unsigned char* currentPtr = dataBuffer.data();
    const size_t totalSize = dataBuffer.size();

    M2Header header;
    memcpy(&header, currentPtr, sizeof(header));

    if (std::string(header.magic, 4) != "MD20")
    {
        qCWarning(logM2Parser) << "Invalid M2 magic.";
        return std::nullopt;
    }

    if (header.version != 264)
    {
        qCWarning(logM2Parser) << "Unsupported M2 version" << header.version;
        return std::nullopt;
    }

    CollisionGeometry geom;

    if (header.num_collision_vertices > 0 && header.offset_collision_vertices > 0)
    {
        size_t verticesSize = header.num_collision_vertices * sizeof(C3Vector);
        if (header.offset_collision_vertices + verticesSize > totalSize)
        {
            qCWarning(logM2Parser) << "Collision vertices data is out of bounds.";
            return std::nullopt;
        }
        geom.vertices.resize(header.num_collision_vertices);
        memcpy(geom.vertices.data(), currentPtr + header.offset_collision_vertices, verticesSize);
    }

    if (header.num_collision_indices > 0 && header.offset_collision_indices > 0)
    {
        size_t indicesSize = header.num_collision_indices * sizeof(uint16_t);
        if (header.offset_collision_indices + indicesSize > totalSize)
        {
            qCWarning(logM2Parser) << "Collision indices data is out of bounds.";
            return std::nullopt;
        }
        geom.indices.resize(header.num_collision_indices);
        memcpy(geom.indices.data(), currentPtr + header.offset_collision_indices, indicesSize);
    }

    if (header.num_collision_normals > 0 && header.offset_collision_normals > 0)
    {
        size_t normalsSize = header.num_collision_normals * sizeof(C3Vector);
        if (header.offset_collision_normals + normalsSize > totalSize)
        {
            qCWarning(logM2Parser) << "Collision normals data is out of bounds.";
            return std::nullopt;
        }
        geom.normals.resize(header.num_collision_normals);
        memcpy(geom.normals.data(), currentPtr + header.offset_collision_normals, normalsSize);
    }

    qCDebug(logM2Parser) << "Successfully parsed M2 buffer. Vertices:" << geom.vertices.size()
                         << "Indices:" << geom.indices.size() << "Normals:" << geom.normals.size();

    return geom;
}

}  // namespace NavMeshTool::M2
