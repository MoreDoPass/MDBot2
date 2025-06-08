#include "M2Parser.h"

#include <QLoggingCategory>

#include <fstream>
#include <string>
#include <vector>

Q_LOGGING_CATEGORY(logM2Parser, "navmesh.m2parser")

namespace NavMeshTool::M2
{

std::optional<CollisionGeometry> Parser::parse(const std::string& file_path) const
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
    {
        qCWarning(logM2Parser) << "Could not open file:" << QString::fromStdString(file_path);
        return std::nullopt;
    }

    M2Header header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (file.gcount() != sizeof(header))
    {
        qCWarning(logM2Parser) << "Could not read M2 header from file:" << QString::fromStdString(file_path);
        return std::nullopt;
    }

    if (std::string(header.magic, 4) != "MD20")
    {
        qCWarning(logM2Parser) << "Invalid M2 magic in file:" << QString::fromStdString(file_path);
        return std::nullopt;
    }

    if (header.version != 264)
    {
        qCWarning(logM2Parser) << "Unsupported M2 version" << header.version
                               << "in file:" << QString::fromStdString(file_path);
        return std::nullopt;
    }

    CollisionGeometry geom;

    if (header.num_collision_vertices > 0 && header.offset_collision_vertices > 0)
    {
        geom.vertices.resize(header.num_collision_vertices);
        file.seekg(header.offset_collision_vertices);
        file.read(reinterpret_cast<char*>(geom.vertices.data()), header.num_collision_vertices * sizeof(C3Vector));
        if (file.gcount() != static_cast<std::streamsize>(header.num_collision_vertices * sizeof(C3Vector)))
        {
            qCWarning(logM2Parser) << "Could not read collision vertices from file:"
                                   << QString::fromStdString(file_path);
            return std::nullopt;
        }
    }

    if (header.num_collision_indices > 0 && header.offset_collision_indices > 0)
    {
        geom.indices.resize(header.num_collision_indices);
        file.seekg(header.offset_collision_indices);
        file.read(reinterpret_cast<char*>(geom.indices.data()), header.num_collision_indices * sizeof(uint16_t));
        if (file.gcount() != static_cast<std::streamsize>(header.num_collision_indices * sizeof(uint16_t)))
        {
            qCWarning(logM2Parser) << "Could not read collision indices from file:"
                                   << QString::fromStdString(file_path);
            return std::nullopt;
        }
    }

    if (header.num_collision_normals > 0 && header.offset_collision_normals > 0)
    {
        geom.normals.resize(header.num_collision_normals);
        file.seekg(header.offset_collision_normals);
        file.read(reinterpret_cast<char*>(geom.normals.data()), header.num_collision_normals * sizeof(C3Vector));
        if (file.gcount() != static_cast<std::streamsize>(header.num_collision_normals * sizeof(C3Vector)))
        {
            qCWarning(logM2Parser) << "Could not read collision normals from file:"
                                   << QString::fromStdString(file_path);
            return std::nullopt;
        }
    }

    qCDebug(logM2Parser) << "Successfully parsed M2 file:" << QString::fromStdString(file_path)
                         << "Vertices:" << geom.vertices.size() << "Indices:" << geom.indices.size()
                         << "Normals:" << geom.normals.size();

    return geom;
}

}  // namespace NavMeshTool::M2
