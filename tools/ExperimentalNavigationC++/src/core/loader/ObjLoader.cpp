#include "ObjLoader.h"
#include "shared/Logger.h" // Наш логгер
#include <fstream>         // Для работы с файлами (ifstream)
#include <sstream>         // Для парсинга строк (istringstream)
#include <vector>

// Статическая функция, поэтому она определяется вне класса вот так
MeshData ObjLoader::loadFile(const std::string &filePath) {
  qInfo(lcCore) << "Loading OBJ file with Blender-compatible loader:"
                << QString::fromStdString(filePath);

  MeshData meshData;
  std::ifstream file(filePath);

  if (!file.is_open()) {
    QString errorMsg = QString("Failed to open OBJ file: %1")
                           .arg(QString::fromStdString(filePath));
    qCritical(lcCore) << errorMsg;
    throw std::runtime_error(errorMsg.toStdString());
  }

  std::string line;
  while (std::getline(file, line)) {
    std::istringstream iss(line);
    std::string lineHeader;
    iss >> lineHeader;

    if (lineHeader == "v") {
      Vector3d vertex;
      if (!(iss >> vertex.x() >> vertex.y() >> vertex.z())) {
        qWarning(lcCore) << "Malformed vertex line, skipping:"
                         << QString::fromStdString(line);
        continue;
      }
      meshData.vertices.push_back(vertex);

    } else if (lineHeader == "f") {
      // --- Используем робастный парсер с триангуляцией, который мы уже делали,
      // --- но с исправленным чтением токена.
      std::vector<int> face_vertex_indices;
      std::string face_token;

      while (iss >> face_token) {
        try {
          // ===================================================================
          // === ИСПРАВЛЕНИЕ ЗДЕСЬ: Ручной парсинг формата "v/vt/vn"       ===
          // ===================================================================
          // 1. Находим позицию первого слэша '/'
          size_t slash_pos = face_token.find('/');

          // 2. Если слэш найден, мы берем подстроку от начала до него.
          std::string vertex_index_str = (slash_pos != std::string::npos)
                                             ? face_token.substr(0, slash_pos)
                                             : face_token;

          // 3. Преобразуем эту "чистую" строку в число.
          //    Индексы в .obj начинаются с 1, а в C++ с 0, поэтому вычитаем 1.
          face_vertex_indices.push_back(std::stoi(vertex_index_str) - 1);

        } catch (const std::exception &e) {
          qWarning(lcCore) << "Invalid face index format, skipping face:"
                           << QString::fromStdString(line)
                           << "Token:" << QString::fromStdString(face_token);
          face_vertex_indices.clear();
          break;
        }
      }

      // Триангулируем полигон "веером", если в нем 3 или больше вершин.
      if (face_vertex_indices.size() >= 3) {
        const int first_vertex_index = face_vertex_indices[0];
        for (size_t i = 1; i < face_vertex_indices.size() - 1; ++i) {
          meshData.indices.push_back({first_vertex_index,
                                      face_vertex_indices[i],
                                      face_vertex_indices[i + 1]});
        }
      }
    }
    // Другие типы строк (vn, l, o, mtllib и т.д.) мы просто игнорируем.
  }

  file.close();

  qInfo(lcCore) << "OBJ file loaded successfully. Vertices:"
                << meshData.vertices.size()
                << ", Triangles (after triangulation):"
                << meshData.indices.size();

  return meshData;
}