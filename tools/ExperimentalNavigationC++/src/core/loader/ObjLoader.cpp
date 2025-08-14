#include "ObjLoader.h"
#include "shared/Logger.h" // Наш логгер
#include <fstream>         // Для работы с файлами (ifstream)
#include <sstream>         // Для парсинга строк (istringstream)

// Статическая функция, поэтому она определяется вне класса вот так
MeshData ObjLoader::loadFile(const std::string &filePath) {
  qInfo(lcCore) << "Loading OBJ file with custom loader:"
                << QString::fromStdString(filePath);

  MeshData meshData;
  std::ifstream file(filePath);

  // --- Обработка ошибок: Проверяем, открылся ли файл ---
  if (!file.is_open()) {
    QString errorMsg = QString("Failed to open OBJ file: %1")
                           .arg(QString::fromStdString(filePath));
    qCritical(lcCore) << errorMsg;
    throw std::runtime_error(errorMsg.toStdString());
  }

  std::string line;
  // Читаем файл построчно
  while (std::getline(file, line)) {
    // Используем istringstream для легкого парсинга строки
    std::istringstream iss(line);
    std::string lineHeader;
    iss >> lineHeader; // Читаем первое слово в строке (v, f, vn, vt...)

    if (lineHeader == "v") {
      // --- Это вершина (vertex) ---
      Vector3d vertex;
      // Читаем 3 числа типа double и записываем их в наш вектор
      if (!(iss >> vertex.x() >> vertex.y() >> vertex.z())) {
        qWarning(lcCore) << "Malformed vertex line, skipping:"
                         << QString::fromStdString(line);
        continue;
      }
      meshData.vertices.push_back(vertex);

    } else if (lineHeader == "f") {
      // --- Это грань (face) ---
      std::array<int, 3> face_indices;
      bool success = true;

      // Проходим по трем индексам грани
      for (int i = 0; i < 3; ++i) {
        std::string face_token;
        if (!(iss >> face_token)) {
          qWarning(lcCore)
              << "Malformed face line (not enough vertices), skipping:"
              << QString::fromStdString(line);
          success = false;
          break;
        }

        try {
          // Индексы в .obj начинаются с 1, а в C++ с 0, поэтому вычитаем 1
          // Мы используем std::stoi и substr, чтобы отрезать все после '/',
          // например из "123/45/67" мы получим "123", а потом 122.
          face_indices[i] = std::stoi(face_token) - 1;
        } catch (const std::invalid_argument &ia) {
          qWarning(lcCore) << "Invalid face index, skipping line:"
                           << QString::fromStdString(line);
          success = false;
          break;
        }
      }

      if (success) {
        meshData.indices.push_back(face_indices);
      }

      // Игнорируем четвертую вершину, если полигон четырехугольный.
      // Наш NavMesh все равно будет работать с треугольниками.
    }
    // Другие типы строк (vn, vt, #, и т.д.) мы просто игнорируем.
  }

  file.close();

  qInfo(lcCore) << "OBJ file loaded successfully. Vertices:"
                << meshData.vertices.size()
                << ", Triangles:" << meshData.indices.size();

  return meshData;
}