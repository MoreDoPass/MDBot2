"""
Скрипт для визуализации 3D геометрии чанков World of Warcraft.

Этот скрипт находит файлы 'all_vertices.bin' и 'all_indices.bin',
сгенерированные скриптом Stalker_Together.py, загружает их и строит
из них единый 3D-меш с помощью библиотеки PyVista.

Требования:
- numpy: pip install numpy
- pyvista: pip install pyvista
- pyqt5: pip install pyqt5 (для бэкенда рендеринга)
"""
import os
import glob
import numpy as np
import pyvista as pv

# Каждая вершина состоит из 6 чисел float32 (pos_x, pos_y, pos_z, norm_x, norm_y, norm_z)
VERTEX_SIZE_FLOATS = 6
VERTEX_DTYPE = np.float32
INDEX_DTYPE = np.uint16

def load_data(script_dir):
    """
    Загружает бинарные файлы с вершинами и индексами.

    Args:
        script_dir (str): Директория, в которой находятся файлы.

    Returns:
        (np.ndarray, np.ndarray)|(None, None): Кортеж из (массив вершин, массив индексов) или (None, None) в случае ошибки.
    """
    vertices_path = os.path.join(script_dir, 'all_vertices.bin')
    indices_path = os.path.join(script_dir, 'all_indices.bin')

    if not os.path.exists(vertices_path) or not os.path.exists(indices_path):
        print(f"Не найдены файлы 'all_vertices.bin' и/или 'all_indices.bin' в директории {script_dir}")
        print("Сначала запустите Stalker_Together.py и сгенерируйте данные, "
              "пройдясь по миру в игре.")
        return None, None

    try:
        # Загружаем вершины
        print(f"Загрузка вершин из {vertices_path}...")
        vertices_binary = np.fromfile(vertices_path, dtype=VERTEX_DTYPE)
        if vertices_binary.size % VERTEX_SIZE_FLOATS != 0:
            print(f"[!] Файл вершин поврежден. Размер ({vertices_binary.size}) не кратен {VERTEX_SIZE_FLOATS}.")
            return None, None
        all_vertices = vertices_binary.reshape(-1, VERTEX_SIZE_FLOATS)

        # Загружаем индексы
        print(f"Загрузка индексов из {indices_path}...")
        all_indices = np.fromfile(indices_path, dtype=INDEX_DTYPE)
        if all_indices.size % 3 != 0:
            print(f"[!] Файл индексов поврежден. Количество ({all_indices.size}) не кратно 3.")
            return None, None

        return all_vertices, all_indices

    except Exception as e:
        print(f"[!] Ошибка при загрузке файлов: {e}")
        return None, None

def main():
    """
    Основная функция для поиска, загрузки и визуализации данных.
    """
    try:
        script_dir = os.path.dirname(__file__)
        all_vertices, all_indices = load_data(script_dir)
        
        if all_vertices is None or all_indices is None:
            print("Не удалось загрузить данные. Завершение.")
            return
            
        print(f"Всего загружено {all_vertices.shape[0]} вершин и {all_indices.shape[0]} индексов ({all_indices.shape[0] // 3} треугольников).")

        # Разделяем данные на координаты точек и векторы нормалей
        points = all_vertices[:, 0:3]
        
        # --- ВАЖНЫЙ ШАГ: Исправление системы координат ---
        # Как мы выяснили ранее, игра хранит Y, X, Z. PyVista ждет X, Y, Z.
        # Меняем местами первые два столбца.
        points_corrected = points[:, [1, 0, 2]]
        
        # --- Подготовка индексов для PyVista ---
        # PyVista ожидает массив вида [3, i0, i1, i2, 3, i3, i4, i5, ...],
        # где '3' - количество вершин в полигоне (треугольнике).
        num_triangles = all_indices.size // 3
        # Создаем массив из троек, который будет вставлен перед каждой группой индексов.
        prefix = np.full((num_triangles, 1), 3, dtype=INDEX_DTYPE)
        # Меняем форму массива индексов, чтобы его можно было склеить с префиксом.
        indices_reshaped = all_indices.reshape(num_triangles, 3)
        # Склеиваем и выравниваем в один длинный массив.
        faces = np.hstack((prefix, indices_reshaped)).flatten()
        
        # Создаем объект PolyData, который является контейнером для геометрии в PyVista
        mesh = pv.PolyData(points_corrected, faces=faces)
        
        # Настраиваем и запускаем визуализацию
        plotter = pv.Plotter(window_size=[1600, 1000])
        plotter.set_background('black')
        
        # Добавляем меш на сцену, показывая ребра для наглядности
        plotter.add_mesh(mesh, show_edges=True, color='cyan', edge_color='blue')
        
        plotter.add_axes()
        plotter.show_grid()
        
        print("\nОкно визуализации открыто. Закройте его, чтобы завершить скрипт.")
        plotter.show()
        print("Скрипт завершен.")

    except ImportError:
        print("[!!!] КРИТИЧЕСКАЯ ОШИБКА [!!!]")
        print("Библиотека 'pyvista' или 'numpy' не установлена.")
        print("Пожалуйста, установите их, выполнив в терминале:")
        print("pip install numpy pyvista pyqt5")
    except Exception as e:
        print(f"Произошла непредвиденная ошибка: {e}")

if __name__ == '__main__':
    main()
