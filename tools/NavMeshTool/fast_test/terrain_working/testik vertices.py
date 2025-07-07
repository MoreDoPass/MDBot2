import os
import re
from dataclasses import dataclass
from ADT.ADTParser import ADTManager, ParsedChunk
import numpy as np

try:
    import pyvista as pv
    PYVISTA_AVAILABLE = True
except ImportError:
    PYVISTA_AVAILABLE = False

# --- Этап 1: Определение констант и базовой структуры ---

# Константа, определяющая размер чанка в мировых координатах.
# В декомпилированном коде это магическое число 33.333332
CHUNK_SIZE = 33.333332
# Центральная точка координатной сетки мира.
ZERO_POINT = 17066.666

class ChunkCalculations:
    """
    Класс для хранения и вычисления координатных данных одного чанка.
    Мы будем добавлять сюда логику шаг за шагом.
    """
    def __init__(self, adt_x, adt_y, chunk_data: ParsedChunk, verbose=True):
        """
        Инициализирует контекст чанка.
        :param adt_x: Координата X тайла ADT (из имени файла, например, 32).
        :param adt_y: Координата Y тайла ADT (из имени файла, например, 32).
        :param chunk_data: Объект ParsedChunk, содержащий все данные, извлеченные из файла.
        :param verbose: Если True, выводить подробную информацию в консоль.
        """
        self.adt_x = adt_x
        self.adt_y = adt_y
        self.verbose = verbose
        
        # --- Распаковываем данные из объекта ParsedChunk ---
        self.grid_x = chunk_data.grid_x
        self.grid_y = chunk_data.grid_y
        self.mcvt_data = chunk_data.mcvt
        self.mcnr_data = chunk_data.mcnr
        self.position = chunk_data.position
        # Это базовая высота чанка, к которой будут добавляться высоты из MCVT
        self.world_z = self.position[2]

        # --- Вычисление глобальных индексов pos_x и pos_y ---
        self.pos_x = (self.adt_x * 16) + self.grid_x
        self.pos_y = (self.adt_y * 16) + self.grid_y
        
        if self.verbose:
            print(f"--- Инициализация чанка ---")
            print(f"  ADT coords: ({adt_x}, {adt_y})")
            print(f"  Grid coords: ({self.grid_x}, {self.grid_y})")
            print(f"  Вычисленные глобальные индексы: pos_x = {self.pos_x}, pos_y = {self.pos_y}")
            print(f"  Базовая позиция из файла (X,Y,Z): ({self.position[0]:.2f}, {self.position[1]:.2f}, {self.position[2]:.2f})")
        
        # --- Переносим первую логику из IDA ---
        self.scaled_y_for_world_x = self.pos_y * CHUNK_SIZE
        self.neighbor_chunk_index_y = self.pos_y + 1
        self.neighbor_chunk_index_x = self.pos_x + 1

        if self.verbose:
            print("\n--- Первые вычисления по логике IDA ---")
            print(f"  scaled_y_for_world_x: {self.scaled_y_for_world_x:.2f}")
            print(f"  neighbor_chunk_index_x: {self.neighbor_chunk_index_x}")
            print(f"  neighbor_chunk_index_y: {self.neighbor_chunk_index_y}")

        # --- Инициализируем кэши ---
        self.VertexYCoordsCache = [0.0] * 9
        self.VertexXCoordsCache = [0.0] * 9

    def _calculate_world_coords_and_cache_grid(self):
        """
        Воссоздает логику вычисления мировых координат и кэширования сетки.
        """
        # --- Вычисляем стартовые мировые координаты угла чанка ---
        # Обратите внимание на инверсию осей: Y мира зависит от X файла, и наоборот.
        final_world_Y = ZERO_POINT - (self.pos_x * CHUNK_SIZE)
        final_world_X = ZERO_POINT - self.scaled_y_for_world_x

        self.VertexYCoordsCache[0] = final_world_Y
        self.VertexXCoordsCache[0] = final_world_X

        # --- БЛОК ПРЕДВЫЧИСЛЕНИЯ КООРДИНАТ СЕТКИ ---
        step = CHUNK_SIZE / 8.0 # 4.1666665
        for i in range(1, 8):
            self.VertexYCoordsCache[i] = final_world_Y - (step * i)
            self.VertexXCoordsCache[i] = final_world_X - (step * i)
            
        # --- Вычисляем координаты для "шва" (стыка с соседями) ---
        self.VertexYCoordsCache[8] = ZERO_POINT - (self.neighbor_chunk_index_x * CHUNK_SIZE)
        self.VertexXCoordsCache[8] = ZERO_POINT - (self.neighbor_chunk_index_y * CHUNK_SIZE)

        if self.verbose:
            print("\n--- Этап 2: Вычисление мировых координат и кэширование сетки ---")
            print(f"  Стартовая мировая Y (Север-Юг): {self.VertexYCoordsCache[0]:.2f}")
            print(f"  Стартовая мировая X (Запад-Восток): {self.VertexXCoordsCache[0]:.2f}")
            print(f"  Координаты сетки Y (первые 3): {[f'{c:.2f}' for c in self.VertexYCoordsCache[:3]]}")
            print(f"  Координаты сетки X (первые 3): {[f'{c:.2f}' for c in self.VertexXCoordsCache[:3]]}")
            print(f"  Координата Y на шве (pos 8): {self.VertexYCoordsCache[8]:.2f}")
            print(f"  Координата X на шве (pos 8): {self.VertexXCoordsCache[8]:.2f}")

    def build_vertices(self):
        """
        Воссоздает основной цикл из IDA для построения финального списка вершин.
        Этот метод имитирует использование указателей на массивы MCVT и MCNR
        для итерации по данным высот и нормалей.
        """
        if not self.VertexYCoordsCache[0]:
            if self.verbose:
                print("ОШИБКА: Кэш координат не инициализирован. Вызовите _calculate_world_coords_and_cache_grid() сначала.")
            return []

        vertices = []
        mcvt_ptr = 0  # Имитация указателя на текущую позицию в данных MCVT
        mcnr_ptr = 0  # Имитация указателя на текущую позицию в данных MCNR

        NORMAL_DIVISOR = 127.0
        step = CHUNK_SIZE / 8.0

        # Основной цикл по 9 столбцам (внешняя сетка)
        for j in range(9):  # j - это column_index, итерация по оси X
            # --- 1. Обработка 9 вершин ВНЕШНЕЙ сетки для текущего столбца ---
            for i in range(9):  # i - итерация по рядам, по оси Y
                world_y = self.VertexYCoordsCache[i]
                world_x = self.VertexXCoordsCache[j]

                # Z-координата = базовая_высота_чанка + относительное_смещение_вершины
                world_z = self.world_z + self.mcvt_data[mcvt_ptr + i]

                # Нормаль. Делим на 127.0 для нормализации в диапазон [-1.0, 1.0]
                nx_byte, ny_byte, nz_byte = self.mcnr_data[mcnr_ptr + i]
                nx = nx_byte / NORMAL_DIVISOR
                ny = ny_byte / NORMAL_DIVISOR
                nz = nz_byte / NORMAL_DIVISOR

                vertices.append({'pos': (world_x, world_y, world_z), 'normal': (nx, ny, nz), 'type': f'outer({j},{i})'})

            # Сдвигаем "указатели" на следующий блок данных
            mcvt_ptr += 9
            mcnr_ptr += 9

            # --- 2. Обработка 8 вершин ВНУТРЕННЕЙ сетки ---
            # Эта сетка существует только для первых 8 столбцов (0-7)
            if j < 8:
                for i in range(8):  # i - итерация по рядам, по оси Y
                    # Координаты вершин внутренней сетки находятся в центре ячеек внешней
                    world_y = self.VertexYCoordsCache[i] - (step / 2.0)
                    world_x = self.VertexXCoordsCache[j] - (step / 2.0)

                    world_z = self.world_z + self.mcvt_data[mcvt_ptr + i]

                    nx_byte, ny_byte, nz_byte = self.mcnr_data[mcnr_ptr + i]
                    nx = nx_byte / NORMAL_DIVISOR
                    ny = ny_byte / NORMAL_DIVISOR
                    ny = nz_byte / NORMAL_DIVISOR

                    vertices.append({'pos': (world_x, world_y, world_z), 'normal': (nx, ny, nz), 'type': f'inner({j},{i})'})

                # Сдвигаем "указатели" после обработки блока внутренней сетки
                mcvt_ptr += 8
                mcnr_ptr += 8
        
        if self.verbose:
            print("\n--- Этап 4: Построение вершин ---")
            print(f"  Всего построено вершин: {len(vertices)} (Ожидалось: 145)")
            print(f"  Пример первой внешней вершины (0,0): pos=({vertices[0]['pos'][0]:.2f}, {vertices[0]['pos'][1]:.2f}, {vertices[0]['pos'][2]:.2f})")
            # Первая внутренняя вершина идет после первых 9 внешних
            print(f"  Пример первой внутренней вершины (0,0): pos=({vertices[9]['pos'][0]:.2f}, {vertices[9]['pos'][1]:.2f}, {vertices[9]['pos'][2]:.2f})")

        return vertices

def visualize_with_pyvista(vertices):
    """
    Визуализирует облако точек вершин с помощью PyVista.
    """
    if not PYVISTA_AVAILABLE:
        print("\n--- Визуализация пропущена ---")
        print("Для визуализации установите PyVista, numpy и pyqt: pip install pyvista numpy pyqt")
        return

    if not vertices:
        print("Нет вершин для визуализации.")
        return

    # --- Подготовка данных для PyVista ---
    points = np.array([v['pos'] for v in vertices])
    
    # Создаем скалярные данные для раскраски: 0 для 'outer', 1 для 'inner'
    scalars = np.array([0 if 'outer' in v['type'] else 1 for v in vertices])
    
    # --- Создание объекта PyVista ---
    point_cloud = pv.PolyData(points)
    point_cloud['PointType'] = scalars

    # --- Настройка и запуск визуализации ---
    plotter = pv.Plotter()
    plotter.add_mesh(
        point_cloud,
        scalars='PointType',
        cmap=['blue', 'red'], # Синий для 'outer', красный для 'inner'
        render_points_as_spheres=True,
        point_size=10,
        show_scalar_bar=False
    )
    plotter.add_text("Визуализация вершин чанка\nСиний=Внешняя сетка, Красный=Внутренняя", position='upper_edge', font_size=12)
    plotter.show_grid()
    print("\n--- Запуск окна PyVista для визуализации... ---")
    plotter.show()

# --- Основной блок для запуска и тестирования ---
if __name__ == '__main__':
    print("--- Запуск пошагового воссоздания логики для ВСЕХ ADT файлов в директории ---")
    
    # --- ЭТАП 1: Инициализация ADTManager ---
    adt_dir = "fast_test/ADT"
    adt_manager = ADTManager(adt_dir)
    all_world_vertices = []

    try:
        adt_files = [f for f in os.listdir(adt_dir) if f.lower().endswith('.adt')]
        if not adt_files:
            raise FileNotFoundError(f"В директории {adt_dir} не найдено .adt файлов.")
            
        print(f"Найдено {len(adt_files)} ADT файлов. Начинаем обработку...")

        # --- ЭТАП 2: Обработка каждого ADT файла в цикле ---
        for adt_filename in adt_files:
            match = re.search(r'_(\d+)_(\d+)\.adt$', adt_filename, re.IGNORECASE)
            if not match:
                print(f"ПРЕДУПРЕЖДЕНИЕ: Не удалось извлечь координаты из имени файла: {adt_filename}. Пропускаем.")
                continue
            
            adt_file_x = int(match.group(1))
            adt_file_y = int(match.group(2))

            print(f"\n--- Обработка файла: {adt_filename} (ADT: {adt_file_x}, {adt_file_y}) ---")

            parser = adt_manager._get_parser(adt_file_x, adt_file_y)
            if not parser or not parser.chunks:
                print(f"ПРЕДУПРЕЖДЕНИЕ: Не удалось получить чанки из {adt_filename}. Пропускаем.")
                continue

            # --- ЭТАП 3: Обработка каждого чанка в ADT ---
            for i, chunk_data in enumerate(parser.chunks):
                if chunk_data is None: continue
                
                # Создаем объект в "тихом" режиме (verbose=False)
                chunk_calc = ChunkCalculations(adt_file_x, adt_file_y, chunk_data, verbose=False)
                chunk_calc._calculate_world_coords_and_cache_grid()
                chunk_vertices = chunk_calc.build_vertices()
                all_world_vertices.extend(chunk_vertices)

        # --- ЭТАП 4: Финальная визуализация всего ---
        print(f"\n\nОбработка всех файлов завершена.")
        print(f"Всего построено вершин для всех ADT: {len(all_world_vertices)}")
        if all_world_vertices:
            visualize_with_pyvista(all_world_vertices)
        else:
            print("Не было построено ни одной вершины.")

    except FileNotFoundError as e:
        print(f"ОШИБКА: {e}")
