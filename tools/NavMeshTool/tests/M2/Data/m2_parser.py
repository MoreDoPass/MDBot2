import os
import struct
import glob
import random # Добавлено для выбора случайного файла
import numpy as np # Добавлено для работы с массивами вершин
import pyvista as pv # Добавлено для визуализации

# Конкретный список файлов, которые мы хотим проанализировать
TARGET_FILES = [
    "frostwyrm_waterfall.m2",
    "Azjol_EggTower_01.M2",
    "DurotarTree01.M2",
    "Azjol_EggSacks_01.M2",
    "nexus_ice_conduit_FALSE.M2"
]

# Сопоставление смещений в M2Header с именами полей
# Оставляем только те, что нужны для collision_indices + model_name для идентификации
M2_HEADER_FIELDS = [
    ('magic', '4s', 0x00),             # "MD20" - оставим для быстрой проверки типа файла
    ('version', 'I', 0x04),           # 264 - оставим для контекста
    ('length_model_name', 'I', 0x08),
    ('offset_model_name', 'I', 0x0C),

    # ('model_flags', 'I', 0x10),
    # ('nGlobalSequences', 'I', 0x14),
    # ('ofsGlobalSequences', 'I', 0x18),
    # ('nAnimations', 'I', 0x1C),
    # ('ofsAnimations', 'I', 0x20),
    # ('nAnimationLookup', 'I', 0x24),
    # ('ofsAnimationLookup', 'I', 0x28),
    # ('nBones', 'I', 0x2C),
    # ('ofsBones', 'I', 0x30),
    # ('nKeyBoneLookup', 'I', 0x34),
    # ('ofsKeyBoneLookup', 'I', 0x38),
    # ('nVertices', 'I', 0x3C),
    # ('ofsVertices', 'I', 0x40),
    # ('nViews', 'I', 0x44),
    # ('nColors', 'I', 0x48),
    # ('ofsColors', 'I', 0x4C),
    # ('nTextures', 'I', 0x50),
    # ('ofsTextures', 'I', 0x54),
    # ('nTransparency', 'I', 0x58),
    # ('ofsTransparency', 'I', 0x5C),
    # ('nTexAnims', 'I', 0x60),
    # ('ofsTexAnims', 'I', 0x64),
    # ('nTexReplace', 'I', 0x68),
    # ('ofsTexReplace', 'I', 0x6C),
    # ('nMaterials', 'I', 0x70),
    # ('ofsMaterials', 'I', 0x74),
    # ('nBoneCombos', 'I', 0x78),
    # ('ofsBoneCombos', 'I', 0x7C),
    # ('nTextureCombos', 'I', 0x80),
    # ('ofsTextureCombos', 'I', 0x84),
    # ('nTexCoordCombos', 'I', 0x88),
    # ('ofsTexCoordCombos', 'I', 0x8C),
    # ('nTransparencyLookup', 'I', 0x90),
    # ('ofsTransparencyLookup', 'I', 0x94),
    # ('nTexAnimLookup', 'I', 0x98),
    # ('ofsTexAnimLookup', 'I', 0x9C),
    # ('bounding_box', '6f', 0xA0),
    # ('bounding_sphere_radius', 'f', 0xB8),
    # ('collision_box', '6f', 0xBC),
    # ('collision_sphere_radius', 'f', 0xD4),

    ('nCollisionIndices', 'I', 0xD8),
    ('ofsCollisionIndices', 'I', 0xDC),
    ('nCollisionVertices', 'I', 0xE0), # Оставим для контекста, т.к. индексы на них ссылаются
    ('ofsCollisionVertices', 'I', 0xE4),
    ('nCollisionNormals', 'I', 0xE8),   # Оставим для контекста
    ('ofsCollisionNormals', 'I', 0xEC),

    # ('nAttachments', 'I', 0xF0),
    # ('ofsAttachments', 'I', 0xF4),
    # ('nAttachLookup', 'I', 0xF8),
    # ('ofsAttachLookup', 'I', 0xFC),
    # ('nEvents', 'I', 0x100),
    # ('ofsEvents', 'I', 0x104)
]

M2_HEADER_SIZE = 0x108 # 264 bytes for WotLK

def parse_m2_header(file_path):
    """Читает заголовок M2, данные collisionIndices, collisionVertices и collisionNormals."""
    parsed_info = {'file_name': os.path.basename(file_path)}
    try:
        with open(file_path, 'rb') as f:
            header_bytes = f.read(M2_HEADER_SIZE)
            if len(header_bytes) < M2_HEADER_SIZE:
                parsed_info['error'] = f"Файл слишком мал для полного заголовка M2 ({len(header_bytes)} байт)."
                return parsed_info

            # Читаем поля заголовка, которые мы оставили
            for name, fmt, offset in M2_HEADER_FIELDS:
                if offset + struct.calcsize(fmt) <= len(header_bytes):
                    values = struct.unpack_from(f'<{fmt}', header_bytes, offset)
                    parsed_info[name] = values[0] if len(values) == 1 else values
                else:
                    parsed_info[name] = None # Поле не удалось прочитать

            # Читаем имя модели (оставили в M2_HEADER_FIELDS)
            model_name = ""
            length_model_name = parsed_info.get('length_model_name', 0)
            offset_model_name = parsed_info.get('offset_model_name', 0)

            if length_model_name > 0 and offset_model_name > 0:
                # Логика чтения имени (упрощенная, т.к. фокус не на ней)
                f.seek(offset_model_name)
                model_name_bytes = f.read(length_model_name)
                model_name = model_name_bytes.partition(b'\\x00')[0].decode('utf-8', errors='ignore')
            parsed_info['model_name_processed'] = model_name

            # Читаем collisionIndices
            n_coll_indices = parsed_info.get('nCollisionIndices', 0)
            ofs_coll_indices = parsed_info.get('ofsCollisionIndices', 0)
            parsed_info['collision_indices_data'] = []
            file_size = os.fstat(f.fileno()).st_size

            if n_coll_indices > 0 and ofs_coll_indices > 0 and ofs_coll_indices < file_size:
                f.seek(ofs_coll_indices)
                # Каждый индекс - это uint16_t (2 байта)
                indices_bytes_to_read = n_coll_indices * 2
                indices_data_bytes = f.read(indices_bytes_to_read)
                
                if len(indices_data_bytes) == indices_bytes_to_read:
                    # Распаковываем все индексы
                    # Формат '<' + 'H'*n_coll_indices означает little-endian, n_coll_indices раз uint16_t
                    parsed_info['collision_indices_data'] = list(struct.unpack(f'<{n_coll_indices}H', indices_data_bytes))
                else:
                    parsed_info['error'] = (parsed_info.get('error', "") +
                                           f" Не удалось прочитать все collision_indices: ожидалось {indices_bytes_to_read} байт, получено {len(indices_data_bytes)}.").strip()
            elif n_coll_indices > 0 and (ofs_coll_indices == 0 or ofs_coll_indices >= file_size):
                 parsed_info['error'] = (parsed_info.get('error', "") +
                                           f" ofsCollisionIndices ({hex(ofs_coll_indices)}) некорректен или выходит за пределы файла ({hex(file_size)}).").strip()

            # Читаем collisionVertices
            n_coll_vertices = parsed_info.get('nCollisionVertices', 0)
            ofs_coll_vertices = parsed_info.get('ofsCollisionVertices', 0)
            parsed_info['collision_vertices_data'] = []

            if n_coll_vertices > 0 and ofs_coll_vertices > 0 and ofs_coll_vertices < file_size:
                f.seek(ofs_coll_vertices)
                vertices_bytes_to_read = n_coll_vertices * 12 # 3 floats * 4 bytes/float
                vertices_data_bytes = f.read(vertices_bytes_to_read)
                if len(vertices_data_bytes) == vertices_bytes_to_read:
                    temp_vertices = []
                    for i in range(n_coll_vertices):
                        vertex_tuple = struct.unpack_from('<fff', vertices_data_bytes, i * 12)
                        temp_vertices.append(vertex_tuple)
                    parsed_info['collision_vertices_data'] = temp_vertices
                else:
                    parsed_info['error'] = (parsed_info.get('error', "") +
                                           f" Не удалось прочитать все collision_vertices: ожидалось {vertices_bytes_to_read}, получено {len(vertices_data_bytes)}.").strip()
            elif n_coll_vertices > 0 and (ofs_coll_vertices == 0 or ofs_coll_vertices >= file_size):
                 parsed_info['error'] = (parsed_info.get('error', "") +
                                           f" ofsCollisionVertices ({hex(ofs_coll_vertices)}) некорректен или выходит за пределы файла ({hex(file_size)}).").strip()

            # Читаем collisionNormals
            n_coll_normals = parsed_info.get('nCollisionNormals', 0)
            ofs_coll_normals = parsed_info.get('ofsCollisionNormals', 0)
            parsed_info['collision_normals_data'] = []
            if n_coll_normals > 0 and ofs_coll_normals > 0 and ofs_coll_normals < file_size:
                f.seek(ofs_coll_normals)
                normals_bytes_to_read = n_coll_normals * 12 # 3 floats * 4 bytes/float
                normals_data_bytes = f.read(normals_bytes_to_read)
                if len(normals_data_bytes) == normals_bytes_to_read:
                    temp_normals = []
                    for i in range(n_coll_normals):
                        normal_tuple = struct.unpack_from('<fff', normals_data_bytes, i * 12)
                        temp_normals.append(normal_tuple)
                    parsed_info['collision_normals_data'] = temp_normals
                else:
                    parsed_info['error'] = (parsed_info.get('error', "") +
                                           f" Не удалось прочитать все collision_normals: ожидалось {normals_bytes_to_read}, получено {len(normals_data_bytes)}.").strip()
            elif n_coll_normals > 0 and (ofs_coll_normals == 0 or ofs_coll_normals >= file_size):
                 parsed_info['error'] = (parsed_info.get('error', "") +
                                           f" ofsCollisionNormals ({hex(ofs_coll_normals)}) некорректен или выходит за пределы файла ({hex(file_size)}).").strip()

            return parsed_info

    except FileNotFoundError:
        parsed_info['error'] = "Файл не найден."
        return parsed_info
    except Exception as e:
        parsed_info['error'] = f"Ошибка при чтении: {e}"
        return parsed_info

def visualize_collision_mesh(vertices, indices):
    """Визуализирует коллизионную сетку с помощью PyVista."""
    if not vertices or not indices:
        print("Нет данных для визуализации (вершины или индексы отсутствуют).")
        return

    # Преобразуем вершины в numpy массив (PyVista это любит)
    verts_np = np.array(vertices)

    # Преобразуем индексы треугольников в формат PyVista
    # PyVista ожидает [3, i0, i1, i2, 3, i3, i4, i5, ...]
    num_triangles = len(indices) // 3
    faces = np.full((num_triangles, 4), 3, dtype=int)
    faces[:, 1:] = np.array(indices).reshape(num_triangles, 3)
    faces = faces.flatten()

    # Создаем PolyData объект
    mesh = pv.PolyData(verts_np, faces=faces)

    # Создаем плоттер и отображаем
    plotter = pv.Plotter()
    plotter.add_mesh(mesh, show_edges=True, color='lightgrey')
    plotter.add_axes()
    plotter.camera_position = 'iso'
    print("Отображение 3D модели коллизий. Закройте окно PyVista, чтобы продолжить...")
    plotter.show()

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    m2_files = glob.glob(os.path.join(current_dir, '*.m2'))
    m2_files_upper = glob.glob(os.path.join(current_dir, '*.M2'))
    all_m2_files = sorted(list(set(m2_files + m2_files_upper)))

    if not all_m2_files:
        print("M2 файлы не найдены в текущей директории.")
    else:
        # Выбираем один случайный файл
        selected_m2_file_path = random.choice(all_m2_files)
        print(f"Выбран случайный M2 файл для анализа: {os.path.basename(selected_m2_file_path)}\n")

        result = parse_m2_header(selected_m2_file_path)
        print(f"--- Анализ файла: {result.get('file_name', os.path.basename(selected_m2_file_path))} ---")
        
        if 'error' in result and result['error']:
            print(f"  Ошибка: {result['error']}")
            for key, value in result.items():
                if key not in ['file_name', 'error', 'collision_indices_data', 'collision_vertices_data', 'collision_normals_data']:
                    display_name = key.replace('_', ' ').title()
                    val_to_print = hex(value) if isinstance(value, int) and ('Ofs' in key or 'offset' in key or 'flags' in key.lower()) else value
                    if key == 'version' and isinstance(value, int): val_to_print = value
                    if key == 'magic' and isinstance(value, bytes): val_to_print = value.decode('utf-8', 'ignore')
                    print(f"  {display_name}: {val_to_print}")
        
        model_name = result.get('model_name_processed', 'N/A')
        print(f"  Model Name: '{model_name}'")
        
        n_coll_indices = result.get('nCollisionIndices')
        ofs_coll_indices = result.get('ofsCollisionIndices')
        
        print(f"  nCollisionIndices: {n_coll_indices if n_coll_indices is not None else 'N/A'}")
        print(f"  ofsCollisionIndices: {hex(ofs_coll_indices) if ofs_coll_indices is not None else 'N/A'}")

        n_coll_vertices = result.get('nCollisionVertices')
        ofs_coll_vertices = result.get('ofsCollisionVertices')
        print(f"  nCollisionVertices: {n_coll_vertices if n_coll_vertices is not None else 'N/A'}")
        print(f"  ofsCollisionVertices: {hex(ofs_coll_vertices) if ofs_coll_vertices is not None else 'N/A'}")

        n_coll_normals = result.get('nCollisionNormals')
        ofs_coll_normals = result.get('ofsCollisionNormals')
        print(f"  nCollisionNormals: {n_coll_normals if n_coll_normals is not None else 'N/A'}")
        print(f"  ofsCollisionNormals: {hex(ofs_coll_normals) if ofs_coll_normals is not None else 'N/A'}")
        
        coll_indices_data = result.get('collision_indices_data', [])
        if n_coll_indices is not None and n_coll_indices > 0:
            if coll_indices_data:
                num_triangles = len(coll_indices_data) // 3
                print(f"  Количество треугольников коллизии: {num_triangles} (всего {len(coll_indices_data)} индексов)")
                max_indices_to_show = 30
                indices_to_show = coll_indices_data[:max_indices_to_show]
                print(f"  Первые {len(indices_to_show)} Collision Indices: {indices_to_show}")
                if len(coll_indices_data) > max_indices_to_show:
                    print("    ...")
            elif not ('error' in result and ('collision_indices' in result['error'] or 'ofsCollisionIndices' in result['error'])):
                 if n_coll_indices > 0 :
                    print("  Данные collision_indices не были прочитаны (возможно, ofsCollisionIndices=0 или указывает на некорректное место, или файл поврежден).")

        coll_vertices_data = result.get('collision_vertices_data', [])
        if n_coll_vertices is not None and n_coll_vertices > 0:
            if coll_vertices_data:
                print(f"  Всего Collision Vertices: {len(coll_vertices_data)}")
                max_vertices_to_show = 5
                for i, vertex in enumerate(coll_vertices_data[:max_vertices_to_show]):
                    print(f"    Vertex {i}: ({vertex[0]:.3f}, {vertex[1]:.3f}, {vertex[2]:.3f})")
                if len(coll_vertices_data) > max_vertices_to_show: print("    ...")
            elif not ('error' in result and ('collision_vertices' in result['error'] or 'ofsCollisionVertices' in result['error'])):
                if n_coll_vertices > 0:
                    print("  Данные collision_vertices не были прочитаны (проверьте ошибки выше).")

        coll_normals_data = result.get('collision_normals_data', [])
        if n_coll_normals is not None and n_coll_normals > 0:
            if coll_normals_data:
                print(f"  Всего Collision Normals: {len(coll_normals_data)}")
                max_normals_to_show = 5
                for i, normal in enumerate(coll_normals_data[:max_normals_to_show]):
                    print(f"    Normal {i}: ({normal[0]:.3f}, {normal[1]:.3f}, {normal[2]:.3f})")
                if len(coll_normals_data) > max_normals_to_show: print("    ...")
            elif not ('error' in result and ('collision_normals' in result['error'] or 'ofsCollisionNormals' in result['error'])):
                if n_coll_normals > 0:
                    print("  Данные collision_normals не были прочитаны (проверьте ошибки выше).")
        
        # Попытка визуализации, если есть данные коллизий
        if result.get('nCollisionIndices', 0) > 0 and \
           result.get('collision_vertices_data') and \
           result.get('collision_indices_data'):
            
            print(f"\n--- Попытка визуализации для: {result.get('file_name')} ---")
            try:
                visualize_collision_mesh(result['collision_vertices_data'], result['collision_indices_data'])
                print("Визуализация завершена.")
            except Exception as e:
                print(f"Ошибка во время визуализации: {e}")
        elif result.get('nCollisionIndices', 0) == 0:
            print("\nНет данных коллизий для визуализации в этом файле.")

        print("\n")

    print("\n--- Истинные значения для тестовых файлов ---")
    print("--- Скопируйте эти значения в TestM2Parser.cpp ---\n")

    for filename in TARGET_FILES:
        file_path = os.path.join(current_dir, filename)
        
        if not os.path.exists(file_path):
            print(f"// Файл не найден: {filename}")
            continue

        result = parse_m2_header(file_path)

        if 'error' in result and result['error']:
            print(f"// Ошибка при обработке {filename}: {result['error']}")
        else:
            vertices = result.get('nCollisionVertices', 0)
            indices = result.get('nCollisionIndices', 0)
            normals = result.get('nCollisionNormals', 0)
            
            # Форматируем как инициализатор структуры C++
            print(f"    {{\"{filename}\", {vertices}, {indices}, {normals}}},")
            
    print("\n--- Анализ завершен ---")
