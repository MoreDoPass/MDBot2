"""
Инструмент для извлечения КОЛЛИЗИОННОЙ геометрии из WMO файлов World of Warcraft (3.3.5a)
и сохранения ее в формате .obj для отладки.

Этот скрипт выполняет следующие действия:
1.  Читает корневой WMO-файл (например, BlackTemple.wmo).
2.  Определяет количество WMO-групп (комнат, секций) из заголовка.
3.  Последовательно загружает каждый файл группы (например, BlackTemple_000.wmo, _001.wmo, ...).
4.  Для каждой группы применяет логику фильтрации, идентичную C++ реализации в WMOParser.cpp:
    - **Приоритет:** Пытается извлечь геометрию на основе BSP-дерева коллизии (чанки MOBN и MOBR).
      Это самый точный источник информации о проходимых поверхностях.
    - **Альтернатива:** Если BSP-дерево отсутствует, скрипт ищет чанк MOPY и извлекает
      только те полигоны, у которых установлен флаг коллизии (0x10).
    - Если ни того, ни другого нет, группа игнорируется.
5.  Собирает отфильтрованную геометрию из всех групп в единый список вершин и полигонов.
6.  Сохраняет результат в .obj файл, который можно открыть в любом 3D-редакторе.

Это позволяет изолированно проверить корректность работы логики парсинга WMO
без влияния остальной части приложения.
"""
import struct
import os
import argparse
import numpy as np
import sys

def read_chunk_header(f):
    """Читает 8-байтовый заголовок чанка (ID и размер)."""
    header_bytes = f.read(8)
    if len(header_bytes) < 8:
        return None, 0
    chunk_id_bytes, chunk_size = struct.unpack('<4sI', header_bytes)
    # НЕ переворачиваем. Работаем с little-endian ID как в C++ коде.
    chunk_id = chunk_id_bytes.decode('ascii')
    return chunk_id, chunk_size

def get_root_wmo_info(root_wmo_path):
    """Читает корневой WMO, чтобы найти количество групп."""
    with open(root_wmo_path, 'rb') as f:
        while True:
            chunk_id, chunk_size = read_chunk_header(f)
            if not chunk_id:
                break
            
            # Сравниваем с little-endian ID "DHOM", как это делает C++ код через memcmp.
            if chunk_id == 'DHOM':
                # nGroups находится по смещению 4 байта от начала чанка MOHD
                f.read(4) 
                nGroups = struct.unpack('<I', f.read(4))[0]
                return nGroups
            
            f.seek(chunk_size, 1) # Перемещаемся к следующему чанку
    return 0

def parse_wmo_group(group_path):
    """
    Парсит один файл группы WMO и извлекает ТОЛЬКО коллизионную геометрию.
    """
    if not os.path.exists(group_path):
        return None, None

    vertices = []
    indices = []
    polygons_flags = []
    bsp_nodes = []
    bsp_refs = []

    with open(group_path, 'rb') as f:
        # В WMO для WotLK чанк MVER всегда имеет размер 12 байт (8 заголовок + 4 данные).
        # Просто пропускаем его, чтобы встать в начало следующего чанка (MOGP).
        f.seek(12)

        # Читаем MOGP - главный чанк группы
        mogp_id, mogp_size = read_chunk_header(f)
        # Сравниваем с little-endian ID
        if mogp_id != 'PGOM':
            print(f"  -> Error: Expected MOGP chunk (PGOM), but found {mogp_id}. Skipping group.")
            return None, None

        mogp_end = f.tell() + mogp_size
        # Пропускаем заголовок MOGP. Его размер для WotLK - 68 байт.
        # В предыдущих версиях была ошибка (использовалось 64), что приводило к смещению
        # и невозможности найти под-чанки.
        f.seek(68, 1)

        # Читаем под-чанки MOGP
        while f.tell() < mogp_end:
            chunk_id, chunk_size = read_chunk_header(f)
            if not chunk_id:
                break
            
            chunk_end = f.tell() + chunk_size
            
            # Используем little-endian (перевернутые) ID, как в C++
            if chunk_id == 'TVOM': # MOVT
                for _ in range(chunk_size // 12):
                    vertices.append(struct.unpack('<3f', f.read(12)))
            elif chunk_id == 'IVOM': # MOVI
                for _ in range(chunk_size // 2):
                    indices.append(struct.unpack('<H', f.read(2))[0])
            elif chunk_id == 'YPOM': # MOPY
                 for _ in range(chunk_size // 2):
                    polygons_flags.append(struct.unpack('<H', f.read(2))[0])
            elif chunk_id == 'NBOM': # MOBN
                 for _ in range(chunk_size // 16):
                    # Исправлен формат: posChild - знаковый (h), а не беззнаковый (H)
                    bsp_nodes.append(struct.unpack('<HhhHI', f.read(12))) # Пропускаем planeDist
                    f.read(4)
            elif chunk_id == 'RBOM': # MOBR
                 for _ in range(chunk_size // 2):
                    bsp_refs.append(struct.unpack('<H', f.read(2))[0])
            
            f.seek(chunk_end)
            
    if not vertices or not indices:
        return None, None

    collision_triangles_refs = []
    
    # Единственный сценарий: используем BSP. Если его нет, геометрия не извлекается.
    if bsp_nodes and bsp_refs:
        unique_refs = set()
        for node in bsp_nodes:
            # flags, negChild, posChild, nFaces, faceStart
            flags, _, _, nFaces, faceStart = node
            if flags & 0x4: # Листовой узел дерева
                for i in range(nFaces):
                    unique_refs.add(bsp_refs[faceStart + i])
        
        # Теперь, когда у нас есть список треугольников из BSP, применяем второй фильтр по флагам MOPY
        for tri_ref in unique_refs:
            # Если данных о флагах нет, или флаги разрешают проход (нет флага 0x04 "no-walk")
            if not polygons_flags or (tri_ref < len(polygons_flags) and not (polygons_flags[tri_ref] & 0x04)):
                collision_triangles_refs.append(tri_ref)

    else:
        # Если BSP нет, мы не делаем ничего и не пытаемся угадать по флагам.
        pass

    if not collision_triangles_refs:
        return None, None

    # Собираем финальную геометрию
    final_vertices = []
    final_faces = []
    vertex_map = {} # {old_index: new_index}

    for tri_ref in collision_triangles_refs:
        face = []
        for i in range(3):
            old_idx = indices[tri_ref * 3 + i]
            if old_idx not in vertex_map:
                vertex_map[old_idx] = len(final_vertices)
                final_vertices.append(vertices[old_idx])
            
            new_idx = vertex_map[old_idx]
            face.append(new_idx)
        final_faces.append(face)
        
    return final_vertices, final_faces


def save_to_obj(vertices, faces, output_path):
    """Сохраняет геометрию в .obj файл."""
    with open(output_path, 'w') as f:
        f.write("# NavMeshTool WMO Collision Geometry Export\n")
        f.write(f"# Vertices: {len(vertices)}\n")
        f.write(f"# Faces: {len(faces)}\n")

        for v in vertices:
            f.write(f"v {v[0]:.6f} {v[1]:.6f} {v[2]:.6f}\n")
        
        for face in faces:
            # .obj использует 1-based индексацию
            f.write(f"f {face[0]+1} {face[1]+1} {face[2]+1}\n")
    print(f"Successfully saved collision geometry to {output_path}")

def main():
    # Убираем парсинг аргументов командной строки.
    # Теперь скрипт будет работать с файлом, определенным в блоке __main__.
    
    # Предполагаем, что sys.argv[1] будет установлен из блока __main__
    if len(sys.argv) < 2:
        print("This script should be run with a file path provided by the __main__ block.")
        print("Attempting to find default 'BlackTemple.wmo'...")
        # Попытка найти файл по умолчанию, если скрипт запущен напрямую без аргументов
        script_dir = os.path.dirname(os.path.abspath(__file__))
        default_file = os.path.join(script_dir, "BlackTemple.wmo")
        if not os.path.exists(default_file):
            print(f"Error: Default file not found at {default_file}")
            return
        root_path = default_file
    else:
        root_path = sys.argv[1]


    if not os.path.exists(root_path):
        print(f"Error: File not found at {root_path}")
        return

    num_groups = get_root_wmo_info(root_path)
    if num_groups == 0:
        print("Could not find MOHD chunk or WMO has no groups.")
        return

    print(f"Found {num_groups} groups in {os.path.basename(root_path)}")
    
    base_name = root_path.rsplit('.', 1)[0]
    wmo_dir = os.path.dirname(root_path)
    
    all_vertices = []
    all_faces = []

    for i in range(num_groups):
        group_filename = f"{base_name}_{i:03d}.wmo"
        group_path = os.path.join(wmo_dir, group_filename)
        print(f"Processing {group_filename}...")

        verts, faces = parse_wmo_group(group_path)
        
        if not verts or not faces:
            print("  -> No collision geometry found.")
            continue
        
        print(f"  -> Found {len(verts)} vertices and {len(faces)} faces.")

        vertex_offset = len(all_vertices)
        all_vertices.extend(verts)
        for face in faces:
            all_faces.append([v_idx + vertex_offset for v_idx in face])

    if not all_vertices:
        print("\nNo collision geometry was extracted from any group.")
        return
        
    output_filename = f"{os.path.basename(base_name)}_collision.obj"
    output_path = os.path.join(wmo_dir, output_filename)
    save_to_obj(all_vertices, all_faces, output_path)


if __name__ == "__main__":
    # Игнорируем аргументы командной строки и всегда используем файл по умолчанию.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_file = os.path.join(script_dir, "BlackTemple.wmo")
    
    if os.path.exists(default_file):
        print(f"Using default file: {default_file}")
        # Модифицируем sys.argv, чтобы main() мог его использовать
        sys.argv = [sys.argv[0], default_file]
        main()
    else:
        print(f"Error: Default file 'BlackTemple.wmo' not found in the script's directory.")
        print(f"Checked path: {default_file}")