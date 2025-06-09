import os
import struct
import glob

def find_wmo_placements():
    """
    Находит все .adt файлы в директории скрипта. Для каждого из них:
    1. Находит чанк MWMO и извлекает из него список имен файлов .wmo.
    2. Находит чанк MODF, который содержит информацию о размещении WMO.
    3. Для каждого размещенного WMO выводит его имя и XYZ-координаты.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    adt_files = glob.glob(os.path.join(script_dir, '*.adt'))

    if not adt_files:
        print(f"Ошибка: В директории '{script_dir}' не найдены .adt файлы.")
        return

    # Обрабатываем каждый .adt файл
    for adt_path in sorted(adt_files):
        print(f"\n--- Анализ файла: {os.path.basename(adt_path)} ---")

        try:
            with open(adt_path, 'rb') as f:
                content = f.read()
        except IOError as e:
            print(f"  Не удалось прочитать файл: {e}")
            continue

        # Находим смещения и размеры всех чанков в файле
        chunk_offsets = {}
        offset = 0
        while offset < len(content):
            if offset + 8 > len(content):
                break
            try:
                # Читаем ID и размер чанка
                chunk_id_rev, chunk_size = struct.unpack_from('<4sI', content, offset)
                # Переворачиваем ID в читаемый вид
                chunk_id = chunk_id_rev.decode('utf-8')[::-1]
                # Сохраняем смещение на НАЧАЛО данных чанка
                chunk_offsets[chunk_id] = {'offset': offset + 8, 'size': chunk_size}
                # Переходим к следующему чанку
                offset += 8 + chunk_size
            except (struct.error, UnicodeDecodeError):
                # Если заголовок поврежден, просто двигаемся дальше
                offset += 1

        # 1. Извлекаем имена WMO из чанка MWMO
        wmo_names = []
        if 'MWMO' in chunk_offsets:
            chunk = chunk_offsets['MWMO']
            data = content[chunk['offset'] : chunk['offset'] + chunk['size']]
            # Имена разделены нулевыми байтами
            wmo_names = [s for s in data.decode('utf-8', errors='ignore').split('\0') if s]

        # 2. Извлекаем информацию о размещении из MODF
        if 'MODF' not in chunk_offsets:
            print("  WMO не найдены (чанк MODF отсутствует).")
            continue

        modf_chunk = chunk_offsets['MODF']
        num_wmos = modf_chunk['size'] // 64
        
        if num_wmos == 0:
            print("  Найдено 0 WMO-объектов.")
            continue
            
        print(f"  Найдено {num_wmos} WMO-объектов:")

        for i in range(num_wmos):
            # Смещение до конкретной записи о WMO (каждая по 64 байта)
            entry_offset = modf_chunk['offset'] + i * 64
            
            # Распаковываем только нужные нам данные:
            # nameId (uint32), uniqueId (uint32), position (3x float)
            data = struct.unpack_from('<I I 3f', content, entry_offset)
            name_id, _, pos_x, pos_y, pos_z = data

            # Находим имя файла по nameId
            wmo_name = wmo_names[name_id] if name_id < len(wmo_names) else f"Неизвестный WMO (ID: {name_id})"

            # Выводим имя и "сырые" XYZ координаты
            print(f"    - {wmo_name} -> XYZ: ({pos_x:.2f}, {pos_y:.2f}, {pos_z:.2f})")

if __name__ == '__main__':
    find_wmo_placements()
