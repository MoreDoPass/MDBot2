import os
import struct

def parse_chunk_header(f):
    """Читает 8-байтный заголовок чанка и возвращает ID в big-endian порядке."""
    try:
        chunk_id_bytes = f.read(4)
        if not chunk_id_bytes: return None, 0
        # Чанк ID хранится в little-endian, переворачиваем для сравнения
        chunk_id_str = chunk_id_bytes.decode(errors='ignore')[::-1]
        chunk_size = struct.unpack('<I', f.read(4))[0]
        return chunk_id_str, chunk_size
    except (struct.error, IndexError):
        return None, 0

def get_string_from_data(data, offset):
    """Извлекает null-terminated строку из блока данных."""
    if offset >= len(data): return "Offset out of bounds"
    end_of_string = data.find(b'\0', offset)
    if end_of_string == -1: return "String not terminated"
    return data[offset:end_of_string].decode(errors='ignore')

def analyze_adt_modf(filepath):
    """
    Анализирует .adt файл и выводит "сырые" данные из чанка MODF.
    """
    filename = os.path.basename(filepath)
    print(f"--- Анализ MODF для файла: {filename} ---")

    try:
        with open(filepath, 'rb') as f:
            # --- MVER и MHDR ---
            mver_id, mver_size = parse_chunk_header(f)
            if mver_id != 'MVER':
                print(f"Ошибка: Неверный формат файла ADT. Ожидался 'MVER', найдено '{mver_id}'.")
                return
            
            # Пропускаем данные MVER (4 байта версии)
            f.seek(mver_size, 1)

            mhdr_id, mhdr_size = parse_chunk_header(f)
            if mhdr_id != 'MHDR':
                print(f"Ошибка: чанк MHDR не найден после MVER. Найдено: '{mhdr_id}'")
                return
            
            mhdr_data_pos = f.tell()
            mhdr_data = f.read(mhdr_size)
            
            try:
                # flags, mcin, mtex, mmdx, mmid, mwmo, mwid, mddf, modf
                # Распаковываем первые 9 * 4 = 36 байт заголовка MHDR
                mhdr_offsets = struct.unpack_from('<9I', mhdr_data, 0)
                offset_mwmo = mhdr_offsets[5]
                offset_mwid = mhdr_offsets[6]
                offset_modf = mhdr_offsets[8]
            except struct.error:
                print("Ошибка: Не удалось распаковать смещения из MHDR. Возможно, чанк слишком мал.")
                return

            # --- Читаем глобальные данные для WMO ---
            # MWMO (имена WMO)
            if offset_mwmo > 0:
                f.seek(mhdr_data_pos + offset_mwmo)
                mwmo_id, mwmo_size = parse_chunk_header(f)
                if mwmo_id == 'MWMO':
                    mwmo_data = f.read(mwmo_size)
                else:
                    mwmo_data = b''
            else:
                mwmo_data = b''

            # MWID (смещения для имен WMO)
            if offset_mwid > 0:
                f.seek(mhdr_data_pos + offset_mwid)
                mwid_id, mwid_size = parse_chunk_header(f)
                if mwid_id == 'MWID':
                    mwid_offsets = list(struct.unpack(f'<{mwid_size // 4}I', f.read(mwid_size)))
                else:
                    mwid_offsets = []
            else:
                mwid_offsets = []

            # MODF (глобальный список всех WMO на тайле)
            if offset_modf == 0:
                print("В этом файле ADT нет чанка MODF.\n")
                return

            f.seek(mhdr_data_pos + offset_modf)
            modf_id, modf_size = parse_chunk_header(f)
            if modf_id != 'MODF':
                print(f"Ошибка: Ожидался чанк MODF, но не найден по смещению. Найдено: {modf_id}")
                return
                
            if modf_size == 0:
                print("Чанк MODF найден, но он пуст (размер 0).\n")
                return

            modf_data_raw = f.read(modf_size)
            num_wmo_defs = modf_size // 64
            print(f"Найден чанк MODF: {num_wmo_defs} определений WMO моделей.\n")

            # --- Итерация и парсинг каждой записи MODF ---
            for i in range(num_wmo_defs):
                wmo_def_raw = modf_data_raw[i*64 : (i+1)*64]
                
                (nameId, uniqueId, 
                 posX, posY, posZ, 
                 rotX, rotY, rotZ,
                 minX, minY, minZ,
                 maxX, maxY, maxZ,
                 flags, doodadSet, nameSet, scale) = struct.unpack('<IIffffffffffffHHHH', wmo_def_raw)

                wmo_name = "Имя не найдено"
                if nameId < len(mwid_offsets):
                    wmo_name_offset = mwid_offsets[nameId]
                    wmo_name = get_string_from_data(mwmo_data, wmo_name_offset)
                
                print(f"--- Запись WMO #{i} ---")
                print(f"  Файл:         {wmo_name} (nameId: {nameId})")
                print(f"  uniqueId:     {uniqueId}")
                print(f"  position:     (X={posX:.3f}, Y={posY:.3f}, Z={posZ:.3f})")
                print(f"  rotation:     (X={rotX:.3f}, Y={rotY:.3f}, Z={rotZ:.3f})")
                print(f"  extents.min:  (X={minX:.3f}, Y={minY:.3f}, Z={minZ:.3f})")
                print(f"  extents.max:  (X={maxX:.3f}, Y={maxY:.3f}, Z={maxZ:.3f})")
                print(f"  flags:        {flags} (0x{flags:04X})")
                print(f"  doodadSet:    {doodadSet}")
                print(f"  nameSet:      {nameSet}")
                print(f"  scale:        {scale}")
                print("")

    except FileNotFoundError:
        print(f"Ошибка: Файл не найден по пути {filepath}")
    except Exception as e:
        print(f"Произошла непредвиденная ошибка при обработке файла {filename}: {e}")


if __name__ == "__main__":
    current_directory = os.path.dirname(os.path.abspath(__file__))
    
    found_adt = False
    for item in os.listdir(current_directory):
        if item.lower().endswith('.adt'):
            found_adt = True
            adt_file_path = os.path.join(current_directory, item)
            analyze_adt_modf(adt_file_path)

    if not found_adt:
        print("Не найдено ни одного .adt файла в директории скрипта.")
        print(f"Пожалуйста, поместите .adt файлы в: {current_directory}")
 