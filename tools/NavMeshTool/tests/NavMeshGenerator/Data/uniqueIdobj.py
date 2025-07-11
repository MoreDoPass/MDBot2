import os
import struct

def parse_chunk_header(f):
    """Читает 8-байтный заголовок чанка и возвращает ID в big-endian порядке."""
    try:
        chunk_id_bytes = f.read(4)
        if not chunk_id_bytes: return None, 0
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

def analyze_adt_mddf(filepath):
    """
    Анализирует .adt файл и выводит "сырые" данные из чанка MDDF.
    """
    filename = os.path.basename(filepath)
    print(f"--- Анализ MDDF для файла: {filename} ---")

    try:
        with open(filepath, 'rb') as f:
            # --- MVER и MHDR ---
            mver_id, mver_size = parse_chunk_header(f)
            if mver_id != 'MVER':
                print(f"Ошибка: Неверный формат файла ADT. Ожидался 'MVER', найдено '{mver_id}'.")
                return
            
            f.seek(mver_size, 1)

            mhdr_id, mhdr_size = parse_chunk_header(f)
            if mhdr_id != 'MHDR':
                print(f"Ошибка: чанк MHDR не найден после MVER. Найдено: '{mhdr_id}'")
                return
            
            mhdr_data_pos = f.tell()
            mhdr_data = f.read(mhdr_size)
            
            try:
                # Распаковываем смещения из MHDR
                # flags, mcin, mtex, mmdx, mmid, mwmo, mwid, mddf, modf
                mhdr_offsets = struct.unpack_from('<9I', mhdr_data, 0)
                offset_mmdx = mhdr_offsets[3]
                offset_mmid = mhdr_offsets[4]
                offset_mddf = mhdr_offsets[7]
            except struct.error:
                print("Ошибка: Не удалось распаковать смещения из MHDR.")
                return

            # --- Читаем данные для имен M2 (Doodads) ---
            # MMDX (блок с именами файлов моделей)
            if offset_mmdx > 0:
                f.seek(mhdr_data_pos + offset_mmdx)
                mmdx_id, mmdx_size = parse_chunk_header(f)
                if mmdx_id == 'MMDX':
                    mmdx_data = f.read(mmdx_size)
                else:
                    mmdx_data = b''
            else:
                mmdx_data = b''

            # MMID (смещения для имен в MMDX)
            if offset_mmid > 0:
                f.seek(mhdr_data_pos + offset_mmid)
                mmid_id, mmid_size = parse_chunk_header(f)
                if mmid_id == 'MMID':
                    mmid_offsets = list(struct.unpack(f'<{mmid_size // 4}I', f.read(mmid_size)))
                else:
                    mmid_offsets = []
            else:
                mmid_offsets = []

            # --- MDDF (определения Doodad) ---
            if offset_mddf == 0:
                print("В этом файле ADT нет чанка MDDF.\n")
                return

            f.seek(mhdr_data_pos + offset_mddf)
            mddf_id, mddf_size = parse_chunk_header(f)
            if mddf_id != 'MDDF':
                print(f"Ошибка: Ожидался чанк MDDF, но не найден по смещению. Найдено: {mddf_id}")
                return
                
            if mddf_size == 0:
                print("Чанк MDDF найден, но он пуст (размер 0).\n")
                return

            mddf_data_raw = f.read(mddf_size)
            num_doodad_defs = mddf_size // 36  # SMDoodadDef = 36 байт
            print(f"Найден чанк MDDF: {num_doodad_defs} определений M2 моделей (doodads).\n")

            # --- Итерация и парсинг каждой записи MDDF ---
            for i in range(num_doodad_defs):
                doodad_def_raw = mddf_data_raw[i*36 : (i+1)*36]
                
                # nameId, uniqueId, pos(3), rot(3), scale, flags
                (nameId, uniqueId, 
                 posX, posY, posZ, 
                 rotX, rotY, rotZ,
                 scale, flags) = struct.unpack('<IIffffffHH', doodad_def_raw)

                doodad_name = "Имя не найдено"
                if nameId < len(mmid_offsets):
                    doodad_name_offset = mmid_offsets[nameId]
                    doodad_name = get_string_from_data(mmdx_data, doodad_name_offset)
                
                print(f"--- Doodad #{i} ---")
                print(f"  Файл:         {doodad_name} (nameId: {nameId})")
                print(f"  uniqueId:     {uniqueId}")
                print(f"  position:     (X={posX:.3f}, Y={posY:.3f}, Z={posZ:.3f})")
                print(f"  rotation:     (X={rotX:.3f}, Y={rotY:.3f}, Z={rotZ:.3f})")
                print(f"  flags:        {flags} (0x{flags:04X})")
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
            analyze_adt_mddf(adt_file_path)

    if not found_adt:
        print("Не найдено ни одного .adt файла в директории скрипта.")
        print(f"Пожалуйста, поместите .adt файлы в: {current_directory}")
 