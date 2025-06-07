import os
import struct
import glob

# Определение известных чанков
CHUNK_MVER = b'MVER'
CHUNK_MHDR = b'MHDR'

# Имена полей смещений в MHDR в порядке их следования после 'flags'
MHDR_OFFSET_FIELD_NAMES = [
    "MCIN", "MTEX", "MMDX", "MMID", "MWMO", "MWID",
    "MDDF", "MODF", "MFBO", "MH2O", "MTXF"
]

def read_chunk_header(f):
    """Читает заголовок чанка (ID и размер). ID возвращается в правильном порядке."""
    chunk_id_reversed = f.read(4)
    if not chunk_id_reversed or len(chunk_id_reversed) < 4:
        return None, None, True # Конец файла или неполные данные
    chunk_id = chunk_id_reversed[::-1] # Переворачиваем ID, т.к. в файле они наоборот
    data_size_bytes = f.read(4)
    if not data_size_bytes or len(data_size_bytes) < 4:
        return chunk_id, None, True # Неполные данные для размера
    data_size = struct.unpack('<I', data_size_bytes)[0]
    return chunk_id, data_size, False

def get_all_chunk_offsets_from_mhdr(mhdr_data_bytes, mhdr_data_block_start_file_offset):
    """
    Извлекает все известные относительные смещения из блока данных MHDR,
    рассчитывает их абсолютные смещения в файле и возвращает в виде словаря.
    """
    offsets = {}
    min_expected_mhdr_data_size = (len(MHDR_OFFSET_FIELD_NAMES) + 1) * 4 
    if len(mhdr_data_bytes) < min_expected_mhdr_data_size:
        pass 

    for i, field_name_suffix in enumerate(MHDR_OFFSET_FIELD_NAMES):
        byte_offset_in_mhdr_data_for_ptr = (i + 1) * 4
        if byte_offset_in_mhdr_data_for_ptr + 4 > len(mhdr_data_bytes):
            offsets[field_name_suffix] = 0 
            continue
        relative_offset_val = struct.unpack_from('<I', mhdr_data_bytes, byte_offset_in_mhdr_data_for_ptr)[0]
        if relative_offset_val == 0:
            offsets[field_name_suffix] = 0
        else:
            offsets[field_name_suffix] = mhdr_data_block_start_file_offset + relative_offset_val
    return offsets

def generate_test_data(adt_file_path):
    """
    Анализирует один .adt файл и выводит структурированные эталонные данные для тестов.
    """
    basename = os.path.basename(adt_file_path)
    output_lines = [f"# Эталонные данные для файла: {basename}"]
    
    try:
        with open(adt_file_path, 'rb') as f:
            # 1. MVER
            mver_id, mver_data_size, eof = read_chunk_header(f)
            if eof or mver_id != CHUNK_MVER or mver_data_size != 4:
                output_lines.append(f"  [ОШИБКА] Проблема с MVER чанком.")
                return 
            f.read(mver_data_size) 

            # 2. MHDR
            mhdr_id, mhdr_actual_data_block_size, eof = read_chunk_header(f)
            if eof or mhdr_id != CHUNK_MHDR:
                output_lines.append(f"  [ОШИБКА] MHDR чанк не найден после MVER.")
                return
            
            mhdr_data_bytes = f.read(mhdr_actual_data_block_size)
            if len(mhdr_data_bytes) < mhdr_actual_data_block_size:
                output_lines.append(f"  [ОШИБКА] Не удалось прочитать полные данные MHDR.")
                return

            MVER_CHUNK_TOTAL_SIZE = 12 
            MHDR_CHUNK_HEADER_SIZE = 8
            MHDR_DATA_BLOCK_START_FILE_OFFSET = MVER_CHUNK_TOTAL_SIZE + MHDR_CHUNK_HEADER_SIZE
            
            chunk_offsets = get_all_chunk_offsets_from_mhdr(mhdr_data_bytes, MHDR_DATA_BLOCK_START_FILE_OFFSET)
            
            output_lines.append("\n[MHDR_Offsets]")
            for name, offset in chunk_offsets.items():
                if offset > 0:
                    output_lines.append(f"{name} = 0x{offset:08X}")

            # Парсинг MMDX/MMID
            absolute_mmdx_offset = chunk_offsets.get("MMDX", 0)
            mmdx_data = b''
            if absolute_mmdx_offset > 0:
                f.seek(absolute_mmdx_offset)
                mmdx_id, mmdx_data_size, _ = read_chunk_header(f)
                if mmdx_id == b'MMDX':
                    mmdx_data = f.read(mmdx_data_size)

            absolute_mmid_offset = chunk_offsets.get("MMID", 0)
            doodad_paths = []
            if absolute_mmid_offset > 0:
                f.seek(absolute_mmid_offset)
                mmid_id, mmid_data_size, _ = read_chunk_header(f)
                if mmid_id == b'MMID' and mmid_data_size > 0:
                    num_offsets = mmid_data_size // 4
                    for _ in range(num_offsets):
                        offset_in_mmdx = struct.unpack('<I', f.read(4))[0]
                        if offset_in_mmdx < len(mmdx_data):
                            path = mmdx_data[offset_in_mmdx:].split(b'\0')[0]
                            doodad_paths.append(path.decode('utf-8', 'replace'))
            
            output_lines.append("\n[Doodad_Paths]")
            output_lines.append(f"count = {len(doodad_paths)}")
            if doodad_paths:
                output_lines.append(f"path_0 = {doodad_paths[0]}")
                if len(doodad_paths) > 1:
                    output_lines.append(f"path_last = {doodad_paths[-1]}")

            # Парсинг MWMO/MWID
            absolute_mwmo_offset = chunk_offsets.get("MWMO", 0)
            mwmo_data = b''
            if absolute_mwmo_offset > 0:
                f.seek(absolute_mwmo_offset)
                mwmo_id, mwmo_data_size, _ = read_chunk_header(f)
                if mwmo_id == b'MWMO':
                    mwmo_data = f.read(mwmo_data_size)

            absolute_mwid_offset = chunk_offsets.get("MWID", 0)
            wmo_paths = []
            if absolute_mwid_offset > 0:
                f.seek(absolute_mwid_offset)
                mwid_id, mwid_data_size, _ = read_chunk_header(f)
                if mwid_id == b'MWID' and mwid_data_size > 0:
                    num_offsets = mwid_data_size // 4
                    for _ in range(num_offsets):
                        offset_in_mwmo = struct.unpack('<I', f.read(4))[0]
                        if offset_in_mwmo < len(mwmo_data):
                            path = mwmo_data[offset_in_mwmo:].split(b'\0')[0]
                            wmo_paths.append(path.decode('utf-8', 'replace'))

            output_lines.append("\n[WMO_Paths]")
            output_lines.append(f"count = {len(wmo_paths)}")
            if wmo_paths:
                output_lines.append(f"path_0 = {wmo_paths[0]}")
                if len(wmo_paths) > 1:
                    output_lines.append(f"path_last = {wmo_paths[-1]}")
            
            # Парсинг MH2O
            absolute_mh2o_offset = chunk_offsets.get("MH2O", 0)
            output_lines.append("\n[MH2O_Data]")
            if absolute_mh2o_offset > 0:
                f.seek(absolute_mh2o_offset)
                mh2o_id, mh2o_data_size, _ = read_chunk_header(f)
                if mh2o_id == b'MH2O' and mh2o_data_size > 0:
                    output_lines.append("found = True")

                    liquid_chunks_with_water_indices = []
                    first_chunk_with_water_info = ""
                    first_chunk_without_water_info = ""

                    for i in range(256):
                        data = struct.unpack('<III', f.read(12))
                        offset_instances, layer_count, offset_attributes = data
                        y, x = divmod(i, 16)

                        if layer_count > 0:
                            liquid_chunks_with_water_indices.append(i)
                            if not first_chunk_with_water_info:
                                first_chunk_with_water_info = (
                                    f"first_chunk_with_water = MCNK_{y}_{x} "
                                    f"(layer_count={layer_count}, "
                                    f"offset_instances=0x{offset_instances:X}, "
                                    f"offset_attributes=0x{offset_attributes:X})")
                        elif not first_chunk_without_water_info:
                            first_chunk_without_water_info = f"first_chunk_without_water = MCNK_{y}_{x}"

                    output_lines.append(f"chunks_with_water_count = {len(liquid_chunks_with_water_indices)}")
                    if first_chunk_with_water_info:
                        output_lines.append(first_chunk_with_water_info)
                    if first_chunk_without_water_info:
                        output_lines.append(first_chunk_without_water_info)
                else:
                    output_lines.append("found = False")
            else:
                output_lines.append("found = False")

    except FileNotFoundError:
        output_lines.append(f"  [КРИТИЧЕСКАЯ ОШИБКА] Файл не найден: {adt_file_path}")
    except Exception as e:
        output_lines.append(f"  [КРИТИЧЕСКАЯ ОШИБКА] Непредвиденная ошибка: {e}")

    print("\n".join(output_lines))


def main():
    """
    Основная функция для запуска анализа ADT файла.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Список файлов для анализа
    target_files = [
        "Azeroth_28_50.adt",
        "BlackTemple_28_30.adt",
        "Expansion01_15_31.adt",
        "IcecrownCitadel_30_30.adt",
        "Northrend_17_23.adt",
        "TanarisInstance_29_30.adt"
    ]

    for filename in target_files:
        target_adt = os.path.join(script_dir, filename)
        
        if not os.path.exists(target_adt):
            print(f"\n# [ОШИБКА] Целевой файл не найден: {target_adt}")
            print(f"# Поместите '{filename}' в директорию '{script_dir}'")
            continue

        try:
            generate_test_data(target_adt)
        except KeyboardInterrupt:
            print("\nАнализ прерван пользователем.")
            break
        except Exception as e:
            print(f"\n# [КРИТИЧЕСКАЯ ОШИБКА] при обработке файла {filename}: {e}")

if __name__ == "__main__":
    main()
