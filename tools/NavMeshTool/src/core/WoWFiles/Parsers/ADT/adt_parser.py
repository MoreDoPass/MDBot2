import os
import struct
import glob
# import random # Больше не нужен
# import pyvista as pv # Убираем PyVista
# import numpy as np # Убираем PyVista

# Определение известных чанков
CHUNK_MVER = b'MVER'
CHUNK_MHDR = b'MHDR'
# CHUNK_MMID_ID_REVERSED_AS_NEXT = b'DIMM' # Больше не используется

# Имена полей смещений в MHDR в порядке их следования после 'flags'
# Используется в get_all_chunk_offsets_from_mhdr
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

# extract_null_terminated_string - больше не нужна для MCRF
# analyze_mcnk_mcvt_subchunk - удаляем, фокусируемся на MCRF
# analyze_mcnk_mcnr_subchunk - удаляем, фокусируемся на MCRF

def analyze_mcnk_mcrf_subchunk(f, mcnk_base_offset, mcrf_relative_offset, 
                               num_doodad_refs, num_map_obj_refs, 
                               mcnk_index_x, mcnk_index_y, output_lines):
    """
    Анализирует подчанк MCRF (ссылки на M2 и WMO) для одного MCNK чанка.

    Args:
        f: Открытый файловый объект ADT файла.
        mcnk_base_offset (int): Абсолютное смещение начала MCNK чанка в файле.
        mcrf_relative_offset (int): Относительное смещение MCRF от начала MCNK чанка.
        num_doodad_refs (int): Количество ссылок на дудады (из заголовка MCNK).
        num_map_obj_refs (int): Количество ссылок на объекты карты (из заголовка MCNK).
        mcnk_index_x (int): X-индекс MCNK чанка (0-15).
        mcnk_index_y (int): Y-индекс MCNK чанка (0-15).
        output_lines (list): Список строк для вывода логов.
    """
    if mcrf_relative_offset == 0:
        # output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: Смещение 0, подчанк отсутствует или не используется (nDoodadRefs={num_doodad_refs}, nMapObjRefs={num_map_obj_refs}).")
        if num_doodad_refs == 0 and num_map_obj_refs == 0:
             # Это нормальная ситуация, если ссылок нет
             pass
        else:
             # Если смещение 0, но счетчики не 0 - это странно
             output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ПРЕДУПРЕЖДЕНИЕ] Смещение MCRF 0, но nDoodadRefs={num_doodad_refs}, nMapObjRefs={num_map_obj_refs}.")
        return

    absolute_mcrf_offset = mcnk_base_offset + mcrf_relative_offset
    original_pos = f.tell()

    try:
        f.seek(absolute_mcrf_offset)
        mcrf_id, mcrf_data_size, eof = read_chunk_header(f)

        if eof:
            output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ОШИБКА] Неожиданный EOF при чтении заголовка MCRF по абс. смещению 0x{absolute_mcrf_offset:08X}.")
            return

        # В ADT файлах ID чанков хранятся в обратном порядке байт.
        # MCRF в файле будет как FRCM.
        if mcrf_id != b"MCRF":
            output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ОШИБКА] Ожидался ID 'MCRF', но найден '{mcrf_id.decode('latin-1', 'replace')}' по абс. смещению 0x{absolute_mcrf_offset:08X}.")
            return
        
        expected_mcrf_data_size = (num_doodad_refs + num_map_obj_refs) * 4
        if mcrf_data_size != expected_mcrf_data_size:
            output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ОШИБКА] Некорректный размер данных {mcrf_data_size}. Ожидалось {expected_mcrf_data_size} байт (на основе nDoodadRefs={num_doodad_refs}, nMapObjRefs={num_map_obj_refs}).")
            # Если размер 0, но счетчики > 0, это тоже проблема.
            # Если размер не 0, но не совпадает, тоже проблема.
            # Можно попробовать прочитать, сколько заявлено в mcrf_data_size, если это полезно для отладки,
            # но это рискованно, если счетчики nDoodadRefs/nMapObjRefs более надежны.
            # Пока что будем строги и вернем, если размер не совпадает с ожидаемым по счетчикам.
            return

        if expected_mcrf_data_size == 0 : # Если и по счетчикам, и по размеру чанка 0, то все ок
            output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: Найден по абс. смещению 0x{absolute_mcrf_offset:08X}. Размер данных: 0. Ссылок нет (nDoodadRefs=0, nMapObjRefs=0).")
            return

        mcrf_data_bytes = f.read(mcrf_data_size)
        if len(mcrf_data_bytes) < mcrf_data_size:
            output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ОШИБКА] Не удалось прочитать полные данные MCRF ({mcrf_data_size} байт).")
            return

        output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: Найден по абс. смещению 0x{absolute_mcrf_offset:08X}. Размер данных: {mcrf_data_size} байт.")
        
        doodad_refs = []
        if num_doodad_refs > 0:
            try:
                refs_fmt = f'<{num_doodad_refs}I'
                doodad_refs = list(struct.unpack(refs_fmt, mcrf_data_bytes[:num_doodad_refs*4]))
                output_lines.append(f"        Ссылки на дудады (MDDF индексы) [{num_doodad_refs} шт.]: {doodad_refs}")
            except struct.error as se_doodad:
                 output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ОШИБКА РАСПАКОВКИ doodad_refs] {se_doodad}")


        object_refs = []
        if num_map_obj_refs > 0:
            try:
                # Смещаемся в байте mcrf_data_bytes для чтения object_refs
                offset_for_obj_refs_in_data = num_doodad_refs * 4
                refs_fmt = f'<{num_map_obj_refs}I'
                object_refs = list(struct.unpack(refs_fmt, mcrf_data_bytes[offset_for_obj_refs_in_data : offset_for_obj_refs_in_data + num_map_obj_refs*4]))
                output_lines.append(f"        Ссылки на объекты карты (MODF индексы) [{num_map_obj_refs} шт.]: {object_refs}")
            except struct.error as se_object:
                 output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ОШИБКА РАСПАКОВКИ object_refs] {se_object}")
        
        if not doodad_refs and not object_refs and expected_mcrf_data_size > 0 : # Если данные были, но ничего не распарсили
             output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ПРЕДУПРЕЖДЕНИЕ] Данные MCRF были ({mcrf_data_size} байт), но ссылки не извлечены (num_doodad_refs={num_doodad_refs}, num_map_obj_refs={num_map_obj_refs}).")


    except struct.error as se:
        output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ОШИБКА РАСПАКОВКИ ЗАГОЛОВКА] {se} по абс. смещению 0x{absolute_mcrf_offset:08X}.")
    except Exception as e_mcrf:
        output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: [ОШИБКА] При обработке: {e_mcrf} по абс. смещению 0x{absolute_mcrf_offset:08X}.")
        import traceback
        output_lines.append(traceback.format_exc())
    finally:
        f.seek(original_pos)

# visualize_adt_mesh - удаляем

def process_all_adt_in_directory():
    """
    Анализирует ВСЕ .adt файлы в директории скрипта, читает MCIN для получения информации о 256 MCNK чанках,
    затем для каждого MCNK чанка читает его заголовок и вызывает анализ под-чанка MCRF.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    adt_files = glob.glob(os.path.join(script_dir, "*.adt"))

    if not adt_files:
        print(f"В директории {script_dir} не найдено .adt файлов.")
        return

    print(f"Найдено {len(adt_files)} ADT файлов для обработки в: {script_dir}")
    
    output_lines = [] 
    # all_map_vertices = [] # Удаляем
    # all_map_faces = [] # Удаляем
    # current_vertex_offset = 0 # Удаляем

    # min_base_x, max_base_x = float('inf'), float('-inf') # Удаляем статистику по позициям
    # min_base_y, max_base_y = float('inf'), float('-inf') # Удаляем
    # min_base_z, max_base_z = float('inf'), float('-inf') # Удаляем
    # mcnk_header_read_success = False # Удаляем

    for adt_file_path in adt_files:
        basename = os.path.basename(adt_file_path)
        output_lines.append(f"--- Анализ файла: {basename} ---") # Используем output_lines для логов
        
        try:
            with open(adt_file_path, 'rb') as f:
                # 1. MVER
                mver_id, mver_data_size, eof = read_chunk_header(f)
                if eof or mver_id != CHUNK_MVER or mver_data_size != 4:
                    output_lines.append(f"  Файл {basename}: [ОШИБКА] Проблема с MVER чанком.")
                    continue 
                f.read(mver_data_size) # Просто пропускаем данные MVER

                # 2. MHDR
                mhdr_id, mhdr_actual_data_block_size, eof = read_chunk_header(f)
                if eof or mhdr_id != CHUNK_MHDR:
                    output_lines.append(f"  Файл {basename}: [ОШИБКА] MHDR чанк не найден после MVER.")
                    continue
                
                mhdr_data_bytes = f.read(mhdr_actual_data_block_size)
                if len(mhdr_data_bytes) < mhdr_actual_data_block_size:
                    output_lines.append(f"  Файл {basename}: [ОШИБКА] Не удалось прочитать полные данные MHDR ({mhdr_actual_data_block_size} байт).")
                    continue

                MVER_CHUNK_TOTAL_SIZE = 12 
                MHDR_CHUNK_HEADER_SIZE = 8
                MHDR_DATA_BLOCK_START_FILE_OFFSET = MVER_CHUNK_TOTAL_SIZE + MHDR_CHUNK_HEADER_SIZE
                
                chunk_offsets = get_all_chunk_offsets_from_mhdr(mhdr_data_bytes, MHDR_DATA_BLOCK_START_FILE_OFFSET)
                if not chunk_offsets:
                    output_lines.append(f"  Файл {basename}: [ОШИБКА] Не удалось извлечь смещения из MHDR для анализа MCIN.")
                    continue

                # 3. Чтение MCIN (Map Chunk Info)
                absolute_mcin_offset = chunk_offsets.get("MCIN", 0)
                mcin_entries = []

                if absolute_mcin_offset == 0:
                    output_lines.append(f"  Файл {basename}: MCIN: Смещение в MHDR равно 0. Чанк MCIN отсутствует.")
                else:
                    try:
                        f.seek(absolute_mcin_offset)
                        mcin_chunk_id, mcin_data_size, eof_mcin = read_chunk_header(f)

                        if eof_mcin or mcin_chunk_id != b"MCIN":
                            output_lines.append(f"    Файл {basename}: [ОШИБКА MCIN] Ожидался ID 'MCIN', но найден '{mcin_chunk_id.decode('latin-1', 'replace') if mcin_chunk_id else 'None'}'")
                        else:
                            MCIN_ENTRY_SIZE = 16 
                            expected_mcin_data_size = 256 * MCIN_ENTRY_SIZE
                            if mcin_data_size != expected_mcin_data_size:
                                output_lines.append(f"      Файл {basename}: [ОШИБКА MCIN] Некорректный размер данных MCIN: {mcin_data_size}. Ожидалось {expected_mcin_data_size}.")
                            else:
                                for i in range(256):
                                    entry_bytes = f.read(MCIN_ENTRY_SIZE)
                                    if len(entry_bytes) < MCIN_ENTRY_SIZE:
                                        output_lines.append(f"        Файл {basename}: [ОШИБКА MCIN] Неполное чтение для записи MCNK #{i}.")
                                        mcin_entries = [] 
                                        break
                                    entry_data = struct.unpack('<IIII', entry_bytes)
                                    mcin_entries.append({
                                        "id": i, "offset": entry_data[0], "size": entry_data[1],
                                        "flags": entry_data[2], "asyncId": entry_data[3]
                                    })
                    except Exception as e_mcin:
                        output_lines.append(f"    Файл {basename}: [ОШИБКА MCIN] При чтении или парсинге чанка MCIN: {e_mcin}")
                
                if not mcin_entries:
                    output_lines.append(f"  Файл {basename}: MCNK: Анализ невозможен, так как записи MCIN не были прочитаны или были ошибки.")
                else:
                    output_lines.append(f"  Файл {basename}: --- Анализ MCRF для {len(mcin_entries)} MCNK чанков --- ")
                    for mcnk_idx, mcin_entry in enumerate(mcin_entries):
                        mcnk_absolute_offset = mcin_entry["offset"]
                        mcnk_expected_size_from_mcin = mcin_entry["size"]
                        
                        mcnk_index_y = mcnk_idx // 16
                        mcnk_index_x = mcnk_idx % 16

                        if mcnk_absolute_offset == 0 and mcnk_expected_size_from_mcin == 0:
                            continue 

                        if mcnk_absolute_offset == 0:
                            # output_lines.append(f"    Файл {basename} MCNK [{mcnk_idx:03d}] (Y={mcnk_index_y}, X={mcnk_index_x}): [ПРЕДУПРЕЖДЕНИЕ] Смещение MCNK равно 0. Пропуск.")
                            continue
                        
                        try:
                            f.seek(mcnk_absolute_offset)
                            mcnk_chunk_id, mcnk_actual_data_size, eof_mcnk = read_chunk_header(f)

                            if eof_mcnk:
                                 output_lines.append(f"    Файл {basename} MCNK [{mcnk_idx:03d}]: [ОШИБКА] Неожиданный EOF при чтении заголовка MCNK по смещению 0x{mcnk_absolute_offset:08X}")
                                 continue

                            if mcnk_chunk_id != b"MCNK":
                                output_lines.append(f"      Файл {basename} MCNK [{mcnk_idx:03d}]: [ОШИБКА] Ожидался ID 'MCNK', но найден '{mcnk_chunk_id.decode('latin-1', 'replace')}' по смещению 0x{mcnk_absolute_offset:08X}.")
                                continue
                            
                            mcnk_header_bytes = f.read(128) 
                            if len(mcnk_header_bytes) < 128:
                                output_lines.append(f"        Файл {basename} MCNK [{mcnk_idx:03d}]: [ОШИБКА] Не удалось прочитать полный 128-байтный заголовок MCNK.")
                                continue
                            
                            # Формат заголовка MCNK (первые интересующие нас поля):
                            # flags (I), indexX (I), indexY (I), nLayers (I), 
                            # nDoodadRefs (I), ofsHeight (I), ofsNormal (I), ofsLayer (I), 
                            # ofsRefs (I), ..., nMapObjRefs (I)
                            # Индексы: nDoodadRefs = 4, ofsRefs = 8, nMapObjRefs = 14
                            # header_fmt = '<IIIIIIIIIIIIIIIHH16s8sIIIIfffIII' # Полный формат не нужен здесь, только часть
                            # parsed_header = struct.unpack(header_fmt, mcnk_header_bytes)
                            
                            # Читаем только необходимые поля из заголовка MCNK
                            # nDoodadRefs (смещение 0x10 = 16 байт)
                            num_doodad_refs = struct.unpack_from('<I', mcnk_header_bytes, 0x10)[0]
                            # ofsRefs (смещение 0x20 = 32 байта)
                            ofs_refs_mcrf = struct.unpack_from('<I', mcnk_header_bytes, 0x20)[0]
                            # nMapObjRefs (смещение 0x38 = 56 байт)
                            num_map_obj_refs = struct.unpack_from('<I', mcnk_header_bytes, 0x38)[0]
                            
                            # mcnk_header_read_success = True # Не используется

                            # Удаляем анализ MCVT и MCNR
                            # current_mcnk_vertices, current_mcnk_faces = analyze_mcnk_mcvt_subchunk(...)
                            # if current_mcnk_vertices: ...
                            # if h_ofs_normals > 0 : analyze_mcnk_mcnr_subchunk(...)
                            
                            # Вызываем анализ MCRF
                            if ofs_refs_mcrf > 0 or num_doodad_refs > 0 or num_map_obj_refs > 0 :
                                analyze_mcnk_mcrf_subchunk(
                                    f, mcnk_absolute_offset, ofs_refs_mcrf,
                                    num_doodad_refs, num_map_obj_refs,
                                    mcnk_index_x, mcnk_index_y,
                                    output_lines
                                )
                            # else: # Если смещение 0 и счетчики 0, то MCRF просто нет
                            #    output_lines.append(f"      MCNK[{mcnk_index_y},{mcnk_index_x}] MCRF: Не используется (ofsRefs=0, nDoodadRefs=0, nMapObjRefs=0).")


                        except struct.error as se:
                            output_lines.append(f"      Файл {basename} MCNK [{mcnk_idx:03d}]: [ОШИБКА РАСПАКОВКИ MCNK Header/MCRF поля] {se}")
                        except Exception as e_mcnk:
                            output_lines.append(f"      Файл {basename} MCNK [{mcnk_idx:03d}]: [ОШИБКА] При обработке MCNK для MCRF (смещение 0x{mcnk_absolute_offset:08X}): {e_mcnk}")
                            
        except FileNotFoundError:
            output_lines.append(f"  [КРИТИЧЕСКАЯ ОШИБКА] Файл не найден: {adt_file_path}")
        except Exception as e:
            output_lines.append(f"  [КРИТИЧЕСКАЯ ОШИБКА] Непредвиденная ошибка при обработке файла: {basename}: {e}")
            import traceback
            output_lines.append(traceback.format_exc())

    # Вывод общего лога после обработки всех файлов
    print("\n".join(output_lines))

    # Удаляем вывод статистики и вызов визуализации
    # if mcnk_header_read_success: ...
    # print(f"\n--- Завершено --- ...")
    # if all_map_vertices: visualize_adt_mesh(...)

def main():
    """
    Основная функция для запуска анализа ADT файлов (фокус на MCRF).
    """
    try:
        process_all_adt_in_directory() 
    except KeyboardInterrupt:
        print("\nАнализ прерван пользователем.")

if __name__ == "__main__":
    main()
