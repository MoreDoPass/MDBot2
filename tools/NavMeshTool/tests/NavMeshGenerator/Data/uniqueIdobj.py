import os
import struct

def parse_chunk_header(f):
    """Читает 8-байтный заголовок чанка и возвращает ID и размер."""
    try:
        chunk_id_bytes = f.read(4)
        if not chunk_id_bytes: return None, 0
        # ID чанка хранится в обратном порядке (little-endian)
        chunk_id_str = chunk_id_bytes.decode(errors='ignore')[::-1]
        chunk_size = struct.unpack('<I', f.read(4))[0]
        return chunk_id_str, chunk_size
    except (struct.error, IndexError):
        return None, 0

def analyze_adt_for_holes(filepath):
    """
    Анализирует .adt файл на наличие "дыр" в ландшафте, корректно обрабатывая
    флаги для WotLK (high-res и low-res hole maps).
    """
    filename = os.path.basename(filepath)
    print(f"--- Анализ дыр в ландшафте для файла: {filename} ---")
    found_any_holes_in_file = False

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
                offset_mcin = struct.unpack_from('<I', mhdr_data, 4)[0]
            except struct.error:
                print("Ошибка: Не удалось распаковать смещение MCIN из MHDR.")
                return

            if offset_mcin == 0:
                print("В этом файле ADT нет чанка MCIN, пропуск.")
                return

            # --- MCIN ---
            f.seek(mhdr_data_pos + offset_mcin)
            mcin_id, mcin_size = parse_chunk_header(f)
            if mcin_id != 'MCIN':
                print(f"Ошибка: Ожидался чанк MCIN по смещению, но найден '{mcin_id}'.")
                return
            
            mcin_entries_data = f.read(mcin_size)
            
            # --- Обработка каждого MCNK чанка ---
            for i in range(256):
                mcnk_offset, mcnk_size, _, _ = struct.unpack_from('<IIII', mcin_entries_data, i * 16)

                if mcnk_size == 0:
                    continue

                f.seek(mcnk_offset)
                mcnk_id, _ = parse_chunk_header(f)
                if mcnk_id != 'MCNK':
                    print(f"Предупреждение: Ожидался MCNK в чанке {i}, но найден '{mcnk_id}'. Пропуск.")
                    continue
                
                mcnk_header_start_pos = f.tell()
                
                # --- Чтение заголовка MCNK ---
                # Читаем флаги (смещение 0) и индексы (смещение 4, 8)
                mcnk_header_data = f.read(128) # Весь заголовок MCNK - 128 байт
                flags, indexX, indexY = struct.unpack_from('<III', mcnk_header_data, 0)
                
                # --- Проверка флага и чтение маски дыр ---
                has_high_res_holes = (flags & 0x10000) != 0

                if has_high_res_holes:
                    # 64-битная маска по смещению 0x40 от начала хедера
                    holes_mask = struct.unpack_from('<Q', mcnk_header_data, 0x40)[0]
                    if holes_mask != 0:
                        print(f"  [!] Найдены дыры в чанке ({indexX}, {indexY}) (индекс {i})")
                        print(f"      Тип: High-Res (64-bit), Флаг 0x10000: Установлен")
                        print(f"      Маска: 0x{holes_mask:016X}")
                        found_any_holes_in_file = True
                else:
                    # 16-битная маска по смещению 0x3C от начала хедера
                    holes_mask = struct.unpack_from('<H', mcnk_header_data, 0x3C)[0]
                    if holes_mask != 0:
                        print(f"  [!] Найдены дыры в чанке ({indexX}, {indexY}) (индекс {i})")
                        print(f"      Тип: Low-Res (16-bit), Флаг 0x10000: НЕ установлен")
                        print(f"      Маска: 0x{holes_mask:04X}")
                        found_any_holes_in_file = True

    except FileNotFoundError:
        print(f"Ошибка: Файл не найден по пути {filepath}")
    except Exception as e:
        print(f"Произошла непредвиденная ошибка при обработке файла {filename}: {e}")
        import traceback
        traceback.print_exc()

    if not found_any_holes_in_file:
        print("Дыр в ландшафте не найдено в этом файле.")
    
    print("-" * (len(filename) + 40) + "\n")


if __name__ == "__main__":
    current_directory = os.path.dirname(os.path.abspath(__file__))
    
    # Ищем все .adt файлы в текущей директории
    adt_files = [f for f in os.listdir(current_directory) if f.lower().endswith('.adt')]
    
    if not adt_files:
        print("Не найдено ни одного .adt файла в директории скрипта.")
        print(f"Пожалуйста, поместите .adt файлы в: {current_directory}")
    else:
        print(f"Найдено {len(adt_files)} .adt файлов. Начинаю анализ...\n")
        for adt_filename in adt_files:
            adt_file_path = os.path.join(current_directory, adt_filename)
            analyze_adt_for_holes(adt_file_path)
 