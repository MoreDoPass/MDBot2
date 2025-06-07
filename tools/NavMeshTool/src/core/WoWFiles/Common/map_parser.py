import struct
import os

def parse_map_dbc(file_path="Map.dbc"):
    """
    Парсит Map.dbc файл и выводит ID карты и имя директории.

    Структура DBC файла (упрощенно для Map.dbc 3.3.5a):
    - Заголовок (20 байт):
        - magic (4 байта): "WDBC"
        - record_count (4 байта, uint32): Количество записей
        - field_count (4 байта, uint32): Количество полей на запись
        - record_size (4 байта, uint32): Размер одной записи
        - string_block_size (4 байта, uint32): Размер строкового блока
    - Блок записей: record_count * record_size байт.
        Каждая запись для Map.dbc (нас интересуют первые два поля):
        - map_id (4 байта, uint32)
        - directory_offset (4 байта, uint32): Смещение к имени директории в строковом блоке
    - Строковый блок: string_block_size байт. Содержит все строки, разделенные \0.
    """
    maps_data = {}
    try:
        with open(file_path, 'rb') as f:
            # Читаем заголовок
            magic, record_count, field_count, record_size, string_block_size = struct.unpack('<4sIIII', f.read(20))

            if magic != b'WDBC':
                # Попытка декодировать magic для более информативного сообщения об ошибке
                try:
                    magic_decoded = magic.decode('ascii', errors='replace')
                except Exception:
                    magic_decoded = str(magic)
                print(f"Ошибка: Неверная магия файла DBC: {magic_decoded}. Ожидалось 'WDBC'.")
                return None

            print(f"Магия файла: {magic.decode('ascii')}")
            print(f"Количество записей: {record_count}")
            print(f"Количество полей: {field_count}")
            print(f"Размер записи: {record_size}")
            print(f"Размер строкового блока: {string_block_size}")

            # Читаем весь блок записей
            records_data_start = f.tell()
            records_block_data = f.read(record_count * record_size)

            # Читаем весь строковый блок
            # string_block_start_offset_in_file = f.tell() # Не используется далее
            string_block_data = f.read(string_block_size)

            print(f"\n--- Записи Map.dbc ---")
            for i in range(record_count):
                record_offset_in_block = i * record_size
                # Извлекаем ID карты и смещение к строке директории
                # Предполагаем, что ID - первое поле (uint32), смещение директории - второе (uint32)
                try:
                    map_id, directory_offset = struct.unpack_from('<II', records_block_data, record_offset_in_block)
                except struct.error as e:
                    print(f"Ошибка распаковки записи {i}: {e}")
                    continue
                
                if directory_offset < string_block_size:
                    try:
                        end_of_string = string_block_data.find(b'\x00', directory_offset)
                        if end_of_string != -1:
                            directory_name = string_block_data[directory_offset:end_of_string].decode('utf-8', errors='replace')
                        else:
                            directory_name = string_block_data[directory_offset:].decode('utf-8', errors='replace').split('\0')[0]
                        
                        maps_data[map_id] = directory_name
                    except UnicodeDecodeError as e:
                        print(f"MapID: {map_id}, Directory Offset: {directory_offset} - Ошибка декодирования строки: {e}")
                    except IndexError:
                        print(f"MapID: {map_id}, Directory Offset: {directory_offset} - Ошибка индекса при доступе к строковому блоку.")
                else:
                    print(f"MapID: {map_id}, Некорректное смещение директории: {directory_offset} (размер блока: {string_block_size})")
            
            return maps_data

    except FileNotFoundError:
        print(f"Ошибка: Файл {file_path} не найден.")
        return None
    except Exception as e:
        print(f"Произошла непредвиденная ошибка: {e}")
        return None

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dbc_file_path = os.path.join(script_dir, "Map.dbc")
    
    print(f"Попытка загрузить Map.dbc из: {dbc_file_path}")
    
    parsed_maps = parse_map_dbc(dbc_file_path)

    if parsed_maps:
        print(f"\n--- Всего найдено карт: {len(parsed_maps)} ---")
        for map_id, directory_name in parsed_maps.items():
            print(f"ID: {map_id}, Directory: '{directory_name}' (Путь в MPQ: World\Maps\{directory_name}\)")

        # Можно сохранить это в JSON или другой формат для дальнейшего использования
        # import json
        # output_json_path = os.path.join(script_dir, "parsed_map_data.json")
        # try:
        #     with open(output_json_path, "w", encoding="utf-8") as f_out:
        #         json.dump(parsed_maps, f_out, indent=4, ensure_ascii=False, sort_keys=True)
        #     print(f"\nДанные о картах сохранены в: {output_json_path}")
        # except IOError as e:
        #     print(f"\nОшибка сохранения JSON: {e}")
