import struct
import os
import re
from dataclasses import dataclass

@dataclass
class ParsedChunk:
    """
    Структура для хранения разобранных данных одного чанка (MCNK).
    Содержит всю информацию, необходимую для построения геометрии.
    """
    grid_x: int
    grid_y: int
    position: tuple[float, float, float]  # Вектор C3Vectorⁱ из заголовка MCNK
    mcvt: list[float]                     # Данные о высотах вершин
    mcnr: list[tuple[int, int, int]]      # Данные о нормалях

class ADTParser:
    """
    Парсит один файл .adt. Он находит все чанки MCNK и извлекает из них
    необходимые данные: высоты, нормали и базовую позицию.
    """
    def __init__(self, filepath):
        self.filepath = filepath
        self.chunks = []

        print(f"-> Парсинг файла: {os.path.basename(filepath)}")
        self._parse()

    def _parse(self):
        """
        Основной метод, который читает файл и запускает парсинг чанков MCNK.
        Правильный способ: найти чанк MCIN, прочитать из него смещения ко всем
        чанкам MCNK, и затем парсить каждый из них.
        """
        with open(self.filepath, 'rb') as f:
            file_data = f.read()

        # Находим позицию чанка MCIN
        try:
            # Ищем заголовок 'MCIN', перевернутый для little-endian
            mcin_offset = file_data.find(b'MCIN'[::-1])
            if mcin_offset == -1:
                print("ОШИБКА: Не удалось найти управляющий чанк MCIN в файле.")
                return
        except Exception:
            print("ОШИБКА: Исключение при поиске чанка MCIN.")
            return
            
        # Смещения в MCIN указывают на 256 блоков MCNK.
        # Структура одного элемента в MCIN:
        # uint32_t ofsMCNK;
        # uint32_t sizeMCNK;
        # ... (еще 8 байт, которые мы игнорируем)
        mcin_data_start = mcin_offset + 8 # Пропускаем заголовок 'MCIN' + size

        for i in range(256):
            # Смещение до текущей записи в MCIN
            record_offset = mcin_data_start + (i * 16)
            
            # Читаем смещение и размер для MCNK чанка
            ofsMCNK, sizeMCNK = struct.unpack_from('<II', file_data, record_offset)

            if ofsMCNK == 0 or sizeMCNK == 0:
                # Этот чанк не существует (вода или пустое место), пропускаем.
                continue

            # Получаем данные MCNK чанка по его смещению и размеру
            chunk_data = file_data[ofsMCNK : ofsMCNK + sizeMCNK]
            
            # Проверяем, что это действительно MCNK
            magic = chunk_data[0:4]
            if magic != b'MCNK'[::-1]: # 'KNCM'
                print(f"ПРЕДУПРЕЖДЕНИЕ: Ожидался MCNK по смещению {ofsMCNK}, но найден {magic}")
                continue
            
            self._parse_mcnk(chunk_data)

    def _parse_mcnk(self, mcnk_data):
        """
        Парсит один блок MCNK, строго следуя предоставленным указаниям.
        """
        # header_base_offset - это начало данных MCNK, сразу после 8-байтного заголовка.
        data_start_offset = 8

        # --- Шаг 1: Извлечение координат сетки (grid) ---
        # Согласно указаниям:
        # - Пропускаем первые 4 байта (flags).
        # - grid_x находится по смещению +4 от начала данных.
        # - grid_y находится по смещению +8 от начала данных.
        index_x = struct.unpack_from('<I', mcnk_data, data_start_offset + 0x04)[0]
        index_y = struct.unpack_from('<I', mcnk_data, data_start_offset + 0x08)[0]

        # --- Шаг 2: Извлечение мировой позиции ---
        # Согласно указаниям, позиция находится по смещению +0x68 от начала данных.
        position_offset = data_start_offset + 0x68
        pos_x, pos_y, pos_z = struct.unpack_from('<3f', mcnk_data, position_offset)
        position = (pos_x, pos_y, pos_z)

        # --- Шаг 3: Чтение MCVT и MCNR по смещениям ---
        # Смещения ofsHeight и ofsNormal находятся в заголовке MCNK.
        # Они указывают на адреса под-чанков MCVT и MCNR от начала блока MCNK.
        ofs_mcvt = struct.unpack_from('<I', mcnk_data, data_start_offset + 0x14)[0]
        ofs_mcnr = struct.unpack_from('<I', mcnk_data, data_start_offset + 0x18)[0]

        # Парсим MCVT (высоты). Данные начинаются после 8-байтного заголовка под-чанка.
        # Подтверждено: блок MCVT содержит ровно 145 float.
        mcvt_data_start = ofs_mcvt + 8
        mcvt_raw = mcnk_data[mcvt_data_start : mcvt_data_start + 145 * 4]
        mcvt = list(struct.unpack('<145f', mcvt_raw))

        # Парсим MCNR (нормали). Данные начинаются после 8-байтного заголовка под-чанка.
        mcnr_data_start = ofs_mcnr + 8
        mcnr_raw = mcnk_data[mcnr_data_start : mcnr_data_start + 145 * 3]
        mcnr_unpacked = struct.unpack('<' + 'b' * (145 * 3), mcnr_raw)
        
        mcnr = []
        for i in range(0, len(mcnr_unpacked), 3):
            ny, nz, nx = mcnr_unpacked[i:i+3]
            mcnr.append((nx, ny, nz))

        chunk = ParsedChunk(
            grid_x=index_x,
            grid_y=index_y,
            position=position,
            mcvt=mcvt,
            mcnr=mcnr
        )
        self.chunks.append(chunk)

    def get_chunk(self, grid_x, grid_y):
        """
        Находит и возвращает разобранный чанк по его внутренним координатам.
        """
        for chunk in self.chunks:
            if chunk.grid_x == grid_x and chunk.grid_y == grid_y:
                return chunk
        return None

class ADTManager:
    """
    Управляет парсерами ADT. 
    Это основной класс, с которым будет взаимодействовать наш testik.py.
    Он кэширует уже загруженные ADT, чтобы не парсить их повторно.
    """
    def __init__(self, adt_dir_path):
        self.adt_path = adt_dir_path
        self._parsers = {}  # Кэш для { (x,y): ADTParser }

    def _get_parser(self, adt_x, adt_y):
        """
        Получает (или создает и кэширует) парсер для нужных координат ADT.
        """
        if (adt_x, adt_y) in self._parsers:
            return self._parsers[(adt_x, adt_y)]

        # Ищем файл. Имена могут отличаться, попробуем стандартные.
        # Например: BlackTemple_32_32.adt
        filename = f"BlackTemple_{adt_x}_{adt_y}.adt"
        filepath = os.path.join(self.adt_path, filename)

        if not os.path.exists(filepath):
            # Пробуем другой распространенный формат имени
            filename_alt = f"map{adt_x}_{adt_y}.adt"
            filepath_alt = os.path.join(self.adt_path, filename_alt)
            if os.path.exists(filepath_alt):
                filepath = filepath_alt
            else:
                # TODO: Добавить другие форматы имен файлов, если потребуется
                raise FileNotFoundError(f"ADT file for ({adt_x}, {adt_y}) not found. Tried: {filepath} and {filepath_alt}")

        parser = ADTParser(filepath)
        self._parsers[(adt_x, adt_y)] = parser
        return parser

    def get_chunk_data(self, adt_x, adt_y, grid_x, grid_y):
        """
        Главный публичный метод. Получает все данные для одного чанка.
        """
        parser = self._get_parser(adt_x, adt_y)
        return parser.get_chunk(grid_x, grid_y)

# --- Тестовый блок для независимой проверки парсера ---
if __name__ == '__main__':
    import sys
    
    # Путь к директории с ADT файлами относительно корня проекта
    adt_dir_path = 'fast_test/ADT'
    
    print(f"--- Запуск независимой проверки ADTParser.py в директории: {adt_dir_path} ---")
    
    adt_file_to_test = None
    try:
        for filename in os.listdir(adt_dir_path):
            if filename.lower().endswith('.adt'):
                adt_file_to_test = os.path.join(adt_dir_path, filename)
                break
    except FileNotFoundError:
        print(f"ОШИБКА: Директория не найдена: {adt_dir_path}")
        sys.exit(1)

    if adt_file_to_test:
        print(f"\nНайден тестовый файл для анализа: {os.path.basename(adt_file_to_test)}")
        try:
            parser = ADTParser(adt_file_to_test)
            
            print("\n--- Вывод данных для всех найденных MCNK чанков ---")
            if not parser.chunks:
                print("В файле не найдено ни одного чанка.")

            for i, chunk in enumerate(parser.chunks):
                grid_str = f"grid = ({chunk.grid_x}, {chunk.grid_y})"
                pos_str = f"world_pos = ({chunk.position[0]:.2f}, {chunk.position[1]:.2f}, {chunk.position[2]:.2f})"
                print(f"{grid_str}\n{pos_str}")

                # Для первых 3 чанков выводим полный список, чтобы детально изучить.
                if i < 3:
                    print(f"mcvt (все 145) = {[f'{h:.2f}' for h in chunk.mcvt]}")
                else:
                    # Для остальных - сокращенно.
                    print(f"mcvt (первые 5) = {[f'{h:.2f}' for h in chunk.mcvt[:5]]}")
                
                print(f"mcnr (первые 5) = {chunk.mcnr[:5]}\n")
        
        except Exception as e:
            print(f"Произошла ошибка во время парсинга: {e}")
            import traceback
            traceback.print_exc()

    else:
        print(f"ОШИБКА: Не найдено ни одного .adt файла в директории '{adt_dir_path}'")
