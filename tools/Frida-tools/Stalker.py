import frida
import time
import sys
import os

# --- Глобальный файловый дескриптор для логов ---
log_file_path = os.path.join(os.path.dirname(__file__), "stalker_log.txt")
try:
    log_file = open(log_file_path, "w", encoding="utf-8")
    print(f"Логи будут записаны в файл: {os.path.abspath(log_file_path)}")
except IOError as e:
    print(f"[FATAL] Не удалось открыть файл для записи логов: {e}")
    sys.exit(1)

# --- JavaScript код, который будет внедрен в процесс игры ---
js_code = """
/**
 * Преобразует "сырой" адрес в читаемую строку (например, "Wow.exe!sub_12345+0x10").
 * @param {NativePointer} addr Адрес для преобразования.
 * @returns {string} Читаемое представление адреса.
 */
function resolveAddress(addr) {
    const symbol = DebugSymbol.fromAddress(addr);
    // DebugSymbol.toString() очень удобен, он дает формат module!symbol+offset или module+offset
    return symbol.toString();
}

/**
 * Форматирует событие Stalker в читаемую строку с отступами, отражающими глубину стека.
 * @param {Array} event Массив события от Stalker.parse(), например, ['call', from, target, depth].
 * @returns {string} Отформатированная строка для лога.
 */
function formatStalkerEvent(event) {
    const type = event[0];
    const from = event[1];
    const target = event[2];
    const depth = event[3];

    // Создаем отступ в зависимости от глубины вызова
    const indent = ' '.repeat(4 + Math.max(0, depth) * 2);

    if (type === 'call') {
        return `${indent}CALL ${resolveAddress(from)} -> ${resolveAddress(target)}`;
    } else if (type === 'ret') {
        // Для ret "from" - это адрес возврата, а "target" - откуда возвращаемся.
        return `${indent}RET  ${resolveAddress(target)} -> ${resolveAddress(from)}`;
    }
    // На случай, если появятся другие типы событий
    return `${indent}${type.toUpperCase()} ${resolveAddress(from)}`;
}

/**
 * Читает и форматирует данные вершин из буфера.
 * @param {NativePointer} ptr Указатель на начало вертексного буфера.
 * @param {number} numVertices Количество вершин для чтения.
 * @returns {string} Отформатированная строка с данными вершин.
 */
function dumpVertices(ptr, numVertices) {
    if (ptr.isNull()) {
        return "  [!] pVertexBuffer is null!";
    }
    let result = "";
    const vertexSize = 24; // 6 floats (x, y, z, nx, ny, nz)
    for (let i = 0; i < numVertices; i++) {
        const offset = i * vertexSize;
        const vPtr = ptr.add(offset);
        try {
            const x = vPtr.add(0).readFloat();
            const y = vPtr.add(4).readFloat();
            const z = vPtr.add(8).readFloat();
            const nx = vPtr.add(12).readFloat();
            const ny = vPtr.add(16).readFloat();
            const nz = vPtr.add(20).readFloat();
            result += `  [${i}] pos: (${x.toFixed(3)}, ${y.toFixed(3)}, ${z.toFixed(3)}), norm: (${nx.toFixed(3)}, ${ny.toFixed(3)}, ${nz.toFixed(3)})\\n`;
        } catch (e) {
            result += `  [${i}] Ошибка чтения вершины: ${e.message}\\n`;
            break;
        }
    }
    return result;
}

/**
 * Читает и форматирует данные о высоте (MCVT)
 * @param {NativePointer} ptr Указатель на данные MCVT.
 * @param {number} numFloats Количество float'ов для чтения.
 * @returns {string} Отформатированная строка.
 */
function dumpMCVT(ptr, numFloats) {
     if (ptr.isNull()) {
        return "  [!] pMCVTData is null!";
    }
    try {
        // Frida не имеет прямого способа читать массив float, поэтому читаем байты и конвертируем
        const floatsData = ptr.readByteArray(numFloats * 4);
        const floatArray = [];
        const dataView = new DataView(floatsData);
        for (let i = 0; i < numFloats; i++) {
            // true для little-endian, что типично для x86
            floatArray.push(dataView.getFloat32(i * 4, true).toFixed(3));
        }
        return `  MCVT Data @ ${ptr}: [${floatArray.join(', ')}]`;
    } catch(e) {
        return `  [!] Ошибка чтения MCVT: ${e.message}`;
    }
}

/**
 * Полностью симулирует игровой алгоритм генерации вершин и сравнивает
 * результат с реальными данными в памяти.
 * @param {NativePointer} pVertexBuffer Указатель на начало реального вертексного буфера.
 * @param {NativePointer} pCMapChunk Указатель на структуру CMapChunk.
 */
function verifyAllVertices(pVertexBuffer, pCMapChunk) {
    if (!pVertexBuffer || pVertexBuffer.isNull() || !pCMapChunk || pCMapChunk.isNull()) {
        send("  [VERIFY_ERROR] Невалидные указатели для верификации.");
        return;
    }

    send("\\n\\n--- ПОЛНАЯ ВЕРИФИКАЦИЯ 145 ВЕРШИН ---");
    try {
        // --- 1. Считываем базовые значения ---
        const pos_x = pCMapChunk.add(0x34).readS32();
        const pos_y = pCMapChunk.add(0x38).readS32();
        const world_z = pCMapChunk.add(0x84).readFloat();
        const pMCVT = pCMapChunk.add(0x11C).readPointer();

        // --- 2. Воспроизводим логику расчета координат ---
        const CHUNK_SIZE = 33.333332;
        const MAP_MAX_COORD = 17066.666;
        const UNIT_SIZE = 4.1666665;
        const HALF_UNIT_SIZE = UNIT_SIZE / 2; // ~2.0833333

        // Важно: Мы меняем X и Y местами, чтобы соответствовать нашей системе координат.
        // Наша 'calc_x' будет сравниваться с реальной 'y', и наоборот.
        const base_world_X = MAP_MAX_COORD - (pos_y * CHUNK_SIZE);
        const base_world_Y = MAP_MAX_COORD - (pos_x * CHUNK_SIZE);

        const x_coords = Array(9).fill(0).map((_, i) => base_world_X - (i * UNIT_SIZE));
        const y_coords = Array(9).fill(0).map((_, i) => base_world_Y - (i * UNIT_SIZE));

        let pCurrentVertexPtr = pVertexBuffer;
        let pCurrentMCVTPtr = pMCVT;
        let totalMismatches = 0;
        const epsilon = 0.01; // Допуск для сравнения float

        // --- 3. Верификация основной сетки 9x9 (81 вершина) ---
        send("\\n  --- Проверка основной сетки 9x9 (81 вершина) ---");
        for (let i = 0; i < 9; i++) { // rowIndex
            for (let j = 0; j < 9; j++) { // colIndex
                const calc_x = x_coords[i];
                const calc_y = y_coords[j];
                const calc_z = world_z + pCurrentMCVTPtr.add(j * 4).readFloat();

                const real_y = pCurrentVertexPtr.add(0).readFloat(); // Real Y (pos)
                const real_x = pCurrentVertexPtr.add(4).readFloat(); // Real X (pos)
                const real_z = pCurrentVertexPtr.add(8).readFloat(); // Real Z (pos)

                const dx = Math.abs(calc_x - real_x);
                const dy = Math.abs(calc_y - real_y);
                const dz = Math.abs(calc_z - real_z);

                if (dx > epsilon || dy > epsilon || dz > epsilon) {
                    totalMismatches++;
                    if (totalMismatches < 5) { // Логируем только первые несколько ошибок
                        send(`    [!] Несовпадение в сетке 9x9 на [i=${i}, j=${j}]`);
                        send(`        - CALC (X,Y,Z): (${calc_x.toFixed(3)}, ${calc_y.toFixed(3)}, ${calc_z.toFixed(3)})`);
                        send(`        - REAL (X,Y,Z): (${real_x.toFixed(3)}, ${real_y.toFixed(3)}, ${real_z.toFixed(3)})`);
                    }
                }
                pCurrentVertexPtr = pCurrentVertexPtr.add(24); // Переход к следующей вершине (6 float * 4 байта)
            }
            pCurrentMCVTPtr = pCurrentMCVTPtr.add(36); // В C++ коде `pMCVT += 9` (9*4=36 байт)
        }

        // --- 4. Верификация "внутренней" сетки 8x8 (64 вершины) ---
        send("\\n  --- Проверка внутренней сетки 8x8 (64 вершины) ---");
        // Сбрасываем указатели для второго прохода
        pCurrentMCVTPtr = pMCVT;

        for (let i = 0; i < 8; i++) { // rowIndex
             pCurrentMCVTPtr = pCurrentMCVTPtr.add(36); // `pMCVT += 9` происходит в C++ до начала этого блока
            for (let j = 0; j < 8; j++) { // colIndex
                // В этой сетке координаты немного смещены
                const calc_x = x_coords[i] - HALF_UNIT_SIZE;
                const calc_y = y_coords[j] - HALF_UNIT_SIZE;
                const calc_z = world_z + pCurrentMCVTPtr.add(j * 4).readFloat();

                const real_y = pCurrentVertexPtr.add(0).readFloat();
                const real_x = pCurrentVertexPtr.add(4).readFloat();
                const real_z = pCurrentVertexPtr.add(8).readFloat();

                const dx = Math.abs(calc_x - real_x);
                const dy = Math.abs(calc_y - real_y);
                const dz = Math.abs(calc_z - real_z);

                if (dx > epsilon || dy > epsilon || dz > epsilon) {
                    totalMismatches++;
                    if (totalMismatches < 10) { // Больше логов, если ошибки тут
                         send(`    [!] Несовпадение в сетке 8x8 на [i=${i}, j=${j}]`);
                         send(`        - CALC (X,Y,Z): (${calc_x.toFixed(3)}, ${calc_y.toFixed(3)}, ${calc_z.toFixed(3)})`);
                         send(`        - REAL (X,Y,Z): (${real_x.toFixed(3)}, ${real_y.toFixed(3)}, ${real_z.toFixed(3)})`);
                    }
                }
                pCurrentVertexPtr = pCurrentVertexPtr.add(24);
            }
            // В C++ коде `pMCVT += 8` внутри этого блока
            // Так как мы уже сделали +9 в начале, здесь ничего не делаем, цикл сам перейдет к следующему i
        }


        if (totalMismatches === 0) {
            send(`\\n  [SUCCESS] ПОЛНОЕ СОВПАДЕНИЕ! Все 145 вершин соответствуют реконструированному алгоритму.`);
        } else {
            send(`\\n  [FAILURE] ОБНАРУЖЕНО РАСХОЖДЕНИЕ! Всего ошибок: ${totalMismatches}.`);
        }

    } catch (e) {
        send(`  [VERIFY_FATAL] Критическая ошибка во время верификации: ${e.message} \\n  ${e.stack}`);
    }
    send("--- КОНЕЦ ПОЛНОЙ ВЕРИФИКАЦИИ ---");
}

function run() {
    const baseAddr = Module.findBaseAddress('run.exe') || Module.findBaseAddress('Wow.exe');
    if (!baseAddr) {
        send('[FATAL] Не удалось найти базовый адрес.');
        return;
    }
    send(`[INFO] Базовый адрес найден: ${baseAddr}`);

    // Адрес функции CMapChunk_BuildVertices_OldWorld (0x7C3F30).
    // Если базовый адрес Wow.exe 0x400000, то смещение = 0x7C3F30 - 0x400000 = 0x3C3F30.
    const targetFuncAddr = baseAddr.add(0x3C3F30);
    send(`[INFO] Установлен перехватчик на CMapChunk_BuildVertices_OldWorld по адресу ${targetFuncAddr}`);

    Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
            try {
                this.stalkerContext = {
                    threadId: Process.getCurrentThreadId()
                };
                const context = this.stalkerContext;

                send(`\\n\\n======================================================================`);
                send(`>>> [${context.threadId}] ВХОД: CMapChunk_BuildVertices_OldWorld`);
                send(`----------------------------------------------------------------------`);

                try {
                    // --- Блок 1: Чтение входных аргументов и данных ---
                    const pCMapChunk = this.context.ecx;
                    const pVertexBuffer = this.context.esp.add(4).readPointer();
                    context.pVertexBuffer = pVertexBuffer;
                    context.pCMapChunk = pCMapChunk; // Сохраняем для onLeave

                    send(`    АРГУМЕНТЫ ИЗ РЕГИСТРОВ/СТЕКА:`);
                    send(`    pCMapChunk (this): ${pCMapChunk}`);
                    send(`    pVertexBuffer:     ${pVertexBuffer}`);

                    if (pCMapChunk.isNull()){
                         send (`    [FATAL] pCMapChunk is NULL. Невозможно продолжить анализ.`);
                         return;
                    }
                    
                    // Читаем ключевые поля из структуры CMapChunk
                    const pos_x = pCMapChunk.add(0x34).readS32(); // m_chunkIndexX
                    const pos_y = pCMapChunk.add(0x38).readS32(); // m_chunkIndexY
                    const world_z = pCMapChunk.add(0x84).readFloat(); // base_z
                    const pMCVT = pCMapChunk.add(0x11C).readPointer();
                    const pMCNR = pCMapChunk.add(0x124).readPointer();
                    
                    send(`\\n    ВХОДНЫЕ ДАННЫЕ (из pCMapChunk @ ${pCMapChunk}):`);
                    send(`    pos_x:      ${pos_x}`);
                    send(`    pos_y:      ${pos_y}`);
                    send(`    world_z:    ${world_z.toFixed(3)}`);
                    send(`    pMCVT:      ${pMCVT}`);
                    send(`    pMCNR:      ${pMCNR}`);

                    // --- Блок 2: Верификация вычислений из C++ кода ---
                    send(`\\n    ПРОВЕРКА ВЫЧИСЛЕНИЙ (согласно вашему C++ коду):`);
                    
                    const CHUNK_SIZE = 33.333332;
                    const MAP_MAX_COORD = 17066.666;
                    const UNIT_SIZE = 4.1666665;

                    const world_y_offset = pos_y * CHUNK_SIZE;
                    const next_chunk_index_y = pos_y + 1;
                    const next_chunk_index_x = pos_x + 1;
                    const base_world_X = MAP_MAX_COORD - (pos_x * CHUNK_SIZE);
                    const base_world_X_copy = base_world_X;
                    const base_world_Y = MAP_MAX_COORD - world_y_offset;
                    
                    send(`    world_y_offset:     ${world_y_offset.toFixed(3)}`);
                    send(`    base_world_X:       ${base_world_X.toFixed(3)}`);
                    send(`    base_world_Y:       ${base_world_Y.toFixed(3)}`);
                    send(`    next_chunk_index_x: ${next_chunk_index_x}`);
                    send(`    next_chunk_index_y: ${next_chunk_index_y}`);
                    
                    // Проверяем вычисление "глобальных" переменных
                    const flt_D25B88_0 = base_world_X;
                    const flt_D25B64 = base_world_Y;
                    const flt_D25B8C = base_world_X_copy - UNIT_SIZE;
                    const flt_D25B68 = base_world_Y - UNIT_SIZE;
                    const flt_D25B84_calc = MAP_MAX_COORD - (next_chunk_index_y * CHUNK_SIZE);

                    send(`\\n    ПРОВЕРКА "ГЛОБАЛЬНЫХ" ПЕРЕМЕННЫХ (локальных на стеке):`);
                    send(`    flt_D25B88[0] (X для 1-й колонки): ${flt_D25B88_0.toFixed(3)}`);
                    send(`    flt_D25B64 (Y для 1-го ряда):    ${flt_D25B64.toFixed(3)}`);
                    send(`    flt_D25B8C (X для 2-й колонки): ${flt_D25B8C.toFixed(3)}`);
                    send(`    flt_D25B68 (Y для 2-го ряда):    ${flt_D25B68.toFixed(3)}`);
                    send(`    flt_D25B84 (Y для след. чанка):  ${flt_D25B84_calc.toFixed(3)}`);
                    
                    // Сохраняем для onLeave
                    context.calculated_base_X = base_world_X;
                    context.calculated_base_Y = base_world_Y;
                    context.world_z = world_z;
                    context.pMCVT = pMCVT;
                    // Сохраняем координаты для именования файла
                    context.pos_x = pos_x;
                    context.pos_y = pos_y;


                } catch (e) {
                    send(`    [ERROR] Ошибка чтения аргументов или данных чанка: ${e.message}`);
                }

                send(`\\n    --- ТРАССИРОВКА ВЫЗОВОВ ВНУТРИ ФУНКЦИИ ---`);
                Stalker.follow(context.threadId, {
                    events: {
                        call: true,
                        ret: true,
                    },
                    onReceive: (events) => {
                        // Парсим события без stringify, чтобы получить NativePointer'ы
                        const parsedEvents = Stalker.parse(events);
                        // Каждое событие форматируем нашей новой функцией
                        const formattedLog = parsedEvents.map(formatStalkerEvent).join('\\n');
                        send(formattedLog);
                    }
                });
            } catch (e) {
                 send(`[FATAL SCRIPT ERROR] onEnter: ${e.message} \\n ${e.stack}`);
            }
        },

        onLeave: function (retval) {
            try {
                const context = this.stalkerContext;
                if (!context) return;

                Stalker.unfollow(context.threadId);
                Stalker.flush(context.threadId);

                send(`    --- КОНЕЦ ТРАССИРОВКИ ---`);

                // --- Полная верификация ---
                // Эта функция теперь делает и сверку, и выводит первую вершину
                verifyAllVertices(context.pVertexBuffer, context.pCMapChunk);

                // Выводим результат - сгенерированные вершины
                send(`\\n    ВЫХОДНЫЕ ДАННЫЕ (реальные вершины из pVertexBuffer @ ${context.pVertexBuffer}):`);
                if (context.pVertexBuffer && !context.pVertexBuffer.isNull()) {
                    // Функция генерирует 9*9 + 8*8 = 145 вершин. Выведем первые 5 для примера.
                    const vertexDump = dumpVertices(context.pVertexBuffer, 5);
                    send(vertexDump);
                    
                } else {
                    send("    [!] Не удалось получить pVertexBuffer или он NULL.");
                }

                // --- ОТЛАДОЧНЫЙ БЛОК ---
                send(`\\n    [DEBUG] Проверка сохранения вершин:`);
                send(`    [DEBUG] startAddr (pVertexBuffer): ${context.pVertexBuffer}`);
                send(`    [DEBUG] endAddr (retval): ${retval}`);
                if (context.pVertexBuffer && !context.pVertexBuffer.isNull() && retval && !retval.isNull()) {
                    send(`    [DEBUG] Адреса не NULL.`);
                    send(`    [DEBUG] endAddr.compare(startAddr): ${retval.compare(context.pVertexBuffer)} (Ожидается > 0)`);
                } else {
                    send(`    [DEBUG] Один или оба адреса являются NULL.`);
                }

                // --- НОВЫЙ БЛОК: Сохранение вершин в файл ---
                try {
                    const startAddr = context.pVertexBuffer;
                    
                    // Мы точно знаем, что функция генерирует 145 вершин (9*9 + 8*8 = 81+64=145).
                    // Каждая вершина = 6 float * 4 байта = 24 байта.
                    // Общий размер = 145 * 24 = 3480 байт.
                    const size = 3480;

                    // Убедимся, что указатель валиден
                    if (startAddr && !startAddr.isNull()) {
                        
                        // Проверка на вменяемый размер, чтобы не считать гигабайты в случае ошибки
                        if (size > 0 && size < 16384) { // Лимит 16KB
                            const vertexData = startAddr.readByteArray(size);
                            
                            // Отправляем бинарные данные и мета-информацию в Python
                            send({ 
                                type: 'vertex_data', 
                                pos_x: context.pos_x,
                                pos_y: context.pos_y,
                                size: size
                            }, vertexData);
                        } else {
                            send(`[ERROR] Рассчитанный размер (${size}) некорректен.`);
                        }
                    } else {
                        send(`[ERROR] pVertexBuffer is NULL, не могу сохранить данные.`);
                    }
                } catch (e) {
                    send(`[ERROR] Не удалось прочитать и отправить данные вершин: ${e.message}`);
                }

                send(`\\n<<< [${context.threadId}] ВЫХОД: Возврат из функции. Результат (eax): ${retval}`);
                send(`======================================================================\\n`);
            } catch (e) {
                send(`[FATAL SCRIPT ERROR] onLeave: ${e.message} \\n ${e.stack}`);
            }
        }
    });

    send(`[SUCCESS] Скрипт запущен. Ожидание вызова функции...`);
}
run();
"""
def on_message(message, data):
    """Функция для обработки сообщений от JavaScript"""
    global log_file
    try:
        if message['type'] == 'error':
            print(f"[!] Ошибка в скрипте Frida: {message['description']}")
            print(f"    {message.get('stack', 'Нет стека вызовов')}")
            log_file.write(f"[!] Ошибка в скрипте Frida: {message['description']}\\n")
            log_file.write(f"    {message.get('stack', 'Нет стека вызовов')}\\n")

        elif message['type'] == 'send':
            payload = message['payload']
            
            # Проверяем, является ли payload словарем с нашим специальным типом
            if isinstance(payload, dict) and payload.get('type') == 'vertex_data':
                pos_x = payload.get('pos_x', 'unknown')
                pos_y = payload.get('pos_y', 'unknown')
                size = payload.get('size', 0)
                
                filename = "all_vertices.bin"
                # Сохраняем в ту же папку, где лежит скрипт
                script_dir = os.path.dirname(__file__)
                filepath = os.path.join(script_dir, filename)
                
                log_msg = f"[+] Получены данные вершин для чанка ({pos_x}, {pos_y}). Размер: {size} байт. Добавление в {filename}..."
                print(log_msg)
                log_file.write(log_msg + '\\n')

                if data:
                    with open(filepath, 'ab') as f:
                        f.write(data)
                    success_msg = f"[+] Данные успешно добавлены в файл."
                    print(success_msg)
                    log_file.write(success_msg + '\\n')
                else:
                    error_msg = f"[-] Ошибка: сообщение 'vertex_data' пришло без бинарных данных."
                    print(error_msg)
                    log_file.write(error_msg + '\\n')
            
            # Иначе, это обычное строковое сообщение для лога
            elif isinstance(payload, str):
                # Заменяем \\n на реальный перенос строки для красивого вывода в консоль
                print(payload.replace('\\n', '\n'))
                # В файл пишем с \\n, чтобы сохранить структуру
                log_file.write(str(payload).replace('\\n', '\n') + '\n')
            
            log_file.flush()

    except Exception as e:
        # Логируем любые другие неожиданные ошибки в обработчике
        error_log = f"[FATAL] Неожиданная ошибка в on_message: {e}"
        print(error_log)
        if log_file and not log_file.closed:
            log_file.write(error_log + '\\n')
            log_file.flush()


def main():
    # --- НОВЫЙ БЛОК: Очистка старого файла ---
    # При каждом запуске Stalker'a мы будем удалять старый файл с вершинами,
    # чтобы сессия сбора данных всегда начиналась с чистого листа.
    output_filename = "all_vertices.bin"
    script_dir = os.path.dirname(__file__)
    output_filepath = os.path.join(script_dir, output_filename)
    if os.path.exists(output_filepath):
        try:
            print(f"Обнаружен старый файл '{output_filename}'. Удаление перед началом новой сессии...")
            os.remove(output_filepath)
        except OSError as e:
            print(f"Не удалось удалить старый файл: {e}")
            # В зависимости от важности, можно либо выйти, либо продолжить
            
    target_process = "Wow.exe"
    try:
        session = frida.attach(target_process)
    except frida.ProcessNotFoundError:
        print(f"Ошибка: процесс {target_process} не найден. Пробуем run.exe...")
        try:
            target_process = "run.exe"
            session = frida.attach(target_process)
        except frida.ProcessNotFoundError:
            print(f"Ошибка: процесс {target_process} также не найден. Пожалуйста, запустите игру.")
            sys.exit(1)
    except Exception as e:
        print(f"Произошла ошибка при подключении: {e}")
        sys.exit(1)

    print(f"Успешно подключились к {target_process}")

    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()

    print("Скрипт загружен. Ожидание вызовов функции...")
    print("Нажмите Ctrl+C в этой консоли, чтобы остановить скрипт.")

    try:
        # Ждем вечно, пока пользователь не нажмет Ctrl+C
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\nОтключаемся от процесса...")
        log_file.close()
        session.detach()
        sys.exit(0)

if __name__ == '__main__':
    main()
