import frida
import time
import sys
import os

# --- Глобальный файловый дескриптор для логов ---
log_file_path = os.path.join(os.path.dirname(__file__), "stalker_log_indices.txt")
try:
    log_file = open(log_file_path, "w", encoding="utf-8")
    print(f"Логи будут записаны в файл: {os.path.abspath(log_file_path)}")
except IOError as e:
    print(f"[FATAL] Не удалось открыть файл для записи логов: {e}")
    sys.exit(1)

# --- JavaScript код, который будет внедрен в процесс игры ---
js_code = """
/**
 * Читает и форматирует данные индексов из буфера.
 * @param {NativePointer} ptr Указатель на начало индексного буфера.
 * @param {number} numIndices Количество индексов для чтения (unsigned short).
 * @returns {string} Отформатированная строка с данными индексов.
 */
function dumpIndices(ptr, numIndices) {
    if (ptr.isNull()) {
        return "  [!] pIndexBuffer is null!";
    }
    let result = "  ";
    const maxIndicesToLog = 36; // Логируем только первые N индексов, чтобы не засорять вывод
    const count = Math.min(numIndices, maxIndicesToLog);
    
    try {
        for (let i = 0; i < count; i++) {
            const index = ptr.add(i * 2).readU16(); // readU16, так как индексы - unsigned short
            result += index.toString().padEnd(5, ' ');
            if ((i + 1) % 3 === 0) {
                result += " | "; // Разделяем треугольники
            }
            if ((i + 1) % 12 === 0 && i < count -1) {
                result += "\\n  "; // Новый квад
            }
        }
        if (numIndices > maxIndicesToLog) {
            result += `... и еще ${numIndices - maxIndicesToLog} индексов`;
        }
    } catch (e) {
        result += `\\n  [!] Ошибка чтения индексов: ${e.message}`;
    }
    return result;
}

/**
 * Воспроизводит алгоритм генерации индексов в JavaScript, основываясь на нашем анализе.
 * @param {number} baseVertexIndex Базовый индекс вершин для этого чанка.
 * @returns {Array<number>} Сгенерированный массив из 768 индексов.
 */
function generateIndicesJS(baseVertexIndex) {
    const indices = [];
    // Итерируем по сетке 8x8 квадов.
    for (let j = 0; j < 8; j++) {
        for (let i = 0; i < 8; i++) {
            // Рассчитываем локальные индексы вершин для квада (i, j)
            // на основе нашего понимания структуры вершин (ряды по 17 вершин).
            const local_quad_base = (j * 17) + i;

            const v_A = local_quad_base;         // Top-Left
            const v_B = local_quad_base + 1;     // Top-Right
            const v_X = local_quad_base + 9;     // Center (внутренняя вершина)
            const v_C = local_quad_base + 17;    // Bottom-Left
            const v_D = local_quad_base + 18;    // Bottom-Right

            // Добавляем 4 треугольника (12 индексов), не забывая прибавить baseVertexIndex.
            // Порядок обхода важен для правильного отображения полигонов (например, по часовой стрелке).
            
            // T1: (X, A, C)
            indices.push(baseVertexIndex + v_X);
            indices.push(baseVertexIndex + v_A);
            indices.push(baseVertexIndex + v_C);
            // T2: (X, B, A)
            indices.push(baseVertexIndex + v_X);
            indices.push(baseVertexIndex + v_B);
            indices.push(baseVertexIndex + v_A);
            // T3: (X, D, B)
            indices.push(baseVertexIndex + v_X);
            indices.push(baseVertexIndex + v_D);
            indices.push(baseVertexIndex + v_B);
            // T4: (X, C, D)
            indices.push(baseVertexIndex + v_X);
            indices.push(baseVertexIndex + v_C);
            indices.push(baseVertexIndex + v_D);
        }
    }
    return indices;
}

/**
 * Сравнивает два массива индексов и сообщает о расхождениях.
 * @param {Array<number>} generatedIndices Индексы, сгенерированные нашей JS-функцией.
 * @param {Array<number>} realIndices Индексы, считанные из памяти игры.
 * @returns {boolean} true, если массивы полностью совпадают.
 */
function compareIndices(generatedIndices, realIndices) {
    if (generatedIndices.length !== realIndices.length) {
        send(`  [VERIFY_FAILURE] Несовпадение длин массивов! JS: ${generatedIndices.length}, Game: ${realIndices.length}`);
        return false;
    }

    let mismatches = 0;
    for (let i = 0; i < realIndices.length; i++) {
        if (generatedIndices[i] !== realIndices[i]) {
            if (mismatches < 5) { // Логируем только первые 5 расхождений, чтобы не спамить
                send(`  [VERIFY_FAILURE] Расхождение по индексу ${i}: Ожидалось ${generatedIndices[i]}, получено ${realIndices[i]}`);
            }
            mismatches++;
        }
    }

    if (mismatches > 0) {
        send(`  [VERIFY_FAILURE] Обнаружено ${mismatches} расхождений.`);
        return false;
    }

    send(`  [VERIFY_SUCCESS] Полное совпадение! Алгоритм генерации индексов подтвержден.`);
    return true;
}

function run() {
    const baseAddr = Module.findBaseAddress('run.exe') || Module.findBaseAddress('Wow.exe');
    if (!baseAddr) {
        send('[FATAL] Не удалось найти базовый адрес.');
        return;
    }
    send(`[INFO] Базовый адрес найден: ${baseAddr}`);

    // Адрес функции CMapChunk_BuildIndices_WithHoles_mb (0x7C3B60).
    // Смещение = 0x7C3B60 - 0x400000 = 0x3C3B60.
    const targetFuncAddr = baseAddr.add(0x3C3B60);
    send(`[INFO] Установлен перехватчик на CMapChunk_BuildIndices_WithHoles_mb по адресу ${targetFuncAddr}`);

    Interceptor.attach(targetFuncAddr, {
        onEnter: function (args) {
            try {
                send(`\\n\\n======================================================================`);
                send(`>>> ВХОД: CMapChunk_BuildIndices_WithHoles_mb`);
                send(`----------------------------------------------------------------------`);
                
                // Аргументы для __fastcall: ecx, edx, затем со стека
                // this.context - это специальный объект Frida для доступа к регистрам CPU
                const pCMapChunk = this.context.ecx;
                const pIndexBuffer = this.context.esp.add(4).readPointer();
                const baseVertexIndex = this.context.esp.add(8).readU32(); // baseIndex

                // Сохраняем данные для onLeave, прикрепляя их напрямую к 'this'
                this.pIndexBuffer = pIndexBuffer;
                this.pCMapChunk = pCMapChunk;
                this.baseVertexIndex = baseVertexIndex;


                send(`    АРГУМЕНТЫ:`);
                send(`    pCMapChunk:        ${pCMapChunk}`);
                send(`    pIndexBuffer:      ${pIndexBuffer}`);
                send(`    baseVertexIndex:   ${baseVertexIndex}`);

                if (pCMapChunk.isNull()){
                     send (`    [FATAL] pCMapChunk is NULL. Невозможно продолжить анализ.`);
                     return;
                }
                
                // Можно добавить чтение каких-либо полей из pCMapChunk, если понадобится.
                // Например, индексы самого чанка, чтобы понимать, для какого чанка генерируются индексы
                const pos_x = pCMapChunk.add(0x34).readS32();
                const pos_y = pCMapChunk.add(0x38).readS32();
                send(`    Чанк (X, Y):       (${pos_x}, ${pos_y})`);


            } catch (e) {
                 send(`[FATAL SCRIPT ERROR] onEnter: ${e.message} \\n ${e.stack}`);
            }
        },

        onLeave: function (retval) {
            try {
                const indicesGenerated = retval.toInt32();
                send(`\\n    ВЫХОДНЫЕ ДАННЫЕ:`);
                send(`    Количество сгенерированных индексов (из EAX): ${indicesGenerated}`);

                if (indicesGenerated > 0) {
                    // Используем данные, сохраненные в 'this' в onEnter
                    send(`\\n    СГЕНЕРИРОВАННЫЕ ИНДЕКСЫ (из pIndexBuffer @ ${this.pIndexBuffer}):`);
                    const indexDump = dumpIndices(this.pIndexBuffer, indicesGenerated);
                    send(indexDump);
                } else {
                    send(`    Индексы не сгенерированы (возможно, чанк пуст или содержит только 'дыры').`);
                }

                // --- БЛОК ВЕРИФИКАЦИИ ---
                // 1. Считываем реальные индексы из памяти, которые сгенерировала игра
                const realIndices = [];
                for (let i = 0; i < indicesGenerated; i++) {
                    realIndices.push(this.pIndexBuffer.add(i * 2).readU16());
                }

                // 2. Генерируем наши ожидаемые индексы с помощью нашей реализации алгоритма
                const generatedIndices = generateIndicesJS(this.baseVertexIndex);

                // 3. Сравниваем их и выводим вердикт
                send(`\n--- ВЕРИФИКАЦИЯ АЛГОРИТМА ИНДЕКСОВ (baseVertexIndex: ${this.baseVertexIndex}) ---`);
                compareIndices(generatedIndices, realIndices);

                send(`\\n<<< ВЫХОД: Возврат из функции. Результат (eax): ${retval}`);
                send(`======================================================================\\n`);
            } catch (e) {
                send(`[FATAL SCRIPT ERROR] onLeave: ${e.message} \\n ${e.stack}`);
            }
        }
    });

    send(`[SUCCESS] Скрипт для ИНДЕКСОВ запущен. Ожидание вызова функции...`);
}

run();
"""

def on_message(message, data):
    """Функция для обработки сообщений от JavaScript"""
    global log_file
    try:
        if message['type'] == 'error':
            log_line = f"[!] Ошибка в скрипте Frida: {message['description']}\\n    {message.get('stack', 'Нет стека вызовов')}\\n"
        elif message['type'] == 'send':
            payload = message.get('payload', '')
            log_line = str(payload).replace('\\n', '\\n') + '\\n'
        else:
            log_line = f"[*] Неизвестное сообщение: {message}\\n"

        print(log_line.replace('\\n', '\\n'), end='')
        log_file.write(log_line)
        log_file.flush()

    except Exception as e:
        error_log = f"[FATAL] Неожиданная ошибка в on_message: {e}\\n"
        print(error_log, end='')
        if log_file and not log_file.closed:
            log_file.write(error_log)
            log_file.flush()


def main():
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
        print("\\nОтключаемся от процесса...")
        log_file.close()
        session.detach()
        sys.exit(0)

if __name__ == '__main__':
    main()
