import frida
import time

# JavaScript код для внедрения в процесс игры
jscode = """
// Получаем базовый адрес модуля, чтобы наши смещения были правильными
const baseAddr = Module.findBaseAddress('run.exe');
console.log('Базовый адрес .exe: ' + baseAddr);

// Адрес функции CMapChunk::BuildVertices_OldWorld
// .text:007C3F30 ; void *__fastcall CMapChunk_BuildVertices_OldWorld(void *this)
const targetFuncAddr = baseAddr.add(0x7C3F30 - 0x400000);
console.log('Перехватываем функцию CMapChunk_BuildVertices_OldWorld по адресу: ' + targetFuncAddr);

Interceptor.attach(targetFuncAddr, {
    onEnter: function(args) {
        // Функция __fastcall. 'this' передается в ECX.
        const pThis = this.context.ecx;

        console.log(`\\n\\n====================== HOOK on CMapChunk_BuildVertices_OldWorld (${targetFuncAddr}) ======================`);
        console.log(`CMapChunk* this (в ECX): ${pThis}`);

        // this - это указатель на объект CMapChunk.
        // Давай посмотрим на его содержимое. Размер объекта нам неизвестен, но мы можем предположить,
        // что он содержит информацию о положении чанка и указатели на данные вершин.
        // В MCNK чанке по смещению 0x14 лежит MCNK_Header.
        // По смещению 0x1C от начала хидера (т.е. 0x14 + 0x1C = 0x30 от pThis) лежит y_pos
        // 0x20 -> z_pos
        // 0x24 -> x_pos
        // Это смещения внутри структуры данных чанка в файле. В памяти может быть иначе.
        // Давайте просто сделаем дамп памяти и посмотрим.
        try {
            console.log("--- ДАМП ПАМЯТИ ДЛЯ 'this' (CMapChunk*) ---");
            // Дампим 256 байт, чтобы охватить возможные поля.
            console.log(hexdump(pThis, { length: 256, header: true, ansi: true }));
        } catch (e) {
            console.log("Не удалось прочитать память по адресу 'this': " + e.message);
        }
        
        // Посмотрим на стек, возможно там есть другие аргументы
        try {
            console.log("--- ДАМП СТЕКА (ESP) ---");
            console.log(hexdump(this.context.esp, { length: 64, header: true, ansi: true }));
        } catch (e) {
            console.log("Не удалось прочитать стек: " + e.message);
        }

        console.log(`================================================================================================\\n\\n`);
        
        // Мы можем также поставить onLeave, чтобы посмотреть на возвращаемое значение в EAX.
    },
    onLeave: function(retval) {
        console.log(`\\n\\n====================== LEAVE CMapChunk_BuildVertices_OldWorld ======================`);
        console.log(`Функция завершилась. Возвращаемое значение (в EAX): ${retval}`);
        // retval - это указатель на массив вершин. Посмотрим, что там.
        try {
            console.log("--- ДАМП ПАМЯТИ ВОЗВРАЩАЕМОГО УКАЗАТЕЛЯ (массив вершин?) ---");
            // В чанке 145 вершин (9*9 + 8*8).
            // Каждая вершина - 3 float'а (x, y, z) = 12 байт.
            // 145 * 12 = 1740 байт. Посмотрим хотя бы на начало (256 байт).
            console.log(hexdump(retval, { length: 256, header: true, ansi: true }));
        } catch (e) {
            console.log("Не удалось прочитать память по адресу возвращаемого значения: " + e.message);
        }
        console.log(`================================================================================================\\n\\n`);
    }
});
"""

def on_message(message, data):
    """Стандартный обработчик сообщений от Frida."""
    print(f"[{message}] => {data}")

# Подключаемся к процессу игры
try:
    session = frida.attach("run.exe")
except frida.ProcessNotFoundError:
    print("Процесс run.exe не найден. Пожалуйста, запустите игру.")
    exit()

# Создаем и загружаем скрипт
script = session.create_script(jscode)
script.on('message', on_message)
print("[*] Скрипт Frida внедрен в игру. Ожидаю вызова CMapChunk_BuildVertices_OldWorld...")
print("[*] Для вызова функции, просто перемещайтесь по игровому миру, чтобы подгружались новые чанки.")
script.load()

# Держим скрипт активным, пока не нажмем Ctrl+C
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    session.detach()
    print("[*] Отключился от процесса.")
