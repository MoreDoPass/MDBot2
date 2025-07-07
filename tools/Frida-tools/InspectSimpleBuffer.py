import frida
import time
import sys

# JavaScript код для инъекции
js_code = """
'use strict';

// Получаем базовый адрес модуля WoW.exe
const baseAddr = Module.findBaseAddress('run.exe');
console.log('run.exe base address: ' + baseAddr);

// Адрес функции TSimpleBuffer::AppendDword - это АБСОЛЮТНЫЙ адрес из IDA
const appendDwordPtr = ptr(0x47B0A0);
console.log('Hooking TSimpleBuffer::AppendDword at: ' + appendDwordPtr);

// Устанавливаем перехватчик
Interceptor.attach(appendDwordPtr, {
    onEnter: function(args) {
        // Сохраняем 'this' и аргумент для использования в onLeave
        this.buffer_this = this.context.ecx;
        // В __thiscall первый аргумент функции находится на стеке после адреса возврата
        this.dword_to_append = this.context.esp.add(4).readU32();

        console.log('---[ TSimpleBuffer::AppendDword ENTER ]---');
        console.log('Called from: ' + this.returnAddress.sub(baseAddr));
        console.log('Value to append (a2): 0x' + this.dword_to_append.toString(16) + ' (' + this.dword_to_append + ')');
        
        // Читаем состояние объекта ДО вызова
        console.log('this: ' + this.buffer_this);
        const vftable = this.buffer_this.readPointer();
        const bufferHandle = this.buffer_this.add(0x4).readPointer();
        const bufferBaseDelta = this.buffer_this.add(0x8).readU32();
        const capacity = this.buffer_this.add(0xC).readU32();
        const writeOffset = this.buffer_this.add(0x10).readU32();

        console.log('State BEFORE:');
        console.log('  vftable:          ' + vftable + ' -> ' + vftable.sub(baseAddr));
        console.log('  m_BufferHandle:   ' + bufferHandle);
        console.log('  m_BufferBaseDelta:  0x' + bufferBaseDelta.toString(16) + ' (' + bufferBaseDelta + ')');
        console.log('  m_Capacity:         0x' + capacity.toString(16) + ' (' + capacity + ')');
        console.log('  m_WriteOffset:      0x' + writeOffset.toString(16) + ' (' + writeOffset + ')');

    },

    onLeave: function(retval) {
        // Читаем состояние объекта ПОСЛЕ вызова
        const writeOffsetAfter = this.buffer_this.add(0x10).readU32();
        
        console.log('State AFTER:');
        console.log('  m_WriteOffset:      0x' + writeOffsetAfter.toString(16) + ' (' + writeOffsetAfter + ')');
        console.log('---[ TSimpleBuffer::AppendDword LEAVE ]---\\n');
    }
});
"""

def on_message(message, data):
    """
    Обработчик сообщений от Frida.
    """
    if message['type'] == 'send':
        print("[Frida] " + message['payload'])
    elif message['type'] == 'error':
        print("[Frida Error] " + message['stack'])
    else:
        print(message)

def main():
    """
    Главная функция.
    """
    try:
        # Подключаемся к процессу WoW.exe
        session = frida.attach("run.exe")
    except frida.ProcessNotFoundError:
        print("Процесс run.exe не найден. Пожалуйста, запустите игру.")
        sys.exit(1)
    
    print("Успешно подключились к run.exe")
    
    # Создаем и загружаем скрипт
    script = session.create_script(js_code)
    script.on('message', on_message)
    print("Загружаем скрипт...")
    script.load()
    
    print("Скрипт запущен. Ожидаем вызовов функции...")
    print("Нажмите Ctrl+C для выхода.")
    
    # Бесконечный цикл, чтобы скрипт продолжал работать
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("Отключаемся от процесса...")
        session.detach()
        print("Готово.")

if __name__ == '__main__':
    main() 