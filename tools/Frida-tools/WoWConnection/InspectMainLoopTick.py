import frida
import sys
import time

# --- JavaScript код, который будет внедрен в процесс игры ---
js_code = """
'use strict';

send({type: 'log', payload: '[INFO] Frida script starting...'});

// Глобальный объект для хранения статистики вызовов.
// Ключ - адрес вызывающего, значение - количество вызовов.
const callStats = {};

// Находим базовый адрес run.exe в памяти
const baseAddr = Module.findBaseAddress('run.exe');
if (!baseAddr) {
    send({type: 'log', payload: "[ERROR] Could not find base address for run.exe. Is the game running?"});
} else {
    send({type: 'log', payload: `[INFO] Base address for run.exe found at: ${baseAddr}`});

    // Смещение функции от начала модуля.
    // IDA Address (0x6B0B50) - IDA Base (0x400000) = Offset (0x2B0B50)
    const functionOffset = 0x2B0B50;
    const targetAddress = baseAddr.add(functionOffset);

    send({type: 'log', payload: `[INFO] Attaching to WoWConnection__MainLoopTick at ${targetAddress} (base + 0x${functionOffset.toString(16)})`});
    send({type: 'log', payload: '[INFO] Collecting call statistics... Move your character or perform actions in-game.'});

    try {
        Interceptor.attach(targetAddress, {
            onEnter: function(args) {
                // Нас не интересуют аргументы пакета.
                // Нас интересует только, КТО вызвал эту функцию.
                // this.returnAddress - это адрес в коде, куда вернется исполнение
                // после завершения этой функции. Это уникально идентифицирует место вызова.
                const caller = this.returnAddress;

                // Увеличиваем счетчик для данного вызывающего
                callStats[caller] = (callStats[caller] || 0) + 1;
            }
            // onLeave нам не нужен, т.к. мы не анализируем результат
        });

        // Каждые 5 секунд будем отправлять собранную статистику в Python для красивого вывода
        setInterval(() => {
            send({type: 'stats', payload: callStats});
        }, 5000);

    } catch (e) {
        send({type: 'log', payload: `[ERROR] Failed to attach: ${e.message}`});
    }
}
"""

def print_stats(stats):
    """Функция для красивого вывода статистики"""
    print("\n--- Call Statistics Update ---")
    
    if not stats:
        print("No calls captured in the last interval.")
        return

    # Сортируем адреса по количеству вызовов (по убыванию)
    sorted_callers = sorted(stats.items(), key=lambda item: item[1], reverse=True)
    
    print(f"Total unique callers: {len(sorted_callers)}")
    print("Top 5 most frequent callers:")
    
    for i, (address, count) in enumerate(sorted_callers[:5]):
        # Рассчитываем смещение от базового адреса 0x400000
        # Сам адрес возврата - это адрес *после* call, так что вычтем 5 байт (размер call)
        # чтобы получить примерный адрес самой инструкции вызова для удобства поиска в IDA.
        ida_address = int(address, 16) - 5
        print(f"  {i+1}. Caller Address: {hex(ida_address)} (approx) -> Called {count} times.")

def on_message_from_script(message, data):
    """Обработчик сообщений от Frida"""
    if message['type'] == 'send':
        msg_data = message['payload']
        if msg_data.get('type') == 'stats':
            print_stats(msg_data.get('payload'))
        elif msg_data.get('type') == 'log':
            print(msg_data.get('payload'))
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def main():
    try:
        session = frida.attach("run.exe")
        script = session.create_script(js_code)
        script.on('message', on_message_from_script)
        script.load()
        
        # Работаем в цикле, чтобы скрипт не завершался сразу
        while True:
            time.sleep(1)
            
    except frida.ProcessNotFoundError:
        print("[FATAL] Could not find the game process 'run.exe'. Is it running?")
    except KeyboardInterrupt:
        print("\n[INFO] Exiting...")
    except Exception as e:
        print(f"[FATAL] An error occurred: {e}")

if __name__ == '__main__':
    main() 