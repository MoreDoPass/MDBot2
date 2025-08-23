#ifndef IHOOK_H
#define IHOOK_H

class IHook
{
   public:
    virtual ~IHook() {}
    virtual bool install() = 0;            // Установить хук
    virtual bool remove() = 0;             // Снять хук
    virtual bool isInstalled() const = 0;  // Проверить установлен ли хук
};

#endif  // IHOOK_H
