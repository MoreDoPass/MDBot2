#ifndef EDITORPLAYERPOINTERHOOK_H
#define EDITORPLAYERPOINTERHOOK_H

#include "HookManager/Hook/InlineHook/InlineHook.h"  // Из Core_HookManager.lib
#include <QLoggingCategory>

// Если будет своя категория логирования
// Q_DECLARE_LOGGING_CATEGORY(editorHookLog)

namespace MapEditor
{
namespace PlayerCore
{

class EditorPlayerPointerHook : public InlineHook
{
   public:
    EditorPlayerPointerHook(uintptr_t addressToHook, uintptr_t addressToStoreEax, MemoryManager* memoryManager);

   protected:
    bool generateTrampoline() override;

   private:
    uintptr_t m_addressToStoreEax;  // Адрес в памяти целевого процесса, куда сохранять EAX
};

}  // namespace PlayerCore
}  // namespace MapEditor

#endif  // EDITORPLAYERPOINTERHOOK_H
