#include "cheat.h"
#include "SHPHook.h"
#include <iostream>
#include <string>
#include <cstdint>
#include "tool.h"

uint64_t 雾隐;
uint64_t 全屏;

void 初始化数据() {

    static uint64_t game_pid = getpid();


    uint64_t libil2cpp = 获取地址(game_pid, "libil2cpp.so");
    uint64_t libunity = 获取地址(game_pid, "libunity.so");

    雾隐 = libil2cpp + 0x035efb18;
    全屏 = libunity + 0x00A8EEAC;
}

//1,先把雾隐跳转写了
// 内联汇编函数
extern "C" void 雾隐新函数() {
    asm volatile(
        "ret\n"
    );
}

// Hook函数，使其跳转到内联汇编
void 雾影hook() {
    // 初始化影子页系统
    shadowpage_mode_t mode = {TMPREG_ON, 17};  // 使用临时寄存器模式
    mprotect_mode_t mprotect_mode = {LOOP_OFF, 0};  // 不启用循环保护
    shadowpage_hookinit(mode, mprotect_mode, false);
    
    // 安装hook
    void* original_function = nullptr;
    void* target_addr = reinterpret_cast<void*>(雾隐);
    shadowpage_hook(target_addr, (void*)雾隐新函数, &original_function);
    
    // original_function 现在指向原始函数的执行路径
    // 你可以保存它以便后续调用原始函数
}

// 回调函数，在执行后修改s0寄存器
void 全屏新函数(ucontext_t *uc, mcontext_t *ctx, fpsimd_context *vctx) {
    // 修改s0寄存器的值为5
    // s0寄存器对应v0的低32位（单精度浮点）
    uint32_t* s0_ptr = (uint32_t*)&vctx->vregs[0];
    *s0_ptr = 5;  // 将s0设置为5
    
    // 如果你需要修改其他浮点寄存器：
    // s1: v1的低32位
    // s2: v2的低32位
    // 等等...
}

// Hook函数，在执行后修改s0寄存器
void 全屏hook() {
    // 初始化影子页系统
    shadowpage_mode_t mode = {TMPREG_ON, 17};
    mprotect_mode_t mprotect_mode = {LOOP_OFF, 0};
    shadowpage_hookinit(mode, mprotect_mode, false);
    
    // 安装带上下文的hook
    void* target_addr = reinterpret_cast<void*>(全屏);
    shadowpage_hookctx(target_addr, 全屏新函数);
}

//3，安装hook
void 安装hook() {
    初始化数据();
    雾影hook();
    全屏hook();
}
//4，在main里面调用构造函数