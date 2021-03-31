#!/usr/bin/env python
# -*- coding: utf-8 -*-#

# Date: 2021/3/30

from binaryninja import *


def get_func_containing(bv, addr):
    """ 根据地址查找对应函数 """
    funcs = bv.get_functions_containing(addr)
    return funcs[0] if funcs else None


def fix_analysis(bv, addr):
    # Binja可能已跳过功能分析，因此我们可以使用llil/mlil
    f = get_func_containing(bv, addr)
    if f is not None and f.analysis_skipped:
        f.analysis_skip_override = FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis
        bv.update_analysis_and_wait()


def patch_and(bv: BinaryView, instructions: [MediumLevelILInstruction]):
    print("patch: {} -> {}".format(hex(instructions[0].address), hex(instructions[-1].address + instructions[-1].size)))
    # nop = instructions[0].function.arch.assemble('nop', instructions[0].address)
    # 移位指令会影响CPSR寄存器。
    # 把第二条指令改为subs r0, r0, r0
    if len(instructions) == 3:
        # 获取lsls指令的寄存器
        register = \
            [item for item in bv.get_disassembly(instructions[2].address, instructions[2].function.arch).split(' ') if
             item]
        register = register[2].replace(',', '').strip()
        ins = instructions[1]
        ins_base = ins.address
        # 两条指令的长度都是2，就不管了
        _code = ins.function.arch.assemble('subs {r0}, {r0}, {r0}'.format(r0=register), ins.address)
        bv.set_comment_at(ins_base, bv.get_disassembly(ins_base, ins.function.arch))
        bv.write(ins_base, _code)


def patch_shl_with_nop(bv: BinaryView, instructions: [MediumLevelILInstruction]):
    print("patch: {} -> {}".format(hex(instructions[0].address), hex(instructions[-1].address + instructions[-1].size)))
    # nop = instructions[0].function.arch.assemble('nop', instructions[0].address)
    # 移位指令会影响CPSR寄存器。
    # 把第二条指令改为subs r0, r0, r0
    if len(instructions) == 3:
        # 获取lsls指令的寄存器
        register = \
            [item for item in bv.get_disassembly(instructions[2].address, instructions[2].function.arch).split(' ') if
             item]
        register = register[1].replace(',', '').strip()
        ins = instructions[1]
        ins_base = ins.address
        # 两条指令的长度都是2，就不管了
        _code = ins.function.arch.assemble('subs {r0}, {r0}, {r0}'.format(r0=register), ins.address)
        bv.set_comment_at(ins_base, bv.get_disassembly(ins_base, ins.function.arch))
        bv.write(ins_base, _code)


# (x * (x - 1)) & 1 ==> 0
def remove_and_cond(bv: BinaryView, address: int):
    func: MediumLevelILFunction = get_func_containing(bv, address).medium_level_il
    ins: MediumLevelILInstruction
    instructions = [ins for ins in func.instructions]
    for i in range(len(instructions)):
        ins = instructions[i]
        # 判定是不是赋值操作
        if ins.operation == MediumLevelILOperation.MLIL_SET_VAR:
            # 判定操作右边的值的operation是不是and运算
            if len(ins.operands) == 2:
                if ins.operands[1].operation == MediumLevelILOperation.MLIL_AND:
                    lsl: MediumLevelILInstruction = ins.operands[1].operands[1]
                    and_value = 0
                    if lsl.operation == MediumLevelILOperation.MLIL_CONST:
                        and_value = lsl.constant
                        # lsl.value
                    # 判定是否是and 0x1
                    if and_value == 0x1:
                        # print(ins, ins.operands[1])
                        if i - 1 > 0:
                            # print(ins.address, ins, instructions[i - 1])
                            # 判定上条指令是不是乘法操作，不是的话看上上条指令是不是乘法操作
                            ins_count = 0
                            pre_ins: MediumLevelILInstruction
                            if instructions[i - 1].operation == MediumLevelILOperation.MLIL_SET_VAR:
                                if instructions[i - 1].operands[1].operation == MediumLevelILOperation.MLIL_MUL:
                                    ins_count = 1
                                    pre_ins = instructions[i - 1]
                                if instructions[i - 1].operands[1].operation == MediumLevelILOperation.MLIL_CONST_PTR:
                                    if i - 2 > 0:
                                        if instructions[i - 2].operands[1].operation == MediumLevelILOperation.MLIL_MUL:
                                            # 上上条指令为乘法的情况
                                            ins_count = 2
                                            pre_ins = instructions[i - 2]
                            # 判定乘法操作的结果是不是用来做移位运算了(就判定变量名字是不是一样的)
                            if pre_ins:
                                if str(ins.operands[1].operands[0]) == str(pre_ins.operands[0]):
                                    print(hex(ins.address), ins, ';', pre_ins)
                                    # 判定当前位置-2处的指令是不是做了减去1的操作。
                                    if i - ins_count - 1 > 0:
                                        pre_pre_ins: MediumLevelILInstruction = instructions[i - ins_count - 1]
                                        if pre_pre_ins.operation == MediumLevelILOperation.MLIL_SET_VAR:
                                            try:
                                                if pre_pre_ins.operands[1].operands[1].operation \
                                                        == MediumLevelILOperation.MLIL_CONST \
                                                        and pre_pre_ins.operands[1].operands[1].constant == 1 and \
                                                        pre_pre_ins.operands[
                                                            1].operation == MediumLevelILOperation.MLIL_SUB \
                                                        and str(pre_pre_ins.operands[0]) == \
                                                        str(pre_ins.operands[1].operands[0]) and \
                                                        str(pre_pre_ins.operands[1].operands[0]) == \
                                                        str(pre_ins.operands[1].operands[1]):
                                                    if ins.function.arch.name == 'thumb2':
                                                        patch_and(bv, [pre_pre_ins, pre_ins, ins])
                                            except Exception as e:
                                                print(e)


# (x * (x - 1)) << 0x1f ==> 0
def remove_shl_cond(bv: BinaryView, address: int):
    func: MediumLevelILFunction = get_func_containing(bv, address).medium_level_il
    ins: MediumLevelILInstruction
    instructions = [ins for ins in func.instructions]
    for i in range(len(instructions)):
        ins = instructions[i]
        # 判定是不是赋值操作
        if ins.operation == MediumLevelILOperation.MLIL_SET_VAR:
            # 判定操作右边的值的operation是不是向左移位的运算
            if len(ins.operands) == 2:
                if ins.operands[1].operation == MediumLevelILOperation.MLIL_LSL:
                    lsl: MediumLevelILInstruction = ins.operands[1].operands[1]
                    lsl_value = 0
                    if lsl.operation == MediumLevelILOperation.MLIL_CONST:
                        lsl_value = lsl.constant
                        # lsl.value
                    # 判定是否是移位0x1f
                    if lsl_value == 0x1f:
                        # print(ins, ins.operands[1])
                        if i - 1 > 0:
                            # print(ins.address, ins, instructions[i - 1])
                            # 判定上条指令是不是乘法操作，不是的话看上上条指令是不是乘法操作
                            ins_count = 0
                            pre_ins: MediumLevelILInstruction
                            if instructions[i - 1].operation == MediumLevelILOperation.MLIL_SET_VAR:
                                if instructions[i - 1].operands[1].operation == MediumLevelILOperation.MLIL_MUL:
                                    ins_count = 1
                                    pre_ins = instructions[i - 1]
                                if instructions[i - 1].operands[1].operation == MediumLevelILOperation.MLIL_CONST_PTR:
                                    if i - 2 > 0:
                                        if instructions[i - 2].operands[1].operation == MediumLevelILOperation.MLIL_MUL:
                                            # 上上条指令为乘法的情况
                                            ins_count = 2
                                            pre_ins = instructions[i - 2]
                            # 判定乘法操作的结果是不是用来做移位运算了(就判定变量名字是不是一样的)
                            if pre_ins:
                                if str(ins.operands[1].operands[0]) == str(pre_ins.operands[0]):
                                    print(hex(ins.address), ins, ';', pre_ins)
                                    # 判定当前位置-2处的指令是不是做了减去1的操作。
                                    if i - ins_count - 1 > 0:
                                        pre_pre_ins: MediumLevelILInstruction = instructions[i - ins_count - 1]
                                        if pre_pre_ins.operation == MediumLevelILOperation.MLIL_SET_VAR:
                                            try:
                                                if pre_pre_ins.operands[1].operands[1].operation \
                                                        == MediumLevelILOperation.MLIL_CONST \
                                                        and pre_pre_ins.operands[1].operands[1].constant == 1 and \
                                                        pre_pre_ins.operands[
                                                            1].operation == MediumLevelILOperation.MLIL_SUB \
                                                        and str(pre_pre_ins.operands[0]) == \
                                                        str(pre_ins.operands[1].operands[0]) and \
                                                        str(pre_pre_ins.operands[1].operands[0]) == \
                                                        str(pre_ins.operands[1].operands[1]):
                                                    if ins.function.arch.name == 'thumb2':
                                                        patch_shl_with_nop(bv, [pre_pre_ins, pre_ins, ins])
                                            except Exception as e:
                                                print(e)


def deflatten(bv: BinaryView, address: int):
    remove_shl_cond(bv, address)
    remove_and_cond(bv, address)
    # func: Function = get_func_containing(bv, address)
    # mlil: MediumLevelILFunction = func.medium_level_il
    # cur: MediumLevelILInstruction = func.get_low_level_il_at(address).medium_level_il
    # print(cur, cur.operation, cur.operands)


class RunInBackground(BackgroundTaskThread):
    def __init__(self, bv, addr, msg, func):
        BackgroundTaskThread.__init__(self, msg, True)
        self.bv = bv
        self.addr = addr
        self.func = func

    def run(self):
        bv = self.bv
        bv.begin_undo_actions()
        fix_analysis(bv, self.addr)
        self.func(bv, self.addr)
        bv.commit_undo_actions()
        bv.update_analysis()


def DeFlattenBackgrounder(bv, addr):
    s = RunInBackground(bv, addr, "Removing Control Flow Flattening", deflatten)
    s.start()


def dump_mlil_info(bv: BinaryView, address: int):
    func: Function = get_func_containing(bv, address)
    cur: MediumLevelILInstruction = func.get_low_level_il_at(address).medium_level_il
    print("当前指令:", cur)
    print("\t指令开始地址:", hex(cur.address))
    print("\t操作符:", cur.operation)
    print("\t操作数:", cur.operands)
    try:
        print("\t操作数中的表达式:", cur.operands[1])
        print("\t\t操作符:", cur.operands[1].operation)
        print("\t\t操作数:", cur.operands[1].operands)
    except Exception as e:
        print(e)


PluginCommand.register_for_address("反混淆",
                                   "去除OLLVM混淆",
                                   DeFlattenBackgrounder)
PluginCommand.register_for_address("当前MLIL",
                                   "获取当前中间语言指令信息",
                                   dump_mlil_info)
