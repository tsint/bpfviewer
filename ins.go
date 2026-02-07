// Copyright 2026 tsint
//
// SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0

package main

import (
	"fmt"
	"math"
	"strings"

	"github.com/cilium/ebpf/asm"
)

func FormatInstructions(buf *strings.Builder, insns asm.Instructions) {
	highestOffset := len(insns) * 2
	offsetWidth := int(math.Ceil(math.Log10(float64(highestOffset))))

	// var buf strings.Builder
	iter := insns.Iterate()
	for iter.Next() {
		if iter.Ins.Symbol() != "" {
			buf.WriteString(iter.Ins.Symbol())
			buf.WriteString(":\n")
		}
		if src := iter.Ins.Source(); src != nil {
			line := strings.TrimSpace(src.String())
			if line != "" {
				buf.WriteString(fmt.Sprintf("%*s", offsetWidth, " "))
				buf.WriteString("; ")
				buf.WriteString(line)
				buf.WriteString("\n")
			}
		}
		buf.WriteString(fmt.Sprintf("%*d: ", offsetWidth, iter.Offset))
		buf.WriteString(FmtIns(iter.Ins))
		buf.WriteString("\n")
	}
	buf.WriteString("\n")
}

func FmtIns(ins *asm.Instruction) string {
	op := ins.OpCode

	if op == asm.InvalidOpCode {
		return "INVALID"
	}

	class := op.Class()
	switch class {
	case asm.ALUClass, asm.ALU64Class:
		return fmtALU(ins)
	case asm.LdXClass:
		return fmtLdX(ins)
	case asm.StXClass:
		return fmtStX(ins) // 包含 Atomic
	case asm.StClass:
		return fmtSt(ins)
	case asm.JumpClass, asm.Jump32Class:
		return fmtJump(ins)
	case asm.LdClass:
		return fmtLd(ins) // 包含 LD_IMM64 (Map FD等) 和 Packet Access
	default:
		return fmt.Sprintf("unknow_ins(%v) ", ins)
	}
}

// --- 1. ALU (算术逻辑) ---
func fmtALU(ins *asm.Instruction) string {
	op := ins.OpCode
	dst := ins.Dst.String()
	aluOp := op.ALUOp()

	// 处理字节序转换 (End)
	if aluOp == asm.Swap {
		// BPF_END 指令
		// 格式: r1 = be16 r1 或 r1 = le64 r1
		// Source 字段用于区分 ToLe/ToBe
		bits := ins.Constant // 16, 32, 64

		// 判断是 be 还是 le (基于 OpCode Source 位)
		endian := "le"
		// Source bit 0x08 代表 TO_BE (大端), 0x00 代表 TO_LE (小端)
		if uint8(ins.OpCode)&0x08 != 0 {
			endian = "be"
		}

		return fmt.Sprintf("(%s) %s = hto%s%d(%s)", op.String(), dst, endian, bits, dst)
	}

	// 处理 Neg (取反)
	if aluOp == asm.Neg {
		return fmt.Sprintf("(%s) %s = ~%s", op.String(), dst, dst)
	}

	// 处理 Mov (赋值)
	if aluOp == asm.Mov {
		src := getSource(ins)
		return fmt.Sprintf("(%s) %s = %s", op.String(), dst, src)
	}

	// 处理普通二元运算 (Add, Sub, Mul, Div, Mod, etc.)
	operator := getALUOpSymbol(aluOp)
	src := getSource(ins)
	return fmt.Sprintf("(%s) %s %s %s", op.String(), dst, operator, src)
}

// --- 2. Memory Load (LdX) ---
// 格式: r1 = *(u64 *)(r2 + 0)
func fmtLdX(ins *asm.Instruction) string {
	dst := ins.Dst.String()
	sizeStr := getSizeStr(ins.OpCode.Size())
	offStr := fmt.Sprintf("%s %+d", ins.Src.String(), ins.Offset)
	// 格式: r7 = *(u64 *)(r6 + 0)
	return fmt.Sprintf("(%s) %s = *(%s *)(%s)", ins.OpCode.String(), dst, sizeStr, offStr)
}

// --- 3. Memory Store Reg (StX) ---
// 格式: *(u64 *)(r10 - 8) = r1
// 同时也包含原子操作 (Atomic)
func fmtStX(ins *asm.Instruction) string {
	op := ins.OpCode
	size := getSizeStr(op.Size())
	dst := ins.Dst.String() // 实际上是地址寄存器 (如 r10)
	src := ins.Src.String() // 值寄存器
	off := fmt.Sprintf("%+d", ins.Offset)

	// 构造内存地址字符串: *(u64 *)(r10 - 8)
	memLoc := fmt.Sprintf("*(%s *)(%s %s)", size, dst, off)

	// 检查是否为原子操作 (Mode == 0xc0)
	if op.Mode() == asm.AtomicMode {
		return fmtAtomic(ins, memLoc, src)
	}

	// 普通 Store: *(u64 *)(r10 - 8) = r1
	return fmt.Sprintf("(%s) %s = %s", op.String(), memLoc, src)
}

// fmtAtomic 处理原子操作的具体逻辑
func fmtAtomic(ins *asm.Instruction, memLoc string, srcReg string) string {
	// Atomic 操作码存储在 ins.Constant (Imm) 中
	imm := int32(ins.Constant)

	const (
		BPF_FETCH   = 0x01
		BPF_ADD     = 0x00
		BPF_OR      = 0x40
		BPF_AND     = 0x50
		BPF_XOR     = 0xa0
		BPF_XCHG    = 0xe0 | BPF_FETCH
		BPF_CMPXCHG = 0xf0 | BPF_FETCH
	)

	isFetch := (imm & BPF_FETCH) != 0
	atomicOp := imm & 0xff // 取高位判断操作类型

	// 1. CMPXCHG (比较并交换)
	// 格式: r0 = atomic_cmpxchg(*(u64 *)(...), r0, r1)
	if atomicOp == int32(BPF_CMPXCHG) {
		return fmt.Sprintf("(%s) if (%s == r0) { %s = %s; r0 = %s } //atomic_cmpxchg",
			ins.OpCode.String(), memLoc, memLoc, srcReg, memLoc)
	}

	// 2. XCHG (直接交换)
	// 格式: r1 = atomic_xchg(*(u64 *)(...), r1)
	if atomicOp == int32(BPF_XCHG) {
		return fmt.Sprintf("(%s) {tmp = %s; %s = %s; %s = tmp} //atomic_xchg",
			ins.OpCode.String(), memLoc, memLoc, srcReg, srcReg)
	}

	// 3. 算术原子操作 (ADD, AND, OR, XOR)
	sym := ""
	switch atomicOp {
	case int32(BPF_ADD):
		sym = "+="
	case int32(BPF_OR):
		sym = "|="
	case int32(BPF_AND):
		sym = "&="
	case int32(BPF_XOR):
		sym = "^="
	}

	if isFetch {
		// Fetch 模式: r1 = atomic_fetch_add(*(u64 *)(...), r1)
		return fmt.Sprintf("(%s) {tmp = %s; %s %s %s; %s = tmp} //atomic_fetch",
			ins.OpCode.String(), memLoc, memLoc, sym, srcReg, srcReg)
	} else {
		// 非 Fetch 模式 (传统 lock): lock *(u64 *)(...) += r1
		// 转换符号: add -> +=, and -> &=
		return fmt.Sprintf("(%s) %s %s %s //atomic", ins.OpCode.String(), memLoc, sym, srcReg)
	}
}

// --- 4. Memory Store Imm (St) ---
// 格式: *(u64 *)(r10 - 8) = 1
func fmtSt(ins *asm.Instruction) string {
	size := getSizeStr(ins.OpCode.Size())
	dst := ins.Dst.String()
	off := fmt.Sprintf("%+d", ins.Offset)
	imm := fmt.Sprintf("%d", ins.Constant)

	return fmt.Sprintf("(%s) *(%s *)(%s %s) = %s", ins.OpCode.String(), size, dst, off, imm)
}

// 定义 BPF 伪资源类型 (对应内核 include/uapi/linux/bpf.h 中的 BPF_PSEUDO_*)
// 这些值存储在 LD_IMM64 指令的 src_reg 字段中
const (
	BPF_PSEUDO_MAP_FD        = 1
	BPF_PSEUDO_MAP_VALUE     = 2
	BPF_PSEUDO_BTF_ID        = 3
	BPF_PSEUDO_FUNC          = 4
	BPF_PSEUDO_MAP_IDX       = 5
	BPF_PSEUDO_MAP_IDX_VALUE = 6
)

// --- 5. Ld (LD_IMM64 & Packet) ---
func fmtLd(ins *asm.Instruction) string {
	op := ins.OpCode
	mode := op.Mode()
	size := op.Size()

	// LD_IMM64 (r1 = <64bit> ll)
	// Mode: 0x00 (Imm)
	if mode == asm.ImmMode {
		dst := ins.Dst.String()
		imm := ins.Constant // 64位立即数 或 FD 或 ID
		typeCode := int(ins.Src)
		refStr := ""
		if ins.Reference() != "" {
			refStr = fmt.Sprintf(" <%s>", ins.Reference())
		}
		switch typeCode {
		case BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_IDX:
			m := ins.Map()
			if m != nil {
				// fmt.Fprintf(f, "LoadMapPtr dst: %s map: %s", ins.Dst, m)
				return fmt.Sprintf("(%s) %s = map_fd_%s%s // PSEUDO_MAP_[FD|IDX]", op.String(), dst, m, refStr)
			}
			// 内核格式: r1 = map_fd<imm> ll
			return fmt.Sprintf("(%s) %s = map_fd_%d%s // PSEUDO_MAP_[FD|IDX]", op.String(), dst, imm, refStr)

		case BPF_PSEUDO_MAP_VALUE, BPF_PSEUDO_MAP_IDX_VALUE:
			// 内核格式: r1 = map_value<imm> ll
			fd := uint32(imm)
			off := uint32(imm >> 32)
			return fmt.Sprintf("(%s) %s = map_value_%d+%d%s // PSEUDO_MAP_[IDX_]VALUE", op.String(), dst,
				fd, off, refStr)

		case BPF_PSEUDO_BTF_ID:
			// 内核格式: r1 = btf_id<imm> ll
			return fmt.Sprintf("(%s) %s = btf_id_%d%s // PSEUDO_BTF_ID", op.String(), dst, imm, refStr)

		case BPF_PSEUDO_FUNC:
			// 内核格式: r1 = func#<imm> ll
			if imm == -1 {
				return fmt.Sprintf("(%s) %s = #%s // PSEUDO_FUNC", op.String(), dst, ins.Reference())
			}
			return fmt.Sprintf("(%s) %s = <pc%+d> #%s // PSEUDO_FUNC", op.String(), dst, imm, ins.Reference())

		case 0: // 普通立即数
			return fmt.Sprintf("(%s) %s = %d // load Imm64", op.String(), dst, imm)

		default:
			// 未知类型，直接打印数值
			return fmt.Sprintf("(%s) %s = type_%d_%d", op.String(), dst, typeCode, imm)
		}
	}

	// Legacy Packet Access (r0 = *(u32 *)skb[off])
	// BPF_ABS (0x20) or BPF_IND (0x40)
	if mode == asm.AbsMode || mode == asm.IndMode {
		sz := getSizeStr(size)

		var idx string
		if mode == asm.AbsMode {
			// r0 = *(u32 *)skb[123]
			idx = fmt.Sprintf("%d", int32(ins.Constant))
		} else {
			// r0 = *(u32 *)skb[r1 + 123]
			// Ind use Src reg
			idx = fmt.Sprintf("%s %+d", ins.Src.String(), int32(ins.Constant))
		}

		return fmt.Sprintf("(%s) r0 = ntohl(*(%s *)(((struct sk_buff *) r6)->data) + %s)", op.String(), sz, idx)
	}

	return "unknown_ld"
}

// --- 6. Jump ---
func fmtJump(ins *asm.Instruction) string {
	op := ins.OpCode
	jmpOp := op.JumpOp()

	// 1. Call
	if jmpOp == asm.Call {
		// ins.Constant 是 func_id (如果是 helper) 或者 pc offset (如果是 local call)
		switch ins.Src {
		case asm.PseudoCall:
			// bpf-to-bpf call
			if ins.Constant == -1 {
				return fmt.Sprintf("call #%s // PseudoCall, return to next ins", ins.Reference())
			}
			return fmt.Sprintf("call pc%+d #%s // PseudoCall, return to next ins", ins.Constant, ins.Reference())
		case asm.PseudoKfuncCall:
			// kfunc call
			return fmt.Sprintf("call kfunc(%d) // PseudoKfuncCall", ins.Constant)
		default:
			return fmt.Sprintf("call %v", asm.BuiltinFunc(ins.Constant))
		}
	}

	// 2. Exit
	if jmpOp == asm.Exit {
		return "exit"
	}

	// 3. Unconditional Goto (Ja)
	if jmpOp == asm.Ja {
		if op.Class() == asm.Jump32Class {
			return fmt.Sprintf("goto %d", ins.Constant)
		} else {
			return fmt.Sprintf("goto pc%+d", ins.Offset)
		}
	}

	// 4. Conditional Jumps
	// 格式: if r1 > 10 goto +5
	dst := ins.Dst.String()
	src := getSource(ins)
	off := fmt.Sprintf("%+d", ins.Offset)
	relation := getJmpOpSymbol(jmpOp)

	return fmt.Sprintf("if %s %s %s goto pc%s", dst, relation, src, off)
}

// --- Helpers ---

// 获取源操作数 (寄存器名 或 立即数)
func getSource(ins *asm.Instruction) string {
	if ins.OpCode.Source() == asm.ImmSource {
		return fmt.Sprintf("%d", ins.Constant)
	}
	return ins.Src.String()
}

// 获取大小文本 (内核日志风格)
func getSizeStr(s asm.Size) string {
	switch s {
	case asm.Byte:
		return "u8"
	case asm.Half:
		return "u16"
	case asm.Word:
		return "u32"
	case asm.DWord:
		return "u64"
	}
	return "u??"
}

// ALU 操作符映射
func getALUOpSymbol(op asm.ALUOp) string {
	switch op {
	case asm.Add:
		return "+="
	case asm.Sub:
		return "-="
	case asm.Mul:
		return "*="
	case asm.Div:
		return "/="
	case asm.SDiv:
		return "/=" // Signed Div
	case asm.Or:
		return "|="
	case asm.And:
		return "&="
	case asm.LSh:
		return "<<="
	case asm.RSh:
		return ">>="
	case asm.Mod:
		return "%="
	case asm.SMod:
		return "%=" // Signed Mod
	case asm.Xor:
		return "^="
	case asm.ArSh:
		return ">>=" // Arithmetic shift (带符号右移)
	case asm.Mov:
		return "="
	}
	return "?"
}

// Jump 操作符映射
func getJmpOpSymbol(op asm.JumpOp) string {
	switch op {
	case asm.JEq:
		return "=="
	case asm.JGT:
		return ">"
	case asm.JGE:
		return ">="
	case asm.JSet:
		return "&"
	case asm.JNE:
		return "!="
	case asm.JSGT:
		return ">"
	case asm.JSGE:
		return ">="
	case asm.JLT:
		return "<"
	case asm.JLE:
		return "<="
	case asm.JSLT:
		return "<"
	case asm.JSLE:
		return "<="
	}
	return "?"
}
