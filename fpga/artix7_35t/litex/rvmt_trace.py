from __future__ import annotations

from migen import Array, Cat, Constant, If, Memory, Module, Signal

from litex.soc.interconnect.csr import AutoCSR, CSRStatus, CSRStorage


RVMT_TRACE_EVENT_WORDS = 16


class RVMTTraceRing(Module, AutoCSR):
    """Minimal non-blocking RV-MalTrace event ring.

    The producer presents one 16-word event for one cycle. If the ring cannot
    accept the event immediately, the event is dropped and counted instead of
    stalling the CPU path.
    """

    def __init__(self, depth: int = 256, entry_words: int = RVMT_TRACE_EVENT_WORDS):
        if depth < 2:
            raise ValueError("trace ring depth must be at least 2")
        if entry_words != RVMT_TRACE_EVENT_WORDS:
            raise ValueError("RV-MalTrace board records are fixed at 16 words")

        self.depth = depth
        self.entry_words = entry_words

        index_bits = (depth - 1).bit_length()
        read_addr_bits = (depth * entry_words - 1).bit_length()

        self.sink_valid = Signal(name="rvmt_trace_valid")
        self.sink_event = Signal(4, name="rvmt_trace_event")
        self.sink_priv = Signal(2, name="rvmt_trace_priv")
        self.sink_old_priv = Signal(2, name="rvmt_trace_old_priv")
        self.sink_new_priv = Signal(2, name="rvmt_trace_new_priv")
        self.sink_pc = Signal(32, name="rvmt_trace_pc")
        self.sink_instr = Signal(32, name="rvmt_trace_instr")
        self.sink_target = Signal(32, name="rvmt_trace_target")
        self.sink_cause = Signal(32, name="rvmt_trace_cause")
        self.sink_tval = Signal(32, name="rvmt_trace_tval")
        self.sink_syscall_id = Signal(32, name="rvmt_trace_syscall_id")
        self.sink_duration = Signal(32, name="rvmt_trace_duration")
        self.sink_args = [Signal(32, name=f"rvmt_trace_a{arg}") for arg in range(8)]

        self._control = CSRStorage(
            10,
            reset=0x03d,
            name="control",
            description=(
                "bit0: enable trace capture, bit1: clear ring/drop counters, "
                "bit2: syscall, bit3: trap, bit4: context, bit5: drop accounting, "
                "bit6: branch, bit7: retire, bit8: jump, bit9: arg_mem"
            ),
        )
        self._status = CSRStatus(
            32,
            name="status",
            description="bit0: empty, bit1: full, bit2: writer busy, bits 31:16: depth",
        )
        self._head = CSRStatus(index_bits, name="head", description="Producer head entry index.")
        self._tail = CSRStorage(index_bits, name="tail", description="Consumer tail entry index.")
        self._count = CSRStatus(index_bits + 1, name="count", description="Number of queued trace records.")
        self._drop_count = CSRStatus(32, name="drop_count", description="Dropped trace event count.")
        self._read_index = CSRStorage(
            read_addr_bits,
            name="read_index",
            description="Flat 32-bit word index into the trace ring BRAM.",
        )
        self._read_word = CSRStatus(32, name="read_word", description="Word at read_index.")

        mem = Memory(32, depth * entry_words, name="rvmt_trace_mem")
        write_port = mem.get_port(write_capable=True)
        read_port = mem.get_port(async_read=True)
        self.specials += mem, write_port, read_port

        head = Signal(index_bits)
        count = Signal(index_bits + 1)
        drop_count = Signal(32)
        cycle = Signal(32)
        busy = Signal()
        word_index = Signal(max=entry_words)
        event_words = [Signal(32, name=f"rvmt_trace_capture_word{i}") for i in range(entry_words)]

        enabled = self._control.storage[0]
        clear = self._control.storage[1]
        enable_syscall = self._control.storage[2]
        enable_trap = self._control.storage[3]
        enable_context = self._control.storage[4]
        enable_drop = self._control.storage[5]
        enable_branch = self._control.storage[6]
        enable_retire = self._control.storage[7]
        enable_jump = self._control.storage[8]
        enable_arg_mem = self._control.storage[9]
        full = count == depth
        empty = count == 0
        syscall_event = (self.sink_event == 4) | (self.sink_event == 5)
        trap_event = self.sink_event == 6
        context_event = (self.sink_event == 9) | (self.sink_event == 7) | (self.sink_event == 8)
        branch_event = self.sink_event == 2
        retire_event = self.sink_event == 1
        jump_event = self.sink_event == 3
        arg_mem_event = self.sink_event == 10
        event_enabled = (
            (syscall_event & enable_syscall)
            | (trap_event & enable_trap)
            | (context_event & enable_context)
            | (branch_event & enable_branch)
            | (retire_event & enable_retire)
            | (jump_event & enable_jump)
            | (arg_mem_event & enable_arg_mem)
        )
        accept = self.sink_valid & enabled & event_enabled & ~full & ~busy
        drop = self.sink_valid & enabled & event_enabled & enable_drop & (full | busy)

        write_enable = Signal()

        self.comb += [
            self._status.status.eq(Cat(empty, full, busy, Constant(0, 13), Constant(depth, 16))),
            self._head.status.eq(head),
            self._count.status.eq(count),
            self._drop_count.status.eq(drop_count),
            read_port.adr.eq(self._read_index.storage),
            self._read_word.status.eq(read_port.dat_r),
            write_port.we.eq(write_enable),
            write_port.dat_w.eq(Array(event_words)[word_index]),
            write_port.adr.eq((head * entry_words) + word_index),
        ]

        next_head = Signal(index_bits)
        self.comb += next_head.eq(head + 1)

        captured_header = Cat(
            self.sink_event,
            self.sink_priv,
            self.sink_old_priv,
            self.sink_new_priv,
            Constant(0, 22),
        )
        capture_words = [
            event_words[0].eq(captured_header),
            event_words[1].eq(cycle),
            event_words[2].eq(self.sink_pc),
            event_words[3].eq(self.sink_instr),
            event_words[4].eq(self.sink_cause | self.sink_target),
            event_words[5].eq(self.sink_tval | self.sink_duration),
            event_words[6].eq(self.sink_syscall_id),
            event_words[7].eq(drop_count),
            *(event_words[8 + arg].eq(self.sink_args[arg]) for arg in range(8)),
        ]

        self.sync += [
            write_enable.eq(0),
            If(
                clear,
                head.eq(0),
                count.eq(0),
                drop_count.eq(0),
                cycle.eq(0),
                busy.eq(0),
                word_index.eq(0),
            ).Else(
                cycle.eq(cycle + 1),
                If(
                    accept,
                    *capture_words,
                    busy.eq(1),
                    word_index.eq(0),
                ).Elif(
                    drop,
                    drop_count.eq(drop_count + 1),
                ),
                If(
                    busy,
                    write_enable.eq(1),
                    If(
                        word_index == (entry_words - 1),
                        busy.eq(0),
                        word_index.eq(0),
                        head.eq(next_head),
                        If(count != depth, count.eq(count + 1)),
                    ).Else(
                        word_index.eq(word_index + 1),
                    ),
                ),
                If(self._tail.re & (count != 0), count.eq(count - 1)),
            ),
        ]
