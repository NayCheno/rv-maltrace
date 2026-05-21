from __future__ import annotations

from dataclasses import dataclass
from typing import Any


CONTROL_ENABLE = 0x0001
CONTROL_CLEAR = 0x0002
CONTROL_SYSCALL = 0x0004
CONTROL_TRAP = 0x0008
CONTROL_CONTEXT = 0x0010
CONTROL_DROP = 0x0020
CONTROL_BRANCH = 0x0040
CONTROL_RETIRE = 0x0080
CONTROL_JUMP = 0x0100
CONTROL_ARG_MEM = 0x0200
CONTROL_MARKER = 0x0400


@dataclass(frozen=True)
class TraceProfile:
    name: str
    purpose: str
    enable_syscall: bool
    enable_trap: bool
    enable_context: bool
    enable_drop: bool
    enable_marker: bool = False
    enable_branch: bool = False
    enable_retire: bool = False
    enable_jump: bool = False
    enable_arg_mem: bool = False
    arg_mem_policy: str = "disabled"

    @property
    def trace_controls(self) -> dict[str, Any]:
        return {
            "enable_syscall": self.enable_syscall,
            "enable_trap": self.enable_trap,
            "enable_context": self.enable_context,
            "enable_drop": self.enable_drop,
            "enable_marker": self.enable_marker,
            "enable_branch": self.enable_branch,
            "enable_retire": self.enable_retire,
            "enable_jump": self.enable_jump,
            "enable_arg_mem": self.enable_arg_mem,
            "arg_mem_policy": self.arg_mem_policy,
        }

    @property
    def control_mask(self) -> int:
        mask = 0
        if self.enable_syscall:
            mask |= CONTROL_SYSCALL
        if self.enable_trap:
            mask |= CONTROL_TRAP
        if self.enable_context:
            mask |= CONTROL_CONTEXT
        if self.enable_drop:
            mask |= CONTROL_DROP
        if self.enable_marker:
            mask |= CONTROL_MARKER
        if self.enable_branch:
            mask |= CONTROL_BRANCH
        if self.enable_retire:
            mask |= CONTROL_RETIRE
        if self.enable_jump:
            mask |= CONTROL_JUMP
        if self.enable_arg_mem:
            mask |= CONTROL_ARG_MEM
        return mask

    @property
    def allowed_events(self) -> set[str]:
        events: set[str] = set()
        if self.enable_syscall:
            events.update({"SYSCALL_ENTRY", "SYSCALL_RET"})
        if self.enable_trap:
            events.add("TRAP")
        if self.enable_context:
            events.update({"CSR", "SATP", "PRIV"})
        if self.enable_drop:
            events.add("DROP")
        if self.enable_marker:
            events.add("MARKER")
        if self.enable_branch:
            events.add("BRANCH")
        if self.enable_retire:
            events.add("RETIRE")
        if self.enable_jump:
            events.add("JUMP")
        if self.enable_arg_mem:
            events.add("ARG_MEM")
        return events


TRACE_PROFILES: dict[str, TraceProfile] = {
    "p0_syscall_trap_context": TraceProfile(
        name="p0_syscall_trap_context",
        purpose="correctness first",
        enable_syscall=True,
        enable_trap=True,
        enable_context=True,
        enable_drop=True,
        enable_marker=True,
    ),
    "p1_branch_context": TraceProfile(
        name="p1_branch_context",
        purpose="add control-flow fragments",
        enable_syscall=True,
        enable_trap=True,
        enable_context=True,
        enable_drop=True,
        enable_marker=True,
        enable_branch=True,
    ),
    "p2_pointer_snapshot": TraceProfile(
        name="p2_pointer_snapshot",
        purpose="pointer semantics experiment",
        enable_syscall=True,
        enable_trap=True,
        enable_context=True,
        enable_drop=True,
        enable_marker=True,
        enable_arg_mem=False,
        arg_mem_policy="gated",
    ),
    "p0a_syscall_drop": TraceProfile(
        name="p0a_syscall_drop",
        purpose="syscall entry/return plus DROP only",
        enable_syscall=True,
        enable_trap=False,
        enable_context=False,
        enable_drop=True,
        enable_marker=True,
    ),
    "p0b_trap_drop": TraceProfile(
        name="p0b_trap_drop",
        purpose="trap plus DROP only",
        enable_syscall=False,
        enable_trap=True,
        enable_context=False,
        enable_drop=True,
        enable_marker=True,
    ),
    "p0c_syscall_trap_drop": TraceProfile(
        name="p0c_syscall_trap_drop",
        purpose="syscall/trap plus DROP, no context events",
        enable_syscall=True,
        enable_trap=True,
        enable_context=False,
        enable_drop=True,
        enable_marker=True,
    ),
}


def profile_names() -> list[str]:
    return sorted(TRACE_PROFILES)


def get_trace_profile(name: str | None) -> TraceProfile:
    selected = name or "p0_syscall_trap_context"
    try:
        return TRACE_PROFILES[selected]
    except KeyError as exc:
        raise ValueError(f"unknown trace profile: {selected}") from exc


def trace_controls_for_profile(name: str | None) -> dict[str, Any]:
    return get_trace_profile(name).trace_controls


def trace_control_mask_for_profile(name: str | None) -> int:
    return get_trace_profile(name).control_mask


def allowed_events_for_profile(name: str | None) -> set[str]:
    return get_trace_profile(name).allowed_events
