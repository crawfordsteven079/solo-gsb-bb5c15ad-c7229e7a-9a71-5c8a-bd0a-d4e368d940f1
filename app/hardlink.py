"""硬链接解包顺序预演：落盘前判定可执行条目与依赖顺序（纯内存，不访问文件系统）。

输入为按原顺序排列的 ``file`` / ``directory`` / ``hardlink`` 条目；
``hardlink`` 必须携带**归档根相对目标路径**，其余类型不得携带（由 schema
层在请求校验阶段保证，违反时返回 422）。

判定规则（逐条给出阻断原因，全部为内存中的静态分析）：

* 路径规范化沿用 :mod:`app.normalize` 的 Windows 规则与 ``casefold``
  比较键；硬链接目标按**归档根相对**路径（无基准目录）规范化。
* 阻断原因：路径不安全（``UNSAFE_PATH``）、同键重复（``DUPLICATE_KEY``）、
  文件或硬链接占据祖先路径（``BLOCKED_BY_FILE_ANCESTOR``）、目标路径不安全
  （``TARGET_UNSAFE``）、目标缺失（``TARGET_MISSING``）、目标为目录
  （``TARGET_IS_DIRECTORY``）、目标链成环（``TARGET_CYCLE``）；
  目标（含链上中间硬链接）被阻断，或目标键存在多候选（同键重复，无法唯一
  解析）时，引用它的硬链接以 ``TARGET_BLOCKED`` 随之阻断，阻断沿链传播。
  允许硬链接指向后续条目并逐级追踪至普通文件。
* 可执行条目的排序：每一步在“依赖已满足”的可执行条目中取原下标最小者；
  file/directory 无依赖，hardlink 依赖其直接目标条目。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .normalize import IssueSeverity, NormalizedEntry, normalize_entry

FILE_TYPE = "file"
DIR_TYPE = "directory"
HARDLINK_TYPE = "hardlink"
LINK_TARGET_TYPE = "hardlink-target"


class HardlinkEntryType(str, Enum):
    FILE = FILE_TYPE
    DIRECTORY = DIR_TYPE
    HARDLINK = HARDLINK_TYPE


class HardlinkStatus(str, Enum):
    EXECUTABLE = "EXECUTABLE"
    BLOCKED = "BLOCKED"


class HardlinkBlockCode(str, Enum):
    UNSAFE_PATH = "UNSAFE_PATH"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    BLOCKED_BY_FILE_ANCESTOR = "BLOCKED_BY_FILE_ANCESTOR"
    TARGET_UNSAFE = "TARGET_UNSAFE"
    TARGET_MISSING = "TARGET_MISSING"
    TARGET_IS_DIRECTORY = "TARGET_IS_DIRECTORY"
    TARGET_CYCLE = "TARGET_CYCLE"
    TARGET_BLOCKED = "TARGET_BLOCKED"


# 逐条阻断原因在输出中的固定排列顺序。
BLOCK_CODE_ORDER = {
    HardlinkBlockCode.UNSAFE_PATH: 0,
    HardlinkBlockCode.DUPLICATE_KEY: 1,
    HardlinkBlockCode.BLOCKED_BY_FILE_ANCESTOR: 2,
    HardlinkBlockCode.TARGET_UNSAFE: 3,
    HardlinkBlockCode.TARGET_MISSING: 4,
    HardlinkBlockCode.TARGET_IS_DIRECTORY: 5,
    HardlinkBlockCode.TARGET_CYCLE: 6,
    HardlinkBlockCode.TARGET_BLOCKED: 7,
}
_BLOCK_CODE_ORDER = BLOCK_CODE_ORDER


class _TraceKind(str, Enum):
    FILE = "file"  # 链上所有键唯一，追踪到普通文件
    DIRECTORY = "directory"  # 终点是目录
    MISSING = "missing"  # 某跳目标键在清单中无任何条目
    TARGET_UNSAFE = "target_unsafe"  # 某条硬链接自身的目标字符串不安全
    CYCLE = "cycle"  # 再次遇到链上已访问硬链接
    AMBIGUOUS = "ambiguous"  # 某跳目标键存在多候选（fail-closed）


@dataclass(frozen=True)
class HardlinkBlock:
    """单条条目的一项阻断原因。"""

    code: HardlinkBlockCode
    message: str
    related_indices: tuple[int, ...] = ()


@dataclass(frozen=True)
class ChainNode:
    """目标链上经过的一个清单条目。"""

    index: int
    entry_type: str
    canonical_path: str


@dataclass
class _Trace:
    """单条硬链接的静态目标链追踪结果（不考虑各节点的阻断状态）。"""

    nodes: list[ChainNode] = field(default_factory=list)
    kind: _TraceKind = _TraceKind.FILE
    owner_index: int | None = None  # 结构性问题发生处的硬链接下标（终点目录/文件时为最后一条链接）
    terminal_index: int | None = None  # DIRECTORY/FILE 终点条目；CYCLE 为重复点
    ambiguous_indices: tuple[int, ...] = ()  # AMBIGUOUS 时该键的全部候选下标
    cycle_members: tuple[int, ...] = ()  # CYCLE 时环上硬链接下标（按追踪顺序）

    @property
    def direct_target_index(self) -> int | None:
        return self.nodes[0].index if self.nodes else None

    @property
    def resolves_to_file(self) -> bool:
        """链在静态层面唯一追踪到普通文件（未缺失/未成环/非目录/无多候选）。"""
        return self.kind is _TraceKind.FILE


@dataclass
class PlannedEntry:
    """单条条目的预演中间状态。"""

    index: int
    entry_type: str
    original_path: str
    target: str | None  # 硬链接的原始归档根相对目标；其余类型为 None
    normalized: NormalizedEntry
    target_normalized: NormalizedEntry | None = None
    trace: _Trace | None = None
    blocks: dict[HardlinkBlockCode, HardlinkBlock] = field(default_factory=dict)

    @property
    def path_safe(self) -> bool:
        return not self.normalized.unsafe

    @property
    def blocked(self) -> bool:
        return bool(self.blocks)

    @property
    def canonical_path(self) -> str:
        return self.normalized.canonical_path

    @property
    def comparison_key(self) -> str | None:
        return self.normalized.comparison_key


def _error_codes(normalized: NormalizedEntry) -> str:
    return ", ".join(
        issue.code.value
        for issue in normalized.issues
        if issue.severity == IssueSeverity.ERROR
    )


def _trace_hardlink(
    start: PlannedEntry,
    by_index: dict[int, PlannedEntry],
    by_key: dict[str, list[int]],
) -> _Trace:
    """从 ``start`` 出发逐级追踪硬链接目标链（纯静态，不看阻断状态）。

    ``trace.nodes`` 记录命中的目标条目：链经过的硬链接 + 最终终点
    （文件/目录）；成环时额外包含一次重复点以闭合环。``seen``/``chain``
    只追踪**目标侧**命中的硬链接（起点自身由初始状态覆盖，使自环可检出）。
    """
    trace = _Trace()
    current = start
    seen: set[int] = {start.index}
    chain: list[int] = []  # 已命中的目标硬链接下标（不含起点，不含重复点）

    while True:
        # 每条硬链接的目标均按归档根相对解析（target_normalized 已预规范化）。
        target_norm = current.target_normalized
        assert target_norm is not None
        if target_norm.unsafe:
            trace.kind = _TraceKind.TARGET_UNSAFE
            trace.owner_index = current.index
            return trace

        key = target_norm.comparison_key
        candidates = by_key.get(key, []) if key is not None else []
        if not candidates:
            trace.kind = _TraceKind.MISSING
            trace.owner_index = current.index
            return trace
        if len(candidates) > 1:
            # 同键多候选必然伴随（路径安全成员间的）同键重复阻断；
            # fail-closed：链在该键处停下，不任意选取目标。
            trace.kind = _TraceKind.AMBIGUOUS
            trace.owner_index = current.index
            trace.ambiguous_indices = tuple(candidates)
            return trace

        node = by_index[candidates[0]]
        is_cycle = node.entry_type == HARDLINK_TYPE and node.index in seen

        # 链步骤：每个唯一命中的条目都记录（文件/目录为终点，硬链接继续
        # 追踪；成环时记录重复点以闭合环）。
        trace.nodes.append(
            ChainNode(
                index=node.index,
                entry_type=node.entry_type,
                canonical_path=node.canonical_path,
            )
        )

        if node.entry_type == DIR_TYPE:
            trace.kind = _TraceKind.DIRECTORY
            trace.owner_index = current.index
            trace.terminal_index = node.index
            return trace
        if node.entry_type == FILE_TYPE:
            trace.kind = _TraceKind.FILE
            trace.owner_index = current.index
            trace.terminal_index = node.index
            return trace
        if is_cycle:
            trace.kind = _TraceKind.CYCLE
            trace.owner_index = current.index
            trace.terminal_index = node.index
            cycle_chain = [start.index] + chain
            first = cycle_chain.index(node.index)
            trace.cycle_members = tuple(cycle_chain[first:])
            return trace

        seen.add(node.index)
        chain.append(node.index)
        current = node


def _add_block(entry: PlannedEntry, block: HardlinkBlock) -> None:
    existing = entry.blocks.get(block.code)
    if existing is None:
        entry.blocks[block.code] = block
        return
    merged = tuple(sorted(set(existing.related_indices) | set(block.related_indices)))
    entry.blocks[block.code] = HardlinkBlock(
        code=block.code, message=block.message, related_indices=merged
    )


def plan_hardlink_order(
    raw_entries: list[tuple[str, str, str | None]],
) -> tuple[list[PlannedEntry], list[tuple[int, ...]], list[int]]:
    """预演硬链接解包顺序。

    ``raw_entries`` 为 ``(type, path, target)`` 三元组列表，按下标从 1 开始
    编号；``target`` 仅 hardlink 非空。返回

    ``(entries, cycles, execution_order)``：逐条预演状态（保持输入顺序）、
    去重后的硬链接环（每环按下标顺序、从最小下标旋转）与可执行条目的
    执行顺序（原下标列表）。
    """
    entries: list[PlannedEntry] = []
    for i, (entry_type, path, target) in enumerate(raw_entries, start=1):
        normalized = normalize_entry(
            index=i, entry_type=entry_type, original_path=path
        )
        target_norm = None
        if entry_type == HARDLINK_TYPE:
            target_norm = normalize_entry(
                index=i, entry_type=LINK_TARGET_TYPE, original_path=target
            )
        entries.append(
            PlannedEntry(
                index=i,
                entry_type=entry_type,
                original_path=path,
                target=target,
                normalized=normalized,
                target_normalized=target_norm,
            )
        )

    by_index = {e.index: e for e in entries}

    # 比较键 → 条目下标：含路径不安全条目（其 comparison_key 仍可能非空），
    # 使“指向被阻断条目”的硬链接可被识别为 TARGET_BLOCKED 而非误报缺失。
    by_key: dict[str, list[int]] = {}
    for entry in entries:
        if entry.comparison_key is not None:
            by_key.setdefault(entry.comparison_key, []).append(entry.index)

    # --- 阶段 A：自身路径类阻断（不安全路径） ---
    for entry in entries:
        if not entry.path_safe:
            _add_block(
                entry,
                HardlinkBlock(
                    HardlinkBlockCode.UNSAFE_PATH,
                    f"条目路径不安全：{_error_codes(entry.normalized)}",
                ),
            )

    # --- 阶段 A：同键重复（仅路径安全、有效键的条目参与分组） ---
    safe_by_key: dict[str, list[PlannedEntry]] = {}
    for entry in entries:
        if entry.path_safe and entry.comparison_key is not None:
            safe_by_key.setdefault(entry.comparison_key, []).append(entry)
    for members in safe_by_key.values():
        if len(members) < 2:
            continue
        for member in members:
            others = tuple(
                sorted(m.index for m in members if m.index != member.index)
            )
            _add_block(
                member,
                HardlinkBlock(
                    HardlinkBlockCode.DUPLICATE_KEY,
                    f"规范化后与条目 {list(others)} 同键重复，落盘路径不唯一",
                    others,
                ),
            )

    # --- 阶段 A：文件/硬链接占据祖先路径（静态，不看占据者自身是否被阻断） ---
    blockers_by_key: dict[str, list[PlannedEntry]] = {}
    for entry in entries:
        if entry.path_safe and entry.entry_type in (FILE_TYPE, HARDLINK_TYPE):
            blockers_by_key.setdefault(entry.comparison_key, []).append(entry)
    for descendant in entries:
        if not descendant.path_safe:
            continue
        ancestor_indices: set[int] = set()
        parts = descendant.normalized.key_parts
        for depth in range(1, len(parts)):  # 不含自身
            ancestor_key = "/".join(parts[:depth])
            for ancestor in blockers_by_key.get(ancestor_key, ()):
                ancestor_indices.add(ancestor.index)
        if ancestor_indices:
            ordered = tuple(sorted(ancestor_indices))
            _add_block(
                descendant,
                HardlinkBlock(
                    HardlinkBlockCode.BLOCKED_BY_FILE_ANCESTOR,
                    f"祖先路径被文件/硬链接条目 {list(ordered)} 占据，"
                    "无法在该路径下落盘",
                    ordered,
                ),
            )

    # --- 阶段 B：逐条静态追踪目标链 ---
    for entry in entries:
        if entry.entry_type == HARDLINK_TYPE:
            entry.trace = _trace_hardlink(entry, by_index, by_key)

    # 环去重：同一环可能被多条硬链接的追踪发现，按最小下标旋转规范化。
    cycles: list[tuple[int, ...]] = []
    seen_cycles: set[tuple[int, ...]] = set()
    for entry in entries:
        trace = entry.trace
        if trace is None or trace.kind is not _TraceKind.CYCLE:
            continue
        members = trace.cycle_members
        start = members.index(min(members))
        canon = tuple(members[start:] + members[:start])
        if canon not in seen_cycles:
            seen_cycles.add(canon)
            cycles.append(canon)

    # 直接（结构性）目标阻断只归属到问题发生处的那条硬链接：
    # 目标不安全 / 目标缺失 / 目标为目录 / 同键多候选 / 成环（环成员）。
    for entry in entries:
        trace = entry.trace
        if trace is None:
            continue
        owner = by_index[trace.owner_index]
        owner_target_norm = owner.target_normalized
        if trace.kind is _TraceKind.TARGET_UNSAFE:
            codes = _error_codes(owner_target_norm)
            _add_block(
                owner,
                HardlinkBlock(
                    HardlinkBlockCode.TARGET_UNSAFE,
                    f"硬链接目标 {owner.target!r} 不是安全的归档根相对路径：{codes}",
                ),
            )
        elif trace.kind is _TraceKind.MISSING:
            _add_block(
                owner,
                HardlinkBlock(
                    HardlinkBlockCode.TARGET_MISSING,
                    f"硬链接目标 {owner.target!r} 规范化后在清单中无同键条目，"
                    "目标缺失",
                ),
            )
        elif trace.kind is _TraceKind.DIRECTORY:
            idx = trace.terminal_index
            _add_block(
                owner,
                HardlinkBlock(
                    HardlinkBlockCode.TARGET_IS_DIRECTORY,
                    f"目标链终点条目 #{idx}（{by_index[idx].canonical_path}）"
                    "是目录，硬链接只能指向普通文件",
                    (idx,),
                ),
            )
        elif trace.kind is _TraceKind.AMBIGUOUS:
            indices = trace.ambiguous_indices
            _add_block(
                owner,
                HardlinkBlock(
                    HardlinkBlockCode.TARGET_BLOCKED,
                    f"目标同键存在多条条目 {list(indices)}（同键重复），"
                    "无法确定唯一目标，硬链接阻断",
                    tuple(sorted(indices)),
                ),
            )
        elif trace.kind is _TraceKind.CYCLE and owner.index in trace.cycle_members:
            members = trace.cycle_members
            _add_block(
                owner,
                HardlinkBlock(
                    HardlinkBlockCode.TARGET_CYCLE,
                    f"目标链成环（环上硬链接条目 {list(members)}），"
                    "无法追踪到普通文件",
                    tuple(sorted(members)),
                ),
            )

    # --- 阶段 C：阻断沿目标链传播（不动点） ---
    # 硬链接的直接目标条目（含中间硬链接）被阻断时，该硬链接以
    # TARGET_BLOCKED 随之阻断；允许“先阻断下游、下一轮再阻断上游”的级联。
    changed = True
    while changed:
        changed = False
        for entry in entries:
            if entry.entry_type != HARDLINK_TYPE or entry.blocked:
                continue
            target_index = entry.trace.direct_target_index
            if target_index is None:
                continue  # 结构性原因已在阶段 B 归属，不应发生
            node = by_index[target_index]
            if not node.blocked:
                continue
            first_code = sorted(node.blocks, key=lambda c: BLOCK_CODE_ORDER[c])[0]
            _add_block(
                entry,
                HardlinkBlock(
                    HardlinkBlockCode.TARGET_BLOCKED,
                    f"目标链上的条目 #{node.index}（{node.canonical_path}）"
                    f"已被阻断（{first_code.value}），硬链接随之阻断",
                    (node.index,),
                ),
            )
            changed = True

    # --- 阶段 D：可执行条目排序（每步取依赖已满足者中原下标最小的） ---
    executable = {e.index for e in entries if not e.blocked}
    deps: dict[int, int] = {}
    for entry in entries:
        if entry.index not in executable:
            continue
        if entry.entry_type == HARDLINK_TYPE:
            # 可执行硬链接的链至少有一个节点且直接目标必为可执行条目。
            deps[entry.index] = entry.trace.direct_target_index

    scheduled: list[int] = []
    done: set[int] = set()
    remaining = set(executable)
    while remaining:
        ready = sorted(
            i
            for i in remaining
            if i not in deps or deps[i] in done
        )
        chosen = ready[0]
        scheduled.append(chosen)
        done.add(chosen)
        remaining.remove(chosen)

    return entries, cycles, scheduled
