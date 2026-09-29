"""含硬链接解包清单的落盘前预演：阻断判定、目标链追踪与可执行顺序（纯内存）。

输入为按原顺序排列的 ``file`` / ``directory`` / ``hardlink`` 条目；hardlink
必须携带**归档根相对**目标路径，其余类型不得携带（schema 层强制，违规 422）。

条目路径与硬链接目标均复用 :mod:`app.normalize` 的 Windows 规范化与
``casefold`` 比较键，全程词法计算，不访问文件系统。

逐条阻断原因（``HardlinkBlockReason``）：

* ``UNSAFE_PATH``：条目自身路径规范化不安全（绝对/UNC/盘符/越界 ``..``/
  保留设备名/非法字符/空路径等）。
* ``DUPLICATE_KEY``：安全条目之间规范化比较键相同（同键重复）；同键全部
  成员都阻断，``related_indices`` 列出同键的其他下标。
* ``LEAF_ANCESTOR``：本条目（任一类型）的祖先路径被一条**文件或硬链接**
  （叶子类型）条目占据（该祖先自身是否另行被阻断均阻断后代）。
* ``TARGET_PATH_UNSAFE``：硬链接目标为空或规范化不安全（越界、保留名、
  非法字符、空路径等）。
* ``TARGET_MISSING``：硬链接目标比较键不对应任何安全条目（不存在，或仅被
  不安全路径条目占据）。
* ``TARGET_AMBIGUOUS``：硬链接目标比较键命中同键重复组（目标身份不唯一）。
* ``TARGET_IS_DIRECTORY``：硬链接直接指向的是目录（硬链接只能指向普通文件，
  不能逐级穿过目录）。
* ``TARGET_CYCLE``：硬链接目标链成环（再次沿链遇到已经过的硬链接）。
* ``TARGET_BLOCKED``：目标链途经的条目本身被阻断（链上首个阻断节点，含最终
  普通文件被阻断的情形）；目标阻断沿链传播。

每条条目可同时携带多个阻断原因；``primary_block_reason`` 取其中枚举序最靠前
（最根本）的一个，便于调用方快速分类。环判定为纯结构属性（沿 ok 边追踪，与
阻断状态无关），结果不依赖条目遍历顺序。

可执行顺序（硬链接只依赖其**直接目标**——落盘时只需直接目标已存在）：每一步
在“未排定且自身未阻断且依赖已满足”的条目中选**原下标最小**者；文件与目录
无依赖，硬链接依赖其直接目标条目（必为文件或硬链接）已排定。最终无解的条目
必然均为被阻断条目。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .normalize import NormalizedEntry, normalize_entry

FILE_TYPE = "file"
DIR_TYPE = "directory"
HARDLINK_TYPE = "hardlink"

LEAF_TYPES = frozenset({FILE_TYPE, HARDLINK_TYPE})


class HardlinkStatus(str, Enum):
    EXECUTABLE = "EXECUTABLE"
    BLOCKED = "BLOCKED"


class HardlinkBlockReason(str, Enum):
    UNSAFE_PATH = "UNSAFE_PATH"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    LEAF_ANCESTOR = "LEAF_ANCESTOR"
    TARGET_PATH_UNSAFE = "TARGET_PATH_UNSAFE"
    TARGET_MISSING = "TARGET_MISSING"
    TARGET_AMBIGUOUS = "TARGET_AMBIGUOUS"
    TARGET_IS_DIRECTORY = "TARGET_IS_DIRECTORY"
    TARGET_CYCLE = "TARGET_CYCLE"
    TARGET_BLOCKED = "TARGET_BLOCKED"


@dataclass(frozen=True)
class ChainNode:
    """目标链上的一跳：清单条目下标与该条目规范化展示路径。"""

    index: int
    canonical_path: str


@dataclass
class HardlinkPlanEntry:
    """单条条目的预演结果（保持输入顺序，下标从 1 开始）。"""

    index: int
    entry_type: str  # "file" | "directory" | "hardlink"
    original_path: str
    link_target: str | None  # 仅 hardlink 回显原始目标字符串
    canonical_path: str
    comparison_key: str | None
    safe: bool
    # hardlink 目标规范化（归档根相对）后的展示路径；无目标或目标路径
    # 不安全时为 None。
    resolved_target_path: str | None = None
    block_reasons: list[HardlinkBlockReason] = field(default_factory=list)
    # 每个阻断原因对应的相关条目下标（如同键其他成员、占据祖先的叶子、
    # 链上首个阻断节点）；无关联时键不存在。
    related_indices_by_reason: dict[HardlinkBlockReason, list[int]] = field(
        default_factory=dict
    )
    target_chain: list[ChainNode] = field(default_factory=list)
    # 目标链逐级追踪到的最终普通文件下标；未能到达普通文件时为 None。
    final_file_index: int | None = None
    # 执行序号（从 1 开始）；被阻断条目为 None。
    execution_order: int | None = None

    @property
    def status(self) -> HardlinkStatus:
        return (
            HardlinkStatus.BLOCKED
            if self.block_reasons
            else HardlinkStatus.EXECUTABLE
        )

    @property
    def primary_block_reason(self) -> HardlinkBlockReason | None:
        if not self.block_reasons:
            return None
        return min(
            self.block_reasons, key=lambda r: list(HardlinkBlockReason).index(r)
        )


@dataclass
class HardlinkPlan:
    """整批清单的预演结果。"""

    entries: list[HardlinkPlanEntry]
    execution_order: list[int]  # 可执行条目下标，按执行顺序排列


def _norm_target(target: str) -> NormalizedEntry:
    """按归档根相对规则规范化硬链接目标（无 initial_parts）。"""
    return normalize_entry(
        index=-1, entry_type="hardlink-target", original_path=target
    )


def plan_hardlinks(
    entries: list[NormalizedEntry],
    link_targets: dict[int, str],
) -> HardlinkPlan:
    """对整批条目做硬链接落盘前预演。

    ``entries`` 已由调用方按输入顺序规范化（``index`` 从 1 开始）；
    ``link_targets`` 提供 hardlink 条目的原始目标字符串。
    本函数不修改 ``entries``（阻断原因只保存在返回的计划对象中）。
    """
    by_index = {e.index: e for e in entries}

    plan: dict[int, HardlinkPlanEntry] = {}
    for entry in entries:
        plan[entry.index] = HardlinkPlanEntry(
            index=entry.index,
            entry_type=entry.entry_type,
            original_path=entry.original_path,
            link_target=link_targets.get(entry.index),
            canonical_path=entry.canonical_path,
            comparison_key=entry.comparison_key,
            safe=not entry.unsafe,
        )

    def add_reason(
        index: int,
        reason: HardlinkBlockReason,
        related: list[int] | None = None,
    ) -> None:
        entry_plan = plan[index]
        if reason not in entry_plan.block_reasons:
            entry_plan.block_reasons.append(reason)
        if related:
            existed = entry_plan.related_indices_by_reason.setdefault(reason, [])
            # TARGET_CYCLE 的相关下标是“再次命中的链上节点”，自环 h→h 时即
            # 条目自身，仍需保留；其余原因跳过自身。
            for rel in related:
                if rel != index or reason is HardlinkBlockReason.TARGET_CYCLE:
                    if rel not in existed:
                        existed.append(rel)
            existed.sort()

    # 1) 不安全路径。
    for entry in entries:
        if entry.unsafe:
            add_reason(entry.index, HardlinkBlockReason.UNSAFE_PATH)

    # 2) 同键重复（仅安全条目建立键身份；不安全条目不参与）。
    key_members: dict[str, list[int]] = {}
    for entry in entries:
        if entry.unsafe or entry.comparison_key is None:
            continue
        key_members.setdefault(entry.comparison_key, []).append(entry.index)
    duplicate_keys = {key for key, m in key_members.items() if len(m) >= 2}
    unique_by_key: dict[str, int] = {
        key: members[0] for key, members in key_members.items() if len(members) == 1
    }
    for key in duplicate_keys:
        for member in key_members[key]:
            add_reason(
                member,
                HardlinkBlockReason.DUPLICATE_KEY,
                related=[m for m in key_members[key] if m != member],
            )

    # 祖先路径上的叶子（文件/硬链接）成员索引；含同键重复组的全部叶子成员。
    leaf_members_by_key: dict[str, list[int]] = {
        key: [i for i in members if by_index[i].entry_type in LEAF_TYPES]
        for key, members in key_members.items()
    }

    # 3) 文件/硬链接占据祖先路径（叶子祖先），对任意后代类型生效。
    for descendant in entries:
        if descendant.unsafe:
            continue
        for depth in range(1, len(descendant.key_parts)):  # 不含自身
            occupants = leaf_members_by_key.get(
                "/".join(descendant.key_parts[:depth])
            )
            if occupants:
                add_reason(
                    descendant.index,
                    HardlinkBlockReason.LEAF_ANCESTOR,
                    related=occupants,
                )

    # 4) 硬链接直接目标解析（仅自身路径安全的硬链接）。
    #    direct[i] 形态：
    #    ("ok", 目标下标) | ("missing",) | ("ambiguous", 同键成员) |
    #    ("directory", 目录下标) | ("unsafe",)
    direct: dict[int, tuple] = {}
    for entry in entries:
        if entry.entry_type != HARDLINK_TYPE or entry.unsafe:
            continue
        p = plan[entry.index]
        target = link_targets[entry.index]
        normalized_target = _norm_target(target)
        if target == "" or normalized_target.unsafe:
            add_reason(entry.index, HardlinkBlockReason.TARGET_PATH_UNSAFE)
            direct[entry.index] = ("unsafe",)
            continue
        p.resolved_target_path = normalized_target.canonical_path
        target_key = normalized_target.comparison_key

        if target_key in duplicate_keys:
            members = key_members[target_key]
            add_reason(
                entry.index,
                HardlinkBlockReason.TARGET_AMBIGUOUS,
                related=members,
            )
            direct[entry.index] = ("ambiguous", members)
        elif target_key not in unique_by_key:
            add_reason(entry.index, HardlinkBlockReason.TARGET_MISSING)
            direct[entry.index] = ("missing",)
        else:
            target_index = unique_by_key[target_key]
            if by_index[target_index].entry_type == DIR_TYPE:
                add_reason(
                    entry.index,
                    HardlinkBlockReason.TARGET_IS_DIRECTORY,
                    related=[target_index],
                )
                direct[entry.index] = ("directory", target_index)
            else:
                direct[entry.index] = ("ok", target_index)

    def node(index: int) -> ChainNode:
        return ChainNode(index, by_index[index].canonical_path)

    # 5) 沿链追踪（纯结构判定，与节点阻断状态无关，保证结果与遍历顺序无关）：
    #    普通文件结束；硬链接继续；再次遇到链上硬链接即 TARGET_CYCLE；
    #    缺目/歧义/目录/目标不安全按链位置归类（起点为自身原因，途经点传播
    #    TARGET_BLOCKED）；正常到达的链上若存在被阻断节点也传播 TARGET_BLOCKED。
    for entry in entries:
        if entry.entry_type != HARDLINK_TYPE or entry.unsafe:
            continue
        idx = entry.index
        p = plan[idx]
        own_direct = direct[idx]
        # 起点目标即缺目/歧义/目录/不安全：目标链只有自身（目录追加目录节点）
        # 或为空（目标路径不安全，无可解析路径），无需沿链追踪。
        chain: list[ChainNode] = []
        if own_direct[0] != "unsafe":
            chain = [node(idx)]
        visited = {idx}
        current = idx
        final_file: int | None = None

        if own_direct[0] in ("missing", "ambiguous"):
            pass  # 直接目标原因已在解析阶段添加
        elif own_direct[0] == "directory":
            chain.append(node(own_direct[1]))
        elif own_direct[0] == "unsafe":
            pass
        else:
            while True:
                outcome = direct.get(current)
                if outcome is None or outcome[0] == "unsafe":
                    # 只可能发生在途经硬链接（起点 unsafe 已在外层排除）。
                    if current != idx:
                        add_reason(
                            idx,
                            HardlinkBlockReason.TARGET_BLOCKED,
                            related=[current],
                        )
                    break

                kind = outcome[0]
                if kind in ("missing", "ambiguous"):
                    if current != idx:
                        add_reason(
                            idx,
                            HardlinkBlockReason.TARGET_BLOCKED,
                            related=[current],
                        )
                    break
                if kind == "directory":
                    chain.append(node(outcome[1]))
                    if current != idx:
                        add_reason(
                            idx,
                            HardlinkBlockReason.TARGET_BLOCKED,
                            related=[current],
                        )
                    break

                # kind == "ok"
                target_index = outcome[1]
                chain.append(node(target_index))
                target_entry = by_index[target_index]
                if target_entry.entry_type == FILE_TYPE:
                    final_file = target_index
                    break
                if target_index in visited:
                    add_reason(
                        idx,
                        HardlinkBlockReason.TARGET_CYCLE,
                        related=[target_index],
                    )
                    break
                visited.add(target_index)
                current = target_index

        # 结构上到达普通文件：检查链上（除自身外）首个被阻断节点并传播。
        if final_file is not None:
            for stepped in chain[1:]:
                if plan[stepped.index].block_reasons:
                    add_reason(
                        idx,
                        HardlinkBlockReason.TARGET_BLOCKED,
                        related=[stepped.index],
                    )
                    break

        p.target_chain = chain
        p.final_file_index = final_file

    # 6) 可执行顺序：文件/目录无依赖；硬链接依赖其**直接目标**已落盘。
    #    每步在依赖已满足的未排定条目中选原下标最小者。
    executable = {idx for idx, p in plan.items() if not p.block_reasons}
    deps: dict[int, int] = {}
    for entry in entries:
        if entry.entry_type == HARDLINK_TYPE and entry.index in executable:
            deps[entry.index] = direct[entry.index][1]  # 直接目标下标

    order: list[int] = []
    placed: set[int] = set()
    remaining = set(executable)
    while remaining:
        ready = sorted(
            idx for idx in remaining if idx not in deps or deps[idx] in placed
        )
        if not ready:
            # 不可达：可执行硬链接必无环地追踪到可执行普通文件。
            break
        chosen = ready[0]
        order.append(chosen)
        placed.add(chosen)
        remaining.remove(chosen)

    for position, idx in enumerate(order, start=1):
        plan[idx].execution_order = position

    return HardlinkPlan(
        entries=[plan[e.index] for e in entries],
        execution_order=order,
    )
