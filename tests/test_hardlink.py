"""hardlink-order：硬链接解包顺序预演测试（目标链追踪、阻断传播与依赖排序）。"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _post(payload):
    return client.post("/api/v1/hardlink-order", json=payload)


def _plan(entries):
    r = _post({"entries": entries})
    assert r.status_code == 200, r.text
    return r.json()


def _by_index(body):
    return {e["index"]: e for e in body["entries"]}


# ---------------------------------------------------------------------------
# 请求校验（422）
# ---------------------------------------------------------------------------


def test_hardlink_requires_target():
    r = _post({"entries": [{"path": "a", "type": "hardlink"}]})
    assert r.status_code == 422


def test_file_and_directory_must_not_carry_target():
    for entry_type in ("file", "directory"):
        r = _post(
            {"entries": [{"path": "a", "type": entry_type, "target": "x"}]}
        )
        assert r.status_code == 422


def test_empty_entries_rejected():
    r = _post({"entries": []})
    assert r.status_code == 422


def test_empty_target_string_is_per_entry_block_not_422():
    body = _plan([{"path": "h", "type": "hardlink", "target": ""}])
    entry = body["entries"][0]
    assert entry["status"] == "BLOCKED"
    assert [b["code"] for b in entry["blocks"]] == ["TARGET_UNSAFE"]


# ---------------------------------------------------------------------------
# 执行顺序：无依赖/直接依赖、前向引用、最小下标
# ---------------------------------------------------------------------------


def test_files_and_directories_execute_in_original_order():
    body = _plan(
        [
            {"path": "a.txt", "type": "file"},
            {"path": "d", "type": "directory"},
            {"path": "b.txt", "type": "file"},
        ]
    )
    assert body["execution_order"] == [1, 2, 3]
    by = _by_index(body)
    assert [by[i]["execution_order"] for i in (1, 2, 3)] == [1, 2, 3]
    assert by[1]["final_file_index"] == 1
    assert by[2]["final_file_index"] is None
    assert by[3]["final_file_index"] == 3


def test_forward_reference_hardlink_waits_for_later_target():
    # #1 硬链接指向后面的 #2 文件：#2 先执行，#1 后执行。
    body = _plan(
        [
            {"path": "h1", "type": "hardlink", "target": "real.txt"},
            {"path": "real.txt", "type": "file"},
        ]
    )
    assert body["execution_order"] == [2, 1]
    by = _by_index(body)
    assert by[1]["execution_order"] == 2
    assert by[1]["final_file_index"] == 2
    assert by[2]["execution_order"] == 1


def test_chain_trace_step_by_step_and_ordering():
    # #1 -> #2(link) -> #4(file)；#3 是无依赖目录。
    # 就绪顺序：#3 先（最小），#4 其次（#2 的依赖），再 #2，再 #1。
    body = _plan(
        [
            {"path": "a/link1", "type": "hardlink", "target": "a/link2"},
            {"path": "a/link2", "type": "hardlink", "target": "b/real.txt"},
            {"path": "b", "type": "directory"},
            {"path": "b/real.txt", "type": "file"},
        ]
    )
    assert body["execution_order"] == [3, 4, 2, 1]
    by = _by_index(body)
    assert by[1]["target_chain"] == [
        {"step": 1, "index": 2, "type": "hardlink", "canonical_path": "a/link2"},
        {"step": 2, "index": 4, "type": "file", "canonical_path": "b/real.txt"},
    ]
    assert by[1]["final_file_index"] == 4
    assert by[2]["target_chain"] == [
        {"step": 1, "index": 4, "type": "file", "canonical_path": "b/real.txt"},
    ]
    assert by[2]["final_file_index"] == 4
    assert all(e["status"] == "EXECUTABLE" for e in body["entries"])


def test_windows_comparison_key_matches_target():
    body = _plan(
        [
            {"path": "Links\\Alias.TXT ", "type": "hardlink", "target": "docs/link.txt"},
            {"path": "docs/link.txt", "type": "file"},
        ]
    )
    by = _by_index(body)
    assert by[1]["comparison_key"] == "links/alias.txt"
    assert by[1]["target_canonical_path"] == "docs/link.txt"
    assert by[1]["status"] == "EXECUTABLE"
    assert by[1]["final_file_index"] == 2


# ---------------------------------------------------------------------------
# 阻断：不安全路径
# ---------------------------------------------------------------------------


def test_unsafe_entry_path_blocks_entry():
    body = _plan(
        [
            {"path": "../evil.bin", "type": "file"},
            {"path": "CON", "type": "directory"},
        ]
    )
    by = _by_index(body)
    assert [b["code"] for b in by[1]["blocks"]] == ["UNSAFE_PATH"]
    assert [b["code"] for b in by[2]["blocks"]] == ["UNSAFE_PATH"]
    assert body["execution_order"] == []


def test_hardlink_to_unsafe_target_blocks_via_propagation():
    # #1 -> #2(hardlink, 自身路径安全但目标越界)：#2 TARGET_UNSAFE，
    # #1 由传播得到 TARGET_BLOCKED。
    body = _plan(
        [
            {"path": "h1", "type": "hardlink", "target": "h2"},
            {"path": "h2", "type": "hardlink", "target": "../escape"},
        ]
    )
    by = _by_index(body)
    assert [b["code"] for b in by[2]["blocks"]] == ["TARGET_UNSAFE"]
    assert [b["code"] for b in by[1]["blocks"]] == ["TARGET_BLOCKED"]
    assert by[1]["blocks"][0]["related_indices"] == [2]
    assert by[1]["target_chain"] == [
        {"step": 1, "index": 2, "type": "hardlink", "canonical_path": "h2"}
    ]


def test_root_relative_target_with_leading_slash_is_unsafe():
    body = _plan([{"path": "h", "type": "hardlink", "target": "/etc/passwd"}])
    assert [b["code"] for b in body["entries"][0]["blocks"]] == ["TARGET_UNSAFE"]


# ---------------------------------------------------------------------------
# 阻断：同键重复
# ---------------------------------------------------------------------------


def test_duplicate_comparison_key_blocks_all_members():
    body = _plan(
        [
            {"path": "Dup", "type": "file"},
            {"path": "dup", "type": "file"},
            {"path": "DUP", "type": "directory"},
        ]
    )
    by = _by_index(body)
    for i in (1, 2, 3):
        codes = [b["code"] for b in by[i]["blocks"]]
        assert codes == ["DUPLICATE_KEY"]
        assert by[i]["blocks"][0]["related_indices"]
    assert by[1]["blocks"][0]["related_indices"] == [2, 3]
    assert by[2]["blocks"][0]["related_indices"] == [1, 3]
    assert by[3]["blocks"][0]["related_indices"] == [1, 2]
    assert body["execution_order"] == []


def test_hardlink_target_ambiguous_is_target_blocked():
    # 两个同键文件：硬链接目标无法唯一解析，fail-closed。
    body = _plan(
        [
            {"path": "h", "type": "hardlink", "target": "f"},
            {"path": "f", "type": "file"},
            {"path": "F", "type": "file"},
        ]
    )
    by = _by_index(body)
    assert [b["code"] for b in by[1]["blocks"]] == ["TARGET_BLOCKED"]
    assert by[1]["blocks"][0]["related_indices"] == [2, 3]
    # 链在多候选处不任意选取，不产生链步骤。
    assert by[1]["target_chain"] == []
    assert by[1]["final_file_index"] is None


# ---------------------------------------------------------------------------
# 阻断：文件/硬链接占据祖先路径
# ---------------------------------------------------------------------------


def test_file_ancestor_blocks_descendant():
    body = _plan(
        [
            {"path": "a/b", "type": "file"},
            {"path": "a/b/c.txt", "type": "file"},
            {"path": "a/b/d", "type": "directory"},
        ]
    )
    by = _by_index(body)
    assert by[1]["blocks"] == []
    assert [b["code"] for b in by[2]["blocks"]] == [
        "BLOCKED_BY_FILE_ANCESTOR"
    ]
    assert by[2]["blocks"][0]["related_indices"] == [1]
    assert [b["code"] for b in by[3]["blocks"]] == [
        "BLOCKED_BY_FILE_ANCESTOR"
    ]


def test_hardlink_ancestor_blocks_descendant():
    body = _plan(
        [
            {"path": "a/real.txt", "type": "file"},
            {"path": "a/ln", "type": "hardlink", "target": "a/real.txt"},
            {"path": "a/ln/child", "type": "file"},
        ]
    )
    by = _by_index(body)
    assert by[3]["status"] == "BLOCKED"
    assert [b["code"] for b in by[3]["blocks"]] == [
        "BLOCKED_BY_FILE_ANCESTOR"
    ]
    assert by[3]["blocks"][0]["related_indices"] == [2]


def test_directory_ancestor_is_normal_layout():
    body = _plan(
        [
            {"path": "a", "type": "directory"},
            {"path": "a/b.txt", "type": "file"},
        ]
    )
    by = _by_index(body)
    assert all(e["status"] == "EXECUTABLE" for e in by.values())


# ---------------------------------------------------------------------------
# 阻断：目标缺失 / 目标为目录
# ---------------------------------------------------------------------------


def test_target_missing_blocks_only_that_link():
    body = _plan(
        [
            {"path": "h", "type": "hardlink", "target": "no/such"},
            {"path": "keep.txt", "type": "file"},
        ]
    )
    by = _by_index(body)
    assert [b["code"] for b in by[1]["blocks"]] == ["TARGET_MISSING"]
    assert by[1]["target_chain"] == []
    assert by[2]["status"] == "EXECUTABLE"
    assert body["execution_order"] == [2]


def test_target_directory_blocks_link():
    body = _plan(
        [
            {"path": "d", "type": "directory"},
            {"path": "h", "type": "hardlink", "target": "d"},
            {"path": "h2", "type": "hardlink", "target": "h"},
        ]
    )
    by = _by_index(body)
    assert [b["code"] for b in by[2]["blocks"]] == ["TARGET_IS_DIRECTORY"]
    assert by[2]["blocks"][0]["related_indices"] == [1]
    # 指向“目标为目录”的硬链接：阻断沿链传播。
    assert [b["code"] for b in by[3]["blocks"]] == ["TARGET_BLOCKED"]
    assert by[3]["blocks"][0]["related_indices"] == [2]


# ---------------------------------------------------------------------------
# 阻断：目标链成环
# ---------------------------------------------------------------------------


def test_three_member_cycle_and_outer_reference():
    body = _plan(
        [
            {"path": "c1", "type": "hardlink", "target": "c2"},
            {"path": "c2", "type": "hardlink", "target": "c3"},
            {"path": "c3", "type": "hardlink", "target": "c1"},
            {"path": "outer", "type": "hardlink", "target": "c2"},
            {"path": "real.txt", "type": "file"},
        ]
    )
    by = _by_index(body)
    for i in (1, 2, 3):
        assert [b["code"] for b in by[i]["blocks"]] == ["TARGET_CYCLE"]
    assert body["cycles"] == [{"members": [1, 2, 3]}]
    # 环上成员的目标链含重复点以闭合环。
    assert [step["index"] for step in by[1]["target_chain"]] == [2, 3, 1]
    assert by[1]["final_file_index"] is None
    # 环外引用方由传播阻断。
    assert [b["code"] for b in by[4]["blocks"]] == ["TARGET_BLOCKED"]
    assert by[4]["blocks"][0]["related_indices"] == [2]
    # 不相关文件照常可执行。
    assert by[5]["status"] == "EXECUTABLE"
    assert body["execution_order"] == [5]


def test_self_cycle():
    body = _plan([{"path": "c", "type": "hardlink", "target": "c"}])
    by = _by_index(body)
    assert [b["code"] for b in by[1]["blocks"]] == ["TARGET_CYCLE"]
    assert body["cycles"] == [{"members": [1]}]
    assert [step["index"] for step in by[1]["target_chain"]] == [1]


def test_chain_entering_cycle_via_tail_is_propagated():
    # #1 -> #2 -> #3 <-> #4；#1/#2 在环外。
    body = _plan(
        [
            {"path": "x1", "type": "hardlink", "target": "x2"},
            {"path": "x2", "type": "hardlink", "target": "x3"},
            {"path": "x3", "type": "hardlink", "target": "x4"},
            {"path": "x4", "type": "hardlink", "target": "x3"},
        ]
    )
    by = _by_index(body)
    assert body["cycles"] == [{"members": [3, 4]}]
    assert [b["code"] for b in by[3]["blocks"]] == ["TARGET_CYCLE"]
    assert [b["code"] for b in by[4]["blocks"]] == ["TARGET_CYCLE"]
    assert [b["code"] for b in by[2]["blocks"]] == ["TARGET_BLOCKED"]
    assert [b["code"] for b in by[1]["blocks"]] == ["TARGET_BLOCKED"]
    # 传播阻断关系逐级记录。
    assert by[2]["blocks"][0]["related_indices"] == [3]
    assert by[1]["blocks"][0]["related_indices"] == [2]


# ---------------------------------------------------------------------------
# 多原因叠加与原因排序
# ---------------------------------------------------------------------------


def test_entry_can_have_multiple_block_reasons_in_fixed_order():
    # #1 dup/#3 DUP 同键重复；#1 又是 #2 硬链接缺失目标外的祖先场景：
    # 构造一个既同键重复又被文件祖先占据的条目。
    body = _plan(
        [
            {"path": "a/b", "type": "file"},          # 1
            {"path": "a/b", "type": "hardlink", "target": "r"},  # 2 与 #1 同键
            {"path": "a/b/c", "type": "file"},        # 3 被 #1/#2 占据祖先
            {"path": "r", "type": "file"},            # 4
        ]
    )
    by = _by_index(body)
    # #2 同键重复（硬链接本身），其目标存在，所以仅 DUPLICATE_KEY。
    assert [b["code"] for b in by[2]["blocks"]] == ["DUPLICATE_KEY"]
    # #3 被 #1（文件）与 #2（硬链接）两个同键祖先占据。
    assert [b["code"] for b in by[3]["blocks"]] == [
        "BLOCKED_BY_FILE_ANCESTOR"
    ]
    assert by[3]["blocks"][0]["related_indices"] == [1, 2]


def test_unsafe_self_path_and_target_missing_both_reported():
    body = _plan(
        [{"path": "../esc", "type": "hardlink", "target": "no/such"}]
    )
    codes = [b["code"] for b in body["entries"][0]["blocks"]]
    assert codes == ["UNSAFE_PATH", "TARGET_MISSING"]


# ---------------------------------------------------------------------------
# 汇总与整体结构
# ---------------------------------------------------------------------------


def test_summary_counts():
    body = _plan(
        [
            {"path": "f1", "type": "file"},
            {"path": "d1", "type": "directory"},
            {"path": "h1", "type": "hardlink", "target": "f1"},
            {"path": "bad", "type": "hardlink", "target": "missing"},
        ]
    )
    assert body["summary"] == {
        "total": 4,
        "files": 1,
        "directories": 1,
        "hardlinks": 2,
        "executable": 3,
        "blocked": 1,
        "executable_files": 1,
        "executable_directories": 1,
        "executable_hardlinks": 1,
        "cycles": 0,
    }
    # 执行顺序：#1/#2/#3 均可执行，#3 依赖 #1。
    # 第一步就绪者 {1,2} 取 1；第二步就绪 {2,3} 取 2；第三步 3。
    assert body["execution_order"] == [1, 2, 3]
    by = _by_index(body)
    assert by[3]["execution_order"] == 3
    assert by[3]["final_file_index"] == 1


def test_non_hardlink_entries_have_no_target_fields():
    body = _plan(
        [
            {"path": "f", "type": "file"},
            {"path": "d", "type": "directory"},
        ]
    )
    for entry in body["entries"]:
        assert entry["target"] is None
        assert entry["target_canonical_path"] is None
        assert entry["target_chain"] == []


def test_multiple_cycles_sorted_by_minimum_member():
    # 两个独立环：#4/#5（大环）在前，#1/#2（小环）在后；输出按最小成员升序。
    body = _plan(
        [
            {"path": "p4", "type": "hardlink", "target": "p5"},
            {"path": "p5", "type": "hardlink", "target": "p4"},
            {"path": "f.txt", "type": "file"},
            {"path": "q1", "type": "hardlink", "target": "q2"},
            {"path": "q2", "type": "hardlink", "target": "q3"},
            {"path": "q3", "type": "hardlink", "target": "q1"},
        ]
    )
    assert [cyc["members"] for cyc in body["cycles"]] == [[1, 2], [4, 5, 6]]
    by = _by_index(body)
    # 各环追踪的 members 从最小下标旋转。
    assert [s["index"] for s in by[5]["target_chain"]] == [6, 4, 5]
    assert body["execution_order"] == [3]


def test_hardlink_to_unsafe_root_relative_target_is_unsafe():
    # 根相对目标 ../evil 越界（硬链接目标不相对链接目录解析）。
    body = _plan(
        [
            {"path": "../evil", "type": "file"},
            {"path": "h", "type": "hardlink", "target": "../evil"},
        ]
    )
    by = _by_index(body)
    assert [b["code"] for b in by[1]["blocks"]] == ["UNSAFE_PATH"]
    assert [b["code"] for b in by[2]["blocks"]] == ["TARGET_UNSAFE"]


def test_hardlink_pointing_at_blocked_unique_hardlink_is_blocked():
    # 唯一键命中的硬链接因目标缺失而被阻断（自身路径安全）：
    # 引用方传播阻断，链可见。
    body = _plan(
        [
            {"path": "mid", "type": "hardlink", "target": "ghost"},
            {"path": "h", "type": "hardlink", "target": "mid"},
        ]
    )
    by = _by_index(body)
    assert [b["code"] for b in by[1]["blocks"]] == ["TARGET_MISSING"]
    assert [b["code"] for b in by[2]["blocks"]] == ["TARGET_BLOCKED"]
    assert by[2]["blocks"][0]["related_indices"] == [1]
    assert [s["index"] for s in by[2]["target_chain"]] == [1]
    assert by[2]["final_file_index"] is None
    assert body["execution_order"] == []


def test_hardlink_pointing_at_duplicate_key_is_ambiguous_block():
    # 两个同键文件：多候选 fail-closed，不产生链步骤。
    body = _plan(
        [
            {"path": "d", "type": "file"},
            {"path": "D", "type": "file"},
            {"path": "h", "type": "hardlink", "target": "d"},
        ]
    )
    by = _by_index(body)
    assert [b["code"] for b in by[3]["blocks"]] == ["TARGET_BLOCKED"]
    assert by[3]["blocks"][0]["related_indices"] == [1, 2]
    assert by[3]["target_chain"] == []
    assert by[3]["final_file_index"] is None
    assert body["execution_order"] == []


def test_grandchild_blocked_by_propagation_and_chain_visible():
    body = _plan(
        [
            {"path": "a1", "type": "hardlink", "target": "a2"},
            {"path": "a2", "type": "hardlink", "target": "a3"},
            {"path": "a3", "type": "hardlink", "target": "ghost"},
        ]
    )
    by = _by_index(body)
    assert [b["code"] for b in by[3]["blocks"]] == ["TARGET_MISSING"]
    assert [b["code"] for b in by[2]["blocks"]] == ["TARGET_BLOCKED"]
    assert [b["code"] for b in by[1]["blocks"]] == ["TARGET_BLOCKED"]
    # 目标链展示静态追踪经过的条目（问题发生处之前的部分）。
    assert [s["index"] for s in by[1]["target_chain"]] == [2, 3]
    assert [s["index"] for s in by[2]["target_chain"]] == [3]
    assert by[3]["target_chain"] == []
