"""hardlink-preview：含硬链接清单的落盘前预演测试（阻断、目标链与执行顺序）。"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _post(payload):
    return client.post("/api/v1/hardlink-preview", json=payload)


def _plan(entries):
    r = _post({"entries": entries})
    assert r.status_code == 200, r.text
    return r.json()


def _by_index(body):
    return {e["index"]: e for e in body["entries"]}


def _reasons(entry):
    return {b["reason"]: b["related_indices"] for b in entry["block_reasons"]}


# ---------------------------------------------------------------------------
# 基本执行顺序
# ---------------------------------------------------------------------------


def test_plain_files_and_directories_execute_in_original_index_order():
    body = _plan(
        [
            {"path": "d", "type": "directory"},
            {"path": "d/a.txt", "type": "file"},
            {"path": "b.txt", "type": "file"},
        ]
    )
    assert body["execution_order"] == [1, 2, 3]
    for e in body["entries"]:
        assert e["status"] == "EXECUTABLE"
        assert e["execution_order"] == e["index"]
        assert e["block_reasons"] == []
    assert body["summary"] == {
        "total": 3,
        "files": 2,
        "directories": 1,
        "hardlinks": 0,
        "executable": 3,
        "blocked": 0,
        "blocked_by_reason": {},
    }


def test_hardlink_may_point_to_later_entry_and_is_scheduled_after_it():
    body = _plan(
        [
            {"path": "lk", "type": "hardlink", "target": "a.txt"},
            {"path": "a.txt", "type": "file"},
        ]
    )
    entries = _by_index(body)
    # 每步选“依赖已满足者中原下标最小者”：第 1 步只能执行 #2，随后 #1。
    assert body["execution_order"] == [2, 1]
    assert entries[2]["execution_order"] == 1
    assert entries[1]["execution_order"] == 2
    assert [n["index"] for n in entries[1]["target_chain"]] == [1, 2]
    assert entries[1]["final_file_index"] == 2
    assert entries[1]["resolved_target_path"] == "a.txt"


def test_chain_followed_step_by_step_to_regular_file():
    body = _plan(
        [
            {"path": "f.txt", "type": "file"},
            {"path": "h1", "type": "hardlink", "target": "f.txt"},
            {"path": "h2", "type": "hardlink", "target": "h1"},
            {"path": "h3", "type": "hardlink", "target": "h2"},
        ]
    )
    entries = _by_index(body)
    assert body["execution_order"] == [1, 2, 3, 4]
    assert [n["index"] for n in entries[4]["target_chain"]] == [4, 3, 2, 1]
    assert entries[4]["final_file_index"] == 1


def test_min_ready_index_chosen_each_step_with_forward_targets():
    body = _plan(
        [
            {"path": "h1", "type": "hardlink", "target": "f1"},
            {"path": "h2", "type": "hardlink", "target": "f2"},
            {"path": "f1", "type": "file"},
            {"path": "f2", "type": "file"},
        ]
    )
    # 初始就绪集合 {3,4}，取最小 #3；随后 #1 就绪，{1,4} 取 #1；再 {4}，最后 #2。
    assert body["execution_order"] == [3, 1, 4, 2]
    entries = _by_index(body)
    assert entries[1]["final_file_index"] == 3
    assert entries[2]["final_file_index"] == 4


def test_windows_normalization_and_comparison_key_reused_for_targets():
    body = _plan(
        [
            {"path": "Src\\ReadMe.TXT", "type": "file"},
            {"path": "lk", "type": "hardlink", "target": "src/readme.txt"},
        ]
    )
    entries = _by_index(body)
    assert entries[2]["status"] == "EXECUTABLE"
    assert entries[2]["final_file_index"] == 1
    assert entries[2]["resolved_target_path"] == "src/readme.txt"
    # 段尾空格/句点裁剪同样作用于目标。
    body = _plan(
        [
            {"path": "a.txt", "type": "file"},
            {"path": "lk", "type": "hardlink", "target": "A.TXT ."},
        ]
    )
    assert body["entries"][1]["status"] == "EXECUTABLE"


# ---------------------------------------------------------------------------
# UNSAFE_PATH
# ---------------------------------------------------------------------------


def test_unsafe_entry_path_blocks_entry():
    body = _plan(
        [
            {"path": "../escape.txt", "type": "file"},
            {"path": "C:/drive", "type": "directory"},
            {"path": "CON", "type": "file"},
        ]
    )
    for e in body["entries"]:
        assert e["status"] == "BLOCKED"
        assert e["primary_block_reason"] == "UNSAFE_PATH"
        assert e["safe"] is False
        assert e["execution_order"] is None
        assert e["issues"]  # 规范化问题明细被回显


def test_unsafe_hardlink_path_skips_target_resolution():
    body = _plan(
        [
            {"path": "f.txt", "type": "file"},
            {"path": "../bad", "type": "hardlink", "target": "f.txt"},
        ]
    )
    entry = body["entries"][1]
    assert entry["primary_block_reason"] == "UNSAFE_PATH"
    assert entry["target_chain"] == []
    assert entry["final_file_index"] is None
    assert entry["resolved_target_path"] is None


# ---------------------------------------------------------------------------
# DUPLICATE_KEY
# ---------------------------------------------------------------------------


def test_same_key_duplicates_block_all_members_regardless_of_type():
    body = _plan(
        [
            {"path": "Name", "type": "directory"},
            {"path": "NAME", "type": "file"},
            {"path": "name .", "type": "hardlink", "target": "f"},
            {"path": "f", "type": "file"},
        ]
    )
    entries = _by_index(body)
    for idx in (1, 2, 3):
        reasons = _reasons(entries[idx])
        assert "DUPLICATE_KEY" in reasons
    assert set(_reasons(entries[1])["DUPLICATE_KEY"]) == {2, 3}
    assert set(_reasons(entries[2])["DUPLICATE_KEY"]) == {1, 3}
    assert set(_reasons(entries[3])["DUPLICATE_KEY"]) == {1, 2}
    assert entries[4]["status"] == "EXECUTABLE"


def test_unsafe_entries_do_not_establish_key_identity():
    # 不安全条目不参与同键分组，也不作为硬链接目标身份。
    body = _plan(
        [
            {"path": "a.txt", "type": "file"},
            {"path": "../a.txt", "type": "file"},
            {"path": "lk", "type": "hardlink", "target": "a.txt"},
        ]
    )
    entries = _by_index(body)
    assert "DUPLICATE_KEY" not in _reasons(entries[1])
    assert entries[3]["status"] == "EXECUTABLE"


# ---------------------------------------------------------------------------
# LEAF_ANCESTOR
# ---------------------------------------------------------------------------


def test_file_occupying_ancestor_blocks_descendants():
    body = _plan(
        [
            {"path": "a", "type": "file"},
            {"path": "a/b/c.txt", "type": "file"},
            {"path": "a/d", "type": "directory"},
        ]
    )
    entries = _by_index(body)
    assert entries[1]["status"] == "EXECUTABLE"
    assert _reasons(entries[2])["LEAF_ANCESTOR"] == [1]
    assert _reasons(entries[3])["LEAF_ANCESTOR"] == [1]


def test_hardlink_occupying_ancestor_blocks_descendants_even_if_blocked():
    # 占据祖先的硬链接自身虽因目标缺失被阻断，仍按其占据路径阻断后代
    # （“文件或硬链接占据祖先路径”不因占据者自身阻断而消失）。
    body = _plan(
        [
            {"path": "leaf", "type": "hardlink", "target": "missing"},
            {"path": "leaf/child.txt", "type": "file"},
        ]
    )
    entries = _by_index(body)
    assert entries[1]["primary_block_reason"] == "TARGET_MISSING"
    assert "LEAF_ANCESTOR" in _reasons(entries[2])
    assert _reasons(entries[2])["LEAF_ANCESTOR"] == [1]


def test_directory_ancestor_is_normal_layout_not_a_block():
    body = _plan(
        [
            {"path": "d/sub/deep", "type": "directory"},
            {"path": "d/sub/deep/f.txt", "type": "file"},
        ]
    )
    assert all(e["status"] == "EXECUTABLE" for e in body["entries"])


# ---------------------------------------------------------------------------
# 硬链接目标问题
# ---------------------------------------------------------------------------


def test_target_missing_and_empty_and_unsafe():
    body = _plan(
        [
            {"path": "m1", "type": "hardlink", "target": "nope/x"},
            {"path": "m2", "type": "hardlink", "target": ""},
            {"path": "m3", "type": "hardlink", "target": "../escape"},
            {"path": "m4", "type": "hardlink", "target": "CON"},
            {"path": "m5", "type": "hardlink", "target": "a/b?"},
        ]
    )
    expected = {
        1: "TARGET_MISSING",
        2: "TARGET_PATH_UNSAFE",
        3: "TARGET_PATH_UNSAFE",
        4: "TARGET_PATH_UNSAFE",
        5: "TARGET_PATH_UNSAFE",
    }
    for idx, reason in expected.items():
        assert body["entries"][idx - 1]["primary_block_reason"] == reason


def test_target_is_directory_blocks_hardlink():
    body = _plan(
        [
            {"path": "d", "type": "directory"},
            {"path": "lk", "type": "hardlink", "target": "d"},
        ]
    )
    entry = body["entries"][1]
    assert entry["primary_block_reason"] == "TARGET_IS_DIRECTORY"
    assert _reasons(entry)["TARGET_IS_DIRECTORY"] == [1]
    assert [n["index"] for n in entry["target_chain"]] == [2, 1]
    assert entry["final_file_index"] is None


def test_target_ambiguous_when_target_key_is_a_duplicate_group():
    body = _plan(
        [
            {"path": "a", "type": "file"},
            {"path": "A", "type": "file"},
            {"path": "lk", "type": "hardlink", "target": "a"},
        ]
    )
    entry = body["entries"][2]
    assert entry["primary_block_reason"] == "TARGET_AMBIGUOUS"
    assert _reasons(entry)["TARGET_AMBIGUOUS"] == [1, 2]
    assert entry["final_file_index"] is None


def test_self_cycle_and_two_node_and_three_node_cycles():
    body = _plan(
        [
            {"path": "self", "type": "hardlink", "target": "self"},
            {"path": "c1", "type": "hardlink", "target": "c2"},
            {"path": "c2", "type": "hardlink", "target": "c1"},
            {"path": "f", "type": "file"},
            {"path": "d1", "type": "hardlink", "target": "d2"},
            {"path": "d2", "type": "hardlink", "target": "d3"},
            {"path": "d3", "type": "hardlink", "target": "d1"},
        ]
    )
    entries = _by_index(body)
    self_entry = entries[1]
    assert self_entry["primary_block_reason"] == "TARGET_CYCLE"
    assert [n["index"] for n in self_entry["target_chain"]] == [1, 1]
    assert _reasons(self_entry)["TARGET_CYCLE"] == [1]  # 自环相关下标为自身

    assert entries[2]["primary_block_reason"] == "TARGET_CYCLE"
    assert [n["index"] for n in entries[2]["target_chain"]] == [2, 3, 2]
    assert entries[3]["primary_block_reason"] == "TARGET_CYCLE"
    assert [n["index"] for n in entries[3]["target_chain"]] == [3, 2, 3]

    assert [n["index"] for n in entries[5]["target_chain"]] == [5, 6, 7, 5]
    assert [n["index"] for n in entries[6]["target_chain"]] == [6, 7, 5, 6]
    assert [n["index"] for n in entries[7]["target_chain"]] == [7, 5, 6, 7]
    # 文件 #4 与环无关，照常可执行。
    assert entries[4]["status"] == "EXECUTABLE"
    assert body["execution_order"] == [4]


def test_hardlink_into_a_cycle_is_cycle_not_blocked():
    # 指向循环的硬链接沿结构追踪同样成环（重复点是循环入口），归 TARGET_CYCLE。
    body = _plan(
        [
            {"path": "in", "type": "hardlink", "target": "c1"},
            {"path": "c1", "type": "hardlink", "target": "c2"},
            {"path": "c2", "type": "hardlink", "target": "c1"},
        ]
    )
    entry = body["entries"][0]
    assert entry["primary_block_reason"] == "TARGET_CYCLE"
    assert [n["index"] for n in entry["target_chain"]] == [1, 2, 3, 2]
    assert _reasons(entry)["TARGET_CYCLE"] == [2]


def test_blocked_target_propagates_through_chain():
    body = _plan(
        [
            {"path": "f", "type": "file"},
            {"path": "dup", "type": "file"},
            {"path": "DUP", "type": "file"},  # #3：与 #2 同键重复
            {"path": "h1", "type": "hardlink", "target": "dup"},  # 歧义
            {"path": "h2", "type": "hardlink", "target": "h1"},  # 传播
            {"path": "h3", "type": "hardlink", "target": "h2"},  # 再传播
            {"path": "d", "type": "directory"},
            {"path": "hd", "type": "hardlink", "target": "d"},  # 指向目录
            {"path": "hd2", "type": "hardlink", "target": "hd"},  # 传播
        ]
    )
    entries = _by_index(body)
    assert entries[4]["primary_block_reason"] == "TARGET_AMBIGUOUS"
    for idx in (5, 6):
        assert "TARGET_BLOCKED" in _reasons(entries[idx])
        assert _reasons(entries[idx])["TARGET_BLOCKED"] == [4]
        assert entries[idx]["final_file_index"] is None
    assert [n["index"] for n in entries[6]["target_chain"]] == [6, 5, 4]
    assert entries[8]["primary_block_reason"] == "TARGET_IS_DIRECTORY"
    assert _reasons(entries[9])["TARGET_BLOCKED"] == [8]


def test_blocked_final_file_propagates_to_hardlink():
    # 链结构上到达普通文件，但该文件自身被阻断（不安全路径除外——它不建身份；
    # 这里用占据自身布局外的阻断情形：文件路径同键重复不影响唯一目标，故改用
    # 叶子祖先阻断最终文件）。
    body = _plan(
        [
            {"path": "a", "type": "file"},  # #1 叶子
            {"path": "a/x", "type": "file"},  # #2 被 #1 阻挡
            {"path": "lk", "type": "hardlink", "target": "a/x"},  # 最终文件被阻断
        ]
    )
    entries = _by_index(body)
    assert "LEAF_ANCESTOR" in _reasons(entries[2])
    assert _reasons(entries[3])["TARGET_BLOCKED"] == [2]
    assert [n["index"] for n in entries[3]["target_chain"]] == [3, 2]
    assert entries[3]["final_file_index"] == 2  # 结构上仍到达最终文件


def test_intermediate_missing_target_propagates_as_target_blocked():
    body = _plan(
        [
            {"path": "h1", "type": "hardlink", "target": "ghost"},  # 缺目
            {"path": "h2", "type": "hardlink", "target": "h1"},  # 传播
        ]
    )
    entries = _by_index(body)
    assert entries[1]["primary_block_reason"] == "TARGET_MISSING"
    assert _reasons(entries[2])["TARGET_BLOCKED"] == [1]
    assert [n["index"] for n in entries[2]["target_chain"]] == [2, 1]


def test_unsafe_direct_target_has_empty_chain():
    body = _plan(
        [
            {"path": "empty", "type": "hardlink", "target": ""},
            {"path": "escape", "type": "hardlink", "target": "../x"},
        ]
    )
    for entry in body["entries"]:
        assert entry["primary_block_reason"] == "TARGET_PATH_UNSAFE"
        assert entry["target_chain"] == []
        assert entry["final_file_index"] is None
        assert entry["resolved_target_path"] is None


def test_unsafe_intermediate_target_propagates_as_target_blocked():
    body = _plan(
        [
            {"path": "bad", "type": "hardlink", "target": "../x"},  # 目标不安全
            {"path": "good", "type": "hardlink", "target": "bad"},  # 传播
        ]
    )
    entries = _by_index(body)
    assert entries[1]["primary_block_reason"] == "TARGET_PATH_UNSAFE"
    assert _reasons(entries[2])["TARGET_BLOCKED"] == [1]
    assert [n["index"] for n in entries[2]["target_chain"]] == [2, 1]
    assert entries[2]["final_file_index"] is None


# ---------------------------------------------------------------------------
# 综合：阻断与排序互不干扰
# ---------------------------------------------------------------------------


def test_blocked_entries_never_scheduled_and_order_skips_them():
    body = _plan(
        [
            {"path": "h", "type": "hardlink", "target": "missing"},  # 阻断
            {"path": "d", "type": "directory"},
            {"path": "f", "type": "file"},
            {"path": "ok", "type": "hardlink", "target": "f"},
        ]
    )
    assert body["execution_order"] == [2, 3, 4]
    entries = _by_index(body)
    assert entries[1]["execution_order"] is None
    assert entries[2]["execution_order"] == 1
    assert entries[3]["execution_order"] == 2
    assert entries[4]["execution_order"] == 3


def test_multiple_reasons_collected_and_primary_is_enum_order_first():
    # 硬链接既与文件同键（DUPLICATE_KEY），其祖先又是叶子（LEAF_ANCESTOR），
    # 目标还是目录：全部原因收集，primary 取枚举序最靠前。
    body = _plan(
        [
            {"path": "a", "type": "file"},  # #1 叶子
            {"path": "d", "type": "directory"},  # #2
            {"path": "a/x", "type": "hardlink", "target": "d"},  # #3 多原因
        ]
    )
    entry = body["entries"][2]
    reasons = _reasons(entry)
    assert set(reasons) == {"LEAF_ANCESTOR", "TARGET_IS_DIRECTORY"}
    assert entry["primary_block_reason"] == "LEAF_ANCESTOR"
    assert reasons["LEAF_ANCESTOR"] == [1]
    assert reasons["TARGET_IS_DIRECTORY"] == [2]


# ---------------------------------------------------------------------------
# 请求结构校验（422）
# ---------------------------------------------------------------------------


def test_hardlink_requires_target_422():
    r = _post({"entries": [{"path": "x", "type": "hardlink"}]})
    assert r.status_code == 422


def test_non_hardlink_must_not_carry_target_422():
    for entry_type in ("file", "directory"):
        r = _post(
            {"entries": [{"path": "x", "type": entry_type, "target": "y"}]}
        )
        assert r.status_code == 422


def test_empty_entries_422():
    assert _post({"entries": []}).status_code == 422


def test_unknown_type_422():
    assert _post(
        {"entries": [{"path": "x", "type": "symlink"}]}
    ).status_code == 422


def test_health_and_root_still_available():
    assert client.get("/health").json()["status"] == "ok"
    root = client.get("/").json()
    assert root["hardlink_preview"] == "POST /api/v1/hardlink-preview"
