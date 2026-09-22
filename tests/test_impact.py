"""历史影响反查 GET /api/v1/audits/impact/{package_name} 的端到端测试。"""


def _create_audits(client):
    """构造三类审计，返回各审计 ID。"""
    feasible_root = client.post(
        "/api/v1/audits",
        json={"plugin_name": "megaplugin", "plugin_version": "1.0.0", "dependencies": []},
    ).json()
    assert feasible_root["status"] == "feasible"

    feasible_direct = client.post(
        "/api/v1/audits",
        json={"dependencies": [{"name": "core-lib", "range": "^2.0.0"}]},
    ).json()
    assert feasible_direct["status"] == "feasible"

    infeasible_manifest = client.post(
        "/api/v1/audits",
        json={
            "dependencies": [
                {"name": "cachekit", "range": "^1.0.0"},
                {"name": "loggerkit", "range": "^0.9.0"},
            ]
        },
    ).json()
    assert infeasible_manifest["status"] == "infeasible"

    return feasible_root, feasible_direct, infeasible_manifest


def test_unknown_package_returns_empty_not_404(client):
    _create_audits(client)
    resp = client.get("/api/v1/audits/impact/no-such-package")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["items"] == []
    assert body["counts"] == {"feasible": 0, "infeasible": 0, "inconclusive": 0}


def test_package_aggregate_distinguishes_resolution_and_conflict(client):
    feasible_root, feasible_direct, infeasible = _create_audits(client)

    body = client.get("/api/v1/audits/impact/core-lib").json()
    assert body["package"] == "core-lib"
    assert body["version"] is None
    assert body["total"] == 3
    assert body["counts"] == {"feasible": 2, "infeasible": 1, "inconclusive": 0}

    by_audit = {item["audit_id"]: item for item in body["items"]}

    # 直接依赖：level=1，resolution 命中
    direct = by_audit[feasible_direct["id"]]
    assert direct["match_type"] == "resolution"
    assert direct["level"] == 1
    assert direct["versions"] == ["2.1.0"]
    assert direct["conflict_packages"] == []
    chain_packages = [step["package"] for step in direct["chains"][0]]
    assert chain_packages == ["<manifest>", "core-lib"]
    assert direct["chains"][0][-1]["version"] == "2.1.0"

    # 传递依赖（megaplugin -> authkit -> core-lib）：level=2，resolution 命中
    transitive = by_audit[feasible_root["id"]]
    assert transitive["match_type"] == "resolution"
    assert transitive["level"] == 2
    assert transitive["versions"] == ["1.5.0"]
    assert [step["package"] for step in transitive["chains"][0]] == [
        "megaplugin",
        "authkit",
        "core-lib",
    ]

    # 冲突目标：conflict 命中，且记录关联的冲突包
    conflicted = by_audit[infeasible["id"]]
    assert conflicted["match_type"] == "conflict"
    assert conflicted["conflict_packages"] == ["core-lib"]
    assert conflicted["level"] == 2
    assert "2.0.0" in conflicted["versions"]


def test_version_specific_match(client):
    _create_audits(client)

    body = client.get("/api/v1/audits/impact/core-lib?version=1.5.0").json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["match_type"] == "resolution"
    assert item["versions"] == ["1.5.0"]

    # 解析时规范化（v 前缀 / 空白）
    body = client.get("/api/v1/audits/impact/core-lib", params={"version": " v1.5.0 "}).json()
    assert body["total"] == 1
    assert body["version"] == "1.5.0"

    # 已知包但该版本从未参与任何审计 => 空结果而非 404
    body = client.get("/api/v1/audits/impact/core-lib?version=1.4.0").json()
    assert body["total"] == 0
    assert body["items"] == []


def test_version_specific_conflict_match(client):
    _create_audits(client)
    # 2.0.0 只在冲突里作为锁定版本出现
    body = client.get("/api/v1/audits/impact/core-lib?version=2.0.0").json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["match_type"] == "conflict"
    assert item["versions"] == ["2.0.0"]


def test_intermediate_package_in_conflict_chain(client):
    """来源链中间跳（cachekit@1.3.0 提出冲突约束）也算被传递拖入冲突。"""
    _create_audits(client)
    body = client.get("/api/v1/audits/impact/cachekit?version=1.3.0").json()
    assert body["total"] >= 1
    conflicted = [it for it in body["items"] if it["status"] == "infeasible"]
    assert conflicted, "cachekit@1.3.0 在冲突来源链上，应有 conflict 命中"
    item = conflicted[0]
    assert item["match_type"] == "conflict"
    assert "core-lib" in item["conflict_packages"]
    # 链在命中包处截断
    assert item["chains"][0][-1]["package"] == "cachekit"
    assert item["chains"][0][-1]["version"] == "1.3.0"


def test_root_plugin_level_zero(client):
    _create_audits(client)
    body = client.get("/api/v1/audits/impact/megaplugin?version=1.0.0").json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["match_type"] == "resolution"
    assert item["level"] == 0


def test_stable_sorting_level_then_created_desc(client):
    # 直接依赖审计（level=1）晚创建，也必须排在更早的传递命中（level=2）之前
    first = client.post(
        "/api/v1/audits",
        json={"plugin_name": "megaplugin", "plugin_version": "1.0.0", "dependencies": []},
    ).json()
    second = client.post(
        "/api/v1/audits",
        json={"dependencies": [{"name": "core-lib", "range": "^1.0.0"}]},
    ).json()
    body = client.get("/api/v1/audits/impact/core-lib").json()
    levels = [item["level"] for item in body["items"]]
    assert levels == sorted(levels)
    assert body["items"][0]["audit_id"] == second["id"]
    assert body["items"][1]["audit_id"] == first["id"]


def test_status_filter_and_pagination(client):
    _create_audits(client)
    body = client.get("/api/v1/audits/impact/core-lib?status=infeasible").json()
    assert body["total"] == 1
    assert body["status"] == "infeasible"
    assert all(item["status"] == "infeasible" for item in body["items"])
    assert body["counts"] == {"feasible": 0, "infeasible": 1, "inconclusive": 0}

    page1 = client.get("/api/v1/audits/impact/core-lib?limit=1&offset=0").json()
    page2 = client.get("/api/v1/audits/impact/core-lib?limit=1&offset=1").json()
    assert page1["total"] == 3
    assert len(page1["items"]) == 1
    assert page1["items"][0]["audit_id"] != page2["items"][0]["audit_id"]


def test_invalid_version_rejected(client):
    resp = client.get("/api/v1/audits/impact/core-lib?version=not-semver")
    assert resp.status_code == 400


def test_invalid_status_rejected(client):
    resp = client.get("/api/v1/audits/impact/core-lib?status=bogus")
    assert resp.status_code == 422
