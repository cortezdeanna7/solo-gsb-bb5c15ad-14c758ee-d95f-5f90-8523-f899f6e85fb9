"""历史影响反查：在已持久化的审计结果中反向定位“谁依赖了某包/版本”。

扫描每条审计结果的三类数据：

* ``resolution``：可行解中被选中的包版本（直接或传递）；
* ``sources``：每个选中版本的全部约束及其逐跳来源链；
* ``conflicts``：无解时的冲突目标（``package`` / ``locked_version``）与
  每条冲突约束的 ``source_chain``——链上的中间跳同样是“被拖入冲突”的包。

命中分两类，结果中明确区分：

* ``resolution``：该包/版本出现在某条可行审计的解中，通过来源链判定直接/传递层级；
* ``conflict``：该包/版本是某条冲突的约束目标，或作为来源链上的某一提出者参与冲突。

命中层级 ``level``：根插件为 0；清单直接声明的依赖为 1；再深一层传递依赖为 2，依此类推。
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple

from .semver import Version, VersionError

MANIFEST_STEP = "<manifest>"

#: 单条命中保留的来源链上限
CHAIN_REPORT_LIMIT = 10


def _chain_key(chain: List[Dict[str, Any]]) -> Tuple[Any, ...]:
    return tuple(
        (step.get("package"), step.get("version"), step.get("version_range")) for step in chain
    )


def _dedupe_chains(chains: List[List[Dict[str, Any]]]) -> List[List[Dict[str, Any]]]:
    seen = set()
    unique: List[List[Dict[str, Any]]] = []
    for chain in chains:
        key = _chain_key(chain)
        if key in seen:
            continue
        seen.add(key)
        unique.append(chain)
    unique.sort(key=lambda ch: (len(ch), _chain_key(ch)))
    return unique[:CHAIN_REPORT_LIMIT]


def _truncate_at(chain: List[Dict[str, Any]], package: str) -> Optional[List[Dict[str, Any]]]:
    """返回来源链从根跳到 package 的截断前缀；package 不在链上时返回 None。"""
    for index, step in enumerate(chain):
        if step.get("package") == package:
            return list(chain[: index + 1])
    return None


def _terminal_step(package: str, version_range: str, version: Optional[str]) -> Dict[str, Any]:
    return {"package": package, "version_range": version_range, "version": version}


def _version_sort_key(text: str) -> Tuple[int, Any, str]:
    try:
        return (0, Version.parse(text), text)
    except VersionError:
        return (1, None, text)


def _sorted_versions(versions: List[str]) -> List[str]:
    return sorted(set(versions), key=_version_sort_key, reverse=True)


def match_audit_result(
    result: Dict[str, Any], package: str, version: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """判定单条审计结果是否直接或传递地命中 package@version。

    返回命中摘要（含层级、版本与来源链证据）；未命中返回 None。
    同一条审计同时存在解命中与冲突命中时，``resolution`` 优先。
    """
    resolution = result.get("resolution")
    if isinstance(resolution, dict) and package in resolution:
        hit_version = resolution[package]
        if version is None or hit_version == version:
            return _match_resolution(result, package, hit_version)
        # 解中的具体版本不匹配：冲突字段为空（feasible），无需再扫
        return None

    return _match_conflicts(result, package, version)


def _match_resolution(
    result: Dict[str, Any], package: str, hit_version: str
) -> Optional[Dict[str, Any]]:
    chains: List[List[Dict[str, Any]]] = []
    sources = result.get("sources") or []
    for source in sources:
        if source.get("package") != package:
            continue
        for constraint in source.get("requested_by", []) or []:
            raw_chain = list(constraint.get("source_chain") or [])
            truncated = _truncate_at(raw_chain, package)
            if truncated is None:
                # 防御：来源链缺失目标跳时补一个目标跳（根插件自身的链可能为空）
                truncated = raw_chain or [
                    _terminal_step(MANIFEST_STEP, "*", None),
                ]
                if truncated[-1].get("package") != package:
                    truncated.append(
                        _terminal_step(package, constraint.get("version_range", "*"), hit_version)
                    )
            else:
                # 统一证据形态：在目标跳位置补上其被选中的版本
                truncated[-1] = {
                    "package": package,
                    "version_range": truncated[-1].get("version_range")
                    or constraint.get("version_range", "*"),
                    "version": hit_version,
                }
            chains.append(truncated)

    if not chains:
        # 根插件在求解器中无约束条目：单跳根链，层级 0；
        # 再防御性兼容缺失 sources 的旧记录（<manifest> -> 包）
        root_plugin = result.get("root_plugin")
        root_name = str(root_plugin).split("@", 1)[0] if root_plugin else None
        if root_name == package:
            chains.append([_terminal_step(package, f"={hit_version}", hit_version)])
        else:
            chains.append([
                _terminal_step(MANIFEST_STEP, "*", None),
                _terminal_step(package, "*", hit_version),
            ])

    chains = _dedupe_chains(chains)
    return {
        "match_type": "resolution",
        "level": min(len(ch) - 1 for ch in chains),
        "versions": [hit_version],
        "chains": chains,
        "conflict_packages": [],
    }


def _match_conflicts(
    result: Dict[str, Any], package: str, version: Optional[str]
) -> Optional[Dict[str, Any]]:
    chains: List[List[Dict[str, Any]]] = []
    conflict_packages: List[str] = []
    seen_versions: Set[str] = set()

    for conflict in result.get("conflicts") or []:
        target = conflict.get("package")
        locked_version = conflict.get("locked_version")
        constraints = []
        for bucket_name in ("minimal_constraints", "all_constraints"):
            for constraint in conflict.get(bucket_name) or []:
                if constraint not in constraints:
                    constraints.append(constraint)

        for constraint in constraints:
            chain = constraint.get("source_chain") or []
            if target == package:
                # 包本身是冲突约束的目标：链上具体版本或锁定版本命中均可
                chain_step_versions = sorted(
                    step.get("version")
                    for step in chain
                    if step.get("package") == package and step.get("version")
                )
                matched_via_chain = version is None or version in chain_step_versions
                matched_via_locked = locked_version is not None and (
                    version is None or version == locked_version
                )
                if not (matched_via_chain or matched_via_locked):
                    continue
                if matched_via_chain:
                    seen_versions.update(chain_step_versions)
                if matched_via_locked:
                    seen_versions.add(locked_version)
                evidence = list(chain)
                if not evidence or evidence[-1].get("package") != package:
                    evidence.append(
                        _terminal_step(
                            package,
                            constraint.get("version_range", "*"),
                            locked_version,
                        )
                    )
                chains.append(evidence)
                conflict_packages.append(target)
            else:
                # 包作为来源链上的中间提出者被传递拖入该冲突
                truncated = _truncate_at(list(chain), package)
                if truncated is None:
                    continue
                hop_version = truncated[-1].get("version")
                if version is not None and hop_version != version:
                    continue
                if hop_version is not None:
                    seen_versions.add(hop_version)
                chains.append(truncated)
                conflict_packages.append(target)

    if not chains:
        return None

    chains = _dedupe_chains(chains)
    return {
        "match_type": "conflict",
        "level": min(len(ch) - 1 for ch in chains),
        "versions": _sorted_versions(list(seen_versions)),
        "chains": chains,
        "conflict_packages": sorted(set(conflict_packages)),
    }


def build_impact_report(
    rows: List[Any],
    package: str,
    version: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """扫描审计行（含 id/created_at/status/result_json），汇总影响反查结果。

    命中按层级升序、创建时间降序（新审计在前）、审计 ID 升序稳定排序。
    """

    matches: List[Dict[str, Any]] = []
    counts = {"feasible": 0, "infeasible": 0, "inconclusive": 0}

    for row in rows:
        result = json.loads(row["result_json"])
        hit = match_audit_result(result, package, version)
        if hit is None:
            continue
        audit_status = row["status"]
        counts[audit_status] = counts.get(audit_status, 0) + 1
        matches.append(
            {
                "audit_id": row["id"],
                "created_at": row["created_at"],
                "status": audit_status,
                "root_plugin": row["root_plugin"],
                **hit,
            }
        )

    # created_at 为同格式 UTC ISO8601 字符串，字符串序即时间序；
    # 利用稳定排序按优先级的逆序逐轮排序：层级升序 → 时间降序 → ID 升序
    matches.sort(key=lambda item: item["audit_id"])
    matches.sort(key=lambda item: item["created_at"], reverse=True)
    matches.sort(key=lambda item: item["level"])

    return {
        "package": package,
        "version": version,
        "status": status_filter,
        "total": len(matches),
        "counts": counts,
        "items": matches,
    }
