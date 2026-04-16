"""
Cross-Scan Diff — Compare two scans to see what changed
"""
from database.manager import ResultDB, ScanDB
from utils.logger import log


def diff_scans(old_id, new_id):
    """
    Compare two scans by value+type.
    Returns: added, removed, common counts + details
    """
    old_results = ResultDB.get_by_scan(old_id, per_page=5000).get("items", [])
    new_results = ResultDB.get_by_scan(new_id, per_page=5000).get("items", [])

    old_set = {(r["value"], r["type"]) for r in old_results}
    new_set = {(r["value"], r["type"]) for r in new_results}

    added_keys = new_set - old_set
    removed_keys = old_set - new_set
    common_keys = old_set & new_set

    added = [r for r in new_results if (r["value"], r["type"]) in added_keys]
    removed = [r for r in old_results if (r["value"], r["type"]) in removed_keys]

    old_scan = ScanDB.get(old_id)
    new_scan = ScanDB.get(new_id)

    log.info(f"Diff {old_id}→{new_id}: +{len(added)} -{len(removed)} ={len(common_keys)}")

    return {
        "old_scan": old_scan,
        "new_scan": new_scan,
        "added": added[:200],
        "removed": removed[:200],
        "common_count": len(common_keys),
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "common": len(common_keys),
            "old_total": len(old_results),
            "new_total": len(new_results),
        }
    }
