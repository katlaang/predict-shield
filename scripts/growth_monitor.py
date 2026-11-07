#!/usr/bin/env python3
"""Read-only GitHub growth snapshot for PREDICT-SHIELD.

Never creates views, clones, release downloads, stars, or posts.
Release-asset download counts are cumulative, not unique-user counts.
"""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def get_json(repo, suffix, token):
    """Return (data, error). Never include auth credentials in output."""
    url = "https://api.github.com/repos/" + repo + suffix
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "User-Agent": "predict-shield-growth-monitor",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=25) as response:
            return json.load(response), None
    except HTTPError as exc:
        return None, "HTTP " + str(exc.code)
    except (URLError, TimeoutError, ValueError) as exc:
        return None, type(exc).__name__


def release_summary(releases):
    """Cumulative asset counts do not establish unique downloads or adoption."""
    assets = []
    for release in releases:
        for asset in release.get("assets", []):
            assets.append(
                {
                    "release_tag": release.get("tag_name"),
                    "name": asset.get("name"),
                    "size_bytes": asset.get("size"),
                    "download_count_cumulative": asset.get("download_count", 0),
                }
            )
    return {
        "release_count_returned": len(releases),
        "release_page_limit": 100,
        "assets": assets,
        "asset_downloads_cumulative": sum(
            item["download_count_cumulative"] for item in assets
        ),
        "interpretation": "Cumulative API counters, not daily or unique-user counts.",
    }


def outreach_draft(repo, visibility, published_releases):
    """Templates require human review; do not claim unverified effectiveness."""
    if visibility != "public":
        return (
            "# Outreach drafts: NOT READY\n\n"
            "Repository is private. Do not share a link to inaccessible code. "
            "Review what may be safely published first.\n"
        )
    if not published_releases:
        return (
            "# Outreach drafts: NOT READY\n\n"
            "No published release was found. Prepare a documented public release "
            "and installation instructions before promoting downloads.\n"
        )
    url = "https://github.com/" + repo
    release_url = url + "/releases"
    return (
        "# PREDICT-SHIELD outreach drafts (human review required)\n\n"
        "Do not automatically post or imply independent validation.\n\n"
        "## Professional network\n\n"
        "I'm developing PREDICT-SHIELD, a research-stage cybersecurity "
        "framework exploring predictive threat intelligence, risk assessment, "
        "policy-governed responses, and independent verification. "
        "A public release is available for technical review: " + release_url +
        ". Feedback on assumptions, reproducibility, and limitations is welcome.\n\n"
        "## Research or open-source community\n\n"
        "Looking for technical feedback on an early-stage cybersecurity research "
        "project, PREDICT-SHIELD. The repository documents its current scope and "
        "limitations. Please review the implementation and open a concrete issue "
        "if you identify a reproducibility gap: " + url + "\n\n"
        "## Release announcement\n\n"
        "PREDICT-SHIELD has a published release: " + release_url +
        ". Please read the README and limitations before testing. "
        "Downloads, if reported, are not evidence of efficacy or adoption.\n"
    )


def snapshot(repo, token, metrics_token):
    metadata, metadata_error = get_json(repo, "", token)
    releases, releases_error = get_json(repo, "/releases?per_page=100", token)
    result = {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "repository": repo,
        "repo_metadata": {
            "status": "ok" if metadata_error is None else "unavailable",
            "error": metadata_error,
        },
        "releases": {
            "status": "ok" if releases_error is None else "unavailable",
            "error": releases_error,
        },
        "traffic": {},
        "notes": [
            "These are GitHub API counters, not proof of independent adoption.",
            "No country-level visitors or download origin is available here.",
            "No automated download or visit requests were generated.",
        ],
    }
    if metadata is not None:
        result["repo_metadata"].update(
            {
                "visibility": metadata.get("visibility"),
                "stargazers_count": metadata.get("stargazers_count"),
                "forks_count": metadata.get("forks_count"),
                "html_url": metadata.get("html_url"),
            }
        )
    if releases is not None:
        result["releases"].update(release_summary(releases))
    for name in ("views", "clones"):
        if not metrics_token:
            result["traffic"][name] = {
                "status": "unavailable",
                "reason": "PREDICT_SHIELD_METRICS_TOKEN not configured; traffic requires an appropriately scoped credential.",
            }
            continue
        response, error = get_json(repo, "/traffic/" + name, metrics_token)
        result["traffic"][name] = (
            {"status": "ok", "period": "rolling_14_days", "data": response}
            if error is None
            else {"status": "unavailable", "reason": error}
        )
    return result


def markdown_summary(data):
    meta = data["repo_metadata"]
    rel = data["releases"]
    lines = [
        "# PREDICT-SHIELD growth snapshot",
        "",
        "Captured (UTC): " + data["captured_at_utc"],
        "",
        "| Metric | Value |",
        "|---|---|",
        "| Visibility | " + str(meta.get("visibility", "unavailable")) + " |",
        "| Stars | " + str(meta.get("stargazers_count", "unavailable")) + " |",
        "| Forks | " + str(meta.get("forks_count", "unavailable")) + " |",
        "| Published releases returned | " + str(rel.get("release_count_returned", "unavailable")) + " |",
        "| Cumulative release asset downloads | " + str(rel.get("asset_downloads_cumulative", "unavailable")) + " |",
    ]
    for name in ("views", "clones"):
        t = data["traffic"][name]
        detail = (
            str(t["data"].get("count", "unavailable")) + " (rolling 14 days)"
            if t["status"] == "ok"
            else "Unavailable (" + t["reason"] + ")"
        )
        lines.append("| " + name.title() + " | " + detail.replace("|", "/") + " |")
    lines += [
        "",
        "Release asset totals are cumulative and cannot be converted to daily "
        "or unique-user figures without dated baselines.",
        "Visitor geography is not available from these endpoints.",
        "Automated verification downloads must be logged separately.",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "katlaang/predict-shield"))
    parser.add_argument("--out", default="growth-report")
    args = parser.parse_args()
    if len(args.repo.split("/")) != 2:
        parser.error("--repo must have the form owner/repo")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.error("GH_TOKEN or GITHUB_TOKEN is required")
    data = snapshot(args.repo, token, os.environ.get("PREDICT_SHIELD_METRICS_TOKEN"))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "snapshot.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    (out / "summary.md").write_text(markdown_summary(data), encoding="utf-8")
    status = data["repo_metadata"]
    published = (
        data["releases"].get("release_count_returned", 0) > 0
        and any(item.get("release_tag") for item in data["releases"].get("assets", []))
    )
    (out / "outreach-drafts.md").write_text(
        outreach_draft(args.repo, status.get("visibility"), published),
        encoding="utf-8",
    )
    print(markdown_summary(data))
    if status["status"] != "ok":
        raise SystemExit("Repository metadata could not be read; see snapshot.json")


if __name__ == "__main__":
    main()
