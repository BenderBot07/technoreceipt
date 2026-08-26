from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

_URL = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    r"(?:/(?P<kind>issues|pull|commit)/(?P<identifier>[A-Za-z0-9_.-]+))?/?(?:[?#].*)?$"
)


@dataclass(frozen=True)
class GitHubRef:
    owner: str
    repo: str
    kind: str
    identifier: str | None


def parse_url(url: str) -> GitHubRef:
    match = _URL.fullmatch(url)
    if not match:
        raise ValueError(
            "supported URLs are GitHub repositories, issues, pull requests, and commits"
        )
    kind = match.group("kind") or "repository"
    return GitHubRef(match.group("owner"), match.group("repo"), kind, match.group("identifier"))


class GitHubClient:
    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.getenv("GITHUB_TOKEN")

    def _get(self, path: str) -> object:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "technoreceipt/0.1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(f"https://api.github.com{path}", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"GitHub API returned {exc.code} for {path}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub API request failed for {path}: {exc.reason}") from exc

    def snapshot(self, ref: GitHubRef) -> dict:
        base = f"/repos/{ref.owner}/{ref.repo}"
        if ref.kind == "repository":
            artifact = self._get(base)
            comments: list[dict] = []
        elif ref.kind == "issues":
            artifact = self._get(f"{base}/issues/{ref.identifier}")
            comments = self._get(f"{base}/issues/{ref.identifier}/comments?per_page=100")
        elif ref.kind == "pull":
            artifact = self._get(f"{base}/pulls/{ref.identifier}")
            comments = self._get(f"{base}/issues/{ref.identifier}/comments?per_page=100")
        else:
            artifact = self._get(f"{base}/commits/{ref.identifier}")
            comments = self._get(f"{base}/commits/{ref.identifier}/comments?per_page=100")
        if not isinstance(artifact, dict) or not isinstance(comments, list):
            raise TypeError("unexpected GitHub API response")
        return _normalize(ref, artifact, comments)

    def file_bytes(self, owner: str, repo: str, path: str, ref: str) -> bytes:
        artifact = self._get(f"/repos/{owner}/{repo}/contents/{path}?ref={ref}")
        if not isinstance(artifact, dict) or artifact.get("type") != "file":
            raise TypeError("GitHub binding URL did not resolve to a file")
        content = artifact.get("content")
        if artifact.get("encoding") != "base64" or not isinstance(content, str):
            raise TypeError("unexpected GitHub file encoding")
        # The contents API wraps base64 at 60 characters. Remove only formatting whitespace;
        # validate=True still refuses any non-base64 byte after that normalization.
        return base64.b64decode("".join(content.split()), validate=True)


def _login(value: object) -> str | None:
    return value.get("login") if isinstance(value, dict) else None


def _normalize(ref: GitHubRef, artifact: dict, comments: list[dict]) -> dict:
    if ref.kind == "commit":
        commit = artifact.get("commit") if isinstance(artifact.get("commit"), dict) else {}
        title = str(commit.get("message", "")).splitlines()[0]
        body = str(commit.get("message", ""))
        author = _login(artifact.get("author"))
        updated_at = (
            commit.get("committer", {}).get("date")
            if isinstance(commit.get("committer"), dict)
            else None
        )
    else:
        title = str(
            artifact.get("title") or artifact.get("name") or artifact.get("full_name") or ""
        )
        body = str(artifact.get("body") or artifact.get("description") or "")
        author = _login(artifact.get("user")) or _login(artifact.get("owner"))
        updated_at = artifact.get("updated_at") or artifact.get("pushed_at")
    normalized_comments = [
        {
            "author": _login(comment.get("user")),
            "body": str(comment.get("body") or ""),
            "url": comment.get("html_url"),
        }
        for comment in comments
        if isinstance(comment, dict)
    ]
    return {
        "type": ref.kind,
        "url": artifact.get("html_url"),
        "repository": f"{ref.owner}/{ref.repo}",
        "author": author,
        "title": title,
        "body": body,
        "state": artifact.get("state"),
        "updated_at": updated_at,
        "comments": normalized_comments,
    }
