"""
Fetch and parse security news from RSS feeds.
Free — standard RSS/Atom feeds from major security publications.

Sources: BleepingComputer, The Hacker News, CISA Alerts, US-CERT.
"""

import json
from datetime import datetime, timezone
from typing import Optional

import feedparser
from langchain_core.tools import tool

from config import SECURITY_RSS_FEEDS, DATA_DIR


@tool
def fetch_security_rss(max_items_per_feed: Optional[int] = None) -> str:
    """Fetch recent security news articles from major security RSS feeds.

    Parses BleepingComputer, The Hacker News, CISA Alerts, and US-CERT feeds.

    Args:
        max_items_per_feed: Max articles per feed (default 10).

    Returns:
        JSON string with categorized security news articles.
    """
    limit = max_items_per_feed or 10

    all_articles = []
    feed_errors = []

    for feed_info in SECURITY_RSS_FEEDS:
        name = feed_info["name"]
        url = feed_info["url"]

        try:
            feed = feedparser.parse(url)

            if feed.bozo and not feed.entries:
                feed_errors.append({"feed": name, "error": "Parse error or unreachable"})
                continue

            for entry in feed.entries[:limit]:
                # Normalize the publication date
                published = ""
                if hasattr(entry, "published_parsed") and entry.published_parsed:
                    try:
                        published = datetime(*entry.published_parsed[:6],
                                             tzinfo=timezone.utc).isoformat()
                    except (TypeError, ValueError):
                        published = getattr(entry, "published", "")
                elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
                    try:
                        published = datetime(*entry.updated_parsed[:6],
                                             tzinfo=timezone.utc).isoformat()
                    except (TypeError, ValueError):
                        published = getattr(entry, "updated", "")

                # Extract summary, strip HTML if present
                summary = getattr(entry, "summary", "")
                if summary:
                    # Basic HTML tag stripping
                    import re
                    summary = re.sub(r"<[^>]+>", "", summary)[:500]

                all_articles.append({
                    "source": name,
                    "title": getattr(entry, "title", "No title"),
                    "link": getattr(entry, "link", ""),
                    "published": published,
                    "summary": summary,
                    "tags": [
                        tag.get("term", "") for tag in getattr(entry, "tags", [])
                    ][:5],
                })

        except Exception as e:
            feed_errors.append({"feed": name, "error": str(e)})

    # Sort by publish date descending
    all_articles.sort(key=lambda a: a["published"], reverse=True)

    result = {
        "source": "Security RSS Feeds",
        "feeds_queried": len(SECURITY_RSS_FEEDS),
        "feeds_with_errors": feed_errors,
        "total_articles": len(all_articles),
        "articles": all_articles,
    }

    # Persist
    now = datetime.now(timezone.utc)
    outpath = DATA_DIR / f"security_rss_{now.strftime('%Y%m%d_%H%M%S')}.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)
