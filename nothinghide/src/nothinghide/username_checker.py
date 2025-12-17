"""Username OSINT Intelligence Module.

Advanced username reconnaissance across multiple platforms to detect
identity exposure and weak security patterns.
"""

import asyncio
import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import httpx

from .exceptions import ValidationError, NetworkError


PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{}", "category": "Development", "icon": "code"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "category": "Development", "icon": "code"},
    {"name": "Twitter/X", "url": "https://twitter.com/{}", "category": "Social", "icon": "social"},
    {"name": "Instagram", "url": "https://instagram.com/{}", "category": "Social", "icon": "social"},
    {"name": "Facebook", "url": "https://facebook.com/{}", "category": "Social", "icon": "social"},
    {"name": "LinkedIn", "url": "https://linkedin.com/in/{}", "category": "Professional", "icon": "work"},
    {"name": "Reddit", "url": "https://reddit.com/user/{}", "category": "Social", "icon": "social"},
    {"name": "Pinterest", "url": "https://pinterest.com/{}", "category": "Social", "icon": "social"},
    {"name": "TikTok", "url": "https://tiktok.com/@{}", "category": "Social", "icon": "social"},
    {"name": "YouTube", "url": "https://youtube.com/@{}", "category": "Media", "icon": "video"},
    {"name": "Twitch", "url": "https://twitch.tv/{}", "category": "Media", "icon": "video"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "category": "Gaming", "icon": "game"},
    {"name": "Discord", "url": "https://discord.com/users/{}", "category": "Communication", "icon": "chat"},
    {"name": "Telegram", "url": "https://t.me/{}", "category": "Communication", "icon": "chat"},
    {"name": "Medium", "url": "https://medium.com/@{}", "category": "Content", "icon": "article"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "category": "Development", "icon": "code"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "category": "Tech", "icon": "news"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "category": "Security", "icon": "key"},
    {"name": "Patreon", "url": "https://patreon.com/{}", "category": "Content", "icon": "money"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "category": "Media", "icon": "music"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "category": "Media", "icon": "music"},
    {"name": "Flickr", "url": "https://flickr.com/people/{}", "category": "Media", "icon": "photo"},
    {"name": "Tumblr", "url": "https://{}.tumblr.com", "category": "Social", "icon": "social"},
    {"name": "WordPress", "url": "https://{}.wordpress.com", "category": "Content", "icon": "article"},
    {"name": "Blogger", "url": "https://{}.blogspot.com", "category": "Content", "icon": "article"},
    {"name": "About.me", "url": "https://about.me/{}", "category": "Professional", "icon": "person"},
    {"name": "Gravatar", "url": "https://gravatar.com/{}", "category": "Identity", "icon": "person"},
    {"name": "PayPal.me", "url": "https://paypal.me/{}", "category": "Financial", "icon": "money"},
    {"name": "Cash App", "url": "https://cash.app/${}", "category": "Financial", "icon": "money"},
    {"name": "Venmo", "url": "https://venmo.com/{}", "category": "Financial", "icon": "money"},
    {"name": "Snapchat", "url": "https://snapchat.com/add/{}", "category": "Social", "icon": "social"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "category": "Media", "icon": "video"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "category": "Design", "icon": "design"},
    {"name": "Behance", "url": "https://behance.net/{}", "category": "Design", "icon": "design"},
    {"name": "500px", "url": "https://500px.com/p/{}", "category": "Media", "icon": "photo"},
    {"name": "Quora", "url": "https://quora.com/profile/{}", "category": "Q&A", "icon": "question"},
    {"name": "Stack Overflow", "url": "https://stackoverflow.com/users/{}", "category": "Development", "icon": "code"},
    {"name": "HackerOne", "url": "https://hackerone.com/{}", "category": "Security", "icon": "security"},
    {"name": "Bugcrowd", "url": "https://bugcrowd.com/{}", "category": "Security", "icon": "security"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}", "category": "Development", "icon": "code"},
    {"name": "NPM", "url": "https://npmjs.com/~{}", "category": "Development", "icon": "code"},
    {"name": "PyPI", "url": "https://pypi.org/user/{}", "category": "Development", "icon": "code"},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{}", "category": "Development", "icon": "code"},
    {"name": "Replit", "url": "https://replit.com/@{}", "category": "Development", "icon": "code"},
    {"name": "CodePen", "url": "https://codepen.io/{}", "category": "Development", "icon": "code"},
    {"name": "Hashnode", "url": "https://hashnode.com/@{}", "category": "Development", "icon": "article"},
    {"name": "ProductHunt", "url": "https://producthunt.com/@{}", "category": "Tech", "icon": "product"},
    {"name": "AngelList", "url": "https://angel.co/u/{}", "category": "Professional", "icon": "work"},
    {"name": "Crunchbase", "url": "https://crunchbase.com/person/{}", "category": "Professional", "icon": "work"},
    {"name": "Mix", "url": "https://mix.com/{}", "category": "Social", "icon": "social"},
    {"name": "Trello", "url": "https://trello.com/{}", "category": "Productivity", "icon": "task"},
    {"name": "Notion", "url": "https://{}.notion.site", "category": "Productivity", "icon": "task"},
    {"name": "Gumroad", "url": "https://gumroad.com/{}", "category": "E-commerce", "icon": "shop"},
    {"name": "Etsy", "url": "https://etsy.com/shop/{}", "category": "E-commerce", "icon": "shop"},
    {"name": "eBay", "url": "https://ebay.com/usr/{}", "category": "E-commerce", "icon": "shop"},
    {"name": "Imgur", "url": "https://imgur.com/user/{}", "category": "Media", "icon": "photo"},
    {"name": "9GAG", "url": "https://9gag.com/u/{}", "category": "Social", "icon": "social"},
    {"name": "VK", "url": "https://vk.com/{}", "category": "Social", "icon": "social"},
    {"name": "Mastodon", "url": "https://mastodon.social/@{}", "category": "Social", "icon": "social"},
    {"name": "Pixiv", "url": "https://pixiv.net/users/{}", "category": "Art", "icon": "art"},
    {"name": "DeviantArt", "url": "https://deviantart.com/{}", "category": "Art", "icon": "art"},
    {"name": "ArtStation", "url": "https://artstation.com/{}", "category": "Art", "icon": "art"},
    {"name": "Giphy", "url": "https://giphy.com/{}", "category": "Media", "icon": "video"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "category": "Link", "icon": "link"},
    {"name": "Carrd", "url": "https://{}.carrd.co", "category": "Link", "icon": "link"},
    {"name": "Bio.link", "url": "https://bio.link/{}", "category": "Link", "icon": "link"},
]


@dataclass
class PlatformResult:
    """Result of checking a single platform."""
    platform: str
    url: str
    exists: bool
    category: str
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "url": self.url,
            "exists": self.exists,
            "category": self.category,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "error": self.error,
        }


@dataclass
class IdentityRisk:
    """Identity risk analysis."""
    level: str
    score: int
    factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "score": self.score,
            "factors": self.factors,
            "recommendations": self.recommendations,
        }


@dataclass
class UsernameResult:
    """Complete username OSINT result."""
    username: str
    total_platforms_checked: int
    accounts_found: int
    platforms: List[PlatformResult] = field(default_factory=list)
    categories: Dict[str, int] = field(default_factory=dict)
    identity_risk: Optional[IdentityRisk] = None
    username_analysis: Dict[str, Any] = field(default_factory=dict)
    checked_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.checked_at is None:
            self.checked_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "total_platforms_checked": self.total_platforms_checked,
            "accounts_found": self.accounts_found,
            "platforms": [p.to_dict() for p in self.platforms],
            "categories": self.categories,
            "identity_risk": self.identity_risk.to_dict() if self.identity_risk else None,
            "username_analysis": self.username_analysis,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


class UsernameChecker:
    """Advanced Username OSINT Intelligence."""
    
    def __init__(self, timeout: float = 8.0, max_concurrent: int = 15):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
    
    def validate_username(self, username: str) -> str:
        """Validate and normalize username."""
        username = username.strip().lower()
        
        if not username:
            raise ValidationError("Username cannot be empty", field="username")
        
        if len(username) < 2:
            raise ValidationError("Username must be at least 2 characters", field="username")
        
        if len(username) > 50:
            raise ValidationError("Username too long (max 50 characters)", field="username")
        
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            raise ValidationError(
                "Username can only contain letters, numbers, dots, underscores, and hyphens",
                field="username"
            )
        
        return username
    
    def analyze_username(self, username: str) -> Dict[str, Any]:
        """Analyze username for patterns and vulnerabilities."""
        analysis = {
            "length": len(username),
            "has_numbers": bool(re.search(r'\d', username)),
            "has_special": bool(re.search(r'[._-]', username)),
            "all_lowercase": username == username.lower(),
            "patterns": [],
            "weaknesses": [],
            "entropy_score": 0,
        }
        
        if re.match(r'^[a-z]+\d{2,4}$', username):
            analysis["patterns"].append("name_with_birth_year")
            analysis["weaknesses"].append("Contains possible birth year - easy to correlate identity")
        
        if re.match(r'^[a-z]+[._-]?[a-z]+$', username):
            analysis["patterns"].append("possible_real_name")
            analysis["weaknesses"].append("Appears to be based on real name - identity exposure risk")
        
        if re.search(r'(19|20)\d{2}', username):
            analysis["patterns"].append("contains_year")
            analysis["weaknesses"].append("Contains year - possible age/birth year indicator")
        
        common_patterns = ['admin', 'user', 'test', 'demo', 'root', 'guest']
        for pattern in common_patterns:
            if pattern in username:
                analysis["patterns"].append(f"common_pattern_{pattern}")
                analysis["weaknesses"].append(f"Contains common pattern '{pattern}'")
        
        if re.match(r'^[a-z]+$', username) and len(username) <= 8:
            analysis["patterns"].append("simple_word")
            analysis["weaknesses"].append("Simple word username - likely used across many platforms")
        
        unique_chars = len(set(username))
        analysis["entropy_score"] = min(100, int((unique_chars / len(username)) * 100))
        
        if analysis["entropy_score"] < 50:
            analysis["weaknesses"].append("Low entropy - predictable username pattern")
        
        return analysis
    
    async def check_platform(
        self, 
        client: httpx.AsyncClient,
        username: str, 
        platform: Dict[str, str]
    ) -> PlatformResult:
        """Check if username exists on a specific platform."""
        url = platform["url"].format(username)
        
        try:
            start_time = asyncio.get_event_loop().time()
            response = await client.get(
                url,
                follow_redirects=True,
                timeout=self.timeout
            )
            response_time = asyncio.get_event_loop().time() - start_time
            
            exists = response.status_code == 200
            
            if exists:
                content = response.text.lower()
                not_found_indicators = [
                    "not found", "doesn't exist", "page not found",
                    "user not found", "404", "no user", "this page",
                    "sorry", "unavailable", "deleted", "suspended"
                ]
                for indicator in not_found_indicators:
                    if indicator in content[:2000]:
                        exists = False
                        break
            
            return PlatformResult(
                platform=platform["name"],
                url=url,
                exists=exists,
                category=platform["category"],
                status_code=response.status_code,
                response_time=round(response_time, 3),
            )
            
        except httpx.TimeoutException:
            return PlatformResult(
                platform=platform["name"],
                url=url,
                exists=False,
                category=platform["category"],
                error="Timeout",
            )
        except Exception as e:
            return PlatformResult(
                platform=platform["name"],
                url=url,
                exists=False,
                category=platform["category"],
                error=str(e)[:100],
            )
    
    def calculate_identity_risk(
        self, 
        username: str,
        accounts_found: int,
        categories: Dict[str, int],
        username_analysis: Dict[str, Any]
    ) -> IdentityRisk:
        """Calculate identity exposure risk."""
        score = 0
        factors = []
        recommendations = []
        
        if accounts_found >= 20:
            score += 40
            factors.append(f"High exposure: {accounts_found} accounts found across platforms")
        elif accounts_found >= 10:
            score += 25
            factors.append(f"Moderate exposure: {accounts_found} accounts found")
        elif accounts_found >= 5:
            score += 15
            factors.append(f"Low-moderate exposure: {accounts_found} accounts found")
        else:
            score += 5
            factors.append(f"Limited exposure: {accounts_found} accounts found")
        
        if categories.get("Financial", 0) > 0:
            score += 20
            factors.append("Financial accounts detected - high value target")
            recommendations.append("Enable 2FA on all financial platforms immediately")
        
        if categories.get("Professional", 0) >= 2:
            score += 15
            factors.append("Multiple professional profiles - identity correlation possible")
            recommendations.append("Review information consistency across professional profiles")
        
        social_count = categories.get("Social", 0)
        if social_count >= 5:
            score += 15
            factors.append(f"Extensive social media presence ({social_count} platforms)")
            recommendations.append("Audit social media privacy settings")
        
        if categories.get("Development", 0) >= 3:
            score += 10
            factors.append("Developer footprint detected - code/project exposure risk")
            recommendations.append("Check for exposed API keys or credentials in public repos")
        
        for weakness in username_analysis.get("weaknesses", []):
            score += 5
            factors.append(f"Username weakness: {weakness}")
        
        if "possible_real_name" in username_analysis.get("patterns", []):
            score += 15
            factors.append("Username appears to contain real name")
            recommendations.append("Consider using pseudonyms for non-professional accounts")
        
        if categories.get("Link", 0) > 0:
            score += 10
            factors.append("Link aggregator detected - consolidated attack surface")
            recommendations.append("Review what information is linked and visible")
        
        score = min(100, score)
        
        if score >= 70:
            level = "CRITICAL"
            recommendations.insert(0, "URGENT: Significant identity exposure detected")
            recommendations.append("Consider username segmentation across platforms")
            recommendations.append("Perform a comprehensive privacy audit")
        elif score >= 50:
            level = "HIGH"
            recommendations.append("Review and update privacy settings across all platforms")
            recommendations.append("Enable 2FA on all accounts using this username")
        elif score >= 30:
            level = "MODERATE"
            recommendations.append("Consider varying usernames for different platform types")
        else:
            level = "LOW"
            recommendations.append("Current exposure is minimal - maintain good practices")
        
        return IdentityRisk(
            level=level,
            score=score,
            factors=factors,
            recommendations=recommendations,
        )
    
    async def check_username(self, username: str) -> UsernameResult:
        """Perform comprehensive username OSINT scan."""
        username = self.validate_username(username)
        username_analysis = self.analyze_username(username)
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def bounded_check(client, platform):
            async with semaphore:
                return await self.check_platform(client, username, platform)
        
        async with httpx.AsyncClient(headers=self.headers) as client:
            tasks = [bounded_check(client, p) for p in PLATFORMS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        platforms = []
        for result in results:
            if isinstance(result, PlatformResult):
                platforms.append(result)
        
        found_platforms = [p for p in platforms if p.exists]
        accounts_found = len(found_platforms)
        
        categories = {}
        for p in found_platforms:
            cat = p.category
            categories[cat] = categories.get(cat, 0) + 1
        
        identity_risk = self.calculate_identity_risk(
            username, accounts_found, categories, username_analysis
        )
        
        platforms.sort(key=lambda x: (not x.exists, x.platform))
        
        return UsernameResult(
            username=username,
            total_platforms_checked=len(PLATFORMS),
            accounts_found=accounts_found,
            platforms=platforms,
            categories=categories,
            identity_risk=identity_risk,
            username_analysis=username_analysis,
        )
    
    def check_username_sync(self, username: str) -> UsernameResult:
        """Synchronous wrapper for check_username."""
        return asyncio.run(self.check_username(username))


async def check_username(username: str, timeout: float = 8.0) -> UsernameResult:
    """Check username across multiple platforms.
    
    Args:
        username: Username to check.
        timeout: Request timeout per platform.
        
    Returns:
        UsernameResult with comprehensive findings.
    """
    checker = UsernameChecker(timeout=timeout)
    return await checker.check_username(username)
