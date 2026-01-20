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
class ProfileInfo:
    """Profile information extracted from a platform."""
    avatar_url: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    followers: Optional[int] = None
    following: Optional[int] = None
    posts_count: Optional[int] = None
    location: Optional[str] = None
    website: Optional[str] = None
    joined_date: Optional[str] = None
    verified: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "avatar_url": self.avatar_url,
            "display_name": self.display_name,
            "bio": self.bio,
            "followers": self.followers,
            "following": self.following,
            "posts_count": self.posts_count,
            "location": self.location,
            "website": self.website,
            "joined_date": self.joined_date,
            "verified": self.verified,
            "extra": self.extra,
        }


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
    profile: Optional[ProfileInfo] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "url": self.url,
            "exists": self.exists,
            "category": self.category,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "error": self.error,
            "profile": self.profile.to_dict() if self.profile else None,
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
    
    def extract_profile_info(self, platform_name: str, html: str, username: str) -> Optional[ProfileInfo]:
        """Extract profile information from HTML based on platform."""
        try:
            profile = ProfileInfo()
            
            # Extract Open Graph and meta tags (works for many platforms)
            og_image = re.search(r'<meta[^>]*property=["\']og:image["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
            if not og_image:
                og_image = re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*property=["\']og:image["\']', html, re.I)
            if og_image:
                profile.avatar_url = og_image.group(1)
            
            og_title = re.search(r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
            if not og_title:
                og_title = re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*property=["\']og:title["\']', html, re.I)
            if og_title:
                profile.display_name = og_title.group(1)[:100]
            
            og_desc = re.search(r'<meta[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
            if not og_desc:
                og_desc = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
            if og_desc:
                profile.bio = og_desc.group(1)[:300]
            
            # Platform-specific extraction
            if platform_name == "GitHub":
                avatar = re.search(r'<img[^>]*class="[^"]*avatar[^"]*"[^>]*src=["\']([^"\']+)["\']', html)
                if avatar:
                    profile.avatar_url = avatar.group(1)
                
                followers = re.search(r'<span[^>]*class="[^"]*text-bold[^"]*"[^>]*>(\d+(?:,\d+)*(?:\.\d+)?[kKmM]?)</span>\s*followers', html, re.I)
                if followers:
                    profile.followers = self._parse_count(followers.group(1))
                
                following = re.search(r'<span[^>]*class="[^"]*text-bold[^"]*"[^>]*>(\d+(?:,\d+)*(?:\.\d+)?[kKmM]?)</span>\s*following', html, re.I)
                if following:
                    profile.following = self._parse_count(following.group(1))
                
                repos = re.search(r'Repositories[^<]*<span[^>]*>(\d+)', html)
                if repos:
                    profile.posts_count = int(repos.group(1))
                
                location = re.search(r'<span[^>]*itemprop=["\']homeLocation["\'][^>]*>([^<]+)</span>', html)
                if location:
                    profile.location = location.group(1).strip()
                
                bio_tag = re.search(r'<div[^>]*class="[^"]*user-profile-bio[^"]*"[^>]*>([^<]+)', html)
                if bio_tag:
                    profile.bio = bio_tag.group(1).strip()[:300]
            
            elif platform_name == "Twitter/X":
                # Twitter requires API, but we can try meta tags
                pass
            
            elif platform_name == "Instagram":
                # Try to get from JSON data embedded in page
                json_data = re.search(r'"profile_pic_url(?:_hd)?"\s*:\s*"([^"]+)"', html)
                if json_data:
                    profile.avatar_url = json_data.group(1).replace('\\u0026', '&')
                
                followers = re.search(r'"edge_followed_by"\s*:\s*\{\s*"count"\s*:\s*(\d+)', html)
                if followers:
                    profile.followers = int(followers.group(1))
                
                following = re.search(r'"edge_follow"\s*:\s*\{\s*"count"\s*:\s*(\d+)', html)
                if following:
                    profile.following = int(following.group(1))
            
            elif platform_name == "Reddit":
                karma = re.search(r'(\d+(?:,\d+)*)\s*karma', html, re.I)
                if karma:
                    profile.extra["karma"] = self._parse_count(karma.group(1))
                
                avatar = re.search(r'<img[^>]*src=["\']([^"\']*(?:reddit|redd\.it)[^"\']*(?:avatar|snoo)[^"\']*)["\']', html, re.I)
                if avatar:
                    profile.avatar_url = avatar.group(1)
            
            elif platform_name == "LinkedIn":
                # LinkedIn blocks scraping heavily, rely on meta tags
                pass
            
            elif platform_name == "YouTube":
                subs = re.search(r'"subscriberCountText"\s*:\s*\{\s*"simpleText"\s*:\s*"([^"]+)"', html)
                if subs:
                    profile.followers = self._parse_count(subs.group(1).split()[0])
                
                videos = re.search(r'"videosCountText"\s*:\s*\{\s*"runs"\s*:\s*\[\s*\{\s*"text"\s*:\s*"(\d+)', html)
                if videos:
                    profile.posts_count = int(videos.group(1))
            
            elif platform_name == "TikTok":
                followers = re.search(r'"followerCount"\s*:\s*(\d+)', html)
                if followers:
                    profile.followers = int(followers.group(1))
                
                following = re.search(r'"followingCount"\s*:\s*(\d+)', html)
                if following:
                    profile.following = int(following.group(1))
                
                likes = re.search(r'"heartCount"\s*:\s*(\d+)', html)
                if likes:
                    profile.extra["likes"] = int(likes.group(1))
            
            elif platform_name == "Twitch":
                avatar = re.search(r'"profileImageURL"\s*:\s*"([^"]+)"', html)
                if avatar:
                    profile.avatar_url = avatar.group(1)
            
            elif platform_name == "Medium":
                followers = re.search(r'(\d+(?:\.\d+)?[kKmM]?)\s*Followers', html, re.I)
                if followers:
                    profile.followers = self._parse_count(followers.group(1))
            
            elif platform_name == "Dev.to":
                avatar = re.search(r'<img[^>]*class="[^"]*profile-pic[^"]*"[^>]*src=["\']([^"\']+)["\']', html)
                if avatar:
                    profile.avatar_url = avatar.group(1)
            
            elif platform_name == "Dribbble":
                followers = re.search(r'<span[^>]*class="[^"]*stat-value[^"]*"[^>]*>(\d+(?:,\d+)*)</span>\s*Followers', html, re.I)
                if followers:
                    profile.followers = self._parse_count(followers.group(1))
            
            elif platform_name == "Behance":
                followers = re.search(r'"appreciations"\s*:\s*(\d+)', html)
                if followers:
                    profile.extra["appreciations"] = int(followers.group(1))
            
            # Check if we got any useful info
            if profile.avatar_url or profile.display_name or profile.bio or profile.followers:
                return profile
            
            return None
            
        except Exception:
            return None
    
    def _parse_count(self, count_str: str) -> int:
        """Parse count strings like '1.2K' or '3,456' to integers."""
        try:
            count_str = count_str.replace(',', '').strip().upper()
            if 'K' in count_str:
                return int(float(count_str.replace('K', '')) * 1000)
            elif 'M' in count_str:
                return int(float(count_str.replace('M', '')) * 1000000)
            elif 'B' in count_str:
                return int(float(count_str.replace('B', '')) * 1000000000)
            return int(float(count_str))
        except:
            return 0

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
            profile = None
            
            if exists:
                content = response.text
                content_lower = content.lower()
                not_found_indicators = [
                    "not found", "doesn't exist", "page not found",
                    "user not found", "404", "no user", "this page",
                    "sorry", "unavailable", "deleted", "suspended"
                ]
                for indicator in not_found_indicators:
                    if indicator in content_lower[:2000]:
                        exists = False
                        break
                
                # Extract profile info if account exists
                if exists:
                    profile = self.extract_profile_info(platform["name"], content, username)
            
            return PlatformResult(
                platform=platform["name"],
                url=url,
                exists=exists,
                category=platform["category"],
                status_code=response.status_code,
                response_time=round(response_time, 3),
                profile=profile,
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
        username_analysis: Dict[str, Any],
        platforms: List[PlatformResult] = None
    ) -> IdentityRisk:
        """Calculate identity exposure risk using advanced 2026 intelligence chain."""
        score = 0
        factors = []
        recommendations = []
        
        # Collection Layer Analysis
        if accounts_found > 15:
            score += 40
            factors.append("Massive digital footprint (>15 accounts found)")
        elif accounts_found > 5:
            score += 20
            factors.append("Moderate digital footprint")
            
        # Category Correlation (Collection -> Analysis)
        if categories.get("Financial", 0) > 0:
            score += 30
            factors.append("Exposure in Financial platforms - High targeting risk")
        if categories.get("Professional", 0) > 0:
            score += 15
            factors.append("Professional profile linkage detected")
            
        # Analysis Layer (Pattern Recognition)
        if username_analysis.get("patterns"):
            for pattern in username_analysis["patterns"]:
                if "real_name" in pattern:
                    score += 25
                    factors.append("PII Leak: Username likely based on legal identity")
                if "birth_year" in pattern:
                    score += 20
                    factors.append("PII Leak: Possible birth year/age exposure")
                    
        # Knowledge Extraction Layer (Cross-Platform Linkage)
        if platforms:
            avatars = [p.profile.avatar_url for p in platforms if p.profile and p.profile.avatar_url]
            if len(set(avatars)) < len(avatars) and len(avatars) > 1:
                score += 15
                factors.append("Identity Convergence: Identical avatars used across platforms")
                
            # Recursive extraction logic (simulated for 2026 standard)
            bios = [p.profile.bio for p in platforms if p.profile and p.profile.bio]
            for bio in bios:
                if bio and re.search(r'[\w\.-]+@[\w\.-]+\.\w+', bio):
                    score += 20
                    factors.append("Recursive Data Leak: Email found in profile bio")
                    break

        # Risk Extraction
        level = "LOW"
        if score >= 80:
            level = "CRITICAL"
            recommendations.append("Immediate: De-link professional and financial accounts")
            recommendations.append("Use non-PII based aliases for social media")
        elif score >= 50:
            level = "HIGH"
            recommendations.append("High risk of de-anonymization")
            recommendations.append("Enable 2FA on all identified accounts")
        elif score >= 30:
            level = "MODERATE"
            recommendations.append("Monitor account activity for targeted phishing")
            
        return IdentityRisk(level=level, score=min(100, score), factors=factors, recommendations=recommendations)

    async def check_username(self, username: str) -> UsernameResult:
        """Perform complete username OSINT scan."""
        username = self.validate_username(username)
        username_analysis = self.analyze_username(username)
        
        platforms_to_check = PLATFORMS
        results = []
        
        async with httpx.AsyncClient(headers=self.headers, verify=False) as client:
            tasks = [self.check_platform(client, username, p) for p in platforms_to_check]
            results = await asyncio.gather(*tasks)
            
        accounts_found = sum(1 for r in results if r.exists)
        categories = {}
        for r in results:
            if r.exists:
                categories[r.category] = categories.get(r.category, 0) + 1
                
        identity_risk = self.calculate_identity_risk(
            username, 
            accounts_found, 
            categories, 
            username_analysis,
            results
        )
        
        return UsernameResult(
            username=username,
            total_platforms_checked=len(platforms_to_check),
            accounts_found=accounts_found,
            platforms=results,
            categories=categories,
            identity_risk=identity_risk,
            username_analysis=username_analysis,
        )


async def check_username(username: str) -> UsernameResult:
    """Main entry point for checking a username."""
    checker = UsernameChecker()
    return await checker.check_username(username)
