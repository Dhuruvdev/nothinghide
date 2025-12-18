"""Advanced Multi-Agent AI Analysis System.

Uses Hugging Face Inference API for deepfake detection and AI-generated content analysis.
Free tier compatible - no API key required for public models.
"""

import io
import base64
import asyncio
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

import httpx
from PIL import Image


class AnalysisStatus(Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    ERROR = "error"


class ThreatLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AgentResult:
    agent_name: str
    status: AnalysisStatus
    confidence: float = 0.0
    prediction: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    processing_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "status": self.status.value,
            "confidence": round(self.confidence * 100, 2),
            "prediction": self.prediction,
            "details": self.details,
            "error": self.error,
            "processing_time": round(self.processing_time, 3),
        }


@dataclass
class MultiAgentAnalysisResult:
    overall_verdict: str
    threat_level: ThreatLevel
    is_authentic: bool
    confidence_score: float
    agent_results: List[AgentResult]
    recommendations: List[str]
    analysis_summary: str
    timestamp: str
    total_processing_time: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_verdict": self.overall_verdict,
            "threat_level": self.threat_level.value,
            "is_authentic": self.is_authentic,
            "confidence_score": round(self.confidence_score * 100, 2),
            "agent_results": [r.to_dict() for r in self.agent_results],
            "recommendations": self.recommendations,
            "analysis_summary": self.analysis_summary,
            "timestamp": self.timestamp,
            "total_processing_time": round(self.total_processing_time, 3),
        }


class BaseAgent:
    """Base class for AI analysis agents."""
    
    def __init__(self, name: str, model_id: str):
        self.name = name
        self.model_id = model_id
        self.api_url = f"https://api-inference.huggingface.co/models/{model_id}"
        self.timeout = 60.0
    
    async def analyze(self, image_bytes: bytes) -> AgentResult:
        raise NotImplementedError


class DeepfakeDetectorAgent(BaseAgent):
    """Detects deepfake/AI-manipulated images using Vision Transformer model."""
    
    def __init__(self):
        super().__init__(
            name="Deepfake Detector v2",
            model_id="prithivMLmods/Deep-Fake-Detector-v2-Model"
        )
    
    async def analyze(self, image_bytes: bytes) -> AgentResult:
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                files = {"data": ("image.jpg", image_bytes, "image/jpeg")}
                response = await client.post(
                    self.api_url,
                    files=files
                )
                
                if response.status_code == 503:
                    return AgentResult(
                        agent_name=self.name,
                        status=AnalysisStatus.ERROR,
                        error="Model is loading, please try again in a few seconds",
                        processing_time=asyncio.get_event_loop().time() - start_time
                    )
                
                if response.status_code != 200:
                    return AgentResult(
                        agent_name=self.name,
                        status=AnalysisStatus.ERROR,
                        error=f"API error: {response.status_code}",
                        processing_time=asyncio.get_event_loop().time() - start_time
                    )
                
                results = response.json()
                
                if isinstance(results, list) and len(results) > 0:
                    top_result = max(results, key=lambda x: x.get("score", 0))
                    label = top_result.get("label", "unknown").lower()
                    score = top_result.get("score", 0)
                    
                    is_real = "real" in label or "realism" in label
                    prediction = "AUTHENTIC" if is_real else "DEEPFAKE DETECTED"
                    
                    return AgentResult(
                        agent_name=self.name,
                        status=AnalysisStatus.COMPLETE,
                        confidence=score,
                        prediction=prediction,
                        details={
                            "raw_label": top_result.get("label"),
                            "all_scores": {r.get("label"): round(r.get("score", 0) * 100, 2) for r in results},
                            "model_version": "v2",
                            "architecture": "Vision Transformer (ViT)"
                        },
                        processing_time=asyncio.get_event_loop().time() - start_time
                    )
                
                return AgentResult(
                    agent_name=self.name,
                    status=AnalysisStatus.ERROR,
                    error="Unexpected response format",
                    processing_time=asyncio.get_event_loop().time() - start_time
                )
                
        except httpx.TimeoutException:
            return AgentResult(
                agent_name=self.name,
                status=AnalysisStatus.ERROR,
                error="Request timed out - model may be loading",
                processing_time=asyncio.get_event_loop().time() - start_time
            )
        except Exception as e:
            return AgentResult(
                agent_name=self.name,
                status=AnalysisStatus.ERROR,
                error=str(e),
                processing_time=asyncio.get_event_loop().time() - start_time
            )


class AIGeneratedDetectorAgent(BaseAgent):
    """Detects AI-generated images (DALL-E, Midjourney, Stable Diffusion, etc.)."""
    
    def __init__(self):
        super().__init__(
            name="AI-Generated Content Detector",
            model_id="umm-maybe/AI-image-detector"
        )
    
    async def analyze(self, image_bytes: bytes) -> AgentResult:
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                files = {"data": ("image.jpg", image_bytes, "image/jpeg")}
                response = await client.post(
                    self.api_url,
                    files=files
                )
                
                if response.status_code == 503:
                    return AgentResult(
                        agent_name=self.name,
                        status=AnalysisStatus.ERROR,
                        error="Model is loading, please try again in a few seconds",
                        processing_time=asyncio.get_event_loop().time() - start_time
                    )
                
                if response.status_code != 200:
                    return AgentResult(
                        agent_name=self.name,
                        status=AnalysisStatus.ERROR,
                        error=f"API error: {response.status_code}",
                        processing_time=asyncio.get_event_loop().time() - start_time
                    )
                
                results = response.json()
                
                if isinstance(results, list) and len(results) > 0:
                    top_result = max(results, key=lambda x: x.get("score", 0))
                    label = top_result.get("label", "unknown").lower()
                    score = top_result.get("score", 0)
                    
                    is_human = "human" in label or "real" in label
                    prediction = "HUMAN-CREATED" if is_human else "AI-GENERATED"
                    
                    return AgentResult(
                        agent_name=self.name,
                        status=AnalysisStatus.COMPLETE,
                        confidence=score,
                        prediction=prediction,
                        details={
                            "raw_label": top_result.get("label"),
                            "all_scores": {r.get("label"): round(r.get("score", 0) * 100, 2) for r in results},
                            "detects": ["DALL-E", "Midjourney", "Stable Diffusion", "AI Art"]
                        },
                        processing_time=asyncio.get_event_loop().time() - start_time
                    )
                
                return AgentResult(
                    agent_name=self.name,
                    status=AnalysisStatus.ERROR,
                    error="Unexpected response format",
                    processing_time=asyncio.get_event_loop().time() - start_time
                )
                
        except httpx.TimeoutException:
            return AgentResult(
                agent_name=self.name,
                status=AnalysisStatus.ERROR,
                error="Request timed out - model may be loading",
                processing_time=asyncio.get_event_loop().time() - start_time
            )
        except Exception as e:
            return AgentResult(
                agent_name=self.name,
                status=AnalysisStatus.ERROR,
                error=str(e),
                processing_time=asyncio.get_event_loop().time() - start_time
            )


class NSFWDetectorAgent(BaseAgent):
    """Detects inappropriate or NSFW content in images."""
    
    def __init__(self):
        super().__init__(
            name="Content Safety Scanner",
            model_id="Falconsai/nsfw_image_detection"
        )
    
    async def analyze(self, image_bytes: bytes) -> AgentResult:
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                files = {"data": ("image.jpg", image_bytes, "image/jpeg")}
                response = await client.post(
                    self.api_url,
                    files=files
                )
                
                if response.status_code == 503:
                    return AgentResult(
                        agent_name=self.name,
                        status=AnalysisStatus.ERROR,
                        error="Model is loading, please try again in a few seconds",
                        processing_time=asyncio.get_event_loop().time() - start_time
                    )
                
                if response.status_code != 200:
                    return AgentResult(
                        agent_name=self.name,
                        status=AnalysisStatus.ERROR,
                        error=f"API error: {response.status_code}",
                        processing_time=asyncio.get_event_loop().time() - start_time
                    )
                
                results = response.json()
                
                if isinstance(results, list) and len(results) > 0:
                    top_result = max(results, key=lambda x: x.get("score", 0))
                    label = top_result.get("label", "unknown").lower()
                    score = top_result.get("score", 0)
                    
                    is_safe = "normal" in label or "safe" in label or "sfw" in label
                    prediction = "SAFE CONTENT" if is_safe else "INAPPROPRIATE CONTENT"
                    
                    return AgentResult(
                        agent_name=self.name,
                        status=AnalysisStatus.COMPLETE,
                        confidence=score,
                        prediction=prediction,
                        details={
                            "raw_label": top_result.get("label"),
                            "all_scores": {r.get("label"): round(r.get("score", 0) * 100, 2) for r in results},
                            "content_category": "safe" if is_safe else "flagged"
                        },
                        processing_time=asyncio.get_event_loop().time() - start_time
                    )
                
                return AgentResult(
                    agent_name=self.name,
                    status=AnalysisStatus.ERROR,
                    error="Unexpected response format",
                    processing_time=asyncio.get_event_loop().time() - start_time
                )
                
        except httpx.TimeoutException:
            return AgentResult(
                agent_name=self.name,
                status=AnalysisStatus.ERROR,
                error="Request timed out - model may be loading",
                processing_time=asyncio.get_event_loop().time() - start_time
            )
        except Exception as e:
            return AgentResult(
                agent_name=self.name,
                status=AnalysisStatus.ERROR,
                error=str(e),
                processing_time=asyncio.get_event_loop().time() - start_time
            )


class MultiAgentAnalyzer:
    """Coordinates multiple AI agents for comprehensive image analysis."""
    
    def __init__(self):
        self.agents = [
            DeepfakeDetectorAgent(),
            AIGeneratedDetectorAgent(),
            NSFWDetectorAgent(),
        ]
    
    def _preprocess_image(self, image_bytes: bytes, max_size: int = 1024) -> bytes:
        """Resize image if too large to optimize API calls."""
        try:
            img = Image.open(io.BytesIO(image_bytes))
            
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            
            if max(img.size) > max_size:
                ratio = max_size / max(img.size)
                new_size = (int(img.size[0] * ratio), int(img.size[1] * ratio))
                img = img.resize(new_size, Image.Resampling.LANCZOS)
            
            output = io.BytesIO()
            img.save(output, format='JPEG', quality=90)
            return output.getvalue()
        except Exception:
            return image_bytes
    
    def _calculate_threat_level(self, agent_results: List[AgentResult]) -> ThreatLevel:
        """Calculate overall threat level based on agent results."""
        threat_indicators = 0
        total_confidence = 0.0
        
        for result in agent_results:
            if result.status != AnalysisStatus.COMPLETE:
                continue
            
            prediction = result.prediction.upper()
            
            if "DEEPFAKE" in prediction:
                threat_indicators += 3
                total_confidence += result.confidence
            elif "AI-GENERATED" in prediction:
                threat_indicators += 2
                total_confidence += result.confidence
            elif "INAPPROPRIATE" in prediction:
                threat_indicators += 2
                total_confidence += result.confidence
        
        if threat_indicators >= 5:
            return ThreatLevel.CRITICAL
        elif threat_indicators >= 4:
            return ThreatLevel.HIGH
        elif threat_indicators >= 2:
            return ThreatLevel.MEDIUM
        elif threat_indicators >= 1:
            return ThreatLevel.LOW
        return ThreatLevel.SAFE
    
    def _generate_recommendations(self, agent_results: List[AgentResult], threat_level: ThreatLevel) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        for result in agent_results:
            if result.status != AnalysisStatus.COMPLETE:
                continue
            
            prediction = result.prediction.upper()
            
            if "DEEPFAKE" in prediction:
                recommendations.extend([
                    "This image shows signs of AI manipulation - verify the source",
                    "Cross-reference with other images of the same person/scene",
                    "Look for inconsistencies in lighting, shadows, and edges",
                    "Check metadata and reverse image search for original"
                ])
            elif "AI-GENERATED" in prediction:
                recommendations.extend([
                    "This appears to be AI-generated content (DALL-E, Midjourney, etc.)",
                    "Do not use as evidence or authentic documentation",
                    "Check for telltale signs: hands, text, background details"
                ])
            elif "INAPPROPRIATE" in prediction:
                recommendations.extend([
                    "This content may not be suitable for all audiences",
                    "Consider content moderation policies before sharing"
                ])
        
        if threat_level == ThreatLevel.SAFE:
            recommendations = ["No significant manipulation detected - image appears authentic"]
        
        return list(set(recommendations))[:6]
    
    def _generate_summary(self, agent_results: List[AgentResult], threat_level: ThreatLevel) -> str:
        """Generate a human-readable analysis summary."""
        successful = [r for r in agent_results if r.status == AnalysisStatus.COMPLETE]
        failed = [r for r in agent_results if r.status == AnalysisStatus.ERROR]
        
        if not successful:
            return "Analysis could not be completed. Please try again."
        
        findings = []
        for result in successful:
            findings.append(f"{result.agent_name}: {result.prediction} ({result.confidence*100:.1f}% confidence)")
        
        summary = f"Multi-Agent Analysis Complete. {len(successful)}/{len(self.agents)} agents succeeded. "
        
        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            summary += "WARNING: High likelihood of manipulated or synthetic content detected. "
        elif threat_level == ThreatLevel.MEDIUM:
            summary += "CAUTION: Some indicators of artificial content detected. "
        elif threat_level == ThreatLevel.LOW:
            summary += "NOTICE: Minor indicators detected, likely authentic. "
        else:
            summary += "Image appears authentic with no significant manipulation detected. "
        
        return summary
    
    async def analyze(self, image_bytes: bytes) -> MultiAgentAnalysisResult:
        """Run all agents in parallel and aggregate results."""
        start_time = asyncio.get_event_loop().time()
        
        processed_image = self._preprocess_image(image_bytes)
        
        tasks = [agent.analyze(processed_image) for agent in self.agents]
        agent_results = await asyncio.gather(*tasks)
        
        threat_level = self._calculate_threat_level(agent_results)
        recommendations = self._generate_recommendations(agent_results, threat_level)
        summary = self._generate_summary(agent_results, threat_level)
        
        successful_results = [r for r in agent_results if r.status == AnalysisStatus.COMPLETE]
        
        is_authentic = True
        avg_confidence = 0.0
        
        if successful_results:
            for result in successful_results:
                if "DEEPFAKE" in result.prediction or "AI-GENERATED" in result.prediction:
                    if result.confidence > 0.6:
                        is_authentic = False
                        break
            
            avg_confidence = sum(r.confidence for r in successful_results) / len(successful_results)
        
        if is_authentic:
            overall_verdict = "AUTHENTIC - No manipulation detected"
        else:
            overall_verdict = "SUSPICIOUS - Potential manipulation or AI-generation detected"
        
        total_time = asyncio.get_event_loop().time() - start_time
        
        return MultiAgentAnalysisResult(
            overall_verdict=overall_verdict,
            threat_level=threat_level,
            is_authentic=is_authentic,
            confidence_score=avg_confidence,
            agent_results=agent_results,
            recommendations=recommendations,
            analysis_summary=summary,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_processing_time=total_time
        )
