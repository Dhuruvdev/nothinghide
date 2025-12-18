"""Advanced Multi-Agent AI Analysis System.

Uses local image forensics and metadata analysis for deepfake and AI-generated content detection.
Works without external APIs - analyzes image properties, metadata, and visual patterns.
"""

import os
import io
import math
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

from PIL import Image
from PIL.ExifTags import TAGS


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


class MetadataAnalyzer:
    """Analyzes image metadata for signs of AI generation or manipulation."""
    
    AI_SOFTWARE_INDICATORS = [
        'stable diffusion', 'midjourney', 'dall-e', 'dalle', 'openai',
        'novelai', 'artbreeder', 'runway', 'automatic1111', 'comfyui',
        'invoke', 'diffusers', 'a1111', 'dreambooth', 'lora', 'controlnet',
        'adobe firefly', 'leonardo', 'playground', 'nightcafe', 'craiyon',
        'stablediffusion', 'sdxl', 'flux', 'kandinsky', 'imagen'
    ]
    
    EDITING_SOFTWARE = [
        'photoshop', 'gimp', 'lightroom', 'affinity', 'pixelmator',
        'capture one', 'darktable', 'rawtherapee', 'snapseed', 'vsco'
    ]
    
    CAMERA_MAKERS = [
        'canon', 'nikon', 'sony', 'fujifilm', 'panasonic', 'olympus',
        'leica', 'hasselblad', 'pentax', 'samsung', 'apple', 'google',
        'huawei', 'xiaomi', 'oppo', 'oneplus', 'motorola', 'lg'
    ]
    
    def analyze(self, img: Image.Image, raw_bytes: bytes) -> AgentResult:
        """Analyze image metadata for authenticity indicators."""
        start_time = datetime.now()
        
        try:
            findings = {
                "has_exif": False,
                "camera_detected": False,
                "ai_software_detected": False,
                "editing_software_detected": False,
                "metadata_stripped": False,
                "suspicious_patterns": [],
                "authenticity_indicators": [],
                "raw_metadata": {}
            }
            
            score = 0.5  # Start neutral
            
            # Extract EXIF data
            exif_data = {}
            try:
                exif = img._getexif()
                if exif:
                    findings["has_exif"] = True
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        try:
                            if isinstance(value, bytes):
                                value = value.decode('utf-8', errors='ignore')
                            exif_data[str(tag)] = str(value)[:200]
                        except:
                            pass
                    findings["raw_metadata"] = dict(list(exif_data.items())[:10])
            except Exception:
                pass
            
            # Check image info (PNG metadata, etc.)
            img_info = img.info if hasattr(img, 'info') else {}
            for key, value in img_info.items():
                try:
                    if isinstance(value, bytes):
                        value = value.decode('utf-8', errors='ignore')
                    exif_data[str(key)] = str(value)[:200]
                except:
                    pass
            
            # Check for AI generation software
            all_metadata = ' '.join([str(v).lower() for v in exif_data.values()])
            
            for indicator in self.AI_SOFTWARE_INDICATORS:
                if indicator in all_metadata:
                    findings["ai_software_detected"] = True
                    findings["suspicious_patterns"].append(f"AI software detected: {indicator}")
                    score -= 0.4
                    break
            
            # Check for camera/device
            for camera in self.CAMERA_MAKERS:
                if camera in all_metadata:
                    findings["camera_detected"] = True
                    findings["authenticity_indicators"].append(f"Camera/device: {camera}")
                    score += 0.2
                    break
            
            # Check for editing software
            for software in self.EDITING_SOFTWARE:
                if software in all_metadata:
                    findings["editing_software_detected"] = True
                    findings["authenticity_indicators"].append(f"Edited with: {software}")
                    score -= 0.1
                    break
            
            # Check if metadata was stripped (suspicious)
            if not findings["has_exif"] and len(exif_data) < 3:
                findings["metadata_stripped"] = True
                findings["suspicious_patterns"].append("Metadata appears stripped or minimal")
                score -= 0.15
            
            # Check for specific EXIF fields that indicate real camera
            if "Make" in exif_data or "Model" in exif_data:
                findings["authenticity_indicators"].append("Camera make/model present")
                score += 0.15
            
            if "DateTimeOriginal" in exif_data or "DateTime" in exif_data:
                findings["authenticity_indicators"].append("Original capture date present")
                score += 0.1
            
            if "GPSInfo" in exif_data or any("GPS" in k for k in exif_data.keys()):
                findings["authenticity_indicators"].append("GPS location data present")
                score += 0.15
            
            # Normalize score
            score = max(0.1, min(0.95, score))
            
            # Determine prediction
            if findings["ai_software_detected"]:
                prediction = "AI-GENERATED SOFTWARE DETECTED"
                is_authentic = False
            elif findings["camera_detected"] and findings["has_exif"]:
                prediction = "AUTHENTIC - Camera metadata verified"
                is_authentic = True
            elif findings["metadata_stripped"]:
                prediction = "INCONCLUSIVE - Metadata stripped"
                is_authentic = True  # Give benefit of doubt
            else:
                prediction = "LIKELY AUTHENTIC - No AI indicators"
                is_authentic = True
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return AgentResult(
                agent_name="Metadata Forensics",
                status=AnalysisStatus.COMPLETE,
                confidence=score,
                prediction=prediction,
                details=findings,
                processing_time=processing_time
            )
            
        except Exception as e:
            return AgentResult(
                agent_name="Metadata Forensics",
                status=AnalysisStatus.ERROR,
                error=str(e)[:100],
                processing_time=(datetime.now() - start_time).total_seconds()
            )


class ImagePropertiesAnalyzer:
    """Analyzes image properties for AI-generation patterns."""
    
    def analyze(self, img: Image.Image, raw_bytes: bytes) -> AgentResult:
        """Analyze image properties for signs of AI generation."""
        start_time = datetime.now()
        
        try:
            findings = {
                "dimensions": f"{img.width}x{img.height}",
                "aspect_ratio": round(img.width / img.height, 3),
                "mode": img.mode,
                "format": img.format or "Unknown",
                "file_size_kb": round(len(raw_bytes) / 1024, 2),
                "suspicious_patterns": [],
                "authenticity_indicators": []
            }
            
            score = 0.6  # Start slightly positive
            
            # Check for AI-typical dimensions
            ai_dimensions = [
                (512, 512), (768, 768), (1024, 1024), (2048, 2048),
                (512, 768), (768, 512), (1024, 768), (768, 1024),
                (896, 1152), (1152, 896), (1024, 1536), (1536, 1024)
            ]
            
            for w, h in ai_dimensions:
                if (img.width == w and img.height == h):
                    findings["suspicious_patterns"].append(f"Common AI-generated dimension: {w}x{h}")
                    score -= 0.15
                    break
            
            # Unusual/perfect aspect ratios common in AI
            aspect = img.width / img.height
            if aspect == 1.0:
                findings["suspicious_patterns"].append("Perfect 1:1 aspect ratio")
                score -= 0.05
            elif abs(aspect - 1.333) < 0.01:  # 4:3
                findings["authenticity_indicators"].append("Standard 4:3 aspect ratio")
                score += 0.05
            elif abs(aspect - 1.778) < 0.01:  # 16:9
                findings["authenticity_indicators"].append("Standard 16:9 aspect ratio")
                score += 0.05
            
            # Check compression quality (AI images often have consistent quality)
            if img.format == "JPEG":
                # Low file size relative to dimensions might indicate AI
                pixels = img.width * img.height
                bytes_per_pixel = len(raw_bytes) / pixels
                findings["compression_ratio"] = round(bytes_per_pixel, 4)
                
                if bytes_per_pixel < 0.3:
                    findings["suspicious_patterns"].append("Unusually high compression")
                elif bytes_per_pixel > 1.5:
                    findings["authenticity_indicators"].append("High quality/raw capture")
                    score += 0.1
            
            # Very large images are more likely real (high-res cameras)
            if img.width >= 4000 or img.height >= 4000:
                findings["authenticity_indicators"].append("High resolution suggests real camera")
                score += 0.15
            
            # Very small images are suspicious
            if img.width < 256 or img.height < 256:
                findings["suspicious_patterns"].append("Very low resolution")
                score -= 0.1
            
            # Check color depth
            if img.mode == "RGB":
                findings["color_depth"] = "24-bit (standard)"
            elif img.mode == "RGBA":
                findings["color_depth"] = "32-bit with alpha"
                findings["authenticity_indicators"].append("Alpha channel (common in edits)")
            
            # Normalize score
            score = max(0.2, min(0.9, score))
            
            # Determine prediction
            if len(findings["suspicious_patterns"]) >= 2:
                prediction = "SUSPICIOUS PROPERTIES - Multiple AI indicators"
                is_authentic = False
            elif len(findings["authenticity_indicators"]) >= 2:
                prediction = "AUTHENTIC PROPERTIES - Standard camera output"
                is_authentic = True
            else:
                prediction = "NEUTRAL - No definitive indicators"
                is_authentic = True
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return AgentResult(
                agent_name="Image Properties Analysis",
                status=AnalysisStatus.COMPLETE,
                confidence=score,
                prediction=prediction,
                details=findings,
                processing_time=processing_time
            )
            
        except Exception as e:
            return AgentResult(
                agent_name="Image Properties Analysis",
                status=AnalysisStatus.ERROR,
                error=str(e)[:100],
                processing_time=(datetime.now() - start_time).total_seconds()
            )


class VisualPatternAnalyzer:
    """Analyzes visual patterns for AI-generation artifacts."""
    
    def analyze(self, img: Image.Image, raw_bytes: bytes) -> AgentResult:
        """Analyze image for visual patterns indicating AI generation."""
        start_time = datetime.now()
        
        try:
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            findings = {
                "color_analysis": {},
                "edge_analysis": {},
                "suspicious_patterns": [],
                "authenticity_indicators": []
            }
            
            score = 0.55  # Start neutral-positive
            
            # Sample pixels for color analysis
            width, height = img.size
            pixels = list(img.getdata())
            sample_size = min(10000, len(pixels))
            step = max(1, len(pixels) // sample_size)
            sampled_pixels = pixels[::step]
            
            # Analyze color distribution
            r_values = [p[0] for p in sampled_pixels]
            g_values = [p[1] for p in sampled_pixels]
            b_values = [p[2] for p in sampled_pixels]
            
            def std_dev(values):
                mean = sum(values) / len(values)
                variance = sum((x - mean) ** 2 for x in values) / len(values)
                return math.sqrt(variance)
            
            r_std = std_dev(r_values)
            g_std = std_dev(g_values)
            b_std = std_dev(b_values)
            
            avg_std = (r_std + g_std + b_std) / 3
            findings["color_analysis"]["avg_std_dev"] = round(avg_std, 2)
            
            # Very uniform colors can indicate AI
            if avg_std < 20:
                findings["suspicious_patterns"].append("Unusually uniform color distribution")
                score -= 0.1
            elif avg_std > 60:
                findings["authenticity_indicators"].append("Natural color variance")
                score += 0.1
            
            # Check for pure black/white pixels (common in AI art)
            pure_black = sum(1 for p in sampled_pixels if p == (0, 0, 0))
            pure_white = sum(1 for p in sampled_pixels if p == (255, 255, 255))
            pure_ratio = (pure_black + pure_white) / len(sampled_pixels)
            
            findings["color_analysis"]["pure_ratio"] = round(pure_ratio * 100, 2)
            
            if pure_ratio > 0.1:
                findings["suspicious_patterns"].append("High pure black/white ratio")
                score -= 0.1
            
            # Calculate unique colors ratio
            unique_colors = len(set(sampled_pixels))
            color_diversity = unique_colors / len(sampled_pixels)
            findings["color_analysis"]["color_diversity"] = round(color_diversity * 100, 2)
            
            if color_diversity < 0.1:
                findings["suspicious_patterns"].append("Low color diversity")
                score -= 0.1
            elif color_diversity > 0.5:
                findings["authenticity_indicators"].append("High color diversity (natural)")
                score += 0.1
            
            # Simple edge detection via gradient
            small_img = img.resize((100, 100), Image.Resampling.LANCZOS)
            small_pixels = list(small_img.getdata())
            
            edge_strengths = []
            for i in range(99):
                for j in range(99):
                    idx = i * 100 + j
                    p1 = small_pixels[idx]
                    p2 = small_pixels[idx + 1]
                    diff = abs(p1[0] - p2[0]) + abs(p1[1] - p2[1]) + abs(p1[2] - p2[2])
                    edge_strengths.append(diff)
            
            avg_edge = sum(edge_strengths) / len(edge_strengths)
            edge_std = std_dev(edge_strengths)
            
            findings["edge_analysis"]["avg_edge_strength"] = round(avg_edge, 2)
            findings["edge_analysis"]["edge_variance"] = round(edge_std, 2)
            
            # AI images often have smoother transitions
            if avg_edge < 15:
                findings["suspicious_patterns"].append("Unusually smooth gradients")
                score -= 0.1
            elif avg_edge > 40:
                findings["authenticity_indicators"].append("Natural texture/edges")
                score += 0.1
            
            # Normalize score
            score = max(0.2, min(0.9, score))
            
            # Determine prediction
            suspicious_count = len(findings["suspicious_patterns"])
            authentic_count = len(findings["authenticity_indicators"])
            
            if suspicious_count >= 3:
                prediction = "SUSPICIOUS PATTERNS - AI-like visual characteristics"
                is_authentic = False
            elif authentic_count >= 3:
                prediction = "AUTHENTIC PATTERNS - Natural visual characteristics"
                is_authentic = True
            elif suspicious_count > authentic_count:
                prediction = "POSSIBLY AI-GENERATED - Some concerning patterns"
                is_authentic = True  # Benefit of doubt
            else:
                prediction = "LIKELY AUTHENTIC - Natural visual patterns"
                is_authentic = True
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return AgentResult(
                agent_name="Visual Pattern Analysis",
                status=AnalysisStatus.COMPLETE,
                confidence=score,
                prediction=prediction,
                details=findings,
                processing_time=processing_time
            )
            
        except Exception as e:
            return AgentResult(
                agent_name="Visual Pattern Analysis",
                status=AnalysisStatus.ERROR,
                error=str(e)[:100],
                processing_time=(datetime.now() - start_time).total_seconds()
            )


class MultiAgentAnalyzer:
    """Coordinates multiple analysis agents for comprehensive image analysis."""
    
    def __init__(self):
        self.metadata_analyzer = MetadataAnalyzer()
        self.properties_analyzer = ImagePropertiesAnalyzer()
        self.visual_analyzer = VisualPatternAnalyzer()
    
    def _calculate_threat_level(self, agent_results: List[AgentResult]) -> ThreatLevel:
        """Calculate overall threat level based on agent results."""
        threat_score = 0
        
        for result in agent_results:
            if result.status != AnalysisStatus.COMPLETE:
                continue
            
            prediction = result.prediction.upper()
            
            if "AI-GENERATED" in prediction or "AI SOFTWARE" in prediction:
                threat_score += 3
            elif "SUSPICIOUS" in prediction:
                threat_score += 2
            elif "POSSIBLY AI" in prediction:
                threat_score += 1
        
        if threat_score >= 6:
            return ThreatLevel.CRITICAL
        elif threat_score >= 4:
            return ThreatLevel.HIGH
        elif threat_score >= 2:
            return ThreatLevel.MEDIUM
        elif threat_score >= 1:
            return ThreatLevel.LOW
        return ThreatLevel.SAFE
    
    def _generate_recommendations(self, agent_results: List[AgentResult], threat_level: ThreatLevel) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        if threat_level == ThreatLevel.SAFE:
            recommendations = [
                "No significant manipulation indicators detected",
                "Image appears to be authentic based on metadata and visual analysis",
                "Standard verification complete"
            ]
        elif threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            recommendations = [
                "High likelihood of AI generation or manipulation detected",
                "Verify source and authenticity before trusting this image",
                "Check for original source using reverse image search",
                "Look for telltale AI signs: hands, text, background inconsistencies"
            ]
        elif threat_level == ThreatLevel.MEDIUM:
            recommendations = [
                "Some indicators of potential manipulation detected",
                "Consider additional verification if authenticity is critical",
                "Check image metadata and source credibility"
            ]
        else:  # LOW
            recommendations = [
                "Minor indicators detected but likely authentic",
                "Image properties are consistent with real photographs",
                "Standard precautions recommended"
            ]
        
        return recommendations[:4]
    
    def _generate_summary(self, agent_results: List[AgentResult], threat_level: ThreatLevel) -> str:
        """Generate a human-readable analysis summary."""
        successful = [r for r in agent_results if r.status == AnalysisStatus.COMPLETE]
        
        if not successful:
            return "Analysis could not be completed. Please try again."
        
        summary = f"Local Forensics Analysis Complete. {len(successful)} detection methods used. "
        
        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            summary += "WARNING: Multiple indicators suggest this image may be AI-generated or manipulated."
        elif threat_level == ThreatLevel.MEDIUM:
            summary += "CAUTION: Some indicators of artificial content detected. Further verification recommended."
        elif threat_level == ThreatLevel.LOW:
            summary += "NOTICE: Minor indicators detected, but image is likely authentic."
        else:
            summary += "Image appears authentic with no significant manipulation indicators."
        
        return summary
    
    async def analyze(self, image_bytes: bytes) -> MultiAgentAnalysisResult:
        """Run all analyzers and aggregate results."""
        start_time = datetime.now()
        
        try:
            img = Image.open(io.BytesIO(image_bytes))
        except Exception as e:
            return MultiAgentAnalysisResult(
                overall_verdict="ERROR - Could not process image",
                threat_level=ThreatLevel.SAFE,
                is_authentic=True,
                confidence_score=0.0,
                agent_results=[],
                recommendations=["Please upload a valid image file"],
                analysis_summary=f"Error: {str(e)[:100]}",
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_processing_time=0.0
            )
        
        # Run all analyzers
        agent_results = [
            self.metadata_analyzer.analyze(img, image_bytes),
            self.properties_analyzer.analyze(img, image_bytes),
            self.visual_analyzer.analyze(img, image_bytes),
        ]
        
        threat_level = self._calculate_threat_level(agent_results)
        recommendations = self._generate_recommendations(agent_results, threat_level)
        summary = self._generate_summary(agent_results, threat_level)
        
        successful_results = [r for r in agent_results if r.status == AnalysisStatus.COMPLETE]
        
        # Calculate overall authenticity
        is_authentic = threat_level in [ThreatLevel.SAFE, ThreatLevel.LOW]
        
        # Calculate average confidence
        if successful_results:
            avg_confidence = sum(r.confidence for r in successful_results) / len(successful_results)
        else:
            avg_confidence = 0.5
        
        if is_authentic:
            overall_verdict = "AUTHENTIC - No significant manipulation detected"
        else:
            overall_verdict = "SUSPICIOUS - Potential AI-generation or manipulation detected"
        
        total_time = (datetime.now() - start_time).total_seconds()
        
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
