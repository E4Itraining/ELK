"""
Cognitive Monitoring Module
===========================

Monitors cognitive aspects of AI systems including:
- Response quality evaluation
- Hallucination detection
- Bias detection
- Toxicity detection
- Sentiment analysis
- Prompt analysis
"""

import re
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock

from .config import Config, CognitiveConfig

logger = logging.getLogger(__name__)


class HallucinationType(Enum):
    """Types of hallucinations."""
    FACTUAL = "factual"  # Incorrect facts
    ATTRIBUTION = "attribution"  # Wrong source attribution
    FABRICATION = "fabrication"  # Made up information
    CONTRADICTION = "contradiction"  # Self-contradicting statements
    TEMPORAL = "temporal"  # Wrong dates/times
    ENTITY = "entity"  # Wrong names/entities


class HallucinationSeverity(Enum):
    """Severity levels for hallucinations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BiasCategory(Enum):
    """Categories of bias."""
    GENDER = "gender"
    RACE = "race"
    AGE = "age"
    RELIGION = "religion"
    POLITICAL = "political"
    SOCIOECONOMIC = "socioeconomic"
    NATIONALITY = "nationality"
    DISABILITY = "disability"


class BiasDirection(Enum):
    """Direction of detected bias."""
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"


class ToxicityCategory(Enum):
    """Categories of toxic content."""
    HATE_SPEECH = "hate_speech"
    HARASSMENT = "harassment"
    VIOLENCE = "violence"
    SEXUAL_CONTENT = "sexual_content"
    SELF_HARM = "self_harm"
    PROFANITY = "profanity"
    THREAT = "threat"


class SentimentLabel(Enum):
    """Sentiment labels."""
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"
    MIXED = "mixed"


class ContentAction(Enum):
    """Actions taken on content."""
    ALLOWED = "allowed"
    FLAGGED = "flagged"
    BLOCKED = "blocked"
    MODIFIED = "modified"


class IntentCategory(Enum):
    """Prompt intent categories."""
    QUESTION = "question"
    INSTRUCTION = "instruction"
    CONVERSATION = "conversation"
    CODING = "coding"
    CREATIVE = "creative"
    ANALYSIS = "analysis"
    TRANSLATION = "translation"
    SUMMARIZATION = "summarization"
    OTHER = "other"


class ReadingLevel(Enum):
    """Response reading level."""
    ELEMENTARY = "elementary"
    MIDDLE_SCHOOL = "middle_school"
    HIGH_SCHOOL = "high_school"
    COLLEGE = "college"
    GRADUATE = "graduate"
    PROFESSIONAL = "professional"


@dataclass
class QualityScores:
    """Quality evaluation scores."""
    overall_score: float = 0.0
    relevance_score: float = 0.0
    coherence_score: float = 0.0
    completeness_score: float = 0.0
    accuracy_score: float = 0.0
    fluency_score: float = 0.0
    helpfulness_score: float = 0.0
    evaluation_method: str = "automatic"


@dataclass
class HumanFeedback:
    """Human feedback data."""
    rating: Optional[int] = None  # 1-5 scale
    thumbs_up: Optional[bool] = None
    feedback_text: Optional[str] = None
    feedback_categories: List[str] = field(default_factory=list)


@dataclass
class FactualError:
    """A detected factual error."""
    claim: str
    source_support: bool
    confidence: float


@dataclass
class HallucinationResult:
    """Hallucination detection result."""
    detected: bool = False
    confidence: float = 0.0
    type: Optional[HallucinationType] = None
    severity: Optional[HallucinationSeverity] = None
    factual_errors: List[FactualError] = field(default_factory=list)
    detection_method: str = "internal"


@dataclass
class BiasResult:
    """Bias detection result for a single category."""
    category: BiasCategory
    score: float  # 0-1, higher = more biased
    direction: BiasDirection
    examples: List[str] = field(default_factory=list)


@dataclass
class BiasAnalysis:
    """Complete bias analysis result."""
    detected: bool = False
    overall_score: float = 0.0
    categories: List[BiasResult] = field(default_factory=list)
    demographic_parity: Optional[float] = None
    equalized_odds: Optional[float] = None
    calibration: Optional[float] = None


@dataclass
class ToxicityResult:
    """Toxicity detection result for a single category."""
    category: ToxicityCategory
    score: float  # 0-1, higher = more toxic
    flagged: bool = False


@dataclass
class ToxicityAnalysis:
    """Complete toxicity analysis result."""
    detected: bool = False
    overall_score: float = 0.0
    categories: List[ToxicityResult] = field(default_factory=list)
    action_taken: ContentAction = ContentAction.ALLOWED


@dataclass
class SentimentResult:
    """Sentiment analysis result."""
    label: SentimentLabel = SentimentLabel.NEUTRAL
    score: float = 0.0  # -1 to 1
    emotions: Dict[str, float] = field(default_factory=dict)


@dataclass
class PromptAnalysis:
    """Prompt analysis result."""
    complexity_score: float = 0.0
    clarity_score: float = 0.0
    intent_category: IntentCategory = IntentCategory.OTHER
    topic_classification: str = ""
    language: str = "en"
    contains_pii: bool = False
    injection_attempt: bool = False
    jailbreak_attempt: bool = False


@dataclass
class ResponseAnalysis:
    """Response analysis result."""
    word_count: int = 0
    sentence_count: int = 0
    reading_level: ReadingLevel = ReadingLevel.HIGH_SCHOOL
    format_type: str = "text"
    contains_code: bool = False
    contains_urls: bool = False
    refusal: bool = False
    refusal_reason: Optional[str] = None


@dataclass
class ConversationMetrics:
    """Conversation-level metrics."""
    turn_number: int = 0
    context_length: int = 0
    topic_drift_score: float = 0.0
    engagement_score: float = 0.0


@dataclass
class CognitiveMetric:
    """Complete cognitive metric for a single request."""
    request_id: str
    trace_id: Optional[str] = None
    provider: str = ""
    model: str = ""
    environment: str = "production"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    quality: QualityScores = field(default_factory=QualityScores)
    human_feedback: Optional[HumanFeedback] = None
    hallucination: HallucinationResult = field(default_factory=HallucinationResult)
    bias: BiasAnalysis = field(default_factory=BiasAnalysis)
    toxicity: ToxicityAnalysis = field(default_factory=ToxicityAnalysis)
    sentiment_input: Optional[SentimentResult] = None
    sentiment_output: Optional[SentimentResult] = None
    prompt_analysis: PromptAnalysis = field(default_factory=PromptAnalysis)
    response_analysis: ResponseAnalysis = field(default_factory=ResponseAnalysis)
    conversation: ConversationMetrics = field(default_factory=ConversationMetrics)
    context: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Elasticsearch indexing."""
        doc = {
            "@timestamp": self.timestamp.isoformat(),
            "request_id": self.request_id,
            "provider": self.provider,
            "model": self.model,
            "environment": self.environment,
            "quality": {
                "overall_score": self.quality.overall_score,
                "relevance_score": self.quality.relevance_score,
                "coherence_score": self.quality.coherence_score,
                "completeness_score": self.quality.completeness_score,
                "accuracy_score": self.quality.accuracy_score,
                "fluency_score": self.quality.fluency_score,
                "helpfulness_score": self.quality.helpfulness_score,
                "evaluation_method": self.quality.evaluation_method,
            },
            "hallucination": {
                "detected": self.hallucination.detected,
                "confidence": self.hallucination.confidence,
                "detection_method": self.hallucination.detection_method,
            },
            "bias": {
                "detected": self.bias.detected,
                "overall_score": self.bias.overall_score,
            },
            "toxicity": {
                "detected": self.toxicity.detected,
                "overall_score": self.toxicity.overall_score,
                "action_taken": self.toxicity.action_taken.value,
            },
            "prompt_analysis": {
                "complexity_score": self.prompt_analysis.complexity_score,
                "clarity_score": self.prompt_analysis.clarity_score,
                "intent_category": self.prompt_analysis.intent_category.value,
                "topic_classification": self.prompt_analysis.topic_classification,
                "language": self.prompt_analysis.language,
                "contains_pii": self.prompt_analysis.contains_pii,
                "injection_attempt": self.prompt_analysis.injection_attempt,
                "jailbreak_attempt": self.prompt_analysis.jailbreak_attempt,
            },
            "response_analysis": {
                "word_count": self.response_analysis.word_count,
                "sentence_count": self.response_analysis.sentence_count,
                "reading_level": self.response_analysis.reading_level.value,
                "format_type": self.response_analysis.format_type,
                "contains_code": self.response_analysis.contains_code,
                "contains_urls": self.response_analysis.contains_urls,
                "refusal": self.response_analysis.refusal,
            },
            "conversation": {
                "turn_number": self.conversation.turn_number,
                "context_length": self.conversation.context_length,
                "topic_drift_score": self.conversation.topic_drift_score,
                "engagement_score": self.conversation.engagement_score,
            },
        }

        # Add optional fields
        if self.trace_id:
            doc["trace_id"] = self.trace_id

        # Add human feedback if present
        if self.human_feedback:
            doc["quality"]["human_feedback"] = {}
            if self.human_feedback.rating is not None:
                doc["quality"]["human_feedback"]["rating"] = self.human_feedback.rating
            if self.human_feedback.thumbs_up is not None:
                doc["quality"]["human_feedback"]["thumbs_up"] = self.human_feedback.thumbs_up
            if self.human_feedback.feedback_text:
                doc["quality"]["human_feedback"]["feedback_text"] = self.human_feedback.feedback_text
            if self.human_feedback.feedback_categories:
                doc["quality"]["human_feedback"]["feedback_categories"] = self.human_feedback.feedback_categories

        # Add hallucination details
        if self.hallucination.type:
            doc["hallucination"]["type"] = self.hallucination.type.value
        if self.hallucination.severity:
            doc["hallucination"]["severity"] = self.hallucination.severity.value
        if self.hallucination.factual_errors:
            doc["hallucination"]["factual_errors"] = [
                {
                    "claim": error.claim,
                    "source_support": error.source_support,
                    "confidence": error.confidence,
                }
                for error in self.hallucination.factual_errors
            ]

        # Add bias categories
        if self.bias.categories:
            doc["bias"]["categories"] = [
                {
                    "category": cat.category.value,
                    "score": cat.score,
                    "direction": cat.direction.value,
                    "examples": cat.examples,
                }
                for cat in self.bias.categories
            ]
        if self.bias.demographic_parity is not None:
            doc["bias"]["fairness_metrics"] = {
                "demographic_parity": self.bias.demographic_parity,
                "equalized_odds": self.bias.equalized_odds,
                "calibration": self.bias.calibration,
            }

        # Add toxicity categories
        if self.toxicity.categories:
            doc["toxicity"]["categories"] = [
                {
                    "category": cat.category.value,
                    "score": cat.score,
                    "flagged": cat.flagged,
                }
                for cat in self.toxicity.categories
            ]

        # Add sentiment
        if self.sentiment_input:
            doc["sentiment"] = {"input": {
                "label": self.sentiment_input.label.value,
                "score": self.sentiment_input.score,
                "emotions": self.sentiment_input.emotions,
            }}
        if self.sentiment_output:
            if "sentiment" not in doc:
                doc["sentiment"] = {}
            doc["sentiment"]["output"] = {
                "label": self.sentiment_output.label.value,
                "score": self.sentiment_output.score,
                "emotions": self.sentiment_output.emotions,
            }

        # Add refusal reason if present
        if self.response_analysis.refusal_reason:
            doc["response_analysis"]["refusal_reason"] = self.response_analysis.refusal_reason

        # Add context and metadata
        if self.context:
            doc["context"] = self.context
        if self.metadata:
            doc["metadata"] = self.metadata

        return doc


class CognitiveMonitor:
    """
    Cognitive monitoring for AI systems.

    Evaluates response quality, detects hallucinations, bias,
    and toxicity in AI-generated content.
    """

    def __init__(self, config: Config):
        """
        Initialize the cognitive monitor.

        Args:
            config: Configuration object
        """
        self.config = config
        self.cog_config = config.cognitive
        self._metrics_buffer: List[CognitiveMetric] = []
        self._buffer_lock = Lock()

        # Patterns for detection
        self._injection_patterns = [
            r"ignore\s+(previous|all|above)\s+instructions",
            r"disregard\s+(previous|all)\s+",
            r"system\s*:\s*you\s+are",
            r"pretend\s+you\s+are",
            r"act\s+as\s+(if|a)\s+",
            r"\[INST\]|\[/INST\]",
            r"<\|im_start\|>|<\|im_end\|>",
        ]

        self._jailbreak_patterns = [
            r"dan\s*mode",
            r"developer\s*mode",
            r"jailbreak",
            r"bypass\s+(safety|filter|restriction)",
            r"evil\s*mode",
            r"uncensored\s*mode",
            r"no\s*restrictions",
        ]

        self._pii_patterns = {
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "phone": r"(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}",
            "ssn": r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",
            "credit_card": r"\b\d{4}[-]?\d{4}[-]?\d{4}[-]?\d{4}\b",
            "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        }

        self._code_patterns = [
            r"```[\s\S]*?```",
            r"def\s+\w+\s*\(",
            r"class\s+\w+\s*[:\(]",
            r"function\s+\w+\s*\(",
            r"import\s+\w+",
            r"from\s+\w+\s+import",
        ]

    def analyze_request(
        self,
        request_id: str,
        provider: str,
        model: str,
        prompt: str,
        response: str,
        **kwargs
    ) -> CognitiveMetric:
        """
        Analyze a request/response pair for cognitive metrics.

        Args:
            request_id: Unique request identifier
            provider: AI provider name
            model: Model name
            prompt: Input prompt
            response: Generated response
            **kwargs: Additional fields

        Returns:
            The cognitive metric
        """
        metric = CognitiveMetric(
            request_id=request_id,
            provider=provider,
            model=model,
            environment=kwargs.get('environment', 'production'),
        )

        # Set trace ID if provided
        if 'trace_id' in kwargs:
            metric.trace_id = kwargs['trace_id']

        # Analyze prompt
        metric.prompt_analysis = self._analyze_prompt(prompt)

        # Analyze response
        metric.response_analysis = self._analyze_response(response)

        # Evaluate quality
        metric.quality = self._evaluate_quality(prompt, response)

        # Detect hallucination
        if self.cog_config.hallucination.enabled:
            metric.hallucination = self._detect_hallucination(
                prompt, response,
                sources=kwargs.get('sources', [])
            )

        # Detect bias
        if self.cog_config.bias.enabled:
            metric.bias = self._detect_bias(response)

        # Detect toxicity
        if self.cog_config.toxicity.enabled:
            metric.toxicity = self._detect_toxicity(response)

        # Analyze sentiment
        metric.sentiment_input = self._analyze_sentiment(prompt)
        metric.sentiment_output = self._analyze_sentiment(response)

        # Set conversation metrics if provided
        if 'turn_number' in kwargs:
            metric.conversation.turn_number = kwargs['turn_number']
        if 'context_length' in kwargs:
            metric.conversation.context_length = kwargs['context_length']

        # Set context
        for ctx_field in ['team', 'project', 'application', 'use_case']:
            if ctx_field in kwargs:
                metric.context[ctx_field] = kwargs[ctx_field]

        # Add to buffer
        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        return metric

    def _analyze_prompt(self, prompt: str) -> PromptAnalysis:
        """Analyze the input prompt."""
        analysis = PromptAnalysis()

        # Calculate complexity based on length and vocabulary
        words = prompt.split()
        unique_words = set(w.lower() for w in words)
        analysis.complexity_score = min(1.0, len(unique_words) / max(len(words), 1))

        # Check for clarity (simple heuristic)
        has_question = '?' in prompt
        has_clear_instruction = any(
            prompt.lower().startswith(word)
            for word in ['please', 'can you', 'write', 'explain', 'create', 'help']
        )
        analysis.clarity_score = 0.5 + (0.25 if has_question else 0) + (0.25 if has_clear_instruction else 0)

        # Determine intent
        analysis.intent_category = self._classify_intent(prompt)

        # Detect PII
        for pii_type, pattern in self._pii_patterns.items():
            if re.search(pattern, prompt, re.IGNORECASE):
                analysis.contains_pii = True
                break

        # Detect injection attempts
        for pattern in self._injection_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                analysis.injection_attempt = True
                break

        # Detect jailbreak attempts
        for pattern in self._jailbreak_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                analysis.jailbreak_attempt = True
                break

        return analysis

    def _classify_intent(self, prompt: str) -> IntentCategory:
        """Classify the intent of a prompt."""
        prompt_lower = prompt.lower()

        # Check for coding
        if any(kw in prompt_lower for kw in ['code', 'function', 'program', 'script', 'debug', 'fix this']):
            return IntentCategory.CODING

        # Check for creative
        if any(kw in prompt_lower for kw in ['write a story', 'poem', 'creative', 'imagine']):
            return IntentCategory.CREATIVE

        # Check for translation
        if any(kw in prompt_lower for kw in ['translate', 'translation', 'in french', 'in spanish']):
            return IntentCategory.TRANSLATION

        # Check for summarization
        if any(kw in prompt_lower for kw in ['summarize', 'summary', 'tldr', 'brief']):
            return IntentCategory.SUMMARIZATION

        # Check for analysis
        if any(kw in prompt_lower for kw in ['analyze', 'analysis', 'explain why', 'compare']):
            return IntentCategory.ANALYSIS

        # Check for question
        if '?' in prompt or prompt_lower.startswith(('what', 'who', 'where', 'when', 'why', 'how')):
            return IntentCategory.QUESTION

        # Check for instruction
        if any(kw in prompt_lower for kw in ['please', 'can you', 'would you', 'help me']):
            return IntentCategory.INSTRUCTION

        return IntentCategory.OTHER

    def _analyze_response(self, response: str) -> ResponseAnalysis:
        """Analyze the response."""
        analysis = ResponseAnalysis()

        # Count words and sentences
        words = response.split()
        analysis.word_count = len(words)
        analysis.sentence_count = len(re.findall(r'[.!?]+', response))

        # Determine reading level (simple approximation)
        avg_word_length = sum(len(w) for w in words) / max(len(words), 1)
        if avg_word_length < 4:
            analysis.reading_level = ReadingLevel.ELEMENTARY
        elif avg_word_length < 5:
            analysis.reading_level = ReadingLevel.MIDDLE_SCHOOL
        elif avg_word_length < 6:
            analysis.reading_level = ReadingLevel.HIGH_SCHOOL
        elif avg_word_length < 7:
            analysis.reading_level = ReadingLevel.COLLEGE
        else:
            analysis.reading_level = ReadingLevel.GRADUATE

        # Determine format type
        if '```' in response:
            analysis.format_type = "code_block"
            analysis.contains_code = True
        elif re.search(r'^\s*[-*]\s', response, re.MULTILINE):
            analysis.format_type = "list"
        elif re.search(r'^\s*\d+\.\s', response, re.MULTILINE):
            analysis.format_type = "numbered_list"
        elif re.search(r'^\s*#', response, re.MULTILINE):
            analysis.format_type = "markdown"
        else:
            analysis.format_type = "text"

        # Check for code
        if not analysis.contains_code:
            for pattern in self._code_patterns:
                if re.search(pattern, response):
                    analysis.contains_code = True
                    break

        # Check for URLs
        analysis.contains_urls = bool(re.search(r'https?://\S+', response))

        # Check for refusal
        refusal_phrases = [
            "i cannot", "i can't", "i'm not able to", "i am not able to",
            "i won't", "i will not", "i'm unable to",
            "as an ai", "as a language model",
            "against my guidelines", "violates my policy"
        ]
        response_lower = response.lower()
        for phrase in refusal_phrases:
            if phrase in response_lower:
                analysis.refusal = True
                analysis.refusal_reason = "content_policy"
                break

        return analysis

    def _evaluate_quality(self, prompt: str, response: str) -> QualityScores:
        """Evaluate response quality."""
        scores = QualityScores()
        scores.evaluation_method = "automatic"

        # Basic fluency check (punctuation, capitalization)
        has_proper_punctuation = bool(re.search(r'[.!?]$', response.strip()))
        has_capitalization = response[0].isupper() if response else False
        scores.fluency_score = 0.5 + (0.25 if has_proper_punctuation else 0) + (0.25 if has_capitalization else 0)

        # Coherence based on sentence structure
        sentences = re.split(r'[.!?]+', response)
        avg_sentence_length = sum(len(s.split()) for s in sentences) / max(len(sentences), 1)
        scores.coherence_score = min(1.0, max(0.0, 1.0 - abs(15 - avg_sentence_length) / 30))

        # Relevance (check for keyword overlap)
        prompt_words = set(prompt.lower().split())
        response_words = set(response.lower().split())
        overlap = len(prompt_words & response_words)
        scores.relevance_score = min(1.0, overlap / max(len(prompt_words), 1))

        # Completeness (response length relative to prompt)
        length_ratio = len(response) / max(len(prompt), 1)
        scores.completeness_score = min(1.0, length_ratio / 2)

        # Helpfulness (heuristic based on structure)
        has_structure = any([
            '```' in response,
            re.search(r'^\s*[-*]', response, re.MULTILINE),
            re.search(r'^\s*\d+\.', response, re.MULTILINE),
        ])
        scores.helpfulness_score = 0.6 + (0.4 if has_structure else 0)

        # Overall score
        scores.overall_score = (
            scores.fluency_score * 0.15 +
            scores.coherence_score * 0.20 +
            scores.relevance_score * 0.25 +
            scores.completeness_score * 0.20 +
            scores.helpfulness_score * 0.20
        )

        return scores

    def _detect_hallucination(
        self,
        prompt: str,
        response: str,
        sources: List[str] = None
    ) -> HallucinationResult:
        """
        Detect potential hallucinations in the response.

        This is a simplified heuristic-based detection.
        For production, consider using a dedicated model.
        """
        result = HallucinationResult()
        result.detection_method = "heuristic"

        # Check for common hallucination patterns
        confidence_markers = [
            (r'according to\s+(?!the|my|your)', 0.3),
            (r'studies show|research shows', 0.2),
            (r'\d+%\s+of\s+people', 0.3),
            (r'in\s+\d{4}(?:\s|,)', 0.2),  # Years
            (r'dr\.|professor\s+\w+', 0.2),  # Names
        ]

        hallucination_score = 0.0
        for pattern, weight in confidence_markers:
            if re.search(pattern, response, re.IGNORECASE):
                hallucination_score += weight

        # If sources provided, check for unsupported claims
        if sources:
            source_text = ' '.join(sources).lower()
            # Extract potential factual claims
            claim_patterns = [
                r'(?:is|are|was|were)\s+(?:a|an|the)?\s*(\w+(?:\s+\w+){0,3})',
                r'(\d+(?:\.\d+)?(?:%|percent))',
            ]

            for pattern in claim_patterns:
                claims = re.findall(pattern, response, re.IGNORECASE)
                for claim in claims:
                    if isinstance(claim, str) and claim.lower() not in source_text:
                        result.factual_errors.append(FactualError(
                            claim=claim,
                            source_support=False,
                            confidence=0.5
                        ))
                        hallucination_score += 0.2

        result.confidence = min(1.0, hallucination_score)
        result.detected = result.confidence > self.cog_config.hallucination.confidence_threshold

        if result.detected:
            if result.factual_errors:
                result.type = HallucinationType.FACTUAL
            else:
                result.type = HallucinationType.FABRICATION

            if result.confidence > 0.8:
                result.severity = HallucinationSeverity.HIGH
            elif result.confidence > 0.6:
                result.severity = HallucinationSeverity.MEDIUM
            else:
                result.severity = HallucinationSeverity.LOW

        return result

    def _detect_bias(self, response: str) -> BiasAnalysis:
        """Detect potential bias in the response."""
        analysis = BiasAnalysis()
        response_lower = response.lower()

        # Simple keyword-based detection
        bias_indicators = {
            BiasCategory.GENDER: {
                'positive': ['women are better at', 'men are better at', 'female employees', 'male employees'],
                'negative': ['women can\'t', 'men can\'t', 'women shouldn\'t', 'men shouldn\'t'],
            },
            BiasCategory.AGE: {
                'positive': ['young people are more', 'older people are wiser'],
                'negative': ['too old to', 'too young to', 'millennials are'],
            },
            BiasCategory.RACE: {
                'positive': [],
                'negative': ['typical of', 'always do', 'people like them'],
            },
        }

        total_score = 0.0

        for category, patterns in bias_indicators.items():
            if category.value not in self.cog_config.bias.categories:
                continue

            category_score = 0.0
            direction = BiasDirection.NEUTRAL
            examples = []

            for pattern in patterns.get('positive', []):
                if pattern in response_lower:
                    category_score += 0.5
                    direction = BiasDirection.POSITIVE
                    examples.append(pattern)

            for pattern in patterns.get('negative', []):
                if pattern in response_lower:
                    category_score += 0.5
                    direction = BiasDirection.NEGATIVE
                    examples.append(pattern)

            if category_score > 0:
                analysis.categories.append(BiasResult(
                    category=category,
                    score=min(1.0, category_score),
                    direction=direction,
                    examples=examples
                ))
                total_score += category_score

        analysis.overall_score = min(1.0, total_score)
        analysis.detected = analysis.overall_score > self.cog_config.bias.threshold

        return analysis

    def _detect_toxicity(self, response: str) -> ToxicityAnalysis:
        """Detect toxicity in the response."""
        analysis = ToxicityAnalysis()
        response_lower = response.lower()

        # Simple keyword-based detection
        toxicity_patterns = {
            ToxicityCategory.HATE_SPEECH: [
                r'\b(hate|despise)\s+(all|every)\s+\w+',
                r'\b(inferior|superior)\s+race',
            ],
            ToxicityCategory.HARASSMENT: [
                r'\byou\s+(idiot|moron|stupid)',
                r'\bshut\s+up\b',
            ],
            ToxicityCategory.VIOLENCE: [
                r'\b(kill|murder|attack)\s+(you|them|him|her)',
                r'\bviolent\s+action',
            ],
            ToxicityCategory.PROFANITY: [
                # Simplified list
                r'\b(damn|hell)\b',
            ],
        }

        total_score = 0.0

        for category, patterns in toxicity_patterns.items():
            category_score = 0.0

            for pattern in patterns:
                if re.search(pattern, response_lower):
                    category_score += 0.5

            if category_score > 0:
                flagged = category_score > self.cog_config.toxicity.threshold
                analysis.categories.append(ToxicityResult(
                    category=category,
                    score=min(1.0, category_score),
                    flagged=flagged
                ))
                total_score += category_score

        analysis.overall_score = min(1.0, total_score)
        analysis.detected = analysis.overall_score > self.cog_config.toxicity.threshold

        # Determine action
        if analysis.overall_score > 0.8:
            analysis.action_taken = ContentAction.BLOCKED
        elif analysis.overall_score > 0.5:
            analysis.action_taken = ContentAction.FLAGGED
        else:
            analysis.action_taken = ContentAction.ALLOWED

        return analysis

    def _analyze_sentiment(self, text: str) -> SentimentResult:
        """Analyze sentiment of text."""
        result = SentimentResult()

        # Simple keyword-based sentiment analysis
        positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'happy', 'love', 'best']
        negative_words = ['bad', 'terrible', 'awful', 'horrible', 'sad', 'hate', 'worst', 'poor']

        text_lower = text.lower()
        words = text_lower.split()

        pos_count = sum(1 for w in words if w in positive_words)
        neg_count = sum(1 for w in words if w in negative_words)

        total = pos_count + neg_count
        if total == 0:
            result.label = SentimentLabel.NEUTRAL
            result.score = 0.0
        elif pos_count > neg_count:
            result.label = SentimentLabel.POSITIVE
            result.score = pos_count / max(len(words), 1)
        elif neg_count > pos_count:
            result.label = SentimentLabel.NEGATIVE
            result.score = -neg_count / max(len(words), 1)
        else:
            result.label = SentimentLabel.MIXED
            result.score = 0.0

        return result

    def record_human_feedback(
        self,
        request_id: str,
        rating: Optional[int] = None,
        thumbs_up: Optional[bool] = None,
        feedback_text: Optional[str] = None,
        categories: Optional[List[str]] = None
    ) -> None:
        """
        Record human feedback for a request.

        Args:
            request_id: Request identifier
            rating: 1-5 rating
            thumbs_up: Thumbs up/down
            feedback_text: Free text feedback
            categories: Feedback categories
        """
        feedback = HumanFeedback(
            rating=rating,
            thumbs_up=thumbs_up,
            feedback_text=feedback_text,
            feedback_categories=categories or []
        )

        # Find and update metric in buffer
        with self._buffer_lock:
            for metric in self._metrics_buffer:
                if metric.request_id == request_id:
                    metric.human_feedback = feedback
                    break

        logger.info(f"Recorded human feedback for request {request_id}")

    def get_buffered_metrics(self, clear: bool = True) -> List[CognitiveMetric]:
        """Get buffered metrics."""
        with self._buffer_lock:
            metrics = self._metrics_buffer.copy()
            if clear:
                self._metrics_buffer.clear()
        return metrics

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of cognitive metrics."""
        with self._buffer_lock:
            total = len(self._metrics_buffer)
            if total == 0:
                return {
                    "total_analyzed": 0,
                    "avg_quality_score": 0,
                    "hallucination_rate": 0,
                    "bias_rate": 0,
                    "toxicity_rate": 0,
                }

            quality_scores = [m.quality.overall_score for m in self._metrics_buffer]
            hallucinations = sum(1 for m in self._metrics_buffer if m.hallucination.detected)
            biases = sum(1 for m in self._metrics_buffer if m.bias.detected)
            toxic = sum(1 for m in self._metrics_buffer if m.toxicity.detected)

            return {
                "total_analyzed": total,
                "avg_quality_score": sum(quality_scores) / total,
                "hallucination_rate": hallucinations / total,
                "bias_rate": biases / total,
                "toxicity_rate": toxic / total,
                "buffered_metrics": total,
            }
