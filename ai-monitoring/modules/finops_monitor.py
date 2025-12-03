"""
FinOps Monitoring Module
========================

Monitors financial operations of AI systems including:
- Token costs and spending
- Budget management and alerts
- Cost allocation and attribution
- ROI tracking
- Usage optimization
- Spending forecasts
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from threading import Lock

from .config import Config, FinOpsConfig

logger = logging.getLogger(__name__)


class BudgetAlertLevel(Enum):
    """Budget alert levels."""
    NORMAL = "normal"
    WARNING_50 = "warning_50"
    WARNING_75 = "warning_75"
    WARNING_90 = "warning_90"
    EXCEEDED = "exceeded"


class CostTrend(Enum):
    """Cost trend direction."""
    INCREASING = "increasing"
    STABLE = "stable"
    DECREASING = "decreasing"


class RequestFrequency(Enum):
    """Request frequency classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class TokenMetrics:
    """Token usage metrics."""
    input: int = 0
    output: int = 0
    total: int = 0
    cached: int = 0
    reasoning: int = 0


@dataclass
class CostMetrics:
    """Cost metrics for a request."""
    input_cost: float = 0.0
    output_cost: float = 0.0
    total_cost: float = 0.0
    currency: str = "USD"
    cached_savings: float = 0.0
    optimization_savings: float = 0.0


@dataclass
class BudgetStatus:
    """Budget status."""
    daily_budget: float = 0.0
    daily_spent: float = 0.0
    daily_remaining: float = 0.0
    weekly_budget: float = 0.0
    weekly_spent: float = 0.0
    monthly_budget: float = 0.0
    monthly_spent: float = 0.0
    budget_exceeded: bool = False
    budget_alert_level: BudgetAlertLevel = BudgetAlertLevel.NORMAL


@dataclass
class CostAllocation:
    """Cost allocation information."""
    team: Optional[str] = None
    project: Optional[str] = None
    department: Optional[str] = None
    cost_center: Optional[str] = None
    environment: Optional[str] = None
    user_id: Optional[str] = None
    application: Optional[str] = None
    use_case: Optional[str] = None


@dataclass
class OptimizationMetrics:
    """Optimization metrics."""
    cache_hit: bool = False
    cache_savings: float = 0.0
    prompt_compressed: bool = False
    compression_ratio: float = 1.0
    model_fallback: bool = False
    original_model: Optional[str] = None
    fallback_model: Optional[str] = None
    fallback_savings: float = 0.0
    batch_processed: bool = False
    batch_size: int = 1


@dataclass
class ROIMetrics:
    """Return on investment metrics."""
    business_value: float = 0.0
    value_category: Optional[str] = None
    conversion: bool = False
    revenue_impact: float = 0.0
    cost_avoidance: float = 0.0
    time_saved_minutes: float = 0.0
    roi_ratio: float = 0.0


@dataclass
class PricingInfo:
    """Pricing information."""
    input_rate_per_1k: float = 0.0
    output_rate_per_1k: float = 0.0
    pricing_tier: str = "standard"
    discount_applied: float = 0.0
    commitment_discount: bool = False


@dataclass
class UsagePattern:
    """Usage pattern information."""
    hour_of_day: int = 0
    day_of_week: int = 0
    is_peak_hour: bool = False
    request_frequency: RequestFrequency = RequestFrequency.MEDIUM


@dataclass
class CostForecast:
    """Cost forecast."""
    predicted_daily_cost: float = 0.0
    predicted_monthly_cost: float = 0.0
    trend: CostTrend = CostTrend.STABLE
    anomaly_detected: bool = False
    anomaly_score: float = 0.0


@dataclass
class FinOpsMetric:
    """Complete FinOps metric for a single request."""
    request_id: str
    provider: str = ""
    model: str = ""
    environment: str = "production"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tokens: TokenMetrics = field(default_factory=TokenMetrics)
    cost: CostMetrics = field(default_factory=CostMetrics)
    budget: BudgetStatus = field(default_factory=BudgetStatus)
    allocation: CostAllocation = field(default_factory=CostAllocation)
    optimization: OptimizationMetrics = field(default_factory=OptimizationMetrics)
    roi: ROIMetrics = field(default_factory=ROIMetrics)
    pricing: PricingInfo = field(default_factory=PricingInfo)
    usage_pattern: UsagePattern = field(default_factory=UsagePattern)
    forecast: CostForecast = field(default_factory=CostForecast)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Elasticsearch indexing."""
        doc = {
            "@timestamp": self.timestamp.isoformat(),
            "request_id": self.request_id,
            "provider": self.provider,
            "model": self.model,
            "environment": self.environment,
            "tokens": {
                "input": self.tokens.input,
                "output": self.tokens.output,
                "total": self.tokens.total,
                "cached": self.tokens.cached,
                "reasoning": self.tokens.reasoning,
            },
            "cost": {
                "input_cost": self.cost.input_cost,
                "output_cost": self.cost.output_cost,
                "total_cost": self.cost.total_cost,
                "currency": self.cost.currency,
                "cached_savings": self.cost.cached_savings,
                "optimization_savings": self.cost.optimization_savings,
            },
            "budget": {
                "daily_budget": self.budget.daily_budget,
                "daily_spent": self.budget.daily_spent,
                "daily_remaining": self.budget.daily_remaining,
                "weekly_budget": self.budget.weekly_budget,
                "weekly_spent": self.budget.weekly_spent,
                "monthly_budget": self.budget.monthly_budget,
                "monthly_spent": self.budget.monthly_spent,
                "budget_exceeded": self.budget.budget_exceeded,
                "budget_alert_level": self.budget.budget_alert_level.value,
            },
            "allocation": {},
            "optimization": {
                "cache_hit": self.optimization.cache_hit,
                "cache_savings": self.optimization.cache_savings,
                "prompt_compressed": self.optimization.prompt_compressed,
                "compression_ratio": self.optimization.compression_ratio,
                "model_fallback": self.optimization.model_fallback,
                "batch_processed": self.optimization.batch_processed,
                "batch_size": self.optimization.batch_size,
            },
            "roi": {
                "business_value": self.roi.business_value,
                "conversion": self.roi.conversion,
                "revenue_impact": self.roi.revenue_impact,
                "cost_avoidance": self.roi.cost_avoidance,
                "time_saved_minutes": self.roi.time_saved_minutes,
                "roi_ratio": self.roi.roi_ratio,
            },
            "pricing": {
                "input_rate_per_1k": self.pricing.input_rate_per_1k,
                "output_rate_per_1k": self.pricing.output_rate_per_1k,
                "pricing_tier": self.pricing.pricing_tier,
                "discount_applied": self.pricing.discount_applied,
                "commitment_discount": self.pricing.commitment_discount,
            },
            "usage_pattern": {
                "hour_of_day": self.usage_pattern.hour_of_day,
                "day_of_week": self.usage_pattern.day_of_week,
                "is_peak_hour": self.usage_pattern.is_peak_hour,
                "request_frequency": self.usage_pattern.request_frequency.value,
            },
            "forecast": {
                "predicted_daily_cost": self.forecast.predicted_daily_cost,
                "predicted_monthly_cost": self.forecast.predicted_monthly_cost,
                "trend": self.forecast.trend.value,
                "anomaly_detected": self.forecast.anomaly_detected,
                "anomaly_score": self.forecast.anomaly_score,
            },
        }

        # Add allocation fields
        if self.allocation.team:
            doc["allocation"]["team"] = self.allocation.team
        if self.allocation.project:
            doc["allocation"]["project"] = self.allocation.project
        if self.allocation.department:
            doc["allocation"]["department"] = self.allocation.department
        if self.allocation.cost_center:
            doc["allocation"]["cost_center"] = self.allocation.cost_center
        if self.allocation.environment:
            doc["allocation"]["environment"] = self.allocation.environment
        if self.allocation.user_id:
            doc["allocation"]["user_id"] = self.allocation.user_id
        if self.allocation.application:
            doc["allocation"]["application"] = self.allocation.application
        if self.allocation.use_case:
            doc["allocation"]["use_case"] = self.allocation.use_case

        # Add optimization model fallback info
        if self.optimization.model_fallback:
            doc["optimization"]["original_model"] = self.optimization.original_model
            doc["optimization"]["fallback_model"] = self.optimization.fallback_model
            doc["optimization"]["fallback_savings"] = self.optimization.fallback_savings

        # Add ROI value category
        if self.roi.value_category:
            doc["roi"]["value_category"] = self.roi.value_category

        # Add metadata
        if self.metadata:
            doc["metadata"] = self.metadata

        return doc


class FinOpsMonitor:
    """
    FinOps monitoring for AI systems.

    Tracks costs, budgets, ROI, and optimization opportunities
    for AI API usage across providers and models.
    """

    def __init__(self, config: Config):
        """
        Initialize the FinOps monitor.

        Args:
            config: Configuration object
        """
        self.config = config
        self.fin_config = config.finops
        self._metrics_buffer: List[FinOpsMetric] = []
        self._buffer_lock = Lock()

        # Cost tracking
        self._daily_costs: Dict[str, float] = defaultdict(float)
        self._weekly_costs: Dict[str, float] = defaultdict(float)
        self._monthly_costs: Dict[str, float] = defaultdict(float)
        self._cost_by_allocation: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))

        # Cost rates from config
        self._cost_rates: Dict[str, Dict[str, Dict[str, float]]] = {}
        self._load_cost_rates()

        # Tracking period
        self._current_day = datetime.now(timezone.utc).date()
        self._current_week = self._current_day.isocalendar()[1]
        self._current_month = self._current_day.month

        # Cost history for forecasting
        self._cost_history: List[Tuple[datetime, float]] = []

    def _load_cost_rates(self) -> None:
        """Load cost rates from configuration."""
        for provider_name, provider_config in self.config.ai_providers.items():
            if provider_config.enabled:
                self._cost_rates[provider_name] = {}
                for model, costs in provider_config.cost_per_1k_tokens.items():
                    self._cost_rates[provider_name][model] = {
                        'input': costs.input,
                        'output': costs.output,
                    }

    def calculate_cost(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0
    ) -> CostMetrics:
        """
        Calculate cost for a request.

        Args:
            provider: AI provider name
            model: Model name
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            cached_tokens: Number of cached tokens (no cost)

        Returns:
            Cost metrics
        """
        cost = CostMetrics()

        # Get rates
        rates = self._cost_rates.get(provider, {}).get(model)
        if not rates:
            # Use default rates if not configured
            rates = {'input': 0.001, 'output': 0.002}

        # Calculate costs
        billable_input = max(0, input_tokens - cached_tokens)
        cost.input_cost = (billable_input / 1000) * rates['input']
        cost.output_cost = (output_tokens / 1000) * rates['output']
        cost.total_cost = cost.input_cost + cost.output_cost

        # Calculate cached savings
        if cached_tokens > 0:
            cost.cached_savings = (cached_tokens / 1000) * rates['input']

        return cost

    def record_usage(
        self,
        request_id: str,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        **kwargs
    ) -> FinOpsMetric:
        """
        Record usage and cost metrics.

        Args:
            request_id: Unique request identifier
            provider: AI provider name
            model: Model name
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            **kwargs: Additional fields

        Returns:
            The recorded metric
        """
        # Rotate periods if needed
        self._check_period_rotation()

        # Calculate tokens
        tokens = TokenMetrics(
            input=input_tokens,
            output=output_tokens,
            total=input_tokens + output_tokens,
            cached=kwargs.get('cached_tokens', 0),
            reasoning=kwargs.get('reasoning_tokens', 0),
        )

        # Calculate costs
        cost = self.calculate_cost(
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=tokens.cached,
        )

        # Update tracking
        key = f"{provider}:{model}"
        self._daily_costs[key] += cost.total_cost
        self._weekly_costs[key] += cost.total_cost
        self._monthly_costs[key] += cost.total_cost

        # Calculate budget status
        budget = self._calculate_budget_status(cost.total_cost)

        # Build allocation
        allocation = CostAllocation(
            team=kwargs.get('team'),
            project=kwargs.get('project'),
            department=kwargs.get('department'),
            cost_center=kwargs.get('cost_center'),
            environment=kwargs.get('environment', 'production'),
            user_id=kwargs.get('user_id'),
            application=kwargs.get('application'),
            use_case=kwargs.get('use_case'),
        )

        # Update cost by allocation
        for field in ['team', 'project', 'department', 'application']:
            value = getattr(allocation, field)
            if value:
                self._cost_by_allocation[field][value] += cost.total_cost

        # Build optimization metrics
        optimization = OptimizationMetrics(
            cache_hit=kwargs.get('cache_hit', False),
            cache_savings=cost.cached_savings,
            prompt_compressed=kwargs.get('prompt_compressed', False),
            compression_ratio=kwargs.get('compression_ratio', 1.0),
            model_fallback=kwargs.get('model_fallback', False),
            original_model=kwargs.get('original_model'),
            fallback_model=kwargs.get('fallback_model'),
            fallback_savings=kwargs.get('fallback_savings', 0.0),
            batch_processed=kwargs.get('batch_processed', False),
            batch_size=kwargs.get('batch_size', 1),
        )

        # Build ROI metrics
        roi = ROIMetrics(
            business_value=kwargs.get('business_value', 0.0),
            value_category=kwargs.get('value_category'),
            conversion=kwargs.get('conversion', False),
            revenue_impact=kwargs.get('revenue_impact', 0.0),
            cost_avoidance=kwargs.get('cost_avoidance', 0.0),
            time_saved_minutes=kwargs.get('time_saved_minutes', 0.0),
        )
        if cost.total_cost > 0:
            roi.roi_ratio = roi.business_value / cost.total_cost

        # Build pricing info
        rates = self._cost_rates.get(provider, {}).get(model, {'input': 0, 'output': 0})
        pricing = PricingInfo(
            input_rate_per_1k=rates.get('input', 0),
            output_rate_per_1k=rates.get('output', 0),
            pricing_tier=kwargs.get('pricing_tier', 'standard'),
            discount_applied=kwargs.get('discount_applied', 0.0),
            commitment_discount=kwargs.get('commitment_discount', False),
        )

        # Build usage pattern
        now = datetime.now(timezone.utc)
        usage_pattern = UsagePattern(
            hour_of_day=now.hour,
            day_of_week=now.weekday(),
            is_peak_hour=9 <= now.hour <= 17,
            request_frequency=self._classify_frequency(),
        )

        # Build forecast
        forecast = self._calculate_forecast(cost.total_cost)

        # Create metric
        metric = FinOpsMetric(
            request_id=request_id,
            provider=provider,
            model=model,
            environment=allocation.environment or 'production',
            tokens=tokens,
            cost=cost,
            budget=budget,
            allocation=allocation,
            optimization=optimization,
            roi=roi,
            pricing=pricing,
            usage_pattern=usage_pattern,
            forecast=forecast,
        )

        # Add to buffer
        with self._buffer_lock:
            self._metrics_buffer.append(metric)

        # Update cost history
        self._cost_history.append((now, cost.total_cost))

        return metric

    def _check_period_rotation(self) -> None:
        """Check and rotate tracking periods if needed."""
        today = datetime.now(timezone.utc).date()
        current_week = today.isocalendar()[1]
        current_month = today.month

        if today != self._current_day:
            self._daily_costs.clear()
            self._current_day = today

        if current_week != self._current_week:
            self._weekly_costs.clear()
            self._current_week = current_week

        if current_month != self._current_month:
            self._monthly_costs.clear()
            self._current_month = current_month

    def _calculate_budget_status(self, new_cost: float) -> BudgetStatus:
        """Calculate current budget status."""
        budget_config = self.fin_config.budget

        daily_spent = sum(self._daily_costs.values()) + new_cost
        weekly_spent = sum(self._weekly_costs.values()) + new_cost
        monthly_spent = sum(self._monthly_costs.values()) + new_cost

        status = BudgetStatus(
            daily_budget=budget_config.daily_limit,
            daily_spent=daily_spent,
            daily_remaining=max(0, budget_config.daily_limit - daily_spent),
            weekly_budget=budget_config.weekly_limit,
            weekly_spent=weekly_spent,
            monthly_budget=budget_config.monthly_limit,
            monthly_spent=monthly_spent,
        )

        # Determine alert level
        daily_percentage = (daily_spent / budget_config.daily_limit) * 100 if budget_config.daily_limit > 0 else 0

        if daily_percentage >= 100:
            status.budget_exceeded = True
            status.budget_alert_level = BudgetAlertLevel.EXCEEDED
        elif daily_percentage >= 90:
            status.budget_alert_level = BudgetAlertLevel.WARNING_90
        elif daily_percentage >= 75:
            status.budget_alert_level = BudgetAlertLevel.WARNING_75
        elif daily_percentage >= 50:
            status.budget_alert_level = BudgetAlertLevel.WARNING_50
        else:
            status.budget_alert_level = BudgetAlertLevel.NORMAL

        return status

    def _classify_frequency(self) -> RequestFrequency:
        """Classify current request frequency."""
        # Count recent requests
        now = datetime.now(timezone.utc)
        recent = [t for t, _ in self._cost_history if (now - t).seconds < 60]

        count = len(recent)
        if count > 100:
            return RequestFrequency.VERY_HIGH
        elif count > 50:
            return RequestFrequency.HIGH
        elif count > 10:
            return RequestFrequency.MEDIUM
        return RequestFrequency.LOW

    def _calculate_forecast(self, new_cost: float) -> CostForecast:
        """Calculate cost forecast based on recent history."""
        forecast = CostForecast()

        # Need some history for forecasting
        if len(self._cost_history) < 10:
            return forecast

        now = datetime.now(timezone.utc)

        # Get costs from the last hour
        hour_ago = now - timedelta(hours=1)
        hourly_costs = [c for t, c in self._cost_history if t > hour_ago]

        if hourly_costs:
            hourly_average = sum(hourly_costs) / len(hourly_costs)
            requests_per_hour = len(hourly_costs)

            # Simple linear projection
            forecast.predicted_daily_cost = hourly_average * requests_per_hour * 24
            forecast.predicted_monthly_cost = forecast.predicted_daily_cost * 30

        # Determine trend
        if len(hourly_costs) >= 2:
            first_half = sum(hourly_costs[:len(hourly_costs)//2])
            second_half = sum(hourly_costs[len(hourly_costs)//2:])

            if second_half > first_half * 1.2:
                forecast.trend = CostTrend.INCREASING
            elif second_half < first_half * 0.8:
                forecast.trend = CostTrend.DECREASING
            else:
                forecast.trend = CostTrend.STABLE

        # Detect anomaly (simple z-score)
        if len(hourly_costs) >= 5:
            mean = sum(hourly_costs) / len(hourly_costs)
            variance = sum((c - mean) ** 2 for c in hourly_costs) / len(hourly_costs)
            std_dev = variance ** 0.5 if variance > 0 else 1

            z_score = abs(new_cost - mean) / std_dev if std_dev > 0 else 0
            forecast.anomaly_score = min(1.0, z_score / 3)
            forecast.anomaly_detected = z_score > 2

        return forecast

    def get_cost_summary(
        self,
        group_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get cost summary.

        Args:
            group_by: Optional field to group by (team, project, model)

        Returns:
            Cost summary
        """
        summary = {
            "daily": {
                "total": sum(self._daily_costs.values()),
                "by_model": dict(self._daily_costs),
                "budget": self.fin_config.budget.daily_limit,
                "percentage_used": 0,
            },
            "weekly": {
                "total": sum(self._weekly_costs.values()),
                "by_model": dict(self._weekly_costs),
                "budget": self.fin_config.budget.weekly_limit,
            },
            "monthly": {
                "total": sum(self._monthly_costs.values()),
                "by_model": dict(self._monthly_costs),
                "budget": self.fin_config.budget.monthly_limit,
            },
        }

        # Calculate percentages
        if summary["daily"]["budget"] > 0:
            summary["daily"]["percentage_used"] = (
                summary["daily"]["total"] / summary["daily"]["budget"]
            ) * 100

        # Add grouped costs
        if group_by and group_by in self._cost_by_allocation:
            summary[f"by_{group_by}"] = dict(self._cost_by_allocation[group_by])

        return summary

    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """
        Get cost optimization recommendations.

        Returns:
            List of recommendations
        """
        recommendations = []

        with self._buffer_lock:
            if not self._metrics_buffer:
                return recommendations

            # Analyze recent metrics
            total_requests = len(self._metrics_buffer)
            cache_hits = sum(1 for m in self._metrics_buffer if m.optimization.cache_hit)
            compressed = sum(1 for m in self._metrics_buffer if m.optimization.prompt_compressed)

            # Cache recommendation
            cache_rate = cache_hits / total_requests if total_requests > 0 else 0
            if cache_rate < 0.1:
                recommendations.append({
                    "type": "caching",
                    "priority": "high",
                    "description": "Enable response caching for repeated queries",
                    "potential_savings": "Up to 30% cost reduction",
                    "current_cache_rate": f"{cache_rate:.1%}",
                })

            # Compression recommendation
            compression_rate = compressed / total_requests if total_requests > 0 else 0
            if compression_rate < 0.5:
                recommendations.append({
                    "type": "compression",
                    "priority": "medium",
                    "description": "Enable prompt compression for long prompts",
                    "potential_savings": "Up to 20% token reduction",
                    "current_compression_rate": f"{compression_rate:.1%}",
                })

            # Model optimization
            model_costs = defaultdict(float)
            for m in self._metrics_buffer:
                model_costs[m.model] += m.cost.total_cost

            expensive_models = [
                (model, cost) for model, cost in model_costs.items()
                if cost > sum(model_costs.values()) * 0.5
            ]

            for model, cost in expensive_models:
                recommendations.append({
                    "type": "model_selection",
                    "priority": "medium",
                    "description": f"Consider using smaller models for simple tasks instead of {model}",
                    "potential_savings": "Variable based on use case",
                    "current_cost": f"${cost:.2f}",
                })

        return recommendations

    def check_budget_alerts(self) -> List[Dict[str, Any]]:
        """
        Check for budget alerts.

        Returns:
            List of active alerts
        """
        alerts = []
        budget_config = self.fin_config.budget

        daily_spent = sum(self._daily_costs.values())
        daily_percentage = (daily_spent / budget_config.daily_limit) * 100 if budget_config.daily_limit > 0 else 0

        for threshold in budget_config.alert_at_percentage:
            if daily_percentage >= threshold:
                severity = "critical" if threshold >= 100 else "warning"
                alerts.append({
                    "type": "budget_threshold",
                    "threshold": threshold,
                    "current_percentage": daily_percentage,
                    "severity": severity,
                    "message": f"Daily budget {threshold}% threshold reached",
                    "spent": daily_spent,
                    "budget": budget_config.daily_limit,
                })
                break  # Only report highest threshold reached

        return alerts

    def get_buffered_metrics(self, clear: bool = True) -> List[FinOpsMetric]:
        """Get buffered metrics."""
        with self._buffer_lock:
            metrics = self._metrics_buffer.copy()
            if clear:
                self._metrics_buffer.clear()
        return metrics

    def get_roi_summary(self) -> Dict[str, Any]:
        """Get ROI summary."""
        with self._buffer_lock:
            if not self._metrics_buffer:
                return {
                    "total_cost": 0,
                    "total_value": 0,
                    "roi_ratio": 0,
                    "conversions": 0,
                }

            total_cost = sum(m.cost.total_cost for m in self._metrics_buffer)
            total_value = sum(m.roi.business_value for m in self._metrics_buffer)
            conversions = sum(1 for m in self._metrics_buffer if m.roi.conversion)

            return {
                "total_cost": total_cost,
                "total_value": total_value,
                "roi_ratio": total_value / total_cost if total_cost > 0 else 0,
                "conversions": conversions,
                "conversion_rate": conversions / len(self._metrics_buffer),
                "avg_cost_per_conversion": total_cost / conversions if conversions > 0 else 0,
            }
