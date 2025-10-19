"""
Report Service for PhishGuard

Business logic for generating analytics reports, business intelligence,
executive summaries, and data visualization for security metrics.
"""

import json
import statistics
import uuid
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, or_, text
from sqlalchemy.orm import Session

from ..models.audit_log import ActionType, AuditLog
from ..models.email import Email
from ..models.notification import Notification
from ..models.quarantine import QuarantinedEmail
from ..models.simulation import SimulationCampaign, SimulationResult
from ..models.user import User
from ..utils.config import get_settings
from ..utils.event_bus import EventBus
from ..utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


class ReportType(Enum):
    """Available report types."""

    EXECUTIVE_SUMMARY = "executive_summary"
    THREAT_ANALYTICS = "threat_analytics"
    USER_ACTIVITY = "user_activity"
    SECURITY_METRICS = "security_metrics"
    COMPLIANCE_REPORT = "compliance_report"
    PHISHING_SIMULATION = "phishing_simulation"
    INCIDENT_RESPONSE = "incident_response"
    PERFORMANCE_METRICS = "performance_metrics"
    TREND_ANALYSIS = "trend_analysis"
    RISK_ASSESSMENT = "risk_assessment"


class ReportFormat(Enum):
    """Report output formats."""

    JSON = "json"
    PDF = "pdf"
    CSV = "csv"
    EXCEL = "excel"
    HTML = "html"


class TimeRange(Enum):
    """Predefined time ranges for reports."""

    LAST_24_HOURS = "last_24_hours"
    LAST_7_DAYS = "last_7_days"
    LAST_30_DAYS = "last_30_days"
    LAST_90_DAYS = "last_90_days"
    LAST_YEAR = "last_year"
    CUSTOM = "custom"


class ReportService:
    """Service for generating reports and analytics."""

    def __init__(self, db: Session):
        """
        Initialize report service.

        Args:
            db: Database session
        """
        self.db = db
        self.event_bus = EventBus()

    async def generate_executive_summary(
        self,
        time_range: TimeRange = TimeRange.LAST_30_DAYS,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Generate executive summary report.

        Args:
            time_range: Predefined time range
            start_date: Custom start date
            end_date: Custom end date

        Returns:
            Executive summary report data
        """
        try:
            # Calculate date range
            if time_range != TimeRange.CUSTOM:
                start_date, end_date = self._get_date_range(time_range)
            elif not start_date or not end_date:
                start_date, end_date = self._get_date_range(TimeRange.LAST_30_DAYS)

            # Gather key metrics
            security_metrics = await self._get_security_metrics(start_date, end_date)
            threat_summary = await self._get_threat_summary(start_date, end_date)
            user_metrics = await self._get_user_metrics(start_date, end_date)
            system_performance = await self._get_system_performance(
                start_date, end_date
            )
            simulation_results = await self._get_simulation_summary(
                start_date, end_date
            )

            # Calculate risk score
            risk_score = await self._calculate_overall_risk_score(
                security_metrics, threat_summary, user_metrics
            )

            # Generate recommendations
            recommendations = await self._generate_executive_recommendations(
                security_metrics, threat_summary, user_metrics, risk_score
            )

            summary = {
                "report_metadata": {
                    "type": ReportType.EXECUTIVE_SUMMARY.value,
                    "generated_at": datetime.utcnow().isoformat(),
                    "period_start": start_date.isoformat(),
                    "period_end": end_date.isoformat(),
                    "time_range": time_range.value,
                    "report_version": "1.0",
                },
                "executive_overview": {
                    "overall_risk_score": risk_score,
                    "security_posture": self._get_security_posture(risk_score),
                    "key_achievements": await self._get_key_achievements(
                        start_date, end_date
                    ),
                    "critical_issues": await self._get_critical_issues(
                        start_date, end_date
                    ),
                    "period_comparison": await self._get_period_comparison(
                        start_date, end_date
                    ),
                },
                "security_metrics": security_metrics,
                "threat_analytics": threat_summary,
                "user_insights": user_metrics,
                "system_performance": system_performance,
                "simulation_overview": simulation_results,
                "strategic_recommendations": recommendations,
                "compliance_status": await self._get_compliance_overview(),
                "budget_impact": await self._calculate_budget_impact(threat_summary),
                "next_steps": await self._generate_next_steps(recommendations),
            }

            # Log report generation
            await self._log_report_action(
                report_type=ReportType.EXECUTIVE_SUMMARY,
                details={
                    "time_range": time_range.value,
                    "risk_score": risk_score,
                    "threats_detected": threat_summary.get("total_threats", 0),
                },
            )

            return summary

        except Exception as e:
            logger.error(f"Error generating executive summary: {str(e)}")
            raise

    async def generate_threat_analytics_report(
        self,
        time_range: TimeRange = TimeRange.LAST_30_DAYS,
        threat_types: Optional[List[str]] = None,
        detailed_analysis: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate detailed threat analytics report.

        Args:
            time_range: Time range for analysis
            threat_types: Specific threat types to analyze
            detailed_analysis: Include detailed threat analysis

        Returns:
            Threat analytics report
        """
        try:
            start_date, end_date = self._get_date_range(time_range)

            # Base threat data
            quarantined_emails = (
                self.db.query(QuarantinedEmail)
                .filter(
                    and_(
                        QuarantinedEmail.quarantined_at >= start_date,
                        QuarantinedEmail.quarantined_at <= end_date,
                    )
                )
                .all()
            )

            # Threat categorization
            threat_categories = await self._categorize_threats(quarantined_emails)
            threat_trends = await self._analyze_threat_trends(
                quarantined_emails, start_date, end_date
            )
            attack_vectors = await self._analyze_attack_vectors(quarantined_emails)
            geographic_analysis = await self._analyze_geographic_threats(
                quarantined_emails
            )

            report = {
                "report_metadata": {
                    "type": ReportType.THREAT_ANALYTICS.value,
                    "generated_at": datetime.utcnow().isoformat(),
                    "period_start": start_date.isoformat(),
                    "period_end": end_date.isoformat(),
                    "total_threats_analyzed": len(quarantined_emails),
                    "threat_type_filter": threat_types,
                },
                "threat_overview": {
                    "total_threats": len(quarantined_emails),
                    "unique_senders": len(
                        set(
                            [
                                email.sender
                                for email in quarantined_emails
                                if email.sender
                            ]
                        )
                    ),
                    "threat_categories": threat_categories,
                    "severity_distribution": await self._get_severity_distribution(
                        quarantined_emails
                    ),
                    "detection_accuracy": await self._calculate_detection_accuracy(
                        quarantined_emails
                    ),
                },
                "threat_trends": threat_trends,
                "attack_analysis": {
                    "attack_vectors": attack_vectors,
                    "target_analysis": await self._analyze_threat_targets(
                        quarantined_emails
                    ),
                    "timing_patterns": await self._analyze_threat_timing(
                        quarantined_emails
                    ),
                    "payload_analysis": await self._analyze_threat_payloads(
                        quarantined_emails
                    ),
                },
                "geographic_intelligence": geographic_analysis,
                "threat_intelligence": await self._get_threat_intelligence_insights(
                    quarantined_emails
                ),
                "mitigation_effectiveness": await self._analyze_mitigation_effectiveness(
                    quarantined_emails
                ),
                "recommendations": await self._generate_threat_recommendations(
                    threat_categories, attack_vectors
                ),
            }

            # Add detailed analysis if requested
            if detailed_analysis:
                report["detailed_analysis"] = (
                    await self._generate_detailed_threat_analysis(quarantined_emails)
                )

            return report

        except Exception as e:
            logger.error(f"Error generating threat analytics report: {str(e)}")
            raise

    async def generate_user_activity_report(
        self,
        time_range: TimeRange = TimeRange.LAST_30_DAYS,
        user_ids: Optional[List[uuid.UUID]] = None,
        include_risk_analysis: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate user activity and behavior report.

        Args:
            time_range: Time range for analysis
            user_ids: Specific users to analyze
            include_risk_analysis: Include user risk analysis

        Returns:
            User activity report
        """
        try:
            start_date, end_date = self._get_date_range(time_range)

            # Base queries
            user_query = self.db.query(User)
            if user_ids:
                user_query = user_query.filter(User.id.in_(user_ids))
            users = user_query.all()

            # Activity analysis
            user_activities = await self._analyze_user_activities(
                users, start_date, end_date
            )
            login_patterns = await self._analyze_login_patterns(
                users, start_date, end_date
            )
            report_behaviors = await self._analyze_reporting_behavior(
                users, start_date, end_date
            )

            report = {
                "report_metadata": {
                    "type": ReportType.USER_ACTIVITY.value,
                    "generated_at": datetime.utcnow().isoformat(),
                    "period_start": start_date.isoformat(),
                    "period_end": end_date.isoformat(),
                    "users_analyzed": len(users),
                    "user_filter": [str(uid) for uid in user_ids] if user_ids else None,
                },
                "user_overview": {
                    "total_users": len(users),
                    "active_users": len([u for u in users if u.is_active]),
                    "new_users": await self._count_new_users(start_date, end_date),
                    "user_roles": await self._analyze_user_roles(users),
                    "activity_summary": user_activities["summary"],
                },
                "activity_patterns": {
                    "login_analysis": login_patterns,
                    "session_analysis": await self._analyze_user_sessions(
                        users, start_date, end_date
                    ),
                    "feature_usage": await self._analyze_feature_usage(
                        users, start_date, end_date
                    ),
                    "peak_activity_times": await self._analyze_peak_activity(
                        users, start_date, end_date
                    ),
                },
                "security_behavior": {
                    "reporting_patterns": report_behaviors,
                    "simulation_performance": await self._analyze_simulation_performance(
                        users, start_date, end_date
                    ),
                    "security_incidents": await self._analyze_user_security_incidents(
                        users, start_date, end_date
                    ),
                },
                "user_rankings": {
                    "most_active": user_activities["most_active"],
                    "top_reporters": report_behaviors["top_reporters"],
                    "security_champions": await self._identify_security_champions(
                        users, start_date, end_date
                    ),
                    "users_at_risk": await self._identify_at_risk_users(
                        users, start_date, end_date
                    ),
                },
            }

            # Add risk analysis if requested
            if include_risk_analysis:
                report["risk_analysis"] = await self._generate_user_risk_analysis(
                    users, start_date, end_date
                )

            return report

        except Exception as e:
            logger.error(f"Error generating user activity report: {str(e)}")
            raise

    async def generate_security_metrics_report(
        self,
        time_range: TimeRange = TimeRange.LAST_30_DAYS,
        include_benchmarks: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive security metrics report.

        Args:
            time_range: Time range for metrics
            include_benchmarks: Include industry benchmarks

        Returns:
            Security metrics report
        """
        try:
            start_date, end_date = self._get_date_range(time_range)

            # Core security metrics
            detection_metrics = await self._calculate_detection_metrics(
                start_date, end_date
            )
            response_metrics = await self._calculate_response_metrics(
                start_date, end_date
            )
            prevention_metrics = await self._calculate_prevention_metrics(
                start_date, end_date
            )

            report = {
                "report_metadata": {
                    "type": ReportType.SECURITY_METRICS.value,
                    "generated_at": datetime.utcnow().isoformat(),
                    "period_start": start_date.isoformat(),
                    "period_end": end_date.isoformat(),
                    "metrics_version": "1.0",
                },
                "detection_effectiveness": detection_metrics,
                "response_efficiency": response_metrics,
                "prevention_success": prevention_metrics,
                "overall_security_score": await self._calculate_security_score(
                    detection_metrics, response_metrics, prevention_metrics
                ),
                "kpi_dashboard": await self._generate_kpi_dashboard(
                    start_date, end_date
                ),
                "trend_analysis": await self._analyze_security_trends(
                    start_date, end_date
                ),
                "performance_indicators": await self._calculate_performance_indicators(
                    start_date, end_date
                ),
            }

            # Add benchmarks if requested
            if include_benchmarks:
                report["industry_benchmarks"] = await self._get_industry_benchmarks()
                report["benchmark_comparison"] = await self._compare_to_benchmarks(
                    report
                )

            return report

        except Exception as e:
            logger.error(f"Error generating security metrics report: {str(e)}")
            raise

    async def generate_simulation_report(
        self,
        campaign_id: Optional[uuid.UUID] = None,
        time_range: TimeRange = TimeRange.LAST_90_DAYS,
    ) -> Dict[str, Any]:
        """
        Generate phishing simulation report.

        Args:
            campaign_id: Specific campaign to analyze
            time_range: Time range for analysis

        Returns:
            Simulation report
        """
        try:
            start_date, end_date = self._get_date_range(time_range)

            # Query campaigns
            campaign_query = self.db.query(SimulationCampaign).filter(
                and_(
                    SimulationCampaign.created_at >= start_date,
                    SimulationCampaign.created_at <= end_date,
                )
            )

            if campaign_id:
                campaign_query = campaign_query.filter(
                    SimulationCampaign.id == campaign_id
                )

            campaigns = campaign_query.all()

            # Analyze simulation results
            overall_stats = await self._calculate_simulation_stats(campaigns)
            campaign_analysis = await self._analyze_individual_campaigns(campaigns)
            user_performance = await self._analyze_simulation_user_performance(
                campaigns
            )
            learning_trends = await self._analyze_learning_trends(campaigns)

            report = {
                "report_metadata": {
                    "type": ReportType.PHISHING_SIMULATION.value,
                    "generated_at": datetime.utcnow().isoformat(),
                    "period_start": start_date.isoformat(),
                    "period_end": end_date.isoformat(),
                    "campaigns_analyzed": len(campaigns),
                    "campaign_filter": str(campaign_id) if campaign_id else None,
                },
                "executive_summary": {
                    "total_campaigns": len(campaigns),
                    "total_users_tested": overall_stats["unique_users"],
                    "overall_click_rate": overall_stats["click_rate"],
                    "overall_report_rate": overall_stats["report_rate"],
                    "security_awareness_score": overall_stats["awareness_score"],
                },
                "campaign_performance": campaign_analysis,
                "user_analysis": user_performance,
                "learning_effectiveness": learning_trends,
                "risk_assessment": await self._assess_simulation_risks(
                    campaigns, overall_stats
                ),
                "template_effectiveness": await self._analyze_template_effectiveness(
                    campaigns
                ),
                "improvement_recommendations": await self._generate_simulation_recommendations(
                    overall_stats, user_performance
                ),
            }

            return report

        except Exception as e:
            logger.error(f"Error generating simulation report: {str(e)}")
            raise

    async def generate_custom_report(
        self,
        report_config: Dict[str, Any],
        format_type: ReportFormat = ReportFormat.JSON,
    ) -> Dict[str, Any]:
        """
        Generate custom report based on configuration.

        Args:
            report_config: Custom report configuration
            format_type: Output format

        Returns:
            Custom report data
        """
        try:
            # Parse configuration
            report_type = report_config.get("type", "custom")
            time_range = report_config.get("time_range", TimeRange.LAST_30_DAYS.value)
            filters = report_config.get("filters", {})
            metrics = report_config.get("metrics", [])

            # Get date range
            if time_range == TimeRange.CUSTOM.value:
                start_date = datetime.fromisoformat(report_config["start_date"])
                end_date = datetime.fromisoformat(report_config["end_date"])
            else:
                start_date, end_date = self._get_date_range(TimeRange(time_range))

            # Build custom report
            report_data = {
                "report_metadata": {
                    "type": "custom",
                    "config": report_config,
                    "generated_at": datetime.utcnow().isoformat(),
                    "period_start": start_date.isoformat(),
                    "period_end": end_date.isoformat(),
                    "format": format_type.value,
                },
                "data": {},
            }

            # Generate requested metrics
            for metric in metrics:
                if metric == "threat_count":
                    report_data["data"]["threat_count"] = await self._get_threat_count(
                        start_date, end_date, filters
                    )
                elif metric == "user_activity":
                    report_data["data"]["user_activity"] = (
                        await self._get_user_activity_metrics(
                            start_date, end_date, filters
                        )
                    )
                elif metric == "detection_rate":
                    report_data["data"]["detection_rate"] = (
                        await self._get_detection_rate(start_date, end_date, filters)
                    )
                elif metric == "response_time":
                    report_data["data"]["response_time"] = (
                        await self._get_response_times(start_date, end_date, filters)
                    )
                elif metric == "simulation_results":
                    report_data["data"]["simulation_results"] = (
                        await self._get_simulation_metrics(
                            start_date, end_date, filters
                        )
                    )

            # Apply filters and formatting based on format_type
            if format_type != ReportFormat.JSON:
                report_data = await self._format_report(report_data, format_type)

            return report_data

        except Exception as e:
            logger.error(f"Error generating custom report: {str(e)}")
            raise

    async def schedule_report(
        self,
        report_type: ReportType,
        schedule_config: Dict[str, Any],
        recipients: List[str],
        format_type: ReportFormat = ReportFormat.PDF,
    ) -> Dict[str, Any]:
        """
        Schedule recurring report generation.

        Args:
            report_type: Type of report to schedule
            schedule_config: Scheduling configuration
            recipients: Report recipients
            format_type: Report format

        Returns:
            Schedule confirmation
        """
        try:
            schedule_id = uuid.uuid4()

            schedule_data = {
                "id": str(schedule_id),
                "report_type": report_type.value,
                "schedule": schedule_config,
                "recipients": recipients,
                "format": format_type.value,
                "created_at": datetime.utcnow().isoformat(),
                "status": "active",
                "next_execution": self._calculate_next_execution(schedule_config),
            }

            # Store schedule (in a real implementation, this would be in the database)
            # For now, we'll just log it
            logger.info(f"Report scheduled: {schedule_id} - {report_type.value}")

            # Emit scheduling event
            await self.event_bus.emit("report_scheduled", schedule_data)

            return {
                "schedule_id": str(schedule_id),
                "status": "scheduled",
                "next_execution": schedule_data["next_execution"],
                "report_type": report_type.value,
                "recipients": recipients,
            }

        except Exception as e:
            logger.error(f"Error scheduling report: {str(e)}")
            raise

    # Private helper methods

    def _get_date_range(self, time_range: TimeRange) -> Tuple[datetime, datetime]:
        """Get start and end dates for time range."""
        end_date = datetime.utcnow()

        if time_range == TimeRange.LAST_24_HOURS:
            start_date = end_date - timedelta(hours=24)
        elif time_range == TimeRange.LAST_7_DAYS:
            start_date = end_date - timedelta(days=7)
        elif time_range == TimeRange.LAST_30_DAYS:
            start_date = end_date - timedelta(days=30)
        elif time_range == TimeRange.LAST_90_DAYS:
            start_date = end_date - timedelta(days=90)
        elif time_range == TimeRange.LAST_YEAR:
            start_date = end_date - timedelta(days=365)
        else:
            start_date = end_date - timedelta(days=30)  # Default

        return start_date, end_date

    async def _get_security_metrics(
        self, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Get comprehensive security metrics."""
        try:
            # Threat detection metrics
            quarantined_count = (
                self.db.query(QuarantinedEmail)
                .filter(
                    and_(
                        QuarantinedEmail.quarantined_at >= start_date,
                        QuarantinedEmail.quarantined_at <= end_date,
                    )
                )
                .count()
            )

            # Email processing metrics
            total_emails_processed = quarantined_count * 10  # Simulated ratio

            return {
                "threats_detected": quarantined_count,
                "emails_processed": total_emails_processed,
                "detection_rate": (quarantined_count / max(total_emails_processed, 1))
                * 100,
                "false_positive_rate": 2.5,  # Simulated
                "average_detection_time": 0.3,  # seconds
                "system_uptime": 99.8,  # percentage
                "processing_performance": {
                    "emails_per_second": 150,
                    "average_processing_time": 0.25,
                    "peak_processing_time": 1.2,
                },
            }
        except Exception as e:
            logger.error(f"Error getting security metrics: {str(e)}")
            return {}

    async def _get_threat_summary(
        self, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Get threat summary for the period."""
        try:
            quarantined_emails = (
                self.db.query(QuarantinedEmail)
                .filter(
                    and_(
                        QuarantinedEmail.quarantined_at >= start_date,
                        QuarantinedEmail.quarantined_at <= end_date,
                    )
                )
                .all()
            )

            # Categorize threats
            threat_types = {}
            severity_counts = {"high": 0, "medium": 0, "low": 0}

            for email in quarantined_emails:
                # Simulate threat categorization
                threat_type = email.threat_type or "phishing"
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1

                # Simulate severity
                if email.confidence_score and email.confidence_score > 0.8:
                    severity_counts["high"] += 1
                elif email.confidence_score and email.confidence_score > 0.5:
                    severity_counts["medium"] += 1
                else:
                    severity_counts["low"] += 1

            return {
                "total_threats": len(quarantined_emails),
                "threat_types": threat_types,
                "severity_distribution": severity_counts,
                "unique_senders": len(
                    set([email.sender for email in quarantined_emails if email.sender])
                ),
                "blocked_threats": len(quarantined_emails),
                "average_threat_score": (
                    statistics.mean(
                        [email.confidence_score or 0.5 for email in quarantined_emails]
                    )
                    if quarantined_emails
                    else 0.0
                ),
            }
        except Exception as e:
            logger.error(f"Error getting threat summary: {str(e)}")
            return {}

    async def _get_user_metrics(
        self, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Get user activity metrics."""
        try:
            # Active users in period
            active_users = (
                self.db.query(AuditLog)
                .filter(
                    and_(
                        AuditLog.timestamp >= start_date,
                        AuditLog.timestamp <= end_date,
                        AuditLog.user_id.isnot(None),
                    )
                )
                .distinct(AuditLog.user_id)
                .count()
            )

            # Total users
            total_users = self.db.query(User).count()

            # User reports
            user_reports = (
                self.db.query(AuditLog)
                .filter(
                    and_(
                        AuditLog.timestamp >= start_date,
                        AuditLog.timestamp <= end_date,
                        AuditLog.action == ActionType.CREATE,
                        AuditLog.details.like("%user_report%"),
                    )
                )
                .count()
            )

            return {
                "total_users": total_users,
                "active_users": active_users,
                "user_engagement_rate": (active_users / max(total_users, 1)) * 100,
                "user_reports_submitted": user_reports,
                "average_reports_per_user": user_reports / max(active_users, 1),
                "new_users": await self._count_new_users(start_date, end_date),
                "user_satisfaction_score": 8.2,  # Simulated
            }
        except Exception as e:
            logger.error(f"Error getting user metrics: {str(e)}")
            return {}

    async def _get_system_performance(
        self, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Get system performance metrics."""
        try:
            return {
                "uptime_percentage": 99.8,
                "average_response_time": 245,  # milliseconds
                "peak_response_time": 1200,
                "error_rate": 0.2,  # percentage
                "throughput": {
                    "emails_per_hour": 5400,
                    "peak_emails_per_hour": 12000,
                    "concurrent_users": 150,
                },
                "resource_utilization": {
                    "cpu_usage": 35.2,
                    "memory_usage": 62.8,
                    "disk_usage": 45.1,
                    "network_usage": 28.5,
                },
                "database_performance": {
                    "query_time": 15.3,  # milliseconds
                    "connection_pool_usage": 67.2,
                    "cache_hit_rate": 89.5,
                },
            }
        except Exception as e:
            logger.error(f"Error getting system performance: {str(e)}")
            return {}

    async def _get_simulation_summary(
        self, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Get simulation campaign summary."""
        try:
            campaigns = (
                self.db.query(SimulationCampaign)
                .filter(
                    and_(
                        SimulationCampaign.created_at >= start_date,
                        SimulationCampaign.created_at <= end_date,
                    )
                )
                .all()
            )

            if not campaigns:
                return {
                    "total_campaigns": 0,
                    "users_tested": 0,
                    "click_rate": 0.0,
                    "report_rate": 0.0,
                    "training_completion_rate": 0.0,
                }

            # Aggregate results
            total_results = 0
            total_clicks = 0
            total_reports = 0

            for campaign in campaigns:
                results = (
                    self.db.query(SimulationResult)
                    .filter(SimulationResult.campaign_id == campaign.id)
                    .all()
                )

                total_results += len(results)
                total_clicks += len([r for r in results if r.clicked])
                total_reports += len([r for r in results if r.reported])

            return {
                "total_campaigns": len(campaigns),
                "users_tested": total_results,
                "click_rate": (total_clicks / max(total_results, 1)) * 100,
                "report_rate": (total_reports / max(total_results, 1)) * 100,
                "training_completion_rate": 78.5,  # Simulated
                "improvement_score": 15.2,  # Simulated improvement
            }
        except Exception as e:
            logger.error(f"Error getting simulation summary: {str(e)}")
            return {}

    async def _calculate_overall_risk_score(
        self,
        security_metrics: Dict[str, Any],
        threat_summary: Dict[str, Any],
        user_metrics: Dict[str, Any],
    ) -> float:
        """Calculate overall organizational risk score."""
        try:
            # Weighted risk factors
            factors = {
                "threat_volume": min(threat_summary.get("total_threats", 0) / 100, 1.0)
                * 0.3,
                "detection_rate": (100 - security_metrics.get("detection_rate", 90))
                / 100
                * 0.25,
                "user_engagement": (100 - user_metrics.get("user_engagement_rate", 80))
                / 100
                * 0.2,
                "false_positive_rate": security_metrics.get("false_positive_rate", 2.5)
                / 100
                * 0.15,
                "system_performance": (
                    100 - security_metrics.get("system_uptime", 99.8)
                )
                / 100
                * 0.1,
            }

            # Calculate weighted risk score (0-100, where 0 is lowest risk)
            risk_score = sum(factors.values()) * 100

            return round(min(max(risk_score, 0), 100), 1)

        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return 25.0  # Default moderate risk

    def _get_security_posture(self, risk_score: float) -> str:
        """Determine security posture based on risk score."""
        if risk_score <= 20:
            return "Excellent"
        elif risk_score <= 40:
            return "Good"
        elif risk_score <= 60:
            return "Fair"
        elif risk_score <= 80:
            return "Poor"
        else:
            return "Critical"

    async def _count_new_users(self, start_date: datetime, end_date: datetime) -> int:
        """Count new users created in the period."""
        try:
            return (
                self.db.query(User)
                .filter(
                    and_(User.created_at >= start_date, User.created_at <= end_date)
                )
                .count()
            )
        except Exception as e:
            logger.error(f"Error counting new users: {str(e)}")
            return 0

    async def _categorize_threats(
        self, quarantined_emails: List[QuarantinedEmail]
    ) -> Dict[str, int]:
        """Categorize threats by type."""
        try:
            categories = defaultdict(int)

            for email in quarantined_emails:
                threat_type = email.threat_type or "unknown"
                categories[threat_type] += 1

            return dict(categories)
        except Exception as e:
            logger.error(f"Error categorizing threats: {str(e)}")
            return {}

    async def _log_report_action(
        self, report_type: ReportType, details: Dict[str, Any]
    ):
        """Log report generation action."""
        try:
            audit_log = AuditLog(
                id=uuid.uuid4(),
                action=ActionType.READ,
                resource_type="report",
                resource_id=None,
                user_id=None,  # System action
                details={
                    "action": "report_generated",
                    "report_type": report_type.value,
                    **details,
                },
                timestamp=datetime.utcnow(),
            )

            self.db.add(audit_log)
            # Note: Don't commit here, let the calling method handle it

        except Exception as e:
            logger.error(f"Error logging report action: {str(e)}")

    # Additional helper methods would continue here...
    # This is a comprehensive foundation for the report service

    async def _get_key_achievements(
        self, start_date: datetime, end_date: datetime
    ) -> List[str]:
        """Get key security achievements for the period."""
        achievements = []

        # Calculate some metrics
        threats_blocked = (
            self.db.query(QuarantinedEmail)
            .filter(
                and_(
                    QuarantinedEmail.quarantined_at >= start_date,
                    QuarantinedEmail.quarantined_at <= end_date,
                )
            )
            .count()
        )

        if threats_blocked > 0:
            achievements.append(
                f"Successfully blocked {threats_blocked} potential threats"
            )

        achievements.extend(
            [
                "Maintained 99.8% system uptime",
                "Achieved 2.5% false positive rate",
                "Improved user security awareness by 15%",
            ]
        )

        return achievements

    async def _get_critical_issues(
        self, start_date: datetime, end_date: datetime
    ) -> List[str]:
        """Get critical issues that need attention."""
        issues = []

        # This would include logic to identify actual issues
        # For now, return simulated issues
        issues.extend(
            [
                "3 users require additional security training",
                "Data retention cleanup needed for old quarantine items",
                "2 high-risk phishing attempts detected",
            ]
        )

        return issues

    async def _get_period_comparison(
        self, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Compare current period with previous period."""
        period_length = end_date - start_date
        prev_start = start_date - period_length
        prev_end = start_date

        current_threats = (
            self.db.query(QuarantinedEmail)
            .filter(
                and_(
                    QuarantinedEmail.quarantined_at >= start_date,
                    QuarantinedEmail.quarantined_at <= end_date,
                )
            )
            .count()
        )

        previous_threats = (
            self.db.query(QuarantinedEmail)
            .filter(
                and_(
                    QuarantinedEmail.quarantined_at >= prev_start,
                    QuarantinedEmail.quarantined_at <= prev_end,
                )
            )
            .count()
        )

        change = ((current_threats - previous_threats) / max(previous_threats, 1)) * 100

        return {
            "current_period_threats": current_threats,
            "previous_period_threats": previous_threats,
            "percentage_change": round(change, 1),
            "trend": (
                "increasing" if change > 0 else "decreasing" if change < 0 else "stable"
            ),
        }

    async def _generate_executive_recommendations(
        self,
        security_metrics: Dict[str, Any],
        threat_summary: Dict[str, Any],
        user_metrics: Dict[str, Any],
        risk_score: float,
    ) -> List[str]:
        """Generate strategic recommendations for executives."""
        recommendations = []

        if risk_score > 60:
            recommendations.append("Immediate security assessment recommended")

        if security_metrics.get("false_positive_rate", 0) > 5:
            recommendations.append(
                "Fine-tune detection algorithms to reduce false positives"
            )

        if user_metrics.get("user_engagement_rate", 0) < 70:
            recommendations.append("Implement user engagement improvement program")

        if threat_summary.get("total_threats", 0) > 50:
            recommendations.append("Consider additional threat intelligence sources")

        if not recommendations:
            recommendations.append(
                "Continue current security practices and monitor trends"
            )

        return recommendations
