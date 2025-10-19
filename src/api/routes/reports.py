"""
Reports Routes for PhishGuard API

Comprehensive reporting endpoints including threat analytics,
compliance reports, executive summaries, and custom reports.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Response, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_, func
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, validator
import uuid
import csv
import io
import json
import pandas as pd
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4

from ..database import get_db
from ..models.quarantine import QuarantinedEmail, QuarantineReason, ThreatLevel
from ..models.simulation import SimulationCampaign, SimulationParticipant
from ..models.audit_log import AuditLog, ActionType
from ..models.user import User
from ..middleware.auth_middleware import get_current_user, get_current_admin_user
from ..services.report_service import ReportService
from ..services.compliance_service import ComplianceService
from ..utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

# Pydantic models for request/response
class ReportRequest(BaseModel):
    report_type: str
    start_date: datetime
    end_date: datetime
    filters: Optional[Dict[str, Any]] = None
    format: str = "json"  # json, csv, pdf, excel
    include_details: bool = False

class ThreatReportResponse(BaseModel):
    total_threats: int
    threats_by_level: Dict[str, int]
    threats_by_type: Dict[str, int]
    threat_trends: List[Dict[str, Any]]
    top_threat_sources: List[Dict[str, Any]]
    quarantine_statistics: Dict[str, Any]

class SecurityMetricsResponse(BaseModel):
    security_score: float
    threat_detection_rate: float
    false_positive_rate: float
    response_time_avg: float
    incidents_resolved: int
    open_incidents: int
    metrics_by_date: List[Dict[str, Any]]

class ComplianceReportResponse(BaseModel):
    compliance_score: float
    framework_scores: Dict[str, float]
    violations: List[Dict[str, Any]]
    audit_findings: List[Dict[str, Any]]
    data_retention_status: Dict[str, Any]
    compliance_trends: List[Dict[str, Any]]

class UserActivityReportResponse(BaseModel):
    total_users: int
    active_users: int
    simulation_participation: Dict[str, Any]
    training_completion: Dict[str, Any]
    risk_distribution: Dict[str, int]
    department_statistics: List[Dict[str, Any]]

class ExecutiveSummaryResponse(BaseModel):
    summary_date: str
    threat_overview: Dict[str, Any]
    security_posture: Dict[str, Any]
    compliance_status: Dict[str, Any]
    business_impact: Dict[str, Any]
    recommendations: List[str]
    key_metrics: Dict[str, Any]

class CustomReportRequest(BaseModel):
    name: str
    description: Optional[str] = None
    data_sources: List[str]
    metrics: List[str]
    filters: Dict[str, Any]
    grouping: Optional[List[str]] = None
    time_range: Dict[str, str]
    format: str = "json"


@router.get("/threat-analytics", response_model=ThreatReportResponse)
async def get_threat_analytics(
    start_date: datetime = Query(..., description="Start date for analytics"),
    end_date: datetime = Query(..., description="End date for analytics"),
    threat_level: Optional[ThreatLevel] = Query(None, description="Filter by threat level"),
    department: Optional[str] = Query(None, description="Filter by department"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive threat analytics report.
    
    Args:
        start_date: Start date for analysis
        end_date: End date for analysis
        threat_level: Optional threat level filter
        department: Optional department filter
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Threat analytics data
    """
    try:
        report_service = ReportService(db)
        
        # Get threat analytics
        analytics = await report_service.generate_threat_analytics(
            start_date=start_date,
            end_date=end_date,
            threat_level=threat_level,
            department=department
        )
        
        return ThreatReportResponse(**analytics)
        
    except Exception as e:
        logger.error(f"Error generating threat analytics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate threat analytics"
        )


@router.get("/security-metrics", response_model=SecurityMetricsResponse)
async def get_security_metrics(
    start_date: datetime = Query(..., description="Start date for metrics"),
    end_date: datetime = Query(..., description="End date for metrics"),
    granularity: str = Query("daily", description="Granularity: daily, weekly, monthly"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get security metrics and KPIs.
    
    Args:
        start_date: Start date for metrics
        end_date: End date for metrics
        granularity: Data granularity
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Security metrics data
    """
    try:
        report_service = ReportService(db)
        
        # Calculate security metrics
        metrics = await report_service.calculate_security_metrics(
            start_date=start_date,
            end_date=end_date,
            granularity=granularity
        )
        
        return SecurityMetricsResponse(**metrics)
        
    except Exception as e:
        logger.error(f"Error generating security metrics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate security metrics"
        )


@router.get("/compliance", response_model=ComplianceReportResponse)
async def get_compliance_report(
    framework: Optional[str] = Query(None, description="Compliance framework (GDPR, HIPAA, SOX, etc.)"),
    start_date: Optional[datetime] = Query(None, description="Start date for compliance period"),
    end_date: Optional[datetime] = Query(None, description="End date for compliance period"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get compliance status report.
    
    Args:
        framework: Specific compliance framework
        start_date: Start date for compliance period
        end_date: End date for compliance period
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Compliance report data
    """
    try:
        compliance_service = ComplianceService(db)
        
        # Generate compliance report
        report = await compliance_service.generate_compliance_report(
            framework=framework,
            start_date=start_date,
            end_date=end_date
        )
        
        return ComplianceReportResponse(**report)
        
    except Exception as e:
        logger.error(f"Error generating compliance report: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate compliance report"
        )


@router.get("/user-activity", response_model=UserActivityReportResponse)
async def get_user_activity_report(
    start_date: datetime = Query(..., description="Start date for activity analysis"),
    end_date: datetime = Query(..., description="End date for activity analysis"),
    department: Optional[str] = Query(None, description="Filter by department"),
    include_simulations: bool = Query(True, description="Include simulation data"),
    include_training: bool = Query(True, description="Include training data"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get user activity and behavior report.
    
    Args:
        start_date: Start date for activity analysis
        end_date: End date for activity analysis
        department: Optional department filter
        include_simulations: Include simulation participation data
        include_training: Include training completion data
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        User activity report data
    """
    try:
        report_service = ReportService(db)
        
        # Generate user activity report
        report = await report_service.generate_user_activity_report(
            start_date=start_date,
            end_date=end_date,
            department=department,
            include_simulations=include_simulations,
            include_training=include_training
        )
        
        return UserActivityReportResponse(**report)
        
    except Exception as e:
        logger.error(f"Error generating user activity report: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate user activity report"
        )


@router.get("/executive-summary", response_model=ExecutiveSummaryResponse)
async def get_executive_summary(
    period: str = Query("monthly", description="Summary period: weekly, monthly, quarterly"),
    date: Optional[datetime] = Query(None, description="Specific date for summary"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get executive summary report for leadership.
    
    Args:
        period: Summary period
        date: Specific date for summary (defaults to current)
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Executive summary data
    """
    try:
        report_service = ReportService(db)
        
        # Determine date range based on period
        if date is None:
            date = datetime.utcnow()
        
        if period == "weekly":
            start_date = date - timedelta(weeks=1)
        elif period == "monthly":
            start_date = date - timedelta(days=30)
        elif period == "quarterly":
            start_date = date - timedelta(days=90)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid period. Must be weekly, monthly, or quarterly"
            )
        
        # Generate executive summary
        summary = await report_service.generate_executive_summary(
            start_date=start_date,
            end_date=date,
            period=period
        )
        
        return ExecutiveSummaryResponse(**summary)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating executive summary: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate executive summary"
        )


@router.post("/custom")
async def create_custom_report(
    request: CustomReportRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Create a custom report based on user specifications.
    
    Args:
        request: Custom report request
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Custom report data or generation status
    """
    try:
        report_service = ReportService(db)
        
        # Validate request
        if not request.data_sources:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one data source must be specified"
            )
        
        if not request.metrics:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one metric must be specified"
            )
        
        # Generate custom report
        if request.format == "json":
            # Generate immediately for JSON
            report_data = await report_service.generate_custom_report(
                name=request.name,
                data_sources=request.data_sources,
                metrics=request.metrics,
                filters=request.filters,
                grouping=request.grouping,
                time_range=request.time_range
            )
            
            return {
                "report_name": request.name,
                "generated_at": datetime.utcnow().isoformat(),
                "data": report_data
            }
        else:
            # Queue for background processing for other formats
            background_tasks.add_task(
                generate_custom_report_file,
                request,
                current_user.id,
                db
            )
            
            return {
                "message": "Custom report queued for generation",
                "report_name": request.name,
                "format": request.format,
                "estimated_completion": (datetime.utcnow() + timedelta(minutes=5)).isoformat()
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating custom report: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create custom report"
        )


@router.get("/export/{report_type}")
async def export_report(
    report_type: str,
    format: str = Query(..., description="Export format: csv, pdf, excel"),
    start_date: datetime = Query(..., description="Start date"),
    end_date: datetime = Query(..., description="End date"),
    filters: Optional[str] = Query(None, description="JSON string of filters"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Export a report in specified format.
    
    Args:
        report_type: Type of report to export
        format: Export format
        start_date: Start date for report
        end_date: End date for report
        filters: Additional filters as JSON string
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        File download response
    """
    try:
        report_service = ReportService(db)
        
        # Parse filters if provided
        filter_dict = {}
        if filters:
            try:
                filter_dict = json.loads(filters)
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid filters JSON format"
                )
        
        # Generate report data
        if report_type == "threat-analytics":
            report_data = await report_service.generate_threat_analytics(
                start_date=start_date,
                end_date=end_date,
                **filter_dict
            )
        elif report_type == "security-metrics":
            report_data = await report_service.calculate_security_metrics(
                start_date=start_date,
                end_date=end_date
            )
        elif report_type == "compliance":
            compliance_service = ComplianceService(db)
            report_data = await compliance_service.generate_compliance_report(
                start_date=start_date,
                end_date=end_date
            )
        elif report_type == "user-activity":
            report_data = await report_service.generate_user_activity_report(
                start_date=start_date,
                end_date=end_date,
                **filter_dict
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid report type"
            )
        
        # Generate file content based on format
        if format == "csv":
            content, media_type, filename = generate_csv_report(report_data, report_type)
        elif format == "pdf":
            content, media_type, filename = generate_pdf_report(report_data, report_type)
        elif format == "excel":
            content, media_type, filename = generate_excel_report(report_data, report_type)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid export format"
            )
        
        # Return file response
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting report: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export report"
        )


@router.get("/templates")
async def get_report_templates(
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get available report templates.
    
    Args:
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        List of available report templates
    """
    try:
        templates = [
            {
                "id": "threat-analytics",
                "name": "Threat Analytics Report",
                "description": "Comprehensive analysis of detected threats and quarantined emails",
                "data_sources": ["quarantined_emails", "audit_logs"],
                "available_metrics": [
                    "total_threats", "threats_by_level", "threats_by_type",
                    "detection_rate", "false_positives"
                ],
                "available_filters": [
                    "threat_level", "quarantine_reason", "department", "sender_domain"
                ]
            },
            {
                "id": "security-metrics",
                "name": "Security Metrics Dashboard",
                "description": "Key security performance indicators and metrics",
                "data_sources": ["audit_logs", "quarantined_emails", "simulations"],
                "available_metrics": [
                    "security_score", "detection_rate", "response_time",
                    "incidents_resolved", "user_risk_scores"
                ],
                "available_filters": [
                    "department", "time_granularity", "incident_type"
                ]
            },
            {
                "id": "compliance-report",
                "name": "Compliance Status Report",
                "description": "Compliance framework adherence and audit findings",
                "data_sources": ["audit_logs", "compliance_events", "data_retention"],
                "available_metrics": [
                    "compliance_score", "violations", "audit_findings",
                    "data_retention_compliance"
                ],
                "available_filters": [
                    "framework", "violation_type", "severity"
                ]
            },
            {
                "id": "user-activity",
                "name": "User Activity Report",
                "description": "User behavior analysis and simulation performance",
                "data_sources": ["simulations", "training", "users"],
                "available_metrics": [
                    "simulation_performance", "training_completion",
                    "risk_scores", "department_statistics"
                ],
                "available_filters": [
                    "department", "role", "simulation_type", "training_status"
                ]
            },
            {
                "id": "executive-summary",
                "name": "Executive Summary",
                "description": "High-level security overview for executive leadership",
                "data_sources": ["all"],
                "available_metrics": [
                    "overall_security_posture", "key_threats", "business_impact",
                    "improvement_recommendations"
                ],
                "available_filters": [
                    "time_period", "department", "priority_level"
                ]
            }
        ]
        
        return {"templates": templates}
        
    except Exception as e:
        logger.error(f"Error getting report templates: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get report templates"
        )


@router.get("/scheduled")
async def get_scheduled_reports(
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get list of scheduled reports.
    
    Args:
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        List of scheduled reports
    """
    try:
        # This would typically query a scheduled_reports table
        # For now, return placeholder data
        scheduled_reports = [
            {
                "id": "weekly-threat-summary",
                "name": "Weekly Threat Summary",
                "type": "threat-analytics",
                "schedule": "weekly",
                "recipients": ["security-team@company.com"],
                "format": "pdf",
                "last_run": "2024-01-15T09:00:00Z",
                "next_run": "2024-01-22T09:00:00Z",
                "status": "active"
            },
            {
                "id": "monthly-compliance-report",
                "name": "Monthly Compliance Report",
                "type": "compliance",
                "schedule": "monthly",
                "recipients": ["compliance@company.com", "legal@company.com"],
                "format": "excel",
                "last_run": "2024-01-01T08:00:00Z",
                "next_run": "2024-02-01T08:00:00Z",
                "status": "active"
            }
        ]
        
        return {"scheduled_reports": scheduled_reports}
        
    except Exception as e:
        logger.error(f"Error getting scheduled reports: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scheduled reports"
        )


# Helper functions for report generation
def generate_csv_report(data: Dict[str, Any], report_type: str) -> tuple:
    """Generate CSV report content."""
    output = io.StringIO()
    
    if report_type == "threat-analytics":
        writer = csv.writer(output)
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total Threats", data.get("total_threats", 0)])
        
        # Add threat level breakdown
        for level, count in data.get("threats_by_level", {}).items():
            writer.writerow([f"Threats - {level}", count])
    
    content = output.getvalue().encode('utf-8')
    filename = f"{report_type}_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return content, "text/csv", filename


def generate_pdf_report(data: Dict[str, Any], report_type: str) -> tuple:
    """Generate PDF report content."""
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    # Title
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, 750, f"{report_type.replace('-', ' ').title()} Report")
    
    # Date
    p.setFont("Helvetica", 12)
    p.drawString(50, 730, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Content (simplified)
    y_position = 700
    p.setFont("Helvetica", 10)
    
    for key, value in data.items():
        if isinstance(value, (str, int, float)):
            p.drawString(50, y_position, f"{key}: {value}")
            y_position -= 20
    
    p.showPage()
    p.save()
    
    content = buffer.getvalue()
    filename = f"{report_type}_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return content, "application/pdf", filename


def generate_excel_report(data: Dict[str, Any], report_type: str) -> tuple:
    """Generate Excel report content."""
    buffer = io.BytesIO()
    
    # Create Excel file with pandas
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        # Summary sheet
        summary_data = []
        for key, value in data.items():
            if isinstance(value, (str, int, float)):
                summary_data.append({"Metric": key, "Value": value})
        
        if summary_data:
            df = pd.DataFrame(summary_data)
            df.to_excel(writer, sheet_name='Summary', index=False)
    
    content = buffer.getvalue()
    filename = f"{report_type}_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    
    return content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename


async def generate_custom_report_file(
    request: CustomReportRequest,
    user_id: uuid.UUID,
    db: Session
):
    """Background task to generate custom report file."""
    try:
        report_service = ReportService(db)
        
        # Generate report data
        report_data = await report_service.generate_custom_report(
            name=request.name,
            data_sources=request.data_sources,
            metrics=request.metrics,
            filters=request.filters,
            grouping=request.grouping,
            time_range=request.time_range
        )
        
        # Generate file based on format
        if request.format == "csv":
            content, media_type, filename = generate_csv_report(report_data, "custom")
        elif request.format == "pdf":
            content, media_type, filename = generate_pdf_report(report_data, "custom")
        elif request.format == "excel":
            content, media_type, filename = generate_excel_report(report_data, "custom")
        else:
            raise ValueError("Invalid format")
        
        # Save file and notify user
        # In a real implementation, you would save the file to storage
        # and send a notification to the user with the download link
        
        logger.info(f"Custom report '{request.name}' generated for user {user_id}")
        
    except Exception as e:
        logger.error(f"Error generating custom report file: {str(e)}")
