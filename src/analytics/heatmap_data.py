"""
PhishGuard Heatmap Data Generator

This module generates heatmap data for visualizing threat patterns,
geographic distributions, and temporal analysis of email threats.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
import asyncio
import json
from collections import defaultdict
from sqlalchemy import func, and_, or_, text
from sqlalchemy.orm import Session

from ..api.database import get_db
from ..api.models.email import Email
from ..api.models.quarantine import QuarantinedEmail
from ..api.models.user import User
from ..api.utils.logger import get_logger

logger = get_logger(__name__)

class HeatmapDataGenerator:
    """Generate various types of heatmap data for threat visualization."""
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    async def generate_temporal_heatmap(
        self, 
        start_date: datetime,
        end_date: datetime,
        granularity: str = 'hour'
    ) -> Dict[str, Any]:
        """
        Generate temporal heatmap showing threat activity over time.
        
        Args:
            start_date: Start date for analysis
            end_date: End date for analysis
            granularity: Time granularity ('hour', 'day', 'week')
            
        Returns:
            Dict containing temporal heatmap data
        """
        try:
            if granularity == 'hour':
                return await self._generate_hourly_heatmap(start_date, end_date)
            elif granularity == 'day':
                return await self._generate_daily_heatmap(start_date, end_date)
            elif granularity == 'week':
                return await self._generate_weekly_heatmap(start_date, end_date)
            else:
                raise ValueError(f"Unsupported granularity: {granularity}")
                
        except Exception as e:
            logger.error(f"Error generating temporal heatmap: {str(e)}")
            raise

    async def _generate_hourly_heatmap(
        self, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate hourly threat activity heatmap."""
        
        # Query threats by hour of day and day of week
        hourly_data = self.db.query(
            func.extract('hour', Email.received_at).label('hour'),
            func.extract('dow', Email.received_at).label('day_of_week'),
            func.count(Email.id).label('threat_count')
        ).filter(
            and_(
                Email.received_at >= start_date,
                Email.received_at <= end_date,
                Email.is_threat == True
            )
        ).group_by('hour', 'day_of_week').all()
        
        # Initialize 24x7 grid
        heatmap_grid = [[0 for _ in range(24)] for _ in range(7)]
        max_count = 0
        
        # Fill grid with data
        for hour, dow, count in hourly_data:
            row = int(dow)  # 0 = Sunday, 6 = Saturday
            col = int(hour)  # 0-23 hours
            heatmap_grid[row][col] = count
            max_count = max(max_count, count)
        
        # Calculate normalized values for color intensity
        normalized_grid = []
        for row in heatmap_grid:
            normalized_row = []
            for cell in row:
                normalized_value = (cell / max_count) if max_count > 0 else 0
                normalized_row.append({
                    'count': cell,
                    'normalized': round(normalized_value, 3),
                    'intensity': self._get_intensity_level(normalized_value)
                })
            normalized_grid.append(normalized_row)
        
        return {
            'type': 'temporal_hourly',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'data': normalized_grid,
            'metadata': {
                'max_count': max_count,
                'total_threats': sum(sum(row) for row in heatmap_grid),
                'dimensions': '7x24',
                'labels': {
                    'x_axis': [f"{i:02d}:00" for i in range(24)],
                    'y_axis': ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
                }
            },
            'insights': await self._generate_temporal_insights(heatmap_grid)
        }

    async def _generate_daily_heatmap(
        self, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate daily threat activity heatmap."""
        
        daily_data = self.db.query(
            func.date(Email.received_at).label('date'),
            func.count(Email.id).label('threat_count')
        ).filter(
            and_(
                Email.received_at >= start_date,
                Email.received_at <= end_date,
                Email.is_threat == True
            )
        ).group_by(func.date(Email.received_at)).all()
        
        # Create date range
        date_range = []
        current_date = start_date.date()
        while current_date <= end_date.date():
            date_range.append(current_date)
            current_date += timedelta(days=1)
        
        # Build data structure
        date_counts = {date: count for date, count in daily_data}
        max_count = max(date_counts.values()) if date_counts else 0
        
        heatmap_data = []
        for date in date_range:
            count = date_counts.get(date, 0)
            normalized = (count / max_count) if max_count > 0 else 0
            
            heatmap_data.append({
                'date': date.isoformat(),
                'count': count,
                'normalized': round(normalized, 3),
                'intensity': self._get_intensity_level(normalized)
            })
        
        return {
            'type': 'temporal_daily',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'data': heatmap_data,
            'metadata': {
                'max_count': max_count,
                'total_threats': sum(item['count'] for item in heatmap_data),
                'date_count': len(date_range)
            },
            'insights': await self._generate_daily_insights(heatmap_data)
        }

    async def generate_geographic_heatmap(
        self, 
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Generate geographic heatmap showing threat origins.
        
        Note: In production, this would use actual IP geolocation data.
        """
        try:
            # Simulate geographic data (in production, use GeoIP databases)
            geographic_threats = {
                'US': {'count': 450, 'lat': 39.8283, 'lng': -98.5795},
                'CN': {'count': 320, 'lat': 35.8617, 'lng': 104.1954},
                'RU': {'count': 280, 'lat': 61.5240, 'lng': 105.3188},
                'NG': {'count': 150, 'lat': 9.0820, 'lng': 8.6753},
                'IN': {'count': 130, 'lat': 20.5937, 'lng': 78.9629},
                'BR': {'count': 110, 'lat': -14.2350, 'lng': -51.9253},
                'RO': {'count': 95, 'lat': 45.9432, 'lng': 24.9668},
                'VN': {'count': 85, 'lat': 14.0583, 'lng': 108.2772},
                'PK': {'count': 70, 'lat': 30.3753, 'lng': 69.3451},
                'ID': {'count': 65, 'lat': -0.7893, 'lng': 113.9213}
            }
            
            max_count = max(data['count'] for data in geographic_threats.values())
            
            # Normalize data for visualization
            normalized_data = {}
            for country, data in geographic_threats.items():
                normalized = data['count'] / max_count
                normalized_data[country] = {
                    'coordinates': [data['lng'], data['lat']],
                    'count': data['count'],
                    'normalized': round(normalized, 3),
                    'intensity': self._get_intensity_level(normalized),
                    'radius': int(normalized * 50) + 10  # For circle markers
                }
            
            return {
                'type': 'geographic',
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'data': normalized_data,
                'metadata': {
                    'max_count': max_count,
                    'total_countries': len(geographic_threats),
                    'total_threats': sum(data['count'] for data in geographic_threats.values())
                },
                'insights': await self._generate_geographic_insights(geographic_threats)
            }
            
        except Exception as e:
            logger.error(f"Error generating geographic heatmap: {str(e)}")
            raise

    async def generate_department_heatmap(
        self, 
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate heatmap showing threat distribution by department."""
        try:
            # Query threats by department
            # This assumes user emails follow department patterns
            department_data = self.db.query(
                func.case(
                    [(Email.recipient.like('%finance%'), 'Finance'),
                     (Email.recipient.like('%hr%'), 'HR'),
                     (Email.recipient.like('%sales%'), 'Sales'),
                     (Email.recipient.like('%marketing%'), 'Marketing'),
                     (Email.recipient.like('%it%'), 'IT'),
                     (Email.recipient.like('%legal%'), 'Legal'),
                     (Email.recipient.like('%exec%'), 'Executive')],
                    else_='Other'
                ).label('department'),
                func.count(Email.id).label('threat_count')
            ).filter(
                and_(
                    Email.received_at >= start_date,
                    Email.received_at <= end_date,
                    Email.is_threat == True
                )
            ).group_by('department').all()
            
            # Calculate total users per department (simulated)
            department_users = {
                'Finance': 45,
                'HR': 25,
                'Sales': 80,
                'Marketing': 35,
                'IT': 30,
                'Legal': 15,
                'Executive': 12,
                'Other': 100
            }
            
            max_threat_rate = 0
            department_analysis = {}
            
            for dept, threat_count in department_data:
                user_count = department_users.get(dept, 50)
                threat_rate = threat_count / user_count
                max_threat_rate = max(max_threat_rate, threat_rate)
                
                department_analysis[dept] = {
                    'threat_count': threat_count,
                    'user_count': user_count,
                    'threat_rate': round(threat_rate, 3),
                    'risk_level': self._calculate_department_risk(threat_rate)
                }
            
            # Normalize data
            for dept in department_analysis:
                data = department_analysis[dept]
                normalized = data['threat_rate'] / max_threat_rate if max_threat_rate > 0 else 0
                data['normalized'] = round(normalized, 3)
                data['intensity'] = self._get_intensity_level(normalized)
            
            return {
                'type': 'department',
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'data': department_analysis,
                'metadata': {
                    'max_threat_rate': round(max_threat_rate, 3),
                    'total_departments': len(department_analysis),
                    'total_users': sum(department_users.values())
                },
                'insights': await self._generate_department_insights(department_analysis)
            }
            
        except Exception as e:
            logger.error(f"Error generating department heatmap: {str(e)}")
            raise

    async def generate_threat_type_heatmap(
        self, 
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate heatmap showing threat type distribution over time."""
        try:
            # Query threat types by week
            threat_type_data = self.db.query(
                Email.threat_type,
                func.date_trunc('week', Email.received_at).label('week'),
                func.count(Email.id).label('count')
            ).filter(
                and_(
                    Email.received_at >= start_date,
                    Email.received_at <= end_date,
                    Email.is_threat == True,
                    Email.threat_type.isnot(None)
                )
            ).group_by(Email.threat_type, 'week').all()
            
            # Get all threat types and weeks
            threat_types = list(set(row.threat_type for row in threat_type_data))
            weeks = []
            current_week = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
            while current_week <= end_date:
                weeks.append(current_week)
                current_week += timedelta(weeks=1)
            
            # Build matrix
            heatmap_matrix = {}
            max_count = 0
            
            for threat_type in threat_types:
                heatmap_matrix[threat_type] = {}
                for week in weeks:
                    heatmap_matrix[threat_type][week.isoformat()] = 0
            
            # Fill matrix with data
            for row in threat_type_data:
                week_str = row.week.isoformat() if hasattr(row.week, 'isoformat') else str(row.week)
                if row.threat_type in heatmap_matrix:
                    heatmap_matrix[row.threat_type][week_str] = row.count
                    max_count = max(max_count, row.count)
            
            # Normalize data
            normalized_matrix = {}
            for threat_type, week_data in heatmap_matrix.items():
                normalized_matrix[threat_type] = {}
                for week, count in week_data.items():
                    normalized = count / max_count if max_count > 0 else 0
                    normalized_matrix[threat_type][week] = {
                        'count': count,
                        'normalized': round(normalized, 3),
                        'intensity': self._get_intensity_level(normalized)
                    }
            
            return {
                'type': 'threat_type_temporal',
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'data': normalized_matrix,
                'metadata': {
                    'threat_types': threat_types,
                    'weeks': [week.isoformat() for week in weeks],
                    'max_count': max_count
                },
                'insights': await self._generate_threat_type_insights(normalized_matrix)
            }
            
        except Exception as e:
            logger.error(f"Error generating threat type heatmap: {str(e)}")
            raise

    async def generate_sender_reputation_heatmap(
        self, 
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate heatmap based on sender reputation scores."""
        try:
            # Query sender reputation data
            reputation_data = self.db.query(
                func.case(
                    [(Email.sender_reputation >= 0.8, 'High (0.8-1.0)'),
                     (Email.sender_reputation >= 0.6, 'Medium (0.6-0.8)'),
                     (Email.sender_reputation >= 0.4, 'Low (0.4-0.6)'),
                     (Email.sender_reputation >= 0.2, 'Very Low (0.2-0.4)')],
                    else_='Unknown (0.0-0.2)'
                ).label('reputation_range'),
                func.avg(Email.risk_score).label('avg_risk_score'),
                func.count(Email.id).label('email_count')
            ).filter(
                and_(
                    Email.received_at >= start_date,
                    Email.received_at <= end_date
                )
            ).group_by('reputation_range').all()
            
            max_risk_score = max((row.avg_risk_score or 0) for row in reputation_data)
            max_email_count = max(row.email_count for row in reputation_data)
            
            heatmap_data = {}
            for row in reputation_data:
                risk_normalized = (row.avg_risk_score or 0) / max_risk_score if max_risk_score > 0 else 0
                count_normalized = row.email_count / max_email_count if max_email_count > 0 else 0
                
                heatmap_data[row.reputation_range] = {
                    'avg_risk_score': round(row.avg_risk_score or 0, 2),
                    'email_count': row.email_count,
                    'risk_normalized': round(risk_normalized, 3),
                    'count_normalized': round(count_normalized, 3),
                    'combined_intensity': self._get_intensity_level((risk_normalized + count_normalized) / 2)
                }
            
            return {
                'type': 'sender_reputation',
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'data': heatmap_data,
                'metadata': {
                    'max_risk_score': round(max_risk_score, 2),
                    'max_email_count': max_email_count,
                    'reputation_ranges': list(heatmap_data.keys())
                },
                'insights': await self._generate_reputation_insights(heatmap_data)
            }
            
        except Exception as e:
            logger.error(f"Error generating sender reputation heatmap: {str(e)}")
            raise

    def _get_intensity_level(self, normalized_value: float) -> str:
        """Convert normalized value to intensity level."""
        if normalized_value >= 0.8:
            return 'very_high'
        elif normalized_value >= 0.6:
            return 'high'
        elif normalized_value >= 0.4:
            return 'medium'
        elif normalized_value >= 0.2:
            return 'low'
        else:
            return 'very_low'

    def _calculate_department_risk(self, threat_rate: float) -> str:
        """Calculate department risk level based on threat rate."""
        if threat_rate >= 5.0:
            return 'critical'
        elif threat_rate >= 3.0:
            return 'high'
        elif threat_rate >= 1.5:
            return 'medium'
        elif threat_rate >= 0.5:
            return 'low'
        else:
            return 'minimal'

    async def _generate_temporal_insights(self, heatmap_grid: List[List[int]]) -> List[str]:
        """Generate insights from temporal heatmap data."""
        insights = []
        
        # Find peak hours
        hourly_totals = [sum(heatmap_grid[day][hour] for day in range(7)) for hour in range(24)]
        peak_hour = hourly_totals.index(max(hourly_totals))
        insights.append(f"Peak threat activity occurs at {peak_hour:02d}:00 hours")
        
        # Find peak days
        daily_totals = [sum(heatmap_grid[day]) for day in range(7)]
        days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        peak_day = daily_totals.index(max(daily_totals))
        insights.append(f"Highest threat volume on {days[peak_day]}s")
        
        # Weekend vs weekday analysis
        weekend_total = daily_totals[0] + daily_totals[6]  # Sunday + Saturday
        weekday_total = sum(daily_totals[1:6])  # Monday-Friday
        
        if weekend_total > weekday_total * 0.4:  # Significant weekend activity
            insights.append("Significant threat activity observed during weekends")
        
        return insights

    async def _generate_daily_insights(self, heatmap_data: List[Dict]) -> List[str]:
        """Generate insights from daily heatmap data."""
        insights = []
        
        # Find patterns
        counts = [item['count'] for item in heatmap_data]
        avg_count = sum(counts) / len(counts)
        
        # Identify spikes
        spikes = [item for item in heatmap_data if item['count'] > avg_count * 2]
        if spikes:
            insights.append(f"Detected {len(spikes)} days with threat spikes")
        
        # Trend analysis
        if len(counts) >= 7:
            recent_avg = sum(counts[-7:]) / 7
            earlier_avg = sum(counts[:-7]) / len(counts[:-7]) if len(counts) > 7 else recent_avg
            
            if recent_avg > earlier_avg * 1.2:
                insights.append("Increasing threat trend detected in recent days")
            elif recent_avg < earlier_avg * 0.8:
                insights.append("Decreasing threat trend observed")
        
        return insights

    async def _generate_geographic_insights(self, geographic_data: Dict) -> List[str]:
        """Generate insights from geographic heatmap data."""
        insights = []
        
        # Top threat countries
        sorted_countries = sorted(
            geographic_data.items(), 
            key=lambda x: x[1]['count'], 
            reverse=True
        )
        
        top_country = sorted_countries[0][0] if sorted_countries else 'Unknown'
        insights.append(f"Primary threat source: {top_country}")
        
        # Concentration analysis
        top_3_total = sum(data['count'] for country, data in sorted_countries[:3])
        total_threats = sum(data['count'] for data in geographic_data.values())
        
        concentration = (top_3_total / total_threats) * 100 if total_threats > 0 else 0
        insights.append(f"Top 3 countries account for {concentration:.1f}% of threats")
        
        return insights

    async def _generate_department_insights(self, department_data: Dict) -> List[str]:
        """Generate insights from department heatmap data."""
        insights = []
        
        # Highest risk department
        highest_risk = max(
            department_data.items(), 
            key=lambda x: x[1]['threat_rate']
        ) if department_data else None
        
        if highest_risk:
            dept_name, data = highest_risk
            insights.append(f"{dept_name} has highest threat rate: {data['threat_rate']:.2f} threats/user")
        
        # Risk distribution
        high_risk_depts = [
            dept for dept, data in department_data.items() 
            if data['risk_level'] in ['high', 'critical']
        ]
        
        if high_risk_depts:
            insights.append(f"{len(high_risk_depts)} departments classified as high risk")
        
        return insights

    async def _generate_threat_type_insights(self, matrix_data: Dict) -> List[str]:
        """Generate insights from threat type heatmap data."""
        insights = []
        
        # Most common threat type
        threat_totals = {}
        for threat_type, week_data in matrix_data.items():
            threat_totals[threat_type] = sum(
                item['count'] for item in week_data.values()
            )
        
        if threat_totals:
            most_common = max(threat_totals.items(), key=lambda x: x[1])
            insights.append(f"Most prevalent threat type: {most_common[0]} ({most_common[1]} incidents)")
        
        # Trend analysis
        for threat_type, week_data in matrix_data.items():
            weekly_counts = [item['count'] for item in week_data.values()]
            if len(weekly_counts) >= 4:
                recent_trend = sum(weekly_counts[-2:]) / 2
                earlier_trend = sum(weekly_counts[:-2]) / len(weekly_counts[:-2])
                
                if recent_trend > earlier_trend * 1.5:
                    insights.append(f"{threat_type} showing increasing trend")
        
        return insights

    async def _generate_reputation_insights(self, reputation_data: Dict) -> List[str]:
        """Generate insights from reputation heatmap data."""
        insights = []
        
        # High-risk low-reputation analysis
        for reputation_range, data in reputation_data.items():
            if 'Low' in reputation_range and data['avg_risk_score'] > 70:
                insights.append(f"{reputation_range} senders have high average risk score: {data['avg_risk_score']}")
        
        # Volume analysis
        total_emails = sum(data['email_count'] for data in reputation_data.values())
        for reputation_range, data in reputation_data.items():
            percentage = (data['email_count'] / total_emails) * 100 if total_emails > 0 else 0
            if percentage > 30:
                insights.append(f"{reputation_range} senders account for {percentage:.1f}% of emails")
        
        return insights


# API functions for generating different heatmap types
async def generate_temporal_heatmap(
    start_date: datetime,
    end_date: datetime,
    granularity: str = 'hour'
) -> Dict[str, Any]:
    """Generate temporal threat heatmap."""
    db = next(get_db())
    try:
        generator = HeatmapDataGenerator(db)
        return await generator.generate_temporal_heatmap(start_date, end_date, granularity)
    finally:
        db.close()


async def generate_geographic_heatmap(
    start_date: datetime,
    end_date: datetime
) -> Dict[str, Any]:
    """Generate geographic threat heatmap."""
    db = next(get_db())
    try:
        generator = HeatmapDataGenerator(db)
        return await generator.generate_geographic_heatmap(start_date, end_date)
    finally:
        db.close()


async def generate_department_heatmap(
    start_date: datetime,
    end_date: datetime
) -> Dict[str, Any]:
    """Generate department threat heatmap."""
    db = next(get_db())
    try:
        generator = HeatmapDataGenerator(db)
        return await generator.generate_department_heatmap(start_date, end_date)
    finally:
        db.close()


async def generate_all_heatmaps(
    start_date: datetime,
    end_date: datetime
) -> Dict[str, Any]:
    """Generate all available heatmap types."""
    db = next(get_db())
    try:
        generator = HeatmapDataGenerator(db)
        
        temporal_task = generator.generate_temporal_heatmap(start_date, end_date)
        geographic_task = generator.generate_geographic_heatmap(start_date, end_date)
        department_task = generator.generate_department_heatmap(start_date, end_date)
        threat_type_task = generator.generate_threat_type_heatmap(start_date, end_date)
        reputation_task = generator.generate_sender_reputation_heatmap(start_date, end_date)
        
        temporal, geographic, department, threat_type, reputation = await asyncio.gather(
            temporal_task, geographic_task, department_task, 
            threat_type_task, reputation_task
        )
        
        return {
            'temporal': temporal,
            'geographic': geographic,
            'department': department,
            'threat_type': threat_type,
            'reputation': reputation,
            'generated_at': datetime.utcnow().isoformat()
        }
        
    finally:
        db.close()


if __name__ == "__main__":
    # Example usage
    async def main():
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        print("Generating heatmap data...")
        heatmaps = await generate_all_heatmaps(start_date, end_date)
        
        print("Heatmap types generated:")
        for heatmap_type in heatmaps:
            if heatmap_type != 'generated_at':
                print(f"- {heatmap_type}")
    
    asyncio.run(main())
