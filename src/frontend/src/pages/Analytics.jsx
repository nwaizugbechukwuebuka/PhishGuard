import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  ToggleButtonGroup,
  ToggleButton,
  Alert,
  Divider
} from '@mui/material';
import {
  Analytics as AnalyticsIcon,
  TrendingUp as TrendingUpIcon,
  ShowChart as ShowChartIcon,
  BarChart as BarChartIcon,
  Timeline as TimelineIcon,
  PieChart as PieChartIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Share as ShareIcon,
  Settings as SettingsIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Email as EmailIcon,
  People as PeopleIcon
} from '@mui/icons-material';
import AnalyticsGraph from '../components/AnalyticsGraph';
import Heatmap from '../components/Heatmap';

const Analytics = () => {
  const [timeRange, setTimeRange] = useState('30d');
  const [viewMode, setViewMode] = useState('overview');
  const [dataSource, setDataSource] = useState('threats');
  const [loading, setLoading] = useState(false);
  const [analyticsData, setAnalyticsData] = useState({});

  const timeRanges = [
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
    { value: '90d', label: 'Last 90 Days' },
    { value: '1y', label: 'Last Year' }
  ];

  const viewModes = [
    { value: 'overview', label: 'Overview', icon: <AnalyticsIcon /> },
    { value: 'threats', label: 'Threat Analysis', icon: <WarningIcon /> },
    { value: 'performance', label: 'Performance', icon: <TrendingUpIcon /> },
    { value: 'users', label: 'User Behavior', icon: <PeopleIcon /> },
    { value: 'compliance', label: 'Compliance', icon: <SecurityIcon /> }
  ];

  const dataSources = [
    { value: 'threats', label: 'Security Threats' },
    { value: 'emails', label: 'Email Traffic' },
    { value: 'users', label: 'User Activity' },
    { value: 'performance', label: 'System Performance' }
  ];

  useEffect(() => {
    fetchAnalyticsData();
  }, [timeRange, viewMode, dataSource]);

  const fetchAnalyticsData = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      const mockData = {
        summary: {
          totalThreats: 1247,
          threatsBlocked: 1156,
          detectionRate: 92.7,
          falsePositives: 91,
          emailsProcessed: 45678,
          usersProtected: 1205,
          systemUptime: 99.8,
          avgResponseTime: 0.23
        },
        trends: {
          threatTrend: 15.2, // percentage change
          emailTrend: -3.4,
          performanceTrend: 8.7,
          userTrend: 12.1
        },
        topThreats: [
          { type: 'Phishing', count: 445, percentage: 35.7, trend: 'up' },
          { type: 'Malware', count: 289, percentage: 23.2, trend: 'down' },
          { type: 'Spam', count: 267, percentage: 21.4, trend: 'stable' },
          { type: 'CEO Fraud', count: 156, percentage: 12.5, trend: 'up' },
          { type: 'Ransomware', count: 90, percentage: 7.2, trend: 'down' }
        ],
        riskMetrics: {
          highRisk: 156,
          mediumRisk: 289,
          lowRisk: 445,
          resolved: 801
        }
      };

      setAnalyticsData(mockData);
    } catch (error) {
      console.error('Error fetching analytics data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExportData = (format) => {
    console.log(`Exporting analytics data as ${format}`);
    // Implement export functionality
  };

  const formatNumber = (num) => {
    return new Intl.NumberFormat().format(num);
  };

  const getTrendIcon = (trend) => {
    if (trend > 0) return <TrendingUpIcon color="error" fontSize="small" />;
    if (trend < 0) return <TrendingUpIcon color="success" fontSize="small" sx={{ transform: 'rotate(180deg)' }} />;
    return null;
  };

  const getTrendColor = (trend) => {
    if (trend > 0) return 'error';
    if (trend < 0) return 'success';
    return 'textSecondary';
  };

  const renderOverviewMode = () => (
    <Grid container spacing={3}>
      {/* Summary Cards */}
      <Grid item xs={12}>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Box>
                    <Typography color="textSecondary" gutterBottom>
                      Total Threats
                    </Typography>
                    <Typography variant="h4" component="h2" color="error.main">
                      {formatNumber(analyticsData.summary?.totalThreats || 0)}
                    </Typography>
                    <Box display="flex" alignItems="center" mt={1}>
                      {getTrendIcon(analyticsData.trends?.threatTrend)}
                      <Typography 
                        variant="body2" 
                        color={getTrendColor(analyticsData.trends?.threatTrend)}
                        ml={0.5}
                      >
                        {Math.abs(analyticsData.trends?.threatTrend || 0).toFixed(1)}%
                      </Typography>
                    </Box>
                  </Box>
                  <WarningIcon color="error" sx={{ fontSize: 40, opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Box>
                    <Typography color="textSecondary" gutterBottom>
                      Detection Rate
                    </Typography>
                    <Typography variant="h4" component="h2" color="success.main">
                      {analyticsData.summary?.detectionRate || 0}%
                    </Typography>
                    <Typography variant="body2" color="textSecondary" mt={1}>
                      AI-powered accuracy
                    </Typography>
                  </Box>
                  <SecurityIcon color="success" sx={{ fontSize: 40, opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Box>
                    <Typography color="textSecondary" gutterBottom>
                      Emails Processed
                    </Typography>
                    <Typography variant="h4" component="h2" color="primary.main">
                      {formatNumber(analyticsData.summary?.emailsProcessed || 0)}
                    </Typography>
                    <Box display="flex" alignItems="center" mt={1}>
                      {getTrendIcon(analyticsData.trends?.emailTrend)}
                      <Typography 
                        variant="body2" 
                        color={getTrendColor(analyticsData.trends?.emailTrend)}
                        ml={0.5}
                      >
                        {Math.abs(analyticsData.trends?.emailTrend || 0).toFixed(1)}%
                      </Typography>
                    </Box>
                  </Box>
                  <EmailIcon color="primary" sx={{ fontSize: 40, opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Box>
                    <Typography color="textSecondary" gutterBottom>
                      System Uptime
                    </Typography>
                    <Typography variant="h4" component="h2" color="info.main">
                      {analyticsData.summary?.systemUptime || 0}%
                    </Typography>
                    <Typography variant="body2" color="textSecondary" mt={1}>
                      Last 30 days
                    </Typography>
                  </Box>
                  <TrendingUpIcon color="info" sx={{ fontSize: 40, opacity: 0.3 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid item xs={12} md={8}>
        <AnalyticsGraph
          title="Security Threats Overview"
          dataSource="threats"
          timeRange={timeRange}
          height={400}
        />
      </Grid>

      <Grid item xs={12} md={4}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Top Threat Types
            </Typography>
            {analyticsData.topThreats?.map((threat, index) => (
              <Box key={index} mb={2}>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                  <Typography variant="body2">{threat.type}</Typography>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Typography variant="body2" fontWeight="bold">
                      {threat.count}
                    </Typography>
                    {threat.trend === 'up' && <TrendingUpIcon color="error" fontSize="small" />}
                    {threat.trend === 'down' && <TrendingUpIcon color="success" fontSize="small" sx={{ transform: 'rotate(180deg)' }} />}
                  </Box>
                </Box>
                <Box
                  sx={{
                    width: '100%',
                    height: 6,
                    bgcolor: 'grey.200',
                    borderRadius: 3,
                    overflow: 'hidden'
                  }}
                >
                  <Box
                    sx={{
                      width: `${threat.percentage}%`,
                      height: '100%',
                      bgcolor: index === 0 ? 'error.main' : index === 1 ? 'warning.main' : 'info.main',
                      borderRadius: 3
                    }}
                  />
                </Box>
              </Box>
            ))}
          </CardContent>
        </Card>
      </Grid>

      {/* Heatmap */}
      <Grid item xs={12}>
        <Heatmap
          title="Threat Activity Heatmap"
          dataType="temporal"
          height={400}
        />
      </Grid>
    </Grid>
  );

  const renderThreatsMode = () => (
    <Grid container spacing={3}>
      <Grid item xs={12} md={6}>
        <AnalyticsGraph
          title="Threat Detection Trends"
          dataSource="threats"
          timeRange={timeRange}
          height={350}
        />
      </Grid>
      <Grid item xs={12} md={6}>
        <AnalyticsGraph
          title="Threat Categories"
          dataSource="threats"
          timeRange={timeRange}
          height={350}
        />
      </Grid>
      <Grid item xs={12}>
        <Heatmap
          title="Geographic Threat Distribution"
          dataType="geographic"
          height={400}
        />
      </Grid>
    </Grid>
  );

  const renderPerformanceMode = () => (
    <Grid container spacing={3}>
      <Grid item xs={12} md={6}>
        <AnalyticsGraph
          title="System Performance Metrics"
          dataSource="performance"
          timeRange={timeRange}
          height={350}
        />
      </Grid>
      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Performance Summary
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'success.50' }}>
                  <Typography variant="h5" color="success.main">
                    {analyticsData.summary?.avgResponseTime || 0}s
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Avg Response Time
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6}>
                <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'info.50' }}>
                  <Typography variant="h5" color="info.main">
                    {analyticsData.summary?.systemUptime || 0}%
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    System Uptime
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderUsersMode = () => (
    <Grid container spacing={3}>
      <Grid item xs={12} md={6}>
        <AnalyticsGraph
          title="User Activity Patterns"
          dataSource="volume"
          timeRange={timeRange}
          height={350}
        />
      </Grid>
      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              User Statistics
            </Typography>
            <Box display="flex" flexDirection="column" gap={2}>
              <Box display="flex" justifyContent="space-between">
                <Typography>Protected Users</Typography>
                <Typography fontWeight="bold">
                  {formatNumber(analyticsData.summary?.usersProtected || 0)}
                </Typography>
              </Box>
              <Box display="flex" justifyContent="space-between">
                <Typography>Active Sessions</Typography>
                <Typography fontWeight="bold">892</Typography>
              </Box>
              <Box display="flex" justifyContent="space-between">
                <Typography>Training Completion</Typography>
                <Typography fontWeight="bold" color="success.main">87%</Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderComplianceMode = () => (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Alert severity="info">
          Compliance analytics and regulatory reporting dashboard
        </Alert>
      </Grid>
      <Grid item xs={12} md={4}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Compliance Score
            </Typography>
            <Typography variant="h3" color="success.main" align="center">
              94.5%
            </Typography>
            <Typography variant="body2" color="textSecondary" align="center">
              Regulatory Compliance
            </Typography>
          </CardContent>
        </Card>
      </Grid>
      <Grid item xs={12} md={8}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Compliance Metrics
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Data Protection</Typography>
                <Typography variant="h6" color="success.main">98%</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Incident Response</Typography>
                <Typography variant="h6" color="success.main">95%</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Access Control</Typography>
                <Typography variant="h6" color="warning.main">89%</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Audit Trail</Typography>
                <Typography variant="h6" color="success.main">97%</Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderContent = () => {
    switch (viewMode) {
      case 'threats': return renderThreatsMode();
      case 'performance': return renderPerformanceMode();
      case 'users': return renderUsersMode();
      case 'compliance': return renderComplianceMode();
      default: return renderOverviewMode();
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box mb={4}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Box>
            <Typography variant="h4" component="h1" fontWeight="bold" gutterBottom>
              Security Analytics Dashboard
            </Typography>
            <Typography variant="body1" color="textSecondary">
              Comprehensive analytics and insights for your security infrastructure
            </Typography>
          </Box>
          <Box display="flex" gap={2}>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={fetchAnalyticsData}
              disabled={loading}
            >
              Refresh
            </Button>
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              onClick={() => handleExportData('pdf')}
            >
              Export
            </Button>
            <Button
              variant="contained"
              startIcon={<SettingsIcon />}
            >
              Settings
            </Button>
          </Box>
        </Box>

        {/* Controls */}
        <Grid container spacing={3} alignItems="center">
          <Grid item xs={12} md={4}>
            <ToggleButtonGroup
              value={viewMode}
              exclusive
              onChange={(e, newMode) => newMode && setViewMode(newMode)}
              size="small"
              fullWidth
            >
              {viewModes.slice(0, 3).map((mode) => (
                <ToggleButton key={mode.value} value={mode.value}>
                  {mode.icon}
                  <Typography variant="caption" ml={0.5}>
                    {mode.label}
                  </Typography>
                </ToggleButton>
              ))}
            </ToggleButtonGroup>
          </Grid>
          <Grid item xs={12} md={4}>
            <ToggleButtonGroup
              value={viewMode}
              exclusive
              onChange={(e, newMode) => newMode && setViewMode(newMode)}
              size="small"
              fullWidth
            >
              {viewModes.slice(3).map((mode) => (
                <ToggleButton key={mode.value} value={mode.value}>
                  {mode.icon}
                  <Typography variant="caption" ml={0.5}>
                    {mode.label}
                  </Typography>
                </ToggleButton>
              ))}
            </ToggleButtonGroup>
          </Grid>
          <Grid item xs={12} md={4}>
            <FormControl fullWidth size="small">
              <InputLabel>Time Range</InputLabel>
              <Select
                value={timeRange}
                label="Time Range"
                onChange={(e) => setTimeRange(e.target.value)}
              >
                {timeRanges.map((range) => (
                  <MenuItem key={range.value} value={range.value}>
                    {range.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
        </Grid>
      </Box>

      {/* Content */}
      {renderContent()}
    </Box>
  );
};

export default Analytics;
