import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  LinearProgress,
  Chip,
  IconButton,
  Alert,
  CircularProgress,
  useTheme,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider
} from '@mui/material';
import {
  Security as SecurityIcon,
  Email as EmailIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Shield as ShieldIcon,
  Assessment as AssessmentIcon,
  School as SchoolIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';

const Dashboard = () => {
  const theme = useTheme();
  const [loading, setLoading] = useState(true);
  const [dashboardData, setDashboardData] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      // Simulate API call with mock data
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      const mockData = {
        summary: {
          totalEmails: 12547,
          threatsBlocked: 234,
          falsePositives: 12,
          systemUptime: 99.7,
          detectionRate: 97.3,
          responseTime: 0.23
        },
        trends: {
          emailVolume: [
            { date: '2024-01-01', emails: 1200, threats: 23 },
            { date: '2024-01-02', emails: 1350, threats: 28 },
            { date: '2024-01-03', emails: 1180, threats: 19 },
            { date: '2024-01-04', emails: 1420, threats: 31 },
            { date: '2024-01-05', emails: 1380, threats: 26 },
            { date: '2024-01-06', emails: 1290, threats: 22 },
            { date: '2024-01-07', emails: 1450, threats: 35 }
          ],
          threatCategories: [
            { name: 'Phishing', value: 145, color: '#FF6B6B' },
            { name: 'Malware', value: 52, color: '#4ECDC4' },
            { name: 'Spam', value: 23, color: '#45B7D1' },
            { name: 'Suspicious', value: 14, color: '#96CEB4' }
          ]
        },
        recentAlerts: [
          {
            id: 1,
            type: 'critical',
            title: 'High-Risk Phishing Campaign Detected',
            description: 'Sophisticated spear phishing targeting finance department',
            timestamp: new Date(Date.now() - 15 * 60000),
            source: 'AI Detection Engine'
          },
          {
            id: 2,
            type: 'warning',
            title: 'Unusual Email Volume Spike',
            description: '300% increase in emails from external domains',
            timestamp: new Date(Date.now() - 45 * 60000),
            source: 'Monitoring System'
          },
          {
            id: 3,
            type: 'info',
            title: 'Monthly Security Training Due',
            description: '23 users pending completion of phishing awareness training',
            timestamp: new Date(Date.now() - 2 * 60 * 60000),
            source: 'Training System'
          }
        ],
        systemHealth: {
          aiEngine: { status: 'healthy', score: 98 },
          quarantine: { status: 'healthy', score: 100 },
          notifications: { status: 'warning', score: 85 },
          reporting: { status: 'healthy', score: 92 }
        },
        topThreats: [
          { rank: 1, type: 'CEO Impersonation', count: 45, trend: 'up' },
          { rank: 2, type: 'Credential Harvesting', count: 38, trend: 'down' },
          { rank: 3, type: 'Malicious Attachments', count: 29, trend: 'up' },
          { rank: 4, type: 'Business Email Compromise', count: 22, trend: 'stable' },
          { rank: 5, type: 'Brand Impersonation', count: 18, trend: 'down' }
        ]
      };

      setDashboardData(mockData);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRefresh = () => {
    fetchDashboardData(true);
  };

  const formatNumber = (num) => {
    return new Intl.NumberFormat().format(num);
  };

  const formatTimestamp = (timestamp) => {
    return timestamp.toLocaleString();
  };

  const getAlertIcon = (type) => {
    switch (type) {
      case 'critical':
        return <ErrorIcon color="error" />;
      case 'warning':
        return <WarningIcon color="warning" />;
      case 'info':
        return <InfoIcon color="info" />;
      default:
        return <InfoIcon />;
    }
  };

  const getHealthColor = (status) => {
    switch (status) {
      case 'healthy':
        return theme.palette.success.main;
      case 'warning':
        return theme.palette.warning.main;
      case 'error':
        return theme.palette.error.main;
      default:
        return theme.palette.grey[500];
    }
  };

  const getTrendIcon = (trend) => {
    switch (trend) {
      case 'up':
        return <TrendingUpIcon color="error" fontSize="small" />;
      case 'down':
        return <TrendingDownIcon color="success" fontSize="small" />;
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <Box
        display="flex"
        justifyContent="center"
        alignItems="center"
        minHeight="400px"
      >
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (!dashboardData) {
    return (
      <Alert severity="error">
        Failed to load dashboard data. Please try refreshing the page.
      </Alert>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1" fontWeight="bold">
          Security Dashboard
        </Typography>
        <IconButton
          onClick={handleRefresh}
          disabled={refreshing}
          color="primary"
        >
          {refreshing ? <CircularProgress size={24} /> : <RefreshIcon />}
        </IconButton>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={2}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <EmailIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6" component="div">
                  Total Emails
                </Typography>
              </Box>
              <Typography variant="h4" component="div" fontWeight="bold">
                {formatNumber(dashboardData.summary.totalEmails)}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Last 24 hours
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={2}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <ShieldIcon color="error" sx={{ mr: 1 }} />
                <Typography variant="h6" component="div">
                  Threats Blocked
                </Typography>
              </Box>
              <Typography variant="h4" component="div" fontWeight="bold">
                {formatNumber(dashboardData.summary.threatsBlocked)}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Automatic quarantine
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={2}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <SecurityIcon color="success" sx={{ mr: 1 }} />
                <Typography variant="h6" component="div">
                  Detection Rate
                </Typography>
              </Box>
              <Typography variant="h4" component="div" fontWeight="bold">
                {dashboardData.summary.detectionRate}%
              </Typography>
              <LinearProgress
                variant="determinate"
                value={dashboardData.summary.detectionRate}
                sx={{ mt: 1, height: 6, borderRadius: 3 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={2}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <WarningIcon color="warning" sx={{ mr: 1 }} />
                <Typography variant="h6" component="div">
                  False Positives
                </Typography>
              </Box>
              <Typography variant="h4" component="div" fontWeight="bold">
                {formatNumber(dashboardData.summary.falsePositives)}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                {((dashboardData.summary.falsePositives / dashboardData.summary.totalEmails) * 100).toFixed(2)}% rate
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={2}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <AssessmentIcon color="info" sx={{ mr: 1 }} />
                <Typography variant="h6" component="div">
                  System Uptime
                </Typography>
              </Box>
              <Typography variant="h4" component="div" fontWeight="bold">
                {dashboardData.summary.systemUptime}%
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Last 30 days
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={2}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <TrendingUpIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6" component="div">
                  Response Time
                </Typography>
              </Box>
              <Typography variant="h4" component="div" fontWeight="bold">
                {dashboardData.summary.responseTime}s
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Avg. detection time
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts Row */}
      <Grid container spacing={3} mb={3}>
        {/* Email Volume Trend */}
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" component="div" mb={2}>
                Email Volume & Threats (Last 7 Days)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={dashboardData.trends.emailVolume}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" tickFormatter={(value) => new Date(value).toLocaleDateString()} />
                  <YAxis />
                  <Tooltip 
                    labelFormatter={(value) => new Date(value).toLocaleDateString()}
                    formatter={(value, name) => [formatNumber(value), name === 'emails' ? 'Emails' : 'Threats']}
                  />
                  <Area type="monotone" dataKey="emails" stackId="1" stroke="#8884d8" fill="#8884d8" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="threats" stackId="2" stroke="#82ca9d" fill="#82ca9d" fillOpacity={0.8} />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Threat Categories */}
        <Grid item xs={12} lg={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" component="div" mb={2}>
                Threat Categories
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={dashboardData.trends.threatCategories}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {dashboardData.trends.threatCategories.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value, name) => [value, name]} />
                </PieChart>
              </ResponsiveContainer>
              <Box mt={2}>
                {dashboardData.trends.threatCategories.map((category, index) => (
                  <Box key={index} display="flex" alignItems="center" mb={0.5}>
                    <Box
                      width={12}
                      height={12}
                      bgcolor={category.color}
                      borderRadius="50%"
                      mr={1}
                    />
                    <Typography variant="body2" sx={{ flexGrow: 1 }}>
                      {category.name}
                    </Typography>
                    <Typography variant="body2" fontWeight="bold">
                      {category.value}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Bottom Row */}
      <Grid container spacing={3}>
        {/* Recent Alerts */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" component="div" mb={2}>
                Recent Security Alerts
              </Typography>
              <List>
                {dashboardData.recentAlerts.map((alert, index) => (
                  <React.Fragment key={alert.id}>
                    <ListItem alignItems="flex-start">
                      <ListItemIcon>
                        {getAlertIcon(alert.type)}
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box display="flex" alignItems="center" mb={0.5}>
                            <Typography variant="subtitle2" sx={{ flexGrow: 1 }}>
                              {alert.title}
                            </Typography>
                            <Chip
                              label={alert.type}
                              size="small"
                              color={alert.type === 'critical' ? 'error' : alert.type === 'warning' ? 'warning' : 'info'}
                            />
                          </Box>
                        }
                        secondary={
                          <>
                            <Typography variant="body2" color="textSecondary" mb={0.5}>
                              {alert.description}
                            </Typography>
                            <Typography variant="caption" color="textSecondary">
                              {formatTimestamp(alert.timestamp)} • {alert.source}
                            </Typography>
                          </>
                        }
                      />
                    </ListItem>
                    {index < dashboardData.recentAlerts.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* System Health & Top Threats */}
        <Grid item xs={12} md={6}>
          <Grid container spacing={2}>
            {/* System Health */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" component="div" mb={2}>
                    System Health
                  </Typography>
                  <Grid container spacing={2}>
                    {Object.entries(dashboardData.systemHealth).map(([key, value]) => (
                      <Grid item xs={6} key={key}>
                        <Box display="flex" alignItems="center" mb={1}>
                          <Box
                            width={8}
                            height={8}
                            bgcolor={getHealthColor(value.status)}
                            borderRadius="50%"
                            mr={1}
                          />
                          <Typography variant="body2" sx={{ textTransform: 'capitalize' }}>
                            {key.replace(/([A-Z])/g, ' $1')}
                          </Typography>
                        </Box>
                        <LinearProgress
                          variant="determinate"
                          value={value.score}
                          sx={{ height: 6, borderRadius: 3 }}
                          color={value.status === 'healthy' ? 'success' : value.status === 'warning' ? 'warning' : 'error'}
                        />
                        <Typography variant="caption" color="textSecondary">
                          {value.score}%
                        </Typography>
                      </Grid>
                    ))}
                  </Grid>
                </CardContent>
              </Card>
            </Grid>

            {/* Top Threats */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" component="div" mb={2}>
                    Top Threat Types
                  </Typography>
                  <List dense>
                    {dashboardData.topThreats.map((threat) => (
                      <ListItem key={threat.rank}>
                        <ListItemText
                          primary={
                            <Box display="flex" alignItems="center">
                              <Typography variant="body2" sx={{ minWidth: 20 }}>
                                #{threat.rank}
                              </Typography>
                              <Typography variant="body2" sx={{ flexGrow: 1, ml: 1 }}>
                                {threat.type}
                              </Typography>
                              {getTrendIcon(threat.trend)}
                            </Box>
                          }
                          secondary={`${threat.count} incidents`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;
