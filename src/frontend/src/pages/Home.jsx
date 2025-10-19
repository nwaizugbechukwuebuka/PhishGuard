import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Typography,
  Card,
  CardContent,
  Paper,
  Button,
  Avatar,
  Chip,
  LinearProgress,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  IconButton,
  Tooltip,
  Badge,
  useTheme
} from '@mui/material';
import {
  Security as SecurityIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  Email as EmailIcon,
  Assessment as AssessmentIcon,
  School as SchoolIcon,
  Person as PersonIcon,
  Computer as ComputerIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Refresh as RefreshIcon,
  Visibility as VisibilityIcon,
  PlayArrow as PlayIcon,
  Report as ReportIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import Dashboard from '../components/Dashboard';
import AnalyticsGraph from '../components/AnalyticsGraph';

const Home = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [dashboardData, setDashboardData] = useState(null);
  const [recentActivity, setRecentActivity] = useState([]);
  const [systemStatus, setSystemStatus] = useState({});

  useEffect(() => {
    fetchHomeData();
  }, []);

  const fetchHomeData = async () => {
    try {
      setLoading(true);
      // Simulate API calls
      await new Promise(resolve => setTimeout(resolve, 1500));

      const mockDashboardData = {
        summary: {
          totalThreats: 1247,
          blockedToday: 89,
          activeSimulations: 3,
          systemUptime: 99.7,
          detectionRate: 97.3,
          falsePositiveRate: 1.2
        },
        quickStats: {
          emailsProcessed: 12547,
          threatsBlocked: 234,
          usersProtected: 1205,
          trainingCompleted: 87
        }
      };

      const mockActivity = [
        {
          id: 1,
          type: 'threat_blocked',
          title: 'High-Risk Phishing Email Blocked',
          description: 'CEO impersonation attempt targeting finance team',
          timestamp: new Date(Date.now() - 15 * 60000),
          severity: 'high',
          icon: <WarningIcon />
        },
        {
          id: 2,
          type: 'simulation_completed',
          title: 'Security Training Simulation Completed',
          description: '95% success rate for Q4 phishing awareness',
          timestamp: new Date(Date.now() - 45 * 60000),
          severity: 'info',
          icon: <SchoolIcon />
        },
        {
          id: 3,
          type: 'user_report',
          title: 'User Security Report Received',
          description: 'Suspicious email reported by Finance Dept.',
          timestamp: new Date(Date.now() - 2 * 60 * 60000),
          severity: 'medium',
          icon: <PersonIcon />
        },
        {
          id: 4,
          type: 'system_update',
          title: 'Detection Engine Updated',
          description: 'New ML model deployed with improved accuracy',
          timestamp: new Date(Date.now() - 3 * 60 * 60000),
          severity: 'info',
          icon: <ComputerIcon />
        }
      ];

      const mockSystemStatus = {
        aiEngine: { status: 'healthy', uptime: 99.8, version: 'v2.1.3' },
        quarantine: { status: 'healthy', capacity: 15, items: 127 },
        emailScanning: { status: 'healthy', throughput: 450, queue: 8 },
        database: { status: 'healthy', connections: 12, maxConnections: 100 }
      };

      setDashboardData(mockDashboardData);
      setRecentActivity(mockActivity);
      setSystemStatus(mockSystemStatus);
    } catch (error) {
      console.error('Error fetching home data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getActivityColor = (severity) => {
    switch (severity) {
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'primary';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'healthy': return theme.palette.success.main;
      case 'warning': return theme.palette.warning.main;
      case 'error': return theme.palette.error.main;
      default: return theme.palette.grey[500];
    }
  };

  const formatNumber = (num) => {
    return new Intl.NumberFormat().format(num);
  };

  const formatTimestamp = (timestamp) => {
    return timestamp.toLocaleString();
  };

  const quickActions = [
    {
      title: 'View Quarantine',
      description: 'Review quarantined emails',
      icon: <ShieldIcon />,
      color: 'warning',
      action: () => navigate('/quarantine')
    },
    {
      title: 'Run Simulation',
      description: 'Start security training',
      icon: <PlayIcon />,
      color: 'primary',
      action: () => navigate('/simulation')
    },
    {
      title: 'Generate Report',
      description: 'Create security report',
      icon: <ReportIcon />,
      color: 'info',
      action: () => navigate('/reports')
    },
    {
      title: 'View Analytics',
      description: 'Analyze threat trends',
      icon: <AssessmentIcon />,
      color: 'success',
      action: () => navigate('/analytics')
    }
  ];

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box mb={4}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Box>
            <Typography variant="h4" component="h1" fontWeight="bold" gutterBottom>
              PhishGuard Security Center
            </Typography>
            <Typography variant="body1" color="textSecondary">
              Welcome to your comprehensive email security dashboard
            </Typography>
          </Box>
          <Box display="flex" gap={2}>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={fetchHomeData}
              disabled={loading}
            >
              Refresh
            </Button>
            <Button
              variant="contained"
              startIcon={<SecurityIcon />}
              onClick={() => navigate('/compliance')}
            >
              Security Status
            </Button>
          </Box>
        </Box>

        {/* Security Alert Banner */}
        <Alert 
          severity="success" 
          icon={<CheckCircleIcon />}
          sx={{ mb: 3 }}
        >
          <Typography variant="subtitle2">
            All Systems Operational
          </Typography>
          <Typography variant="body2">
            PhishGuard is actively protecting your organization. Last threat blocked 15 minutes ago.
          </Typography>
        </Alert>
      </Box>

      {/* Quick Stats Cards */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Threats Blocked Today
                  </Typography>
                  <Typography variant="h4" component="h2" color="error.main">
                    {dashboardData?.summary.blockedToday || 0}
                  </Typography>
                </Box>
                <Avatar sx={{ bgcolor: 'error.main' }}>
                  <ShieldIcon />
                </Avatar>
              </Box>
              <LinearProgress 
                variant="determinate" 
                value={75} 
                color="error"
                sx={{ mt: 2, height: 6, borderRadius: 3 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Emails Processed
                  </Typography>
                  <Typography variant="h4" component="h2" color="primary.main">
                    {formatNumber(dashboardData?.quickStats.emailsProcessed || 0)}
                  </Typography>
                </Box>
                <Avatar sx={{ bgcolor: 'primary.main' }}>
                  <EmailIcon />
                </Avatar>
              </Box>
              <Typography variant="body2" color="success.main" sx={{ mt: 1 }}>
                +12% from yesterday
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Detection Rate
                  </Typography>
                  <Typography variant="h4" component="h2" color="success.main">
                    {dashboardData?.summary.detectionRate || 0}%
                  </Typography>
                </Box>
                <Avatar sx={{ bgcolor: 'success.main' }}>
                  <TrendingUpIcon />
                </Avatar>
              </Box>
              <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                AI-powered accuracy
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Active Simulations
                  </Typography>
                  <Typography variant="h4" component="h2" color="info.main">
                    {dashboardData?.summary.activeSimulations || 0}
                  </Typography>
                </Box>
                <Avatar sx={{ bgcolor: 'info.main' }}>
                  <SchoolIcon />
                </Avatar>
              </Box>
              <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                Training in progress
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Main Content */}
      <Grid container spacing={3}>
        {/* Left Column */}
        <Grid item xs={12} lg={8}>
          {/* Mini Dashboard */}
          <Box mb={3}>
            <Typography variant="h6" gutterBottom>
              Security Overview
            </Typography>
            <Dashboard />
          </Box>

          {/* Threat Analytics */}
          <Box>
            <Typography variant="h6" gutterBottom>
              Threat Trends
            </Typography>
            <AnalyticsGraph 
              title="Weekly Threat Analysis"
              dataSource="threats"
              timeRange="7d"
              height={300}
              showControls={false}
            />
          </Box>
        </Grid>

        {/* Right Column */}
        <Grid item xs={12} lg={4}>
          {/* Quick Actions */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Quick Actions
              </Typography>
              <Grid container spacing={2}>
                {quickActions.map((action, index) => (
                  <Grid item xs={6} key={index}>
                    <Paper
                      sx={{
                        p: 2,
                        textAlign: 'center',
                        cursor: 'pointer',
                        bgcolor: `${action.color}.50`,
                        '&:hover': {
                          bgcolor: `${action.color}.100`,
                          transform: 'translateY(-2px)',
                          boxShadow: 2
                        },
                        transition: 'all 0.2s ease'
                      }}
                      onClick={action.action}
                    >
                      <Avatar 
                        sx={{ 
                          bgcolor: `${action.color}.main`, 
                          margin: '0 auto',
                          mb: 1 
                        }}
                      >
                        {action.icon}
                      </Avatar>
                      <Typography variant="subtitle2" gutterBottom>
                        {action.title}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {action.description}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>

          {/* System Status */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Status
              </Typography>
              <List dense>
                {Object.entries(systemStatus).map(([key, status]) => (
                  <ListItem key={key}>
                    <ListItemIcon>
                      <Box
                        sx={{
                          width: 12,
                          height: 12,
                          borderRadius: '50%',
                          bgcolor: getStatusColor(status.status)
                        }}
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                      secondary={`${status.status} • ${
                        status.uptime ? `${status.uptime}% uptime` :
                        status.capacity ? `${status.items}/${status.capacity * 10} capacity` :
                        status.throughput ? `${status.throughput}/min throughput` :
                        `${status.connections}/${status.maxConnections} connections`
                      }`}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>

          {/* Recent Activity */}
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6">
                  Recent Activity
                </Typography>
                <Tooltip title="View All Activity">
                  <IconButton size="small" onClick={() => navigate('/reports')}>
                    <VisibilityIcon />
                  </IconButton>
                </Tooltip>
              </Box>
              <List dense>
                {recentActivity.map((activity, index) => (
                  <React.Fragment key={activity.id}>
                    <ListItem alignItems="flex-start">
                      <ListItemIcon>
                        <Badge
                          variant="dot"
                          color={getActivityColor(activity.severity)}
                        >
                          <Avatar sx={{ width: 32, height: 32, bgcolor: `${getActivityColor(activity.severity)}.main` }}>
                            {activity.icon}
                          </Avatar>
                        </Badge>
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Typography variant="subtitle2">
                            {activity.title}
                          </Typography>
                        }
                        secondary={
                          <>
                            <Typography variant="body2" color="textSecondary">
                              {activity.description}
                            </Typography>
                            <Typography variant="caption" color="textSecondary">
                              {formatTimestamp(activity.timestamp)}
                            </Typography>
                          </>
                        }
                      />
                    </ListItem>
                    {index < recentActivity.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Home;
