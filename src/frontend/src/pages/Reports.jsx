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
  TextField,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Alert,
  LinearProgress,
  Avatar,
  Badge
} from '@mui/material';
import {
  Assessment as AssessmentIcon,
  Download as DownloadIcon,
  Schedule as ScheduleIcon,
  Share as ShareIcon,
  Refresh as RefreshIcon,
  FilterList as FilterListIcon,
  PictureAsPdf as PdfIcon,
  TableChart as ExcelIcon,
  Email as EmailIcon,
  Security as SecurityIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Info as InfoIcon,
  CalendarToday as CalendarIcon,
  Business as BusinessIcon
} from '@mui/icons-material';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import AnalyticsGraph from '../components/AnalyticsGraph';

const Reports = () => {
  const [reportType, setReportType] = useState('security_summary');
  const [dateRange, setDateRange] = useState('last_30_days');
  const [startDate, setStartDate] = useState(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000));
  const [endDate, setEndDate] = useState(new Date());
  const [department, setDepartment] = useState('all');
  const [loading, setLoading] = useState(false);
  const [generateDialogOpen, setGenerateDialogOpen] = useState(false);
  const [reportHistory, setReportHistory] = useState([]);
  const [reportPreview, setReportPreview] = useState(null);

  const reportTypes = [
    {
      value: 'security_summary',
      label: 'Security Summary Report',
      description: 'Overall security posture and threat landscape',
      icon: <SecurityIcon />,
      color: 'primary'
    },
    {
      value: 'threat_analysis',
      label: 'Threat Analysis Report',
      description: 'Detailed analysis of security threats and incidents',
      icon: <WarningIcon />,
      color: 'error'
    },
    {
      value: 'compliance_audit',
      label: 'Compliance Audit Report',
      description: 'Regulatory compliance and policy adherence',
      icon: <CheckCircleIcon />,
      color: 'success'
    },
    {
      value: 'simulation_results',
      label: 'Training Simulation Results',
      description: 'Security awareness training outcomes',
      icon: <AssessmentIcon />,
      color: 'info'
    },
    {
      value: 'executive_summary',
      label: 'Executive Summary',
      description: 'High-level security metrics for leadership',
      icon: <BusinessIcon />,
      color: 'secondary'
    },
    {
      value: 'incident_response',
      label: 'Incident Response Report',
      description: 'Security incident timelines and responses',
      icon: <InfoIcon />,
      color: 'warning'
    }
  ];

  const dateRangeOptions = [
    { value: 'last_7_days', label: 'Last 7 Days' },
    { value: 'last_30_days', label: 'Last 30 Days' },
    { value: 'last_90_days', label: 'Last 90 Days' },
    { value: 'last_year', label: 'Last Year' },
    { value: 'custom', label: 'Custom Range' }
  ];

  const departments = [
    { value: 'all', label: 'All Departments' },
    { value: 'finance', label: 'Finance' },
    { value: 'hr', label: 'Human Resources' },
    { value: 'it', label: 'Information Technology' },
    { value: 'sales', label: 'Sales' },
    { value: 'marketing', label: 'Marketing' },
    { value: 'operations', label: 'Operations' },
    { value: 'legal', label: 'Legal' },
    { value: 'executive', label: 'Executive' }
  ];

  useEffect(() => {
    fetchReportHistory();
    generateReportPreview();
  }, [reportType, dateRange, department]);

  const fetchReportHistory = async () => {
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));

      const mockHistory = [
        {
          id: 1,
          name: 'Monthly Security Summary - October 2024',
          type: 'security_summary',
          generatedDate: new Date('2024-10-15T10:30:00'),
          generatedBy: 'John Admin',
          size: '2.4 MB',
          format: 'PDF',
          status: 'completed',
          downloads: 12
        },
        {
          id: 2,
          name: 'Q3 Threat Analysis Report',
          type: 'threat_analysis',
          generatedDate: new Date('2024-09-30T14:20:00'),
          generatedBy: 'Security Team',
          size: '8.7 MB',
          format: 'PDF',
          status: 'completed',
          downloads: 25
        },
        {
          id: 3,
          name: 'Compliance Audit - September 2024',
          type: 'compliance_audit',
          generatedDate: new Date('2024-09-28T09:15:00'),
          generatedBy: 'Compliance Officer',
          size: '5.2 MB',
          format: 'PDF',
          status: 'completed',
          downloads: 8
        },
        {
          id: 4,
          name: 'Phishing Simulation Results - Q3',
          type: 'simulation_results',
          generatedDate: new Date('2024-09-25T16:45:00'),
          generatedBy: 'Training Admin',
          size: '1.8 MB',
          format: 'Excel',
          status: 'completed',
          downloads: 18
        }
      ];

      setReportHistory(mockHistory);
    } catch (error) {
      console.error('Error fetching report history:', error);
    }
  };

  const generateReportPreview = async () => {
    try {
      // Simulate generating preview data based on selected parameters
      const mockPreview = {
        totalThreats: 1247,
        blockedEmails: 892,
        quarantinedItems: 156,
        falsePositives: 23,
        detectionRate: 97.3,
        simulationParticipants: 245,
        trainingSuccessRate: 89.2,
        complianceScore: 94.5,
        incidentCount: 8,
        resolvedIncidents: 7,
        avgResponseTime: '2.3 hours',
        topThreatTypes: [
          { type: 'Phishing', count: 445, percentage: 35.7 },
          { type: 'Malware', count: 289, percentage: 23.2 },
          { type: 'Spam', count: 267, percentage: 21.4 },
          { type: 'Suspicious Links', count: 246, percentage: 19.7 }
        ]
      };

      setReportPreview(mockPreview);
    } catch (error) {
      console.error('Error generating report preview:', error);
    }
  };

  const handleGenerateReport = async () => {
    try {
      setLoading(true);
      // Simulate report generation
      await new Promise(resolve => setTimeout(resolve, 3000));

      const newReport = {
        id: Date.now(),
        name: `${reportTypes.find(t => t.value === reportType)?.label} - ${new Date().toLocaleDateString()}`,
        type: reportType,
        generatedDate: new Date(),
        generatedBy: 'Current User',
        size: `${(Math.random() * 10 + 1).toFixed(1)} MB`,
        format: 'PDF',
        status: 'completed',
        downloads: 0
      };

      setReportHistory(prev => [newReport, ...prev]);
      setGenerateDialogOpen(false);
    } catch (error) {
      console.error('Error generating report:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = (reportId, format = 'pdf') => {
    // Simulate download
    console.log(`Downloading report ${reportId} as ${format}`);
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'success';
      case 'generating': return 'warning';
      case 'failed': return 'error';
      default: return 'default';
    }
  };

  const getReportIcon = (type) => {
    const reportType = reportTypes.find(t => t.value === type);
    return reportType?.icon || <AssessmentIcon />;
  };

  const formatNumber = (num) => {
    return new Intl.NumberFormat().format(num);
  };

  return (
    <LocalizationProvider dateAdapter={AdapterDateFns}>
      <Box sx={{ p: 3 }}>
        {/* Header */}
        <Box mb={4}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Box>
              <Typography variant="h4" component="h1" fontWeight="bold" gutterBottom>
                Security Reports & Analytics
              </Typography>
              <Typography variant="body1" color="textSecondary">
                Generate comprehensive security reports and export analytics data
              </Typography>
            </Box>
            <Box display="flex" gap={2}>
              <Button
                variant="outlined"
                startIcon={<RefreshIcon />}
                onClick={fetchReportHistory}
              >
                Refresh
              </Button>
              <Button
                variant="contained"
                startIcon={<AssessmentIcon />}
                onClick={() => setGenerateDialogOpen(true)}
              >
                Generate Report
              </Button>
            </Box>
          </Box>
        </Box>

        {/* Report Configuration */}
        <Grid container spacing={3} mb={4}>
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Report Configuration
                </Typography>
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth>
                      <InputLabel>Report Type</InputLabel>
                      <Select
                        value={reportType}
                        label="Report Type"
                        onChange={(e) => setReportType(e.target.value)}
                      >
                        {reportTypes.map((type) => (
                          <MenuItem key={type.value} value={type.value}>
                            <Box display="flex" alignItems="center" gap={1}>
                              {type.icon}
                              <Box>
                                <Typography variant="body2">{type.label}</Typography>
                                <Typography variant="caption" color="textSecondary">
                                  {type.description}
                                </Typography>
                              </Box>
                            </Box>
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth>
                      <InputLabel>Date Range</InputLabel>
                      <Select
                        value={dateRange}
                        label="Date Range"
                        onChange={(e) => setDateRange(e.target.value)}
                      >
                        {dateRangeOptions.map((option) => (
                          <MenuItem key={option.value} value={option.value}>
                            {option.label}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  {dateRange === 'custom' && (
                    <>
                      <Grid item xs={12} md={6}>
                        <DatePicker
                          label="Start Date"
                          value={startDate}
                          onChange={(newValue) => setStartDate(newValue)}
                          renderInput={(params) => <TextField {...params} fullWidth />}
                        />
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <DatePicker
                          label="End Date"
                          value={endDate}
                          onChange={(newValue) => setEndDate(newValue)}
                          renderInput={(params) => <TextField {...params} fullWidth />}
                        />
                      </Grid>
                    </>
                  )}
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth>
                      <InputLabel>Department</InputLabel>
                      <Select
                        value={department}
                        label="Department"
                        onChange={(e) => setDepartment(e.target.value)}
                      >
                        {departments.map((dept) => (
                          <MenuItem key={dept.value} value={dept.value}>
                            {dept.label}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            {reportPreview && (
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Report Preview
                  </Typography>
                  <Box display="flex" flexDirection="column" gap={2}>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Total Threats</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {formatNumber(reportPreview.totalThreats)}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Detection Rate</Typography>
                      <Typography variant="body2" fontWeight="bold" color="success.main">
                        {reportPreview.detectionRate}%
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Blocked Emails</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {formatNumber(reportPreview.blockedEmails)}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Training Success</Typography>
                      <Typography variant="body2" fontWeight="bold" color="info.main">
                        {reportPreview.trainingSuccessRate}%
                      </Typography>
                    </Box>
                  </Box>
                  <Divider sx={{ my: 2 }} />
                  <Button
                    fullWidth
                    variant="contained"
                    startIcon={<AssessmentIcon />}
                    onClick={() => setGenerateDialogOpen(true)}
                  >
                    Generate Full Report
                  </Button>
                </CardContent>
              </Card>
            )}
          </Grid>
        </Grid>

        {/* Analytics Charts */}
        <Grid container spacing={3} mb={4}>
          <Grid item xs={12} md={6}>
            <AnalyticsGraph
              title="Threat Detection Trends"
              dataSource="threats"
              timeRange="30d"
              height={300}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <AnalyticsGraph
              title="Email Processing Volume"
              dataSource="volume"
              timeRange="30d"
              height={300}
            />
          </Grid>
        </Grid>

        {/* Report History */}
        <Card>
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
              <Typography variant="h6">
                Report History
              </Typography>
              <Box display="flex" gap={1}>
                <Tooltip title="Filter Reports">
                  <IconButton size="small">
                    <FilterListIcon />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Schedule Reports">
                  <IconButton size="small">
                    <ScheduleIcon />
                  </IconButton>
                </Tooltip>
              </Box>
            </Box>

            <List>
              {reportHistory.map((report, index) => (
                <React.Fragment key={report.id}>
                  <ListItem>
                    <ListItemIcon>
                      <Avatar sx={{ bgcolor: `${reportTypes.find(t => t.value === report.type)?.color || 'primary'}.main` }}>
                        {getReportIcon(report.type)}
                      </Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" gap={1}>
                          <Typography variant="subtitle2">
                            {report.name}
                          </Typography>
                          <Chip
                            label={report.status}
                            color={getStatusColor(report.status)}
                            size="small"
                          />
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" color="textSecondary">
                            Generated by {report.generatedBy} on {report.generatedDate.toLocaleDateString()}
                          </Typography>
                          <Box display="flex" gap={2} mt={0.5}>
                            <Typography variant="caption">
                              Size: {report.size}
                            </Typography>
                            <Typography variant="caption">
                              Format: {report.format}
                            </Typography>
                            <Typography variant="caption">
                              Downloads: {report.downloads}
                            </Typography>
                          </Box>
                        </Box>
                      }
                    />
                    <Box display="flex" gap={1}>
                      <Tooltip title="Download PDF">
                        <IconButton
                          size="small"
                          onClick={() => handleDownloadReport(report.id, 'pdf')}
                        >
                          <PdfIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Download Excel">
                        <IconButton
                          size="small"
                          onClick={() => handleDownloadReport(report.id, 'excel')}
                        >
                          <ExcelIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Share Report">
                        <IconButton size="small">
                          <ShareIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </ListItem>
                  {index < reportHistory.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          </CardContent>
        </Card>

        {/* Generate Report Dialog */}
        <Dialog
          open={generateDialogOpen}
          onClose={() => setGenerateDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            Generate Security Report
          </DialogTitle>
          <DialogContent>
            <Box py={2}>
              <Alert severity="info" sx={{ mb: 3 }}>
                You are about to generate a {reportTypes.find(t => t.value === reportType)?.label} 
                for the selected time period and department. This process may take a few minutes.
              </Alert>

              <Typography variant="h6" gutterBottom>
                Report Configuration Summary
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Report Type:</Typography>
                  <Typography variant="body2" fontWeight="bold">
                    {reportTypes.find(t => t.value === reportType)?.label}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Date Range:</Typography>
                  <Typography variant="body2" fontWeight="bold">
                    {dateRangeOptions.find(r => r.value === dateRange)?.label}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Department:</Typography>
                  <Typography variant="body2" fontWeight="bold">
                    {departments.find(d => d.value === department)?.label}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Estimated Size:</Typography>
                  <Typography variant="body2" fontWeight="bold">
                    ~{(Math.random() * 10 + 1).toFixed(1)} MB
                  </Typography>
                </Grid>
              </Grid>

              {loading && (
                <Box mt={3}>
                  <Typography variant="body2" gutterBottom>
                    Generating report...
                  </Typography>
                  <LinearProgress />
                </Box>
              )}
            </Box>
          </DialogContent>
          <DialogActions>
            <Button 
              onClick={() => setGenerateDialogOpen(false)}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleGenerateReport}
              disabled={loading}
              startIcon={loading ? null : <DownloadIcon />}
            >
              {loading ? 'Generating...' : 'Generate Report'}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </LocalizationProvider>
  );
};

export default Reports;
