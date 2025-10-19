import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Chip,
  Paper,
  Alert,
  Divider,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Snackbar
} from '@mui/material';
import {
  Shield as ShieldIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  FilterList as FilterListIcon,
  Settings as SettingsIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import QuarantineTable from '../components/QuarantineTable';
import EmailViewer from '../components/EmailViewer';

const Quarantine = () => {
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [emailViewerOpen, setEmailViewerOpen] = useState(false);
  const [quarantineStats, setQuarantineStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'info' });

  useEffect(() => {
    fetchQuarantineStats();
  }, []);

  const fetchQuarantineStats = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      const mockStats = {
        totalQuarantined: 1247,
        todayQuarantined: 89,
        pendingReview: 23,
        falsePositives: 12,
        highRisk: 156,
        mediumRisk: 89,
        lowRisk: 45,
        storageUsed: 2.4, // GB
        storageLimit: 10.0, // GB
        retentionDays: 30,
        autoDeleteEnabled: true
      };

      setQuarantineStats(mockStats);
    } catch (error) {
      console.error('Error fetching quarantine stats:', error);
      setSnackbar({
        open: true,
        message: 'Error loading quarantine statistics',
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleEmailView = (email) => {
    setSelectedEmail(email);
    setEmailViewerOpen(true);
  };

  const handleBulkAction = (action, emailIds) => {
    setSnackbar({
      open: true,
      message: `${action} action performed on ${emailIds.length} email(s)`,
      severity: 'success'
    });
    // Refresh data after action
    fetchQuarantineStats();
  };

  const handleExportData = () => {
    setSnackbar({
      open: true,
      message: 'Quarantine data export started. You will receive a download link shortly.',
      severity: 'info'
    });
  };

  const formatFileSize = (sizeGB) => {
    return `${sizeGB.toFixed(1)} GB`;
  };

  const formatNumber = (num) => {
    return new Intl.NumberFormat().format(num);
  };

  const getStorageUsagePercentage = () => {
    return (quarantineStats.storageUsed / quarantineStats.storageLimit) * 100;
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box mb={4}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Box>
            <Typography variant="h4" component="h1" fontWeight="bold" gutterBottom>
              Email Quarantine Center
            </Typography>
            <Typography variant="body1" color="textSecondary">
              Review and manage quarantined emails and security threats
            </Typography>
          </Box>
          <Box display="flex" gap={2}>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={fetchQuarantineStats}
              disabled={loading}
            >
              Refresh
            </Button>
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              onClick={handleExportData}
            >
              Export Data
            </Button>
            <Button
              variant="contained"
              startIcon={<SecurityIcon />}
              onClick={() => {/* Navigate to settings */}}
            >
              Quarantine Settings
            </Button>
          </Box>
        </Box>

        {/* Status Alert */}
        <Alert 
          severity={getStorageUsagePercentage() > 80 ? 'warning' : 'info'}
          icon={getStorageUsagePercentage() > 80 ? <WarningIcon /> : <InfoIcon />}
        >
          <Typography variant="subtitle2">
            Quarantine Status: {getStorageUsagePercentage() > 80 ? 'Storage Warning' : 'Operational'}
          </Typography>
          <Typography variant="body2">
            {getStorageUsagePercentage() > 80 
              ? `Storage usage is at ${getStorageUsagePercentage().toFixed(1)}%. Consider reviewing and cleaning old quarantined items.`
              : `Quarantine system is operating normally. ${quarantineStats.todayQuarantined || 0} emails quarantined today.`
            }
          </Typography>
        </Alert>
      </Box>

      {/* Statistics Cards */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Total Quarantined
                  </Typography>
                  <Typography variant="h4" component="h2" color="primary.main">
                    {formatNumber(quarantineStats.totalQuarantined || 0)}
                  </Typography>
                </Box>
                <ShieldIcon color="primary" sx={{ fontSize: 40 }} />
              </Box>
              <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                All time total
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Today's Quarantine
                  </Typography>
                  <Typography variant="h4" component="h2" color="warning.main">
                    {formatNumber(quarantineStats.todayQuarantined || 0)}
                  </Typography>
                </Box>
                <WarningIcon color="warning" sx={{ fontSize: 40 }} />
              </Box>
              <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                New threats blocked
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Pending Review
                  </Typography>
                  <Typography variant="h4" component="h2" color="info.main">
                    {formatNumber(quarantineStats.pendingReview || 0)}
                  </Typography>
                </Box>
                <InfoIcon color="info" sx={{ fontSize: 40 }} />
              </Box>
              <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                Awaiting manual review
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Storage Used
                  </Typography>
                  <Typography variant="h4" component="h2" color="success.main">
                    {formatFileSize(quarantineStats.storageUsed || 0)}
                  </Typography>
                </Box>
                <Box sx={{ textAlign: 'right' }}>
                  <Typography variant="caption" color="textSecondary">
                    of {formatFileSize(quarantineStats.storageLimit || 10)}
                  </Typography>
                  <Box
                    sx={{
                      width: 40,
                      height: 6,
                      bgcolor: 'grey.300',
                      borderRadius: 3,
                      mt: 0.5,
                      position: 'relative'
                    }}
                  >
                    <Box
                      sx={{
                        width: `${getStorageUsagePercentage()}%`,
                        height: '100%',
                        bgcolor: getStorageUsagePercentage() > 80 ? 'warning.main' : 'success.main',
                        borderRadius: 3
                      }}
                    />
                  </Box>
                </Box>
              </Box>
              <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                {getStorageUsagePercentage().toFixed(1)}% capacity
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Risk Level Breakdown */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Level Distribution
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={4}>
                  <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'error.50' }}>
                    <Typography variant="h5" color="error.main" fontWeight="bold">
                      {formatNumber(quarantineStats.highRisk || 0)}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      High Risk
                    </Typography>
                    <Chip label="Critical" color="error" size="small" sx={{ mt: 1 }} />
                  </Paper>
                </Grid>
                <Grid item xs={4}>
                  <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'warning.50' }}>
                    <Typography variant="h5" color="warning.main" fontWeight="bold">
                      {formatNumber(quarantineStats.mediumRisk || 0)}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Medium Risk
                    </Typography>
                    <Chip label="Moderate" color="warning" size="small" sx={{ mt: 1 }} />
                  </Paper>
                </Grid>
                <Grid item xs={4}>
                  <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'info.50' }}>
                    <Typography variant="h5" color="info.main" fontWeight="bold">
                      {formatNumber(quarantineStats.lowRisk || 0)}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Low Risk
                    </Typography>
                    <Chip label="Suspicious" color="info" size="small" sx={{ mt: 1 }} />
                  </Paper>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Quarantine Settings
              </Typography>
              <Box display="flex" flexDirection="column" gap={2}>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Typography variant="body2">Retention Period</Typography>
                  <Chip 
                    label={`${quarantineStats.retentionDays || 30} days`}
                    size="small"
                    variant="outlined"
                  />
                </Box>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Typography variant="body2">Auto-Delete</Typography>
                  <Chip 
                    label={quarantineStats.autoDeleteEnabled ? "Enabled" : "Disabled"}
                    size="small"
                    color={quarantineStats.autoDeleteEnabled ? "success" : "default"}
                  />
                </Box>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Typography variant="body2">False Positives</Typography>
                  <Chip 
                    label={formatNumber(quarantineStats.falsePositives || 0)}
                    size="small"
                    color="warning"
                    variant="outlined"
                  />
                </Box>
              </Box>
              <Divider sx={{ my: 2 }} />
              <Button
                fullWidth
                variant="outlined"
                startIcon={<SettingsIcon />}
                onClick={() => {/* Navigate to quarantine settings */}}
              >
                Configure Settings
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Quarantine Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Quarantined Emails
          </Typography>
          <QuarantineTable 
            onEmailView={handleEmailView}
            onBulkAction={handleBulkAction}
          />
        </CardContent>
      </Card>

      {/* Email Viewer Dialog */}
      <EmailViewer
        open={emailViewerOpen}
        onClose={() => setEmailViewerOpen(false)}
        emailData={selectedEmail}
      />

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Quarantine;
