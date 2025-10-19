import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Switch,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  FormControlLabel,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Chip,
  Alert,
  Paper,
  Tabs,
  Tab,
  Slider,
  RadioGroup,
  Radio,
  FormLabel,
  Checkbox,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Snackbar
} from '@mui/material';
import {
  Settings as SettingsIcon,
  Security as SecurityIcon,
  Notifications as NotificationsIcon,
  Storage as StorageIcon,
  Cloud as CloudIcon,
  People as PeopleIcon,
  Email as EmailIcon,
  Shield as ShieldIcon,
  ExpandMore as ExpandMoreIcon,
  Edit as EditIcon,
  Save as SaveIcon,
  RestoreFromTrash as ResetIcon,
  Backup as BackupIcon,
  Update as UpdateIcon,
  Warning as WarningIcon,
  Info as InfoIcon
} from '@mui/icons-material';

const Settings = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [settings, setSettings] = useState({});
  const [unsavedChanges, setUnsavedChanges] = useState(false);
  const [loading, setLoading] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [confirmDialog, setConfirmDialog] = useState({ open: false, title: '', message: '', action: null });

  const [generalSettings, setGeneralSettings] = useState({
    organizationName: 'PhishGuard Enterprise',
    timeZone: 'UTC-5',
    language: 'en',
    dateFormat: 'MM/DD/YYYY',
    sessionTimeout: 30,
    autoSave: true,
    darkMode: false,
    enableAnalytics: true
  });

  const [securitySettings, setSecuritySettings] = useState({
    mfaRequired: true,
    passwordMinLength: 12,
    passwordComplexity: 'high',
    sessionExpiry: 480,
    ipWhitelist: [],
    apiRateLimit: 1000,
    encryptionLevel: 'AES-256',
    auditLogging: true,
    suspiciousActivityAlerts: true,
    autoBlockThreats: true
  });

  const [notificationSettings, setNotificationSettings] = useState({
    emailNotifications: true,
    smsNotifications: false,
    slackIntegration: true,
    webhookUrl: '',
    threatAlerts: true,
    systemAlerts: true,
    maintenanceAlerts: true,
    reportAlerts: true,
    digestFrequency: 'daily',
    alertThreshold: 'medium'
  });

  const [integrationSettings, setIntegrationSettings] = useState({
    exchangeEnabled: false,
    gmailEnabled: true,
    office365Enabled: true,
    slackEnabled: true,
    teamsEnabled: false,
    siemEnabled: true,
    soarEnabled: false,
    apiKeys: {},
    webhooks: []
  });

  const timeZones = [
    'UTC-12', 'UTC-11', 'UTC-10', 'UTC-9', 'UTC-8', 'UTC-7', 'UTC-6',
    'UTC-5', 'UTC-4', 'UTC-3', 'UTC-2', 'UTC-1', 'UTC+0', 'UTC+1',
    'UTC+2', 'UTC+3', 'UTC+4', 'UTC+5', 'UTC+6', 'UTC+7', 'UTC+8',
    'UTC+9', 'UTC+10', 'UTC+11', 'UTC+12'
  ];

  const languages = [
    { value: 'en', label: 'English' },
    { value: 'es', label: 'Spanish' },
    { value: 'fr', label: 'French' },
    { value: 'de', label: 'German' },
    { value: 'it', label: 'Italian' },
    { value: 'pt', label: 'Portuguese' }
  ];

  const dateFormats = [
    'MM/DD/YYYY', 'DD/MM/YYYY', 'YYYY-MM-DD', 'DD-MM-YYYY'
  ];

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Settings would be fetched from API
      showSnackbar('Settings loaded successfully');
    } catch (error) {
      console.error('Error fetching settings:', error);
      showSnackbar('Error loading settings', 'error');
    } finally {
      setLoading(false);
    }
  };

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const showConfirmDialog = (title, message, action) => {
    setConfirmDialog({ open: true, title, message, action });
  };

  const handleSaveSettings = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setUnsavedChanges(false);
      showSnackbar('Settings saved successfully');
    } catch (error) {
      showSnackbar('Error saving settings', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleResetSettings = () => {
    showConfirmDialog(
      'Reset Settings',
      'Are you sure you want to reset all settings to their default values? This action cannot be undone.',
      () => {
        // Reset all settings to defaults
        setUnsavedChanges(true);
        showSnackbar('Settings reset to defaults');
      }
    );
  };

  const handleExportSettings = () => {
    const settingsData = {
      general: generalSettings,
      security: securitySettings,
      notifications: notificationSettings,
      integrations: integrationSettings
    };
    
    const dataStr = JSON.stringify(settingsData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'phishguard_settings.json';
    link.click();
    
    showSnackbar('Settings exported successfully');
  };

  const updateGeneralSetting = (key, value) => {
    setGeneralSettings(prev => ({ ...prev, [key]: value }));
    setUnsavedChanges(true);
  };

  const updateSecuritySetting = (key, value) => {
    setSecuritySettings(prev => ({ ...prev, [key]: value }));
    setUnsavedChanges(true);
  };

  const updateNotificationSetting = (key, value) => {
    setNotificationSettings(prev => ({ ...prev, [key]: value }));
    setUnsavedChanges(true);
  };

  const updateIntegrationSetting = (key, value) => {
    setIntegrationSettings(prev => ({ ...prev, [key]: value }));
    setUnsavedChanges(true);
  };

  const renderGeneralTab = () => (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Organization Settings
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Organization Name"
                  value={generalSettings.organizationName}
                  onChange={(e) => updateGeneralSetting('organizationName', e.target.value)}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Time Zone</InputLabel>
                  <Select
                    value={generalSettings.timeZone}
                    label="Time Zone"
                    onChange={(e) => updateGeneralSetting('timeZone', e.target.value)}
                  >
                    {timeZones.map((tz) => (
                      <MenuItem key={tz} value={tz}>{tz}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Language</InputLabel>
                  <Select
                    value={generalSettings.language}
                    label="Language"
                    onChange={(e) => updateGeneralSetting('language', e.target.value)}
                  >
                    {languages.map((lang) => (
                      <MenuItem key={lang.value} value={lang.value}>
                        {lang.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Date Format</InputLabel>
                  <Select
                    value={generalSettings.dateFormat}
                    label="Date Format"
                    onChange={(e) => updateGeneralSetting('dateFormat', e.target.value)}
                  >
                    {dateFormats.map((format) => (
                      <MenuItem key={format} value={format}>{format}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              User Interface
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={generalSettings.darkMode}
                      onChange={(e) => updateGeneralSetting('darkMode', e.target.checked)}
                    />
                  }
                  label="Dark Mode"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={generalSettings.autoSave}
                      onChange={(e) => updateGeneralSetting('autoSave', e.target.checked)}
                    />
                  }
                  label="Auto Save"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={generalSettings.enableAnalytics}
                      onChange={(e) => updateGeneralSetting('enableAnalytics', e.target.checked)}
                    />
                  }
                  label="Enable Analytics"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography gutterBottom>
                  Session Timeout (minutes): {generalSettings.sessionTimeout}
                </Typography>
                <Slider
                  value={generalSettings.sessionTimeout}
                  onChange={(e, value) => updateGeneralSetting('sessionTimeout', value)}
                  min={5}
                  max={120}
                  marks={[
                    { value: 5, label: '5m' },
                    { value: 30, label: '30m' },
                    { value: 60, label: '1h' },
                    { value: 120, label: '2h' }
                  ]}
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderSecurityTab = () => (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Alert severity="warning" sx={{ mb: 3 }}>
          Changes to security settings will affect all users. Please ensure you understand the implications before making changes.
        </Alert>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Authentication & Access
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={securitySettings.mfaRequired}
                      onChange={(e) => updateSecuritySetting('mfaRequired', e.target.checked)}
                    />
                  }
                  label="Require Multi-Factor Authentication"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Minimum Password Length"
                  value={securitySettings.passwordMinLength}
                  onChange={(e) => updateSecuritySetting('passwordMinLength', parseInt(e.target.value))}
                  inputProps={{ min: 8, max: 32 }}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <FormLabel>Password Complexity</FormLabel>
                  <RadioGroup
                    value={securitySettings.passwordComplexity}
                    onChange={(e) => updateSecuritySetting('passwordComplexity', e.target.value)}
                  >
                    <FormControlLabel value="low" control={<Radio />} label="Low (Letters only)" />
                    <FormControlLabel value="medium" control={<Radio />} label="Medium (Letters + Numbers)" />
                    <FormControlLabel value="high" control={<Radio />} label="High (Letters + Numbers + Symbols)" />
                  </RadioGroup>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Session Expiry (minutes)"
                  value={securitySettings.sessionExpiry}
                  onChange={(e) => updateSecuritySetting('sessionExpiry', parseInt(e.target.value))}
                  inputProps={{ min: 15, max: 1440 }}
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Threat Protection
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={securitySettings.autoBlockThreats}
                      onChange={(e) => updateSecuritySetting('autoBlockThreats', e.target.checked)}
                    />
                  }
                  label="Auto-block Detected Threats"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={securitySettings.suspiciousActivityAlerts}
                      onChange={(e) => updateSecuritySetting('suspiciousActivityAlerts', e.target.checked)}
                    />
                  }
                  label="Suspicious Activity Alerts"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={securitySettings.auditLogging}
                      onChange={(e) => updateSecuritySetting('auditLogging', e.target.checked)}
                    />
                  }
                  label="Enable Audit Logging"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="API Rate Limit (requests/hour)"
                  value={securitySettings.apiRateLimit}
                  onChange={(e) => updateSecuritySetting('apiRateLimit', parseInt(e.target.value))}
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Encryption & Data Protection
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Encryption Level</InputLabel>
                  <Select
                    value={securitySettings.encryptionLevel}
                    label="Encryption Level"
                    onChange={(e) => updateSecuritySetting('encryptionLevel', e.target.value)}
                  >
                    <MenuItem value="AES-128">AES-128</MenuItem>
                    <MenuItem value="AES-256">AES-256</MenuItem>
                    <MenuItem value="RSA-2048">RSA-2048</MenuItem>
                    <MenuItem value="RSA-4096">RSA-4096</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderNotificationsTab = () => (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Notification Channels
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={notificationSettings.emailNotifications}
                      onChange={(e) => updateNotificationSetting('emailNotifications', e.target.checked)}
                    />
                  }
                  label="Email Notifications"
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={notificationSettings.smsNotifications}
                      onChange={(e) => updateNotificationSetting('smsNotifications', e.target.checked)}
                    />
                  }
                  label="SMS Notifications"
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={notificationSettings.slackIntegration}
                      onChange={(e) => updateNotificationSetting('slackIntegration', e.target.checked)}
                    />
                  }
                  label="Slack Integration"
                />
              </Grid>
            </Grid>
            
            {notificationSettings.slackIntegration && (
              <TextField
                fullWidth
                label="Webhook URL"
                value={notificationSettings.webhookUrl}
                onChange={(e) => updateNotificationSetting('webhookUrl', e.target.value)}
                placeholder="https://hooks.slack.com/services/..."
                sx={{ mt: 2 }}
              />
            )}
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Alert Types
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={3}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={notificationSettings.threatAlerts}
                      onChange={(e) => updateNotificationSetting('threatAlerts', e.target.checked)}
                    />
                  }
                  label="Threat Alerts"
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={notificationSettings.systemAlerts}
                      onChange={(e) => updateNotificationSetting('systemAlerts', e.target.checked)}
                    />
                  }
                  label="System Alerts"
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={notificationSettings.maintenanceAlerts}
                      onChange={(e) => updateNotificationSetting('maintenanceAlerts', e.target.checked)}
                    />
                  }
                  label="Maintenance Alerts"
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={notificationSettings.reportAlerts}
                      onChange={(e) => updateNotificationSetting('reportAlerts', e.target.checked)}
                    />
                  }
                  label="Report Alerts"
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Notification Preferences
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Digest Frequency</InputLabel>
                  <Select
                    value={notificationSettings.digestFrequency}
                    label="Digest Frequency"
                    onChange={(e) => updateNotificationSetting('digestFrequency', e.target.value)}
                  >
                    <MenuItem value="realtime">Real-time</MenuItem>
                    <MenuItem value="hourly">Hourly</MenuItem>
                    <MenuItem value="daily">Daily</MenuItem>
                    <MenuItem value="weekly">Weekly</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Alert Threshold</InputLabel>
                  <Select
                    value={notificationSettings.alertThreshold}
                    label="Alert Threshold"
                    onChange={(e) => updateNotificationSetting('alertThreshold', e.target.value)}
                  >
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="critical">Critical Only</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderIntegrationsTab = () => (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Email Providers
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={integrationSettings.gmailEnabled}
                      onChange={(e) => updateIntegrationSetting('gmailEnabled', e.target.checked)}
                    />
                  }
                  label="Gmail Integration"
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={integrationSettings.office365Enabled}
                      onChange={(e) => updateIntegrationSetting('office365Enabled', e.target.checked)}
                    />
                  }
                  label="Office 365"
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={integrationSettings.exchangeEnabled}
                      onChange={(e) => updateIntegrationSetting('exchangeEnabled', e.target.checked)}
                    />
                  }
                  label="Exchange Server"
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Collaboration Tools
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={integrationSettings.slackEnabled}
                      onChange={(e) => updateIntegrationSetting('slackEnabled', e.target.checked)}
                    />
                  }
                  label="Slack"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={integrationSettings.teamsEnabled}
                      onChange={(e) => updateIntegrationSetting('teamsEnabled', e.target.checked)}
                    />
                  }
                  label="Microsoft Teams"
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Security Tools
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={integrationSettings.siemEnabled}
                      onChange={(e) => updateIntegrationSetting('siemEnabled', e.target.checked)}
                    />
                  }
                  label="SIEM Integration"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={integrationSettings.soarEnabled}
                      onChange={(e) => updateIntegrationSetting('soarEnabled', e.target.checked)}
                    />
                  }
                  label="SOAR Platform"
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box mb={4}>
        <Typography variant="h4" component="h1" fontWeight="bold" gutterBottom>
          System Settings
        </Typography>
        <Typography variant="body1" color="textSecondary">
          Configure and customize your PhishGuard security platform
        </Typography>
        
        {unsavedChanges && (
          <Alert severity="info" sx={{ mt: 2 }}>
            You have unsaved changes. Don't forget to save your settings.
          </Alert>
        )}
      </Box>

      {/* Action Buttons */}
      <Box display="flex" gap={2} mb={3}>
        <Button
          variant="contained"
          startIcon={<SaveIcon />}
          onClick={handleSaveSettings}
          disabled={!unsavedChanges || loading}
        >
          Save Changes
        </Button>
        <Button
          variant="outlined"
          startIcon={<ResetIcon />}
          onClick={handleResetSettings}
        >
          Reset to Defaults
        </Button>
        <Button
          variant="outlined"
          startIcon={<BackupIcon />}
          onClick={handleExportSettings}
        >
          Export Settings
        </Button>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
          <Tab icon={<SettingsIcon />} label="General" />
          <Tab icon={<SecurityIcon />} label="Security" />
          <Tab icon={<NotificationsIcon />} label="Notifications" />
          <Tab icon={<CloudIcon />} label="Integrations" />
        </Tabs>
      </Paper>

      {/* Tab Content */}
      <Box>
        {activeTab === 0 && renderGeneralTab()}
        {activeTab === 1 && renderSecurityTab()}
        {activeTab === 2 && renderNotificationsTab()}
        {activeTab === 3 && renderIntegrationsTab()}
      </Box>

      {/* Confirmation Dialog */}
      <Dialog
        open={confirmDialog.open}
        onClose={() => setConfirmDialog({...confirmDialog, open: false})}
      >
        <DialogTitle>{confirmDialog.title}</DialogTitle>
        <DialogContent>
          <Typography>{confirmDialog.message}</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmDialog({...confirmDialog, open: false})}>
            Cancel
          </Button>
          <Button
            onClick={() => {
              confirmDialog.action?.();
              setConfirmDialog({...confirmDialog, open: false});
            }}
            color="error"
            variant="contained"
          >
            Confirm
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({...snackbar, open: false})}
      >
        <Alert
          onClose={() => setSnackbar({...snackbar, open: false})}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Settings;
