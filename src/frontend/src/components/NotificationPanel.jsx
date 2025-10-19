import React, { useState, useEffect } from 'react';
import {
  Drawer,
  Box,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Badge,
  Chip,
  Divider,
  Button,
  Menu,
  MenuItem,
  Alert,
  Collapse,
  Avatar,
  Paper,
  CircularProgress,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  Switch,
  FormControlLabel,
  TextField
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Close as CloseIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Info as InfoIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Email as EmailIcon,
  Shield as ShieldIcon,
  Schedule as ScheduleIcon,
  Person as PersonIcon,
  Computer as ComputerIcon,
  Settings as SettingsIcon,
  FilterList as FilterListIcon,
  MarkAsUnread as MarkAsUnreadIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Refresh as RefreshIcon,
  VolumeOff as VolumeOffIcon,
  VolumeUp as VolumeUpIcon
} from '@mui/icons-material';

const NotificationPanel = ({ 
  open, 
  onClose, 
  anchor = 'right',
  width = 400 
}) => {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [sortBy, setSortBy] = useState('newest');
  const [expandedItems, setExpandedItems] = useState(new Set());
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [filterMenuAnchor, setFilterMenuAnchor] = useState(null);
  const [selectedNotification, setSelectedNotification] = useState(null);
  
  const [settings, setSettings] = useState({
    enableSound: true,
    enableDesktop: true,
    enableEmail: false,
    enableHigh: true,
    enableMedium: true,
    enableLow: false,
    autoMarkRead: 300, // seconds
    maxNotifications: 50
  });

  const notificationTypes = {
    threat_detected: { 
      icon: <WarningIcon />, 
      color: 'error', 
      label: 'Threat Detected',
      priority: 'high'
    },
    quarantine_alert: { 
      icon: <ShieldIcon />, 
      color: 'warning', 
      label: 'Quarantine Alert',
      priority: 'medium'
    },
    system_alert: { 
      icon: <ErrorIcon />, 
      color: 'error', 
      label: 'System Alert',
      priority: 'high'
    },
    security_info: { 
      icon: <SecurityIcon />, 
      color: 'info', 
      label: 'Security Info',
      priority: 'low'
    },
    user_report: { 
      icon: <PersonIcon />, 
      color: 'primary', 
      label: 'User Report',
      priority: 'medium'
    },
    simulation_update: { 
      icon: <CheckCircleIcon />, 
      color: 'success', 
      label: 'Simulation Update',
      priority: 'low'
    },
    compliance_alert: { 
      icon: <InfoIcon />, 
      color: 'warning', 
      label: 'Compliance Alert',
      priority: 'medium'
    }
  };

  const filters = [
    { value: 'all', label: 'All Notifications' },
    { value: 'unread', label: 'Unread Only' },
    { value: 'high', label: 'High Priority' },
    { value: 'medium', label: 'Medium Priority' },
    { value: 'low', label: 'Low Priority' },
    { value: 'today', label: 'Today' },
    { value: 'week', label: 'This Week' }
  ];

  useEffect(() => {
    if (open) {
      fetchNotifications();
      // Set up real-time updates
      const interval = setInterval(fetchNotifications, 30000); // Every 30 seconds
      return () => clearInterval(interval);
    }
  }, [open, filter, sortBy]);

  const fetchNotifications = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      const mockNotifications = [
        {
          id: 1,
          type: 'threat_detected',
          title: 'High-Risk Phishing Email Detected',
          message: 'CEO impersonation attempt targeting finance team detected and quarantined.',
          details: 'A sophisticated phishing email impersonating the CEO was sent to 12 finance department employees. The email requested immediate wire transfer authorization and contained suspicious links.',
          timestamp: new Date(Date.now() - 15 * 60000), // 15 minutes ago
          read: false,
          priority: 'high',
          source: 'AI Detection Engine',
          actions: ['View Email', 'Block Sender', 'Generate Report']
        },
        {
          id: 2,
          type: 'quarantine_alert',
          title: 'Malware Attachment Quarantined',
          message: '3 emails with suspicious attachments have been quarantined.',
          details: 'Multiple emails containing potentially malicious executable files were automatically quarantined. Files are being analyzed by the malware detection system.',
          timestamp: new Date(Date.now() - 45 * 60000), // 45 minutes ago
          read: false,
          priority: 'medium',
          source: 'Quarantine System',
          actions: ['Review Quarantine', 'Download Analysis']
        },
        {
          id: 3,
          type: 'user_report',
          title: 'Security Incident Report Received',
          message: 'John Doe reported a suspicious email in Finance department.',
          details: 'User reported receiving an email with urgent language requesting password reset. Email has been forwarded for analysis.',
          timestamp: new Date(Date.now() - 2 * 60 * 60000), // 2 hours ago
          read: true,
          priority: 'medium',
          source: 'User Report System',
          actions: ['View Report', 'Contact User', 'Investigate']
        },
        {
          id: 4,
          type: 'system_alert',
          title: 'Detection Engine Performance Alert',
          message: 'Email processing rate has decreased by 15% in the last hour.',
          details: 'System monitoring detected performance degradation in the email analysis pipeline. Response times have increased but are within acceptable limits.',
          timestamp: new Date(Date.now() - 3 * 60 * 60000), // 3 hours ago
          read: true,
          priority: 'low',
          source: 'System Monitor',
          actions: ['View Metrics', 'Run Diagnostics']
        },
        {
          id: 5,
          type: 'simulation_update',
          title: 'Phishing Simulation Completed',
          message: 'Q1 Phishing Awareness Campaign finished with 92% success rate.',
          details: 'The quarterly phishing simulation completed successfully. 225 out of 245 employees correctly identified and reported the simulated phishing attempt.',
          timestamp: new Date(Date.now() - 6 * 60 * 60000), // 6 hours ago
          read: false,
          priority: 'low',
          source: 'Training System',
          actions: ['View Results', 'Generate Report', 'Schedule Follow-up']
        },
        {
          id: 6,
          type: 'compliance_alert',
          title: 'Monthly Security Report Due',
          message: 'Compliance report for January is due in 3 days.',
          details: 'The monthly security compliance report needs to be completed and submitted to management by January 31st.',
          timestamp: new Date(Date.now() - 24 * 60 * 60000), // 1 day ago
          read: true,
          priority: 'medium',
          source: 'Compliance System',
          actions: ['Start Report', 'View Requirements']
        }
      ];

      // Apply filters
      let filtered = mockNotifications;
      
      switch (filter) {
        case 'unread':
          filtered = filtered.filter(n => !n.read);
          break;
        case 'high':
          filtered = filtered.filter(n => n.priority === 'high');
          break;
        case 'medium':
          filtered = filtered.filter(n => n.priority === 'medium');
          break;
        case 'low':
          filtered = filtered.filter(n => n.priority === 'low');
          break;
        case 'today':
          const today = new Date().toDateString();
          filtered = filtered.filter(n => n.timestamp.toDateString() === today);
          break;
        case 'week':
          const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60000);
          filtered = filtered.filter(n => n.timestamp > weekAgo);
          break;
      }

      // Sort notifications
      if (sortBy === 'newest') {
        filtered.sort((a, b) => b.timestamp - a.timestamp);
      } else if (sortBy === 'oldest') {
        filtered.sort((a, b) => a.timestamp - b.timestamp);
      } else if (sortBy === 'priority') {
        const priorityOrder = { high: 3, medium: 2, low: 1 };
        filtered.sort((a, b) => priorityOrder[b.priority] - priorityOrder[a.priority]);
      }

      setNotifications(filtered);
    } catch (error) {
      console.error('Error fetching notifications:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleMarkAsRead = (id) => {
    setNotifications(prev => 
      prev.map(notification => 
        notification.id === id 
          ? { ...notification, read: true }
          : notification
      )
    );
  };

  const handleMarkAllAsRead = () => {
    setNotifications(prev => 
      prev.map(notification => ({ ...notification, read: true }))
    );
  };

  const handleDeleteNotification = (id) => {
    setNotifications(prev => prev.filter(notification => notification.id !== id));
  };

  const handleExpandToggle = (id) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedItems(newExpanded);
  };

  const getNotificationIcon = (type) => {
    return notificationTypes[type]?.icon || <InfoIcon />;
  };

  const getNotificationColor = (type) => {
    return notificationTypes[type]?.color || 'default';
  };

  const formatTimestamp = (timestamp) => {
    const now = new Date();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
  };

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <>
      <Drawer
        anchor={anchor}
        open={open}
        onClose={onClose}
        PaperProps={{
          sx: { width: width }
        }}
      >
        <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
          {/* Header */}
          <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
            <Box display="flex" justifyContent="space-between" alignItems="center">
              <Typography variant="h6" component="div">
                <Badge badgeContent={unreadCount} color="error">
                  <NotificationsIcon sx={{ mr: 1 }} />
                </Badge>
                Notifications
              </Typography>
              <IconButton onClick={onClose}>
                <CloseIcon />
              </IconButton>
            </Box>
            
            {/* Controls */}
            <Box display="flex" gap={1} mt={2} alignItems="center">
              <Button
                size="small"
                startIcon={<FilterListIcon />}
                onClick={(e) => setFilterMenuAnchor(e.currentTarget)}
              >
                Filter
              </Button>
              <Button
                size="small"
                startIcon={<RefreshIcon />}
                onClick={fetchNotifications}
              >
                Refresh
              </Button>
              <Button
                size="small"
                onClick={handleMarkAllAsRead}
                disabled={unreadCount === 0}
              >
                Mark All Read
              </Button>
              <IconButton
                size="small"
                onClick={() => setSettingsOpen(true)}
              >
                <SettingsIcon />
              </IconButton>
            </Box>
          </Box>

          {/* Notification List */}
          <Box sx={{ flex: 1, overflow: 'auto' }}>
            {loading ? (
              <Box display="flex" justifyContent="center" alignItems="center" py={4}>
                <CircularProgress />
              </Box>
            ) : notifications.length === 0 ? (
              <Box textAlign="center" py={4} px={2}>
                <NotificationsIcon sx={{ fontSize: 48, color: 'grey.400', mb: 2 }} />
                <Typography variant="body1" color="textSecondary">
                  No notifications found
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  {filter !== 'all' ? 'Try changing your filter settings' : 'You\'re all caught up!'}
                </Typography>
              </Box>
            ) : (
              <List>
                {notifications.map((notification, index) => (
                  <React.Fragment key={notification.id}>
                    <ListItem
                      sx={{
                        bgcolor: notification.read ? 'transparent' : 'action.hover',
                        cursor: 'pointer',
                        flexDirection: 'column',
                        alignItems: 'stretch',
                        px: 2,
                        py: 1
                      }}
                      onClick={() => !notification.read && handleMarkAsRead(notification.id)}
                    >
                      <Box display="flex" alignItems="flex-start" width="100%">
                        <ListItemIcon sx={{ minWidth: 40, mt: 0.5 }}>
                          <Avatar 
                            sx={{ 
                              width: 32, 
                              height: 32, 
                              bgcolor: `${getNotificationColor(notification.type)}.main` 
                            }}
                          >
                            {getNotificationIcon(notification.type)}
                          </Avatar>
                        </ListItemIcon>
                        
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Box display="flex" justifyContent="space-between" alignItems="start">
                            <Typography 
                              variant="subtitle2" 
                              sx={{ 
                                fontWeight: notification.read ? 'normal' : 'bold',
                                mb: 0.5 
                              }}
                            >
                              {notification.title}
                            </Typography>
                            <Box display="flex" alignItems="center" gap={0.5}>
                              <Typography variant="caption" color="textSecondary">
                                {formatTimestamp(notification.timestamp)}
                              </Typography>
                              {!notification.read && (
                                <Box
                                  sx={{
                                    width: 8,
                                    height: 8,
                                    borderRadius: '50%',
                                    bgcolor: 'primary.main'
                                  }}
                                />
                              )}
                            </Box>
                          </Box>
                          
                          <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
                            {notification.message}
                          </Typography>
                          
                          <Box display="flex" justifyContent="space-between" alignItems="center">
                            <Box display="flex" gap={1}>
                              <Chip
                                label={notification.priority}
                                size="small"
                                color={
                                  notification.priority === 'high' ? 'error' :
                                  notification.priority === 'medium' ? 'warning' : 'default'
                                }
                                variant="outlined"
                              />
                              <Chip
                                label={notification.source}
                                size="small"
                                variant="outlined"
                              />
                            </Box>
                            
                            <Box>
                              <IconButton
                                size="small"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleExpandToggle(notification.id);
                                }}
                              >
                                {expandedItems.has(notification.id) ? (
                                  <ExpandLessIcon />
                                ) : (
                                  <ExpandMoreIcon />
                                )}
                              </IconButton>
                              <IconButton
                                size="small"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleDeleteNotification(notification.id);
                                }}
                              >
                                <DeleteIcon />
                              </IconButton>
                            </Box>
                          </Box>
                        </Box>
                      </Box>
                      
                      {/* Expanded Details */}
                      <Collapse in={expandedItems.has(notification.id)}>
                        <Box sx={{ mt: 2, pl: 5 }}>
                          <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                            <Typography variant="body2" paragraph>
                              {notification.details}
                            </Typography>
                            
                            {notification.actions && notification.actions.length > 0 && (
                              <Box display="flex" gap={1} flexWrap="wrap">
                                {notification.actions.map((action, actionIndex) => (
                                  <Button
                                    key={actionIndex}
                                    size="small"
                                    variant="outlined"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      // Handle action click
                                      console.log(`Action: ${action} for notification ${notification.id}`);
                                    }}
                                  >
                                    {action}
                                  </Button>
                                ))}
                              </Box>
                            )}
                          </Paper>
                        </Box>
                      </Collapse>
                    </ListItem>
                    
                    {index < notifications.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            )}
          </Box>
        </Box>
      </Drawer>

      {/* Filter Menu */}
      <Menu
        anchorEl={filterMenuAnchor}
        open={Boolean(filterMenuAnchor)}
        onClose={() => setFilterMenuAnchor(null)}
      >
        {filters.map((filterOption) => (
          <MenuItem
            key={filterOption.value}
            onClick={() => {
              setFilter(filterOption.value);
              setFilterMenuAnchor(null);
            }}
            selected={filter === filterOption.value}
          >
            {filterOption.label}
          </MenuItem>
        ))}
      </Menu>

      {/* Settings Dialog */}
      <Dialog
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Notification Settings</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <Typography variant="subtitle2" gutterBottom>
              Notification Preferences
            </Typography>
            
            <FormControlLabel
              control={
                <Switch
                  checked={settings.enableSound}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableSound: e.target.checked }))}
                />
              }
              label="Sound notifications"
            />
            
            <FormControlLabel
              control={
                <Switch
                  checked={settings.enableDesktop}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableDesktop: e.target.checked }))}
                />
              }
              label="Desktop notifications"
            />
            
            <FormControlLabel
              control={
                <Switch
                  checked={settings.enableEmail}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableEmail: e.target.checked }))}
                />
              }
              label="Email notifications"
            />
            
            <Divider sx={{ my: 2 }} />
            
            <Typography variant="subtitle2" gutterBottom>
              Priority Levels
            </Typography>
            
            <FormControlLabel
              control={
                <Switch
                  checked={settings.enableHigh}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableHigh: e.target.checked }))}
                />
              }
              label="High priority alerts"
            />
            
            <FormControlLabel
              control={
                <Switch
                  checked={settings.enableMedium}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableMedium: e.target.checked }))}
                />
              }
              label="Medium priority alerts"
            />
            
            <FormControlLabel
              control={
                <Switch
                  checked={settings.enableLow}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableLow: e.target.checked }))}
                />
              }
              label="Low priority alerts"
            />
            
            <Divider sx={{ my: 2 }} />
            
            <TextField
              fullWidth
              type="number"
              label="Auto-mark as read (seconds)"
              value={settings.autoMarkRead}
              onChange={(e) => setSettings(prev => ({ ...prev, autoMarkRead: parseInt(e.target.value) }))}
              margin="normal"
              inputProps={{ min: 0, max: 3600 }}
              helperText="Set to 0 to disable auto-marking"
            />
            
            <TextField
              fullWidth
              type="number"
              label="Maximum notifications to keep"
              value={settings.maxNotifications}
              onChange={(e) => setSettings(prev => ({ ...prev, maxNotifications: parseInt(e.target.value) }))}
              margin="normal"
              inputProps={{ min: 10, max: 1000 }}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSettingsOpen(false)}>
            Cancel
          </Button>
          <Button variant="contained" onClick={() => setSettingsOpen(false)}>
            Save Settings
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default NotificationPanel;
