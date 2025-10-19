import React, { useState, useRef } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
  Tooltip,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Snackbar,
  FormControlLabel,
  Checkbox,
  RadioGroup,
  Radio,
  Rating,
  Divider,
  Avatar,
  Grid
} from '@mui/material';
import {
  Send as SendIcon,
  AttachFile as AttachFileIcon,
  Delete as DeleteIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Email as EmailIcon,
  Link as LinkIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Upload as UploadIcon,
  Visibility as VisibilityIcon,
  Phone as PhoneIcon,
  Person as PersonIcon,
  Schedule as ScheduleIcon,
  Flag as FlagIcon
} from '@mui/icons-material';

const UserReportForm = ({ 
  onSubmit, 
  onClose, 
  initialData = null,
  embedded = false 
}) => {
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'info' });
  const fileInputRef = useRef(null);

  const [formData, setFormData] = useState({
    reportType: 'suspicious_email',
    severity: 'medium',
    title: '',
    description: '',
    emailDetails: {
      sender: '',
      subject: '',
      receivedDate: '',
      suspiciousLinks: '',
      attachments: []
    },
    evidence: {
      screenshots: [],
      files: [],
      urls: []
    },
    userInfo: {
      name: '',
      email: '',
      department: '',
      phone: '',
      allowContact: true
    },
    additionalInfo: {
      similarIncidents: false,
      actionsTaken: '',
      urgency: 3,
      confidence: 3
    }
  });

  const reportTypes = [
    { value: 'suspicious_email', label: 'Suspicious Email', icon: <EmailIcon />, color: 'warning' },
    { value: 'phishing_attempt', label: 'Phishing Attempt', icon: <SecurityIcon />, color: 'error' },
    { value: 'malware_detection', label: 'Malware Detection', icon: <WarningIcon />, color: 'error' },
    { value: 'data_breach', label: 'Potential Data Breach', icon: <ErrorIcon />, color: 'error' },
    { value: 'social_engineering', label: 'Social Engineering', icon: <PersonIcon />, color: 'warning' },
    { value: 'suspicious_website', label: 'Suspicious Website', icon: <LinkIcon />, color: 'warning' },
    { value: 'other', label: 'Other Security Concern', icon: <FlagIcon />, color: 'info' }
  ];

  const severityLevels = [
    { value: 'low', label: 'Low', color: 'info', description: 'Minor concern, no immediate threat' },
    { value: 'medium', label: 'Medium', color: 'warning', description: 'Moderate risk, requires attention' },
    { value: 'high', label: 'High', color: 'error', description: 'Significant threat, urgent action needed' },
    { value: 'critical', label: 'Critical', color: 'error', description: 'Immediate security risk' }
  ];

  const departments = [
    'Finance', 'Human Resources', 'Information Technology', 'Sales', 'Marketing', 
    'Operations', 'Legal', 'Executive', 'Customer Service', 'Research & Development'
  ];

  const steps = [
    'Report Type & Details',
    'Email Information',
    'Evidence & Files',
    'Contact Information',
    'Review & Submit'
  ];

  const handleNext = () => {
    setActiveStep((prevActiveStep) => prevActiveStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevActiveStep) => prevActiveStep - 1);
  };

  const handleInputChange = (section, field, value) => {
    setFormData(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [field]: value
      }
    }));
  };

  const handleFileUpload = (event, type) => {
    const files = Array.from(event.target.files);
    const maxSize = 10 * 1024 * 1024; // 10MB

    const validFiles = files.filter(file => {
      if (file.size > maxSize) {
        setSnackbar({
          open: true,
          message: `File ${file.name} is too large. Maximum size is 10MB.`,
          severity: 'error'
        });
        return false;
      }
      return true;
    });

    if (type === 'screenshots') {
      const imageFiles = validFiles.filter(file => file.type.startsWith('image/'));
      setFormData(prev => ({
        ...prev,
        evidence: {
          ...prev.evidence,
          screenshots: [...prev.evidence.screenshots, ...imageFiles]
        }
      }));
    } else if (type === 'attachments') {
      setFormData(prev => ({
        ...prev,
        emailDetails: {
          ...prev.emailDetails,
          attachments: [...prev.emailDetails.attachments, ...validFiles]
        }
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        evidence: {
          ...prev.evidence,
          files: [...prev.evidence.files, ...validFiles]
        }
      }));
    }
  };

  const removeFile = (type, index) => {
    if (type === 'screenshots') {
      setFormData(prev => ({
        ...prev,
        evidence: {
          ...prev.evidence,
          screenshots: prev.evidence.screenshots.filter((_, i) => i !== index)
        }
      }));
    } else if (type === 'attachments') {
      setFormData(prev => ({
        ...prev,
        emailDetails: {
          ...prev.emailDetails,
          attachments: prev.emailDetails.attachments.filter((_, i) => i !== index)
        }
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        evidence: {
          ...prev.evidence,
          files: prev.evidence.files.filter((_, i) => i !== index)
        }
      }));
    }
  };

  const handleSubmit = async () => {
    try {
      setLoading(true);
      
      // Simulate API submission
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const reportData = {
        ...formData,
        id: Date.now(),
        submissionDate: new Date(),
        status: 'submitted',
        ticketNumber: `SEC-${Date.now().toString().slice(-6)}`
      };

      if (onSubmit) {
        onSubmit(reportData);
      }

      setSubmitSuccess(true);
      setSnackbar({
        open: true,
        message: `Security report submitted successfully! Ticket #${reportData.ticketNumber}`,
        severity: 'success'
      });

    } catch (error) {
      setSnackbar({
        open: true,
        message: 'Failed to submit report. Please try again.',
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const renderStepContent = (step) => {
    switch (step) {
      case 0:
        return (
          <Box>
            <FormControl fullWidth margin="normal">
              <InputLabel>Report Type</InputLabel>
              <Select
                value={formData.reportType}
                label="Report Type"
                onChange={(e) => setFormData(prev => ({ ...prev, reportType: e.target.value }))}
              >
                {reportTypes.map((type) => (
                  <MenuItem key={type.value} value={type.value}>
                    <Box display="flex" alignItems="center" gap={1}>
                      {type.icon}
                      {type.label}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl fullWidth margin="normal">
              <InputLabel>Severity Level</InputLabel>
              <Select
                value={formData.severity}
                label="Severity Level"
                onChange={(e) => setFormData(prev => ({ ...prev, severity: e.target.value }))}
              >
                {severityLevels.map((level) => (
                  <MenuItem key={level.value} value={level.value}>
                    <Box display="flex" alignItems="center" justifyContent="space-between" width="100%">
                      <Chip label={level.label} color={level.color} size="small" />
                      <Typography variant="body2" color="textSecondary">
                        {level.description}
                      </Typography>
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <TextField
              fullWidth
              label="Report Title"
              value={formData.title}
              onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
              margin="normal"
              required
              placeholder="Brief summary of the security concern"
            />

            <TextField
              fullWidth
              multiline
              rows={4}
              label="Description"
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              margin="normal"
              required
              placeholder="Provide detailed information about what you observed..."
            />
          </Box>
        );

      case 1:
        return (
          <Box>
            <Alert severity="info" sx={{ mb: 2 }}>
              If reporting a suspicious email, please provide as much detail as possible.
            </Alert>
            
            <TextField
              fullWidth
              label="Sender Email Address"
              value={formData.emailDetails.sender}
              onChange={(e) => handleInputChange('emailDetails', 'sender', e.target.value)}
              margin="normal"
              placeholder="suspicious@example.com"
            />

            <TextField
              fullWidth
              label="Email Subject"
              value={formData.emailDetails.subject}
              onChange={(e) => handleInputChange('emailDetails', 'subject', e.target.value)}
              margin="normal"
              placeholder="The subject line of the suspicious email"
            />

            <TextField
              fullWidth
              type="datetime-local"
              label="Date & Time Received"
              value={formData.emailDetails.receivedDate}
              onChange={(e) => handleInputChange('emailDetails', 'receivedDate', e.target.value)}
              margin="normal"
              InputLabelProps={{ shrink: true }}
            />

            <TextField
              fullWidth
              multiline
              rows={3}
              label="Suspicious Links (if any)"
              value={formData.emailDetails.suspiciousLinks}
              onChange={(e) => handleInputChange('emailDetails', 'suspiciousLinks', e.target.value)}
              margin="normal"
              placeholder="List any suspicious URLs found in the email..."
            />

            <Box mt={2}>
              <Typography variant="subtitle2" gutterBottom>
                Email Attachments
              </Typography>
              <input
                type="file"
                multiple
                ref={fileInputRef}
                style={{ display: 'none' }}
                onChange={(e) => handleFileUpload(e, 'attachments')}
              />
              <Button
                variant="outlined"
                startIcon={<AttachFileIcon />}
                onClick={() => fileInputRef.current?.click()}
              >
                Add Attachments
              </Button>
              {formData.emailDetails.attachments.length > 0 && (
                <List dense>
                  {formData.emailDetails.attachments.map((file, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <AttachFileIcon />
                      </ListItemIcon>
                      <ListItemText
                        primary={file.name}
                        secondary={`${(file.size / 1024 / 1024).toFixed(2)} MB`}
                      />
                      <IconButton onClick={() => removeFile('attachments', index)}>
                        <DeleteIcon />
                      </IconButton>
                    </ListItem>
                  ))}
                </List>
              )}
            </Box>
          </Box>
        );

      case 2:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Supporting Evidence
            </Typography>
            
            <Box mb={3}>
              <Typography variant="subtitle2" gutterBottom>
                Screenshots
              </Typography>
              <Typography variant="body2" color="textSecondary" mb={1}>
                Upload screenshots that show the security concern
              </Typography>
              <input
                type="file"
                multiple
                accept="image/*"
                style={{ display: 'none' }}
                id="screenshots-input"
                onChange={(e) => handleFileUpload(e, 'screenshots')}
              />
              <label htmlFor="screenshots-input">
                <Button
                  variant="outlined"
                  component="span"
                  startIcon={<UploadIcon />}
                >
                  Upload Screenshots
                </Button>
              </label>
              {formData.evidence.screenshots.length > 0 && (
                <Grid container spacing={2} mt={1}>
                  {formData.evidence.screenshots.map((file, index) => (
                    <Grid item xs={6} sm={4} md={3} key={index}>
                      <Paper sx={{ p: 1, position: 'relative' }}>
                        <img
                          src={URL.createObjectURL(file)}
                          alt={`Screenshot ${index + 1}`}
                          style={{ 
                            width: '100%', 
                            height: '80px', 
                            objectFit: 'cover',
                            borderRadius: '4px'
                          }}
                        />
                        <IconButton
                          size="small"
                          sx={{ position: 'absolute', top: 0, right: 0 }}
                          onClick={() => removeFile('screenshots', index)}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                        <Typography variant="caption" noWrap>
                          {file.name}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              )}
            </Box>

            <Box mb={3}>
              <Typography variant="subtitle2" gutterBottom>
                Additional Files
              </Typography>
              <input
                type="file"
                multiple
                style={{ display: 'none' }}
                id="files-input"
                onChange={(e) => handleFileUpload(e, 'files')}
              />
              <label htmlFor="files-input">
                <Button
                  variant="outlined"
                  component="span"
                  startIcon={<AttachFileIcon />}
                >
                  Upload Files
                </Button>
              </label>
              {formData.evidence.files.length > 0 && (
                <List dense>
                  {formData.evidence.files.map((file, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <AttachFileIcon />
                      </ListItemIcon>
                      <ListItemText
                        primary={file.name}
                        secondary={`${(file.size / 1024 / 1024).toFixed(2)} MB`}
                      />
                      <IconButton onClick={() => removeFile('files', index)}>
                        <DeleteIcon />
                      </IconButton>
                    </ListItem>
                  ))}
                </List>
              )}
            </Box>

            <TextField
              fullWidth
              multiline
              rows={2}
              label="Related URLs"
              value={formData.evidence.urls.join('\n')}
              onChange={(e) => setFormData(prev => ({
                ...prev,
                evidence: {
                  ...prev.evidence,
                  urls: e.target.value.split('\n').filter(url => url.trim())
                }
              }))}
              margin="normal"
              placeholder="Enter any related URLs (one per line)..."
            />
          </Box>
        );

      case 3:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Contact Information
            </Typography>
            
            <TextField
              fullWidth
              label="Your Name"
              value={formData.userInfo.name}
              onChange={(e) => handleInputChange('userInfo', 'name', e.target.value)}
              margin="normal"
              required
            />

            <TextField
              fullWidth
              label="Email Address"
              type="email"
              value={formData.userInfo.email}
              onChange={(e) => handleInputChange('userInfo', 'email', e.target.value)}
              margin="normal"
              required
            />

            <FormControl fullWidth margin="normal">
              <InputLabel>Department</InputLabel>
              <Select
                value={formData.userInfo.department}
                label="Department"
                onChange={(e) => handleInputChange('userInfo', 'department', e.target.value)}
              >
                {departments.map((dept) => (
                  <MenuItem key={dept} value={dept}>
                    {dept}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <TextField
              fullWidth
              label="Phone Number"
              value={formData.userInfo.phone}
              onChange={(e) => handleInputChange('userInfo', 'phone', e.target.value)}
              margin="normal"
              placeholder="Optional"
            />

            <FormControlLabel
              control={
                <Checkbox
                  checked={formData.userInfo.allowContact}
                  onChange={(e) => handleInputChange('userInfo', 'allowContact', e.target.checked)}
                />
              }
              label="Allow security team to contact me for follow-up questions"
            />

            <Divider sx={{ my: 2 }} />

            <Typography variant="subtitle2" gutterBottom>
              Additional Assessment
            </Typography>

            <Box mb={2}>
              <Typography component="legend">How urgent is this issue?</Typography>
              <Rating
                value={formData.additionalInfo.urgency}
                onChange={(event, newValue) => handleInputChange('additionalInfo', 'urgency', newValue)}
                max={5}
              />
            </Box>

            <Box mb={2}>
              <Typography component="legend">How confident are you that this is a security threat?</Typography>
              <Rating
                value={formData.additionalInfo.confidence}
                onChange={(event, newValue) => handleInputChange('additionalInfo', 'confidence', newValue)}
                max={5}
              />
            </Box>

            <FormControlLabel
              control={
                <Checkbox
                  checked={formData.additionalInfo.similarIncidents}
                  onChange={(e) => handleInputChange('additionalInfo', 'similarIncidents', e.target.checked)}
                />
              }
              label="I have seen similar incidents before"
            />

            <TextField
              fullWidth
              multiline
              rows={3}
              label="Actions Already Taken"
              value={formData.additionalInfo.actionsTaken}
              onChange={(e) => handleInputChange('additionalInfo', 'actionsTaken', e.target.value)}
              margin="normal"
              placeholder="Describe any actions you've already taken (e.g., deleted email, changed password)..."
            />
          </Box>
        );

      case 4:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Review Your Report
            </Typography>
            
            <Paper sx={{ p: 2, mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Report Summary
              </Typography>
              <Box display="flex" gap={1} mb={1}>
                <Chip 
                  label={reportTypes.find(t => t.value === formData.reportType)?.label}
                  color={reportTypes.find(t => t.value === formData.reportType)?.color}
                />
                <Chip 
                  label={severityLevels.find(s => s.value === formData.severity)?.label}
                  color={severityLevels.find(s => s.value === formData.severity)?.color}
                />
              </Box>
              <Typography variant="body1" fontWeight="bold">
                {formData.title}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                {formData.description}
              </Typography>
            </Paper>

            <Paper sx={{ p: 2, mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Contact Information
              </Typography>
              <Typography variant="body2">
                <strong>Name:</strong> {formData.userInfo.name}
              </Typography>
              <Typography variant="body2">
                <strong>Email:</strong> {formData.userInfo.email}
              </Typography>
              <Typography variant="body2">
                <strong>Department:</strong> {formData.userInfo.department}
              </Typography>
            </Paper>

            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Evidence Summary
              </Typography>
              <Typography variant="body2">
                Screenshots: {formData.evidence.screenshots.length}
              </Typography>
              <Typography variant="body2">
                Files: {formData.evidence.files.length + formData.emailDetails.attachments.length}
              </Typography>
              <Typography variant="body2">
                URLs: {formData.evidence.urls.length}
              </Typography>
            </Paper>

            <Alert severity="info" sx={{ mt: 2 }}>
              By submitting this report, you confirm that the information provided is accurate 
              and you consent to the security team investigating this matter.
            </Alert>
          </Box>
        );

      default:
        return null;
    }
  };

  const isStepValid = (step) => {
    switch (step) {
      case 0:
        return formData.title && formData.description && formData.reportType;
      case 3:
        return formData.userInfo.name && formData.userInfo.email && formData.userInfo.department;
      default:
        return true;
    }
  };

  if (submitSuccess) {
    return (
      <Card>
        <CardContent>
          <Box textAlign="center" py={4}>
            <CheckCircleIcon sx={{ fontSize: 64, color: 'success.main', mb: 2 }} />
            <Typography variant="h5" gutterBottom>
              Report Submitted Successfully!
            </Typography>
            <Typography variant="body1" color="textSecondary" paragraph>
              Thank you for reporting this security concern. Your report has been received 
              and will be reviewed by our security team.
            </Typography>
            <Alert severity="success" sx={{ mb: 2, maxWidth: 400, mx: 'auto' }}>
              Your ticket number is: <strong>SEC-{Date.now().toString().slice(-6)}</strong>
            </Alert>
            <Typography variant="body2" color="textSecondary" paragraph>
              You will receive an email confirmation shortly. If this is an urgent matter, 
              please contact the IT security team directly.
            </Typography>
            {onClose && (
              <Button variant="contained" onClick={onClose}>
                Close
              </Button>
            )}
          </Box>
        </CardContent>
      </Card>
    );
  }

  const content = (
    <Box>
      <Stepper activeStep={activeStep} orientation="vertical">
        {steps.map((label, index) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
            <StepContent>
              {renderStepContent(index)}
              <Box sx={{ mb: 2, mt: 2 }}>
                {index < steps.length - 1 ? (
                  <Button
                    variant="contained"
                    onClick={handleNext}
                    sx={{ mt: 1, mr: 1 }}
                    disabled={!isStepValid(index)}
                  >
                    Continue
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    onClick={handleSubmit}
                    disabled={loading || !isStepValid(index)}
                    startIcon={loading ? <CircularProgress size={20} /> : <SendIcon />}
                    sx={{ mt: 1, mr: 1 }}
                  >
                    Submit Report
                  </Button>
                )}
                <Button
                  disabled={index === 0}
                  onClick={handleBack}
                  sx={{ mt: 1, mr: 1 }}
                >
                  Back
                </Button>
              </Box>
            </StepContent>
          </Step>
        ))}
      </Stepper>

      {loading && (
        <Box mt={2}>
          <LinearProgress />
          <Typography variant="body2" color="textSecondary" align="center" mt={1}>
            Submitting your security report...
          </Typography>
        </Box>
      )}
    </Box>
  );

  if (embedded) {
    return (
      <Card>
        <CardContent>
          <Typography variant="h5" component="h1" gutterBottom>
            Report Security Concern
          </Typography>
          <Typography variant="body2" color="textSecondary" paragraph>
            Help us keep our organization secure by reporting suspicious activities, 
            emails, or potential security threats.
          </Typography>
          {content}
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      {content}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
      >
        <Alert severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </>
  );
};

export default UserReportForm;
