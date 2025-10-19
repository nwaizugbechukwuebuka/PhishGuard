import React, { useState, useEffect, useRef } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Paper,
  Typography,
  Box,
  Chip,
  Divider,
  IconButton,
  Tooltip,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Collapse,
  Alert,
  LinearProgress,
  Grid,
  Avatar,
  Badge,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  Close as CloseIcon,
  ExpandMore as ExpandMoreIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  AttachFile as AttachFileIcon,
  Link as LinkIcon,
  Person as PersonIcon,
  Schedule as ScheduleIcon,
  Flag as FlagIcon,
  Shield as ShieldIcon,
  Visibility as VisibilityIcon,
  Download as DownloadIcon,
  Block as BlockIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Psychology as PsychologyIcon,
  Analytics as AnalyticsIcon,
  Report as ReportIcon
} from '@mui/icons-material';

const EmailViewer = ({ open, onClose, emailData }) => {
  const [activeTab, setActiveTab] = useState(0);
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [analysisExpanded, setAnalysisExpanded] = useState(true);
  const [attachmentWarningOpen, setAttachmentWarningOpen] = useState(false);
  const contentRef = useRef(null);

  useEffect(() => {
    if (open && emailData) {
      setActiveTab(0);
      setShowRawHeaders(false);
      setAnalysisExpanded(true);
    }
  }, [open, emailData]);

  if (!emailData) {
    return null;
  }

  const getRiskColor = (score) => {
    if (score >= 80) return 'error';
    if (score >= 50) return 'warning';
    return 'success';
  };

  const getRiskLabel = (score) => {
    if (score >= 80) return 'High Risk';
    if (score >= 50) return 'Medium Risk';
    return 'Low Risk';
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const handleAttachmentClick = (attachment) => {
    setAttachmentWarningOpen(true);
  };

  const sanitizeEmailContent = (content) => {
    // In a real implementation, this would sanitize HTML content
    // For demo purposes, we'll return safe mock content
    return `
      <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <p>Dear Finance Team,</p>
        <p><strong style="color: red;">URGENT ACTION REQUIRED</strong></p>
        <p>We have detected suspicious activity on our corporate account and need immediate verification of the following wire transfer:</p>
        <div style="background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 4px solid #ff4444;">
          <p><strong>Amount:</strong> $85,000 USD</p>
          <p><strong>Recipient:</strong> Global Trading Solutions LLC</p>
          <p><strong>Account:</strong> ************7892</p>
          <p><strong>Routing:</strong> 021000021</p>
        </div>
        <p>Please process this transfer within the next 2 hours to avoid penalties. Click the secure link below to authorize:</p>
        <p><a href="https://fake-bank-portal.com/authorize" style="color: #0066cc; text-decoration: underline;">Authorize Wire Transfer - SECURE LINK</a></p>
        <p>If you have any questions, please contact me immediately at this secure phone number: +1 (555) 123-4567</p>
        <p>Best regards,<br/>
        John Smith<br/>
        Chief Executive Officer<br/>
        Company Corp.</p>
        <div style="font-size: 11px; color: #666; margin-top: 20px;">
          <p>This email is confidential and may be legally privileged. If you are not the intended recipient, please delete this message.</p>
        </div>
      </div>
    `;
  };

  const mockAnalysisData = {
    overallRisk: emailData?.riskScore || 95,
    confidence: emailData?.aiConfidence || 97,
    threats: [
      { type: 'CEO Impersonation', severity: 'Critical', confidence: 98 },
      { type: 'Financial Fraud', severity: 'High', confidence: 95 },
      { type: 'Urgent Language', severity: 'Medium', confidence: 89 },
      { type: 'External Links', severity: 'High', confidence: 92 }
    ],
    indicators: [
      { 
        category: 'Sender Authentication', 
        status: 'fail', 
        details: 'SPF check failed, DKIM invalid, sender domain mismatch' 
      },
      { 
        category: 'Content Analysis', 
        status: 'warning', 
        details: 'Urgent financial language, CEO impersonation patterns detected' 
      },
      { 
        category: 'Link Analysis', 
        status: 'fail', 
        details: 'Suspicious external domains, potential phishing URLs' 
      },
      { 
        category: 'Attachment Scan', 
        status: 'warning', 
        details: 'Potentially malicious file types detected' 
      }
    ],
    aiInsights: [
      'Email exhibits classic CEO impersonation fraud patterns',
      'Sender domain does not match claimed organization',
      'Urgent language designed to bypass security protocols',
      'Financial request with tight deadline is common attack vector',
      'External links redirect to suspicious domains'
    ]
  };

  const getIndicatorIcon = (status) => {
    switch (status) {
      case 'pass':
        return <CheckCircleIcon color="success" />;
      case 'warning':
        return <WarningIcon color="warning" />;
      case 'fail':
        return <ErrorIcon color="error" />;
      default:
        return <InfoIcon color="info" />;
    }
  };

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: { height: '90vh', maxHeight: '90vh' }
        }}
      >
        <DialogTitle>
          <Box display="flex" justifyContent="space-between" alignItems="center">
            <Box>
              <Typography variant="h6" component="div">
                Email Analysis & Viewer
              </Typography>
              <Typography variant="body2" color="textSecondary">
                {emailData.subject}
              </Typography>
            </Box>
            <IconButton onClick={onClose}>
              <CloseIcon />
            </IconButton>
          </Box>
        </DialogTitle>

        <DialogContent dividers sx={{ p: 0 }}>
          <Box display="flex" height="100%">
            {/* Left Panel - Email Content */}
            <Box flex={2} sx={{ borderRight: 1, borderColor: 'divider' }}>
              {/* Email Header */}
              <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider', bgcolor: 'grey.50' }}>
                <Grid container spacing={2} alignItems="center">
                  <Grid item>
                    <Avatar sx={{ bgcolor: 'primary.main' }}>
                      <PersonIcon />
                    </Avatar>
                  </Grid>
                  <Grid item xs>
                    <Typography variant="h6" noWrap>
                      {emailData.subject}
                    </Typography>
                    <Box display="flex" flexWrap="wrap" gap={1} alignItems="center" mt={1}>
                      <Typography variant="body2" color="textSecondary">
                        <strong>From:</strong> {emailData.sender}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        <strong>To:</strong> {emailData.recipient}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        <strong>Date:</strong> {formatTimestamp(emailData.timestamp)}
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item>
                    <Box display="flex" flexDirection="column" alignItems="center" gap={1}>
                      <Chip
                        label={`Risk: ${emailData.riskScore}%`}
                        color={getRiskColor(emailData.riskScore)}
                        size="small"
                      />
                      <Chip
                        label={emailData.threatType}
                        color="error"
                        variant="outlined"
                        size="small"
                      />
                    </Box>
                  </Grid>
                </Grid>

                {/* Threat Indicators */}
                <Box mt={2}>
                  <Alert 
                    severity={getRiskColor(emailData.riskScore)} 
                    icon={<SecurityIcon />}
                    sx={{ mb: 1 }}
                  >
                    <Box>
                      <Typography variant="subtitle2">
                        {getRiskLabel(emailData.riskScore)} - {emailData.threatType} Detected
                      </Typography>
                      <Typography variant="body2">
                        AI Confidence: {mockAnalysisData.confidence}% | 
                        This email has been quarantined for security review.
                      </Typography>
                    </Box>
                  </Alert>
                </Box>

                {/* Attachments and Links */}
                {(emailData.attachments?.length > 0 || emailData.links?.length > 0) && (
                  <Box mt={2} display="flex" gap={2}>
                    {emailData.attachments?.length > 0 && (
                      <Box display="flex" alignItems="center" gap={1}>
                        <AttachFileIcon fontSize="small" />
                        <Typography variant="body2">
                          {emailData.attachments.length} attachment(s)
                        </Typography>
                      </Box>
                    )}
                    {emailData.links?.length > 0 && (
                      <Box display="flex" alignItems="center" gap={1}>
                        <LinkIcon fontSize="small" />
                        <Typography variant="body2">
                          {emailData.links.length} external link(s)
                        </Typography>
                      </Box>
                    )}
                  </Box>
                )}
              </Box>

              {/* Email Content */}
              <Box sx={{ p: 2, height: 'calc(100% - 200px)', overflow: 'auto' }}>
                <Paper variant="outlined" sx={{ p: 2, minHeight: '100%' }}>
                  <div 
                    ref={contentRef}
                    dangerouslySetInnerHTML={{ 
                      __html: sanitizeEmailContent(emailData.content) 
                    }}
                    style={{
                      fontFamily: 'Arial, sans-serif',
                      lineHeight: 1.6,
                      color: '#333'
                    }}
                  />
                </Paper>
              </Box>
            </Box>

            {/* Right Panel - Analysis */}
            <Box flex={1} sx={{ bgcolor: 'grey.50' }}>
              <Box sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Security Analysis
                </Typography>

                {/* Overall Risk Score */}
                <Card sx={{ mb: 2 }}>
                  <CardContent>
                    <Box display="flex" alignItems="center" gap={2} mb={2}>
                      <Shield color={getRiskColor(mockAnalysisData.overallRisk)} />
                      <Box>
                        <Typography variant="h6">
                          Risk Score: {mockAnalysisData.overallRisk}%
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          AI Confidence: {mockAnalysisData.confidence}%
                        </Typography>
                      </Box>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={mockAnalysisData.overallRisk}
                      color={getRiskColor(mockAnalysisData.overallRisk)}
                      sx={{ height: 8, borderRadius: 4 }}
                    />
                  </CardContent>
                </Card>

                {/* Threat Detection */}
                <Accordion expanded={analysisExpanded} onChange={() => setAnalysisExpanded(!analysisExpanded)}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box display="flex" alignItems="center" gap={1}>
                      <WarningIcon color="error" />
                      <Typography variant="subtitle2">
                        Detected Threats ({mockAnalysisData.threats.length})
                      </Typography>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {mockAnalysisData.threats.map((threat, index) => (
                        <ListItem key={index}>
                          <ListItemIcon>
                            <FlagIcon 
                              color={threat.severity === 'Critical' ? 'error' : 
                                     threat.severity === 'High' ? 'warning' : 'info'} 
                              fontSize="small"
                            />
                          </ListItemIcon>
                          <ListItemText
                            primary={threat.type}
                            secondary={`${threat.severity} - ${threat.confidence}% confidence`}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>

                {/* Security Indicators */}
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box display="flex" alignItems="center" gap={1}>
                      <SecurityIcon color="primary" />
                      <Typography variant="subtitle2">
                        Security Indicators
                      </Typography>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {mockAnalysisData.indicators.map((indicator, index) => (
                        <ListItem key={index}>
                          <ListItemIcon>
                            {getIndicatorIcon(indicator.status)}
                          </ListItemIcon>
                          <ListItemText
                            primary={indicator.category}
                            secondary={indicator.details}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>

                {/* AI Insights */}
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box display="flex" alignItems="center" gap={1}>
                      <PsychologyIcon color="info" />
                      <Typography variant="subtitle2">
                        AI Insights
                      </Typography>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {mockAnalysisData.aiInsights.map((insight, index) => (
                        <ListItem key={index}>
                          <ListItemIcon>
                            <InfoIcon color="info" fontSize="small" />
                          </ListItemIcon>
                          <ListItemText
                            primary={insight}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>

                {/* Attachments Analysis */}
                {emailData.attachments?.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box display="flex" alignItems="center" gap={1}>
                        <AttachFileIcon color="warning" />
                        <Typography variant="subtitle2">
                          Attachments ({emailData.attachments.length})
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense>
                        {emailData.attachments.map((attachment, index) => (
                          <ListItem key={index}>
                            <ListItemIcon>
                              <AttachFileIcon fontSize="small" />
                            </ListItemIcon>
                            <ListItemText
                              primary={attachment}
                              secondary="Potentially malicious - Do not download"
                            />
                            <Box display="flex" gap={1}>
                              <Tooltip title="Scan Results">
                                <IconButton size="small">
                                  <AnalyticsIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Download (Quarantined)">
                                <IconButton 
                                  size="small" 
                                  onClick={() => handleAttachmentClick(attachment)}
                                  disabled
                                >
                                  <DownloadIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            </Box>
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Links Analysis */}
                {emailData.links?.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box display="flex" alignItems="center" gap={1}>
                        <LinkIcon color="error" />
                        <Typography variant="subtitle2">
                          External Links ({emailData.links.length})
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense>
                        {emailData.links.map((link, index) => (
                          <ListItem key={index}>
                            <ListItemIcon>
                              <BlockIcon color="error" fontSize="small" />
                            </ListItemIcon>
                            <ListItemText
                              primary={link}
                              secondary="Blocked - Potential phishing site"
                            />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                )}
              </Box>
            </Box>
          </Box>
        </DialogContent>

        <DialogActions>
          <Box display="flex" justifyContent="space-between" width="100%">
            <Box display="flex" gap={1}>
              <Button
                startIcon={<ReportIcon />}
                variant="outlined"
                size="small"
              >
                Generate Report
              </Button>
              <Button
                startIcon={<VisibilityIcon />}
                variant="outlined"
                size="small"
                onClick={() => setShowRawHeaders(!showRawHeaders)}
              >
                {showRawHeaders ? 'Hide' : 'Show'} Headers
              </Button>
            </Box>
            <Box display="flex" gap={1}>
              <Button onClick={onClose}>
                Close
              </Button>
              <Button
                variant="contained"
                color="primary"
                startIcon={<SecurityIcon />}
              >
                Take Action
              </Button>
            </Box>
          </Box>
        </DialogActions>
      </Dialog>

      {/* Attachment Warning Dialog */}
      <Dialog
        open={attachmentWarningOpen}
        onClose={() => setAttachmentWarningOpen(false)}
      >
        <DialogTitle>
          <Box display="flex" alignItems="center" gap={1}>
            <WarningIcon color="error" />
            Security Warning
          </Box>
        </DialogTitle>
        <DialogContent>
          <Alert severity="error" sx={{ mb: 2 }}>
            This attachment has been identified as potentially malicious and is currently quarantined.
          </Alert>
          <Typography variant="body1" gutterBottom>
            Downloading or opening this attachment could compromise your system security. 
            The file has been scanned and flagged by our security systems.
          </Typography>
          <Typography variant="body2" color="textSecondary">
            If you believe this is a legitimate file, please contact your IT security team 
            for further analysis and approval.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAttachmentWarningOpen(false)}>
            Cancel
          </Button>
          <Button variant="outlined" color="primary">
            Contact IT Security
          </Button>
        </DialogActions>
      </Dialog>

      {/* Raw Headers Dialog */}
      {showRawHeaders && (
        <Dialog
          open={showRawHeaders}
          onClose={() => setShowRawHeaders(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            Raw Email Headers
          </DialogTitle>
          <DialogContent>
            <Paper sx={{ p: 2, bgcolor: 'grey.100', fontFamily: 'monospace', fontSize: '12px' }}>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
{`Received: from mail.fake-company.com ([192.168.1.100])
    by mx.company.com with ESMTP id abc123def456
    for <finance@company.com>; Mon, 15 Jan 2024 10:30:00 +0000
Return-Path: <ceo@fake-company.com>
From: "John Smith" <ceo@fake-company.com>
To: "Finance Department" <finance@company.com>
Subject: URGENT: Wire Transfer Required - CEO Authorization
Date: Mon, 15 Jan 2024 10:29:45 +0000
Message-ID: <20240115102945.12345@fake-company.com>
X-Mailer: Microsoft Outlook 16.0
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: 8.5
X-Phishing-Score: 95
X-SPF-Result: FAIL
X-DKIM-Result: INVALID
X-DMARC-Result: FAIL
X-Quarantine-Reason: High-confidence phishing attempt
X-AI-Analysis: CEO Impersonation, Financial Fraud Pattern
X-Risk-Score: 95`}
              </pre>
            </Paper>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setShowRawHeaders(false)}>
              Close
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </>
  );
};

export default EmailViewer;
