import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  LinearProgress,
  Alert,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Switch,
  FormControlLabel,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Snackbar
} from '@mui/material';
import {
  Security as SecurityIcon,
  Gavel as GavelIcon,
  Assignment as AssignmentIcon,
  ExpandMore as ExpandMoreIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Visibility as VisibilityIcon,
  Edit as EditIcon,
  Policy as PolicyIcon,
  Assessment as AssessmentIcon,
  AccountBalance as ComplianceIcon,
  VerifiedUser as VerifiedIcon,
  Schedule as ScheduleIcon
} from '@mui/icons-material';

const Compliance = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [complianceData, setComplianceData] = useState({});
  const [policies, setPolicies] = useState([]);
  const [assessments, setAssessments] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [policyDialog, setPolicyDialog] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState(null);

  const complianceFrameworks = [
    'GDPR', 'HIPAA', 'SOX', 'PCI-DSS', 'ISO 27001', 'NIST', 'SOC 2'
  ];

  const riskLevels = [
    { value: 'low', label: 'Low Risk', color: 'success' },
    { value: 'medium', label: 'Medium Risk', color: 'warning' },
    { value: 'high', label: 'High Risk', color: 'error' },
    { value: 'critical', label: 'Critical Risk', color: 'error' }
  ];

  useEffect(() => {
    fetchComplianceData();
  }, []);

  const fetchComplianceData = async () => {
    try {
      setLoading(true);
      // Simulate API calls
      await new Promise(resolve => setTimeout(resolve, 1000));

      const mockComplianceData = {
        overallScore: 94.5,
        frameworks: {
          'GDPR': { score: 96.2, status: 'compliant', lastAudit: '2024-01-15' },
          'HIPAA': { score: 92.8, status: 'compliant', lastAudit: '2024-01-10' },
          'SOX': { score: 95.1, status: 'compliant', lastAudit: '2024-01-20' },
          'PCI-DSS': { score: 89.3, status: 'warning', lastAudit: '2024-01-05' },
          'ISO 27001': { score: 97.5, status: 'compliant', lastAudit: '2024-01-25' },
          'NIST': { score: 93.7, status: 'compliant', lastAudit: '2024-01-12' },
          'SOC 2': { score: 91.4, status: 'compliant', lastAudit: '2024-01-18' }
        },
        riskDistribution: {
          low: 145,
          medium: 28,
          high: 7,
          critical: 2
        },
        trends: {
          scoreChange: +2.3,
          riskReduction: -15.2,
          policyCompliance: +5.8
        }
      };

      const mockPolicies = [
        {
          id: 1,
          name: 'Data Protection Policy',
          framework: 'GDPR',
          version: '2.1',
          status: 'active',
          compliance: 98.5,
          lastReview: '2024-01-15',
          nextReview: '2024-07-15',
          approver: 'Chief Privacy Officer',
          violations: 2,
          riskLevel: 'low'
        },
        {
          id: 2,
          name: 'Information Security Policy',
          framework: 'ISO 27001',
          version: '3.0',
          status: 'active',
          compliance: 95.2,
          lastReview: '2024-01-10',
          nextReview: '2024-04-10',
          approver: 'CISO',
          violations: 5,
          riskLevel: 'medium'
        },
        {
          id: 3,
          name: 'Access Control Policy',
          framework: 'SOX',
          version: '1.8',
          status: 'under_review',
          compliance: 87.3,
          lastReview: '2024-01-05',
          nextReview: '2024-03-05',
          approver: 'Security Manager',
          violations: 12,
          riskLevel: 'high'
        }
      ];

      const mockAssessments = [
        {
          id: 1,
          name: 'Q1 2024 Security Assessment',
          framework: 'ISO 27001',
          type: 'internal',
          status: 'completed',
          score: 94.2,
          findings: 8,
          criticalFindings: 1,
          startDate: '2024-01-01',
          endDate: '2024-01-31',
          assessor: 'Internal Audit Team'
        },
        {
          id: 2,
          name: 'GDPR Compliance Review',
          framework: 'GDPR',
          type: 'external',
          status: 'in_progress',
          score: null,
          findings: null,
          criticalFindings: null,
          startDate: '2024-02-01',
          endDate: '2024-02-28',
          assessor: 'External Auditor'
        }
      ];

      const mockAuditLogs = [
        {
          id: 1,
          timestamp: '2024-01-25T10:30:00Z',
          user: 'admin@company.com',
          action: 'Policy Updated',
          resource: 'Data Protection Policy',
          status: 'success',
          ipAddress: '192.168.1.100',
          details: 'Updated section 4.2 - Data retention guidelines'
        },
        {
          id: 2,
          timestamp: '2024-01-24T14:15:00Z',
          user: 'auditor@company.com',
          action: 'Assessment Started',
          resource: 'Security Assessment Q1',
          status: 'info',
          ipAddress: '192.168.1.105',
          details: 'Initiated quarterly security assessment'
        },
        {
          id: 3,
          timestamp: '2024-01-23T09:45:00Z',
          user: 'system',
          action: 'Compliance Check',
          resource: 'All Policies',
          status: 'warning',
          ipAddress: 'system',
          details: 'Automated compliance check detected 3 policy violations'
        }
      ];

      setComplianceData(mockComplianceData);
      setPolicies(mockPolicies);
      setAssessments(mockAssessments);
      setAuditLogs(mockAuditLogs);
    } catch (error) {
      console.error('Error fetching compliance data:', error);
      showSnackbar('Error loading compliance data', 'error');
    } finally {
      setLoading(false);
    }
  };

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const getFrameworkStatus = (score) => {
    if (score >= 95) return { status: 'compliant', color: 'success' };
    if (score >= 85) return { status: 'warning', color: 'warning' };
    return { status: 'non-compliant', color: 'error' };
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString();
  };

  const handlePolicyView = (policy) => {
    setSelectedPolicy(policy);
    setPolicyDialog(true);
  };

  const renderOverviewTab = () => (
    <Grid container spacing={3}>
      {/* Overall Compliance Score */}
      <Grid item xs={12} md={4}>
        <Card>
          <CardContent sx={{ textAlign: 'center' }}>
            <ComplianceIcon sx={{ fontSize: 48, color: 'success.main', mb: 2 }} />
            <Typography variant="h3" color="success.main" gutterBottom>
              {complianceData.overallScore}%
            </Typography>
            <Typography variant="h6" gutterBottom>
              Overall Compliance Score
            </Typography>
            <Typography variant="body2" color="textSecondary">
              +{complianceData.trends?.scoreChange}% from last quarter
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      {/* Risk Distribution */}
      <Grid item xs={12} md={8}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Risk Distribution
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="success.main">
                    {complianceData.riskDistribution?.low || 0}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Low Risk
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="warning.main">
                    {complianceData.riskDistribution?.medium || 0}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Medium Risk
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="error.main">
                    {complianceData.riskDistribution?.high || 0}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    High Risk
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="error.dark">
                    {complianceData.riskDistribution?.critical || 0}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Critical Risk
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>

      {/* Framework Compliance */}
      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Compliance Framework Status
            </Typography>
            <Grid container spacing={2}>
              {Object.entries(complianceData.frameworks || {}).map(([framework, data]) => {
                const { status, color } = getFrameworkStatus(data.score);
                return (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={framework}>
                    <Paper sx={{ p: 2, border: 1, borderColor: `${color}.main` }}>
                      <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                        <Typography variant="subtitle1" fontWeight="bold">
                          {framework}
                        </Typography>
                        <Chip label={status} color={color} size="small" />
                      </Box>
                      <Typography variant="h5" color={`${color}.main`} gutterBottom>
                        {data.score}%
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Last audit: {formatDate(data.lastAudit)}
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={data.score}
                        color={color}
                        sx={{ mt: 1 }}
                      />
                    </Paper>
                  </Grid>
                );
              })}
            </Grid>
          </CardContent>
        </Card>
      </Grid>

      {/* Recent Alerts */}
      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Recent Compliance Alerts
            </Typography>
            <Alert severity="warning" sx={{ mb: 1 }}>
              PCI-DSS compliance score dropped below 90%. Immediate review required.
            </Alert>
            <Alert severity="info" sx={{ mb: 1 }}>
              GDPR assessment scheduled for next week. Preparation checklist available.
            </Alert>
            <Alert severity="success">
              ISO 27001 certification renewed successfully. Valid until 2025.
            </Alert>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderPoliciesTab = () => (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h6">Policy Management</Typography>
        <Button variant="contained" startIcon={<PolicyIcon />}>
          New Policy
        </Button>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Policy Name</TableCell>
              <TableCell>Framework</TableCell>
              <TableCell>Version</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Compliance</TableCell>
              <TableCell>Next Review</TableCell>
              <TableCell>Risk Level</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {policies.map((policy) => (
              <TableRow key={policy.id}>
                <TableCell>
                  <Typography variant="subtitle2">{policy.name}</Typography>
                </TableCell>
                <TableCell>
                  <Chip label={policy.framework} size="small" />
                </TableCell>
                <TableCell>{policy.version}</TableCell>
                <TableCell>
                  <Chip
                    label={policy.status.replace('_', ' ')}
                    color={policy.status === 'active' ? 'success' : 'warning'}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Typography variant="body2">{policy.compliance}%</Typography>
                    <LinearProgress
                      variant="determinate"
                      value={policy.compliance}
                      sx={{ width: 60, height: 6 }}
                      color={policy.compliance >= 95 ? 'success' : policy.compliance >= 85 ? 'warning' : 'error'}
                    />
                  </Box>
                </TableCell>
                <TableCell>{formatDate(policy.nextReview)}</TableCell>
                <TableCell>
                  <Chip
                    label={policy.riskLevel}
                    color={riskLevels.find(r => r.value === policy.riskLevel)?.color}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <IconButton
                    size="small"
                    onClick={() => handlePolicyView(policy)}
                  >
                    <VisibilityIcon />
                  </IconButton>
                  <IconButton size="small">
                    <EditIcon />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );

  const renderAssessmentsTab = () => (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h6">Compliance Assessments</Typography>
        <Button variant="contained" startIcon={<AssessmentIcon />}>
          New Assessment
        </Button>
      </Box>

      <Grid container spacing={3}>
        {assessments.map((assessment) => (
          <Grid item xs={12} md={6} key={assessment.id}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2}>
                  <Box>
                    <Typography variant="h6" gutterBottom>
                      {assessment.name}
                    </Typography>
                    <Chip
                      label={assessment.status.replace('_', ' ')}
                      color={assessment.status === 'completed' ? 'success' : 'info'}
                      size="small"
                    />
                  </Box>
                  <Chip label={assessment.framework} variant="outlined" />
                </Box>

                <Grid container spacing={2} mb={2}>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="textSecondary">
                      Type
                    </Typography>
                    <Typography variant="body1">
                      {assessment.type.charAt(0).toUpperCase() + assessment.type.slice(1)}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="textSecondary">
                      Assessor
                    </Typography>
                    <Typography variant="body1">
                      {assessment.assessor}
                    </Typography>
                  </Grid>
                </Grid>

                {assessment.score && (
                  <Box mb={2}>
                    <Typography variant="body2" color="textSecondary" gutterBottom>
                      Compliance Score
                    </Typography>
                    <Box display="flex" alignItems="center" gap={1}>
                      <Typography variant="h6" color="success.main">
                        {assessment.score}%
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={assessment.score}
                        sx={{ flexGrow: 1, height: 8 }}
                        color="success"
                      />
                    </Box>
                  </Box>
                )}

                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Typography variant="body2" color="textSecondary">
                    {formatDate(assessment.startDate)} - {formatDate(assessment.endDate)}
                  </Typography>
                  {assessment.findings !== null && (
                    <Typography variant="body2">
                      {assessment.findings} findings ({assessment.criticalFindings} critical)
                    </Typography>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );

  const renderAuditTab = () => (
    <Box>
      <Typography variant="h6" mb={3}>Audit Trail</Typography>
      
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Timestamp</TableCell>
              <TableCell>User</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Resource</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Details</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {auditLogs.map((log) => (
              <TableRow key={log.id}>
                <TableCell>
                  <Typography variant="body2">
                    {new Date(log.timestamp).toLocaleString()}
                  </Typography>
                </TableCell>
                <TableCell>{log.user}</TableCell>
                <TableCell>{log.action}</TableCell>
                <TableCell>{log.resource}</TableCell>
                <TableCell>
                  <Chip
                    label={log.status}
                    color={
                      log.status === 'success' ? 'success' :
                      log.status === 'warning' ? 'warning' :
                      log.status === 'error' ? 'error' : 'info'
                    }
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                    {log.details}
                  </Typography>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box mb={4}>
        <Typography variant="h4" component="h1" fontWeight="bold" gutterBottom>
          Compliance Management
        </Typography>
        <Typography variant="body1" color="textSecondary">
          Monitor and manage regulatory compliance across all frameworks
        </Typography>
      </Box>

      {/* Action Buttons */}
      <Box display="flex" gap={2} mb={3}>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={fetchComplianceData}
        >
          Refresh Data
        </Button>
        <Button
          variant="outlined"
          startIcon={<DownloadIcon />}
        >
          Export Report
        </Button>
        <Button
          variant="contained"
          startIcon={<AssessmentIcon />}
        >
          Run Assessment
        </Button>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
          <Tab icon={<SecurityIcon />} label="Overview" />
          <Tab icon={<PolicyIcon />} label="Policies" />
          <Tab icon={<AssessmentIcon />} label="Assessments" />
          <Tab icon={<GavelIcon />} label="Audit Trail" />
        </Tabs>
      </Paper>

      {/* Tab Content */}
      <Box>
        {activeTab === 0 && renderOverviewTab()}
        {activeTab === 1 && renderPoliciesTab()}
        {activeTab === 2 && renderAssessmentsTab()}
        {activeTab === 3 && renderAuditTab()}
      </Box>

      {/* Policy Details Dialog */}
      <Dialog
        open={policyDialog}
        onClose={() => setPolicyDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Policy Details: {selectedPolicy?.name}
        </DialogTitle>
        <DialogContent>
          {selectedPolicy && (
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Framework</Typography>
                <Typography variant="body1">{selectedPolicy.framework}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Version</Typography>
                <Typography variant="body1">{selectedPolicy.version}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Compliance Score</Typography>
                <Typography variant="body1">{selectedPolicy.compliance}%</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="body2" color="textSecondary">Risk Level</Typography>
                <Chip
                  label={selectedPolicy.riskLevel}
                  color={riskLevels.find(r => r.value === selectedPolicy.riskLevel)?.color}
                  size="small"
                />
              </Grid>
              <Grid item xs={12}>
                <Typography variant="body2" color="textSecondary">Approver</Typography>
                <Typography variant="body1">{selectedPolicy.approver}</Typography>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPolicyDialog(false)}>Close</Button>
          <Button variant="contained">Download Policy</Button>
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

export default Compliance;
