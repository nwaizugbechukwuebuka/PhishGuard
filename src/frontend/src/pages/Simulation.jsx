import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  Alert,
  Tabs,
  Tab,
  Paper,
  Divider,
  CircularProgress,
  Snackbar
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Add as AddIcon,
  People as PeopleIcon,
  Email as EmailIcon,
  Schedule as ScheduleIcon,
  Assessment as AssessmentIcon,
  Security as SecurityIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  CloudUpload as UploadIcon,
  Download as DownloadIcon
} from '@mui/icons-material';
import SimulationPanel from '../components/SimulationPanel';

const Simulation = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [simulations, setSimulations] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [users, setUsers] = useState([]);
  const [newSimulationDialog, setNewSimulationDialog] = useState(false);
  const [editSimulationDialog, setEditSimulationDialog] = useState(false);
  const [selectedSimulation, setSelectedSimulation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Form data for new/edit simulation
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    templateId: '',
    targetGroups: [],
    startDate: '',
    endDate: '',
    frequency: 'once',
    difficulty: 'medium',
    includeAttachments: false,
    trackClicks: true,
    trackReplies: true,
    autoRemediation: false
  });

  const simulationTypes = [
    { value: 'phishing', label: 'Phishing Email', icon: <EmailIcon /> },
    { value: 'social_engineering', label: 'Social Engineering', icon: <PeopleIcon /> },
    { value: 'vishing', label: 'Voice Phishing', icon: <SecurityIcon /> },
    { value: 'smishing', label: 'SMS Phishing', icon: <EmailIcon /> }
  ];

  const difficultyLevels = [
    { value: 'easy', label: 'Easy', color: 'success' },
    { value: 'medium', label: 'Medium', color: 'warning' },
    { value: 'hard', label: 'Hard', color: 'error' }
  ];

  const frequencyOptions = [
    { value: 'once', label: 'One-time' },
    { value: 'weekly', label: 'Weekly' },
    { value: 'monthly', label: 'Monthly' },
    { value: 'quarterly', label: 'Quarterly' }
  ];

  useEffect(() => {
    fetchSimulationData();
  }, []);

  const fetchSimulationData = async () => {
    try {
      setLoading(true);
      // Simulate API calls
      await new Promise(resolve => setTimeout(resolve, 1000));

      const mockSimulations = [
        {
          id: 1,
          name: 'Q1 Phishing Assessment',
          description: 'Quarterly phishing simulation for all departments',
          type: 'phishing',
          status: 'active',
          targetUsers: 245,
          clickRate: 12.5,
          reportRate: 87.5,
          startDate: '2024-01-15',
          endDate: '2024-02-15',
          difficulty: 'medium',
          templateName: 'Fake Bank Alert'
        },
        {
          id: 2,
          name: 'Executive Team Training',
          description: 'Advanced social engineering simulation for executives',
          type: 'social_engineering',
          status: 'completed',
          targetUsers: 15,
          clickRate: 6.7,
          reportRate: 93.3,
          startDate: '2024-01-01',
          endDate: '2024-01-31',
          difficulty: 'hard',
          templateName: 'CEO Impersonation'
        },
        {
          id: 3,
          name: 'New Employee Onboarding',
          description: 'Basic security awareness for new hires',
          type: 'phishing',
          status: 'scheduled',
          targetUsers: 32,
          clickRate: null,
          reportRate: null,
          startDate: '2024-02-01',
          endDate: '2024-02-28',
          difficulty: 'easy',
          templateName: 'IT Support Scam'
        }
      ];

      const mockCampaigns = [
        {
          id: 1,
          name: 'Security Awareness Month',
          description: 'Comprehensive security training campaign',
          simulations: 3,
          participants: 450,
          completion: 78,
          startDate: '2024-01-01',
          endDate: '2024-01-31',
          status: 'completed'
        },
        {
          id: 2,
          name: 'Advanced Threat Training',
          description: 'Advanced phishing and social engineering training',
          simulations: 2,
          participants: 125,
          completion: 92,
          startDate: '2024-02-01',
          endDate: '2024-02-29',
          status: 'active'
        }
      ];

      const mockTemplates = [
        {
          id: 1,
          name: 'Fake Bank Alert',
          type: 'phishing',
          difficulty: 'medium',
          category: 'Financial',
          description: 'Simulates a fraudulent banking security alert',
          usage: 156,
          effectiveness: 85.2
        },
        {
          id: 2,
          name: 'CEO Impersonation',
          type: 'social_engineering',
          difficulty: 'hard',
          category: 'Executive',
          description: 'Simulates CEO requesting urgent action',
          usage: 89,
          effectiveness: 92.1
        },
        {
          id: 3,
          name: 'IT Support Scam',
          type: 'phishing',
          difficulty: 'easy',
          category: 'Technical',
          description: 'Fake IT support requesting credentials',
          usage: 234,
          effectiveness: 78.9
        }
      ];

      setSimulations(mockSimulations);
      setCampaigns(mockCampaigns);
      setTemplates(mockTemplates);
    } catch (error) {
      console.error('Error fetching simulation data:', error);
      showSnackbar('Error loading simulation data', 'error');
    } finally {
      setLoading(false);
    }
  };

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const handleCreateSimulation = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const newSimulation = {
        id: Date.now(),
        ...formData,
        status: 'scheduled',
        targetUsers: Math.floor(Math.random() * 200) + 50,
        clickRate: null,
        reportRate: null
      };
      
      setSimulations([...simulations, newSimulation]);
      setNewSimulationDialog(false);
      resetForm();
      showSnackbar('Simulation created successfully');
    } catch (error) {
      showSnackbar('Error creating simulation', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleEditSimulation = async () => {
    try {
      setLoading(true);
      await new Promise(resolve => setTimeout(resolve, 500));
      
      const updatedSimulations = simulations.map(sim =>
        sim.id === selectedSimulation.id ? { ...sim, ...formData } : sim
      );
      
      setSimulations(updatedSimulations);
      setEditSimulationDialog(false);
      setSelectedSimulation(null);
      resetForm();
      showSnackbar('Simulation updated successfully');
    } catch (error) {
      showSnackbar('Error updating simulation', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteSimulation = async (simulationId) => {
    if (window.confirm('Are you sure you want to delete this simulation?')) {
      try {
        setLoading(true);
        await new Promise(resolve => setTimeout(resolve, 500));
        
        setSimulations(simulations.filter(sim => sim.id !== simulationId));
        showSnackbar('Simulation deleted successfully');
      } catch (error) {
        showSnackbar('Error deleting simulation', 'error');
      } finally {
        setLoading(false);
      }
    }
  };

  const handleStartSimulation = async (simulationId) => {
    try {
      setLoading(true);
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const updatedSimulations = simulations.map(sim =>
        sim.id === simulationId ? { ...sim, status: 'active' } : sim
      );
      
      setSimulations(updatedSimulations);
      showSnackbar('Simulation started successfully');
    } catch (error) {
      showSnackbar('Error starting simulation', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleStopSimulation = async (simulationId) => {
    try {
      setLoading(true);
      await new Promise(resolve => setTimeout(resolve, 500));
      
      const updatedSimulations = simulations.map(sim =>
        sim.id === simulationId ? { ...sim, status: 'stopped' } : sim
      );
      
      setSimulations(updatedSimulations);
      showSnackbar('Simulation stopped');
    } catch (error) {
      showSnackbar('Error stopping simulation', 'error');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      templateId: '',
      targetGroups: [],
      startDate: '',
      endDate: '',
      frequency: 'once',
      difficulty: 'medium',
      includeAttachments: false,
      trackClicks: true,
      trackReplies: true,
      autoRemediation: false
    });
  };

  const openEditDialog = (simulation) => {
    setSelectedSimulation(simulation);
    setFormData({
      name: simulation.name,
      description: simulation.description,
      templateId: simulation.templateId || '',
      targetGroups: simulation.targetGroups || [],
      startDate: simulation.startDate,
      endDate: simulation.endDate,
      frequency: simulation.frequency || 'once',
      difficulty: simulation.difficulty,
      includeAttachments: simulation.includeAttachments || false,
      trackClicks: simulation.trackClicks !== false,
      trackReplies: simulation.trackReplies !== false,
      autoRemediation: simulation.autoRemediation || false
    });
    setEditSimulationDialog(true);
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'success';
      case 'completed': return 'info';
      case 'scheduled': return 'warning';
      case 'stopped': return 'error';
      default: return 'default';
    }
  };

  const renderSimulationsTab = () => (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h6">Active Simulations</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setNewSimulationDialog(true)}
        >
          New Simulation
        </Button>
      </Box>

      <Grid container spacing={3}>
        {simulations.map((simulation) => (
          <Grid item xs={12} md={6} lg={4} key={simulation.id}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2}>
                  <Box>
                    <Typography variant="h6" gutterBottom>
                      {simulation.name}
                    </Typography>
                    <Chip
                      label={simulation.status}
                      color={getStatusColor(simulation.status)}
                      size="small"
                    />
                  </Box>
                  <Box>
                    {simulation.status === 'scheduled' && (
                      <IconButton
                        size="small"
                        color="primary"
                        onClick={() => handleStartSimulation(simulation.id)}
                      >
                        <PlayIcon />
                      </IconButton>
                    )}
                    {simulation.status === 'active' && (
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleStopSimulation(simulation.id)}
                      >
                        <StopIcon />
                      </IconButton>
                    )}
                    <IconButton
                      size="small"
                      onClick={() => openEditDialog(simulation)}
                    >
                      <EditIcon />
                    </IconButton>
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => handleDeleteSimulation(simulation.id)}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Box>
                </Box>

                <Typography variant="body2" color="textSecondary" mb={2}>
                  {simulation.description}
                </Typography>

                <Box display="flex" justifyContent="space-between" mb={1}>
                  <Typography variant="body2">Target Users:</Typography>
                  <Typography variant="body2" fontWeight="bold">
                    {simulation.targetUsers}
                  </Typography>
                </Box>

                {simulation.clickRate !== null && (
                  <>
                    <Box display="flex" justifyContent="space-between" mb={1}>
                      <Typography variant="body2">Click Rate:</Typography>
                      <Typography variant="body2" fontWeight="bold" color="error.main">
                        {simulation.clickRate}%
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between" mb={1}>
                      <Typography variant="body2">Report Rate:</Typography>
                      <Typography variant="body2" fontWeight="bold" color="success.main">
                        {simulation.reportRate}%
                      </Typography>
                    </Box>
                  </>
                )}

                <Chip
                  label={simulation.difficulty}
                  color={difficultyLevels.find(d => d.value === simulation.difficulty)?.color}
                  variant="outlined"
                  size="small"
                />
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );

  const renderCampaignsTab = () => (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h6">Training Campaigns</Typography>
        <Button variant="contained" startIcon={<AddIcon />}>
          New Campaign
        </Button>
      </Box>

      <Grid container spacing={3}>
        {campaigns.map((campaign) => (
          <Grid item xs={12} md={6} key={campaign.id}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {campaign.name}
                </Typography>
                <Typography variant="body2" color="textSecondary" mb={2}>
                  {campaign.description}
                </Typography>
                
                <Grid container spacing={2} mb={2}>
                  <Grid item xs={6}>
                    <Typography variant="body2">Simulations:</Typography>
                    <Typography variant="h6">{campaign.simulations}</Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2">Participants:</Typography>
                    <Typography variant="h6">{campaign.participants}</Typography>
                  </Grid>
                </Grid>

                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Typography variant="body2">
                    Completion: {campaign.completion}%
                  </Typography>
                  <Chip
                    label={campaign.status}
                    color={getStatusColor(campaign.status)}
                    size="small"
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );

  const renderTemplatesTab = () => (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h6">Simulation Templates</Typography>
        <Button variant="contained" startIcon={<UploadIcon />}>
          Upload Template
        </Button>
      </Box>

      <Grid container spacing={3}>
        {templates.map((template) => (
          <Grid item xs={12} md={6} lg={4} key={template.id}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {template.name}
                </Typography>
                <Typography variant="body2" color="textSecondary" mb={2}>
                  {template.description}
                </Typography>
                
                <Box display="flex" gap={1} mb={2}>
                  <Chip label={template.category} size="small" />
                  <Chip
                    label={template.difficulty}
                    color={difficultyLevels.find(d => d.value === template.difficulty)?.color}
                    size="small"
                  />
                </Box>

                <Box display="flex" justifyContent="space-between" mb={1}>
                  <Typography variant="body2">Usage Count:</Typography>
                  <Typography variant="body2" fontWeight="bold">
                    {template.usage}
                  </Typography>
                </Box>
                
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2">Effectiveness:</Typography>
                  <Typography variant="body2" fontWeight="bold" color="success.main">
                    {template.effectiveness}%
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );

  const renderAnalyticsTab = () => (
    <Box>
      <Typography variant="h6" mb={3}>Simulation Analytics</Typography>
      <SimulationPanel />
    </Box>
  );

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box mb={4}>
        <Typography variant="h4" component="h1" fontWeight="bold" gutterBottom>
          Security Training Simulations
        </Typography>
        <Typography variant="body1" color="textSecondary">
          Create, manage, and analyze security awareness training simulations
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
          <Tab icon={<SecurityIcon />} label="Simulations" />
          <Tab icon={<AssessmentIcon />} label="Campaigns" />
          <Tab icon={<EmailIcon />} label="Templates" />
          <Tab icon={<VisibilityIcon />} label="Analytics" />
        </Tabs>
      </Paper>

      {/* Tab Content */}
      <Box>
        {activeTab === 0 && renderSimulationsTab()}
        {activeTab === 1 && renderCampaignsTab()}
        {activeTab === 2 && renderTemplatesTab()}
        {activeTab === 3 && renderAnalyticsTab()}
      </Box>

      {/* New Simulation Dialog */}
      <Dialog
        open={newSimulationDialog}
        onClose={() => setNewSimulationDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Create New Simulation</DialogTitle>
        <DialogContent>
          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Simulation Name"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={3}
                label="Description"
                value={formData.description}
                onChange={(e) => setFormData({...formData, description: e.target.value})}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Template</InputLabel>
                <Select
                  value={formData.templateId}
                  label="Template"
                  onChange={(e) => setFormData({...formData, templateId: e.target.value})}
                >
                  {templates.map((template) => (
                    <MenuItem key={template.id} value={template.id}>
                      {template.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Difficulty</InputLabel>
                <Select
                  value={formData.difficulty}
                  label="Difficulty"
                  onChange={(e) => setFormData({...formData, difficulty: e.target.value})}
                >
                  {difficultyLevels.map((level) => (
                    <MenuItem key={level.value} value={level.value}>
                      {level.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                type="date"
                label="Start Date"
                InputLabelProps={{ shrink: true }}
                value={formData.startDate}
                onChange={(e) => setFormData({...formData, startDate: e.target.value})}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                type="date"
                label="End Date"
                InputLabelProps={{ shrink: true }}
                value={formData.endDate}
                onChange={(e) => setFormData({...formData, endDate: e.target.value})}
              />
            </Grid>
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.trackClicks}
                    onChange={(e) => setFormData({...formData, trackClicks: e.target.checked})}
                  />
                }
                label="Track Click Events"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.trackReplies}
                    onChange={(e) => setFormData({...formData, trackReplies: e.target.checked})}
                  />
                }
                label="Track Email Replies"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.autoRemediation}
                    onChange={(e) => setFormData({...formData, autoRemediation: e.target.checked})}
                  />
                }
                label="Auto Remediation"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewSimulationDialog(false)}>Cancel</Button>
          <Button
            onClick={handleCreateSimulation}
            variant="contained"
            disabled={loading || !formData.name}
          >
            {loading ? <CircularProgress size={24} /> : 'Create Simulation'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Simulation Dialog */}
      <Dialog
        open={editSimulationDialog}
        onClose={() => setEditSimulationDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Edit Simulation</DialogTitle>
        <DialogContent>
          {/* Similar form content as new simulation dialog */}
          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Simulation Name"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={3}
                label="Description"
                value={formData.description}
                onChange={(e) => setFormData({...formData, description: e.target.value})}
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditSimulationDialog(false)}>Cancel</Button>
          <Button
            onClick={handleEditSimulation}
            variant="contained"
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : 'Update Simulation'}
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

export default Simulation;
