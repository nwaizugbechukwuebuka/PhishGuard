import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
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
  Avatar,
  Badge,
  Divider,
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Switch,
  FormControlLabel
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Pause as PauseIcon,
  Settings as SettingsIcon,
  People as PeopleIcon,
  Email as EmailIcon,
  Timeline as TimelineIcon,
  Assessment as AssessmentIcon,
  School as SchoolIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  ExpandMore as ExpandMoreIcon,
  Visibility as VisibilityIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Add as AddIcon,
  Schedule as ScheduleIcon,
  Group as GroupIcon,
  TrendingUp as TrendingUpIcon
} from '@mui/icons-material';

const SimulationPanel = () => {
  const [activeSimulations, setActiveSimulations] = useState([]);
  const [simulationHistory, setSimulationHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [viewDialogOpen, setViewDialogOpen] = useState(false);
  const [selectedSimulation, setSelectedSimulation] = useState(null);
  const [activeStep, setActiveStep] = useState(0);
  
  const [newSimulation, setNewSimulation] = useState({
    name: '',
    type: 'phishing',
    targetGroups: [],
    schedule: 'immediate',
    duration: 30,
    difficulty: 'medium',
    template: '',
    notifications: true,
    autoReport: true
  });

  const simulationTypes = [
    { value: 'phishing', label: 'Phishing Simulation', icon: <SecurityIcon />, color: 'error' },
    { value: 'social_engineering', label: 'Social Engineering', icon: <PeopleIcon />, color: 'warning' },
    { value: 'malware', label: 'Malware Awareness', icon: <WarningIcon />, color: 'error' },
    { value: 'data_breach', label: 'Data Breach Response', icon: <ErrorIcon />, color: 'error' },
    { value: 'physical_security', label: 'Physical Security', icon: <SchoolIcon />, color: 'info' }
  ];

  const difficultyLevels = [
    { value: 'easy', label: 'Easy', color: 'success', description: 'Basic awareness level' },
    { value: 'medium', label: 'Medium', color: 'warning', description: 'Intermediate sophistication' },
    { value: 'hard', label: 'Hard', color: 'error', description: 'Advanced attack simulation' }
  ];

  const targetGroups = [
    { id: 1, name: 'All Employees', count: 245, department: 'All' },
    { id: 2, name: 'Finance Team', count: 12, department: 'Finance' },
    { id: 3, name: 'IT Department', count: 18, department: 'Technology' },
    { id: 4, name: 'Management', count: 8, department: 'Executive' },
    { id: 5, name: 'Sales Team', count: 35, department: 'Sales' },
    { id: 6, name: 'HR Department', count: 6, department: 'Human Resources' }
  ];

  const steps = [
    'Simulation Setup',
    'Target Selection',
    'Content Configuration',
    'Schedule & Launch'
  ];

  useEffect(() => {
    fetchSimulationData();
  }, []);

  const fetchSimulationData = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      const mockActive = [
        {
          id: 1,
          name: 'Q1 Phishing Awareness Campaign',
          type: 'phishing',
          status: 'running',
          progress: 65,
          startDate: new Date('2024-01-15T09:00:00'),
          endDate: new Date('2024-01-22T17:00:00'),
          targets: 245,
          responded: 158,
          failed: 23,
          reported: 64,
          success_rate: 90.6,
          difficulty: 'medium'
        },
        {
          id: 2,
          name: 'Finance Team CEO Impersonation Test',
          type: 'social_engineering',
          status: 'paused',
          progress: 30,
          startDate: new Date('2024-01-14T10:00:00'),
          endDate: new Date('2024-01-16T18:00:00'),
          targets: 12,
          responded: 4,
          failed: 2,
          reported: 2,
          success_rate: 50.0,
          difficulty: 'hard'
        }
      ];

      const mockHistory = [
        {
          id: 3,
          name: 'Holiday Season Phishing Campaign',
          type: 'phishing',
          status: 'completed',
          completion_date: new Date('2023-12-20T17:00:00'),
          targets: 180,
          success_rate: 92.2,
          failed: 14,
          duration: 7,
          difficulty: 'easy'
        },
        {
          id: 4,
          name: 'Malware Attachment Awareness',
          type: 'malware',
          status: 'completed',
          completion_date: new Date('2023-12-10T15:30:00'),
          targets: 245,
          success_rate: 87.8,
          failed: 30,
          duration: 5,
          difficulty: 'medium'
        }
      ];

      setActiveSimulations(mockActive);
      setSimulationHistory(mockHistory);
    } catch (error) {
      console.error('Error fetching simulation data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSimulation = () => {
    setCreateDialogOpen(true);
    setActiveStep(0);
    setNewSimulation({
      name: '',
      type: 'phishing',
      targetGroups: [],
      schedule: 'immediate',
      duration: 30,
      difficulty: 'medium',
      template: '',
      notifications: true,
      autoReport: true
    });
  };

  const handleNext = () => {
    setActiveStep((prevActiveStep) => prevActiveStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevActiveStep) => prevActiveStep - 1);
  };

  const handleLaunchSimulation = async () => {
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      const newSim = {
        id: Date.now(),
        name: newSimulation.name,
        type: newSimulation.type,
        status: 'running',
        progress: 0,
        startDate: new Date(),
        endDate: new Date(Date.now() + newSimulation.duration * 24 * 60 * 60 * 1000),
        targets: newSimulation.targetGroups.reduce((sum, group) => sum + group.count, 0),
        responded: 0,
        failed: 0,
        reported: 0,
        success_rate: 0,
        difficulty: newSimulation.difficulty
      };

      setActiveSimulations(prev => [...prev, newSim]);
      setCreateDialogOpen(false);
    } catch (error) {
      console.error('Error launching simulation:', error);
    }
  };

  const handleSimulationAction = async (id, action) => {
    try {
      setActiveSimulations(prev => 
        prev.map(sim => 
          sim.id === id 
            ? { ...sim, status: action === 'pause' ? 'paused' : action === 'resume' ? 'running' : 'stopped' }
            : sim
        )
      );
    } catch (error) {
      console.error('Error updating simulation:', error);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'running': return 'success';
      case 'paused': return 'warning';
      case 'stopped': return 'error';
      case 'completed': return 'info';
      default: return 'default';
    }
  };

  const getSuccessRateColor = (rate) => {
    if (rate >= 90) return 'success';
    if (rate >= 70) return 'warning';
    return 'error';
  };

  const formatDuration = (startDate, endDate) => {
    const diffTime = Math.abs(endDate - startDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return `${diffDays} days`;
  };

  const renderStepContent = (step) => {
    switch (step) {
      case 0:
        return (
          <Box>
            <TextField
              fullWidth
              label="Simulation Name"
              value={newSimulation.name}
              onChange={(e) => setNewSimulation(prev => ({ ...prev, name: e.target.value }))}
              margin="normal"
              required
            />
            <FormControl fullWidth margin="normal">
              <InputLabel>Simulation Type</InputLabel>
              <Select
                value={newSimulation.type}
                label="Simulation Type"
                onChange={(e) => setNewSimulation(prev => ({ ...prev, type: e.target.value }))}
              >
                {simulationTypes.map((type) => (
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
              <InputLabel>Difficulty Level</InputLabel>
              <Select
                value={newSimulation.difficulty}
                label="Difficulty Level"
                onChange={(e) => setNewSimulation(prev => ({ ...prev, difficulty: e.target.value }))}
              >
                {difficultyLevels.map((level) => (
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
          </Box>
        );

      case 1:
        return (
          <Box>
            <Typography variant="body1" gutterBottom>
              Select target groups for this simulation:
            </Typography>
            <List>
              {targetGroups.map((group) => (
                <ListItem key={group.id}>
                  <ListItemIcon>
                    <Avatar sx={{ bgcolor: 'primary.main' }}>
                      <GroupIcon />
                    </Avatar>
                  </ListItemIcon>
                  <ListItemText
                    primary={group.name}
                    secondary={`${group.count} employees • ${group.department}`}
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={newSimulation.targetGroups.some(g => g.id === group.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setNewSimulation(prev => ({
                              ...prev,
                              targetGroups: [...prev.targetGroups, group]
                            }));
                          } else {
                            setNewSimulation(prev => ({
                              ...prev,
                              targetGroups: prev.targetGroups.filter(g => g.id !== group.id)
                            }));
                          }
                        }}
                      />
                    }
                    label=""
                  />
                </ListItem>
              ))}
            </List>
            {newSimulation.targetGroups.length > 0 && (
              <Alert severity="info" sx={{ mt: 2 }}>
                Selected {newSimulation.targetGroups.length} group(s) with {' '}
                {newSimulation.targetGroups.reduce((sum, group) => sum + group.count, 0)} total employees
              </Alert>
            )}
          </Box>
        );

      case 2:
        return (
          <Box>
            <TextField
              fullWidth
              multiline
              rows={4}
              label="Email Template/Content"
              value={newSimulation.template}
              onChange={(e) => setNewSimulation(prev => ({ ...prev, template: e.target.value }))}
              margin="normal"
              placeholder="Enter the simulation email content or select a template..."
            />
            <Box display="flex" gap={2} mt={2}>
              <FormControlLabel
                control={
                  <Switch
                    checked={newSimulation.notifications}
                    onChange={(e) => setNewSimulation(prev => ({ ...prev, notifications: e.target.checked }))}
                  />
                }
                label="Send notifications to administrators"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={newSimulation.autoReport}
                    onChange={(e) => setNewSimulation(prev => ({ ...prev, autoReport: e.target.checked }))}
                  />
                }
                label="Generate automatic reports"
              />
            </Box>
          </Box>
        );

      case 3:
        return (
          <Box>
            <FormControl fullWidth margin="normal">
              <InputLabel>Schedule</InputLabel>
              <Select
                value={newSimulation.schedule}
                label="Schedule"
                onChange={(e) => setNewSimulation(prev => ({ ...prev, schedule: e.target.value }))}
              >
                <MenuItem value="immediate">Launch Immediately</MenuItem>
                <MenuItem value="scheduled">Schedule for Later</MenuItem>
                <MenuItem value="recurring">Recurring Campaign</MenuItem>
              </Select>
            </FormControl>
            <TextField
              fullWidth
              type="number"
              label="Duration (days)"
              value={newSimulation.duration}
              onChange={(e) => setNewSimulation(prev => ({ ...prev, duration: parseInt(e.target.value) }))}
              margin="normal"
              inputProps={{ min: 1, max: 90 }}
            />
            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Simulation Summary
              </Typography>
              <Typography variant="body2">
                • Name: {newSimulation.name || 'Untitled Simulation'}
              </Typography>
              <Typography variant="body2">
                • Type: {simulationTypes.find(t => t.value === newSimulation.type)?.label}
              </Typography>
              <Typography variant="body2">
                • Targets: {newSimulation.targetGroups.reduce((sum, group) => sum + group.count, 0)} employees
              </Typography>
              <Typography variant="body2">
                • Duration: {newSimulation.duration} days
              </Typography>
            </Alert>
          </Box>
        );

      default:
        return null;
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1" fontWeight="bold">
          Security Training Simulations
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={handleCreateSimulation}
        >
          New Simulation
        </Button>
      </Box>

      {/* Active Simulations */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Active Simulations ({activeSimulations.length})
          </Typography>
          {activeSimulations.length === 0 ? (
            <Alert severity="info">
              No active simulations. Create a new simulation to get started.
            </Alert>
          ) : (
            <Grid container spacing={2}>
              {activeSimulations.map((simulation) => (
                <Grid item xs={12} md={6} key={simulation.id}>
                  <Card variant="outlined">
                    <CardContent>
                      <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
                        <Box>
                          <Typography variant="h6" gutterBottom>
                            {simulation.name}
                          </Typography>
                          <Box display="flex" gap={1} mb={1}>
                            <Chip 
                              label={simulationTypes.find(t => t.value === simulation.type)?.label}
                              color={simulationTypes.find(t => t.value === simulation.type)?.color}
                              size="small"
                            />
                            <Chip
                              label={simulation.status}
                              color={getStatusColor(simulation.status)}
                              size="small"
                            />
                            <Chip
                              label={simulation.difficulty}
                              color={difficultyLevels.find(d => d.value === simulation.difficulty)?.color}
                              size="small"
                              variant="outlined"
                            />
                          </Box>
                        </Box>
                        <Box display="flex" gap={1}>
                          {simulation.status === 'running' && (
                            <IconButton 
                              size="small" 
                              color="warning"
                              onClick={() => handleSimulationAction(simulation.id, 'pause')}
                            >
                              <PauseIcon />
                            </IconButton>
                          )}
                          {simulation.status === 'paused' && (
                            <IconButton 
                              size="small" 
                              color="success"
                              onClick={() => handleSimulationAction(simulation.id, 'resume')}
                            >
                              <PlayIcon />
                            </IconButton>
                          )}
                          <IconButton 
                            size="small" 
                            color="error"
                            onClick={() => handleSimulationAction(simulation.id, 'stop')}
                          >
                            <StopIcon />
                          </IconButton>
                          <IconButton 
                            size="small"
                            onClick={() => {
                              setSelectedSimulation(simulation);
                              setViewDialogOpen(true);
                            }}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Box>
                      </Box>

                      <Box mb={2}>
                        <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                          <Typography variant="body2">Progress</Typography>
                          <Typography variant="body2">{simulation.progress}%</Typography>
                        </Box>
                        <LinearProgress 
                          variant="determinate" 
                          value={simulation.progress}
                          sx={{ height: 8, borderRadius: 4 }}
                        />
                      </Box>

                      <Grid container spacing={2}>
                        <Grid item xs={6}>
                          <Typography variant="body2" color="textSecondary">
                            Targets
                          </Typography>
                          <Typography variant="h6">
                            {simulation.targets}
                          </Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="body2" color="textSecondary">
                            Success Rate
                          </Typography>
                          <Typography 
                            variant="h6"
                            color={`${getSuccessRateColor(simulation.success_rate)}.main`}
                          >
                            {simulation.success_rate.toFixed(1)}%
                          </Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="body2" color="textSecondary">
                            Failed
                          </Typography>
                          <Typography variant="h6" color="error.main">
                            {simulation.failed}
                          </Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="body2" color="textSecondary">
                            Reported
                          </Typography>
                          <Typography variant="h6" color="success.main">
                            {simulation.reported}
                          </Typography>
                        </Grid>
                      </Grid>

                      <Typography variant="body2" color="textSecondary" mt={2}>
                        {formatDuration(simulation.startDate, simulation.endDate)} • 
                        Ends {simulation.endDate.toLocaleDateString()}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          )}
        </CardContent>
      </Card>

      {/* Simulation History */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Recent Simulations
          </Typography>
          {simulationHistory.length === 0 ? (
            <Alert severity="info">
              No completed simulations found.
            </Alert>
          ) : (
            <List>
              {simulationHistory.map((simulation, index) => (
                <React.Fragment key={simulation.id}>
                  <ListItem>
                    <ListItemIcon>
                      <Avatar sx={{ bgcolor: getSuccessRateColor(simulation.success_rate) === 'success' ? 'success.main' : 'warning.main' }}>
                        {simulationTypes.find(t => t.value === simulation.type)?.icon}
                      </Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={simulation.name}
                      secondary={
                        <Box>
                          <Typography variant="body2" color="textSecondary">
                            Completed {simulation.completion_date.toLocaleDateString()} • 
                            {simulation.targets} participants • 
                            {simulation.duration} days duration
                          </Typography>
                          <Box display="flex" gap={1} mt={0.5}>
                            <Chip
                              label={`${simulation.success_rate.toFixed(1)}% Success`}
                              color={getSuccessRateColor(simulation.success_rate)}
                              size="small"
                            />
                            <Chip
                              label={`${simulation.failed} Failed`}
                              color="error"
                              variant="outlined"
                              size="small"
                            />
                          </Box>
                        </Box>
                      }
                    />
                    <Box display="flex" gap={1}>
                      <IconButton size="small">
                        <VisibilityIcon />
                      </IconButton>
                      <IconButton size="small">
                        <AssessmentIcon />
                      </IconButton>
                    </Box>
                  </ListItem>
                  {index < simulationHistory.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          )}
        </CardContent>
      </Card>

      {/* Create Simulation Dialog */}
      <Dialog 
        open={createDialogOpen} 
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Create New Security Simulation</DialogTitle>
        <DialogContent>
          <Stepper activeStep={activeStep} orientation="vertical">
            {steps.map((label, index) => (
              <Step key={label}>
                <StepLabel>{label}</StepLabel>
                <StepContent>
                  {renderStepContent(index)}
                  <Box sx={{ mb: 2, mt: 2 }}>
                    <Button
                      variant="contained"
                      onClick={index === steps.length - 1 ? handleLaunchSimulation : handleNext}
                      sx={{ mt: 1, mr: 1 }}
                      disabled={
                        (index === 0 && !newSimulation.name) ||
                        (index === 1 && newSimulation.targetGroups.length === 0)
                      }
                    >
                      {index === steps.length - 1 ? 'Launch Simulation' : 'Continue'}
                    </Button>
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
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>
            Cancel
          </Button>
        </DialogActions>
      </Dialog>

      {/* View Simulation Dialog */}
      <Dialog
        open={viewDialogOpen}
        onClose={() => setViewDialogOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>
          {selectedSimulation?.name}
        </DialogTitle>
        <DialogContent>
          {selectedSimulation && (
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Progress Overview
                    </Typography>
                    <LinearProgress 
                      variant="determinate" 
                      value={selectedSimulation.progress}
                      sx={{ height: 10, borderRadius: 5, mb: 2 }}
                    />
                    <Typography variant="h4" align="center" color="primary">
                      {selectedSimulation.progress}%
                    </Typography>
                    <Typography variant="body2" align="center" color="textSecondary">
                      Completion Rate
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Performance Metrics
                    </Typography>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">Responded</Typography>
                        <Typography variant="h5">{selectedSimulation.responded}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">Failed</Typography>
                        <Typography variant="h5" color="error">{selectedSimulation.failed}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">Reported</Typography>
                        <Typography variant="h5" color="success">{selectedSimulation.reported}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="textSecondary">Success Rate</Typography>
                        <Typography 
                          variant="h5" 
                          color={`${getSuccessRateColor(selectedSimulation.success_rate)}.main`}
                        >
                          {selectedSimulation.success_rate.toFixed(1)}%
                        </Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViewDialogOpen(false)}>
            Close
          </Button>
          <Button variant="contained" startIcon={<AssessmentIcon />}>
            View Full Report
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default SimulationPanel;
