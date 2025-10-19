import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Slider,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Paper,
  Tooltip,
  CircularProgress,
  ToggleButtonGroup,
  ToggleButton,
  Alert,
  IconButton,
  Badge
} from '@mui/material';
import {
  ThermostatIcon,
  ZoomInIcon,
  ZoomOutIcon,
  CenterFocusStrongIcon,
  FilterListIcon,
  RefreshIcon,
  ViewModuleIcon,
  GridViewIcon,
  MapIcon
} from '@mui/icons-material';

const Heatmap = ({ 
  title = "Threat Activity Heatmap",
  dataType = "geographic", // geographic, temporal, network
  refreshInterval = 30000,
  height = 500,
  interactive = true 
}) => {
  const [loading, setLoading] = useState(true);
  const [heatmapData, setHeatmapData] = useState([]);
  const [viewMode, setViewMode] = useState('grid');
  const [zoomLevel, setZoomLevel] = useState(1);
  const [selectedMetric, setSelectedMetric] = useState('threat_count');
  const [timeRange, setTimeRange] = useState('24h');
  const [selectedCell, setSelectedCell] = useState(null);
  const [maxValue, setMaxValue] = useState(100);
  const [colorScheme, setColorScheme] = useState('heat');

  const metrics = [
    { value: 'threat_count', label: 'Threat Count', unit: '' },
    { value: 'risk_score', label: 'Average Risk Score', unit: '%' },
    { value: 'attack_frequency', label: 'Attack Frequency', unit: '/hr' },
    { value: 'blocked_ips', label: 'Blocked IPs', unit: '' },
    { value: 'malware_detected', label: 'Malware Detected', unit: '' }
  ];

  const colorSchemes = {
    heat: {
      name: 'Heat',
      colors: ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D']
    },
    security: {
      name: 'Security',
      colors: ['#4CAF50', '#FFC107', '#FF9800', '#F44336']
    },
    ocean: {
      name: 'Ocean',
      colors: ['#E8F4FD', '#4FC3F7', '#29B6F6', '#0277BD']
    },
    monochrome: {
      name: 'Monochrome',
      colors: ['#F5F5F5', '#BDBDBD', '#757575', '#212121']
    }
  };

  useEffect(() => {
    fetchHeatmapData();
    
    if (refreshInterval > 0) {
      const interval = setInterval(fetchHeatmapData, refreshInterval);
      return () => clearInterval(interval);
    }
  }, [dataType, selectedMetric, timeRange, refreshInterval]);

  const fetchHeatmapData = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      const mockData = generateHeatmapData(dataType, selectedMetric, timeRange);
      setHeatmapData(mockData);
      setMaxValue(Math.max(...mockData.map(cell => cell.value)));
    } catch (error) {
      console.error('Error fetching heatmap data:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateHeatmapData = (type, metric, range) => {
    const data = [];
    
    if (type === 'geographic') {
      // Generate geographic grid (representing regions/countries)
      const regions = [
        'North America', 'South America', 'Europe', 'Africa', 
        'Asia', 'Oceania', 'Middle East', 'Caribbean'
      ];
      
      regions.forEach((region, regionIndex) => {
        for (let i = 0; i < 8; i++) {
          for (let j = 0; j < 12; j++) {
            const value = Math.floor(Math.random() * 100);
            data.push({
              x: j,
              y: regionIndex,
              value: value,
              region: region,
              label: `${region} (${i},${j})`,
              details: {
                threats: Math.floor(value * 0.8),
                blocked: Math.floor(value * 0.2),
                countries: Math.floor(Math.random() * 20) + 1
              }
            });
          }
        }
      });
    } else if (type === 'temporal') {
      // Generate time-based heatmap (24h x 7 days)
      const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
      
      days.forEach((day, dayIndex) => {
        for (let hour = 0; hour < 24; hour++) {
          // Simulate higher activity during business hours
          const businessHours = hour >= 9 && hour <= 17;
          const baseValue = businessHours ? 60 : 20;
          const value = baseValue + Math.floor(Math.random() * 40);
          
          data.push({
            x: hour,
            y: dayIndex,
            value: value,
            day: day,
            hour: hour,
            label: `${day} ${hour}:00`,
            details: {
              threats: Math.floor(value * 0.7),
              emails: Math.floor(value * 15),
              avgRisk: Math.floor(Math.random() * 30) + 50
            }
          });
        }
      });
    } else if (type === 'network') {
      // Generate network topology heatmap (IP ranges/subnets)
      const subnets = ['192.168.1', '192.168.2', '10.0.1', '10.0.2', '172.16.1', '172.16.2'];
      
      subnets.forEach((subnet, subnetIndex) => {
        for (let i = 1; i <= 16; i++) {
          for (let j = 1; j <= 16; j++) {
            const value = Math.floor(Math.random() * 80);
            data.push({
              x: j - 1,
              y: subnetIndex * 16 + i - 1,
              value: value,
              subnet: subnet,
              ip: `${subnet}.${i * 16 + j}`,
              label: `${subnet}.${i * 16 + j}`,
              details: {
                connections: Math.floor(value * 2),
                blocked: Math.floor(value * 0.1),
                reputation: Math.floor(Math.random() * 100)
              }
            });
          }
        }
      });
    }

    return data;
  };

  const getIntensityColor = (value, scheme = colorScheme) => {
    if (value === 0) return '#f5f5f5';
    
    const colors = colorSchemes[scheme].colors;
    const intensity = Math.min(value / maxValue, 1);
    
    if (intensity <= 0.25) return colors[0];
    if (intensity <= 0.5) return colors[1];
    if (intensity <= 0.75) return colors[2];
    return colors[3];
  };

  const handleCellClick = (cell) => {
    if (interactive) {
      setSelectedCell(cell);
    }
  };

  const handleZoom = (direction) => {
    const newZoom = direction === 'in' 
      ? Math.min(zoomLevel + 0.2, 3) 
      : Math.max(zoomLevel - 0.2, 0.5);
    setZoomLevel(newZoom);
  };

  const renderGridHeatmap = () => {
    const gridSize = dataType === 'temporal' ? { cols: 24, rows: 7 } 
                   : dataType === 'geographic' ? { cols: 12, rows: 8 }
                   : { cols: 16, rows: 6 };

    return (
      <Box 
        sx={{ 
          display: 'grid',
          gridTemplateColumns: `repeat(${gridSize.cols}, 1fr)`,
          gridTemplateRows: `repeat(${gridSize.rows}, 1fr)`,
          gap: 1,
          p: 2,
          transform: `scale(${zoomLevel})`,
          transformOrigin: 'top left',
          transition: 'transform 0.3s ease'
        }}
      >
        {heatmapData.map((cell, index) => (
          <Tooltip
            key={index}
            title={
              <Box>
                <Typography variant="subtitle2">{cell.label}</Typography>
                <Typography variant="body2">
                  {selectedMetric.replace('_', ' ')}: {cell.value}
                  {metrics.find(m => m.value === selectedMetric)?.unit}
                </Typography>
                {cell.details && Object.entries(cell.details).map(([key, value]) => (
                  <Typography key={key} variant="caption" display="block">
                    {key}: {value}
                  </Typography>
                ))}
              </Box>
            }
            arrow
          >
            <Paper
              sx={{
                aspectRatio: '1',
                backgroundColor: getIntensityColor(cell.value),
                cursor: interactive ? 'pointer' : 'default',
                border: selectedCell?.x === cell.x && selectedCell?.y === cell.y 
                  ? '2px solid #1976d2' : 'none',
                borderRadius: 0.5,
                transition: 'all 0.2s ease',
                '&:hover': interactive ? {
                  transform: 'scale(1.1)',
                  zIndex: 1,
                  boxShadow: 2
                } : {}
              }}
              onClick={() => handleCellClick(cell)}
            />
          </Tooltip>
        ))}
      </Box>
    );
  };

  const renderLegend = () => {
    const steps = 5;
    const stepValue = maxValue / steps;

    return (
      <Box display="flex" alignItems="center" gap={2} mt={2}>
        <Typography variant="body2" color="textSecondary">
          Low
        </Typography>
        <Box display="flex" gap={1}>
          {Array.from({ length: steps }, (_, i) => (
            <Box
              key={i}
              sx={{
                width: 20,
                height: 10,
                backgroundColor: getIntensityColor(i * stepValue),
                border: '1px solid #e0e0e0'
              }}
            />
          ))}
        </Box>
        <Typography variant="body2" color="textSecondary">
          High
        </Typography>
        <Typography variant="body2" color="textSecondary" ml={2}>
          Max: {Math.round(maxValue)}
        </Typography>
      </Box>
    );
  };

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="center" alignItems="center" height={height}>
            <CircularProgress size={60} />
          </Box>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent>
        <Box mb={2}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6" component="div">
              {title}
            </Typography>
            <Box display="flex" gap={1}>
              <IconButton size="small" onClick={() => handleZoom('out')}>
                <ZoomOutIcon />
              </IconButton>
              <IconButton size="small" onClick={() => setZoomLevel(1)}>
                <CenterFocusStrongIcon />
              </IconButton>
              <IconButton size="small" onClick={() => handleZoom('in')}>
                <ZoomInIcon />
              </IconButton>
              <IconButton size="small" onClick={fetchHeatmapData}>
                <RefreshIcon />
              </IconButton>
            </Box>
          </Box>

          {/* Controls */}
          <Grid container spacing={2} mb={2} alignItems="center">
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Metric</InputLabel>
                <Select
                  value={selectedMetric}
                  label="Metric"
                  onChange={(e) => setSelectedMetric(e.target.value)}
                >
                  {metrics.map((metric) => (
                    <MenuItem key={metric.value} value={metric.value}>
                      {metric.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Time Range</InputLabel>
                <Select
                  value={timeRange}
                  label="Time Range"
                  onChange={(e) => setTimeRange(e.target.value)}
                >
                  <MenuItem value="1h">Last Hour</MenuItem>
                  <MenuItem value="24h">Last 24 Hours</MenuItem>
                  <MenuItem value="7d">Last 7 Days</MenuItem>
                  <MenuItem value="30d">Last 30 Days</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Color Scheme</InputLabel>
                <Select
                  value={colorScheme}
                  label="Color Scheme"
                  onChange={(e) => setColorScheme(e.target.value)}
                >
                  {Object.entries(colorSchemes).map(([key, scheme]) => (
                    <MenuItem key={key} value={key}>
                      {scheme.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <ToggleButtonGroup
                value={viewMode}
                exclusive
                onChange={(e, newMode) => newMode && setViewMode(newMode)}
                size="small"
              >
                <ToggleButton value="grid">
                  <GridViewIcon />
                </ToggleButton>
                <ToggleButton value="density">
                  <ViewModuleIcon />
                </ToggleButton>
              </ToggleButtonGroup>
            </Grid>
          </Grid>

          {/* Activity Summary */}
          <Grid container spacing={2} mb={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 1, textAlign: 'center', bgcolor: 'error.50' }}>
                <Typography variant="h6" color="error.main">
                  {heatmapData.filter(cell => cell.value > maxValue * 0.75).length}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  High Activity Zones
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 1, textAlign: 'center', bgcolor: 'warning.50' }}>
                <Typography variant="h6" color="warning.main">
                  {heatmapData.filter(cell => cell.value > maxValue * 0.5 && cell.value <= maxValue * 0.75).length}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Medium Activity Zones
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 1, textAlign: 'center', bgcolor: 'success.50' }}>
                <Typography variant="h6" color="success.main">
                  {heatmapData.filter(cell => cell.value <= maxValue * 0.25).length}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Low Activity Zones
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 1, textAlign: 'center', bgcolor: 'info.50' }}>
                <Typography variant="h6" color="info.main">
                  {Math.round(heatmapData.reduce((sum, cell) => sum + cell.value, 0) / heatmapData.length)}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Average Activity
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Box>

        {/* Heatmap Visualization */}
        <Box 
          sx={{ 
            height: height,
            overflow: 'auto',
            border: '1px solid #e0e0e0',
            borderRadius: 1,
            bgcolor: '#fafafa'
          }}
        >
          {renderGridHeatmap()}
        </Box>

        {/* Legend */}
        {renderLegend()}

        {/* Selected Cell Details */}
        {selectedCell && (
          <Alert 
            severity="info" 
            sx={{ mt: 2 }}
            onClose={() => setSelectedCell(null)}
          >
            <Typography variant="subtitle2" gutterBottom>
              {selectedCell.label}
            </Typography>
            <Box display="flex" flexWrap="wrap" gap={1}>
              <Chip 
                label={`${selectedMetric.replace('_', ' ')}: ${selectedCell.value}`}
                color="primary"
                size="small"
              />
              {selectedCell.details && Object.entries(selectedCell.details).map(([key, value]) => (
                <Chip 
                  key={key}
                  label={`${key}: ${value}`}
                  variant="outlined"
                  size="small"
                />
              ))}
            </Box>
          </Alert>
        )}

        {/* Data Type Indicator */}
        <Box display="flex" alignItems="center" gap={1} mt={2}>
          <MapIcon color="action" fontSize="small" />
          <Typography variant="body2" color="textSecondary">
            Viewing {dataType} threat activity | 
            Updated {new Date().toLocaleTimeString()} |
            {heatmapData.length} data points
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
};

export default Heatmap;
