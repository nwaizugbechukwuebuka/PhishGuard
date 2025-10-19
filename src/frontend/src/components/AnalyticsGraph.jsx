import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  Chip,
  LinearProgress,
  CircularProgress,
  ToggleButton,
  ToggleButtonGroup,
  Paper,
  Tooltip
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  ShowChart as ShowChartIcon,
  BarChart as BarChartIcon,
  Timeline as TimelineIcon
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
  PieChart,
  Pie,
  Cell,
  ScatterChart,
  Scatter,
  ComposedChart
} from 'recharts';

const AnalyticsGraph = ({ 
  title = "Security Analytics", 
  dataSource = "threats", 
  timeRange = "7d",
  height = 400,
  showControls = true 
}) => {
  const [chartType, setChartType] = useState('line');
  const [selectedMetric, setSelectedMetric] = useState('all');
  const [selectedTimeRange, setSelectedTimeRange] = useState(timeRange);
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState([]);
  const [summary, setSummary] = useState({});

  const chartTypes = [
    { value: 'line', label: 'Line Chart', icon: <ShowChartIcon /> },
    { value: 'area', label: 'Area Chart', icon: <TimelineIcon /> },
    { value: 'bar', label: 'Bar Chart', icon: <BarChartIcon /> }
  ];

  const timeRanges = [
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
    { value: '90d', label: 'Last 90 Days' }
  ];

  const metrics = {
    threats: [
      { value: 'all', label: 'All Metrics' },
      { value: 'total_threats', label: 'Total Threats' },
      { value: 'phishing', label: 'Phishing Attempts' },
      { value: 'malware', label: 'Malware Detected' },
      { value: 'spam', label: 'Spam Messages' },
      { value: 'false_positives', label: 'False Positives' }
    ],
    performance: [
      { value: 'all', label: 'All Metrics' },
      { value: 'detection_rate', label: 'Detection Rate' },
      { value: 'response_time', label: 'Response Time' },
      { value: 'processing_speed', label: 'Processing Speed' },
      { value: 'system_uptime', label: 'System Uptime' }
    ],
    volume: [
      { value: 'all', label: 'All Metrics' },
      { value: 'total_emails', label: 'Total Emails' },
      { value: 'quarantined', label: 'Quarantined' },
      { value: 'blocked', label: 'Blocked' },
      { value: 'delivered', label: 'Delivered' }
    ]
  };

  useEffect(() => {
    fetchAnalyticsData();
  }, [dataSource, selectedTimeRange, selectedMetric]);

  const fetchAnalyticsData = async () => {
    setLoading(true);
    try {
      // Simulate API call with dynamic data generation
      await new Promise(resolve => setTimeout(resolve, 800));

      const mockData = generateMockData(dataSource, selectedTimeRange, selectedMetric);
      setData(mockData.chartData);
      setSummary(mockData.summary);
    } catch (error) {
      console.error('Error fetching analytics data:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateMockData = (source, range, metric) => {
    const now = new Date();
    const points = range === '24h' ? 24 : range === '7d' ? 7 : range === '30d' ? 30 : 90;
    const interval = range === '24h' ? 'hour' : 'day';

    const chartData = [];
    const summary = { total: 0, trend: 0, peak: 0, average: 0 };

    for (let i = points - 1; i >= 0; i--) {
      const date = new Date(now);
      if (interval === 'hour') {
        date.setHours(date.getHours() - i);
      } else {
        date.setDate(date.getDate() - i);
      }

      const dataPoint = {
        timestamp: date.toISOString(),
        label: interval === 'hour' 
          ? date.getHours() + ':00'
          : date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      };

      if (source === 'threats') {
        const baseThreats = Math.floor(Math.random() * 50) + 10;
        dataPoint.total_threats = baseThreats;
        dataPoint.phishing = Math.floor(baseThreats * 0.6);
        dataPoint.malware = Math.floor(baseThreats * 0.25);
        dataPoint.spam = Math.floor(baseThreats * 0.1);
        dataPoint.false_positives = Math.floor(Math.random() * 5);
        
        summary.total += baseThreats;
        summary.peak = Math.max(summary.peak, baseThreats);
      } else if (source === 'performance') {
        dataPoint.detection_rate = 95 + Math.random() * 5;
        dataPoint.response_time = 0.1 + Math.random() * 0.5;
        dataPoint.processing_speed = 1000 + Math.random() * 500;
        dataPoint.system_uptime = 99 + Math.random() * 1;
        
        summary.total += dataPoint.detection_rate;
        summary.peak = Math.max(summary.peak, dataPoint.detection_rate);
      } else if (source === 'volume') {
        const totalEmails = Math.floor(Math.random() * 2000) + 500;
        dataPoint.total_emails = totalEmails;
        dataPoint.quarantined = Math.floor(totalEmails * 0.02);
        dataPoint.blocked = Math.floor(totalEmails * 0.01);
        dataPoint.delivered = totalEmails - dataPoint.quarantined - dataPoint.blocked;
        
        summary.total += totalEmails;
        summary.peak = Math.max(summary.peak, totalEmails);
      }

      chartData.push(dataPoint);
    }

    summary.average = summary.total / points;
    summary.trend = chartData.length > 1 
      ? ((chartData[chartData.length - 1].total_threats || chartData[chartData.length - 1].total_emails || chartData[chartData.length - 1].detection_rate) - 
         (chartData[0].total_threats || chartData[0].total_emails || chartData[0].detection_rate)) / 
        (chartData[0].total_threats || chartData[0].total_emails || chartData[0].detection_rate) * 100
      : 0;

    return { chartData, summary };
  };

  const getMetricColor = (metric) => {
    const colors = {
      total_threats: '#FF6B6B',
      phishing: '#4ECDC4',
      malware: '#45B7D1',
      spam: '#96CEB4',
      false_positives: '#FECA57',
      detection_rate: '#48CAE4',
      response_time: '#F38BA8',
      processing_speed: '#A8DADC',
      system_uptime: '#81B29A',
      total_emails: '#6C5CE7',
      quarantined: '#FDCB6E',
      blocked: '#E17055',
      delivered: '#00B894'
    };
    return colors[metric] || '#74B9FF';
  };

  const formatMetricValue = (value, metric) => {
    if (metric.includes('rate') || metric.includes('uptime')) {
      return `${value.toFixed(1)}%`;
    } else if (metric.includes('time')) {
      return `${value.toFixed(2)}s`;
    } else if (metric.includes('speed')) {
      return `${Math.round(value)}/s`;
    }
    return Math.round(value).toLocaleString();
  };

  const getTrendIcon = (trend) => {
    if (trend > 0) {
      return <TrendingUpIcon color={dataSource === 'threats' ? 'error' : 'success'} />;
    } else if (trend < 0) {
      return <TrendingDownIcon color={dataSource === 'threats' ? 'success' : 'error'} />;
    }
    return null;
  };

  const renderChart = () => {
    if (loading) {
      return (
        <Box display="flex" justifyContent="center" alignItems="center" height={height}>
          <CircularProgress size={60} />
        </Box>
      );
    }

    const metricsToShow = selectedMetric === 'all' 
      ? Object.keys(metrics[dataSource]).slice(1).map(m => metrics[dataSource][m].value)
      : [selectedMetric];

    const commonProps = {
      width: '100%',
      height: height,
      data: data,
      margin: { top: 20, right: 30, left: 20, bottom: 20 }
    };

    if (chartType === 'line') {
      return (
        <ResponsiveContainer {...commonProps}>
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis 
              dataKey="label" 
              tick={{ fontSize: 12 }}
              axisLine={{ stroke: '#e0e0e0' }}
            />
            <YAxis 
              tick={{ fontSize: 12 }}
              axisLine={{ stroke: '#e0e0e0' }}
            />
            <RechartsTooltip 
              contentStyle={{ 
                backgroundColor: '#fff', 
                border: '1px solid #e0e0e0',
                borderRadius: '4px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
              }}
              formatter={(value, name) => [formatMetricValue(value, name), name.replace('_', ' ')]}
            />
            <Legend />
            {metricsToShow.map((metric, index) => (
              <Line
                key={metric}
                type="monotone"
                dataKey={metric}
                stroke={getMetricColor(metric)}
                strokeWidth={2}
                dot={{ r: 4 }}
                activeDot={{ r: 6 }}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      );
    }

    if (chartType === 'area') {
      return (
        <ResponsiveContainer {...commonProps}>
          <AreaChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis 
              dataKey="label" 
              tick={{ fontSize: 12 }}
              axisLine={{ stroke: '#e0e0e0' }}
            />
            <YAxis 
              tick={{ fontSize: 12 }}
              axisLine={{ stroke: '#e0e0e0' }}
            />
            <RechartsTooltip 
              contentStyle={{ 
                backgroundColor: '#fff', 
                border: '1px solid #e0e0e0',
                borderRadius: '4px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
              }}
              formatter={(value, name) => [formatMetricValue(value, name), name.replace('_', ' ')]}
            />
            <Legend />
            {metricsToShow.map((metric, index) => (
              <Area
                key={metric}
                type="monotone"
                dataKey={metric}
                stackId={selectedMetric === 'all' ? '1' : undefined}
                stroke={getMetricColor(metric)}
                fill={getMetricColor(metric)}
                fillOpacity={0.6}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      );
    }

    if (chartType === 'bar') {
      return (
        <ResponsiveContainer {...commonProps}>
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis 
              dataKey="label" 
              tick={{ fontSize: 12 }}
              axisLine={{ stroke: '#e0e0e0' }}
            />
            <YAxis 
              tick={{ fontSize: 12 }}
              axisLine={{ stroke: '#e0e0e0' }}
            />
            <RechartsTooltip 
              contentStyle={{ 
                backgroundColor: '#fff', 
                border: '1px solid #e0e0e0',
                borderRadius: '4px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
              }}
              formatter={(value, name) => [formatMetricValue(value, name), name.replace('_', ' ')]}
            />
            <Legend />
            {metricsToShow.map((metric, index) => (
              <Bar
                key={metric}
                dataKey={metric}
                fill={getMetricColor(metric)}
                radius={[2, 2, 0, 0]}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      );
    }
  };

  return (
    <Card>
      <CardContent>
        <Box mb={2}>
          <Typography variant="h6" component="div" gutterBottom>
            {title}
          </Typography>
          
          {/* Summary Cards */}
          <Grid container spacing={2} mb={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'primary.50' }}>
                <Typography variant="h4" color="primary.main" fontWeight="bold">
                  {Math.round(summary.total || 0).toLocaleString()}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Total {selectedTimeRange}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'success.50' }}>
                <Typography variant="h4" color="success.main" fontWeight="bold">
                  {Math.round(summary.average || 0).toLocaleString()}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Daily Average
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'warning.50' }}>
                <Typography variant="h4" color="warning.main" fontWeight="bold">
                  {Math.round(summary.peak || 0).toLocaleString()}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Peak Value
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'info.50' }}>
                <Box display="flex" alignItems="center" justifyContent="center" gap={1}>
                  <Typography variant="h4" color="info.main" fontWeight="bold">
                    {summary.trend > 0 ? '+' : ''}{summary.trend.toFixed(1)}%
                  </Typography>
                  {getTrendIcon(summary.trend)}
                </Box>
                <Typography variant="body2" color="textSecondary">
                  Trend
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          {/* Controls */}
          {showControls && (
            <Grid container spacing={2} mb={2} alignItems="center">
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Time Range</InputLabel>
                  <Select
                    value={selectedTimeRange}
                    label="Time Range"
                    onChange={(e) => setSelectedTimeRange(e.target.value)}
                  >
                    {timeRanges.map((range) => (
                      <MenuItem key={range.value} value={range.value}>
                        {range.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Metric</InputLabel>
                  <Select
                    value={selectedMetric}
                    label="Metric"
                    onChange={(e) => setSelectedMetric(e.target.value)}
                  >
                    {metrics[dataSource]?.map((metric) => (
                      <MenuItem key={metric.value} value={metric.value}>
                        {metric.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={12} md={6}>
                <ToggleButtonGroup
                  value={chartType}
                  exclusive
                  onChange={(e, newType) => newType && setChartType(newType)}
                  size="small"
                >
                  {chartTypes.map((type) => (
                    <ToggleButton key={type.value} value={type.value}>
                      <Tooltip title={type.label}>
                        {type.icon}
                      </Tooltip>
                    </ToggleButton>
                  ))}
                </ToggleButtonGroup>
              </Grid>
            </Grid>
          )}

          {/* Loading Progress */}
          {loading && (
            <LinearProgress sx={{ mb: 2 }} />
          )}
        </Box>

        {/* Chart Container */}
        <Box sx={{ width: '100%', height: height }}>
          {renderChart()}
        </Box>

        {/* Metric Legend */}
        {selectedMetric === 'all' && !loading && (
          <Box mt={2}>
            <Typography variant="subtitle2" gutterBottom>
              Metrics Legend
            </Typography>
            <Box display="flex" flexWrap="wrap" gap={1}>
              {metrics[dataSource]?.slice(1).map((metric) => (
                <Chip
                  key={metric.value}
                  label={metric.label}
                  size="small"
                  sx={{
                    bgcolor: getMetricColor(metric.value),
                    color: 'white',
                    '&:hover': {
                      bgcolor: getMetricColor(metric.value),
                      opacity: 0.8
                    }
                  }}
                />
              ))}
            </Box>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default AnalyticsGraph;
