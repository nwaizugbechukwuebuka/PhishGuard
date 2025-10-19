import React, { useState, useEffect, useMemo } from 'react';
import {
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  Toolbar,
  Typography,
  Checkbox,
  IconButton,
  Tooltip,
  Box,
  Chip,
  Button,
  TextField,
  InputAdornment,
  Menu,
  MenuItem,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Snackbar,
  CircularProgress,
  FormControl,
  InputLabel,
  Select,
  Collapse
} from '@mui/material';
import {
  Delete as DeleteIcon,
  FilterList as FilterListIcon,
  Search as SearchIcon,
  Visibility as VisibilityIcon,
  GetApp as GetAppIcon,
  Restore as RestoreIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Email as EmailIcon,
  AttachFile as AttachFileIcon,
  Link as LinkIcon,
  Schedule as ScheduleIcon
} from '@mui/icons-material';
import { visuallyHidden } from '@mui/utils';

const QuarantineTable = () => {
  const [order, setOrder] = useState('desc');
  const [orderBy, setOrderBy] = useState('timestamp');
  const [selected, setSelected] = useState([]);
  const [page, setPage] = useState(0);
  const [dense, setDense] = useState(false);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterAnchorEl, setFilterAnchorEl] = useState(null);
  const [filters, setFilters] = useState({
    status: 'all',
    threatType: 'all',
    riskLevel: 'all',
    dateRange: 'all'
  });
  const [quarantineData, setQuarantineData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [viewDialogOpen, setViewDialogOpen] = useState(false);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [actionDialogOpen, setActionDialogOpen] = useState(false);
  const [actionType, setActionType] = useState('');
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'info' });
  const [expandedRows, setExpandedRows] = useState(new Set());

  const headCells = [
    { id: 'select', numeric: false, disablePadding: true, label: '' },
    { id: 'timestamp', numeric: false, disablePadding: false, label: 'Date/Time' },
    { id: 'sender', numeric: false, disablePadding: false, label: 'Sender' },
    { id: 'recipient', numeric: false, disablePadding: false, label: 'Recipient' },
    { id: 'subject', numeric: false, disablePadding: false, label: 'Subject' },
    { id: 'threatType', numeric: false, disablePadding: false, label: 'Threat Type' },
    { id: 'riskScore', numeric: true, disablePadding: false, label: 'Risk Score' },
    { id: 'status', numeric: false, disablePadding: false, label: 'Status' },
    { id: 'actions', numeric: false, disablePadding: false, label: 'Actions' }
  ];

  useEffect(() => {
    fetchQuarantineData();
  }, []);

  const fetchQuarantineData = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      const mockData = [
        {
          id: '1',
          timestamp: new Date('2024-01-15T10:30:00'),
          sender: 'ceo@fake-company.com',
          recipient: 'finance@company.com',
          subject: 'URGENT: Wire Transfer Required - CEO Authorization',
          threatType: 'CEO Impersonation',
          riskScore: 95,
          status: 'quarantined',
          attachments: ['invoice_final.pdf', 'bank_details.xlsx'],
          links: ['https://fake-bank-portal.com/login'],
          size: '2.3 MB',
          aiConfidence: 97,
          reasonFlags: ['Sender domain mismatch', 'Urgent language patterns', 'Financial request', 'External links'],
          quarantineReason: 'High-confidence phishing attempt detected by AI engine'
        },
        {
          id: '2',
          timestamp: new Date('2024-01-15T09:45:00'),
          sender: 'noreply@microsoft-security.com',
          recipient: 'john.doe@company.com',
          subject: 'Security Alert: Suspicious Sign-in Attempt',
          threatType: 'Brand Impersonation',
          riskScore: 88,
          status: 'quarantined',
          attachments: [],
          links: ['https://fake-microsoft.com/security'],
          size: '145 KB',
          aiConfidence: 92,
          reasonFlags: ['Suspicious domain', 'Brand impersonation', 'Credential harvesting'],
          quarantineReason: 'Brand impersonation with credential harvesting attempt'
        },
        {
          id: '3',
          timestamp: new Date('2024-01-15T08:20:00'),
          sender: 'hr@company.com',
          recipient: 'all-staff@company.com',
          subject: 'Employee Benefits Update - Action Required',
          threatType: 'Suspicious Content',
          riskScore: 45,
          status: 'pending_review',
          attachments: ['benefits_form.docx'],
          links: [],
          size: '892 KB',
          aiConfidence: 68,
          reasonFlags: ['Internal sender', 'Unusual distribution', 'Form attachment'],
          quarantineReason: 'Suspicious distribution pattern from internal account'
        },
        {
          id: '4',
          timestamp: new Date('2024-01-14T16:30:00'),
          sender: 'support@paypal-security.org',
          recipient: 'accounting@company.com',
          subject: 'Account Verification Required - Immediate Action',
          threatType: 'Phishing',
          riskScore: 92,
          status: 'released',
          attachments: [],
          links: ['https://fake-paypal.org/verify'],
          size: '203 KB',
          aiConfidence: 94,
          reasonFlags: ['Domain spoofing', 'Urgent action required', 'Account verification'],
          quarantineReason: 'Classic phishing attempt with domain spoofing'
        },
        {
          id: '5',
          timestamp: new Date('2024-01-14T14:15:00'),
          sender: 'malware@suspicious-domain.ru',
          recipient: 'it@company.com',
          subject: 'System Update Package - Install Immediately',
          threatType: 'Malware',
          riskScore: 99,
          status: 'deleted',
          attachments: ['system_update.exe', 'install_guide.pdf'],
          links: ['https://malicious-site.ru/download'],
          size: '15.7 MB',
          aiConfidence: 99,
          reasonFlags: ['Executable attachment', 'Suspicious TLD', 'Malware signature match'],
          quarantineReason: 'Confirmed malware payload detected in attachments'
        }
      ];

      setQuarantineData(mockData);
    } catch (error) {
      console.error('Error fetching quarantine data:', error);
      setSnackbar({
        open: true,
        message: 'Error loading quarantine data',
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRequestSort = (property) => {
    const isAsc = orderBy === property && order === 'asc';
    setOrder(isAsc ? 'desc' : 'asc');
    setOrderBy(property);
  };

  const handleSelectAllClick = (event) => {
    if (event.target.checked) {
      const newSelecteds = filteredData.map((n) => n.id);
      setSelected(newSelecteds);
      return;
    }
    setSelected([]);
  };

  const handleClick = (id) => {
    const selectedIndex = selected.indexOf(id);
    let newSelected = [];

    if (selectedIndex === -1) {
      newSelected = newSelected.concat(selected, id);
    } else if (selectedIndex === 0) {
      newSelected = newSelected.concat(selected.slice(1));
    } else if (selectedIndex === selected.length - 1) {
      newSelected = newSelected.concat(selected.slice(0, -1));
    } else if (selectedIndex > 0) {
      newSelected = newSelected.concat(
        selected.slice(0, selectedIndex),
        selected.slice(selectedIndex + 1),
      );
    }

    setSelected(newSelected);
  };

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleFilterClick = (event) => {
    setFilterAnchorEl(event.currentTarget);
  };

  const handleFilterClose = () => {
    setFilterAnchorEl(null);
  };

  const handleFilterChange = (filterType, value) => {
    setFilters(prev => ({ ...prev, [filterType]: value }));
    setPage(0);
  };

  const handleViewEmail = (email) => {
    setSelectedEmail(email);
    setViewDialogOpen(true);
  };

  const handleAction = (type, emailIds = null) => {
    setActionType(type);
    if (emailIds) {
      setSelected([emailIds]);
    }
    setActionDialogOpen(true);
  };

  const executeAction = async () => {
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      const actionMessages = {
        delete: 'Emails permanently deleted',
        restore: 'Emails restored to inbox',
        release: 'Emails released from quarantine'
      };

      setSnackbar({
        open: true,
        message: actionMessages[actionType] || 'Action completed',
        severity: 'success'
      });

      // Update local data
      if (actionType === 'delete') {
        setQuarantineData(prev => prev.filter(email => !selected.includes(email.id)));
      } else if (actionType === 'restore' || actionType === 'release') {
        setQuarantineData(prev => prev.map(email => 
          selected.includes(email.id) 
            ? { ...email, status: actionType === 'restore' ? 'released' : 'released' }
            : email
        ));
      }

      setSelected([]);
      setActionDialogOpen(false);
    } catch (error) {
      setSnackbar({
        open: true,
        message: 'Error performing action',
        severity: 'error'
      });
    }
  };

  const handleExpandRow = (id) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedRows(newExpanded);
  };

  const filteredData = useMemo(() => {
    return quarantineData.filter(email => {
      const matchesSearch = !searchTerm || 
        email.sender.toLowerCase().includes(searchTerm.toLowerCase()) ||
        email.recipient.toLowerCase().includes(searchTerm.toLowerCase()) ||
        email.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
        email.threatType.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesStatus = filters.status === 'all' || email.status === filters.status;
      const matchesThreatType = filters.threatType === 'all' || email.threatType === filters.threatType;
      const matchesRiskLevel = filters.riskLevel === 'all' || 
        (filters.riskLevel === 'high' && email.riskScore >= 80) ||
        (filters.riskLevel === 'medium' && email.riskScore >= 50 && email.riskScore < 80) ||
        (filters.riskLevel === 'low' && email.riskScore < 50);

      return matchesSearch && matchesStatus && matchesThreatType && matchesRiskLevel;
    });
  }, [quarantineData, searchTerm, filters]);

  const sortedData = useMemo(() => {
    return [...filteredData].sort((a, b) => {
      if (orderBy === 'timestamp') {
        return order === 'asc' 
          ? new Date(a.timestamp) - new Date(b.timestamp)
          : new Date(b.timestamp) - new Date(a.timestamp);
      }
      if (orderBy === 'riskScore') {
        return order === 'asc' ? a.riskScore - b.riskScore : b.riskScore - a.riskScore;
      }
      const aValue = a[orderBy]?.toString().toLowerCase() || '';
      const bValue = b[orderBy]?.toString().toLowerCase() || '';
      return order === 'asc' 
        ? aValue.localeCompare(bValue)
        : bValue.localeCompare(aValue);
    });
  }, [filteredData, order, orderBy]);

  const paginatedData = useMemo(() => {
    return sortedData.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);
  }, [sortedData, page, rowsPerPage]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'quarantined':
        return 'error';
      case 'pending_review':
        return 'warning';
      case 'released':
        return 'success';
      case 'deleted':
        return 'default';
      default:
        return 'default';
    }
  };

  const getRiskLevelColor = (score) => {
    if (score >= 80) return 'error';
    if (score >= 50) return 'warning';
    return 'info';
  };

  const formatTimestamp = (timestamp) => {
    return timestamp.toLocaleString();
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box sx={{ width: '100%' }}>
      <Paper sx={{ width: '100%', mb: 2 }}>
        {/* Toolbar */}
        <Toolbar sx={{ pl: { sm: 2 }, pr: { xs: 1, sm: 1 } }}>
          {selected.length > 0 ? (
            <Typography
              sx={{ flex: '1 1 100%' }}
              color="inherit"
              variant="subtitle1"
              component="div"
            >
              {selected.length} selected
            </Typography>
          ) : (
            <Typography
              sx={{ flex: '1 1 100%' }}
              variant="h6"
              id="tableTitle"
              component="div"
            >
              Quarantined Emails
            </Typography>
          )}

          {selected.length > 0 ? (
            <Box display="flex" gap={1}>
              <Tooltip title="Delete">
                <IconButton onClick={() => handleAction('delete')}>
                  <DeleteIcon />
                </IconButton>
              </Tooltip>
              <Tooltip title="Restore">
                <IconButton onClick={() => handleAction('restore')}>
                  <RestoreIcon />
                </IconButton>
              </Tooltip>
            </Box>
          ) : (
            <Box display="flex" gap={2} alignItems="center">
              <TextField
                placeholder="Search emails..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                size="small"
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                }}
              />
              <Tooltip title="Filter list">
                <IconButton onClick={handleFilterClick}>
                  <FilterListIcon />
                </IconButton>
              </Tooltip>
            </Box>
          )}
        </Toolbar>

        {/* Filter Menu */}
        <Menu
          anchorEl={filterAnchorEl}
          open={Boolean(filterAnchorEl)}
          onClose={handleFilterClose}
        >
          <Box sx={{ p: 2, minWidth: 300 }}>
            <Typography variant="subtitle2" gutterBottom>
              Filters
            </Typography>
            <FormControl fullWidth size="small" sx={{ mb: 2 }}>
              <InputLabel>Status</InputLabel>
              <Select
                value={filters.status}
                label="Status"
                onChange={(e) => handleFilterChange('status', e.target.value)}
              >
                <MenuItem value="all">All Status</MenuItem>
                <MenuItem value="quarantined">Quarantined</MenuItem>
                <MenuItem value="pending_review">Pending Review</MenuItem>
                <MenuItem value="released">Released</MenuItem>
                <MenuItem value="deleted">Deleted</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth size="small" sx={{ mb: 2 }}>
              <InputLabel>Threat Type</InputLabel>
              <Select
                value={filters.threatType}
                label="Threat Type"
                onChange={(e) => handleFilterChange('threatType', e.target.value)}
              >
                <MenuItem value="all">All Types</MenuItem>
                <MenuItem value="Phishing">Phishing</MenuItem>
                <MenuItem value="Malware">Malware</MenuItem>
                <MenuItem value="CEO Impersonation">CEO Impersonation</MenuItem>
                <MenuItem value="Brand Impersonation">Brand Impersonation</MenuItem>
                <MenuItem value="Suspicious Content">Suspicious Content</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth size="small">
              <InputLabel>Risk Level</InputLabel>
              <Select
                value={filters.riskLevel}
                label="Risk Level"
                onChange={(e) => handleFilterChange('riskLevel', e.target.value)}
              >
                <MenuItem value="all">All Levels</MenuItem>
                <MenuItem value="high">High (80-100)</MenuItem>
                <MenuItem value="medium">Medium (50-79)</MenuItem>
                <MenuItem value="low">Low (0-49)</MenuItem>
              </Select>
            </FormControl>
          </Box>
        </Menu>

        {/* Table */}
        <TableContainer>
          <Table
            sx={{ minWidth: 750 }}
            aria-labelledby="tableTitle"
            size={dense ? 'small' : 'medium'}
          >
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    color="primary"
                    indeterminate={selected.length > 0 && selected.length < filteredData.length}
                    checked={filteredData.length > 0 && selected.length === filteredData.length}
                    onChange={handleSelectAllClick}
                    inputProps={{ 'aria-label': 'select all emails' }}
                  />
                </TableCell>
                <TableCell />
                {headCells.slice(2).map((headCell) => (
                  <TableCell
                    key={headCell.id}
                    align={headCell.numeric ? 'right' : 'left'}
                    padding={headCell.disablePadding ? 'none' : 'normal'}
                    sortDirection={orderBy === headCell.id ? order : false}
                  >
                    {headCell.id !== 'actions' ? (
                      <TableSortLabel
                        active={orderBy === headCell.id}
                        direction={orderBy === headCell.id ? order : 'asc'}
                        onClick={() => handleRequestSort(headCell.id)}
                      >
                        {headCell.label}
                        {orderBy === headCell.id ? (
                          <Box component="span" sx={visuallyHidden}>
                            {order === 'desc' ? 'sorted descending' : 'sorted ascending'}
                          </Box>
                        ) : null}
                      </TableSortLabel>
                    ) : (
                      headCell.label
                    )}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {paginatedData.map((row) => {
                const isItemSelected = selected.indexOf(row.id) !== -1;
                const isExpanded = expandedRows.has(row.id);

                return (
                  <React.Fragment key={row.id}>
                    <TableRow
                      hover
                      role="checkbox"
                      aria-checked={isItemSelected}
                      tabIndex={-1}
                      selected={isItemSelected}
                    >
                      <TableCell padding="checkbox">
                        <Checkbox
                          color="primary"
                          checked={isItemSelected}
                          onChange={() => handleClick(row.id)}
                          inputProps={{ 'aria-labelledby': `enhanced-table-checkbox-${row.id}` }}
                        />
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleExpandRow(row.id)}
                        >
                          {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                        </IconButton>
                      </TableCell>
                      <TableCell>{formatTimestamp(row.timestamp)}</TableCell>
                      <TableCell>{row.sender}</TableCell>
                      <TableCell>{row.recipient}</TableCell>
                      <TableCell>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                          {row.subject}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={row.threatType}
                          size="small"
                          color={getRiskLevelColor(row.riskScore)}
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Box display="flex" alignItems="center" justifyContent="flex-end">
                          <Typography variant="body2" sx={{ mr: 1 }}>
                            {row.riskScore}
                          </Typography>
                          <Chip
                            label={`${row.riskScore}%`}
                            size="small"
                            color={getRiskLevelColor(row.riskScore)}
                            variant="outlined"
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={row.status.replace('_', ' ')}
                          size="small"
                          color={getStatusColor(row.status)}
                        />
                      </TableCell>
                      <TableCell>
                        <Box display="flex" gap={1}>
                          <Tooltip title="View Details">
                            <IconButton
                              size="small"
                              onClick={() => handleViewEmail(row)}
                            >
                              <VisibilityIcon />
                            </IconButton>
                          </Tooltip>
                          {row.status === 'quarantined' && (
                            <Tooltip title="Release">
                              <IconButton
                                size="small"
                                onClick={() => handleAction('release', row.id)}
                              >
                                <RestoreIcon />
                              </IconButton>
                            </Tooltip>
                          )}
                          <Tooltip title="Delete">
                            <IconButton
                              size="small"
                              onClick={() => handleAction('delete', row.id)}
                            >
                              <DeleteIcon />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                    
                    {/* Expanded Row Details */}
                    <TableRow>
                      <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={9}>
                        <Collapse in={isExpanded} timeout="auto" unmountOnExit>
                          <Box sx={{ margin: 1, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
                            <Typography variant="h6" gutterBottom component="div">
                              Email Details
                            </Typography>
                            
                            <Box display="flex" flexWrap="wrap" gap={3} mb={2}>
                              <Box>
                                <Typography variant="subtitle2">AI Confidence</Typography>
                                <Typography variant="body2">{row.aiConfidence}%</Typography>
                              </Box>
                              <Box>
                                <Typography variant="subtitle2">Email Size</Typography>
                                <Typography variant="body2">{row.size}</Typography>
                              </Box>
                              <Box>
                                <Typography variant="subtitle2">Attachments</Typography>
                                <Typography variant="body2">
                                  {row.attachments.length > 0 ? row.attachments.join(', ') : 'None'}
                                </Typography>
                              </Box>
                              <Box>
                                <Typography variant="subtitle2">External Links</Typography>
                                <Typography variant="body2">
                                  {row.links.length > 0 ? row.links.length + ' links detected' : 'None'}
                                </Typography>
                              </Box>
                            </Box>

                            <Box mb={2}>
                              <Typography variant="subtitle2" gutterBottom>
                                Quarantine Reason
                              </Typography>
                              <Typography variant="body2">
                                {row.quarantineReason}
                              </Typography>
                            </Box>

                            <Box>
                              <Typography variant="subtitle2" gutterBottom>
                                Detection Flags
                              </Typography>
                              <Box display="flex" flexWrap="wrap" gap={1}>
                                {row.reasonFlags.map((flag, index) => (
                                  <Chip
                                    key={index}
                                    label={flag}
                                    size="small"
                                    variant="outlined"
                                    color="warning"
                                  />
                                ))}
                              </Box>
                            </Box>
                          </Box>
                        </Collapse>
                      </TableCell>
                    </TableRow>
                  </React.Fragment>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
        
        <TablePagination
          rowsPerPageOptions={[10, 25, 50, 100]}
          component="div"
          count={filteredData.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Paper>

      {/* View Email Dialog */}
      <Dialog
        open={viewDialogOpen}
        onClose={() => setViewDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Email Details
        </DialogTitle>
        <DialogContent>
          {selectedEmail && (
            <Box>
              <Typography variant="h6" gutterBottom>
                {selectedEmail.subject}
              </Typography>
              <Box display="flex" flexDirection="column" gap={2}>
                <Box>
                  <Typography variant="subtitle2">From:</Typography>
                  <Typography variant="body2">{selectedEmail.sender}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2">To:</Typography>
                  <Typography variant="body2">{selectedEmail.recipient}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2">Date:</Typography>
                  <Typography variant="body2">{formatTimestamp(selectedEmail.timestamp)}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2">Risk Assessment:</Typography>
                  <Box display="flex" gap={2} alignItems="center">
                    <Chip
                      label={`${selectedEmail.riskScore}% Risk`}
                      color={getRiskLevelColor(selectedEmail.riskScore)}
                    />
                    <Chip
                      label={selectedEmail.threatType}
                      color="error"
                      variant="outlined"
                    />
                  </Box>
                </Box>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViewDialogOpen(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Action Confirmation Dialog */}
      <Dialog
        open={actionDialogOpen}
        onClose={() => setActionDialogOpen(false)}
      >
        <DialogTitle>
          Confirm Action
        </DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to {actionType} {selected.length} selected email(s)?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setActionDialogOpen(false)}>
            Cancel
          </Button>
          <Button onClick={executeAction} variant="contained" color="primary">
            Confirm
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default QuarantineTable;
