/**
 * Error Fallback Component
 * 
 * Displays error boundaries and error states
 */

import React from 'react';
import PropTypes from 'prop-types';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Alert,
  AlertTitle,
} from '@mui/material';
import { Refresh, BugReport } from '@mui/icons-material';

const ErrorFallback = ({ error, resetErrorBoundary }) => {
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '400px',
        p: 2,
      }}
    >
      <Card sx={{ maxWidth: 500, width: '100%' }}>
        <CardContent sx={{ textAlign: 'center', p: 3 }}>
          <BugReport sx={{ fontSize: 60, color: 'error.main', mb: 2 }} />
          
          <Typography variant="h5" component="h2" gutterBottom>
            Something went wrong
          </Typography>
          
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            We're sorry, but an unexpected error occurred. Please try refreshing the page or contact support if the problem persists.
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 3, textAlign: 'left' }}>
              <AlertTitle>Error Details</AlertTitle>
              <Typography variant="body2" component="pre" sx={{ fontSize: '0.75rem' }}>
                {error.message}
              </Typography>
            </Alert>
          )}

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
            <Button
              variant="contained"
              startIcon={<Refresh />}
              onClick={resetErrorBoundary}
            >
              Try Again
            </Button>
            
            <Button
              variant="outlined"
              onClick={() => window.location.reload()}
            >
              Reload Page
            </Button>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

ErrorFallback.propTypes = {
  error: PropTypes.shape({
    message: PropTypes.string,
    stack: PropTypes.string,
  }),
  resetErrorBoundary: PropTypes.func.isRequired,
};

export default ErrorFallback;