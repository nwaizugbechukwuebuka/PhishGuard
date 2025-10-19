/**
 * Loading Spinner Component
 * 
 * Displays a loading spinner with optional text
 */

import React from 'react';
import PropTypes from 'prop-types';
import { Box, CircularProgress, Typography } from '@mui/material';

const LoadingSpinner = ({ message = 'Loading...', size = 40 }) => {
  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '200px',
        gap: 2,
      }}
    >
      <CircularProgress size={size} />
      {message && (
        <Typography variant="body2" color="text.secondary">
          {message}
        </Typography>
      )}
    </Box>
  );
};

LoadingSpinner.propTypes = {
  message: PropTypes.string,
  size: PropTypes.number,
};

LoadingSpinner.defaultProps = {
  message: 'Loading...',
  size: 40,
};

export default LoadingSpinner;