import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { AuthAPI, ApiUtils } from './api';

// Initial authentication state
const initialState = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
  permissions: [],
  preferences: {},
  sessionExpiry: null
};

// Authentication action types
const AUTH_ACTIONS = {
  LOGIN_START: 'LOGIN_START',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  SET_USER: 'SET_USER',
  SET_LOADING: 'SET_LOADING',
  SET_ERROR: 'SET_ERROR',
  CLEAR_ERROR: 'CLEAR_ERROR',
  UPDATE_PROFILE: 'UPDATE_PROFILE',
  SET_PREFERENCES: 'SET_PREFERENCES',
  SESSION_EXPIRED: 'SESSION_EXPIRED'
};

// Authentication reducer
const authReducer = (state, action) => {
  switch (action.type) {
    case AUTH_ACTIONS.LOGIN_START:
      return {
        ...state,
        isLoading: true,
        error: null
      };
      
    case AUTH_ACTIONS.LOGIN_SUCCESS:
      return {
        ...state,
        user: action.payload.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
        permissions: action.payload.permissions || [],
        sessionExpiry: action.payload.sessionExpiry
      };
      
    case AUTH_ACTIONS.LOGIN_FAILURE:
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: action.payload.error,
        permissions: []
      };
      
    case AUTH_ACTIONS.LOGOUT:
      return {
        ...initialState,
        isLoading: false
      };
      
    case AUTH_ACTIONS.SET_USER:
      return {
        ...state,
        user: action.payload.user,
        isAuthenticated: true,
        isLoading: false,
        permissions: action.payload.permissions || state.permissions
      };
      
    case AUTH_ACTIONS.SET_LOADING:
      return {
        ...state,
        isLoading: action.payload
      };
      
    case AUTH_ACTIONS.SET_ERROR:
      return {
        ...state,
        error: action.payload,
        isLoading: false
      };
      
    case AUTH_ACTIONS.CLEAR_ERROR:
      return {
        ...state,
        error: null
      };
      
    case AUTH_ACTIONS.UPDATE_PROFILE:
      return {
        ...state,
        user: {
          ...state.user,
          ...action.payload
        }
      };
      
    case AUTH_ACTIONS.SET_PREFERENCES:
      return {
        ...state,
        preferences: action.payload
      };
      
    case AUTH_ACTIONS.SESSION_EXPIRED:
      return {
        ...initialState,
        isLoading: false,
        error: 'Your session has expired. Please log in again.'
      };
      
    default:
      return state;
  }
};

// Create authentication context
const AuthContext = createContext();

// Authentication provider component
export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Check for existing authentication on mount
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: true });
        
        // Check if user is authenticated
        if (ApiUtils.isAuthenticated()) {
          // Try to get current user data
          try {
            const userData = await AuthAPI.getCurrentUser();
            dispatch({
              type: AUTH_ACTIONS.SET_USER,
              payload: {
                user: userData.user,
                permissions: userData.permissions
              }
            });
          } catch (error) {
            // Token might be invalid, clear it
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            dispatch({ type: AUTH_ACTIONS.LOGOUT });
          }
        } else {
          dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: false });
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
        dispatch({
          type: AUTH_ACTIONS.SET_ERROR,
          payload: 'Failed to initialize authentication'
        });
      }
    };

    initializeAuth();
  }, []);

  // Set up session expiry check
  useEffect(() => {
    let sessionTimer;
    
    if (state.isAuthenticated && state.sessionExpiry) {
      const expiryTime = new Date(state.sessionExpiry).getTime();
      const currentTime = Date.now();
      const timeUntilExpiry = expiryTime - currentTime;
      
      if (timeUntilExpiry > 0) {
        sessionTimer = setTimeout(() => {
          dispatch({ type: AUTH_ACTIONS.SESSION_EXPIRED });
          logout();
        }, timeUntilExpiry);
      } else {
        // Session already expired
        dispatch({ type: AUTH_ACTIONS.SESSION_EXPIRED });
        logout();
      }
    }
    
    return () => {
      if (sessionTimer) {
        clearTimeout(sessionTimer);
      }
    };
  }, [state.isAuthenticated, state.sessionExpiry]);

  // Authentication actions
  const login = async (email, password, rememberMe = false) => {
    try {
      dispatch({ type: AUTH_ACTIONS.LOGIN_START });
      
      const response = await AuthAPI.login(email, password);
      
      // Store tokens
      localStorage.setItem('access_token', response.access_token);
      if (response.refresh_token) {
        localStorage.setItem('refresh_token', response.refresh_token);
      }
      
      // Set remember me preference
      if (rememberMe) {
        localStorage.setItem('remember_me', 'true');
      }
      
      dispatch({
        type: AUTH_ACTIONS.LOGIN_SUCCESS,
        payload: {
          user: response.user,
          permissions: response.permissions,
          sessionExpiry: response.session_expiry
        }
      });
      
      return { success: true };
    } catch (error) {
      const errorMessage = ApiUtils.formatError(error);
      dispatch({
        type: AUTH_ACTIONS.LOGIN_FAILURE,
        payload: { error: errorMessage }
      });
      return { success: false, error: errorMessage };
    }
  };

  const logout = async () => {
    try {
      // Call logout API to invalidate tokens on server
      await AuthAPI.logout();
    } catch (error) {
      console.error('Logout API error:', error);
    } finally {
      // Clear local storage and reset state
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('remember_me');
      dispatch({ type: AUTH_ACTIONS.LOGOUT });
    }
  };

  const register = async (userData) => {
    try {
      dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: true });
      
      const response = await AuthAPI.register(userData);
      
      // Automatically log in after successful registration
      if (response.access_token) {
        localStorage.setItem('access_token', response.access_token);
        if (response.refresh_token) {
          localStorage.setItem('refresh_token', response.refresh_token);
        }
        
        dispatch({
          type: AUTH_ACTIONS.LOGIN_SUCCESS,
          payload: {
            user: response.user,
            permissions: response.permissions
          }
        });
      }
      
      return { success: true, message: 'Registration successful' };
    } catch (error) {
      const errorMessage = ApiUtils.formatError(error);
      dispatch({
        type: AUTH_ACTIONS.SET_ERROR,
        payload: errorMessage
      });
      return { success: false, error: errorMessage };
    }
  };

  const forgotPassword = async (email) => {
    try {
      await AuthAPI.forgotPassword(email);
      return { 
        success: true, 
        message: 'Password reset instructions sent to your email' 
      };
    } catch (error) {
      const errorMessage = ApiUtils.formatError(error);
      return { success: false, error: errorMessage };
    }
  };

  const resetPassword = async (token, newPassword) => {
    try {
      await AuthAPI.resetPassword(token, newPassword);
      return { success: true, message: 'Password reset successfully' };
    } catch (error) {
      const errorMessage = ApiUtils.formatError(error);
      return { success: false, error: errorMessage };
    }
  };

  const updateProfile = async (updates) => {
    try {
      const response = await AuthAPI.updateProfile(updates);
      dispatch({
        type: AUTH_ACTIONS.UPDATE_PROFILE,
        payload: response.user
      });
      return { success: true, message: 'Profile updated successfully' };
    } catch (error) {
      const errorMessage = ApiUtils.formatError(error);
      return { success: false, error: errorMessage };
    }
  };

  const clearError = () => {
    dispatch({ type: AUTH_ACTIONS.CLEAR_ERROR });
  };

  const refreshUserData = async () => {
    try {
      const userData = await AuthAPI.getCurrentUser();
      dispatch({
        type: AUTH_ACTIONS.SET_USER,
        payload: {
          user: userData.user,
          permissions: userData.permissions
        }
      });
      return { success: true };
    } catch (error) {
      const errorMessage = ApiUtils.formatError(error);
      return { success: false, error: errorMessage };
    }
  };

  // Permission checking utilities
  const hasPermission = (permission) => {
    return state.permissions.includes(permission);
  };

  const hasAnyPermission = (permissions) => {
    return permissions.some(permission => state.permissions.includes(permission));
  };

  const hasAllPermissions = (permissions) => {
    return permissions.every(permission => state.permissions.includes(permission));
  };

  const isAdmin = () => {
    return hasPermission('admin') || state.user?.role === 'admin';
  };

  const isSuperAdmin = () => {
    return hasPermission('super_admin') || state.user?.role === 'super_admin';
  };

  // Context value
  const value = {
    // State
    ...state,
    
    // Actions
    login,
    logout,
    register,
    forgotPassword,
    resetPassword,
    updateProfile,
    clearError,
    refreshUserData,
    
    // Permission utilities
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    isAdmin,
    isSuperAdmin
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use authentication context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Higher-order component for protected routes
export const withAuth = (WrappedComponent, requiredPermissions = []) => {
  return (props) => {
    const { isAuthenticated, isLoading, hasAnyPermission } = useAuth();
    
    if (isLoading) {
      return <div>Loading...</div>; // Replace with proper loading component
    }
    
    if (!isAuthenticated) {
      // Redirect to login page
      window.location.href = '/login';
      return null;
    }
    
    if (requiredPermissions.length > 0 && !hasAnyPermission(requiredPermissions)) {
      return <div>Access Denied</div>; // Replace with proper access denied component
    }
    
    return <WrappedComponent {...props} />;
  };
};

// Protected route component
export const ProtectedRoute = ({ 
  children, 
  requiredPermissions = [], 
  fallback = null,
  redirectTo = '/login' 
}) => {
  const { isAuthenticated, isLoading, hasAnyPermission } = useAuth();
  
  if (isLoading) {
    return fallback || <div>Loading...</div>;
  }
  
  if (!isAuthenticated) {
    window.location.href = redirectTo;
    return null;
  }
  
  if (requiredPermissions.length > 0 && !hasAnyPermission(requiredPermissions)) {
    return fallback || <div>Access Denied</div>;
  }
  
  return children;
};

// Authentication status component
export const AuthStatus = () => {
  const { user, isAuthenticated, logout } = useAuth();
  
  if (!isAuthenticated) {
    return null;
  }
  
  return (
    <div style={{ padding: '10px', background: '#f0f0f0', borderRadius: '4px' }}>
      <span>Logged in as: {user?.email}</span>
      <button onClick={logout} style={{ marginLeft: '10px' }}>
        Logout
      </button>
    </div>
  );
};

// Export context for advanced usage
export { AuthContext };

// Default export for convenience
export default {
  AuthProvider,
  useAuth,
  withAuth,
  ProtectedRoute,
  AuthStatus,
  AuthContext
};
