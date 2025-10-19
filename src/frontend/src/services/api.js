import axios from 'axios';

// API Configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
const API_TIMEOUT = 30000; // 30 seconds

// Create axios instance with default configuration
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: API_TIMEOUT,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

// Request interceptor to add authentication token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    // Add request timestamp for debugging
    config.metadata = { startTime: new Date() };
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling and token refresh
apiClient.interceptors.response.use(
  (response) => {
    // Calculate request duration
    const endTime = new Date();
    const duration = endTime - response.config.metadata.startTime;
    console.log(`API Request to ${response.config.url} took ${duration}ms`);
    
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    
    // Handle 401 Unauthorized - Token expired
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken
          });
          
          const { access_token, refresh_token: newRefreshToken } = response.data;
          localStorage.setItem('access_token', access_token);
          localStorage.setItem('refresh_token', newRefreshToken);
          
          // Retry original request with new token
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return apiClient(originalRequest);
        }
      } catch (refreshError) {
        // Refresh failed, redirect to login
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    // Handle network errors
    if (!error.response) {
      console.error('Network Error:', error.message);
      return Promise.reject({
        message: 'Network error. Please check your connection.',
        type: 'network_error'
      });
    }
    
    // Handle API errors
    const apiError = {
      status: error.response.status,
      message: error.response.data?.message || error.message,
      details: error.response.data?.details || null,
      type: 'api_error'
    };
    
    console.error('API Error:', apiError);
    return Promise.reject(apiError);
  }
);

// API Service Classes
class AuthAPI {
  static async login(email, password) {
    const response = await apiClient.post('/auth/login', { email, password });
    return response.data;
  }
  
  static async logout() {
    try {
      await apiClient.post('/auth/logout');
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  }
  
  static async register(userData) {
    const response = await apiClient.post('/auth/register', userData);
    return response.data;
  }
  
  static async forgotPassword(email) {
    const response = await apiClient.post('/auth/forgot-password', { email });
    return response.data;
  }
  
  static async resetPassword(token, newPassword) {
    const response = await apiClient.post('/auth/reset-password', {
      token,
      new_password: newPassword
    });
    return response.data;
  }
  
  static async getCurrentUser() {
    const response = await apiClient.get('/auth/me');
    return response.data;
  }
  
  static async updateProfile(userData) {
    const response = await apiClient.put('/auth/profile', userData);
    return response.data;
  }
}

class EmailsAPI {
  static async getQuarantinedEmails(params = {}) {
    const response = await apiClient.get('/quarantine', { params });
    return response.data;
  }
  
  static async getEmailDetails(emailId) {
    const response = await apiClient.get(`/quarantine/${emailId}`);
    return response.data;
  }
  
  static async releaseEmail(emailId) {
    const response = await apiClient.post(`/quarantine/${emailId}/release`);
    return response.data;
  }
  
  static async deleteEmail(emailId) {
    const response = await apiClient.delete(`/quarantine/${emailId}`);
    return response.data;
  }
  
  static async bulkAction(action, emailIds) {
    const response = await apiClient.post('/quarantine/bulk', {
      action,
      email_ids: emailIds
    });
    return response.data;
  }
  
  static async reportEmail(emailData) {
    const response = await apiClient.post('/emails/report', emailData);
    return response.data;
  }
}

class AnalyticsAPI {
  static async getDashboardData(timeRange = '30d') {
    const response = await apiClient.get('/analytics/dashboard', {
      params: { time_range: timeRange }
    });
    return response.data;
  }
  
  static async getThreatTrends(params = {}) {
    const response = await apiClient.get('/analytics/threats', { params });
    return response.data;
  }
  
  static async getHeatmapData(dataType, timeRange) {
    const response = await apiClient.get('/analytics/heatmap', {
      params: { data_type: dataType, time_range: timeRange }
    });
    return response.data;
  }
  
  static async getPerformanceMetrics(timeRange) {
    const response = await apiClient.get('/analytics/performance', {
      params: { time_range: timeRange }
    });
    return response.data;
  }
  
  static async exportAnalytics(format, params) {
    const response = await apiClient.get('/analytics/export', {
      params: { format, ...params },
      responseType: 'blob'
    });
    return response.data;
  }
}

class ReportsAPI {
  static async getReports(params = {}) {
    const response = await apiClient.get('/reports', { params });
    return response.data;
  }
  
  static async generateReport(reportConfig) {
    const response = await apiClient.post('/reports/generate', reportConfig);
    return response.data;
  }
  
  static async getReportStatus(reportId) {
    const response = await apiClient.get(`/reports/${reportId}/status`);
    return response.data;
  }
  
  static async downloadReport(reportId, format = 'pdf') {
    const response = await apiClient.get(`/reports/${reportId}/download`, {
      params: { format },
      responseType: 'blob'
    });
    return response.data;
  }
  
  static async deleteReport(reportId) {
    const response = await apiClient.delete(`/reports/${reportId}`);
    return response.data;
  }
  
  static async scheduleReport(scheduleConfig) {
    const response = await apiClient.post('/reports/schedule', scheduleConfig);
    return response.data;
  }
}

class SimulationAPI {
  static async getSimulations(params = {}) {
    const response = await apiClient.get('/simulations', { params });
    return response.data;
  }
  
  static async createSimulation(simulationData) {
    const response = await apiClient.post('/simulations', simulationData);
    return response.data;
  }
  
  static async updateSimulation(simulationId, updates) {
    const response = await apiClient.put(`/simulations/${simulationId}`, updates);
    return response.data;
  }
  
  static async deleteSimulation(simulationId) {
    const response = await apiClient.delete(`/simulations/${simulationId}`);
    return response.data;
  }
  
  static async startSimulation(simulationId) {
    const response = await apiClient.post(`/simulations/${simulationId}/start`);
    return response.data;
  }
  
  static async stopSimulation(simulationId) {
    const response = await apiClient.post(`/simulations/${simulationId}/stop`);
    return response.data;
  }
  
  static async getSimulationResults(simulationId) {
    const response = await apiClient.get(`/simulations/${simulationId}/results`);
    return response.data;
  }
  
  static async getTemplates() {
    const response = await apiClient.get('/simulations/templates');
    return response.data;
  }
  
  static async uploadTemplate(templateData) {
    const response = await apiClient.post('/simulations/templates', templateData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return response.data;
  }
}

class UsersAPI {
  static async getUsers(params = {}) {
    const response = await apiClient.get('/users', { params });
    return response.data;
  }
  
  static async createUser(userData) {
    const response = await apiClient.post('/users', userData);
    return response.data;
  }
  
  static async updateUser(userId, updates) {
    const response = await apiClient.put(`/users/${userId}`, updates);
    return response.data;
  }
  
  static async deleteUser(userId) {
    const response = await apiClient.delete(`/users/${userId}`);
    return response.data;
  }
  
  static async getUserActivity(userId, timeRange) {
    const response = await apiClient.get(`/users/${userId}/activity`, {
      params: { time_range: timeRange }
    });
    return response.data;
  }
  
  static async bulkUserAction(action, userIds) {
    const response = await apiClient.post('/users/bulk', {
      action,
      user_ids: userIds
    });
    return response.data;
  }
}

class NotificationsAPI {
  static async getNotifications(params = {}) {
    const response = await apiClient.get('/notifications', { params });
    return response.data;
  }
  
  static async markAsRead(notificationId) {
    const response = await apiClient.put(`/notifications/${notificationId}/read`);
    return response.data;
  }
  
  static async markAllAsRead() {
    const response = await apiClient.put('/notifications/read-all');
    return response.data;
  }
  
  static async deleteNotification(notificationId) {
    const response = await apiClient.delete(`/notifications/${notificationId}`);
    return response.data;
  }
  
  static async getNotificationSettings() {
    const response = await apiClient.get('/notifications/settings');
    return response.data;
  }
  
  static async updateNotificationSettings(settings) {
    const response = await apiClient.put('/notifications/settings', settings);
    return response.data;
  }
}

class ComplianceAPI {
  static async getComplianceOverview() {
    const response = await apiClient.get('/compliance/overview');
    return response.data;
  }
  
  static async getFrameworkStatus(framework) {
    const response = await apiClient.get(`/compliance/frameworks/${framework}`);
    return response.data;
  }
  
  static async getPolicies(params = {}) {
    const response = await apiClient.get('/compliance/policies', { params });
    return response.data;
  }
  
  static async createPolicy(policyData) {
    const response = await apiClient.post('/compliance/policies', policyData);
    return response.data;
  }
  
  static async updatePolicy(policyId, updates) {
    const response = await apiClient.put(`/compliance/policies/${policyId}`, updates);
    return response.data;
  }
  
  static async getAssessments(params = {}) {
    const response = await apiClient.get('/compliance/assessments', { params });
    return response.data;
  }
  
  static async createAssessment(assessmentData) {
    const response = await apiClient.post('/compliance/assessments', assessmentData);
    return response.data;
  }
  
  static async getAuditLog(params = {}) {
    const response = await apiClient.get('/compliance/audit-log', { params });
    return response.data;
  }
  
  static async exportComplianceReport(framework, format) {
    const response = await apiClient.get('/compliance/export', {
      params: { framework, format },
      responseType: 'blob'
    });
    return response.data;
  }
}

class SettingsAPI {
  static async getSettings() {
    const response = await apiClient.get('/settings');
    return response.data;
  }
  
  static async updateSettings(settings) {
    const response = await apiClient.put('/settings', settings);
    return response.data;
  }
  
  static async resetSettings() {
    const response = await apiClient.post('/settings/reset');
    return response.data;
  }
  
  static async exportSettings() {
    const response = await apiClient.get('/settings/export', {
      responseType: 'blob'
    });
    return response.data;
  }
  
  static async importSettings(settingsFile) {
    const formData = new FormData();
    formData.append('settings_file', settingsFile);
    
    const response = await apiClient.post('/settings/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return response.data;
  }
  
  static async testIntegration(integrationType, config) {
    const response = await apiClient.post('/settings/test-integration', {
      integration_type: integrationType,
      config
    });
    return response.data;
  }
}

// Utility functions
const ApiUtils = {
  // Handle file downloads
  downloadFile: (blob, filename) => {
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  },
  
  // Format error messages for display
  formatError: (error) => {
    if (error.type === 'network_error') {
      return 'Network connection error. Please check your internet connection.';
    }
    
    if (error.status === 400) {
      return error.message || 'Invalid request. Please check your input.';
    }
    
    if (error.status === 401) {
      return 'Authentication required. Please log in again.';
    }
    
    if (error.status === 403) {
      return 'You do not have permission to perform this action.';
    }
    
    if (error.status === 404) {
      return 'The requested resource was not found.';
    }
    
    if (error.status === 429) {
      return 'Too many requests. Please wait a moment and try again.';
    }
    
    if (error.status >= 500) {
      return 'Server error. Please try again later or contact support.';
    }
    
    return error.message || 'An unexpected error occurred.';
  },
  
  // Check if user is authenticated
  isAuthenticated: () => {
    return !!localStorage.getItem('access_token');
  },
  
  // Get current user from token (basic JWT decode)
  getCurrentUserFromToken: () => {
    const token = localStorage.getItem('access_token');
    if (!token) return null;
    
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload;
    } catch (error) {
      console.error('Error decoding token:', error);
      return null;
    }
  }
};

// Export all APIs
export {
  apiClient,
  AuthAPI,
  EmailsAPI,
  AnalyticsAPI,
  ReportsAPI,
  SimulationAPI,
  UsersAPI,
  NotificationsAPI,
  ComplianceAPI,
  SettingsAPI,
  ApiUtils
};

// Default export for backward compatibility
export default {
  Auth: AuthAPI,
  Emails: EmailsAPI,
  Analytics: AnalyticsAPI,
  Reports: ReportsAPI,
  Simulation: SimulationAPI,
  Users: UsersAPI,
  Notifications: NotificationsAPI,
  Compliance: ComplianceAPI,
  Settings: SettingsAPI,
  Utils: ApiUtils
};
