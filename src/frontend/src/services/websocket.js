/**
 * WebSocket Service
 * 
 * Manages WebSocket connections for real-time updates
 */

let socket = null;
let reconnectAttempts = 0;
const maxReconnectAttempts = 5;
const reconnectInterval = 5000; // 5 seconds

const initializeWebSocket = () => {
  const wsUrl = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws';
  
  try {
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      console.log('WebSocket connected');
      reconnectAttempts = 0;
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    socket.onclose = (event) => {
      console.log('WebSocket disconnected:', event.code, event.reason);
      
      // Attempt to reconnect
      if (reconnectAttempts < maxReconnectAttempts) {
        setTimeout(() => {
          reconnectAttempts++;
          console.log(`Attempting to reconnect... (${reconnectAttempts}/${maxReconnectAttempts})`);
          initializeWebSocket();
        }, reconnectInterval);
      } else {
        console.log('Max reconnection attempts reached');
      }
    };

    socket.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

  } catch (error) {
    console.error('Error initializing WebSocket:', error);
  }

  // Return cleanup function
  return () => {
    if (socket) {
      socket.close();
      socket = null;
    }
  };
};

const handleWebSocketMessage = (data) => {
  // Handle different message types
  switch (data.type) {
    case 'threat_detected':
      // Handle threat detection notification
      console.log('New threat detected:', data.payload);
      break;
      
    case 'quarantine_update':
      // Handle quarantine status updates
      console.log('Quarantine update:', data.payload);
      break;
      
    case 'simulation_result':
      // Handle simulation results
      console.log('Simulation result:', data.payload);
      break;
      
    default:
      console.log('Unknown WebSocket message type:', data.type);
  }
};

const sendMessage = (type, payload) => {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type, payload }));
  } else {
    console.warn('WebSocket is not connected');
  }
};

const getConnectionStatus = () => {
  if (!socket) return 'disconnected';
  
  switch (socket.readyState) {
    case WebSocket.CONNECTING:
      return 'connecting';
    case WebSocket.OPEN:
      return 'connected';
    case WebSocket.CLOSING:
      return 'closing';
    case WebSocket.CLOSED:
      return 'disconnected';
    default:
      return 'unknown';
  }
};

export {
  initializeWebSocket,
  sendMessage,
  getConnectionStatus,
};