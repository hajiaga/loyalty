import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auth API
export const authAPI = {
  register: (name: string, email: string, password: string) =>
    api.post('/register', { name, email, password }),

  login: (email: string, password: string) =>
    api.post('/token', new URLSearchParams({ username: email, password }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }),

  getMe: () => api.get('/me'),
};

// Property API
export const propertyAPI = {
  getAll: () => api.get('/properties'),
  getOne: (id: string) => api.get(`/properties/${id}`),
  create: (data: any) => api.post('/properties', data),
  update: (id: string, data: any) => api.put(`/properties/${id}`, data),
  delete: (id: string) => api.delete(`/properties/${id}`),
};

// Bill API
export const billAPI = {
  getAll: (status?: string, propertyId?: string) => {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (propertyId) params.append('property_id', propertyId);
    return api.get('/bills', { params });
  },
  getOne: (id: string) => api.get(`/bills/${id}`),
  create: (data: any) => api.post('/bills', data),
  update: (id: string, data: any) => api.put(`/bills/${id}`, data),
  delete: (id: string) => api.delete(`/bills/${id}`),
};

// Payment API
export const paymentAPI = {
  getAll: () => api.get('/payments'),
  createPaymentIntent: (data: any) => api.post('/payments/create-payment-intent', data),
  confirmPayment: (data: any) => api.post('/payments/confirm', data),
};

// Reports API
export const reportsAPI = {
  getSummary: () => api.get('/reports/summary'),
  getPropertyReports: () => api.get('/reports/properties'),
  getPaymentHistory: (startDate?: string, endDate?: string) => {
    const params = new URLSearchParams();
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    return api.get('/reports/payment-history', { params });
  },
};

export default api;
