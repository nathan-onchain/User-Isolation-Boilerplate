import axios from 'axios';

const API_BASE_URL = 'http://localhost:8080/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true, // Important for cookies
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface LoginData {
  email: string;
  password: string;
}

export interface RegisterData {
  username: string;
  email: string;
  password: string;
}

export interface AuthResponse {
  message: string;
}

export const authAPI = {
  login: async (data: LoginData): Promise<AuthResponse> => {
    console.log('Attempting login with:', data);
    const response = await api.post('/auth/login', data);
    console.log('Login response:', response.data);
    return response.data;
  },

  register: async (data: RegisterData): Promise<AuthResponse> => {
    console.log('Attempting registration with:', data);
    const response = await api.post('/auth/register', data);
    console.log('Registration response:', response.data);
    return response.data;
  },

  logout: async (): Promise<AuthResponse> => {
    const response = await api.post('/auth/logout');
    return response.data;
  },

  health: async (): Promise<string> => {
    const response = await api.get('/health');
    return response.data;
  },
};

export default api;
