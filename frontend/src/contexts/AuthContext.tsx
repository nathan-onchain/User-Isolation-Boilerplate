import React, { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import { authAPI, type LoginData, type RegisterData } from '@/lib/api';

interface User {
  id: string;
  username: string;
  email: string;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (data: LoginData) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const isAuthenticated = !!user;

  const login = async (data: LoginData) => {
    try {
      console.log('AuthContext: Starting login for:', data);
      await authAPI.login(data);
      console.log('AuthContext: Login successful');
      // In a real app, you'd decode the JWT to get user info
      // For now, we'll just set a placeholder user
      setUser({
        id: '1',
        username: data.email.split('@')[0],
        email: data.email,
      });
    } catch (error) {
      console.error('AuthContext: Login failed:', error);
      console.error('Error details:', error);
      throw error;
    }
  };

  const register = async (data: RegisterData) => {
    try {
      console.log('AuthContext: Starting registration for:', data);
      await authAPI.register(data);
      console.log('AuthContext: Registration successful');
      // In a real app, you'd decode the JWT to get user info
      setUser({
        id: '1',
        username: data.username,
        email: data.email,
      });
    } catch (error) {
      console.error('AuthContext: Registration failed:', error);
      console.error('Error details:', error);
      throw error;
    }
  };

  const logout = async () => {
    try {
      await authAPI.logout();
      setUser(null);
    } catch (error) {
      console.error('Logout failed:', error);
      throw error;
    }
  };

  useEffect(() => {
    // Check if user is already authenticated
    // In a real app, you'd check for a valid JWT token
    setIsLoading(false);
  }, []);

  const value = {
    user,
    isAuthenticated,
    isLoading,
    login,
    register,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
