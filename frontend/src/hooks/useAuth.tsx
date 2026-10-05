import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from '../types';
import { api } from '../services/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (credentialsOrUsername: string | { username: string; password: string }, password?: string) => Promise<void>;
  logout: () => void;
  isAdmin: boolean;
  isAnalyst: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    const saved = localStorage.getItem('idps_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('idps_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const verifySession = async () => {
      if (token) {
        try {
          const freshUser = await api.getMe();
          setUser(freshUser);
          localStorage.setItem('idps_user', JSON.stringify(freshUser));
        } catch {
          api.clearToken();
          setUser(null);
          setToken(null);
        }
      }
      setLoading(false);
    };
    verifySession();
  }, [token]);

  const login = async (
    credentialsOrUsername: string | { username: string; password: string },
    password?: string
  ) => {
    const creds =
      typeof credentialsOrUsername === 'string'
        ? { username: credentialsOrUsername, password: password || '' }
        : credentialsOrUsername;
    const res = await api.login(creds);
    setToken(res.access_token);
    setUser(res.user);
  };

  const logout = () => {
    api.clearToken();
    setUser(null);
    setToken(null);
    window.location.href = '/login';
  };

  const isAdmin = user?.role === 'admin';
  const isAnalyst = user?.role === 'analyst' || isAdmin;

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        login,
        logout,
        isAdmin,
        isAnalyst,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
