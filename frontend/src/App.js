import React, { useState, useEffect, createContext, useContext } from 'react';
import './App.css';

// Create Auth Context
const AuthContext = createContext();

// Auth Provider Component
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is logged in
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
    }
    setLoading(false);
  }, []);

  const login = (tokenData) => {
    localStorage.setItem('token', tokenData.access_token);
    localStorage.setItem('user', JSON.stringify(tokenData.user));
    setUser(tokenData.user);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use auth context
const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// API utility functions
const API_BASE_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

const apiCall = async (endpoint, options = {}) => {
  const token = localStorage.getItem('token');
  const url = `${API_BASE_URL}${endpoint}`;
  
  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
    },
    ...options,
  };

  if (config.body && typeof config.body === 'object') {
    config.body = JSON.stringify(config.body);
  }

  try {
    const response = await fetch(url, config);
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.detail || 'API request failed');
    }
    
    return data;
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
};

// Login/Register Component
const AuthForm = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    full_name: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const payload = isLogin 
        ? { username: formData.username, password: formData.password }
        : formData;

      const response = await apiCall(endpoint, {
        method: 'POST',
        body: payload,
      });

      login(response);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="mx-auto h-12 w-12 bg-indigo-600 rounded-lg flex items-center justify-center">
            <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
            </svg>
          </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            {isLogin ? 'Iniciar Sesión' : 'Crear Cuenta'}
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Gestor de Credenciales para Desarrolladores
          </p>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-md">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                Usuario
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Nombre de usuario"
                value={formData.username}
                onChange={handleChange}
              />
            </div>

            {!isLogin && (
              <>
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                    Email
                  </label>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    required
                    className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                    placeholder="Email"
                    value={formData.email}
                    onChange={handleChange}
                  />
                </div>
                <div>
                  <label htmlFor="full_name" className="block text-sm font-medium text-gray-700">
                    Nombre Completo
                  </label>
                  <input
                    id="full_name"
                    name="full_name"
                    type="text"
                    required
                    className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                    placeholder="Nombre completo"
                    value={formData.full_name}
                    onChange={handleChange}
                  />
                </div>
              </>
            )}

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Contraseña
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Contraseña"
                value={formData.password}
                onChange={handleChange}
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
            >
              {loading ? 'Procesando...' : (isLogin ? 'Iniciar Sesión' : 'Crear Cuenta')}
            </button>
          </div>

          <div className="text-center">
            <button
              type="button"
              className="text-indigo-600 hover:text-indigo-500"
              onClick={() => setIsLogin(!isLogin)}
            >
              {isLogin ? '¿No tienes cuenta? Regístrate' : '¿Ya tienes cuenta? Inicia sesión'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('namespaces');
  const [namespaces, setNamespaces] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [selectedNamespace, setSelectedNamespace] = useState(null);
  const [stats, setStats] = useState({ total_namespaces: 0, total_credentials: 0 });
  const [loading, setLoading] = useState(false);

  // Modals
  const [showNamespaceModal, setShowNamespaceModal] = useState(false);
  const [showCredentialModal, setShowCredentialModal] = useState(false);
  const [showCredentialDetail, setShowCredentialDetail] = useState(null);

  // Forms
  const [namespaceForm, setNamespaceForm] = useState({ name: '', description: '' });
  const [credentialForm, setCredentialForm] = useState({
    title: '',
    credential_type: 'username_password',
    username: '',
    password: '',
    api_key: '',
    token: '',
    file_content: '',
    file_name: '',
    notes: ''
  });

  useEffect(() => {
    loadNamespaces();
    loadStats();
  }, []);

  const loadNamespaces = async () => {
    try {
      const data = await apiCall('/api/namespaces');
      setNamespaces(data);
    } catch (error) {
      console.error('Error loading namespaces:', error);
    }
  };

  const loadStats = async () => {
    try {
      const data = await apiCall('/api/stats');
      setStats(data);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const loadCredentials = async (namespaceId) => {
    try {
      setLoading(true);
      const data = await apiCall(`/api/credentials/namespace/${namespaceId}`);
      setCredentials(data);
    } catch (error) {
      console.error('Error loading credentials:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateNamespace = async (e) => {
    e.preventDefault();
    try {
      await apiCall('/api/namespaces', {
        method: 'POST',
        body: namespaceForm,
      });
      setShowNamespaceModal(false);
      setNamespaceForm({ name: '', description: '' });
      loadNamespaces();
      loadStats();
    } catch (error) {
      console.error('Error creating namespace:', error);
    }
  };

  const handleCreateCredential = async (e) => {
    e.preventDefault();
    try {
      await apiCall('/api/credentials', {
        method: 'POST',
        body: {
          ...credentialForm,
          namespace_id: selectedNamespace.id
        },
      });
      setShowCredentialModal(false);
      setCredentialForm({
        title: '',
        credential_type: 'username_password',
        username: '',
        password: '',
        api_key: '',
        token: '',
        file_content: '',
        file_name: '',
        notes: ''
      });
      loadCredentials(selectedNamespace.id);
      loadStats();
    } catch (error) {
      console.error('Error creating credential:', error);
    }
  };

  const handleDeleteNamespace = async (namespaceId) => {
    if (window.confirm('¿Estás seguro? Esto eliminará todas las credenciales del namespace.')) {
      try {
        await apiCall(`/api/namespaces/${namespaceId}`, { method: 'DELETE' });
        loadNamespaces();
        loadStats();
        if (selectedNamespace && selectedNamespace.id === namespaceId) {
          setSelectedNamespace(null);
          setCredentials([]);
        }
      } catch (error) {
        console.error('Error deleting namespace:', error);
      }
    }
  };

  const handleDeleteCredential = async (credentialId) => {
    if (window.confirm('¿Estás seguro de que quieres eliminar esta credencial?')) {
      try {
        await apiCall(`/api/credentials/${credentialId}`, { method: 'DELETE' });
        loadCredentials(selectedNamespace.id);
        loadStats();
      } catch (error) {
        console.error('Error deleting credential:', error);
      }
    }
  };

  const handleNamespaceClick = (namespace) => {
    setSelectedNamespace(namespace);
    setActiveTab('credentials');
    loadCredentials(namespace.id);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <div className="h-8 w-8 bg-indigo-600 rounded-lg flex items-center justify-center mr-3">
                <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
              </div>
              <h1 className="text-2xl font-bold text-gray-900">Gestor de Credenciales</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-500">Hola, {user?.full_name}</span>
              <button
                onClick={logout}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-medium"
              >
                Cerrar Sesión
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Stats */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-3 rounded-full bg-blue-100">
                <svg className="h-8 w-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Total Namespaces</p>
                <p className="text-2xl font-bold text-gray-900">{stats.total_namespaces}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-3 rounded-full bg-green-100">
                <svg className="h-8 w-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Total Credenciales</p>
                <p className="text-2xl font-bold text-gray-900">{stats.total_credentials}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-200 mb-6">
          <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => setActiveTab('namespaces')}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'namespaces'
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Namespaces
            </button>
            <button
              onClick={() => setActiveTab('credentials')}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'credentials'
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
              disabled={!selectedNamespace}
            >
              Credenciales {selectedNamespace && `(${selectedNamespace.name})`}
            </button>
          </nav>
        </div>

        {/* Content */}
        {activeTab === 'namespaces' && (
          <div>
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-xl font-semibold text-gray-900">Namespaces</h2>
              <button
                onClick={() => setShowNamespaceModal(true)}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md text-sm font-medium"
              >
                + Crear Namespace
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {namespaces.map((namespace) => (
                <div key={namespace.id} className="bg-white rounded-lg shadow p-6 hover:shadow-md transition-shadow">
                  <div className="flex justify-between items-start mb-3">
                    <h3 className="text-lg font-medium text-gray-900">{namespace.name}</h3>
                    <button
                      onClick={() => handleDeleteNamespace(namespace.id)}
                      className="text-red-600 hover:text-red-800"
                    >
                      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                      </svg>
                    </button>
                  </div>
                  <p className="text-gray-600 text-sm mb-4">{namespace.description}</p>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500">
                      {namespace.credentials_count} credenciales
                    </span>
                    <button
                      onClick={() => handleNamespaceClick(namespace)}
                      className="text-indigo-600 hover:text-indigo-800 text-sm font-medium"
                    >
                      Ver credenciales →
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'credentials' && selectedNamespace && (
          <div>
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-xl font-semibold text-gray-900">
                Credenciales - {selectedNamespace.name}
              </h2>
              <button
                onClick={() => setShowCredentialModal(true)}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md text-sm font-medium"
              >
                + Crear Credencial
              </button>
            </div>

            {loading ? (
              <div className="text-center py-8">
                <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {credentials.map((credential) => (
                  <div key={credential.id} className="bg-white rounded-lg shadow p-6">
                    <div className="flex justify-between items-start mb-3">
                      <h3 className="text-lg font-medium text-gray-900">{credential.title}</h3>
                      <button
                        onClick={() => handleDeleteCredential(credential.id)}
                        className="text-red-600 hover:text-red-800"
                      >
                        <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                        </svg>
                      </button>
                    </div>
                    <div className="space-y-2">
                      <p className="text-sm text-gray-600">
                        <span className="font-medium">Tipo:</span> {credential.credential_type}
                      </p>
                      {credential.username && (
                        <p className="text-sm text-gray-600">
                          <span className="font-medium">Usuario:</span> {credential.username}
                        </p>
                      )}
                      {credential.notes && (
                        <p className="text-sm text-gray-600">
                          <span className="font-medium">Notas:</span> {credential.notes}
                        </p>
                      )}
                    </div>
                    <button
                      onClick={() => setShowCredentialDetail(credential)}
                      className="mt-4 w-full bg-gray-100 hover:bg-gray-200 text-gray-700 py-2 px-4 rounded-md text-sm font-medium"
                    >
                      Ver Detalles
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Namespace Modal */}
      {showNamespaceModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Crear Namespace</h3>
            <form onSubmit={handleCreateNamespace}>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Nombre</label>
                  <input
                    type="text"
                    required
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    value={namespaceForm.name}
                    onChange={(e) => setNamespaceForm({...namespaceForm, name: e.target.value})}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Descripción</label>
                  <textarea
                    rows={3}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    value={namespaceForm.description}
                    onChange={(e) => setNamespaceForm({...namespaceForm, description: e.target.value})}
                  />
                </div>
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  type="button"
                  onClick={() => setShowNamespaceModal(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 border border-transparent rounded-md hover:bg-indigo-700"
                >
                  Crear
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Credential Modal */}
      {showCredentialModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-lg max-h-screen overflow-y-auto">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Crear Credencial</h3>
            <form onSubmit={handleCreateCredential}>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Título</label>
                  <input
                    type="text"
                    required
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    value={credentialForm.title}
                    onChange={(e) => setCredentialForm({...credentialForm, title: e.target.value})}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Tipo</label>
                  <select
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    value={credentialForm.credential_type}
                    onChange={(e) => setCredentialForm({...credentialForm, credential_type: e.target.value})}
                  >
                    <option value="username_password">Usuario/Contraseña</option>
                    <option value="api_key">API Key</option>
                    <option value="token">Token</option>
                    <option value="file">Archivo</option>
                  </select>
                </div>

                {credentialForm.credential_type === 'username_password' && (
                  <>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Usuario</label>
                      <input
                        type="text"
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        value={credentialForm.username}
                        onChange={(e) => setCredentialForm({...credentialForm, username: e.target.value})}
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Contraseña</label>
                      <input
                        type="password"
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        value={credentialForm.password}
                        onChange={(e) => setCredentialForm({...credentialForm, password: e.target.value})}
                      />
                    </div>
                  </>
                )}

                {credentialForm.credential_type === 'api_key' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700">API Key</label>
                    <textarea
                      rows={3}
                      className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                      value={credentialForm.api_key}
                      onChange={(e) => setCredentialForm({...credentialForm, api_key: e.target.value})}
                    />
                  </div>
                )}

                {credentialForm.credential_type === 'token' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Token</label>
                    <textarea
                      rows={3}
                      className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                      value={credentialForm.token}
                      onChange={(e) => setCredentialForm({...credentialForm, token: e.target.value})}
                    />
                  </div>
                )}

                {credentialForm.credential_type === 'file' && (
                  <>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Nombre del archivo</label>
                      <input
                        type="text"
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        value={credentialForm.file_name}
                        onChange={(e) => setCredentialForm({...credentialForm, file_name: e.target.value})}
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Contenido del archivo</label>
                      <textarea
                        rows={5}
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        value={credentialForm.file_content}
                        onChange={(e) => setCredentialForm({...credentialForm, file_content: e.target.value})}
                      />
                    </div>
                  </>
                )}

                <div>
                  <label className="block text-sm font-medium text-gray-700">Notas</label>
                  <textarea
                    rows={3}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    value={credentialForm.notes}
                    onChange={(e) => setCredentialForm({...credentialForm, notes: e.target.value})}
                  />
                </div>
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  type="button"
                  onClick={() => setShowCredentialModal(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 border border-transparent rounded-md hover:bg-indigo-700"
                >
                  Crear
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Credential Detail Modal */}
      {showCredentialDetail && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-2xl max-h-screen overflow-y-auto">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-lg font-medium text-gray-900">{showCredentialDetail.title}</h3>
              <button
                onClick={() => setShowCredentialDetail(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Tipo</label>
                <p className="mt-1 text-sm text-gray-900">{showCredentialDetail.credential_type}</p>
              </div>
              
              {showCredentialDetail.username && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">Usuario</label>
                  <div className="mt-1 flex items-center space-x-2">
                    <code className="px-2 py-1 bg-gray-100 rounded text-sm">{showCredentialDetail.username}</code>
                    <button
                      onClick={() => copyToClipboard(showCredentialDetail.username)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                      </svg>
                    </button>
                  </div>
                </div>
              )}
              
              {showCredentialDetail.password && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">Contraseña</label>
                  <div className="mt-1 flex items-center space-x-2">
                    <code className="px-2 py-1 bg-gray-100 rounded text-sm">{showCredentialDetail.password}</code>
                    <button
                      onClick={() => copyToClipboard(showCredentialDetail.password)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                      </svg>
                    </button>
                  </div>
                </div>
              )}
              
              {showCredentialDetail.api_key && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">API Key</label>
                  <div className="mt-1 flex items-center space-x-2">
                    <code className="px-2 py-1 bg-gray-100 rounded text-sm break-all">{showCredentialDetail.api_key}</code>
                    <button
                      onClick={() => copyToClipboard(showCredentialDetail.api_key)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                      </svg>
                    </button>
                  </div>
                </div>
              )}
              
              {showCredentialDetail.token && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">Token</label>
                  <div className="mt-1 flex items-center space-x-2">
                    <code className="px-2 py-1 bg-gray-100 rounded text-sm break-all">{showCredentialDetail.token}</code>
                    <button
                      onClick={() => copyToClipboard(showCredentialDetail.token)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                      </svg>
                    </button>
                  </div>
                </div>
              )}
              
              {showCredentialDetail.file_name && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">Nombre del archivo</label>
                  <p className="mt-1 text-sm text-gray-900">{showCredentialDetail.file_name}</p>
                </div>
              )}
              
              {showCredentialDetail.file_content && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">Contenido del archivo</label>
                  <div className="mt-1 flex items-start space-x-2">
                    <pre className="px-2 py-1 bg-gray-100 rounded text-sm whitespace-pre-wrap flex-1">{showCredentialDetail.file_content}</pre>
                    <button
                      onClick={() => copyToClipboard(showCredentialDetail.file_content)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                      </svg>
                    </button>
                  </div>
                </div>
              )}
              
              {showCredentialDetail.notes && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">Notas</label>
                  <p className="mt-1 text-sm text-gray-900">{showCredentialDetail.notes}</p>
                </div>
              )}
              
              <div className="text-xs text-gray-500 pt-4 border-t">
                <p>Creado: {new Date(showCredentialDetail.created_at).toLocaleString()}</p>
                <p>Actualizado: {new Date(showCredentialDetail.updated_at).toLocaleString()}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Main App Component
const App = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

const AppContent = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  return user ? <Dashboard /> : <AuthForm />;
};

export default App;