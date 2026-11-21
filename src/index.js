import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import { LangProvider } from './i18n/ui';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <LangProvider>
      <App />
    </LangProvider>
  </React.StrictMode>
);
