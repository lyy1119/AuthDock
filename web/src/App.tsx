import { App as AntApp, ConfigProvider, theme as antdTheme } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom'

import AppLayout from './Layout'
import GatesPage from './pages/GatesPage'
import SettingsPage from './pages/SettingsPage'
import UsersPage from './pages/UsersPage'
import { ThemeProvider, useTheme } from './theme'

/**
 * Routes live in the URL hash, so the Go server only ever has to serve this
 * shell at /admin/ and the app keeps working behind any path prefix.
 */
export default function App() {
  return (
    <ThemeProvider>
      <ThemedApp />
    </ThemeProvider>
  )
}

function ThemedApp() {
  const { resolved } = useTheme()

  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: resolved === 'dark' ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
        token: {
          colorPrimary: '#2f6fa8',
          borderRadius: 8,
          colorBgLayout: resolved === 'dark' ? '#10161c' : '#f4f7f9',
        },
      }}
    >
      <AntApp>
        <HashRouter>
          <Routes>
            <Route element={<AppLayout />}>
              <Route path="/" element={<Navigate to="/users" replace />} />
              <Route path="/users" element={<UsersPage />} />
              <Route path="/gates" element={<GatesPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<Navigate to="/users" replace />} />
            </Route>
          </Routes>
        </HashRouter>
      </AntApp>
    </ConfigProvider>
  )
}
