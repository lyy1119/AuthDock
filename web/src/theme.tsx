import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

import { getSettings, type ThemeName } from './api'

interface ThemeState {
  /** The stored preference: light, dark or auto. */
  theme: ThemeName
  /** What is actually applied right now. */
  resolved: 'light' | 'dark'
  /** Called by the settings page after the preference was saved. */
  setTheme: (theme: ThemeName) => void
}

const STORAGE_KEY = 'authdock.theme'
const DARK_QUERY = '(prefers-color-scheme: dark)'

const ThemeContext = createContext<ThemeState | null>(null)

function readCachedTheme(): ThemeName {
  const cached = window.localStorage.getItem(STORAGE_KEY)
  return cached === 'dark' || cached === 'auto' ? cached : 'light'
}

/**
 * ThemeProvider resolves the colour scheme. The preference lives in the system
 * settings; the last value is cached locally so a reload does not flash the
 * wrong palette while the settings request is in flight.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<ThemeName>(readCachedTheme)
  const [systemDark, setSystemDark] = useState(
    () => window.matchMedia(DARK_QUERY).matches,
  )

  useEffect(() => {
    const query = window.matchMedia(DARK_QUERY)
    const listener = (event: MediaQueryListEvent) => setSystemDark(event.matches)
    query.addEventListener('change', listener)
    return () => query.removeEventListener('change', listener)
  }, [])

  useEffect(() => {
    let cancelled = false
    getSettings()
      .then((settings) => {
        if (!cancelled) {
          setTheme(settings.theme)
        }
      })
      .catch(() => {
        // Not signed in or the request failed: the cached value stays.
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, theme)
  }, [theme])

  const resolved: 'light' | 'dark' = theme === 'auto' ? (systemDark ? 'dark' : 'light') : theme

  useEffect(() => {
    document.documentElement.dataset.theme = resolved
  }, [resolved])

  const value = useMemo<ThemeState>(() => ({ theme, resolved, setTheme }), [theme, resolved])

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeState {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used inside ThemeProvider')
  }
  return context
}
