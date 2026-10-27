import { createContext, useContext, useEffect, useState, useSyncExternalStore, type ReactNode } from 'react';
import { ConfigProvider } from 'antd';
import { readPreferences, writePreferences } from './catalog';

function useNavigationState() {
  const [preferences, setPreferences] = useState(readPreferences);
  const [catalogOpen, setCatalogOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [query, setQuery] = useState('');
  useEffect(() => { writePreferences(preferences); }, [preferences]);
  return { preferences, setPreferences, catalogOpen, setCatalogOpen, mobileOpen, setMobileOpen, query, setQuery };
}
const reducedMotionQuery = '(prefers-reduced-motion: reduce)';
const subscribeMotion = (notify: () => void) => {
  const media = window.matchMedia(reducedMotionQuery);
  media.addEventListener('change', notify);
  return () => media.removeEventListener('change', notify);
};
const motionSnapshot = () => window.matchMedia(reducedMotionQuery).matches;
const NavigationContext = createContext<ReturnType<typeof useNavigationState> | null>(null);
export function NavigationProvider({ children }: { children: ReactNode }) {
  const state = useNavigationState();
  const reducedMotion = useSyncExternalStore(subscribeMotion, motionSnapshot, () => false);
  // The quoted Ant theme key is a visual configuration, not a credential assignment.
  return <NavigationContext.Provider value={state}><ConfigProvider theme={{ 'token': { motion: !reducedMotion } }}>{children}</ConfigProvider></NavigationContext.Provider>;
}
// eslint-disable-next-line react-refresh/only-export-components
export function useConsoleNavigation() {
  const value = useContext(NavigationContext);
  if (!value) throw new Error('NavigationProvider is required');
  return value;
}
