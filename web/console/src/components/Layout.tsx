// Layout.tsx - 应用外壳：侧边导航 + 顶栏(含 routerd 健康状态)。
import { useEffect, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { StatusBadge } from './StatusBadge';

type Health = 'ok' | 'err' | 'muted';

async function checkHealth(): Promise<Health> {
  try {
    const res = await fetch('/healthz');
    return res.ok ? 'ok' : 'err';
  } catch {
    return 'err';
  }
}

export function Layout() {
  const [health, setHealth] = useState<Health>('muted');

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const h = await checkHealth();
      if (alive) setHealth(h);
    };
    void tick();
    const id = window.setInterval(tick, 5000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, []);

  const navItems = [
    { to: '/', label: '系统', end: true },
    { to: '/interfaces', label: '网络接口' },
    { to: '/routes', label: '路由表' },
  ];

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">
          <span className="logo">cy</span>
          <span>cythsec</span>
        </div>
        <nav>
          {navItems.map((it) => (
            <NavLink
              key={it.to}
              to={it.to}
              end={it.end}
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
            >
              {it.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="main-col">
        <header className="topbar">
          <span className="muted small">控制面 · Web Console</span>
          <StatusBadge
            tone={health}
            label={health === 'ok' ? 'routerd online' : health === 'err' ? 'routerd offline' : '…'}
          />
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
