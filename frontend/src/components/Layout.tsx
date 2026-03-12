import { Outlet, NavLink } from 'react-router-dom';
import { LayoutDashboard, ScanLine, ShieldCheck, FileText, Shield, Settings, Hexagon, Container, FlaskConical, Users } from 'lucide-react';

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans', icon: ScanLine, label: 'Scans' },
  { to: '/registries', icon: Container, label: 'Registries' },
  { to: '/workers', icon: Hexagon, label: 'Workers' },
  { to: '/teams', icon: Users, label: 'Teams' },
  { to: '/policies', icon: ShieldCheck, label: 'Policies' },
  { to: '/audit-log', icon: FileText, label: 'Audit Log' },
  { to: '/settings', icon: Settings, label: 'Settings' },
  { to: '/seed', icon: FlaskConical, label: 'Seed Scans' },
];

export default function Layout() {
  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      <aside style={{
        width: 240,
        background: 'var(--bg-secondary)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}>
        <div style={{
          padding: '20px 16px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
        }}>
          <Shield size={24} color="var(--accent)" />
          <span style={{ fontWeight: 700, fontSize: 16, color: 'var(--text-primary)' }}>
            Dunedain
          </span>
        </div>
        <nav style={{ padding: '12px 8px', flex: 1 }}>
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 12px',
                borderRadius: 6,
                color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
                background: isActive ? 'rgba(59,130,246,0.1)' : 'transparent',
                marginBottom: 2,
                fontWeight: isActive ? 600 : 400,
                transition: 'background 0.15s, color 0.15s',
              })}
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main style={{ flex: 1, overflow: 'auto', padding: 24 }}>
        <Outlet />
      </main>
    </div>
  );
}
