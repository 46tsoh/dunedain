import { useState, useRef } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { FlaskConical, Trash2, Play, CheckSquare, Square, X, Radio } from 'lucide-react';
import { createScan, deleteAllScans, flushQueue } from '../api/scans';

// ---------------------------------------------------------------------------
// Seed data
// ---------------------------------------------------------------------------

const CONTAINER_IMAGES = [
  'nginx:latest',
  'nginx:1.25',
  'nginx:1.24',
  'python:3.12-slim',
  'python:3.11-slim',
  'python:3.10-slim',
  'node:20-slim',
  'node:18-slim',
  'node:16-slim',
  'ubuntu:22.04',
  'ubuntu:20.04',
  'ubuntu:24.04',
  'debian:12-slim',
  'debian:11-slim',
  'alpine:3.19',
  'alpine:3.18',
  'alpine:3.17',
  'redis:7-alpine',
  'redis:6-alpine',
  'postgres:16-alpine',
  'postgres:15-alpine',
  'postgres:14-alpine',
  'mysql:8.0',
  'mysql:5.7',
  'mongo:7',
  'mongo:6',
  'rabbitmq:3-management',
  'elasticsearch:8.12.0',
  'kibana:8.12.0',
  'golang:1.22-alpine',
  'golang:1.21-alpine',
  'eclipse-temurin:21-jre-alpine',
  'eclipse-temurin:17-jre-alpine',
  'eclipse-temurin:11-jre-alpine',
  'amazoncorretto:21',
  'amazoncorretto:17',
  'php:8.3-fpm-alpine',
  'php:8.2-fpm-alpine',
  'ruby:3.3-slim',
  'ruby:3.2-slim',
  'rust:1.76-slim',
  'memcached:1.6-alpine',
  'traefik:v3.0',
  'caddy:2-alpine',
  'haproxy:2.9-alpine',
  'grafana/grafana:10.3.1',
  'prom/prometheus:v2.50.1',
  'curlimages/curl:8.6.0',
  'busybox:1.36',
  'gcr.io/distroless/base-debian12',
];

const DEPENDENCY_TARGETS = [
  'django-app',
  'flask-api',
  'fastapi-service',
  'express-server',
  'react-frontend',
  'vue-dashboard',
  'spring-boot-api',
  'rails-app',
  'laravel-backend',
  'nextjs-app',
  'nuxt-frontend',
  'nestjs-service',
  'gin-api',
  'echo-server',
  'actix-service',
  'axum-api',
  'dotnet-webapi',
  'phoenix-app',
  'quarkus-service',
  'micronaut-app',
];

const DEPENDENCY_PACKAGES: Record<string, Array<{ name: string; version: string; ecosystem: string }>> = {
  'django-app': [
    { name: 'django', version: '4.2.0', ecosystem: 'PyPI' },
    { name: 'djangorestframework', version: '3.14.0', ecosystem: 'PyPI' },
    { name: 'celery', version: '5.3.0', ecosystem: 'PyPI' },
    { name: 'redis', version: '4.6.0', ecosystem: 'PyPI' },
    { name: 'psycopg2-binary', version: '2.9.7', ecosystem: 'PyPI' },
    { name: 'pillow', version: '9.5.0', ecosystem: 'PyPI' },
    { name: 'cryptography', version: '41.0.0', ecosystem: 'PyPI' },
    { name: 'pyjwt', version: '2.8.0', ecosystem: 'PyPI' },
  ],
  'flask-api': [
    { name: 'flask', version: '2.3.0', ecosystem: 'PyPI' },
    { name: 'flask-sqlalchemy', version: '3.0.5', ecosystem: 'PyPI' },
    { name: 'flask-jwt-extended', version: '4.5.2', ecosystem: 'PyPI' },
    { name: 'marshmallow', version: '3.19.0', ecosystem: 'PyPI' },
    { name: 'requests', version: '2.31.0', ecosystem: 'PyPI' },
    { name: 'gunicorn', version: '21.2.0', ecosystem: 'PyPI' },
  ],
  'fastapi-service': [
    { name: 'fastapi', version: '0.100.0', ecosystem: 'PyPI' },
    { name: 'uvicorn', version: '0.23.0', ecosystem: 'PyPI' },
    { name: 'pydantic', version: '2.0.0', ecosystem: 'PyPI' },
    { name: 'sqlalchemy', version: '2.0.18', ecosystem: 'PyPI' },
    { name: 'httpx', version: '0.24.1', ecosystem: 'PyPI' },
    { name: 'python-jose', version: '3.3.0', ecosystem: 'PyPI' },
  ],
  'express-server': [
    { name: 'express', version: '4.18.2', ecosystem: 'npm' },
    { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    { name: 'axios', version: '1.4.0', ecosystem: 'npm' },
    { name: 'jsonwebtoken', version: '9.0.0', ecosystem: 'npm' },
    { name: 'bcrypt', version: '5.1.0', ecosystem: 'npm' },
    { name: 'mongoose', version: '7.4.0', ecosystem: 'npm' },
    { name: 'cors', version: '2.8.5', ecosystem: 'npm' },
  ],
  'react-frontend': [
    { name: 'react', version: '18.2.0', ecosystem: 'npm' },
    { name: 'react-dom', version: '18.2.0', ecosystem: 'npm' },
    { name: 'axios', version: '1.4.0', ecosystem: 'npm' },
    { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    { name: 'moment', version: '2.29.4', ecosystem: 'npm' },
    { name: 'marked', version: '5.1.0', ecosystem: 'npm' },
  ],
  'vue-dashboard': [
    { name: 'vue', version: '3.3.4', ecosystem: 'npm' },
    { name: 'vue-router', version: '4.2.4', ecosystem: 'npm' },
    { name: 'pinia', version: '2.1.6', ecosystem: 'npm' },
    { name: 'axios', version: '1.4.0', ecosystem: 'npm' },
    { name: 'chart.js', version: '4.3.3', ecosystem: 'npm' },
  ],
  'spring-boot-api': [
    { name: 'org.springframework.boot:spring-boot-starter-web', version: '3.1.0', ecosystem: 'Maven' },
    { name: 'org.springframework.boot:spring-boot-starter-security', version: '3.1.0', ecosystem: 'Maven' },
    { name: 'io.jsonwebtoken:jjwt', version: '0.11.5', ecosystem: 'Maven' },
    { name: 'org.postgresql:postgresql', version: '42.6.0', ecosystem: 'Maven' },
  ],
  'rails-app': [
    { name: 'rails', version: '7.0.6', ecosystem: 'RubyGems' },
    { name: 'devise', version: '4.9.2', ecosystem: 'RubyGems' },
    { name: 'sidekiq', version: '7.1.2', ecosystem: 'RubyGems' },
    { name: 'pg', version: '1.5.3', ecosystem: 'RubyGems' },
    { name: 'jwt', version: '2.7.1', ecosystem: 'RubyGems' },
    { name: 'nokogiri', version: '1.15.3', ecosystem: 'RubyGems' },
  ],
  'laravel-backend': [
    { name: 'laravel/framework', version: '10.14.1', ecosystem: 'Packagist' },
    { name: 'tymon/jwt-auth', version: '2.0.0', ecosystem: 'Packagist' },
    { name: 'guzzlehttp/guzzle', version: '7.7.0', ecosystem: 'Packagist' },
    { name: 'predis/predis', version: '2.2.0', ecosystem: 'Packagist' },
  ],
  'nextjs-app': [
    { name: 'next', version: '13.4.10', ecosystem: 'npm' },
    { name: 'react', version: '18.2.0', ecosystem: 'npm' },
    { name: 'next-auth', version: '4.23.1', ecosystem: 'npm' },
    { name: 'axios', version: '1.4.0', ecosystem: 'npm' },
    { name: 'prisma', version: '5.0.0', ecosystem: 'npm' },
  ],
  'nuxt-frontend': [
    { name: 'nuxt', version: '3.6.5', ecosystem: 'npm' },
    { name: 'vue', version: '3.3.4', ecosystem: 'npm' },
    { name: 'axios', version: '1.4.0', ecosystem: 'npm' },
  ],
  'nestjs-service': [
    { name: '@nestjs/core', version: '10.1.1', ecosystem: 'npm' },
    { name: '@nestjs/common', version: '10.1.1', ecosystem: 'npm' },
    { name: '@nestjs/jwt', version: '10.1.0', ecosystem: 'npm' },
    { name: 'typeorm', version: '0.3.17', ecosystem: 'npm' },
    { name: 'class-validator', version: '0.14.0', ecosystem: 'npm' },
  ],
  'gin-api': [
    { name: 'github.com/gin-gonic/gin', version: '1.9.1', ecosystem: 'Go' },
    { name: 'github.com/golang-jwt/jwt', version: '3.2.2', ecosystem: 'Go' },
    { name: 'gorm.io/gorm', version: '1.25.2', ecosystem: 'Go' },
    { name: 'github.com/redis/go-redis/v9', version: '9.0.5', ecosystem: 'Go' },
  ],
  'echo-server': [
    { name: 'github.com/labstack/echo/v4', version: '4.11.1', ecosystem: 'Go' },
    { name: 'github.com/golang-jwt/jwt/v5', version: '5.0.0', ecosystem: 'Go' },
    { name: 'gorm.io/gorm', version: '1.25.2', ecosystem: 'Go' },
  ],
  'actix-service': [
    { name: 'actix-web', version: '4.3.1', ecosystem: 'crates.io' },
    { name: 'serde', version: '1.0.183', ecosystem: 'crates.io' },
    { name: 'tokio', version: '1.32.0', ecosystem: 'crates.io' },
    { name: 'sqlx', version: '0.7.1', ecosystem: 'crates.io' },
    { name: 'jsonwebtoken', version: '8.3.0', ecosystem: 'crates.io' },
  ],
  'axum-api': [
    { name: 'axum', version: '0.6.20', ecosystem: 'crates.io' },
    { name: 'tokio', version: '1.32.0', ecosystem: 'crates.io' },
    { name: 'serde', version: '1.0.183', ecosystem: 'crates.io' },
    { name: 'sqlx', version: '0.7.1', ecosystem: 'crates.io' },
  ],
  'dotnet-webapi': [
    { name: 'Microsoft.AspNetCore.Authentication.JwtBearer', version: '7.0.9', ecosystem: 'NuGet' },
    { name: 'Microsoft.EntityFrameworkCore', version: '7.0.9', ecosystem: 'NuGet' },
    { name: 'Newtonsoft.Json', version: '13.0.3', ecosystem: 'NuGet' },
    { name: 'Serilog', version: '3.0.1', ecosystem: 'NuGet' },
  ],
  'phoenix-app': [
    { name: 'phoenix', version: '1.7.7', ecosystem: 'Hex' },
    { name: 'ecto_sql', version: '3.10.2', ecosystem: 'Hex' },
    { name: 'postgrex', version: '0.17.2', ecosystem: 'Hex' },
    { name: 'guardian', version: '2.3.1', ecosystem: 'Hex' },
  ],
  'quarkus-service': [
    { name: 'io.quarkus:quarkus-resteasy-reactive', version: '3.2.3', ecosystem: 'Maven' },
    { name: 'io.quarkus:quarkus-smallrye-jwt', version: '3.2.3', ecosystem: 'Maven' },
    { name: 'io.quarkus:quarkus-hibernate-orm-panache', version: '3.2.3', ecosystem: 'Maven' },
  ],
  'micronaut-app': [
    { name: 'io.micronaut:micronaut-http-server-netty', version: '4.0.3', ecosystem: 'Maven' },
    { name: 'io.micronaut.security:micronaut-security-jwt', version: '4.0.1', ecosystem: 'Maven' },
    { name: 'io.micronaut.data:micronaut-data-jdbc', version: '4.0.3', ecosystem: 'Maven' },
  ],
};

const SOURCE_TARGETS = [
  '/app/src/api',
  '/app/src/web',
  '/app/src/cli',
  '/app/src/worker',
  '/app/src/scheduler',
  '/app/src/gateway',
  '/app/src/auth',
  '/app/src/billing',
  '/app/src/notifications',
  '/app/src/analytics',
  '/app/src/search',
  '/app/src/storage',
  '/app/src/ml',
  '/app/src/admin',
  '/app/src/reporting',
  '/app/src/integrations',
  '/app/src/payments',
  '/app/src/webhooks',
  '/app/src/jobs',
  '/app/src/monitoring',
];

// ---------------------------------------------------------------------------
// Engine options per scan type
// ---------------------------------------------------------------------------

const CONTAINER_ENGINES = [
  { value: 'grype',      label: 'grype' },
  { value: 'trivy',      label: 'trivy' },
  { value: 'syft_grype', label: 'syft+grype' },
];

const DEP_SOURCE_ENGINES = [
  { value: 'grype',       label: 'grype' },
  { value: 'trivy',       label: 'trivy' },
  { value: 'osv_scanner', label: 'osv-scanner' },
];

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const overlayStyle: React.CSSProperties = {
  position: 'fixed', inset: 0,
  background: 'rgba(0,0,0,0.6)',
  display: 'flex', alignItems: 'center', justifyContent: 'center',
  zIndex: 100,
};

const modalStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 10,
  padding: 24,
  width: 400,
  maxWidth: '95vw',
};

const sectionCard: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  overflow: 'hidden',
};

const sectionHeader: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '12px 16px',
  borderBottom: '1px solid var(--border)',
  background: 'rgba(255,255,255,0.02)',
};

const checkItem: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  padding: '5px 16px',
  cursor: 'pointer',
  borderBottom: '1px solid rgba(51,65,85,0.4)',
  fontSize: 13,
};

const enginePill = (active: boolean): React.CSSProperties => ({
  padding: '3px 12px',
  borderRadius: 20,
  border: '1px solid var(--border)',
  background: active ? 'var(--accent)' : 'transparent',
  color: active ? '#fff' : 'var(--text-secondary)',
  cursor: 'pointer',
  fontSize: 12,
  fontFamily: 'monospace',
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Column component
// ---------------------------------------------------------------------------

interface ColumnProps {
  title: string;
  items: string[];
  selected: Set<string>;
  onToggle: (item: string) => void;
  onToggleAll: () => void;
  engines: Array<{ value: string; label: string }>;
  engine: string;
  onEngine: (e: string) => void;
  color: string;
}

function Column({ title, items, selected, onToggle, onToggleAll, engines, engine, onEngine, color }: ColumnProps) {
  const allSelected = items.every(i => selected.has(i));
  return (
    <div style={{ ...sectionCard, display: 'flex', flexDirection: 'column', flex: 1, minWidth: 0 }}>
      <div style={sectionHeader}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <button onClick={onToggleAll} style={{ background: 'none', border: 'none', cursor: 'pointer', color, display: 'flex', padding: 0 }}>
            {allSelected ? <CheckSquare size={15} /> : <Square size={15} />}
          </button>
          <span style={{ fontWeight: 600, fontSize: 14, color }}>{title}</span>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            {selected.size}/{items.length}
          </span>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {engines.map(e => (
            <button key={e.value} onClick={() => onEngine(e.value)} style={enginePill(engine === e.value)}>
              {e.label}
            </button>
          ))}
        </div>
      </div>
      <div style={{ overflowY: 'auto', maxHeight: 420, flex: 1 }}>
        {items.map(item => (
          <div
            key={item}
            style={{
              ...checkItem,
              background: selected.has(item) ? 'rgba(59,130,246,0.06)' : 'transparent',
            }}
            onClick={() => onToggle(item)}
            onMouseEnter={e => { if (!selected.has(item)) e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = selected.has(item) ? 'rgba(59,130,246,0.06)' : 'transparent'; }}
          >
            <span style={{ color: selected.has(item) ? color : 'var(--text-secondary)', flexShrink: 0 }}>
              {selected.has(item) ? <CheckSquare size={13} /> : <Square size={13} />}
            </span>
            <span style={{ fontFamily: 'monospace', fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {item}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

type EnqueueStatus = 'idle' | 'running' | 'done' | 'error';

interface LogEntry {
  target: string;
  engine: string;
  ok: boolean;
  msg: string;
}

export default function SeedScans() {
  // Selection state
  const [containerSel, setContainerSel] = useState<Set<string>>(new Set(CONTAINER_IMAGES));
  const [depSel,       setDepSel]       = useState<Set<string>>(new Set(DEPENDENCY_TARGETS));
  const [srcSel,       setSrcSel]       = useState<Set<string>>(new Set(SOURCE_TARGETS));

  // Engine state
  const [containerEngine, setContainerEngine] = useState('grype');
  const [depEngine,       setDepEngine]       = useState('grype');
  const [srcEngine,       setSrcEngine]       = useState('grype');

  // Enqueue progress
  const [status,   setStatus]   = useState<EnqueueStatus>('idle');
  const [progress, setProgress] = useState(0);
  const [total,    setTotal]    = useState(0);
  const [log,      setLog]      = useState<LogEntry[]>([]);
  const logRef = useRef<HTMLDivElement>(null);

  // Delete confirm
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showFlushConfirm, setShowFlushConfirm] = useState(false);

  const qc = useQueryClient();

  const deleteAllMutation = useMutation({
    mutationFn: deleteAllScans,
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      setShowDeleteConfirm(false);
      addLog({ target: '(all scans)', engine: '', ok: true, msg: `Deleted ${data.deleted} scans` });
    },
  });

  const flushMutation = useMutation({
    mutationFn: flushQueue,
    onSuccess: (data) => {
      setShowFlushConfirm(false);
      addLog({ target: '(queue)', engine: '', ok: true, msg: `Flushed ${data.purged} queued tasks` });
    },
  });

  function addLog(entry: LogEntry) {
    setLog(prev => {
      const next = [...prev, entry];
      // scroll to bottom
      setTimeout(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, 20);
      return next;
    });
  }

  function toggle(set: Set<string>, item: string, setter: (s: Set<string>) => void) {
    const next = new Set(set);
    if (next.has(item)) next.delete(item); else next.add(item);
    setter(next);
  }

  function toggleAll(items: string[], set: Set<string>, setter: (s: Set<string>) => void) {
    if (items.every(i => set.has(i))) setter(new Set());
    else setter(new Set(items));
  }

  const totalSelected = containerSel.size + depSel.size + srcSel.size;

  async function handleEnqueue() {
    setStatus('running');
    setProgress(0);
    setLog([]);

    const jobs: Array<() => Promise<void>> = [];

    for (const target of containerSel) {
      jobs.push(async () => {
        try {
          await createScan({ scan_type: 'container', target, scanner_override: containerEngine });
          addLog({ target, engine: containerEngine, ok: true, msg: 'queued' });
        } catch {
          addLog({ target, engine: containerEngine, ok: false, msg: 'failed to enqueue' });
        }
      });
    }

    for (const target of depSel) {
      jobs.push(async () => {
        try {
          const packages = DEPENDENCY_PACKAGES[target];
          await createScan({ scan_type: 'dependency', target, packages, scanner_override: depEngine });
          addLog({ target, engine: depEngine, ok: true, msg: 'queued' });
        } catch {
          addLog({ target, engine: depEngine, ok: false, msg: 'failed to enqueue' });
        }
      });
    }

    for (const target of srcSel) {
      jobs.push(async () => {
        try {
          await createScan({ scan_type: 'source', target, scanner_override: srcEngine });
          addLog({ target, engine: srcEngine, ok: true, msg: 'queued' });
        } catch {
          addLog({ target, engine: srcEngine, ok: false, msg: 'failed to enqueue' });
        }
      });
    }

    setTotal(jobs.length);

    // Run in batches of 5 with a small delay to avoid flooding
    const BATCH = 5;
    let done = 0;
    for (let i = 0; i < jobs.length; i += BATCH) {
      const batch = jobs.slice(i, i + BATCH);
      await Promise.all(batch.map(fn => fn()));
      done += batch.length;
      setProgress(done);
      if (i + BATCH < jobs.length) await sleep(200);
    }

    qc.invalidateQueries({ queryKey: ['scans'] });
    setStatus('done');
  }

  const isRunning = status === 'running';

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <FlaskConical size={22} color="var(--accent)" />
          <h1 style={{ fontSize: 24, fontWeight: 700 }}>Seed Scans</h1>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            onClick={() => setShowFlushConfirm(true)}
            disabled={isRunning}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'transparent',
              border: '1px solid var(--warning)',
              color: 'var(--warning)',
              borderRadius: 6, padding: '8px 14px',
              fontWeight: 600, cursor: 'pointer', fontSize: 13,
              opacity: isRunning ? 0.4 : 1,
            }}
          >
            <Radio size={14} /> Flush Queue
          </button>
          <button
            onClick={() => setShowDeleteConfirm(true)}
            disabled={isRunning}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'transparent',
              border: '1px solid var(--critical)',
              color: 'var(--critical)',
              borderRadius: 6, padding: '8px 14px',
              fontWeight: 600, cursor: 'pointer', fontSize: 13,
              opacity: isRunning ? 0.4 : 1,
            }}
          >
            <Trash2 size={14} /> Delete All Scans
          </button>
          <button
            onClick={handleEnqueue}
            disabled={isRunning || totalSelected === 0}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--accent)', color: '#fff',
              border: 'none', borderRadius: 6, padding: '8px 16px',
              fontWeight: 600, cursor: 'pointer', fontSize: 13,
              opacity: (isRunning || totalSelected === 0) ? 0.5 : 1,
            }}
          >
            <Play size={14} />
            {isRunning ? `Enqueueing… ${progress}/${total}` : `Enqueue ${totalSelected} Scans`}
          </button>
        </div>
      </div>

      <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 20 }}>
        Select targets and engines below, then click Enqueue. Each selected item is submitted as a separate scan job.
      </p>

      {/* Progress bar */}
      {(status === 'running' || status === 'done') && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${total > 0 ? (progress / total) * 100 : 0}%`,
              background: status === 'done' ? 'var(--low)' : 'var(--accent)',
              transition: 'width 0.2s ease',
              borderRadius: 3,
            }} />
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
            {status === 'done' ? `Done — ${progress} scans enqueued` : `${progress} / ${total}`}
          </div>
        </div>
      )}

      {/* Three columns */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'flex-start' }}>
        <Column
          title="Container Images"
          items={CONTAINER_IMAGES}
          selected={containerSel}
          onToggle={item => toggle(containerSel, item, setContainerSel)}
          onToggleAll={() => toggleAll(CONTAINER_IMAGES, containerSel, setContainerSel)}
          engines={CONTAINER_ENGINES}
          engine={containerEngine}
          onEngine={setContainerEngine}
          color="var(--accent)"
        />
        <Column
          title="Dependencies"
          items={DEPENDENCY_TARGETS}
          selected={depSel}
          onToggle={item => toggle(depSel, item, setDepSel)}
          onToggleAll={() => toggleAll(DEPENDENCY_TARGETS, depSel, setDepSel)}
          engines={DEP_SOURCE_ENGINES}
          engine={depEngine}
          onEngine={setDepEngine}
          color="var(--low)"
        />
        <Column
          title="Source Paths"
          items={SOURCE_TARGETS}
          selected={srcSel}
          onToggle={item => toggle(srcSel, item, setSrcSel)}
          onToggleAll={() => toggleAll(SOURCE_TARGETS, srcSel, setSrcSel)}
          engines={DEP_SOURCE_ENGINES}
          engine={srcEngine}
          onEngine={setSrcEngine}
          color="#a78bfa"
        />
      </div>

      {/* Log */}
      {log.length > 0 && (
        <div style={{ ...sectionCard }}>
          <div style={{ ...sectionHeader }}>
            <span style={{ fontWeight: 600, fontSize: 13 }}>Enqueue Log</span>
            <button onClick={() => setLog([])} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              <X size={14} />
            </button>
          </div>
          <div ref={logRef} style={{ maxHeight: 240, overflowY: 'auto', padding: '8px 0', fontFamily: 'monospace', fontSize: 12 }}>
            {log.map((entry, i) => (
              <div key={i} style={{ padding: '2px 16px', color: entry.ok ? 'var(--low)' : 'var(--critical)', whiteSpace: 'nowrap' }}>
                {entry.ok ? '✓' : '✗'} {entry.target}
                {entry.engine && <span style={{ color: 'var(--text-secondary)', marginLeft: 8 }}>[{entry.engine}]</span>}
                <span style={{ color: 'var(--text-secondary)', marginLeft: 8 }}>{entry.msg}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Flush Queue Confirmation Modal */}
      {showFlushConfirm && (
        <div style={overlayStyle} onClick={() => setShowFlushConfirm(false)}>
          <div style={modalStyle} onClick={e => e.stopPropagation()}>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 12 }}>Flush Queue</h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: 24, lineHeight: 1.6 }}>
              This will remove all <strong style={{ color: 'var(--text-primary)' }}>pending tasks</strong> from the Celery queue. Any scans currently <em>running</em> on workers will finish, but nothing new will be picked up from the queue. Scan rows already in the DB are not affected.
            </p>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button
                onClick={() => setShowFlushConfirm(false)}
                style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, padding: '8px 16px', cursor: 'pointer' }}
              >
                Cancel
              </button>
              <button
                onClick={() => flushMutation.mutate()}
                disabled={flushMutation.isPending}
                style={{ background: 'var(--warning)', color: '#000', border: 'none', borderRadius: 6, padding: '8px 16px', fontWeight: 600, cursor: 'pointer' }}
              >
                {flushMutation.isPending ? 'Flushing…' : 'Flush Queue'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete All Confirmation Modal */}
      {showDeleteConfirm && (
        <div style={overlayStyle} onClick={() => setShowDeleteConfirm(false)}>
          <div style={modalStyle} onClick={e => e.stopPropagation()}>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 12 }}>Delete All Scans</h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: 24, lineHeight: 1.6 }}>
              This will permanently delete <strong style={{ color: 'var(--text-primary)' }}>every scan</strong> in the database, including all findings, SBOMs, and policy results. This cannot be undone.
            </p>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button
                onClick={() => setShowDeleteConfirm(false)}
                style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, padding: '8px 16px', cursor: 'pointer' }}
              >
                Cancel
              </button>
              <button
                onClick={() => deleteAllMutation.mutate()}
                disabled={deleteAllMutation.isPending}
                style={{ background: 'var(--critical)', color: '#fff', border: 'none', borderRadius: 6, padding: '8px 16px', fontWeight: 600, cursor: 'pointer' }}
              >
                {deleteAllMutation.isPending ? 'Deleting…' : 'Delete All'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
