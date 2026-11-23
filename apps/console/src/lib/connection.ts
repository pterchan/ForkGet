import { forkget } from '../../package.json';
import type { Engine } from './model';

export const connectionEngines = ([
  { value: 'postgresql', label: 'PostgreSQL' },
  { value: 'mysql', label: 'MySQL' },
  { value: 'tidb', label: 'TiDB' },
  { value: 'mongodb', label: 'MongoDB' }
] satisfies { value: Engine; label: string }[]).filter(({ value }) => forkget.connectionEngines.includes(value));

export interface ConnectionSettings { engine: string; host: string; port: string; username: string; caFile: string; deployment: string }
export const defaultSettings: ConnectionSettings = { engine: 'postgresql', host: '127.0.0.1', port: '5432', username: '', caFile: 'proxy-ca.pem', deployment: 'Local Forkget' };
export const defaultPort = (engine: string) => engine === 'postgresql' ? '5432' : engine === 'mongodb' ? '28017' : '3306';

export function readConnectionSettings(stored: unknown): ConnectionSettings {
  const settings = { ...defaultSettings };
  if (typeof stored !== 'object' || stored === null) return settings;

  const saved = stored as Record<string, unknown>;
  // An endpoint saved for a different engine must not be reused with fallback settings.
  if (typeof saved.engine === 'string' && !connectionEngines.some(({ value }) => value === saved.engine)) {
    return settings;
  }

  for (const key of Object.keys(settings) as (keyof ConnectionSettings)[]) {
    const value = saved[key];
    if (typeof value === 'string') settings[key] = value;
  }
  return settings;
}

const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
export function connectionCommand(settings: ConnectionSettings, name: string): string {
  const { host, port, username, caFile, engine } = settings;
  if (engine === 'postgresql') return `PGSSLMODE=verify-full PGSSLROOTCERT=${quote(caFile)} psql --host ${quote(host)} --port ${quote(port)} --username ${quote(username || '<frontend-user>')} --dbname ${quote(name)}`;
  if (engine === 'mongodb') {
    const address = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
    const uri = `mongodb://${address}:${port}/${encodeURIComponent(name)}?authSource=admin&directConnection=true&retryWrites=false`;
    return `mongosh ${quote(uri)} --username ${quote(username || '<frontend-user>')} --tls --tlsCAFile ${quote(caFile)} --password`;
  }
  return `mysql --host ${quote(host)} --port ${quote(port)} --user ${quote(username || '<frontend-user>')} --database ${quote(name)} --ssl-ca ${quote(caFile)} --ssl-mode=VERIFY_IDENTITY -p`;
}
