import { describe, expect, it } from 'vitest';
import { forkget } from '../../package.json';
import { connectionCommand, connectionEngines, defaultPort, defaultSettings, readConnectionSettings } from './connection';

describe('stored connection preferences', () => {
  const saved = { ...defaultSettings, engine: 'mysql', host: 'db.example', port: '13306', username: 'owner', caFile: 'db-ca.pem' };

  it('keeps a supported engine and its endpoint', () => {
    expect(readConnectionSettings(saved)).toEqual(saved);
  });

  it('resets the entire connection when its engine is excluded', () => {
    expect(connectionEngines.map(({ value }) => value)).toEqual(forkget.connectionEngines);
    expect(readConnectionSettings({ ...saved, engine: 'unknown' })).toEqual(defaultSettings);

    const tidb = { ...saved, engine: 'tidb' };
    const expected = forkget.connectionEngines.includes('tidb') ? tidb : defaultSettings;
    expect(readConnectionSettings(tidb)).toEqual(expected);
  });
});

describe('native client command generation', () => {
  it('selects the branch database and retains verified TLS', () => {
    expect(connectionCommand({ ...defaultSettings, username: 'alice' }, 'branch-one')).toContain("--dbname 'branch-one'");
    expect(connectionCommand(defaultSettings, 'branch-one')).toContain('PGSSLMODE=verify-full');
    expect(connectionCommand({ ...defaultSettings, engine: 'mysql' }, 'branch-one')).toContain('--ssl-mode=VERIFY_IDENTITY -p');
    expect(connectionCommand({ ...defaultSettings, engine: 'tidb' }, 'branch-one')).toContain('mysql --host');
    expect(connectionCommand({ ...defaultSettings, engine: 'mongodb' }, 'branch-one')).toContain('--tls --tlsCAFile');
    expect(defaultPort('mongodb')).toBe('28017');
    expect(connectionCommand({ ...defaultSettings, engine:'mongodb', port:defaultPort('mongodb') }, 'branch-one')).toContain('28017/branch-one?authSource=admin&directConnection=true&retryWrites=false');
  });
  it('quotes user-supplied settings and never inserts an API token or password', () => {
    const value = connectionCommand({ ...defaultSettings, username: "test' $(bad)", caFile: 'path with spaces/ca.pem' }, 'test-branch');
    expect(value).toContain("--username 'test'\\'' $(bad)'");
    expect(value).toContain("PGSSLROOTCERT='path with spaces/ca.pem'");
    expect(value).not.toContain('password=');
  });
});
