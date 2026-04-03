import type { AuthService } from './auth/auth-service';
import type { FortressConfig } from './config';
import type { IamService } from './iam/iam-service';
import { createAuthService } from './auth/auth-service';
import { Errors } from './errors';
import { createIamService } from './iam/iam-service';
import { processPlugins } from './plugin-runner';

export interface Fortress {
  auth: AuthService;
  iam: IamService;
  // eslint-disable-next-line ts/no-unsafe-function-type -- plugin methods are dynamically typed
  plugins: Record<string, Record<string, Function>>;
  config: Readonly<FortressConfig>;
}

export function createFortress(config: FortressConfig): Fortress {
  const plugins = config.plugins ?? [];
  const db = config.database;

  // Validate plugin name uniqueness
  const pluginNames = new Set<string>();
  for (const plugin of plugins) {
    if (pluginNames.has(plugin.name)) {
      throw Errors.badRequest(`Duplicate plugin name: '${plugin.name}'`);
    }
    pluginNames.add(plugin.name);
  }

  const auth = createAuthService(db, config, plugins);
  const iam = createIamService(db, config);
  const pluginMethods = processPlugins(plugins, db, config);

  return {
    auth,
    iam,
    plugins: pluginMethods,
    config,
  };
}
