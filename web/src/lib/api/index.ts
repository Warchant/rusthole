// The API object that pages use. main.ts calls initApi() once at start.

import { ApiError, createClient, type ClientOptions } from './client';
import { makeApi, type Api } from './endpoints';

export { ApiError };
export type { Api };

export let api: Api = makeApi(
  createClient({ fetch: (url, init) => fetch(url, init), getCsrfToken: () => null }),
);

export function initApi(options: ClientOptions): void {
  api = makeApi(createClient(options));
}

/** Text for an error that people can read. */
export function errorText(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.code === 'config_conflict') {
      return 'The config file changed on disk. The data was loaded again. Do the change again.';
    }
    if (err.details.length > 0) return err.details.map((d) => d.message).join(' ');
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}
