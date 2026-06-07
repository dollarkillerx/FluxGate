/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Bearer token sent on every /rpc request. Optional in dev. */
  readonly VITE_ADMIN_TOKEN?: string
  /** When 'true', serve responses from the in-repo mock instead of /rpc. */
  readonly VITE_USE_MOCK?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
