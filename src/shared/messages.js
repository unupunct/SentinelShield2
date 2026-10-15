/**
 * SentinelShield2 - tipurile de mesaje schimbate între paginile extensiei și
 * service worker. Centralizate aici pentru a evita șiruri duplicate.
 */

export const MSG = Object.freeze({
  // Analiză
  ANALYZE_URL: 'analyze:url',
  ANALYZE_ACTIVE_TAB: 'analyze:activeTab',

  // Context UI
  GET_CONTEXT: 'ui:context',
  GET_LAST_ANALYSIS: 'ui:lastAnalysis',
  OPEN_DETAILS: 'ui:openDetails',
  OPEN_OPTIONS: 'ui:openOptions',
  GET_RULES: 'ui:rules',

  // Setări
  GET_SETTINGS: 'settings:get',
  SAVE_SETTINGS: 'settings:save',

  // Liste
  GET_LISTS: 'lists:get',
  LIST_ADD: 'lists:add',
  LIST_REMOVE: 'lists:remove',

  // Configurare
  EXPORT_CONFIG: 'config:export',
  IMPORT_CONFIG: 'config:import',
  RESET_ALL: 'config:reset',

  // Pagina de avertizare
  GET_PENDING_WARNING: 'warning:pending',
  CONTINUE_ANYWAY: 'warning:continue',
  GO_BACK_SAFELY: 'warning:back',

  // Permisiuni web
  GET_PAGE_PERMISSIONS: 'permissions:page',

  // Monitorizarea navigării (înregistrare la cerere, după acordarea permisiunilor)
  REGISTER_NAVIGATION: 'navigation:register',
});

/** Nivelurile de risc pentru care se aplică o excepție temporară (în minute). */
export const TEMP_EXCEPTION_MINUTES = 10;

/** Prefixele cheilor din chrome.storage.session. */
export const SESSION_KEYS = Object.freeze({
  PENDING_WARNING: 'session.pendingWarning',
  LAST_ANALYSIS: 'session.lastAnalysis',
  TEMP_ALLOW: 'session.tempAllow',
  PENDING_DETAILS: 'session.pendingDetails',
  LAST_ERROR: 'session.lastError',
  NAVIGATION_STATE: 'session.navigationState',
});
