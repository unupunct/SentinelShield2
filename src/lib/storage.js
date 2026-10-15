// Strat subțire peste chrome.storage cu implementare în memorie pentru teste.
export function createMemoryArea() {
  const data = {};
  return {
    async get(keys) {
      if (keys == null) return structuredClone(data);
      const list = Array.isArray(keys) ? keys : typeof keys === 'string' ? [keys] : Object.keys(keys);
      const out = {};
      for (const k of list) if (k in data) out[k] = structuredClone(data[k]);
      return out;
    },
    async set(obj) { for (const [k, v] of Object.entries(obj)) data[k] = structuredClone(v); },
    async remove(keys) { for (const k of [].concat(keys)) delete data[k]; },
    async clear() { for (const k of Object.keys(data)) delete data[k]; },
    _data: data
  };
}

export function createStore(area) {
  return {
    async get(key, fallback = undefined) {
      const r = await area.get(key);
      return key in r ? r[key] : fallback;
    },
    async set(key, value) { await area.set({ [key]: value }); },
    async remove(key) { await area.remove(key); },
    async all() { return (await area.get(null)) ?? {}; }
  };
}

/** Coadă simplă: serializează operațiunile read-modify-write (evită pierderea de evenimente la scrieri concurente). */
export function createMutex() {
  let tail = Promise.resolve();
  return (fn) => {
    const run = tail.then(fn, fn);
    tail = run.catch(() => {});
    return run;
  };
}
