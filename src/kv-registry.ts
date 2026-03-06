import type {
  Registry,
  RegistryMeta,
  RegistryNamespace,
  TypeIndex,
} from "./types";

/**
 * Per-request KV access with in-request caching.
 *
 * Each incoming request creates a RegistryContext that caches KV reads
 * for the duration of that request. This avoids redundant KV fetches
 * when both the parser and resolver need the same data.
 */
export class RegistryContext {
  private kv: KVNamespace;
  private typeCache = new Map<string, TypeIndex | null>();
  private nsCache = new Map<string, RegistryNamespace | null>();

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async getTypeIndex(type: string): Promise<TypeIndex | null> {
    if (this.typeCache.has(type)) return this.typeCache.get(type)!;
    const data = await this.kv.get<TypeIndex>(`type:${type}`, "json");
    this.typeCache.set(type, data);
    return data;
  }

  async getNamespace(
    type: string,
    namespace: string
  ): Promise<RegistryNamespace | null> {
    const key = `${type}/${namespace}`;
    if (this.nsCache.has(key)) return this.nsCache.get(key)!;
    const data = await this.kv.get<RegistryNamespace>(`ns:${key}`, "json");
    this.nsCache.set(key, data);
    return data;
  }

  async getNamespaces(
    type: string,
    namespaces: string[]
  ): Promise<Map<string, RegistryNamespace>> {
    const result = new Map<string, RegistryNamespace>();
    const toFetch: string[] = [];

    for (const ns of namespaces) {
      const key = `${type}/${ns}`;
      if (this.nsCache.has(key)) {
        const cached = this.nsCache.get(key);
        if (cached) result.set(ns, cached);
      } else {
        toFetch.push(ns);
      }
    }

    if (toFetch.length > 0) {
      const fetches = toFetch.map(async (ns) => {
        const data = await this.kv.get<RegistryNamespace>(
          `ns:${type}/${ns}`,
          "json"
        );
        this.nsCache.set(`${type}/${ns}`, data);
        if (data) result.set(ns, data);
      });
      await Promise.all(fetches);
    }

    return result;
  }

  async getFullRegistry(): Promise<Registry | null> {
    return this.kv.get<Registry>("full:registry", "json");
  }

  async getMeta(): Promise<RegistryMeta | null> {
    return this.kv.get<RegistryMeta>("meta:registry", "json");
  }
}
