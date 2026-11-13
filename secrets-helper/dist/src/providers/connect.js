// 1Password Connect: the REST API of the customer's own Connect server (Bearer = the Connect token).
//   GET /v1/vaults                       -> [{id, name}]
//   GET /v1/vaults/{vault}/items         -> [{id, title}]
//   GET /v1/vaults/{vault}/items/{item}  -> {id, title, sections: [{id, label}], fields: [{id, label, value, section: {id}}]}
// Vaults, items, sections and fields match by id or, case-insensitively, by name (as op:// does).
import { getJson, ProviderFailure } from "./types.js";
const same = (a, want) => a !== undefined && a.toLowerCase() === want.toLowerCase();
const matches = (n, want) => n.id === want || same(n.name ?? n.title ?? n.label, want);
export class ConnectProvider {
    token;
    base;
    constructor(token, host) {
        this.token = token;
        const url = new URL(host); // throws on a malformed host: the caller reports bad_config
        if (url.protocol !== "https:" && url.protocol !== "http:")
            throw new ProviderFailure("bad_config", "the Connect host is an http(s) URL");
        this.base = url.origin + url.pathname.replace(/\/+$/, "");
    }
    async get(path, signal) {
        const { status, body } = await getJson(this.base + path, { headers: { authorization: `Bearer ${this.token}`, accept: "application/json" }, signal });
        if (status === 401 || status === 403)
            throw new ProviderFailure("denied", `the Connect server refused the token (HTTP ${status})`);
        if (status === 404)
            return undefined;
        if (status < 200 || status >= 300)
            throw new ProviderFailure("provider_error", `the Connect server answered HTTP ${status}`);
        return body;
    }
    async list(path, signal) {
        const body = await this.get(path, signal);
        if (body !== undefined && !Array.isArray(body))
            throw new ProviderFailure("provider_error", "the Connect server sent an unexpected list");
        return body ?? [];
    }
    async check(signal) {
        try {
            const vaults = await this.list("/v1/vaults", signal);
            return { ok: true, detail: `${vaults.length} vault${vaults.length === 1 ? "" : "s"} visible` };
        }
        catch (e) {
            if (e instanceof ProviderFailure)
                return { ok: false, error: e.error, message: e.message };
            throw e;
        }
    }
    async resolve(refs, signal) {
        const vaults = await this.list("/v1/vaults", signal);
        const items = new Map();
        const full = new Map();
        const out = [];
        for (const ref of refs) {
            if (ref.scheme !== "op") {
                out.push({ ok: false, error: "invalid_ref", message: "a 1Password Connect reference starts with op://" });
                continue;
            }
            out.push(await this.one(ref, vaults, items, full, signal));
        }
        return out;
    }
    async one(ref, vaults, items, full, signal) {
        if (ref.attribute && ref.attribute !== "value")
            return { ok: false, error: "invalid_ref", message: `the attribute ${JSON.stringify(ref.attribute)} is not supported through Connect` };
        const vs = vaults.filter((v) => matches(v, ref.vault));
        if (vs.length !== 1)
            return { ok: false, error: "not_found", message: vs.length ? "more than one vault matches" : "no such vault" };
        const vid = vs[0].id;
        if (!items.has(vid))
            items.set(vid, await this.list(`/v1/vaults/${encodeURIComponent(vid)}/items`, signal));
        const is = items.get(vid).filter((i) => matches(i, ref.item));
        if (is.length !== 1)
            return { ok: false, error: "not_found", message: is.length ? "more than one item matches" : "no such item" };
        const key = `${vid}/${is[0].id}`;
        if (!full.has(key))
            full.set(key, (await this.get(`/v1/vaults/${encodeURIComponent(vid)}/items/${encodeURIComponent(is[0].id)}`, signal)));
        const item = full.get(key);
        if (!item)
            return { ok: false, error: "not_found", message: "no such item" };
        let fields = item.fields ?? [];
        if (ref.section !== undefined) {
            const sections = (item.sections ?? []).filter((s) => matches(s, ref.section));
            if (sections.length !== 1)
                return { ok: false, error: "not_found", message: sections.length ? "more than one section matches" : "no such section" };
            fields = fields.filter((f) => f.section?.id === sections[0].id);
        }
        let hits = fields.filter((f) => matches(f, ref.field));
        // op://vault/item/field: a field outside any section wins over same-named ones inside sections
        if (ref.section === undefined && hits.length > 1) {
            const top = hits.filter((f) => !f.section?.id);
            if (top.length === 1)
                hits = top;
        }
        if (hits.length !== 1)
            return { ok: false, error: "not_found", message: hits.length ? "more than one field matches" : "no such field" };
        const value = hits[0].value;
        if (typeof value !== "string" || value.length === 0)
            return { ok: false, error: "not_found", message: "the field is empty" };
        return { ok: true, value };
    }
}
