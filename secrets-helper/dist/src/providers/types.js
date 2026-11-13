export const KINDS = ["onepassword_connect", "onepassword_service_account", "bitwarden_sm"];
/** A provider call failed as a whole (auth, network): every reference of the request gets it. */
export class ProviderFailure extends Error {
    error;
    constructor(error, message) {
        super(message);
        this.error = error;
    }
}
/** fetch with the request's abort signal and a JSON body; never follows redirects (a token must not
 * be sent on to another host). */
export async function getJson(url, init) {
    const res = await fetch(url, { ...init, redirect: "manual" });
    const text = await res.text();
    let body = undefined;
    try {
        body = text ? JSON.parse(text) : undefined;
    }
    catch {
        body = undefined;
    }
    return { status: res.status, body };
}
