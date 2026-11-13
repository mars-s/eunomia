// Every message the sidecar logs or returns passes through here: the request's token (raw, URL-encoded
// and base64url forms) becomes [token] and every value it resolved becomes [value].
export class Scrubber {
    secrets = [];
    token(t) {
        if (t && t.length >= 4) {
            this.add(t, "[token]");
            this.add(encodeURIComponent(t), "[token]");
            this.add(Buffer.from(t).toString("base64url"), "[token]");
        }
        return this;
    }
    value(v) {
        if (v.length >= 4)
            this.add(v, "[value]");
        return this;
    }
    add(s, mark) {
        if (!this.secrets.some(([x]) => x === s))
            this.secrets.push([s, mark]);
        // longest first, so a token is never left half replaced by a shorter overlapping one
        this.secrets.sort((a, b) => b[0].length - a[0].length);
    }
    clean(text) {
        let out = text;
        for (const [s, mark] of this.secrets)
            out = out.split(s).join(mark);
        return out;
    }
}
