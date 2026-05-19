//#region node_modules/@noble/ciphers/utils.js
function e(e) {
	return e instanceof Uint8Array || ArrayBuffer.isView(e) && e.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in e && e.BYTES_PER_ELEMENT === 1;
}
function t(e) {
	if (typeof e != "boolean") throw TypeError(`boolean expected, not ${e}`);
}
function n(e) {
	if (typeof e != "number") throw TypeError("number expected, got " + typeof e);
	if (!Number.isSafeInteger(e) || e < 0) throw RangeError("positive integer expected, got " + e);
}
function r(t, n, r = "") {
	let i = e(t), a = t?.length, o = n !== void 0;
	if (!i || o && a !== n) {
		let e = r && `"${r}" `, s = o ? ` of length ${n}` : "", c = i ? `length=${a}` : `type=${typeof t}`, l = e + "expected Uint8Array" + s + ", got " + c;
		throw i ? RangeError(l) : TypeError(l);
	}
	return t;
}
function i(e, t = !0) {
	if (e.destroyed) throw Error("Hash instance has been destroyed");
	if (t && e.finished) throw Error("Hash#digest() has already been called");
}
function a(e, t, n = !1) {
	r(e, void 0, "output");
	let i = t.outputLen;
	if (e.length < i) throw RangeError("digestInto() expects output buffer of length at least " + i);
	if (n && !v(e)) throw Error("invalid output, must be aligned");
}
function o(e) {
	return new Uint32Array(e.buffer, e.byteOffset, Math.floor(e.byteLength / 4));
}
function s(...e) {
	for (let t = 0; t < e.length; t++) e[t].fill(0);
}
function c(e) {
	return new DataView(e.buffer, e.byteOffset, e.byteLength);
}
var l = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68, u = (e) => e << 24 & 4278190080 | e << 8 & 16711680 | e >>> 8 & 65280 | e >>> 24 & 255, d = l ? (e) => e : (e) => {
	for (let t = 0; t < e.length; t++) e[t] = u(e[t]);
	return e;
};
typeof Uint8Array.from([]).toHex == "function" && Uint8Array.fromHex;
function f(e, t) {
	if (typeof t != "object" || !t) throw Error("options must be defined");
	return Object.assign(e, t);
}
function p(e, t) {
	if (e.length !== t.length) return !1;
	let n = 0;
	for (let r = 0; r < e.length; r++) n |= e[r] ^ t[r];
	return n === 0;
}
function m(e, t, n) {
	let r = t, i = n || (() => []), a = (e, t) => r(t, ...i(e)).update(e).digest(), o = r(new Uint8Array(e), ...i(new Uint8Array()));
	return a.outputLen = o.outputLen, a.blockLen = o.blockLen, a.create = (e, ...t) => r(e, ...t), a;
}
var h = (e, t) => {
	function n(n, ...i) {
		if (r(n, void 0, "key"), e.nonceLength !== void 0) {
			let t = i[0];
			r(t, e.varSizeNonce ? void 0 : e.nonceLength, "nonce");
		}
		let a = e.tagLength;
		a && i[1] !== void 0 && r(i[1], void 0, "AAD");
		let o = t(n, ...i), s = (e, t) => {
			if (t !== void 0) {
				if (e !== 2) throw Error("cipher output not supported");
				r(t, void 0, "output");
			}
		}, c = !1;
		return {
			encrypt(e, t) {
				if (c) throw Error("cannot encrypt() twice with same key + nonce");
				return c = !0, r(e), s(o.encrypt.length, t), o.encrypt(e, t);
			},
			decrypt(e, t) {
				if (r(e), a && e.length < a) throw Error("\"ciphertext\" expected length bigger than tagLength=" + a);
				return s(o.decrypt.length, t), o.decrypt(e, t);
			}
		};
	}
	return Object.assign(n, e), n;
};
function g(e, t, n = !0) {
	if (t === void 0) return new Uint8Array(e);
	if (r(t, void 0, "output"), t.length !== e) throw Error("\"output\" expected Uint8Array of length " + e + ", got: " + t.length);
	if (n && !v(t)) throw Error("invalid output, must be aligned");
	return t;
}
function _(e, r, i) {
	n(e), n(r), t(i);
	let a = new Uint8Array(16), o = c(a);
	return o.setBigUint64(0, BigInt(r), i), o.setBigUint64(8, BigInt(e), i), a;
}
function v(e) {
	return e.byteOffset % 4 == 0;
}
function y(e) {
	return Uint8Array.from(r(e));
}
function b(e = 32) {
	n(e);
	let t = typeof globalThis == "object" ? globalThis.crypto : null;
	if (typeof t?.getRandomValues != "function") throw Error("crypto.getRandomValues must be defined");
	return t.getRandomValues(new Uint8Array(e));
}
//#endregion
//#region node_modules/@noble/ciphers/_arx.js
var x = (e) => Uint8Array.from(e.split(""), (e) => e.charCodeAt(0)), S = d(o(x("expand 16-byte k"))), C = d(o(x("expand 32-byte k")));
function w(e, t) {
	return e << t | e >>> 32 - t;
}
var T = 64, E = 16, D = 2 ** 32 - 1, O = /* @__PURE__ */ Uint32Array.of();
function k(e, t, n, r, i, a, s, c) {
	let u = i.length, f = new Uint8Array(T), p = o(f), m = l && v(i) && v(a), h = m ? o(i) : O, g = m ? o(a) : O;
	if (!l) {
		for (let o = 0; o < u; s++) {
			if (e(t, n, r, p, s, c), d(p), s >= D) throw Error("arx: counter overflow");
			let l = Math.min(T, u - o);
			for (let e = 0, t; e < l; e++) t = o + e, a[t] = i[t] ^ f[e];
			o += l;
		}
		return;
	}
	for (let o = 0; o < u; s++) {
		if (e(t, n, r, p, s, c), s >= D) throw Error("arx: counter overflow");
		let l = Math.min(T, u - o);
		if (m && l === T) {
			let e = o / 4;
			if (o % 4 != 0) throw Error("arx: invalid block position");
			for (let t = 0, n; t < E; t++) n = e + t, g[n] = h[n] ^ p[t];
			o += T;
			continue;
		}
		for (let e = 0, t; e < l; e++) t = o + e, a[t] = i[t] ^ f[e];
		o += l;
	}
}
function A(e, i) {
	let { allowShortKeys: a, extendNonceFn: c, counterLength: u, counterRight: p, rounds: m } = f({
		allowShortKeys: !1,
		counterLength: 8,
		counterRight: !1,
		rounds: 20
	}, i);
	if (typeof e != "function") throw Error("core must be a function");
	return n(u), n(m), t(p), t(a), (t, i, f, h, _ = 0) => {
		r(t, void 0, "key"), r(i, void 0, "nonce"), r(f, void 0, "data");
		let b = f.length;
		if (h = g(b, h, !1), n(_), _ < 0 || _ >= D) throw Error("arx: counter overflow");
		let x = [], w = t.length, T, E;
		if (w === 32) x.push(T = y(t)), E = C;
		else if (w === 16 && a) T = new Uint8Array(32), T.set(t), T.set(t, 16), E = S, x.push(T);
		else throw r(t, 32, "arx key"), Error("invalid key size");
		(!l || !v(i)) && x.push(i = y(i));
		let O = o(T);
		if (c) {
			if (i.length !== 24) throw Error("arx: extended nonce must be 24 bytes");
			let e = i.subarray(0, 16);
			if (l) c(E, O, o(e), O);
			else {
				let t = d(Uint32Array.from(E));
				c(t, O, o(e), O), s(t), d(O);
			}
			i = i.subarray(16);
		} else l || d(O);
		let A = 16 - u;
		if (A !== i.length) throw Error(`arx: nonce must be ${A} or 16 bytes`);
		if (A !== 12) {
			let e = new Uint8Array(12);
			e.set(i, p ? 0 : 12 - i.length), i = e, x.push(i);
		}
		let j = d(o(i));
		try {
			return k(e, E, O, j, f, h, _, m), h;
		} finally {
			s(...x);
		}
	};
}
//#endregion
//#region node_modules/@noble/ciphers/_poly1305.js
function j(e, t) {
	return e[t++] & 255 | (e[t++] & 255) << 8;
}
var M = class {
	blockLen = 16;
	outputLen = 16;
	buffer = new Uint8Array(16);
	r = new Uint16Array(10);
	h = new Uint16Array(10);
	pad = new Uint16Array(8);
	pos = 0;
	finished = !1;
	destroyed = !1;
	constructor(e) {
		e = y(r(e, 32, "key"));
		let t = j(e, 0), n = j(e, 2), i = j(e, 4), a = j(e, 6), o = j(e, 8), s = j(e, 10), c = j(e, 12), l = j(e, 14);
		this.r[0] = t & 8191, this.r[1] = (t >>> 13 | n << 3) & 8191, this.r[2] = (n >>> 10 | i << 6) & 7939, this.r[3] = (i >>> 7 | a << 9) & 8191, this.r[4] = (a >>> 4 | o << 12) & 255, this.r[5] = o >>> 1 & 8190, this.r[6] = (o >>> 14 | s << 2) & 8191, this.r[7] = (s >>> 11 | c << 5) & 8065, this.r[8] = (c >>> 8 | l << 8) & 8191, this.r[9] = l >>> 5 & 127;
		for (let t = 0; t < 8; t++) this.pad[t] = j(e, 16 + 2 * t);
	}
	process(e, t, n = !1) {
		let r = n ? 0 : 2048, { h: i, r: a } = this, o = a[0], s = a[1], c = a[2], l = a[3], u = a[4], d = a[5], f = a[6], p = a[7], m = a[8], h = a[9], g = j(e, t + 0), _ = j(e, t + 2), v = j(e, t + 4), y = j(e, t + 6), b = j(e, t + 8), x = j(e, t + 10), S = j(e, t + 12), C = j(e, t + 14), w = i[0] + (g & 8191), T = i[1] + ((g >>> 13 | _ << 3) & 8191), E = i[2] + ((_ >>> 10 | v << 6) & 8191), D = i[3] + ((v >>> 7 | y << 9) & 8191), O = i[4] + ((y >>> 4 | b << 12) & 8191), k = i[5] + (b >>> 1 & 8191), A = i[6] + ((b >>> 14 | x << 2) & 8191), M = i[7] + ((x >>> 11 | S << 5) & 8191), N = i[8] + ((S >>> 8 | C << 8) & 8191), P = i[9] + (C >>> 5 | r), F = 0, I = F + w * o + 5 * h * T + 5 * m * E + 5 * p * D + 5 * f * O;
		F = I >>> 13, I &= 8191, I += 5 * d * k + 5 * u * A + 5 * l * M + 5 * c * N + 5 * s * P, F += I >>> 13, I &= 8191;
		let L = F + w * s + T * o + 5 * h * E + 5 * m * D + 5 * p * O;
		F = L >>> 13, L &= 8191, L += 5 * f * k + 5 * d * A + 5 * u * M + 5 * l * N + 5 * c * P, F += L >>> 13, L &= 8191;
		let R = F + w * c + T * s + E * o + 5 * h * D + 5 * m * O;
		F = R >>> 13, R &= 8191, R += 5 * p * k + 5 * f * A + 5 * d * M + 5 * u * N + 5 * l * P, F += R >>> 13, R &= 8191;
		let z = F + w * l + T * c + E * s + D * o + 5 * h * O;
		F = z >>> 13, z &= 8191, z += 5 * m * k + 5 * p * A + 5 * f * M + 5 * d * N + 5 * u * P, F += z >>> 13, z &= 8191;
		let B = F + w * u + T * l + E * c + D * s + O * o;
		F = B >>> 13, B &= 8191, B += 5 * h * k + 5 * m * A + 5 * p * M + 5 * f * N + 5 * d * P, F += B >>> 13, B &= 8191;
		let V = F + w * d + T * u + E * l + D * c + O * s;
		F = V >>> 13, V &= 8191, V += k * o + 5 * h * A + 5 * m * M + 5 * p * N + 5 * f * P, F += V >>> 13, V &= 8191;
		let H = F + w * f + T * d + E * u + D * l + O * c;
		F = H >>> 13, H &= 8191, H += k * s + A * o + 5 * h * M + 5 * m * N + 5 * p * P, F += H >>> 13, H &= 8191;
		let U = F + w * p + T * f + E * d + D * u + O * l;
		F = U >>> 13, U &= 8191, U += k * c + A * s + M * o + 5 * h * N + 5 * m * P, F += U >>> 13, U &= 8191;
		let W = F + w * m + T * p + E * f + D * d + O * u;
		F = W >>> 13, W &= 8191, W += k * l + A * c + M * s + N * o + 5 * h * P, F += W >>> 13, W &= 8191;
		let G = F + w * h + T * m + E * p + D * f + O * d;
		F = G >>> 13, G &= 8191, G += k * u + A * l + M * c + N * s + P * o, F += G >>> 13, G &= 8191, F = (F << 2) + F | 0, F = F + I | 0, I = F & 8191, F >>>= 13, L += F, i[0] = I, i[1] = L, i[2] = R, i[3] = z, i[4] = B, i[5] = V, i[6] = H, i[7] = U, i[8] = W, i[9] = G;
	}
	finalize() {
		let { h: e, pad: t } = this, n = new Uint16Array(10), r = e[1] >>> 13;
		e[1] &= 8191;
		for (let t = 2; t < 10; t++) e[t] += r, r = e[t] >>> 13, e[t] &= 8191;
		e[0] += r * 5, r = e[0] >>> 13, e[0] &= 8191, e[1] += r, r = e[1] >>> 13, e[1] &= 8191, e[2] += r, n[0] = e[0] + 5, r = n[0] >>> 13, n[0] &= 8191;
		for (let t = 1; t < 10; t++) n[t] = e[t] + r, r = n[t] >>> 13, n[t] &= 8191;
		n[9] -= 8192;
		let i = (r ^ 1) - 1;
		for (let e = 0; e < 10; e++) n[e] &= i;
		i = ~i;
		for (let t = 0; t < 10; t++) e[t] = e[t] & i | n[t];
		e[0] = (e[0] | e[1] << 13) & 65535, e[1] = (e[1] >>> 3 | e[2] << 10) & 65535, e[2] = (e[2] >>> 6 | e[3] << 7) & 65535, e[3] = (e[3] >>> 9 | e[4] << 4) & 65535, e[4] = (e[4] >>> 12 | e[5] << 1 | e[6] << 14) & 65535, e[5] = (e[6] >>> 2 | e[7] << 11) & 65535, e[6] = (e[7] >>> 5 | e[8] << 8) & 65535, e[7] = (e[8] >>> 8 | e[9] << 5) & 65535;
		let a = e[0] + t[0];
		e[0] = a & 65535;
		for (let n = 1; n < 8; n++) a = (e[n] + t[n] | 0) + (a >>> 16) | 0, e[n] = a & 65535;
		s(n);
	}
	update(e) {
		i(this), r(e), e = y(e);
		let { buffer: t, blockLen: n } = this, a = e.length;
		for (let r = 0; r < a;) {
			let i = Math.min(n - this.pos, a - r);
			if (i === n) {
				for (; n <= a - r; r += n) this.process(e, r);
				continue;
			}
			t.set(e.subarray(r, r + i), this.pos), this.pos += i, r += i, this.pos === n && (this.process(t, 0, !1), this.pos = 0);
		}
		return this;
	}
	destroy() {
		this.destroyed = !0, s(this.h, this.r, this.buffer, this.pad);
	}
	digestInto(e) {
		i(this), a(e, this), this.finished = !0;
		let { buffer: t, h: n } = this, { pos: r } = this;
		if (r) {
			for (t[r++] = 1; r < 16; r++) t[r] = 0;
			this.process(t, 0, !0);
		}
		this.finalize();
		let o = 0;
		for (let t = 0; t < 8; t++) e[o++] = n[t] >>> 0, e[o++] = n[t] >>> 8;
	}
	digest() {
		let { buffer: e, outputLen: t } = this;
		this.digestInto(e);
		let n = e.slice(0, t);
		return this.destroy(), n;
	}
}, N = /* @__PURE__ */ m(32, (e) => new M(e));
//#endregion
//#region node_modules/@noble/ciphers/chacha.js
function P(e, t, n, r, i, a = 20) {
	let o = e[0], s = e[1], c = e[2], l = e[3], u = t[0], d = t[1], f = t[2], p = t[3], m = t[4], h = t[5], g = t[6], _ = t[7], v = i, y = n[0], b = n[1], x = n[2], S = o, C = s, T = c, E = l, D = u, O = d, k = f, A = p, j = m, M = h, N = g, P = _, F = v, I = y, L = b, R = x;
	for (let e = 0; e < a; e += 2) S = S + D | 0, F = w(F ^ S, 16), j = j + F | 0, D = w(D ^ j, 12), S = S + D | 0, F = w(F ^ S, 8), j = j + F | 0, D = w(D ^ j, 7), C = C + O | 0, I = w(I ^ C, 16), M = M + I | 0, O = w(O ^ M, 12), C = C + O | 0, I = w(I ^ C, 8), M = M + I | 0, O = w(O ^ M, 7), T = T + k | 0, L = w(L ^ T, 16), N = N + L | 0, k = w(k ^ N, 12), T = T + k | 0, L = w(L ^ T, 8), N = N + L | 0, k = w(k ^ N, 7), E = E + A | 0, R = w(R ^ E, 16), P = P + R | 0, A = w(A ^ P, 12), E = E + A | 0, R = w(R ^ E, 8), P = P + R | 0, A = w(A ^ P, 7), S = S + O | 0, R = w(R ^ S, 16), N = N + R | 0, O = w(O ^ N, 12), S = S + O | 0, R = w(R ^ S, 8), N = N + R | 0, O = w(O ^ N, 7), C = C + k | 0, F = w(F ^ C, 16), P = P + F | 0, k = w(k ^ P, 12), C = C + k | 0, F = w(F ^ C, 8), P = P + F | 0, k = w(k ^ P, 7), T = T + A | 0, I = w(I ^ T, 16), j = j + I | 0, A = w(A ^ j, 12), T = T + A | 0, I = w(I ^ T, 8), j = j + I | 0, A = w(A ^ j, 7), E = E + D | 0, L = w(L ^ E, 16), M = M + L | 0, D = w(D ^ M, 12), E = E + D | 0, L = w(L ^ E, 8), M = M + L | 0, D = w(D ^ M, 7);
	let z = 0;
	r[z++] = o + S | 0, r[z++] = s + C | 0, r[z++] = c + T | 0, r[z++] = l + E | 0, r[z++] = u + D | 0, r[z++] = d + O | 0, r[z++] = f + k | 0, r[z++] = p + A | 0, r[z++] = m + j | 0, r[z++] = h + M | 0, r[z++] = g + N | 0, r[z++] = _ + P | 0, r[z++] = v + F | 0, r[z++] = y + I | 0, r[z++] = b + L | 0, r[z++] = x + R | 0;
}
var F = /* @__PURE__ */ A(P, {
	counterRight: !1,
	counterLength: 4,
	allowShortKeys: !1
}), I = /* @__PURE__ */ new Uint8Array(16), L = (e, t) => {
	e.update(t);
	let n = t.length % 16;
	n && e.update(I.subarray(n));
}, R = /* @__PURE__ */ new Uint8Array(32);
function z(e, t, n, i, a) {
	a !== void 0 && r(a, void 0, "AAD");
	let o = e(t, n, R), c = _(i.length, a ? a.length : 0, !0), l = N.create(o);
	a && L(l, a), L(l, i), l.update(c);
	let u = l.digest();
	return s(o, c), u;
}
var B = /* @__PURE__ */ h({
	blockSize: 64,
	nonceLength: 12,
	tagLength: 16
}, /* @__PURE__ */ ((e) => (t, n, r) => ({
	encrypt(i, a) {
		let o = i.length;
		a = g(o + 16, a, !1), a.set(i);
		let c = a.subarray(0, -16);
		e(t, n, c, c, 1);
		let l = z(e, t, n, c, r);
		return a.set(l, o), s(l), a;
	},
	decrypt(i, a) {
		a = g(i.length - 16, a, !1);
		let o = i.subarray(0, -16), c = i.subarray(-16), l = z(e, t, n, o, r);
		if (!p(c, l)) throw s(l), Error("invalid tag");
		return a.set(i.subarray(0, -16)), e(t, n, a, a, 1), s(l), a;
	}
}))(F)), V = "3.7.8", H = V, U = typeof Buffer == "function", W = typeof TextDecoder == "function" ? new TextDecoder() : void 0, G = typeof TextEncoder == "function" ? new TextEncoder() : void 0, ee = Array.prototype.slice.call("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="), te = ((e) => {
	let t = {};
	return e.forEach((e, n) => t[e] = n), t;
})(ee), ne = /^(?:[A-Za-z\d+\/]{4})*?(?:[A-Za-z\d+\/]{2}(?:==)?|[A-Za-z\d+\/]{3}=?)?$/, K = String.fromCharCode.bind(String), re = typeof Uint8Array.from == "function" ? Uint8Array.from.bind(Uint8Array) : (e) => new Uint8Array(Array.prototype.slice.call(e, 0)), ie = (e) => e.replace(/=/g, "").replace(/[+\/]/g, (e) => e == "+" ? "-" : "_"), ae = (e) => e.replace(/[^A-Za-z0-9\+\/]/g, ""), oe = (e) => {
	let t, n, r, i, a = "", o = e.length % 3;
	for (let o = 0; o < e.length;) {
		if ((n = e.charCodeAt(o++)) > 255 || (r = e.charCodeAt(o++)) > 255 || (i = e.charCodeAt(o++)) > 255) throw TypeError("invalid character found");
		t = n << 16 | r << 8 | i, a += ee[t >> 18 & 63] + ee[t >> 12 & 63] + ee[t >> 6 & 63] + ee[t & 63];
	}
	return o ? a.slice(0, o - 3) + "===".substring(o) : a;
}, se = typeof btoa == "function" ? (e) => btoa(e) : U ? (e) => Buffer.from(e, "binary").toString("base64") : oe, ce = U ? (e) => Buffer.from(e).toString("base64") : (e) => {
	let t = 4096, n = [];
	for (let r = 0, i = e.length; r < i; r += t) n.push(K.apply(null, e.subarray(r, r + t)));
	return se(n.join(""));
}, le = (e, t = !1) => t ? ie(ce(e)) : ce(e), ue = (e) => {
	if (e.length < 2) {
		var t = e.charCodeAt(0);
		return t < 128 ? e : t < 2048 ? K(192 | t >>> 6) + K(128 | t & 63) : K(224 | t >>> 12 & 15) + K(128 | t >>> 6 & 63) + K(128 | t & 63);
	} else {
		var t = 65536 + (e.charCodeAt(0) - 55296) * 1024 + (e.charCodeAt(1) - 56320);
		return K(240 | t >>> 18 & 7) + K(128 | t >>> 12 & 63) + K(128 | t >>> 6 & 63) + K(128 | t & 63);
	}
}, de = /[\uD800-\uDBFF][\uDC00-\uDFFFF]|[^\x00-\x7F]/g, fe = (e) => e.replace(de, ue), pe = U ? (e) => Buffer.from(e, "utf8").toString("base64") : G ? (e) => ce(G.encode(e)) : (e) => se(fe(e)), q = (e, t = !1) => t ? ie(pe(e)) : pe(e), me = (e) => q(e, !0), he = /[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3}/g, ge = (e) => {
	switch (e.length) {
		case 4:
			var t = ((7 & e.charCodeAt(0)) << 18 | (63 & e.charCodeAt(1)) << 12 | (63 & e.charCodeAt(2)) << 6 | 63 & e.charCodeAt(3)) - 65536;
			return K((t >>> 10) + 55296) + K((t & 1023) + 56320);
		case 3: return K((15 & e.charCodeAt(0)) << 12 | (63 & e.charCodeAt(1)) << 6 | 63 & e.charCodeAt(2));
		default: return K((31 & e.charCodeAt(0)) << 6 | 63 & e.charCodeAt(1));
	}
}, _e = (e) => e.replace(he, ge), ve = (e) => {
	if (e = e.replace(/\s+/g, ""), !ne.test(e)) throw TypeError("malformed base64.");
	e += "==".slice(2 - (e.length & 3));
	let t, n, r, i = [];
	for (let a = 0; a < e.length;) t = te[e.charAt(a++)] << 18 | te[e.charAt(a++)] << 12 | (n = te[e.charAt(a++)]) << 6 | (r = te[e.charAt(a++)]), n === 64 ? i.push(K(t >> 16 & 255)) : r === 64 ? i.push(K(t >> 16 & 255, t >> 8 & 255)) : i.push(K(t >> 16 & 255, t >> 8 & 255, t & 255));
	return i.join("");
}, ye = typeof atob == "function" ? (e) => atob(ae(e)) : U ? (e) => Buffer.from(e, "base64").toString("binary") : ve, be = U ? (e) => re(Buffer.from(e, "base64")) : (e) => re(ye(e).split("").map((e) => e.charCodeAt(0))), xe = (e) => be(Ce(e)), Se = U ? (e) => Buffer.from(e, "base64").toString("utf8") : W ? (e) => W.decode(be(e)) : (e) => _e(ye(e)), Ce = (e) => ae(e.replace(/[-_]/g, (e) => e == "-" ? "+" : "/")), we = (e) => Se(Ce(e)), Te = (e) => {
	if (typeof e != "string") return !1;
	let t = e.replace(/\s+/g, "").replace(/={0,2}$/, "");
	return !/[^\s0-9a-zA-Z\+/]/.test(t) || !/[^\s0-9a-zA-Z\-_]/.test(t);
}, Ee = (e) => ({
	value: e,
	enumerable: !1,
	writable: !0,
	configurable: !0
}), De = function() {
	let e = (e, t) => Object.defineProperty(String.prototype, e, Ee(t));
	e("fromBase64", function() {
		return we(this);
	}), e("toBase64", function(e) {
		return q(this, e);
	}), e("toBase64URI", function() {
		return q(this, !0);
	}), e("toBase64URL", function() {
		return q(this, !0);
	}), e("toUint8Array", function() {
		return xe(this);
	});
}, Oe = function() {
	let e = (e, t) => Object.defineProperty(Uint8Array.prototype, e, Ee(t));
	e("toBase64", function(e) {
		return le(this, e);
	}), e("toBase64URI", function() {
		return le(this, !0);
	}), e("toBase64URL", function() {
		return le(this, !0);
	});
}, J = {
	version: V,
	VERSION: H,
	atob: ye,
	atobPolyfill: ve,
	btoa: se,
	btoaPolyfill: oe,
	fromBase64: we,
	toBase64: q,
	encode: q,
	encodeURI: me,
	encodeURL: me,
	utob: fe,
	btou: _e,
	decode: we,
	isValid: Te,
	fromUint8Array: le,
	toUint8Array: xe,
	extendString: De,
	extendUint8Array: Oe,
	extendBuiltins: () => {
		De(), Oe();
	}
};
//#endregion
//#region node_modules/@noble/hashes/utils.js
function ke(e) {
	return e instanceof Uint8Array || ArrayBuffer.isView(e) && e.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in e && e.BYTES_PER_ELEMENT === 1;
}
function Ae(e, t, n = "") {
	let r = ke(e), i = e?.length, a = t !== void 0;
	if (!r || a && i !== t) {
		let o = n && `"${n}" `, s = a ? ` of length ${t}` : "", c = r ? `length=${i}` : `type=${typeof e}`, l = o + "expected Uint8Array" + s + ", got " + c;
		throw r ? RangeError(l) : TypeError(l);
	}
	return e;
}
function je(e, t = !0) {
	if (e.destroyed) throw Error("Hash instance has been destroyed");
	if (t && e.finished) throw Error("Hash#digest() has already been called");
}
function Me(e, t) {
	Ae(e, void 0, "digestInto() output");
	let n = t.outputLen;
	if (e.length < n) throw RangeError("\"digestInto() output\" expected to be of length >=" + n);
}
function Ne(...e) {
	for (let t = 0; t < e.length; t++) e[t].fill(0);
}
function Pe(e) {
	return new DataView(e.buffer, e.byteOffset, e.byteLength);
}
new Uint8Array(new Uint32Array([287454020]).buffer)[0], typeof Uint8Array.from([]).toHex == "function" && Uint8Array.fromHex;
function Fe(e, t = {}) {
	let n = (t, n) => e(n).update(t).digest(), r = e(void 0);
	return n.outputLen = r.outputLen, n.blockLen = r.blockLen, n.canXOF = r.canXOF, n.create = (t) => e(t), Object.assign(n, t), Object.freeze(n);
}
var Ie = (e) => ({ oid: Uint8Array.from([
	6,
	9,
	96,
	134,
	72,
	1,
	101,
	3,
	4,
	2,
	e
]) }), Le = class {
	blockLen;
	outputLen;
	canXOF = !1;
	padOffset;
	isLE;
	buffer;
	view;
	finished = !1;
	length = 0;
	pos = 0;
	destroyed = !1;
	constructor(e, t, n, r) {
		this.blockLen = e, this.outputLen = t, this.padOffset = n, this.isLE = r, this.buffer = new Uint8Array(e), this.view = Pe(this.buffer);
	}
	update(e) {
		je(this), Ae(e);
		let { view: t, buffer: n, blockLen: r } = this, i = e.length;
		for (let a = 0; a < i;) {
			let o = Math.min(r - this.pos, i - a);
			if (o === r) {
				let t = Pe(e);
				for (; r <= i - a; a += r) this.process(t, a);
				continue;
			}
			n.set(e.subarray(a, a + o), this.pos), this.pos += o, a += o, this.pos === r && (this.process(t, 0), this.pos = 0);
		}
		return this.length += e.length, this.roundClean(), this;
	}
	digestInto(e) {
		je(this), Me(e, this), this.finished = !0;
		let { buffer: t, view: n, blockLen: r, isLE: i } = this, { pos: a } = this;
		t[a++] = 128, Ne(this.buffer.subarray(a)), this.padOffset > r - a && (this.process(n, 0), a = 0);
		for (let e = a; e < r; e++) t[e] = 0;
		n.setBigUint64(r - 8, BigInt(this.length * 8), i), this.process(n, 0);
		let o = Pe(e), s = this.outputLen;
		if (s % 4) throw Error("_sha2: outputLen must be aligned to 32bit");
		let c = s / 4, l = this.get();
		if (c > l.length) throw Error("_sha2: outputLen bigger than state");
		for (let e = 0; e < c; e++) o.setUint32(4 * e, l[e], i);
	}
	digest() {
		let { buffer: e, outputLen: t } = this;
		this.digestInto(e);
		let n = e.slice(0, t);
		return this.destroy(), n;
	}
	_cloneInto(e) {
		e ||= new this.constructor(), e.set(...this.get());
		let { blockLen: t, buffer: n, length: r, finished: i, destroyed: a, pos: o } = this;
		return e.destroyed = a, e.finished = i, e.length = r, e.pos = o, r % t && e.buffer.set(n), e;
	}
	clone() {
		return this._cloneInto();
	}
}, Y = /* @__PURE__ */ Uint32Array.from([
	1779033703,
	4089235720,
	3144134277,
	2227873595,
	1013904242,
	4271175723,
	2773480762,
	1595750129,
	1359893119,
	2917565137,
	2600822924,
	725511199,
	528734635,
	4215389547,
	1541459225,
	327033209
]), Re = /* @__PURE__ */ BigInt(2 ** 32 - 1), ze = /* @__PURE__ */ BigInt(32);
function Be(e, t = !1) {
	return t ? {
		h: Number(e & Re),
		l: Number(e >> ze & Re)
	} : {
		h: Number(e >> ze & Re) | 0,
		l: Number(e & Re) | 0
	};
}
function Ve(e, t = !1) {
	let n = e.length, r = new Uint32Array(n), i = new Uint32Array(n);
	for (let a = 0; a < n; a++) {
		let { h: n, l: o } = Be(e[a], t);
		[r[a], i[a]] = [n, o];
	}
	return [r, i];
}
var He = (e, t, n) => e >>> n, Ue = (e, t, n) => e << 32 - n | t >>> n, X = (e, t, n) => e >>> n | t << 32 - n, We = (e, t, n) => e << 32 - n | t >>> n, Ge = (e, t, n) => e << 64 - n | t >>> n - 32, Ke = (e, t, n) => e >>> n - 32 | t << 64 - n;
function Z(e, t, n, r) {
	let i = (t >>> 0) + (r >>> 0);
	return {
		h: e + n + (i / 2 ** 32 | 0) | 0,
		l: i | 0
	};
}
var qe = (e, t, n) => (e >>> 0) + (t >>> 0) + (n >>> 0), Je = (e, t, n, r) => t + n + r + (e / 2 ** 32 | 0) | 0, Ye = (e, t, n, r) => (e >>> 0) + (t >>> 0) + (n >>> 0) + (r >>> 0), Xe = (e, t, n, r, i) => t + n + r + i + (e / 2 ** 32 | 0) | 0, Ze = (e, t, n, r, i) => (e >>> 0) + (t >>> 0) + (n >>> 0) + (r >>> 0) + (i >>> 0), Qe = (e, t, n, r, i, a) => t + n + r + i + a + (e / 2 ** 32 | 0) | 0, $e = Ve((/* @__PURE__ */ "0x428a2f98d728ae22.0x7137449123ef65cd.0xb5c0fbcfec4d3b2f.0xe9b5dba58189dbbc.0x3956c25bf348b538.0x59f111f1b605d019.0x923f82a4af194f9b.0xab1c5ed5da6d8118.0xd807aa98a3030242.0x12835b0145706fbe.0x243185be4ee4b28c.0x550c7dc3d5ffb4e2.0x72be5d74f27b896f.0x80deb1fe3b1696b1.0x9bdc06a725c71235.0xc19bf174cf692694.0xe49b69c19ef14ad2.0xefbe4786384f25e3.0x0fc19dc68b8cd5b5.0x240ca1cc77ac9c65.0x2de92c6f592b0275.0x4a7484aa6ea6e483.0x5cb0a9dcbd41fbd4.0x76f988da831153b5.0x983e5152ee66dfab.0xa831c66d2db43210.0xb00327c898fb213f.0xbf597fc7beef0ee4.0xc6e00bf33da88fc2.0xd5a79147930aa725.0x06ca6351e003826f.0x142929670a0e6e70.0x27b70a8546d22ffc.0x2e1b21385c26c926.0x4d2c6dfc5ac42aed.0x53380d139d95b3df.0x650a73548baf63de.0x766a0abb3c77b2a8.0x81c2c92e47edaee6.0x92722c851482353b.0xa2bfe8a14cf10364.0xa81a664bbc423001.0xc24b8b70d0f89791.0xc76c51a30654be30.0xd192e819d6ef5218.0xd69906245565a910.0xf40e35855771202a.0x106aa07032bbd1b8.0x19a4c116b8d2d0c8.0x1e376c085141ab53.0x2748774cdf8eeb99.0x34b0bcb5e19b48a8.0x391c0cb3c5c95a63.0x4ed8aa4ae3418acb.0x5b9cca4f7763e373.0x682e6ff3d6b2b8a3.0x748f82ee5defb2fc.0x78a5636f43172f60.0x84c87814a1f0ab72.0x8cc702081a6439ec.0x90befffa23631e28.0xa4506cebde82bde9.0xbef9a3f7b2c67915.0xc67178f2e372532b.0xca273eceea26619c.0xd186b8c721c0c207.0xeada7dd6cde0eb1e.0xf57d4f7fee6ed178.0x06f067aa72176fba.0x0a637dc5a2c898a6.0x113f9804bef90dae.0x1b710b35131c471b.0x28db77f523047d84.0x32caab7b40c72493.0x3c9ebe0a15c9bebc.0x431d67c49c100d4c.0x4cc5d4becb3e42b6.0x597f299cfc657e2a.0x5fcb6fab3ad6faec.0x6c44198c4a475817".split(".")).map((e) => BigInt(e))), et = $e[0], tt = $e[1], Q = /* @__PURE__ */ new Uint32Array(80), $ = /* @__PURE__ */ new Uint32Array(80), nt = class extends Le {
	constructor(e) {
		super(128, e, 16, !1);
	}
	get() {
		let { Ah: e, Al: t, Bh: n, Bl: r, Ch: i, Cl: a, Dh: o, Dl: s, Eh: c, El: l, Fh: u, Fl: d, Gh: f, Gl: p, Hh: m, Hl: h } = this;
		return [
			e,
			t,
			n,
			r,
			i,
			a,
			o,
			s,
			c,
			l,
			u,
			d,
			f,
			p,
			m,
			h
		];
	}
	set(e, t, n, r, i, a, o, s, c, l, u, d, f, p, m, h) {
		this.Ah = e | 0, this.Al = t | 0, this.Bh = n | 0, this.Bl = r | 0, this.Ch = i | 0, this.Cl = a | 0, this.Dh = o | 0, this.Dl = s | 0, this.Eh = c | 0, this.El = l | 0, this.Fh = u | 0, this.Fl = d | 0, this.Gh = f | 0, this.Gl = p | 0, this.Hh = m | 0, this.Hl = h | 0;
	}
	process(e, t) {
		for (let n = 0; n < 16; n++, t += 4) Q[n] = e.getUint32(t), $[n] = e.getUint32(t += 4);
		for (let e = 16; e < 80; e++) {
			let t = Q[e - 15] | 0, n = $[e - 15] | 0, r = X(t, n, 1) ^ X(t, n, 8) ^ He(t, n, 7), i = We(t, n, 1) ^ We(t, n, 8) ^ Ue(t, n, 7), a = Q[e - 2] | 0, o = $[e - 2] | 0, s = X(a, o, 19) ^ Ge(a, o, 61) ^ He(a, o, 6), c = Ye(i, We(a, o, 19) ^ Ke(a, o, 61) ^ Ue(a, o, 6), $[e - 7], $[e - 16]);
			Q[e] = Xe(c, r, s, Q[e - 7], Q[e - 16]) | 0, $[e] = c | 0;
		}
		let { Ah: n, Al: r, Bh: i, Bl: a, Ch: o, Cl: s, Dh: c, Dl: l, Eh: u, El: d, Fh: f, Fl: p, Gh: m, Gl: h, Hh: g, Hl: _ } = this;
		for (let e = 0; e < 80; e++) {
			let t = X(u, d, 14) ^ X(u, d, 18) ^ Ge(u, d, 41), v = We(u, d, 14) ^ We(u, d, 18) ^ Ke(u, d, 41), y = u & f ^ ~u & m, b = d & p ^ ~d & h, x = Ze(_, v, b, tt[e], $[e]), S = Qe(x, g, t, y, et[e], Q[e]), C = x | 0, w = X(n, r, 28) ^ Ge(n, r, 34) ^ Ge(n, r, 39), T = We(n, r, 28) ^ Ke(n, r, 34) ^ Ke(n, r, 39), E = n & i ^ n & o ^ i & o, D = r & a ^ r & s ^ a & s;
			g = m | 0, _ = h | 0, m = f | 0, h = p | 0, f = u | 0, p = d | 0, {h: u, l: d} = Z(c | 0, l | 0, S | 0, C | 0), c = o | 0, l = s | 0, o = i | 0, s = a | 0, i = n | 0, a = r | 0;
			let O = qe(C, T, D);
			n = Je(O, S, w, E), r = O | 0;
		}
		({h: n, l: r} = Z(this.Ah | 0, this.Al | 0, n | 0, r | 0)), {h: i, l: a} = Z(this.Bh | 0, this.Bl | 0, i | 0, a | 0), {h: o, l: s} = Z(this.Ch | 0, this.Cl | 0, o | 0, s | 0), {h: c, l: l} = Z(this.Dh | 0, this.Dl | 0, c | 0, l | 0), {h: u, l: d} = Z(this.Eh | 0, this.El | 0, u | 0, d | 0), {h: f, l: p} = Z(this.Fh | 0, this.Fl | 0, f | 0, p | 0), {h: m, l: h} = Z(this.Gh | 0, this.Gl | 0, m | 0, h | 0), {h: g, l: _} = Z(this.Hh | 0, this.Hl | 0, g | 0, _ | 0), this.set(n, r, i, a, o, s, c, l, u, d, f, p, m, h, g, _);
	}
	roundClean() {
		Ne(Q, $);
	}
	destroy() {
		this.destroyed = !0, Ne(this.buffer), this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	}
}, rt = class extends nt {
	Ah = Y[0] | 0;
	Al = Y[1] | 0;
	Bh = Y[2] | 0;
	Bl = Y[3] | 0;
	Ch = Y[4] | 0;
	Cl = Y[5] | 0;
	Dh = Y[6] | 0;
	Dl = Y[7] | 0;
	Eh = Y[8] | 0;
	El = Y[9] | 0;
	Fh = Y[10] | 0;
	Fl = Y[11] | 0;
	Gh = Y[12] | 0;
	Gl = Y[13] | 0;
	Hh = Y[14] | 0;
	Hl = Y[15] | 0;
	constructor() {
		super(64);
	}
}, it = /* @__PURE__ */ Fe(() => new rt(), /* @__PURE__ */ Ie(3)), at = 64 * 1024, ot = 16;
function st(e, t) {
	let n = t instanceof Uint8Array ? t : new Uint8Array(t), r = new Uint8Array(e.length + n.length);
	return r.set(e, 0), r.set(n, e.length), r;
}
function ct(e, t, n = 0) {
	new DataView(t.buffer, t.byteOffset, t.byteLength).setUint32(n, e, !1);
}
function lt(e, t, n = 0) {
	new DataView(t.buffer, t.byteOffset, t.byteLength).setBigUint64(n, e, !0);
}
function ut(e, t = 0) {
	return new DataView(e.buffer, e.byteOffset, e.byteLength).getUint32(t, !1);
}
function dt(e) {
	return e instanceof Uint8Array ? e : e instanceof ArrayBuffer ? new Uint8Array(e) : ArrayBuffer.isView(e) ? new Uint8Array(e.buffer, e.byteOffset, e.byteLength) : typeof e == "string" ? new TextEncoder().encode(e) : new TextEncoder().encode(String(e));
}
function ft(e, t, n) {
	let r = n;
	for (let n = 0; n < 8; n++) {
		let i = BigInt(e[t + n]) + (r & 255n);
		e[t + n] = Number(i & 255n), r = (r >> 8n) + (i >> 8n);
	}
}
function pt(e, t) {
	if (e.length !== 12) throw Error("Nonce must be 12 bytes");
	let n = new Uint8Array(e);
	return ft(n, 4, BigInt(t)), n;
}
function mt(e) {
	let t = new Uint8Array(4);
	return ct(e, t), t;
}
function ht(e, t) {
	let n = new Uint8Array(16);
	return lt(e, n, 0), lt(t, n, 8), n;
}
function gt(e, t, n, r) {
	let i = new Uint8Array(32);
	F(e, t, new Uint8Array(32), i, 0);
	let a = new M(i);
	return n.length > 0 && (a.update(n), n.length % 16 != 0 && a.update(new Uint8Array(16 - n.length % 16))), r.length > 0 && (a.update(r), r.length % 16 != 0 && a.update(new Uint8Array(16 - r.length % 16))), a.update(ht(BigInt(n.length), BigInt(r.length))), a.digest();
}
function _t(e, t, n, r) {
	let i = new Uint8Array(r.length);
	return F(e, t, r, i, 1), {
		ciphertext: i,
		tag: gt(e, t, n, i)
	};
}
function vt(e, t, n, r, i) {
	if (!Ct(gt(e, t, n, r), i)) throw Error("ChaCha20-Poly1305 authentication failed");
	let a = new Uint8Array(r.length);
	return F(e, t, r, a, 1), a;
}
async function yt(e, t, n, r, i) {
	let a = it.create(), o = 0, s = 0, c = e.getReader();
	try {
		for (;;) {
			let { done: e, value: i } = await c.read();
			if (e) break;
			let l = dt(i), u = 0;
			for (; u < l.length;) {
				let e = l.subarray(u, Math.min(u + at, l.length));
				a.update(e), o += e.length;
				let { ciphertext: i, tag: c } = _t(n, pt(r, s), mt(s), e), d = new Uint8Array(4);
				ct(i.length, d), await t.write(d), i.length > 0 && await t.write(i), await t.write(c), s += 1, u += e.length;
			}
		}
		i.sha512Hash = new Uint8Array(a.digest()), i.size = o, await t.close();
	} catch (e) {
		throw await t.abort(e), e;
	} finally {
		c.releaseLock();
	}
}
async function bt(e, t, n, r, i) {
	let a = e.getReader(), o = i?.sha512Hash ? it.create() : void 0, s = 0, c = 0;
	try {
		let e = new Uint8Array();
		for (;;) {
			let { done: i, value: l } = await a.read();
			if (i) break;
			let u = dt(l);
			for (e = st(e, u); e.length >= 4;) {
				let i = ut(e, 0);
				if (i > at) throw Error("Invalid record length");
				let a = 4 + i + ot;
				if (e.length < a) break;
				let l = e.subarray(4, 4 + i), u = e.subarray(4 + i, a), d = vt(n, pt(r, c), mt(c), l, u);
				o && o.update(d), s += d.length, await t.write(d), c += 1, e = e.subarray(a);
			}
		}
		if (e.length !== 0) throw Error("Encrypted stream ended with incomplete record");
		if (o && !Ct(new Uint8Array(o.digest()), i?.sha512Hash ?? new Uint8Array())) throw Error("SHA-512 verification failed");
		if (i?.size != null && s !== i.size) throw Error("Size verification failed");
		await t.close();
	} catch (e) {
		throw await t.abort(e), e;
	} finally {
		a.releaseLock();
	}
}
async function xt(e) {
	let t = b(32), n = b(12), r = b(12), i = new TransformStream(), a = i.writable.getWriter(), o = e instanceof Blob ? e.stream() : e, s = {
		key: t,
		nonceIn: n,
		nonceOut: r,
		sha512Hash: new Uint8Array(),
		size: 0,
		encodedStream: i.readable
	};
	return yt(o, a, t, n, s).catch((e) => {
		a.abort(e);
	}), s;
}
async function St(e) {
	let t = e.data instanceof Blob ? e.data.stream() : e.data, n = new TransformStream(), r = n.writable.getWriter();
	return bt(t, r, e.key, e.nonce, e.verification).catch((e) => {
		r.abort(e);
	}), n.readable;
}
function Ct(e, t) {
	if (e.length !== t.length) return !1;
	for (let n = 0; n < e.length; n++) if (e[n] !== t[n]) return !1;
	return !0;
}
//#endregion
//#region src/index.ts
async function wt(e) {
	return xt(e);
}
async function Tt(e, t, n) {
	let r = await wt(e), i = await Et(r, await t.uploadData(r), n);
	return t.uploadMeta(i);
}
async function Et(e, t, n) {
	let r = {
		schema_in: 1,
		nonce_in: J.fromUint8Array(e.nonceIn),
		data_in: t,
		hash: J.fromUint8Array(e.sha512Hash),
		size: e.size,
		mime: n?.mime
	}, i = JSON.stringify(r), a = B(e.key, e.nonceOut).encrypt(Dt(new TextEncoder().encode(i), n?.metaPadRule));
	return {
		schema_out: 10,
		nonce_out: J.fromUint8Array(e.nonceOut),
		meta_in: J.fromUint8Array(a)
	};
}
function Dt(e, t) {
	if (t === null) return e;
	t === void 0 ? t = (e) => Math.ceil(e / 1024) * 1024 : typeof t == "number" && (t = (e) => e);
	let n = e.length, r = t(n);
	return r <= n ? e : Ot(e, b(r - n));
}
function Ot(e, t) {
	let n = t instanceof Uint8Array ? t : new Uint8Array(t), r = new Uint8Array(e.length + n.length);
	return r.set(e, 0), r.set(n, e.length), r;
}
async function kt(e) {
	return St(e);
}
async function At(e, t, n = Nt) {
	if (!Pt(e)) throw Error("Unsupported metadata schema version");
	let r = J.toUint8Array(e.nonce_out), i = J.toUint8Array(e.meta_in), a = B(t, r).decrypt(i), o = jt(new TextDecoder().decode(a));
	return Mt(o), St({
		data: await n(o.data_in),
		key: t,
		nonce: J.toUint8Array(o.nonce_in),
		verification: {
			sha512Hash: J.toUint8Array(o.hash),
			size: o.size
		}
	});
}
function jt(e) {
	if (typeof e != "string" || e.length === 0 || e[0] !== "{") throw Error("Invalid JSON: not an object");
	let t = 0, n = !1, r = !1;
	for (let i = 0; i < e.length; i++) {
		let a = e[i];
		if (n) {
			r ? r = !1 : a === "\\" ? r = !0 : a === "\"" && (n = !1);
			continue;
		}
		if (a === "\"") n = !0;
		else if (a === "{") t++;
		else if (a === "}" && (t--, t === 0)) return JSON.parse(e.slice(0, i + 1));
	}
	throw Error("Failed to parse raw_meta_in JSON");
}
function Mt(e) {
	if (e.schema_in !== 1) throw Error("Unsupported raw_meta_in schema version");
	let t = e;
	if (typeof t.data_in != "string") throw Error("raw_meta_in.data_in must be a string");
	if (typeof t.nonce_in != "string") throw Error("raw_meta_in.nonce_in must be a base64 string");
	if (typeof t.hash != "string") throw Error("raw_meta_in.hash must be a base64 string");
	if (typeof t.size != "number") throw Error("raw_meta_in.size must be a number");
}
async function Nt(e) {
	if (e.startsWith("data:")) {
		let t = e.indexOf(",");
		if (t < 0) throw Error("Invalid data URL");
		let n = e.slice(5, t), r = e.slice(t + 1), i = n.endsWith(";base64") ? J.toUint8Array(r) : new TextEncoder().encode(decodeURIComponent(r));
		return new ReadableStream({ start(e) {
			e.enqueue(i), e.close();
		} });
	}
	let t = await fetch(e);
	if (!t.ok) throw Error(`Fetch failed: ${t.status} ${t.statusText}`);
	if (!t.body) throw Error("Fetch response has no body");
	return t.body;
}
function Pt(e) {
	return e.schema_out === 10 && "nonce_out" in e && "meta_in" in e;
}
//#endregion
export { kt as decrypt, Nt as defaultFetchDataSource, At as download, wt as encrypt, Tt as upload };
