var exports = {};
var module = {};
var window = {};
window.crypto = {};
window.crypto.getRandomValues = Math.random;
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.PointG2 = exports.PointG1 = exports.utils = exports.psi2 = exports.psi = exports.millerLoop = exports.calcPairingPrecomputes = exports.isogenyMapG2 = exports.map_to_curve_simple_swu_9mod16 = exports.ProjectivePoint = exports.Fp12 = exports.Fp6 = exports.Fp2 = exports.Fr = exports.Fp = exports.powMod = exports.mod = exports.CURVE = void 0;
exports.CURVE = {
    P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
    r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    h: 0x396c8c005555e1568c00aaab0000aaabn,
    Gx: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
    Gy: 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,
    b: 4n,
    P2: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn **
        2n -
        1n,
    h2: 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n,
    G2x: [
        0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
        0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
    ],
    G2y: [
        0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
        0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
    ],
    b2: [4n, 4n],
    x: 0xd201000000010000n,
    h2Eff: 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n,
};
const BLS_X_LEN = bitLen(exports.CURVE.x);
function mod(a, b) {
    const res = a % b;
    return res >= 0n ? res : b + res;
}
exports.mod = mod;
function powMod(a, power, modulo) {
    let res = 1n;
    while (power > 0n) {
        if (power & 1n)
            res = (res * a) % modulo;
        a = (a * a) % modulo;
        power >>= 1n;
    }
    return res;
}
exports.powMod = powMod;
function genInvertBatch(cls, nums) {
    const len = nums.length;
    const scratch = new Array(len);
    let acc = cls.ONE;
    for (let i = 0; i < len; i++) {
        if (nums[i].isZero())
            continue;
        scratch[i] = acc;
        acc = acc.multiply(nums[i]);
    }
    acc = acc.invert();
    for (let i = len - 1; i >= 0; i--) {
        if (nums[i].isZero())
            continue;
        let tmp = acc.multiply(nums[i]);
        nums[i] = acc.multiply(scratch[i]);
        acc = tmp;
    }
    return nums;
}
function bitLen(n) {
    let len;
    for (len = 0; n > 0n; n >>= 1n, len += 1)
        ;
    return len;
}
function bitGet(n, pos) {
    return (n >> BigInt(pos)) & 1n;
}
function invert(number, modulo = exports.CURVE.P) {
    if (number === 0n || modulo <= 0n) {
        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
    }
    let a = mod(number, modulo);
    let b = modulo;
    let [x, y, u, v] = [0n, 1n, 1n, 0n];
    while (a !== 0n) {
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        const n = y - v * q;
        [b, a] = [a, r];
        [x, y] = [u, v];
        [u, v] = [m, n];
    }
    const gcd = b;
    if (gcd !== 1n)
        throw new Error('invert: does not exist');
    return mod(x, modulo);
}
class Fp {
    constructor(value) {
        this.value = mod(value, Fp.ORDER);
    }
    isZero() {
        return this.value === 0n;
    }
    equals(rhs) {
        return this.value === rhs.value;
    }
    negate() {
        return new Fp(-this.value);
    }
    invert() {
        return new Fp(invert(this.value, Fp.ORDER));
    }
    add(rhs) {
        return new Fp(this.value + rhs.value);
    }
    square() {
        return new Fp(this.value * this.value);
    }
    pow(n) {
        return new Fp(powMod(this.value, n, Fp.ORDER));
    }
    sqrt() {
        const root = this.pow((Fp.ORDER + 1n) / 4n);
        if (!root.square().equals(this))
            return;
        return root;
    }
    subtract(rhs) {
        return new Fp(this.value - rhs.value);
    }
    multiply(rhs) {
        if (rhs instanceof Fp)
            rhs = rhs.value;
        return new Fp(this.value * rhs);
    }
    div(rhs) {
        if (typeof rhs === 'bigint')
            rhs = new Fp(rhs);
        return this.multiply(rhs.invert());
    }
    toString() {
        const str = this.value.toString(16).padStart(96, '0');
        return str.slice(0, 2) + '.' + str.slice(-2);
    }
}
exports.Fp = Fp;
Fp.ORDER = exports.CURVE.P;
Fp.MAX_BITS = bitLen(exports.CURVE.P);
Fp.ZERO = new Fp(0n);
Fp.ONE = new Fp(1n);
class Fr {
    constructor(value) {
        this.value = mod(value, Fr.ORDER);
    }
    static isValid(b) {
        return b <= Fr.ORDER;
    }
    isZero() {
        return this.value === 0n;
    }
    equals(rhs) {
        return this.value === rhs.value;
    }
    negate() {
        return new Fr(-this.value);
    }
    invert() {
        return new Fr(invert(this.value, Fr.ORDER));
    }
    add(rhs) {
        return new Fr(this.value + rhs.value);
    }
    square() {
        return new Fr(this.value * this.value);
    }
    pow(n) {
        return new Fr(powMod(this.value, n, Fr.ORDER));
    }
    subtract(rhs) {
        return new Fr(this.value - rhs.value);
    }
    multiply(rhs) {
        if (rhs instanceof Fr)
            rhs = rhs.value;
        return new Fr(this.value * rhs);
    }
    div(rhs) {
        if (typeof rhs === 'bigint')
            rhs = new Fr(rhs);
        return this.multiply(rhs.invert());
    }
    legendre() {
        return this.pow((Fr.ORDER - 1n) / 2n);
    }
    sqrt() {
        if (!this.legendre().equals(Fr.ONE))
            return;
        const P = Fr.ORDER;
        let q, s, z;
        for (q = P - 1n, s = 0; q % 2n === 0n; q /= 2n, s++)
            ;
        if (s === 1)
            return this.pow((P + 1n) / 4n);
        for (z = 2n; z < P && new Fr(z).legendre().value !== P - 1n; z++)
            ;
        let c = powMod(z, q, P);
        let r = powMod(this.value, (q + 1n) / 2n, P);
        let t = powMod(this.value, q, P);
        let t2 = 0n;
        while (mod(t - 1n, P) !== 0n) {
            t2 = mod(t * t, P);
            let i;
            for (i = 1; i < s; i++) {
                if (mod(t2 - 1n, P) === 0n)
                    break;
                t2 = mod(t2 * t2, P);
            }
            let b = powMod(c, BigInt(1 << (s - i - 1)), P);
            r = mod(r * b, P);
            c = mod(b * b, P);
            t = mod(t * c, P);
            s = i;
        }
        return new Fr(r);
    }
    toString() {
        return '0x' + this.value.toString(16).padStart(64, '0');
    }
}
exports.Fr = Fr;
Fr.ORDER = exports.CURVE.r;
Fr.ZERO = new Fr(0n);
Fr.ONE = new Fr(1n);
class FQP {
    zip(rhs, mapper) {
        const c0 = this.c;
        const c1 = rhs.c;
        const res = [];
        for (let i = 0; i < c0.length; i++) {
            res.push(mapper(c0[i], c1[i]));
        }
        return res;
    }
    map(callbackfn) {
        return this.c.map(callbackfn);
    }
    isZero() {
        return this.c.every((c) => c.isZero());
    }
    equals(rhs) {
        return this.zip(rhs, (left, right) => left.equals(right)).every((r) => r);
    }
    negate() {
        return this.init(this.map((c) => c.negate()));
    }
    add(rhs) {
        return this.init(this.zip(rhs, (left, right) => left.add(right)));
    }
    subtract(rhs) {
        return this.init(this.zip(rhs, (left, right) => left.subtract(right)));
    }
    conjugate() {
        return this.init([this.c[0], this.c[1].negate()]);
    }
    one() {
        const el = this;
        let one;
        if (el instanceof Fp2)
            one = Fp2.ONE;
        if (el instanceof Fp6)
            one = Fp6.ONE;
        if (el instanceof Fp12)
            one = Fp12.ONE;
        return one;
    }
    pow(n) {
        const elm = this;
        const one = this.one();
        if (n === 0n)
            return one;
        if (n === 1n)
            return elm;
        let p = one;
        let d = elm;
        while (n > 0n) {
            if (n & 1n)
                p = p.multiply(d);
            n >>= 1n;
            d = d.square();
        }
        return p;
    }
    div(rhs) {
        const inv = typeof rhs === 'bigint' ? new Fp(rhs).invert().value : rhs.invert();
        return this.multiply(inv);
    }
}
class Fp2 extends FQP {
    constructor(coeffs) {
        super();
        if (coeffs.length !== 2)
            throw new Error(`Expected array with 2 elements`);
        coeffs.forEach((c, i) => {
            if (typeof c === 'bigint')
                coeffs[i] = new Fp(c);
        });
        this.c = coeffs;
    }
    init(tuple) {
        return new Fp2(tuple);
    }
    toString() {
        return `Fp2(${this.c[0]} + ${this.c[1]}×i)`;
    }
    get values() {
        return this.c.map((c) => c.value);
    }
    multiply(rhs) {
        if (typeof rhs === 'bigint')
            return new Fp2(this.map((c) => c.multiply(rhs)));
        const [c0, c1] = this.c;
        const [r0, r1] = rhs.c;
        let t1 = c0.multiply(r0);
        let t2 = c1.multiply(r1);
        return new Fp2([t1.subtract(t2), c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2))]);
    }
    mulByNonresidue() {
        const c0 = this.c[0];
        const c1 = this.c[1];
        return new Fp2([c0.subtract(c1), c0.add(c1)]);
    }
    square() {
        const c0 = this.c[0];
        const c1 = this.c[1];
        const a = c0.add(c1);
        const b = c0.subtract(c1);
        const c = c0.add(c0);
        return new Fp2([a.multiply(b), c.multiply(c1)]);
    }
    sqrt() {
        const candidateSqrt = this.pow((Fp2.ORDER + 8n) / 16n);
        const check = candidateSqrt.square().div(this);
        const R = FP2_ROOTS_OF_UNITY;
        const divisor = [R[0], R[2], R[4], R[6]].find((r) => r.equals(check));
        if (!divisor)
            return;
        const index = R.indexOf(divisor);
        const root = R[index / 2];
        if (!root)
            throw new Error('Invalid root');
        const x1 = candidateSqrt.div(root);
        const x2 = x1.negate();
        const [re1, im1] = x1.values;
        const [re2, im2] = x2.values;
        if (im1 > im2 || (im1 === im2 && re1 > re2))
            return x1;
        return x2;
    }
    invert() {
        const [a, b] = this.values;
        const factor = new Fp(a * a + b * b).invert();
        return new Fp2([factor.multiply(new Fp(a)), factor.multiply(new Fp(-b))]);
    }
    frobeniusMap(power) {
        return new Fp2([this.c[0], this.c[1].multiply(FP2_FROBENIUS_COEFFICIENTS[power % 2])]);
    }
    multiplyByB() {
        let [c0, c1] = this.c;
        let t0 = c0.multiply(4n);
        let t1 = c1.multiply(4n);
        return new Fp2([t0.subtract(t1), t0.add(t1)]);
    }
}
exports.Fp2 = Fp2;
Fp2.ORDER = exports.CURVE.P2;
Fp2.MAX_BITS = bitLen(exports.CURVE.P2);
Fp2.ZERO = new Fp2([0n, 0n]);
Fp2.ONE = new Fp2([1n, 0n]);
class Fp6 extends FQP {
    constructor(c) {
        super();
        this.c = c;
        if (c.length !== 3)
            throw new Error(`Expected array with 3 elements`);
    }
    static fromTuple(t) {
        if (!Array.isArray(t) || t.length !== 6)
            throw new Error('Invalid Fp6 usage');
        return new Fp6([new Fp2(t.slice(0, 2)), new Fp2(t.slice(2, 4)), new Fp2(t.slice(4, 6))]);
    }
    init(triple) {
        return new Fp6(triple);
    }
    toString() {
        return `Fp6(${this.c[0]} + ${this.c[1]} * v, ${this.c[2]} * v^2)`;
    }
    conjugate() {
        throw new TypeError('No conjugate on Fp6');
    }
    multiply(rhs) {
        if (typeof rhs === 'bigint')
            return new Fp6([this.c[0].multiply(rhs), this.c[1].multiply(rhs), this.c[2].multiply(rhs)]);
        let [c0, c1, c2] = this.c;
        const [r0, r1, r2] = rhs.c;
        let t0 = c0.multiply(r0);
        let t1 = c1.multiply(r1);
        let t2 = c2.multiply(r2);
        return new Fp6([
            t0.add(c1.add(c2).multiply(r1.add(r2)).subtract(t1.add(t2)).mulByNonresidue()),
            c0.add(c1).multiply(r0.add(r1)).subtract(t0.add(t1)).add(t2.mulByNonresidue()),
            t1.add(c0.add(c2).multiply(r0.add(r2)).subtract(t0.add(t2))),
        ]);
    }
    mulByNonresidue() {
        return new Fp6([this.c[2].mulByNonresidue(), this.c[0], this.c[1]]);
    }
    multiplyBy1(b1) {
        return new Fp6([
            this.c[2].multiply(b1).mulByNonresidue(),
            this.c[0].multiply(b1),
            this.c[1].multiply(b1),
        ]);
    }
    multiplyBy01(b0, b1) {
        let [c0, c1, c2] = this.c;
        let t0 = c0.multiply(b0);
        let t1 = c1.multiply(b1);
        return new Fp6([
            c1.add(c2).multiply(b1).subtract(t1).mulByNonresidue().add(t0),
            b0.add(b1).multiply(c0.add(c1)).subtract(t0).subtract(t1),
            c0.add(c2).multiply(b0).subtract(t0).add(t1),
        ]);
    }
    multiplyByFp2(rhs) {
        return new Fp6(this.map((c) => c.multiply(rhs)));
    }
    square() {
        let [c0, c1, c2] = this.c;
        let t0 = c0.square();
        let t1 = c0.multiply(c1).multiply(2n);
        let t3 = c1.multiply(c2).multiply(2n);
        let t4 = c2.square();
        return new Fp6([
            t3.mulByNonresidue().add(t0),
            t4.mulByNonresidue().add(t1),
            t1.add(c0.subtract(c1).add(c2).square()).add(t3).subtract(t0).subtract(t4),
        ]);
    }
    invert() {
        let [c0, c1, c2] = this.c;
        let t0 = c0.square().subtract(c2.multiply(c1).mulByNonresidue());
        let t1 = c2.square().mulByNonresidue().subtract(c0.multiply(c1));
        let t2 = c1.square().subtract(c0.multiply(c2));
        let t4 = c2.multiply(t1).add(c1.multiply(t2)).mulByNonresidue().add(c0.multiply(t0)).invert();
        return new Fp6([t4.multiply(t0), t4.multiply(t1), t4.multiply(t2)]);
    }
    frobeniusMap(power) {
        return new Fp6([
            this.c[0].frobeniusMap(power),
            this.c[1].frobeniusMap(power).multiply(FP6_FROBENIUS_COEFFICIENTS_1[power % 6]),
            this.c[2].frobeniusMap(power).multiply(FP6_FROBENIUS_COEFFICIENTS_2[power % 6]),
        ]);
    }
}
exports.Fp6 = Fp6;
Fp6.ZERO = new Fp6([Fp2.ZERO, Fp2.ZERO, Fp2.ZERO]);
Fp6.ONE = new Fp6([Fp2.ONE, Fp2.ZERO, Fp2.ZERO]);
class Fp12 extends FQP {
    constructor(c) {
        super();
        this.c = c;
        if (c.length !== 2)
            throw new Error(`Expected array with 2 elements`);
    }
    static fromTuple(t) {
        return new Fp12([
            Fp6.fromTuple(t.slice(0, 6)),
            Fp6.fromTuple(t.slice(6, 12)),
        ]);
    }
    init(c) {
        return new Fp12(c);
    }
    toString() {
        return `Fp12(${this.c[0]} + ${this.c[1]} * w)`;
    }
    multiply(rhs) {
        if (typeof rhs === 'bigint')
            return new Fp12([this.c[0].multiply(rhs), this.c[1].multiply(rhs)]);
        let [c0, c1] = this.c;
        const [r0, r1] = rhs.c;
        let t1 = c0.multiply(r0);
        let t2 = c1.multiply(r1);
        return new Fp12([
            t1.add(t2.mulByNonresidue()),
            c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2)),
        ]);
    }
    multiplyBy014(o0, o1, o4) {
        let [c0, c1] = this.c;
        let [t0, t1] = [c0.multiplyBy01(o0, o1), c1.multiplyBy1(o4)];
        return new Fp12([
            t1.mulByNonresidue().add(t0),
            c1.add(c0).multiplyBy01(o0, o1.add(o4)).subtract(t0).subtract(t1),
        ]);
    }
    multiplyByFp2(rhs) {
        return this.init(this.map((c) => c.multiplyByFp2(rhs)));
    }
    square() {
        let [c0, c1] = this.c;
        let ab = c0.multiply(c1);
        return new Fp12([
            c1.mulByNonresidue().add(c0).multiply(c0.add(c1)).subtract(ab).subtract(ab.mulByNonresidue()),
            ab.add(ab),
        ]);
    }
    invert() {
        let [c0, c1] = this.c;
        let t = c0.square().subtract(c1.square().mulByNonresidue()).invert();
        return new Fp12([c0.multiply(t), c1.multiply(t).negate()]);
    }
    frobeniusMap(power) {
        const [c0, c1] = this.c;
        let r0 = c0.frobeniusMap(power);
        let [c1_0, c1_1, c1_2] = c1.frobeniusMap(power).c;
        const coeff = FP12_FROBENIUS_COEFFICIENTS[power % 12];
        return new Fp12([
            r0,
            new Fp6([c1_0.multiply(coeff), c1_1.multiply(coeff), c1_2.multiply(coeff)]),
        ]);
    }
    Fp4Square(a, b) {
        const a2 = a.square(), b2 = b.square();
        return [
            b2.mulByNonresidue().add(a2),
            a.add(b).square().subtract(a2).subtract(b2),
        ];
    }
    cyclotomicSquare() {
        const [c0, c1] = this.c;
        const [c0c0, c0c1, c0c2] = c0.c;
        const [c1c0, c1c1, c1c2] = c1.c;
        let [t3, t4] = this.Fp4Square(c0c0, c1c1);
        let [t5, t6] = this.Fp4Square(c1c0, c0c2);
        let [t7, t8] = this.Fp4Square(c0c1, c1c2);
        let t9 = t8.mulByNonresidue();
        return new Fp12([
            new Fp6([
                t3.subtract(c0c0).multiply(2n).add(t3),
                t5.subtract(c0c1).multiply(2n).add(t5),
                t7.subtract(c0c2).multiply(2n).add(t7),
            ]),
            new Fp6([
                t9.add(c1c0).multiply(2n).add(t9),
                t4.add(c1c1).multiply(2n).add(t4),
                t6.add(c1c2).multiply(2n).add(t6),
            ]),
        ]);
    }
    cyclotomicExp(n) {
        let z = Fp12.ONE;
        for (let i = BLS_X_LEN - 1; i >= 0; i--) {
            z = z.cyclotomicSquare();
            if (bitGet(n, i))
                z = z.multiply(this);
        }
        return z;
    }
    finalExponentiate() {
        const { x } = exports.CURVE;
        const t0 = this.frobeniusMap(6).div(this);
        const t1 = t0.frobeniusMap(2).multiply(t0);
        const t2 = t1.cyclotomicExp(x).conjugate();
        const t3 = t1.cyclotomicSquare().conjugate().multiply(t2);
        const t4 = t3.cyclotomicExp(x).conjugate();
        const t5 = t4.cyclotomicExp(x).conjugate();
        const t6 = t5.cyclotomicExp(x).conjugate().multiply(t2.cyclotomicSquare());
        const t7 = t6.cyclotomicExp(x).conjugate();
        const t2_t5_pow_q2 = t2.multiply(t5).frobeniusMap(2);
        const t4_t1_pow_q3 = t4.multiply(t1).frobeniusMap(3);
        const t6_t1c_pow_q1 = t6.multiply(t1.conjugate()).frobeniusMap(1);
        const t7_t3c_t1 = t7.multiply(t3.conjugate()).multiply(t1);
        return t2_t5_pow_q2.multiply(t4_t1_pow_q3).multiply(t6_t1c_pow_q1).multiply(t7_t3c_t1);
    }
}
exports.Fp12 = Fp12;
Fp12.ZERO = new Fp12([Fp6.ZERO, Fp6.ZERO]);
Fp12.ONE = new Fp12([Fp6.ONE, Fp6.ZERO]);
class ProjectivePoint {
    constructor(x, y, z, C) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.C = C;
    }
    isZero() {
        return this.z.isZero();
    }
    createPoint(x, y, z) {
        return new this.constructor(x, y, z);
    }
    getZero() {
        return this.createPoint(this.C.ONE, this.C.ONE, this.C.ZERO);
    }
    equals(rhs) {
        if (this.constructor !== rhs.constructor)
            throw new Error(`ProjectivePoint#equals: this is ${this.constructor}, but rhs is ${rhs.constructor}`);
        const a = this;
        const b = rhs;
        const xe = a.x.multiply(b.z).equals(b.x.multiply(a.z));
        const ye = a.y.multiply(b.z).equals(b.y.multiply(a.z));
        return xe && ye;
    }
    negate() {
        return this.createPoint(this.x, this.y.negate(), this.z);
    }
    toString(isAffine = true) {
        if (!isAffine) {
            return `Point<x=${this.x}, y=${this.y}, z=${this.z}>`;
        }
        const [x, y] = this.toAffine();
        return `Point<x=${x}, y=${y}>`;
    }
    fromAffineTuple(xy) {
        return this.createPoint(xy[0], xy[1], this.C.ONE);
    }
    toAffine(invZ = this.z.invert()) {
        return [this.x.multiply(invZ), this.y.multiply(invZ)];
    }
    toAffineBatch(points) {
        const toInv = genInvertBatch(this.C, points.map((p) => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    normalizeZ(points) {
        return this.toAffineBatch(points).map((t) => this.fromAffineTuple(t));
    }
    double() {
        const { x, y, z } = this;
        const W = x.multiply(x).multiply(3n);
        const S = y.multiply(z);
        const SS = S.multiply(S);
        const SSS = SS.multiply(S);
        const B = x.multiply(y).multiply(S);
        const H = W.multiply(W).subtract(B.multiply(8n));
        const X3 = H.multiply(S).multiply(2n);
        const Y3 = W.multiply(B.multiply(4n).subtract(H)).subtract(y.multiply(y).multiply(8n).multiply(SS));
        const Z3 = SSS.multiply(8n);
        return this.createPoint(X3, Y3, Z3);
    }
    add(rhs) {
        if (this.constructor !== rhs.constructor)
            throw new Error(`ProjectivePoint#add: this is ${this.constructor}, but rhs is ${rhs.constructor}`);
        const p1 = this;
        const p2 = rhs;
        if (p1.isZero())
            return p2;
        if (p2.isZero())
            return p1;
        const X1 = p1.x;
        const Y1 = p1.y;
        const Z1 = p1.z;
        const X2 = p2.x;
        const Y2 = p2.y;
        const Z2 = p2.z;
        const U1 = Y2.multiply(Z1);
        const U2 = Y1.multiply(Z2);
        const V1 = X2.multiply(Z1);
        const V2 = X1.multiply(Z2);
        if (V1.equals(V2) && U1.equals(U2))
            return this.double();
        if (V1.equals(V2))
            return this.getZero();
        const U = U1.subtract(U2);
        const V = V1.subtract(V2);
        const VV = V.multiply(V);
        const VVV = VV.multiply(V);
        const V2VV = V2.multiply(VV);
        const W = Z1.multiply(Z2);
        const A = U.multiply(U).multiply(W).subtract(VVV).subtract(V2VV.multiply(2n));
        const X3 = V.multiply(A);
        const Y3 = U.multiply(V2VV.subtract(A)).subtract(VVV.multiply(U2));
        const Z3 = VVV.multiply(W);
        return this.createPoint(X3, Y3, Z3);
    }
    subtract(rhs) {
        if (this.constructor !== rhs.constructor)
            throw new Error(`ProjectivePoint#subtract: this is ${this.constructor}, but rhs is ${rhs.constructor}`);
        return this.add(rhs.negate());
    }
    validateScalar(n) {
        if (typeof n === 'number')
            n = BigInt(n);
        if (typeof n !== 'bigint' || n <= 0 || n > exports.CURVE.r) {
            throw new Error(`Point#multiply: invalid scalar, expected positive integer < CURVE.r. Got: ${n}`);
        }
        return n;
    }
    multiplyUnsafe(scalar) {
        let n = this.validateScalar(scalar);
        let point = this.getZero();
        let d = this;
        while (n > 0n) {
            if (n & 1n)
                point = point.add(d);
            d = d.double();
            n >>= 1n;
        }
        return point;
    }
    multiply(scalar) {
        let n = this.validateScalar(scalar);
        let point = this.getZero();
        let fake = this.getZero();
        let d = this;
        let bits = Fp.ORDER;
        while (bits > 0n) {
            if (n & 1n) {
                point = point.add(d);
            }
            else {
                fake = fake.add(d);
            }
            d = d.double();
            n >>= 1n;
            bits >>= 1n;
        }
        return point;
    }
    maxBits() {
        return this.C.MAX_BITS;
    }
    precomputeWindow(W) {
        const windows = Math.ceil(this.maxBits() / W);
        const windowSize = 2 ** (W - 1);
        let points = [];
        let p = this;
        let base = p;
        for (let window = 0; window < windows; window++) {
            base = p;
            points.push(base);
            for (let i = 1; i < windowSize; i++) {
                base = base.add(p);
                points.push(base);
            }
            p = base.double();
        }
        return points;
    }
    calcMultiplyPrecomputes(W) {
        if (this._MPRECOMPUTES)
            throw new Error('This point already has precomputes');
        this._MPRECOMPUTES = [W, this.normalizeZ(this.precomputeWindow(W))];
    }
    clearMultiplyPrecomputes() {
        this._MPRECOMPUTES = undefined;
    }
    wNAF(n) {
        let W, precomputes;
        if (this._MPRECOMPUTES) {
            [W, precomputes] = this._MPRECOMPUTES;
        }
        else {
            W = 1;
            precomputes = this.precomputeWindow(W);
        }
        let [p, f] = [this.getZero(), this.getZero()];
        const windows = Math.ceil(this.maxBits() / W);
        const windowSize = 2 ** (W - 1);
        const mask = BigInt(2 ** W - 1);
        const maxNumber = 2 ** W;
        const shiftBy = BigInt(W);
        for (let window = 0; window < windows; window++) {
            const offset = window * windowSize;
            let wbits = Number(n & mask);
            n >>= shiftBy;
            if (wbits > windowSize) {
                wbits -= maxNumber;
                n += 1n;
            }
            if (wbits === 0) {
                f = f.add(window % 2 ? precomputes[offset].negate() : precomputes[offset]);
            }
            else {
                const cached = precomputes[offset + Math.abs(wbits) - 1];
                p = p.add(wbits < 0 ? cached.negate() : cached);
            }
        }
        return [p, f];
    }
    multiplyPrecomputed(scalar) {
        return this.wNAF(this.validateScalar(scalar))[0];
    }
}
exports.ProjectivePoint = ProjectivePoint;
function sgn0(x) {
    const [x0, x1] = x.values;
    const sign_0 = x0 % 2n;
    const zero_0 = x0 === 0n;
    const sign_1 = x1 % 2n;
    return BigInt(sign_0 || (zero_0 && sign_1));
}
const P_MINUS_9_DIV_16 = (exports.CURVE.P ** 2n - 9n) / 16n;
function sqrt_div_fp2(u, v) {
    const v7 = v.pow(7n);
    const uv7 = u.multiply(v7);
    const uv15 = uv7.multiply(v7.multiply(v));
    const gamma = uv15.pow(P_MINUS_9_DIV_16).multiply(uv7);
    let success = false;
    let result = gamma;
    const positiveRootsOfUnity = FP2_ROOTS_OF_UNITY.slice(0, 4);
    for (const root of positiveRootsOfUnity) {
        const candidate = root.multiply(gamma);
        if (candidate.pow(2n).multiply(v).subtract(u).isZero() && !success) {
            success = true;
            result = candidate;
        }
    }
    return [success, result];
}
function map_to_curve_simple_swu_9mod16(t) {
    const iso_3_a = new Fp2([0n, 240n]);
    const iso_3_b = new Fp2([1012n, 1012n]);
    const iso_3_z = new Fp2([-2n, -1n]);
    if (Array.isArray(t))
        t = new Fp2(t);
    const t2 = t.pow(2n);
    const iso_3_z_t2 = iso_3_z.multiply(t2);
    const ztzt = iso_3_z_t2.add(iso_3_z_t2.pow(2n));
    let denominator = iso_3_a.multiply(ztzt).negate();
    let numerator = iso_3_b.multiply(ztzt.add(Fp2.ONE));
    if (denominator.isZero())
        denominator = iso_3_z.multiply(iso_3_a);
    let v = denominator.pow(3n);
    let u = numerator
        .pow(3n)
        .add(iso_3_a.multiply(numerator).multiply(denominator.pow(2n)))
        .add(iso_3_b.multiply(v));
    const [success, sqrtCandidateOrGamma] = sqrt_div_fp2(u, v);
    let y;
    if (success)
        y = sqrtCandidateOrGamma;
    const sqrtCandidateX1 = sqrtCandidateOrGamma.multiply(t.pow(3n));
    u = iso_3_z_t2.pow(3n).multiply(u);
    let success2 = false;
    for (const eta of FP2_ETAs) {
        const etaSqrtCandidate = eta.multiply(sqrtCandidateX1);
        const temp = etaSqrtCandidate.pow(2n).multiply(v).subtract(u);
        if (temp.isZero() && !success && !success2) {
            y = etaSqrtCandidate;
            success2 = true;
        }
    }
    if (!success && !success2)
        throw new Error('Hash to Curve - Optimized SWU failure');
    if (success2)
        numerator = numerator.multiply(iso_3_z_t2);
    y = y;
    if (sgn0(t) !== sgn0(y))
        y = y.negate();
    y = y.multiply(denominator);
    return [numerator, y, denominator];
}
exports.map_to_curve_simple_swu_9mod16 = map_to_curve_simple_swu_9mod16;
function isogenyMapG2(xyz) {
    const [x, y, z] = xyz;
    const zz = z.multiply(z);
    const zzz = zz.multiply(z);
    const zPowers = [z, zz, zzz];
    const mapped = [Fp2.ZERO, Fp2.ZERO, Fp2.ZERO, Fp2.ZERO];
    for (let i = 0; i < ISOGENY_COEFFICIENTS.length; i++) {
        const k_i = ISOGENY_COEFFICIENTS[i];
        mapped[i] = k_i.slice(-1)[0];
        const arr = k_i.slice(0, -1).reverse();
        for (let j = 0; j < arr.length; j++) {
            const k_i_j = arr[j];
            mapped[i] = mapped[i].multiply(x).add(zPowers[j].multiply(k_i_j));
        }
    }
    mapped[2] = mapped[2].multiply(y);
    mapped[3] = mapped[3].multiply(z);
    const z2 = mapped[1].multiply(mapped[3]);
    const x2 = mapped[0].multiply(mapped[3]);
    const y2 = mapped[1].multiply(mapped[2]);
    return [x2, y2, z2];
}
exports.isogenyMapG2 = isogenyMapG2;
function calcPairingPrecomputes(x, y) {
    const [Qx, Qy, Qz] = [x, y, Fp2.ONE];
    let [Rx, Ry, Rz] = [Qx, Qy, Qz];
    let ell_coeff = [];
    for (let i = BLS_X_LEN - 2; i >= 0; i--) {
        let t0 = Ry.square();
        let t1 = Rz.square();
        let t2 = t1.multiply(3n).multiplyByB();
        let t3 = t2.multiply(3n);
        let t4 = Ry.add(Rz).square().subtract(t1).subtract(t0);
        ell_coeff.push([
            t2.subtract(t0),
            Rx.square().multiply(3n),
            t4.negate(),
        ]);
        Rx = t0.subtract(t3).multiply(Rx).multiply(Ry).div(2n);
        Ry = t0.add(t3).div(2n).square().subtract(t2.square().multiply(3n));
        Rz = t0.multiply(t4);
        if (bitGet(exports.CURVE.x, i)) {
            let t0 = Ry.subtract(Qy.multiply(Rz));
            let t1 = Rx.subtract(Qx.multiply(Rz));
            ell_coeff.push([
                t0.multiply(Qx).subtract(t1.multiply(Qy)),
                t0.negate(),
                t1,
            ]);
            let t2 = t1.square();
            let t3 = t2.multiply(t1);
            let t4 = t2.multiply(Rx);
            let t5 = t3.subtract(t4.multiply(2n)).add(t0.square().multiply(Rz));
            Rx = t1.multiply(t5);
            Ry = t4.subtract(t5).multiply(t0).subtract(t3.multiply(Ry));
            Rz = Rz.multiply(t3);
        }
    }
    return ell_coeff;
}
exports.calcPairingPrecomputes = calcPairingPrecomputes;
function millerLoop(ell, g1) {
    let f12 = Fp12.ONE;
    const [x, y] = g1;
    const [Px, Py] = [x, y];
    for (let j = 0, i = BLS_X_LEN - 2; i >= 0; i--, j++) {
        f12 = f12.multiplyBy014(ell[j][0], ell[j][1].multiply(Px.value), ell[j][2].multiply(Py.value));
        if (bitGet(exports.CURVE.x, i)) {
            j += 1;
            f12 = f12.multiplyBy014(ell[j][0], ell[j][1].multiply(Px.value), ell[j][2].multiply(Py.value));
        }
        if (i !== 0)
            f12 = f12.square();
    }
    return f12.conjugate();
}
exports.millerLoop = millerLoop;
const ut_root = new Fp6([Fp2.ZERO, Fp2.ONE, Fp2.ZERO]);
const wsq = new Fp12([ut_root, Fp6.ZERO]);
const wsq_inv = wsq.invert();
const wcu = new Fp12([Fp6.ZERO, ut_root]);
const wcu_inv = wcu.invert();
function psi(x, y) {
    const x2 = wsq_inv.multiplyByFp2(x).frobeniusMap(1).multiply(wsq).c[0].c[0];
    const y2 = wcu_inv.multiplyByFp2(y).frobeniusMap(1).multiply(wcu).c[0].c[0];
    return [x2, y2];
}
exports.psi = psi;
function psi2(x, y) {
    return [x.multiply(PSI2_C1), y.negate()];
}
exports.psi2 = psi2;
const PSI2_C1 = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn;
const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
const ev1 = 0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n;
const ev2 = 0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n;
const ev3 = 0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n;
const ev4 = 0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n;
const FP2_FROBENIUS_COEFFICIENTS = [
    0x1n,
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
].map((item) => new Fp(item));
const FP2_ROOTS_OF_UNITY = [
    [1n, 0n],
    [rv1, -rv1],
    [0n, 1n],
    [rv1, rv1],
    [-1n, 0n],
    [-rv1, rv1],
    [0n, -1n],
    [-rv1, -rv1],
].map((pair) => new Fp2(pair));
const FP2_ETAs = [
    [ev1, ev2],
    [-ev2, ev1],
    [ev3, ev4],
    [-ev4, ev3],
].map((pair) => new Fp2(pair));
const FP6_FROBENIUS_COEFFICIENTS_1 = [
    [0x1n, 0x0n],
    [
        0x0n,
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
    ],
    [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
        0x0n,
    ],
    [0x0n, 0x1n],
    [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
        0x0n,
    ],
    [
        0x0n,
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
    ],
].map((pair) => new Fp2(pair));
const FP6_FROBENIUS_COEFFICIENTS_2 = [
    [0x1n, 0x0n],
    [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
        0x0n,
    ],
    [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
        0x0n,
    ],
    [
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
        0x0n,
    ],
    [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
        0x0n,
    ],
    [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
        0x0n,
    ],
].map((pair) => new Fp2(pair));
const FP12_FROBENIUS_COEFFICIENTS = [
    [0x1n, 0x0n],
    [
        0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n,
        0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n,
    ],
    [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
        0x0n,
    ],
    [
        0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n,
        0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n,
    ],
    [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
        0x0n,
    ],
    [
        0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n,
        0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n,
    ],
    [
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
        0x0n,
    ],
    [
        0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n,
        0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n,
    ],
    [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
        0x0n,
    ],
    [
        0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n,
        0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n,
    ],
    [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
        0x0n,
    ],
    [
        0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n,
        0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n,
    ],
].map((pair) => new Fp2(pair));
const xnum = [
    [
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
    ],
    [
        0x0n,
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an,
    ],
    [
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn,
    ],
    [
        0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n,
        0x0n,
    ],
].map((pair) => new Fp2(pair));
const xden = [
    [
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n,
    ],
    [
        0xcn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn,
    ],
    [0x1n, 0x0n],
    [0x0n, 0x0n],
].map((pair) => new Fp2(pair));
const ynum = [
    [
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
    ],
    [
        0x0n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben,
    ],
    [
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn,
    ],
    [
        0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n,
        0x0n,
    ],
].map((pair) => new Fp2(pair));
const yden = [
    [
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
    ],
    [
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n,
    ],
    [
        0x12n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n,
    ],
    [0x1n, 0x0n],
].map((pair) => new Fp2(pair));
const ISOGENY_COEFFICIENTS = [xnum, xden, ynum, yden];
const POW_2_381 = 2n ** 381n;
const POW_2_382 = POW_2_381 * 2n;
const POW_2_383 = POW_2_382 * 2n;
const PUBLIC_KEY_LENGTH = 48;
const SHA256_DIGEST_SIZE = 32;
const htfDefaults = {
    DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_',
    p: exports.CURVE.P,
    m: 2,
    k: 128,
    expand: true,
};
function isWithinCurveOrder(num) {
    return 0 < num && num < exports.CURVE.r;
}
const crypto = (() => {
    const webCrypto = typeof self === 'object' && 'crypto' in self ? self.crypto : undefined;
    const nodeRequire = typeof module !== 'undefined' && typeof require === 'function';
    return {
        node: nodeRequire && !webCrypto ? require('crypto') : undefined,
        web: webCrypto,
    };
})();
exports.utils = {
    hashToField: hash_to_field,
    randomBytes: (bytesLength = 32) => {
        if (crypto.web) {
            return crypto.web.getRandomValues(new Uint8Array(bytesLength));
        }
        else if (crypto.node) {
            const { randomBytes } = crypto.node;
            return new Uint8Array(randomBytes(bytesLength).buffer);
        }
        else {
            throw new Error("The environment doesn't have randomBytes function");
        }
    },
    randomPrivateKey: () => {
        let i = 8;
        while (i--) {
            const b32 = exports.utils.randomBytes(32);
            const num = bytesToNumberBE(b32);
            if (isWithinCurveOrder(num) && num !== 1n)
                return b32;
        }
        throw new Error('Valid private key was not found in 8 iterations. PRNG is broken');
    },
    sha256: async (message) => {
        if (crypto.web) {
            const buffer = await crypto.web.subtle.digest('SHA-256', message.buffer);
            return new Uint8Array(buffer);
        }
        else if (crypto.node) {
            return Uint8Array.from(crypto.node.createHash('sha256').update(message).digest());
        }
        else {
            throw new Error("The environment doesn't have sha256 function");
        }
    },
    mod,
    getDSTLabel() {
        return htfDefaults.DST;
    },
    setDSTLabel(newLabel) {
        if (typeof newLabel !== 'string' || newLabel.length > 2048 || newLabel.length === 0) {
            throw new TypeError('Invalid DST');
        }
        htfDefaults.DST = newLabel;
    },
};
function bytesToNumberBE(bytes) {
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
}
function bytesToHex(uint8a) {
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += uint8a[i].toString(16).padStart(2, '0');
    }
    return hex;
}
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2)
        throw new Error('hexToBytes: received invalid unpadded hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}
function toPaddedHex(num, padding) {
    if (num < 0n)
        throw new Error('Expected valid number');
    if (typeof padding !== 'number')
        throw new TypeError('Expected valid padding');
    return num.toString(16).padStart(padding * 2, '0');
}
function ensureBytes(hex) {
    if (hex instanceof Uint8Array)
        return hex;
    if (typeof hex === 'string')
        return hexToBytes(hex);
    throw new TypeError('Expected hex string or Uint8Array');
}
function concatBytes(...arrays) {
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
function stringToBytes(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}
function os2ip(bytes) {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result <<= 8n;
        result += BigInt(bytes[i]);
    }
    return result;
}
function i2osp(value, length) {
    if (value < 0 || value >= 1 << (8 * length)) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    }
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 0xff;
        value >>>= 8;
    }
    return new Uint8Array(res);
}
function strxor(a, b) {
    const arr = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        arr[i] = a[i] ^ b[i];
    }
    return arr;
}
async function expand_message_xmd(msg, DST, lenInBytes) {
    const H = exports.utils.sha256;
    const b_in_bytes = SHA256_DIGEST_SIZE;
    const r_in_bytes = b_in_bytes * 2;
    const ell = Math.ceil(lenInBytes / b_in_bytes);
    if (ell > 255)
        throw new Error('Invalid xmd length');
    const DST_prime = concatBytes(DST, i2osp(DST.length, 1));
    const Z_pad = i2osp(0, r_in_bytes);
    const l_i_b_str = i2osp(lenInBytes, 2);
    const b = new Array(ell);
    const b_0 = await H(concatBytes(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
    b[0] = await H(concatBytes(b_0, i2osp(1, 1), DST_prime));
    for (let i = 1; i <= ell; i++) {
        const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
        b[i] = await H(concatBytes(...args));
    }
    const pseudo_random_bytes = concatBytes(...b);
    return pseudo_random_bytes.slice(0, lenInBytes);
}
async function hash_to_field(msg, count, options = {}) {
    const htfOptions = { ...htfDefaults, ...options };
    const log2p = htfOptions.p.toString(2).length;
    const L = Math.ceil((log2p + htfOptions.k) / 8);
    const len_in_bytes = count * htfOptions.m * L;
    const DST = stringToBytes(htfOptions.DST);
    let pseudo_random_bytes = msg;
    if (htfOptions.expand) {
        pseudo_random_bytes = await expand_message_xmd(msg, DST, len_in_bytes);
    }
    const u = new Array(count);
    for (let i = 0; i < count; i++) {
        const e = new Array(htfOptions.m);
        for (let j = 0; j < htfOptions.m; j++) {
            const elm_offset = L * (j + i * htfOptions.m);
            const tv = pseudo_random_bytes.slice(elm_offset, elm_offset + L);
            e[j] = mod(os2ip(tv), htfOptions.p);
        }
        u[i] = e;
    }
    return u;
}
function normalizePrivKey(key) {
    let int;
    if (key instanceof Uint8Array && key.length === 32)
        int = bytesToNumberBE(key);
    else if (typeof key === 'string' && key.length === 64)
        int = BigInt(`0x${key}`);
    else if (typeof key === 'number' && key > 0 && Number.isSafeInteger(key))
        int = BigInt(key);
    else if (typeof key === 'bigint' && key > 0n)
        int = key;
    else
        throw new TypeError('Expected valid private key');
    int = mod(int, exports.CURVE.r);
    if (!isWithinCurveOrder(int))
        throw new Error('Private key must be 0 < key < CURVE.r');
    return int;
}
function assertType(item, type) {
    if (!(item instanceof type))
        throw new Error('Expected Fp* argument, not number/bigint');
}
class PointG1 extends ProjectivePoint {
    constructor(x, y, z = Fp.ONE) {
        super(x, y, z, Fp);
        assertType(x, Fp);
        assertType(y, Fp);
        assertType(z, Fp);
    }
    static fromHex(bytes) {
        bytes = ensureBytes(bytes);
        const { P } = exports.CURVE;
        let point;
        if (bytes.length === 48) {
            const compressedValue = bytesToNumberBE(bytes);
            const bflag = mod(compressedValue, POW_2_383) / POW_2_382;
            if (bflag === 1n) {
                return this.ZERO;
            }
            const x = new Fp(mod(compressedValue, POW_2_381));
            const right = x.pow(3n).add(new Fp(exports.CURVE.b));
            let y = right.sqrt();
            if (!y)
                throw new Error('Invalid compressed G1 point');
            const aflag = mod(compressedValue, POW_2_382) / POW_2_381;
            if ((y.value * 2n) / P !== aflag)
                y = y.negate();
            point = new PointG1(x, y);
        }
        else if (bytes.length === 96) {
            if ((bytes[0] & (1 << 6)) !== 0)
                return PointG1.ZERO;
            const x = bytesToNumberBE(bytes.slice(0, PUBLIC_KEY_LENGTH));
            const y = bytesToNumberBE(bytes.slice(PUBLIC_KEY_LENGTH));
            point = new PointG1(new Fp(x), new Fp(y));
        }
        else {
            throw new Error('Invalid point G1, expected 48/96 bytes');
        }
        point.assertValidity();
        return point;
    }
    static fromPrivateKey(privateKey) {
        return this.BASE.multiplyPrecomputed(normalizePrivKey(privateKey));
    }
    toRawBytes(isCompressed = false) {
        return hexToBytes(this.toHex(isCompressed));
    }
    toHex(isCompressed = false) {
        this.assertValidity();
        const { P } = exports.CURVE;
        if (isCompressed) {
            let hex;
            if (this.isZero()) {
                hex = POW_2_383 + POW_2_382;
            }
            else {
                const [x, y] = this.toAffine();
                const flag = (y.value * 2n) / P;
                hex = x.value + flag * POW_2_381 + POW_2_383;
            }
            return toPaddedHex(hex, PUBLIC_KEY_LENGTH);
        }
        else {
            if (this.isZero()) {
                return '4'.padEnd(2 * 2 * PUBLIC_KEY_LENGTH, '0');
            }
            else {
                const [x, y] = this.toAffine();
                return toPaddedHex(x.value, PUBLIC_KEY_LENGTH) + toPaddedHex(y.value, PUBLIC_KEY_LENGTH);
            }
        }
    }
    assertValidity() {
        if (this.isZero())
            return this;
        if (!this.isOnCurve())
            throw new Error('Invalid G1 point: not on curve Fp');
        if (!this.isTorsionFree())
            throw new Error('Invalid G1 point: must be of prime-order subgroup');
        return this;
    }
    [Symbol.for('nodejs.util.inspect.custom')]() {
        return this.toString();
    }
    millerLoop(P) {
        return millerLoop(P.pairingPrecomputes(), this.toAffine());
    }
    clearCofactor() {
        return this.multiplyUnsafe(exports.CURVE.h);
    }
    isOnCurve() {
        const b = new Fp(exports.CURVE.b);
        const { x, y, z } = this;
        const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
        const right = b.multiply(z.pow(3n));
        return left.subtract(right).isZero();
    }
    sigma() {
        const BETA = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn;
        const [x, y] = this.toAffine();
        return new PointG1(x.multiply(BETA), y);
    }
    isTorsionFree() {
        const c1 = 0x396c8c005555e1560000000055555555n;
        const P = this;
        const S = P.sigma();
        const Q = S.double();
        const S2 = S.sigma();
        const left = Q.subtract(P).subtract(S2).multiplyUnsafe(c1);
        const C = left.subtract(S2);
        return C.isZero();
    }
}
exports.PointG1 = PointG1;
PointG1.BASE = new PointG1(new Fp(exports.CURVE.Gx), new Fp(exports.CURVE.Gy), Fp.ONE);
PointG1.ZERO = new PointG1(Fp.ONE, Fp.ONE, Fp.ZERO);
class PointG2 extends ProjectivePoint {
    constructor(x, y, z = Fp2.ONE) {
        super(x, y, z, Fp2);
        assertType(x, Fp2);
        assertType(y, Fp2);
        assertType(z, Fp2);
    }
    static async hashToCurve(msg) {
        msg = ensureBytes(msg);
        const u = await hash_to_field(msg, 2);
        const Q0 = new PointG2(...isogenyMapG2(map_to_curve_simple_swu_9mod16(u[0])));
        const Q1 = new PointG2(...isogenyMapG2(map_to_curve_simple_swu_9mod16(u[1])));
        const R = Q0.add(Q1);
        const P = R.clearCofactor();
        return P;
    }
    static fromSignature(hex) {
        hex = ensureBytes(hex);
        const { P } = exports.CURVE;
        const half = hex.length / 2;
        if (half !== 48 && half !== 96)
            throw new Error('Invalid compressed signature length, must be 96 or 192');
        const z1 = bytesToNumberBE(hex.slice(0, half));
        const z2 = bytesToNumberBE(hex.slice(half));
        const bflag1 = mod(z1, POW_2_383) / POW_2_382;
        if (bflag1 === 1n)
            return this.ZERO;
        const x1 = z1 % POW_2_381;
        const x2 = z2;
        const x = new Fp2([x2, x1]);
        const y2 = x.pow(3n).add(new Fp2(exports.CURVE.b2));
        let y = y2.sqrt();
        if (!y)
            throw new Error('Failed to find a square root');
        const [y0, y1] = y.values;
        const aflag1 = (z1 % POW_2_382) / POW_2_381;
        const isGreater = y1 > 0n && (y1 * 2n) / P !== aflag1;
        const isZero = y1 === 0n && (y0 * 2n) / P !== aflag1;
        if (isGreater || isZero)
            y = y.multiply(-1n);
        const point = new PointG2(x, y, Fp2.ONE);
        point.assertValidity();
        return point;
    }
    static fromHex(bytes) {
        bytes = ensureBytes(bytes);
        let point;
        if (bytes.length === 96) {
            throw new Error('Compressed format not supported yet.');
        }
        else if (bytes.length === 192) {
            if ((bytes[0] & (1 << 6)) !== 0) {
                return PointG2.ZERO;
            }
            const x1 = bytesToNumberBE(bytes.slice(0, PUBLIC_KEY_LENGTH));
            const x0 = bytesToNumberBE(bytes.slice(PUBLIC_KEY_LENGTH, 2 * PUBLIC_KEY_LENGTH));
            const y1 = bytesToNumberBE(bytes.slice(2 * PUBLIC_KEY_LENGTH, 3 * PUBLIC_KEY_LENGTH));
            const y0 = bytesToNumberBE(bytes.slice(3 * PUBLIC_KEY_LENGTH));
            point = new PointG2(new Fp2([x0, x1]), new Fp2([y0, y1]));
        }
        else {
            throw new Error('Invalid uncompressed point G2, expected 192 bytes');
        }
        point.assertValidity();
        return point;
    }
    static fromPrivateKey(privateKey) {
        return this.BASE.multiplyPrecomputed(normalizePrivKey(privateKey));
    }
    toSignature() {
        if (this.equals(PointG2.ZERO)) {
            const sum = POW_2_383 + POW_2_382;
            return toPaddedHex(sum, PUBLIC_KEY_LENGTH) + toPaddedHex(0n, PUBLIC_KEY_LENGTH);
        }
        const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.values);
        const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
        const aflag1 = tmp / exports.CURVE.P;
        const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
        const z2 = x0;
        return toPaddedHex(z1, PUBLIC_KEY_LENGTH) + toPaddedHex(z2, PUBLIC_KEY_LENGTH);
    }
    toRawBytes(isCompressed = false) {
        return hexToBytes(this.toHex(isCompressed));
    }
    toHex(isCompressed = false) {
        this.assertValidity();
        if (isCompressed) {
            throw new Error('Point compression has not yet been implemented');
        }
        else {
            if (this.equals(PointG2.ZERO)) {
                return '4'.padEnd(2 * 4 * PUBLIC_KEY_LENGTH, '0');
            }
            const [[x0, x1], [y0, y1]] = this.toAffine().map((a) => a.values);
            return (toPaddedHex(x1, PUBLIC_KEY_LENGTH) +
                toPaddedHex(x0, PUBLIC_KEY_LENGTH) +
                toPaddedHex(y1, PUBLIC_KEY_LENGTH) +
                toPaddedHex(y0, PUBLIC_KEY_LENGTH));
        }
    }
    assertValidity() {
        if (this.isZero())
            return this;
        if (!this.isOnCurve())
            throw new Error('Invalid G2 point: not on curve Fp2');
        if (!this.isTorsionFree())
            throw new Error('Invalid G2 point: must be of prime-order subgroup');
        return this;
    }
    psi() {
        return this.fromAffineTuple(psi(...this.toAffine()));
    }
    psi2() {
        return this.fromAffineTuple(psi2(...this.toAffine()));
    }
    mulNegX() {
        return this.multiplyUnsafe(exports.CURVE.x).negate();
    }
    clearCofactor() {
        const P = this;
        let t1 = P.mulNegX();
        let t2 = P.psi();
        let t3 = P.double();
        t3 = t3.psi2();
        t3 = t3.subtract(t2);
        t2 = t1.add(t2);
        t2 = t2.mulNegX();
        t3 = t3.add(t2);
        t3 = t3.subtract(t1);
        const Q = t3.subtract(P);
        return Q;
    }
    isOnCurve() {
        const b = new Fp2(exports.CURVE.b2);
        const { x, y, z } = this;
        const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
        const right = b.multiply(z.pow(3n));
        return left.subtract(right).isZero();
    }
    isTorsionFree() {
        const P = this;
        const psi2 = P.psi2();
        const psi3 = psi2.psi();
        const zPsi3 = psi3.mulNegX();
        return zPsi3.subtract(psi2).add(P).isZero();
    }
    [Symbol.for('nodejs.util.inspect.custom')]() {
        return this.toString();
    }
    clearPairingPrecomputes() {
        this._PPRECOMPUTES = undefined;
    }
    pairingPrecomputes() {
        if (this._PPRECOMPUTES)
            return this._PPRECOMPUTES;
        this._PPRECOMPUTES = calcPairingPrecomputes(...this.toAffine());
        return this._PPRECOMPUTES;
    }
}
exports.PointG2 = PointG2;
PointG2.BASE = new PointG2(new Fp2(exports.CURVE.G2x), new Fp2(exports.CURVE.G2y), Fp2.ONE);
PointG2.ZERO = new PointG2(Fp2.ONE, Fp2.ONE, Fp2.ZERO);
function pairing(P, Q, withFinalExponent = true) {
    if (P.isZero() || Q.isZero())
        throw new Error('No pairings at point of Infinity');
    P.assertValidity();
    Q.assertValidity();
    const looped = P.millerLoop(Q);
    return withFinalExponent ? looped.finalExponentiate() : looped;
}
exports.pairing = pairing;
function normP1(point) {
    return point instanceof PointG1 ? point : PointG1.fromHex(point);
}
function normP2(point) {
    return point instanceof PointG2 ? point : PointG2.fromSignature(point);
}
async function normP2Hash(point) {
    return point instanceof PointG2 ? point : PointG2.hashToCurve(point);
}
function getPublicKey(privateKey) {
    const bytes = PointG1.fromPrivateKey(privateKey).toRawBytes(true);
    return typeof privateKey === 'string' ? bytesToHex(bytes) : bytes;
}
exports.getPublicKey = getPublicKey;
async function sign(message, privateKey) {
    const msgPoint = await normP2Hash(message);
    msgPoint.assertValidity();
    const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
    if (message instanceof PointG2)
        return sigPoint;
    const hex = sigPoint.toSignature();
    return typeof message === 'string' ? hex : hexToBytes(hex);
}
exports.sign = sign;
async function verify(signature, message, publicKey) {
    const P = normP1(publicKey);
    const Hm = await normP2Hash(message);
    const G = PointG1.BASE;
    const S = normP2(signature);
    const ePHm = pairing(P.negate(), Hm, false);
    const eGS = pairing(G, S, false);
    const exp = eGS.multiply(ePHm).finalExponentiate();
    return exp.equals(Fp12.ONE);
}
exports.verify = verify;
function aggregatePublicKeys(publicKeys) {
    if (!publicKeys.length)
        throw new Error('Expected non-empty array');
    const agg = publicKeys.map(normP1).reduce((sum, p) => sum.add(p), PointG1.ZERO);
    if (publicKeys[0] instanceof PointG1)
        return agg.assertValidity();
    const bytes = agg.toRawBytes(true);
    if (publicKeys[0] instanceof Uint8Array)
        return bytes;
    return bytesToHex(bytes);
}
exports.aggregatePublicKeys = aggregatePublicKeys;
function aggregateSignatures(signatures) {
    if (!signatures.length)
        throw new Error('Expected non-empty array');
    const agg = signatures.map(normP2).reduce((sum, s) => sum.add(s), PointG2.ZERO);
    if (signatures[0] instanceof PointG2)
        return agg.assertValidity();
    const bytes = agg.toSignature();
    if (signatures[0] instanceof Uint8Array)
        return hexToBytes(bytes);
    return bytes;
}
exports.aggregateSignatures = aggregateSignatures;
async function verifyBatch(signature, messages, publicKeys) {
    if (!messages.length)
        throw new Error('Expected non-empty messages array');
    if (publicKeys.length !== messages.length)
        throw new Error('Pubkey count should equal msg count');
    const sig = normP2(signature);
    const nMessages = await Promise.all(messages.map(normP2Hash));
    const nPublicKeys = publicKeys.map(normP1);
    try {
        const paired = [];
        for (const message of new Set(nMessages)) {
            const groupPublicKey = nMessages.reduce((groupPublicKey, subMessage, i) => subMessage === message ? groupPublicKey.add(nPublicKeys[i]) : groupPublicKey, PointG1.ZERO);
            paired.push(pairing(groupPublicKey, message, false));
        }
        paired.push(pairing(PointG1.BASE.negate(), sig, false));
        const product = paired.reduce((a, b) => a.multiply(b), Fp12.ONE);
        const exp = product.finalExponentiate();
        return exp.equals(Fp12.ONE);
    }
    catch {
        return false;
    }
}
exports.verifyBatch = verifyBatch;
PointG1.BASE.calcMultiplyPrecomputes(4);
var IsECRDSA_Verify = function(id) { return id == BigInt("2075488948259244450"); }
var IsHMAC = function(id) { return id == BigInt("2199449812569109303"); }
var IsBLS_Sign = function(id) { return id == BigInt("2875235401351023405"); }
var IsECC_Point_Add = function(id) { return id == BigInt("2953094577370070712"); }
var IsSymmetricEncrypt = function(id) { return id == BigInt("2976759534500793820"); }
var IsKDF_PBKDF1 = function(id) { return id == BigInt("3450355166456167260"); }
var IsKDF_PBKDF2 = function(id) { return id == BigInt("3450358464991051893"); }
var IsKDF_PBKDF = function(id) { return id == BigInt("3504204876962697477"); }
var IsBLS_Decompress_G1 = function(id) { return id == BigInt("3672527266831566440"); }
var IsBLS_Decompress_G2 = function(id) { return id == BigInt("3672530565366451073"); }
var IsBLS_G1_IsEq = function(id) { return id == BigInt("3745040402587948587"); }
var IsBignumCalc_Mod_BLS12_381_R = function(id) { return id == BigInt("3927672189283779123"); }
var IsBignumCalc_Mod_BLS12_381_P = function(id) { return id == BigInt("3927674388307035545"); }
var IsBLS_G2_Add = function(id) { return id == BigInt("3982242242522983881"); }
var IsBLS_G1_Add = function(id) { return id == BigInt("4460206687329269228"); }
var IsECDSA_Verify = function(id) { return id == BigInt("4475220330049108872"); }
var IsECDH_Derive = function(id) { return id == BigInt("5046600913796342794"); }
var IsBLS_IsG2OnCurve = function(id) { return id == BigInt("5323959883309341751"); }
var IsECC_PrivateToPublic = function(id) { return id == BigInt("5539743395198706529"); }
var IsECIES_Encrypt = function(id) { return id == BigInt("5560960351281728901"); }
var IsDigest = function(id) { return id == BigInt("5809491516167589196"); }
var IsBignumCalc = function(id) { return id == BigInt("5866728786590536975"); }
var IsBLS_G2_IsEq = function(id) { return id == BigInt("6019528506043436648"); }
var IsDH_Derive = function(id) { return id == BigInt("6854737006333781894"); }
var IsECGDSA_Sign = function(id) { return id == BigInt("8163694440785824261"); }
var IsECGDSA_Verify = function(id) { return id == BigInt("8361011715369233209"); }
var IsSchnorr_Verify = function(id) { return id == BigInt("8473266746052007431"); }
var IsECDSA_Recover = function(id) { return id == BigInt("8872906712023707375"); }
var IsDH_GenerateKeyPair = function(id) { return id == BigInt("8955882836668873941"); }
var IsKDF_ARGON2 = function(id) { return id == BigInt("8989551212334913101"); }
var IsKDF_X963 = function(id) { return id == BigInt("9326441367258825100"); }
var IsKDF_TLS1_PRF = function(id) { return id == BigInt("9382889272173326955"); }
var IsBLS_PrivateToPublic = function(id) { return id == BigInt("9518715530777777963"); }
var IsBLS_PrivateToPublic_G2 = function(id) { return id == BigInt("9582672856034496969"); }
var IsBLS_G2_Neg = function(id) { return id == BigInt("9715691805813100268"); }
var IsKDF_SCRYPT = function(id) { return id == BigInt("10005503820668675355"); }
var IsBLS_Verify = function(id) { return id == BigInt("10031261976360763489"); }
var IsECC_Point_Mul = function(id) { return id == BigInt("10512925313610633373"); }
var IsBLS_GenerateKeyPair = function(id) { return id == BigInt("10944057886766318610"); }
var IsBLS_G2_Mul = function(id) { return id == BigInt("11540353342577402988"); }
var IsBLS_Compress_G2 = function(id) { return id == BigInt("11823635277989142852"); }
var IsBLS_Compress_G1 = function(id) { return id == BigInt("11823638576524027485"); }
var IsECC_GenerateKeyPair = function(id) { return id == BigInt("12332401161757138384"); }
var IsSR25519_Verify = function(id) { return id == BigInt("12506434490133466843"); }
var IsBignumCalc_Mod_SECP256K1 = function(id) { return id == BigInt("12712141260368232507"); }
var IsBignumCalc_Mod_2Exp256 = function(id) { return id == BigInt("13026559038354618177"); }
var IsECRDSA_Sign = function(id) { return id == BigInt("13361868971281677690"); }
var IsKDF_SP_800_108 = function(id) { return id == BigInt("13576222566899769656"); }
var IsECDSA_Sign = function(id) { return id == BigInt("14229822751382312176"); }
var IsKDF_SSH = function(id) { return id == BigInt("14291370178360082506"); }
var IsSymmetricDecrypt = function(id) { return id == BigInt("14331211725752570280"); }
var IsKDF_HKDF = function(id) { return id == BigInt("14356609771627578971"); }
var IsECIES_Decrypt = function(id) { return id == BigInt("15307561034024662125"); }
var IsBLS_G1_Mul = function(id) { return id == BigInt("15624386071052607225"); }
var IsMisc = function(id) { return id == BigInt("15698672930317548180"); }
var IsECC_ValidatePubkey = function(id) { return id == BigInt("15952101299761277882"); }
var IsBLS_HashToG2 = function(id) { return id == BigInt("16384127429031991996"); }
var IsBLS_HashToG1 = function(id) { return id == BigInt("16384130727566876629"); }
var IsKDF_BCRYPT = function(id) { return id == BigInt("16452550327545558230"); }
var IsBLS_Aggregate_G1 = function(id) { return id == BigInt("16811328735348207892"); }
var IsBLS_Aggregate_G2 = function(id) { return id == BigInt("16811332033883092525"); }
var IsBLS_IsG1OnCurve = function(id) { return id == BigInt("16891560331061928144"); }
var IsCMAC = function(id) { return id == BigInt("17223730669190186232"); }
var IsBLS_Pairing = function(id) { return id == BigInt("17259658332555689480"); }
var IsBLS_G1_Neg = function(id) { return id == BigInt("17479745972470505865"); }
var IsSchnorr_Sign = function(id) { return id == BigInt("18302666542519829747"); }
var IsCmp = function(id) { return id == "278502619037614225"; }
var IsMod_NIST_224 = function(id) { return id == "328442376415470609"; }
var IsNeg = function(id) { return id == "497803678004747625"; }
var IsRand = function(id) { return id == "752527180851484917"; }
var IsSqrMod = function(id) { return id == "840523479701349425"; }
var IsMin = function(id) { return id == "1135892590552068761"; }
var IsExpMod = function(id) { return id == "1317996975705594123"; }
var IsAnd = function(id) { return id == "1431659550035644982"; }
var IsMax = function(id) { return id == "2316310815682592019"; }
var IsJacobi = function(id) { return id == "2320969532226616953"; }
var IsIsPrime = function(id) { return id == "2533057117655612930"; }
var IsOr = function(id) { return id == "2652194927012011212"; }
var IsCondSet = function(id) { return id == "2910448180055264741"; }
var IsSqrt = function(id) { return id == "3246105777544845851"; }
var IsRessol = function(id) { return id == "3646149807237422511"; }
var IsMSB = function(id) { return id == "3914790112055834161"; }
var IsMod_NIST_192 = function(id) { return id == "3985001678117154633"; }
var IsMulAdd = function(id) { return id == "4838132959585393335"; }
var IsInvMod = function(id) { return id == "4944816444068270084"; }
var IsNumLSZeroBits = function(id) { return id == "5028249431888347578"; }
var IsIsGte = function(id) { return id == "5243674767385134835"; }
var IsMod_NIST_521 = function(id) { return id == "5321720337552789659"; }
var IsIsCoprime = function(id) { return id == "5477127052586603538"; }
var IsSet = function(id) { return id == "5575473018973207767"; }
var IsMod_NIST_256 = function(id) { return id == "5575823971303299034"; }
var IsGCD = function(id) { return id == "5785484340816638963"; }
var IsSqrtMod = function(id) { return id == "5940576748551985711"; }
var IsSetBit = function(id) { return id == "7114552031224698798"; }
var IsClearBit = function(id) { return id == "7245952310988955231"; }
var IsNot = function(id) { return id == "7327676617649672056"; }
var IsIsLt = function(id) { return id == "7367988338173335495"; }
var IsNumBits = function(id) { return id == "7388945974529068435"; }
var IsModLShift = function(id) { return id == "7508375228105742854"; }
var IsSub = function(id) { return id == "7565474059520578463"; }
var IsAddMod = function(id) { return id == "7829063627812952999"; }
var IsAbs = function(id) { return id == "8313790271709138543"; }
var IsCmpAbs = function(id) { return id == "8434802902606449387"; }
var IsLog10 = function(id) { return id == "8523052216371035834"; }
var IsLShift1 = function(id) { return id == "9202869717780373138"; }
var IsIsZero = function(id) { return id == "9784528180127606591"; }
var IsExp = function(id) { return id == "10207793044261461432"; }
var IsAdd = function(id) { return id == "10633833424446033180"; }
var IsIsPow2 = function(id) { return id == "10935818379206750101"; }
var IsIsEq = function(id) { return id == "10998724852397858805"; }
var IsBit = function(id) { return id == "11778408755722008352"; }
var IsMod = function(id) { return id == "12110391648600810285"; }
var IsMulMod = function(id) { return id == "12168006286085220942"; }
var IsMul = function(id) { return id == "12211643382727132651"; }
var IsLCM = function(id) { return id == "12234676516579856929"; }
var IsDiv = function(id) { return id == "13646095757308424912"; }
var IsSubMod = function(id) { return id == "14199920696347809146"; }
var IsXor = function(id) { return id == "14328566578340454326"; }
var IsExp2 = function(id) { return id == "14465538327966413692"; }
var IsIsOdd = function(id) { return id == "15092317424047335748"; }
var IsIsGt = function(id) { return id == "15477000640961809998"; }
var IsIsNotZero = function(id) { return id == "16279986849973627458"; }
var IsSqr = function(id) { return id == "16314490223308766513"; }
var IsMod_NIST_384 = function(id) { return id == "16445788808805648178"; }
var IsIsEven = function(id) { return id == "16951741325418416169"; }
var IsIsOne = function(id) { return id == "17368484737873471187"; }
var IsRShift = function(id) { return id == "17389184683344743809"; }
var IsIsNeg = function(id) { return id == "17395210549452595161"; }
var IsIsLte = function(id) { return id == "17987934071602219992"; }
var IsMask = function(id) { return id == "18160400994409278475"; }
/*globals window, global, require*/

/**
 * CryptoJS core components.
 */
var CryptoJS = CryptoJS || (function (Math, undefined) {

    var crypto;

    // Native crypto from window (Browser)
    if (typeof window !== 'undefined' && window.crypto) {
        crypto = window.crypto;
    }

    // Native crypto in web worker (Browser)
    if (typeof self !== 'undefined' && self.crypto) {
        crypto = self.crypto;
    }

    // Native crypto from worker
    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
        crypto = globalThis.crypto;
    }

    // Native (experimental IE 11) crypto from window (Browser)
    if (!crypto && typeof window !== 'undefined' && window.msCrypto) {
        crypto = window.msCrypto;
    }

    // Native crypto from global (NodeJS)
    if (!crypto && typeof global !== 'undefined' && global.crypto) {
        crypto = global.crypto;
    }

    // Native crypto import via require (NodeJS)
    if (!crypto && typeof require === 'function') {
        try {
            crypto = require('crypto');
        } catch (err) {}
    }

    /*
     * Cryptographically secure pseudorandom number generator
     *
     * As Math.random() is cryptographically not safe to use
     */
    var cryptoSecureRandomInt = function () {
        if (crypto) {
            // Use getRandomValues method (Browser)
            if (typeof crypto.getRandomValues === 'function') {
                try {
                    return crypto.getRandomValues(new Uint32Array(1))[0];
                } catch (err) {}
            }

            // Use randomBytes method (NodeJS)
            if (typeof crypto.randomBytes === 'function') {
                try {
                    return crypto.randomBytes(4).readInt32LE();
                } catch (err) {}
            }
        }

        throw new Error('Native crypto module could not be used to get secure random number.');
    };

    /*
     * Local polyfill of Object.create

     */
    var create = Object.create || (function () {
        function F() {}

        return function (obj) {
            var subtype;

            F.prototype = obj;

            subtype = new F();

            F.prototype = null;

            return subtype;
        };
    }());

    /**
     * CryptoJS namespace.
     */
    var C = {};

    /**
     * Library namespace.
     */
    var C_lib = C.lib = {};

    /**
     * Base object for prototypal inheritance.
     */
    var Base = C_lib.Base = (function () {


        return {
            /**
             * Creates a new object that inherits from this object.
             *
             * @param {Object} overrides Properties to copy into the new object.
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         field: 'value',
             *
             *         method: function () {
             *         }
             *     });
             */
            extend: function (overrides) {
                // Spawn
                var subtype = create(this);

                // Augment
                if (overrides) {
                    subtype.mixIn(overrides);
                }

                // Create default initializer
                if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
                    subtype.init = function () {
                        subtype.$super.init.apply(this, arguments);
                    };
                }

                // Initializer's prototype is the subtype object
                subtype.init.prototype = subtype;

                // Reference supertype
                subtype.$super = this;

                return subtype;
            },

            /**
             * Extends this object and runs the init method.
             * Arguments to create() will be passed to init().
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var instance = MyType.create();
             */
            create: function () {
                var instance = this.extend();
                instance.init.apply(instance, arguments);

                return instance;
            },

            /**
             * Initializes a newly created object.
             * Override this method to add some logic when your objects are created.
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         init: function () {
             *             // ...
             *         }
             *     });
             */
            init: function () {
            },

            /**
             * Copies properties into this object.
             *
             * @param {Object} properties The properties to mix in.
             *
             * @example
             *
             *     MyType.mixIn({
             *         field: 'value'
             *     });
             */
            mixIn: function (properties) {
                for (var propertyName in properties) {
                    if (properties.hasOwnProperty(propertyName)) {
                        this[propertyName] = properties[propertyName];
                    }
                }

                // IE won't copy toString using the loop above
                if (properties.hasOwnProperty('toString')) {
                    this.toString = properties.toString;
                }
            },

            /**
             * Creates a copy of this object.
             *
             * @return {Object} The clone.
             *
             * @example
             *
             *     var clone = instance.clone();
             */
            clone: function () {
                return this.init.prototype.extend(this);
            }
        };
    }());

    /**
     * An array of 32-bit words.
     *
     * @property {Array} words The array of 32-bit words.
     * @property {number} sigBytes The number of significant bytes in this word array.
     */
    var WordArray = C_lib.WordArray = Base.extend({
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of 32-bit words.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.create();
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
         */
        init: function (words, sigBytes) {
            words = this.words = words || [];

            if (sigBytes != undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 4;
            }
        },

        /**
         * Converts this word array to a string.
         *
         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
         *
         * @return {string} The stringified word array.
         *
         * @example
         *
         *     var string = wordArray + '';
         *     var string = wordArray.toString();
         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
         */
        toString: function (encoder) {
            return (encoder || Hex).stringify(this);
        },

        /**
         * Concatenates a word array to this word array.
         *
         * @param {WordArray} wordArray The word array to append.
         *
         * @return {WordArray} This word array.
         *
         * @example
         *
         *     wordArray1.concat(wordArray2);
         */
        concat: function (wordArray) {
            // Shortcuts
            var thisWords = this.words;
            var thatWords = wordArray.words;
            var thisSigBytes = this.sigBytes;
            var thatSigBytes = wordArray.sigBytes;

            // Clamp excess bits
            this.clamp();

            // Concat
            if (thisSigBytes % 4) {
                // Copy one byte at a time
                for (var i = 0; i < thatSigBytes; i++) {
                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                }
            } else {
                // Copy one word at a time
                for (var j = 0; j < thatSigBytes; j += 4) {
                    thisWords[(thisSigBytes + j) >>> 2] = thatWords[j >>> 2];
                }
            }
            this.sigBytes += thatSigBytes;

            // Chainable
            return this;
        },

        /**
         * Removes insignificant bits.
         *
         * @example
         *
         *     wordArray.clamp();
         */
        clamp: function () {
            // Shortcuts
            var words = this.words;
            var sigBytes = this.sigBytes;

            // Clamp
            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
            words.length = Math.ceil(sigBytes / 4);
        },

        /**
         * Creates a copy of this word array.
         *
         * @return {WordArray} The clone.
         *
         * @example
         *
         *     var clone = wordArray.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone.words = this.words.slice(0);

            return clone;
        },

        /**
         * Creates a word array filled with random bytes.
         *
         * @param {number} nBytes The number of random bytes to generate.
         *
         * @return {WordArray} The random word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.random(16);
         */
        random: function (nBytes) {
            var words = [];

            for (var i = 0; i < nBytes; i += 4) {
                words.push(cryptoSecureRandomInt());
            }

            return new WordArray.init(words, nBytes);
        }
    });

    /**
     * Encoder namespace.
     */
    var C_enc = C.enc = {};

    /**
     * Hex encoding strategy.
     */
    var Hex = C_enc.Hex = {
        /**
         * Converts a word array to a hex string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The hex string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var hexChars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                hexChars.push((bite >>> 4).toString(16));
                hexChars.push((bite & 0x0f).toString(16));
            }

            return hexChars.join('');
        },

        /**
         * Converts a hex string to a word array.
         *
         * @param {string} hexStr The hex string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
         */
        parse: function (hexStr) {
            // Shortcut
            var hexStrLength = hexStr.length;

            // Convert
            var words = [];
            for (var i = 0; i < hexStrLength; i += 2) {
                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
            }

            return new WordArray.init(words, hexStrLength / 2);
        }
    };

    /**
     * Latin1 encoding strategy.
     */
    var Latin1 = C_enc.Latin1 = {
        /**
         * Converts a word array to a Latin1 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Latin1 string.
         *
         * @static
         *
         * @example
         *
         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var latin1Chars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                latin1Chars.push(String.fromCharCode(bite));
            }

            return latin1Chars.join('');
        },

        /**
         * Converts a Latin1 string to a word array.
         *
         * @param {string} latin1Str The Latin1 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
         */
        parse: function (latin1Str) {
            // Shortcut
            var latin1StrLength = latin1Str.length;

            // Convert
            var words = [];
            for (var i = 0; i < latin1StrLength; i++) {
                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
            }

            return new WordArray.init(words, latin1StrLength);
        }
    };

    /**
     * UTF-8 encoding strategy.
     */
    var Utf8 = C_enc.Utf8 = {
        /**
         * Converts a word array to a UTF-8 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-8 string.
         *
         * @static
         *
         * @example
         *
         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
         */
        stringify: function (wordArray) {
            try {
                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
            } catch (e) {
                throw new Error('Malformed UTF-8 data');
            }
        },

        /**
         * Converts a UTF-8 string to a word array.
         *
         * @param {string} utf8Str The UTF-8 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
         */
        parse: function (utf8Str) {
            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
        }
    };

    /**
     * Abstract buffered block algorithm template.
     *
     * The property blockSize must be implemented in a concrete subtype.
     *
     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
     */
    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
        /**
         * Resets this block algorithm's data buffer to its initial state.
         *
         * @example
         *
         *     bufferedBlockAlgorithm.reset();
         */
        reset: function () {
            // Initial values
            this._data = new WordArray.init();
            this._nDataBytes = 0;
        },

        /**
         * Adds new data to this block algorithm's buffer.
         *
         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
         *
         * @example
         *
         *     bufferedBlockAlgorithm._append('data');
         *     bufferedBlockAlgorithm._append(wordArray);
         */
        _append: function (data) {
            // Convert string to WordArray, else assume WordArray already
            if (typeof data == 'string') {
                data = Utf8.parse(data);
            }

            // Append
            this._data.concat(data);
            this._nDataBytes += data.sigBytes;
        },

        /**
         * Processes available data blocks.
         *
         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
         *
         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
         *
         * @return {WordArray} The processed data.
         *
         * @example
         *
         *     var processedData = bufferedBlockAlgorithm._process();
         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
         */
        _process: function (doFlush) {
            var processedWords;

            // Shortcuts
            var data = this._data;
            var dataWords = data.words;
            var dataSigBytes = data.sigBytes;
            var blockSize = this.blockSize;
            var blockSizeBytes = blockSize * 4;

            // Count blocks ready
            var nBlocksReady = dataSigBytes / blockSizeBytes;
            if (doFlush) {
                // Round up to include partial blocks
                nBlocksReady = Math.ceil(nBlocksReady);
            } else {
                // Round down to include only full blocks,
                // less the number of blocks that must remain in the buffer
                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
            }

            // Count words ready
            var nWordsReady = nBlocksReady * blockSize;

            // Count bytes ready
            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

            // Process blocks
            if (nWordsReady) {
                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                    // Perform concrete-algorithm logic
                    this._doProcessBlock(dataWords, offset);
                }

                // Remove processed words
                processedWords = dataWords.splice(0, nWordsReady);
                data.sigBytes -= nBytesReady;
            }

            // Return processed words
            return new WordArray.init(processedWords, nBytesReady);
        },

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = bufferedBlockAlgorithm.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone._data = this._data.clone();

            return clone;
        },

        _minBufferSize: 0
    });

    /**
     * Abstract hasher template.
     *
     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
     */
    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
        /**
         * Configuration options.
         */
        cfg: Base.extend(),

        /**
         * Initializes a newly created hasher.
         *
         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
         *
         * @example
         *
         *     var hasher = CryptoJS.algo.SHA256.create();
         */
        init: function (cfg) {
            // Apply config defaults
            this.cfg = this.cfg.extend(cfg);

            // Set initial values
            this.reset();
        },

        /**
         * Resets this hasher to its initial state.
         *
         * @example
         *
         *     hasher.reset();
         */
        reset: function () {
            // Reset data buffer
            BufferedBlockAlgorithm.reset.call(this);

            // Perform concrete-hasher logic
            this._doReset();
        },

        /**
         * Updates this hasher with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {Hasher} This hasher.
         *
         * @example
         *
         *     hasher.update('message');
         *     hasher.update(wordArray);
         */
        update: function (messageUpdate) {
            // Append
            this._append(messageUpdate);

            // Update the hash
            this._process();

            // Chainable
            return this;
        },

        /**
         * Finalizes the hash computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The hash.
         *
         * @example
         *
         *     var hash = hasher.finalize();
         *     var hash = hasher.finalize('message');
         *     var hash = hasher.finalize(wordArray);
         */
        finalize: function (messageUpdate) {
            // Final message update
            if (messageUpdate) {
                this._append(messageUpdate);
            }

            // Perform concrete-hasher logic
            var hash = this._doFinalize();

            return hash;
        },

        blockSize: 512/32,

        /**
         * Creates a shortcut function to a hasher's object interface.
         *
         * @param {Hasher} hasher The hasher to create a helper for.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
         */
        _createHelper: function (hasher) {
            return function (message, cfg) {
                return new hasher.init(cfg).finalize(message);
            };
        },

        /**
         * Creates a shortcut function to the HMAC's object interface.
         *
         * @param {Hasher} hasher The hasher to use in this HMAC helper.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
         */
        _createHmacHelper: function (hasher) {
            return function (message, key) {
                return new C_algo.HMAC.init(hasher, key).finalize(message);
            };
        }
    });

    /**
     * Algorithm namespace.
     */
    var C_algo = C.algo = {};

    return C;
}(Math));
(function (undefined) {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var Base = C_lib.Base;
    var X32WordArray = C_lib.WordArray;

    /**
     * x64 namespace.
     */
    var C_x64 = C.x64 = {};

    /**
     * A 64-bit word.
     */
    var X64Word = C_x64.Word = Base.extend({
        /**
         * Initializes a newly created 64-bit word.
         *
         * @param {number} high The high 32 bits.
         * @param {number} low The low 32 bits.
         *
         * @example
         *
         *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
         */
        init: function (high, low) {
            this.high = high;
            this.low = low;
        }

        /**
         * Bitwise NOTs this word.
         *
         * @return {X64Word} A new x64-Word object after negating.
         *
         * @example
         *
         *     var negated = x64Word.not();
         */
        // not: function () {
            // var high = ~this.high;
            // var low = ~this.low;

            // return X64Word.create(high, low);
        // },

        /**
         * Bitwise ANDs this word with the passed word.
         *
         * @param {X64Word} word The x64-Word to AND with this word.
         *
         * @return {X64Word} A new x64-Word object after ANDing.
         *
         * @example
         *
         *     var anded = x64Word.and(anotherX64Word);
         */
        // and: function (word) {
            // var high = this.high & word.high;
            // var low = this.low & word.low;

            // return X64Word.create(high, low);
        // },

        /**
         * Bitwise ORs this word with the passed word.
         *
         * @param {X64Word} word The x64-Word to OR with this word.
         *
         * @return {X64Word} A new x64-Word object after ORing.
         *
         * @example
         *
         *     var ored = x64Word.or(anotherX64Word);
         */
        // or: function (word) {
            // var high = this.high | word.high;
            // var low = this.low | word.low;

            // return X64Word.create(high, low);
        // },

        /**
         * Bitwise XORs this word with the passed word.
         *
         * @param {X64Word} word The x64-Word to XOR with this word.
         *
         * @return {X64Word} A new x64-Word object after XORing.
         *
         * @example
         *
         *     var xored = x64Word.xor(anotherX64Word);
         */
        // xor: function (word) {
            // var high = this.high ^ word.high;
            // var low = this.low ^ word.low;

            // return X64Word.create(high, low);
        // },

        /**
         * Shifts this word n bits to the left.
         *
         * @param {number} n The number of bits to shift.
         *
         * @return {X64Word} A new x64-Word object after shifting.
         *
         * @example
         *
         *     var shifted = x64Word.shiftL(25);
         */
        // shiftL: function (n) {
            // if (n < 32) {
                // var high = (this.high << n) | (this.low >>> (32 - n));
                // var low = this.low << n;
            // } else {
                // var high = this.low << (n - 32);
                // var low = 0;
            // }

            // return X64Word.create(high, low);
        // },

        /**
         * Shifts this word n bits to the right.
         *
         * @param {number} n The number of bits to shift.
         *
         * @return {X64Word} A new x64-Word object after shifting.
         *
         * @example
         *
         *     var shifted = x64Word.shiftR(7);
         */
        // shiftR: function (n) {
            // if (n < 32) {
                // var low = (this.low >>> n) | (this.high << (32 - n));
                // var high = this.high >>> n;
            // } else {
                // var low = this.high >>> (n - 32);
                // var high = 0;
            // }

            // return X64Word.create(high, low);
        // },

        /**
         * Rotates this word n bits to the left.
         *
         * @param {number} n The number of bits to rotate.
         *
         * @return {X64Word} A new x64-Word object after rotating.
         *
         * @example
         *
         *     var rotated = x64Word.rotL(25);
         */
        // rotL: function (n) {
            // return this.shiftL(n).or(this.shiftR(64 - n));
        // },

        /**
         * Rotates this word n bits to the right.
         *
         * @param {number} n The number of bits to rotate.
         *
         * @return {X64Word} A new x64-Word object after rotating.
         *
         * @example
         *
         *     var rotated = x64Word.rotR(7);
         */
        // rotR: function (n) {
            // return this.shiftR(n).or(this.shiftL(64 - n));
        // },

        /**
         * Adds this word with the passed word.
         *
         * @param {X64Word} word The x64-Word to add with this word.
         *
         * @return {X64Word} A new x64-Word object after adding.
         *
         * @example
         *
         *     var added = x64Word.add(anotherX64Word);
         */
        // add: function (word) {
            // var low = (this.low + word.low) | 0;
            // var carry = (low >>> 0) < (this.low >>> 0) ? 1 : 0;
            // var high = (this.high + word.high + carry) | 0;

            // return X64Word.create(high, low);
        // }
    });

    /**
     * An array of 64-bit words.
     *
     * @property {Array} words The array of CryptoJS.x64.Word objects.
     * @property {number} sigBytes The number of significant bytes in this word array.
     */
    var X64WordArray = C_x64.WordArray = Base.extend({
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.x64.WordArray.create();
         *
         *     var wordArray = CryptoJS.x64.WordArray.create([
         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
         *     ]);
         *
         *     var wordArray = CryptoJS.x64.WordArray.create([
         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
         *     ], 10);
         */
        init: function (words, sigBytes) {
            words = this.words = words || [];

            if (sigBytes != undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 8;
            }
        },

        /**
         * Converts this 64-bit word array to a 32-bit word array.
         *
         * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
         *
         * @example
         *
         *     var x32WordArray = x64WordArray.toX32();
         */
        toX32: function () {
            // Shortcuts
            var x64Words = this.words;
            var x64WordsLength = x64Words.length;

            // Convert
            var x32Words = [];
            for (var i = 0; i < x64WordsLength; i++) {
                var x64Word = x64Words[i];
                x32Words.push(x64Word.high);
                x32Words.push(x64Word.low);
            }

            return X32WordArray.create(x32Words, this.sigBytes);
        },

        /**
         * Creates a copy of this word array.
         *
         * @return {X64WordArray} The clone.
         *
         * @example
         *
         *     var clone = x64WordArray.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);

            // Clone "words" array
            var words = clone.words = this.words.slice(0);

            // Clone each X64Word object
            var wordsLength = words.length;
            for (var i = 0; i < wordsLength; i++) {
                words[i] = words[i].clone();
            }

            return clone;
        }
    });
}());
(function (Math) {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;
    var Hasher = C_lib.Hasher;
    var C_algo = C.algo;

    // Initialization and round constants tables
    var H = [];
    var K = [];

    // Compute constants
    (function () {
        function isPrime(n) {
            var sqrtN = Math.sqrt(n);
            for (var factor = 2; factor <= sqrtN; factor++) {
                if (!(n % factor)) {
                    return false;
                }
            }

            return true;
        }

        function getFractionalBits(n) {
            return ((n - (n | 0)) * 0x100000000) | 0;
        }

        var n = 2;
        var nPrime = 0;
        while (nPrime < 64) {
            if (isPrime(n)) {
                if (nPrime < 8) {
                    H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
                }
                K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

                nPrime++;
            }

            n++;
        }
    }());

    // Reusable object
    var W = [];

    /**
     * SHA-256 hash algorithm.
     */
    var SHA256 = C_algo.SHA256 = Hasher.extend({
        _doReset: function () {
            this._hash = new WordArray.init(H.slice(0));
        },

        _doProcessBlock: function (M, offset) {
            // Shortcut
            var H = this._hash.words;

            // Working variables
            var a = H[0];
            var b = H[1];
            var c = H[2];
            var d = H[3];
            var e = H[4];
            var f = H[5];
            var g = H[6];
            var h = H[7];

            // Computation
            for (var i = 0; i < 64; i++) {
                if (i < 16) {
                    W[i] = M[offset + i] | 0;
                } else {
                    var gamma0x = W[i - 15];
                    var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
                                  ((gamma0x << 14) | (gamma0x >>> 18)) ^
                                   (gamma0x >>> 3);

                    var gamma1x = W[i - 2];
                    var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
                                  ((gamma1x << 13) | (gamma1x >>> 19)) ^
                                   (gamma1x >>> 10);

                    W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
                }

                var ch  = (e & f) ^ (~e & g);
                var maj = (a & b) ^ (a & c) ^ (b & c);

                var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
                var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

                var t1 = h + sigma1 + ch + K[i] + W[i];
                var t2 = sigma0 + maj;

                h = g;
                g = f;
                f = e;
                e = (d + t1) | 0;
                d = c;
                c = b;
                b = a;
                a = (t1 + t2) | 0;
            }

            // Intermediate hash value
            H[0] = (H[0] + a) | 0;
            H[1] = (H[1] + b) | 0;
            H[2] = (H[2] + c) | 0;
            H[3] = (H[3] + d) | 0;
            H[4] = (H[4] + e) | 0;
            H[5] = (H[5] + f) | 0;
            H[6] = (H[6] + g) | 0;
            H[7] = (H[7] + h) | 0;
        },

        _doFinalize: function () {
            // Shortcuts
            var data = this._data;
            var dataWords = data.words;

            var nBitsTotal = this._nDataBytes * 8;
            var nBitsLeft = data.sigBytes * 8;

            // Add padding
            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
            data.sigBytes = dataWords.length * 4;

            // Hash final blocks
            this._process();

            // Return final computed hash
            return this._hash;
        },

        clone: function () {
            var clone = Hasher.clone.call(this);
            clone._hash = this._hash.clone();

            return clone;
        }
    });

    /**
     * Shortcut function to the hasher's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     *
     * @return {WordArray} The hash.
     *
     * @static
     *
     * @example
     *
     *     var hash = CryptoJS.SHA256('message');
     *     var hash = CryptoJS.SHA256(wordArray);
     */
    C.SHA256 = Hasher._createHelper(SHA256);

    /**
     * Shortcut function to the HMAC's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     * @param {WordArray|string} key The secret key.
     *
     * @return {WordArray} The HMAC.
     *
     * @static
     *
     * @example
     *
     *     var hmac = CryptoJS.HmacSHA256(message, key);
     */
    C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
}(Math));
/* Simple emulation of subtle crypto using crypto-js */
window.crypto.subtle = {};
window.crypto.subtle.digest = function(alg, msg) {
    var hasher = CryptoJS.algo.SHA256.create();
    msg = new Uint8Array(msg);
    msg = [...msg].map(x => x.toString(16).padStart(2, '0')).join('');
    msg = CryptoJS.enc.Hex.parse(msg);
    hasher.update(msg);
    var ret = hasher.finalize().toString()
    ret = new Uint8Array(ret.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    return ret;
}

var HexToDec = function(hex) {
    return BigInt('0x'.concat(hex)).toString(10);
}

var HexToBytes = function(hex) {
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}

var SetDST = function(dst) {
    dst = HexToBytes(dst);
    var ret = '';
    for (var i = 0; i < dst.length; i++) {
        if ( dst[i] >= 128 ) {
            return false;
        }
        ret += String.fromCharCode(dst[i]);
    }

    try {
        exports.utils.setDSTLabel(ret);
    } catch ( e ) {
        return false;
    }

    return true;
}

var To_G1 = function(x, y) {
    var x = BigInt(x);
    var y = BigInt(y);
    return new exports.PointG1(new Fp(x), new Fp(y), new Fp(1n));
}

var From_G1 = function(g1) {
    var affine = g1.toAffine();

    var x = affine[0].value.toString(10);
    var y = affine[1].value.toString(10);

    return [x, y];
}

var To_G2 = function(x, y, v, w) {
    var x1 = BigInt(v);
    var y1 = BigInt(w);
    var x2 = BigInt(x);
    var y2 = BigInt(y);
    return new exports.PointG2(new Fp2([x1, y1]), new Fp2([x2, y2]), Fp2.ONE);
}

var From_G2 = function(g2) {
    var affine = g2.toAffine();

    var x1 = affine[0].values[0].toString(10);
    var y1 = affine[1].values[0].toString(10);
    var x2 = affine[0].values[1].toString(10);
    var y2 = affine[1].values[1].toString(10);

    return [ [x1, y1], [x2, y2] ];
}

var OpBLS_PrivateToPublic = function(FuzzerInput) {
    var priv = BigInt(FuzzerInput['priv']);

    try {
        var pub = exports.getPublicKey(priv);
        pub = exports.PointG1.fromHex(pub);

        FuzzerOutput = JSON.stringify([pub.x.value.toString(), pub.y.value.toString()]);
    } catch ( e ) { }
}

var OpBLS_HashToG1 = async function(FuzzerInput) {
    /* XXX unsupported? */
    return;
}

var OpBLS_HashToG2 = async function(FuzzerInput) {
    if ( SetDST(FuzzerInput['dest']) == false ) {
        return;
    }

    try {
        var msg = FuzzerInput['aug'] + FuzzerInput['cleartext'];

        var res = await exports.PointG2.hashToCurve(msg);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { console.log(e); }
}

var OpBLS_Sign = async function(FuzzerInput) {
    if ( SetDST(FuzzerInput['dest']) == false ) {
        return;
    }

    var msg;
    if ( FuzzerInput['hashOrPoint'] == true ) {
        msg = FuzzerInput['aug'] + FuzzerInput['cleartext'];
    } else {
        msg = To_G2(FuzzerInput['g2_v'], FuzzerInput['g2_x'], FuzzerInput['g2_w'], FuzzerInput['g2_y']);
    }

    var priv = BigInt(FuzzerInput['priv']);

    try {
        var pub = exports.getPublicKey(priv);
        pub = exports.PointG1.fromHex(pub);

        var signature = await exports.sign(msg, priv);

        if ( FuzzerInput['hashOrPoint'] == true ) {
            signature = exports.PointG2.fromSignature(signature);
        }

        var affine = signature.toAffine();

        var x1 = affine[0].values[0].toString(10);
        var y1 = affine[1].values[0].toString(10);
        var x2 = affine[0].values[1].toString(10);
        var y2 = affine[1].values[1].toString(10);

        FuzzerOutput = JSON.stringify({
            'signature' : [
                [x1, y1], [x2, y2]
            ],
            'pub' : [
                pub.x.value.toString(),
                pub.y.value.toString()]
        });
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_Verify = async function(FuzzerInput) {
    if ( SetDST(FuzzerInput['dest']) == false ) {
        return;
    }

    try {
        var pub = To_G1(FuzzerInput['g1_x'], FuzzerInput['g1_y']);
        var sig = To_G2(FuzzerInput['g2_w'], FuzzerInput['g2_y'], FuzzerInput['g2_v'], FuzzerInput['g2_x']);
        var msg = FuzzerInput['cleartext'];

        var res = await exports.verify(sig, msg, pub);

        FuzzerOutput = JSON.stringify(res);
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_Compress_G1 = async function(FuzzerInput) {
    var g1 = To_G1(FuzzerInput['g1_x'], FuzzerInput['g1_y']);

    try {
        g1.assertValidity();
    } catch ( e ) {
        return;
    }

    var compressed = g1.toHex(true);
    compressed = HexToDec(compressed);

    FuzzerOutput = JSON.stringify(compressed);
}

var OpBLS_Decompress_G1 = async function(FuzzerInput) {
    var compressed = BigInt(FuzzerInput['compressed']).toString(16);
    if ( compressed.length > 96 ) {
        return;
    }

    compressed = '0'.repeat(96 - compressed.length) + compressed;

    var g1 = exports.PointG1.fromHex(compressed);

    try {
        g1.assertValidity();
    } catch ( e ) {
        return;
    }

    return; /* XXX */
    FuzzerOutput = JSON.stringify(From_G1(g1));
}

var OpBLS_Compress_G2 = async function(FuzzerInput) {
    /* XXX not implemented by noble-bls12-381 */
}

var OpBLS_Decompress_G2 = async function(FuzzerInput) {
    var x = BigInt(FuzzerInput['g1_x']).toString(16);
    if ( x.length > 96 ) {
        return;
    }
    x = '0'.repeat(96 - x.length) + x;

    var y = BigInt(FuzzerInput['g1_y']).toString(16);
    if ( y.length > 96 ) {
        return;
    }
    y = '0'.repeat(96 - y.length) + y;

    var compressed = x + y;

    var g2 = exports.PointG2.fromHex(compressed);

    try {
        g2.assertValidity();
    } catch ( e ) {
        return;
    }

    FuzzerOutput = JSON.stringify(From_G2(g2));
}

var OpBLS_IsG1OnCurve = async function(FuzzerInput) {
    var a = To_G1(FuzzerInput['g1_x'], FuzzerInput['g1_y']);
    var res = true;

    try {
        a.assertValidity();
    } catch ( e ) {
        res = false;
    }

    FuzzerOutput = JSON.stringify(res);
}

var OpBLS_IsG2OnCurve = async function(FuzzerInput) {
    var a = To_G2(FuzzerInput['g2_w'], FuzzerInput['g2_y'], FuzzerInput['g2_v'], FuzzerInput['g2_x']);
    var res = true;

    try {
        a.assertValidity();
    } catch ( e ) {
        res = false;
    }

    FuzzerOutput = JSON.stringify(res);
}

var OpBLS_G1_Add = async function(FuzzerInput) {
    try {
        var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
        a.assertValidity();

        var b = To_G1(FuzzerInput['b_x'], FuzzerInput['b_y']);
        b.assertValidity();

        var res = a.add(b);

        FuzzerOutput = JSON.stringify(From_G1(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G1_Mul = async function(FuzzerInput) {
    try {
        var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
        a.assertValidity();

        var b = BigInt(FuzzerInput['b']);

        var res = a.multiply(b);

        FuzzerOutput = JSON.stringify(From_G1(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G1_Neg = async function(FuzzerInput) {
    try {
        var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
        a.assertValidity();

        var res = a.negate(b);

        FuzzerOutput = JSON.stringify(From_G1(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G1_IsEq = async function(FuzzerInput) {
    try {
        var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
        var b = To_G1(FuzzerInput['b_x'], FuzzerInput['b_y']);

        var res = a.equals(b);

        FuzzerOutput = JSON.stringify(res);
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G2_Add = async function(FuzzerInput) {
    try {
        var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
        a.assertValidity();

        var b = To_G2(FuzzerInput['b_w'], FuzzerInput['b_y'], FuzzerInput['b_v'], FuzzerInput['b_x']);
        b.assertValidity();

        var res = a.add(b);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G2_Mul = async function(FuzzerInput) {
    try {
        var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
        a.assertValidity();

        var b = BigInt(FuzzerInput['b']);

        var res = a.multiply(b);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G2_Neg = async function(FuzzerInput) {
    try {
        var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
        a.assertValidity();

        var res = a.negate(b);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G2_IsEq = async function(FuzzerInput) {
    try {
        var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
        var b = To_G2(FuzzerInput['b_w'], FuzzerInput['b_y'], FuzzerInput['b_v'], FuzzerInput['b_x']);

        var res = a.equals(b);

        FuzzerOutput = JSON.stringify(res);
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_Aggregate_G1 = async function(FuzzerInput) {
    try {
        var points = [];
        for (var i = 0; i < FuzzerInput['points'].length; i++) {
            var point = To_G1(
                FuzzerInput['points'][i]['x'],
                FuzzerInput['points'][i]['y']);
            points.push(point);
        }

        var res = aggregatePublicKeys(points);

        FuzzerOutput = JSON.stringify(From_G1(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_Aggregate_G2 = async function(FuzzerInput) {
    try {
        var points = [];
        for (var i = 0; i < FuzzerInput['points'].length; i++) {
            var point = To_G2(
                FuzzerInput['points'][i]['w'],
                FuzzerInput['points'][i]['y'],
                FuzzerInput['points'][i]['v'],
                FuzzerInput['points'][i]['x']);
            points.push(point);
        }

        var res = aggregateSignatures(points);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBignumCalc = async function(FuzzerInput, Fx) {
    var calcOp = BigInt(FuzzerInput["calcOp"]);

    var bn1 = new Fx(BigInt(FuzzerInput['bn0']));
    var bn2 = new Fx(BigInt(FuzzerInput['bn1']));

    var res;

    if ( IsAdd(calcOp) ) {
        res = bn1.add(bn2);
    } else if ( IsSub(calcOp) ) {
        res = bn1.subtract(bn2);
    } else if ( IsMul(calcOp) ) {
        res = bn1.multiply(bn2);
    } else if ( IsDiv(calcOp) ) {
        res = bn1.div(bn2);
    } else if ( IsSqr(calcOp) ) {
        res = bn1.square();
    } else if ( IsInvMod(calcOp) ) {
        res = bn1.invert();
    } else if ( IsSqrt(calcOp) ) {
        res = bn1.sqrt();
        if (typeof res === "undefined") {
            res = new Fx(0n);
        } else {
            res = res.square();
        }
    } else if ( IsJacobi(calcOp) ) {
        res = bn1.legendre();
    } else if ( IsNeg(calcOp) ) {
        res = bn1.negate();
    } else if ( IsIsEq(calcOp) ) {
        res = bn1.equals(bn2);
    } else if ( IsIsZero(calcOp) ) {
        res = bn1.isZero();
    } else {
        return;
    }

    res = res.value.toString(10);
    FuzzerOutput = JSON.stringify(res);
}

FuzzerInput = JSON.parse(FuzzerInput);
var operation = BigInt(FuzzerInput['operation']);

if ( IsBLS_PrivateToPublic(operation) ) {
    OpBLS_PrivateToPublic(FuzzerInput);
} else if ( IsBLS_HashToG1(operation) ) {
    OpBLS_HashToG1(FuzzerInput);
} else if ( IsBLS_HashToG2(operation) ) {
    OpBLS_HashToG2(FuzzerInput);
} else if ( IsBLS_Sign(operation) ) {
    OpBLS_Sign(FuzzerInput);
} else if ( IsBLS_Verify(operation) ) {
    OpBLS_Verify(FuzzerInput);
} else if ( IsBLS_Compress_G1(operation) ) {
    OpBLS_Compress_G1(FuzzerInput);
} else if ( IsBLS_Decompress_G1(operation) ) {
    OpBLS_Decompress_G1(FuzzerInput);
} else if ( IsBLS_Compress_G2(operation) ) {
    OpBLS_Compress_G2(FuzzerInput);
} else if ( IsBLS_Decompress_G2(operation) ) {
    OpBLS_Decompress_G2(FuzzerInput);
} else if ( IsBLS_IsG1OnCurve(operation) ) {
    OpBLS_IsG1OnCurve(FuzzerInput);
} else if ( IsBLS_IsG2OnCurve(operation) ) {
    OpBLS_IsG2OnCurve(FuzzerInput);
} else if ( IsBLS_G1_Add(operation) ) {
    OpBLS_G1_Add(FuzzerInput);
} else if ( IsBLS_G1_Mul(operation) ) {
    OpBLS_G1_Mul(FuzzerInput);
} else if ( IsBLS_G1_Neg(operation) ) {
    OpBLS_G1_Neg(FuzzerInput);
} else if ( IsBLS_G1_IsEq(operation) ) {
    OpBLS_G1_IsEq(FuzzerInput);
} else if ( IsBLS_G2_Add(operation) ) {
    OpBLS_G2_Add(FuzzerInput);
} else if ( IsBLS_G2_Mul(operation) ) {
    OpBLS_G2_Mul(FuzzerInput);
} else if ( IsBLS_G2_Neg(operation) ) {
    OpBLS_G2_Neg(FuzzerInput);
} else if ( IsBLS_G2_IsEq(operation) ) {
    OpBLS_G2_IsEq(FuzzerInput);
} else if ( IsBLS_Aggregate_G1(operation) ) {
    OpBLS_Aggregate_G1(FuzzerInput);
} else if ( IsBLS_Aggregate_G2(operation) ) {
    OpBLS_Aggregate_G2(FuzzerInput);
} else if ( IsBignumCalc_Mod_BLS12_381_P(operation) ) {
    OpBignumCalc(FuzzerInput, exports.Fp);
} else if ( IsBignumCalc_Mod_BLS12_381_R(operation) ) {
    OpBignumCalc(FuzzerInput, exports.Fr);
}
