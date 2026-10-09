//! Port of tfjs-core `fingerPrint64` (hash_util.ts), must stay bit-identical to it.

const K0: u64 = 0xc3a5c85c97cb3127;
const K1: u64 = 0xb492b66fbe98f273;
const K2: u64 = 0x9ae16a3b2f90404f;

fn shift_mix(val: u64) -> u64 {
	val ^ (val >> 47)
}

fn fetch64(s: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(s[offset..offset + 8].try_into().unwrap())
}

fn fetch32(s: &[u8], offset: usize) -> u64 {
	u64::from(u32::from_le_bytes(
		s[offset..offset + 4].try_into().unwrap(),
	))
}

fn rotate64(val: u64, shift: u32) -> u64 {
	val.rotate_right(shift)
}

fn hash_len16(u: u64, v: u64, mul: u64) -> u64 {
	let mut a = (u ^ v).wrapping_mul(mul);
	a ^= a >> 47;
	let mut b = (v ^ a).wrapping_mul(mul);
	b ^= b >> 47;
	b.wrapping_mul(mul)
}

fn weak_hash_len32_with_seeds(
	w: u64,
	x: u64,
	y: u64,
	z: u64,
	mut a: u64,
	mut b: u64,
) -> (u64, u64) {
	a = a.wrapping_add(w);
	b = rotate64(b.wrapping_add(a).wrapping_add(z), 21);
	let c = a;
	a = a.wrapping_add(x);
	a = a.wrapping_add(y);
	b = b.wrapping_add(rotate64(a, 44));
	(a.wrapping_add(z), b.wrapping_add(c))
}

fn weak_hash_len32_with_seeds_str(s: &[u8], offset: usize, a: u64, b: u64) -> (u64, u64) {
	weak_hash_len32_with_seeds(
		fetch64(s, offset),
		fetch64(s, offset + 8),
		fetch64(s, offset + 16),
		fetch64(s, offset + 24),
		a,
		b,
	)
}

fn hash_len0to16(s: &[u8]) -> u64 {
	let len = s.len();
	if len >= 8 {
		let mul = K2.wrapping_add(len as u64 * 2);
		let a = fetch64(s, 0).wrapping_add(K2);
		let b = fetch64(s, len - 8);
		let c = rotate64(b, 37).wrapping_mul(mul).wrapping_add(a);
		let d = rotate64(a, 25).wrapping_add(b).wrapping_mul(mul);
		return hash_len16(c, d, mul);
	}
	if len >= 4 {
		let mul = K2.wrapping_add(len as u64 * 2);
		let a = fetch32(s, 0);
		return hash_len16((a << 3).wrapping_add(len as u64), fetch32(s, len - 4), mul);
	}
	if len > 0 {
		let a = u64::from(s[0]);
		let b = u64::from(s[len >> 1]);
		let c = u64::from(s[len - 1]);
		let y = a + (b << 8);
		let z = len as u64 + (c << 2);
		return shift_mix(K2.wrapping_mul(y) ^ K0.wrapping_mul(z)).wrapping_mul(K2);
	}
	K2
}

fn hash_len17to32(s: &[u8]) -> u64 {
	let len = s.len();
	let mul = K2.wrapping_add(len as u64 * 2);
	let a = fetch64(s, 0).wrapping_mul(K1);
	let b = fetch64(s, 8);
	let c = fetch64(s, len - 8).wrapping_mul(mul);
	let d = fetch64(s, len - 16).wrapping_mul(K2);
	hash_len16(
		rotate64(a.wrapping_add(b), 43)
			.wrapping_add(rotate64(c, 30))
			.wrapping_add(d),
		a.wrapping_add(rotate64(b.wrapping_add(K2), 18))
			.wrapping_add(c),
		mul,
	)
}

fn hash_len33to64(s: &[u8]) -> u64 {
	let len = s.len();
	let mul = K2.wrapping_add(len as u64 * 2);
	let a = fetch64(s, 0).wrapping_mul(K2);
	let b = fetch64(s, 8);
	let c = fetch64(s, len - 8).wrapping_mul(mul);
	let d = fetch64(s, len - 16).wrapping_mul(K2);
	let y = rotate64(a.wrapping_add(b), 43)
		.wrapping_add(rotate64(c, 30))
		.wrapping_add(d);
	let z = hash_len16(
		y,
		a.wrapping_add(rotate64(b.wrapping_add(K2), 18))
			.wrapping_add(c),
		mul,
	);
	let e = fetch64(s, 16).wrapping_mul(mul);
	let f = fetch64(s, 24);
	let g = y.wrapping_add(fetch64(s, len - 32)).wrapping_mul(mul);
	let h = z.wrapping_add(fetch64(s, len - 24)).wrapping_mul(mul);
	hash_len16(
		rotate64(e.wrapping_add(f), 43)
			.wrapping_add(rotate64(g, 30))
			.wrapping_add(h),
		e.wrapping_add(rotate64(f.wrapping_add(a), 18))
			.wrapping_add(g),
		mul,
	)
}

pub fn fingerprint64(s: &[u8]) -> u64 {
	let len = s.len();
	let seed: u64 = 81;
	if len <= 32 {
		if len <= 16 {
			return hash_len0to16(s);
		}
		return hash_len17to32(s);
	} else if len <= 64 {
		return hash_len33to64(s);
	}

	let mut x = seed;
	let mut y = seed.wrapping_mul(K1).wrapping_add(113);
	let mut z = shift_mix(y.wrapping_mul(K2).wrapping_add(113)).wrapping_mul(K2);
	let mut v = (0u64, 0u64);
	let mut w = (0u64, 0u64);
	x = x.wrapping_mul(K2).wrapping_add(fetch64(s, 0));

	let mut offset = 0usize;
	let end = ((len - 1) >> 6) * 64;
	let last64 = end + ((len - 1) & 63) - 63;

	loop {
		x = rotate64(
			x.wrapping_add(y)
				.wrapping_add(v.0)
				.wrapping_add(fetch64(s, offset + 8)),
			37,
		)
		.wrapping_mul(K1);
		y = rotate64(
			y.wrapping_add(v.1).wrapping_add(fetch64(s, offset + 48)),
			42,
		)
		.wrapping_mul(K1);
		x ^= w.1;
		y = y.wrapping_add(v.0).wrapping_add(fetch64(s, offset + 40));
		z = rotate64(z.wrapping_add(w.0), 33).wrapping_mul(K1);
		v = weak_hash_len32_with_seeds_str(s, offset, v.1.wrapping_mul(K1), x.wrapping_add(w.0));
		w = weak_hash_len32_with_seeds_str(
			s,
			offset + 32,
			z.wrapping_add(w.1),
			y.wrapping_add(fetch64(s, offset + 16)),
		);
		std::mem::swap(&mut z, &mut x);
		offset += 64;
		if offset == end {
			break;
		}
	}

	let mul = K1.wrapping_add((z & 0xff) << 1);
	offset = last64;

	w.0 = w.0.wrapping_add(((len - 1) & 63) as u64);
	v.0 = v.0.wrapping_add(w.0);
	w.0 = w.0.wrapping_add(v.0);

	x = rotate64(
		x.wrapping_add(y)
			.wrapping_add(v.0)
			.wrapping_add(fetch64(s, offset + 8)),
		37,
	)
	.wrapping_mul(mul);
	y = rotate64(
		y.wrapping_add(v.1).wrapping_add(fetch64(s, offset + 48)),
		42,
	)
	.wrapping_mul(mul);
	x ^= w.1.wrapping_mul(9);
	y = y.wrapping_add(v.0.wrapping_mul(9).wrapping_add(fetch64(s, offset + 40)));
	z = rotate64(z.wrapping_add(w.0), 33).wrapping_mul(mul);
	v = weak_hash_len32_with_seeds_str(s, offset, v.1.wrapping_mul(mul), x.wrapping_add(w.0));
	w = weak_hash_len32_with_seeds_str(
		s,
		offset + 32,
		z.wrapping_add(w.1),
		y.wrapping_add(fetch64(s, offset + 16)),
	);
	std::mem::swap(&mut z, &mut x);

	hash_len16(
		hash_len16(v.0, w.0, mul)
			.wrapping_add(shift_mix(y).wrapping_mul(K0))
			.wrapping_add(z),
		hash_len16(v.1, w.1, mul).wrapping_add(x),
		mul,
	)
}

/// `tf.string.stringToHashBucketFast` for a single token
pub fn hash_bucket(token: &str, num_buckets: u64) -> usize {
	(fingerprint64(token.as_bytes()) % num_buckets) as usize
}
