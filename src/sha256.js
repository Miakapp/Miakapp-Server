/* eslint-disable no-bitwise */
module.exports = function sha256(asciiIn) {
  const rRotate = (value, amount) => (value >>> amount) | (value << (32 - amount));

  const maxWord = 2 ** 32;
  let i; let j;
  let result = '';

  const words = [];
  const asciiBitLength = asciiIn.length * 8;

  const k = [];
  let hash = [];
  let pCount = 0;

  const isComposite = {};
  for (let cdt = 2; pCount < 64; cdt += 1) {
    if (!isComposite[cdt]) {
      for (i = 0; i < 313; i += cdt) isComposite[i] = cdt;
      hash[pCount] = ((cdt ** 0.5) * maxWord) | 0;
      k[(pCount += 1) - 1] = ((cdt ** (1 / 3)) * maxWord) | 0;
    }
  }

  let ascii = `${asciiIn}\x80`;

  while ((ascii.length % 64) - 56) ascii += '\x00';
  for (i = 0; i < ascii.length; i += 1) {
    j = ascii.charCodeAt(i);
    if (j >> 8) return '';
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }

  words[words.length] = ((asciiBitLength / maxWord) | 0);
  words[words.length] = (asciiBitLength);

  for (j = 0; j < words.length;) {
    const w = words.slice(j, j += 16);
    const oldHash = hash;

    hash = hash.slice(0, 8);

    for (i = 0; i < 64; i += 1) {
      const w15 = w[i - 15];
      const w2 = w[i - 2];
      const a = hash[0];
      const e = hash[4];
      const temp1 = hash[7]
        + (rRotate(e, 6) ^ rRotate(e, 11) ^ rRotate(e, 25))
        + ((e & hash[5]) ^ ((~e) & hash[6]))
        + k[i]
        + (w[i] = (i < 16) ? w[i] : (
          w[i - 16]
            + (rRotate(w15, 7) ^ rRotate(w15, 18) ^ (w15 >>> 3))
            + w[i - 7]
            + (rRotate(w2, 17) ^ rRotate(w2, 19) ^ (w2 >>> 10))
        ) | 0
        );
      const temp2 = (rRotate(a, 2) ^ rRotate(a, 13) ^ rRotate(a, 22))
        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }

    for (i = 0; i < 8; i += 1) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }

  for (i = 0; i < 8; i += 1) {
    for (j = 3; j + 1; j -= 1) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += ((b < 16) ? 0 : '') + b.toString(16);
    }
  }

  return result;
};
