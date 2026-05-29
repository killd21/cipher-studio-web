import { describe, it, expect } from 'vitest';
import { hmac, cmacAes, desMac, desMacAlg2, desMacAlg4, desTdesMac, retailMac } from '../../src/crypto/mac.ts';
import { ecbEncrypt } from '../../src/crypto/des.ts';

// MAC algorithms — RFC 2104 (HMAC) · RFC 4493 (AES-CMAC) · ISO/IEC 9797-1 (DES MAC algorithms).

describe('HMAC (RFC 2104)', () => {
  it('HMAC-SHA256 — "key" + "The quick brown fox..."', () => {
    const key = '6b6579';
    const data = '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67';
    expect(hmac('sha256', key, data)).toBe('F7BC83F430538424B13298E6AA6FB143EF4D59A14946175997479DBC2D1A3CD8');
  });
});

describe('AES-CMAC (RFC 4493)', () => {
  it('empty message', () => {
    expect(cmacAes('2b7e151628aed2a6abf7158809cf4f3c', '')).toBe('BB1D6929E95937287FA37D129B756746');
  });
  it('16-byte message', () => {
    expect(cmacAes('2b7e151628aed2a6abf7158809cf4f3c', '6bc1bee22e409f96e93d7e117393172a'))
      .toBe('070A16B46B4D4144F79BDD9DD04A287C');
  });
});

describe('DES MAC — ISO 9797-1 Algorithm 1 (basic CBC-MAC)', () => {
  it('1-block CBC-MAC equals ECB encrypt', () => {
    const key = '0123456789ABCDEF';
    const data = '1122334455667788';
    const res = desMac(key, data, '0000000000000000', 8, 'none');
    expect(res).toBe(ecbEncrypt(key, data));
  });
});

describe('DES MAC — ISO 9797-1 Algorithm 2 (OT1: E_K\'(Hn))', () => {
  const msg = '0001020304050607' + '08090A0B0C0D0E0F' + '10';
  const iv = '0000000000000000';

  it('produces 8-byte output for 16-byte key', () => {
    const key = '0123456789ABCDEFFEDCBA9876543210';
    expect(desMacAlg2(key, msg, iv, 'iso9797m2').length).toBe(16);
  });

  it('accepts 8-byte key (auto KDM2 derivation)', () => {
    expect(desMacAlg2('0123456789ABCDEF', msg, iv, 'iso9797m2').length).toBe(16);
  });

  it('rejects malformed key (6 bytes)', () => {
    expect(() => desMacAlg2('001122334455', msg, iv, 'iso9797m2')).toThrow();
  });

  it('structural: K=K\' → equals E_K(Alg1_output)', () => {
    const k = '0123456789ABCDEF';
    const keyDouble = k + k;
    const alg1 = desMac(k, msg, iv, 8, 'iso9797m2');
    const expected = ecbEncrypt(k, alg1);
    expect(desMacAlg2(keyDouble, msg, iv, 'iso9797m2')).toBe(expected);
  });

  it('differs from Algorithm 1 when K != K\'', () => {
    const key = '11223344556677880011223344556677';
    const alg1 = desMac(key.substring(0, 16), msg, iv, 8, 'iso9797m2');
    expect(desMacAlg2(key, msg, iv, 'iso9797m2')).not.toBe(alg1);
  });
});

describe('DES MAC — ISO 9797-1 Algorithm 3 (Retail MAC, OT3)', () => {
  it('produces 16-hex (8-byte) output', () => {
    const res = retailMac('0123456789ABCDEF0123456789ABCDEF', '1122334455667788', '0000000000000000', 'none');
    expect(res.length).toBe(16);
  });

  it('desTdesMac accepts 16-byte and 24-byte keys', () => {
    const msg = '1122334455667788';
    const iv = '0000000000000000';
    expect(desTdesMac('0123456789ABCDEFFEDCBA9876543210', msg, iv, 'iso9797m2').length).toBe(16);
    expect(desTdesMac('0123456789ABCDEFFEDCBA98765432100123456789ABCDEF', msg, iv, 'iso9797m2').length).toBe(16);
  });
});

describe('DES MAC — ISO 9797-1 Algorithm 4 (OT2: E_K\'(D_K(Hn)))', () => {
  const msg = '0001020304050607' + '08090A0B0C0D0E0F' + '10';
  const iv = '0000000000000000';

  it('produces 8-byte output for 16-byte key', () => {
    const key = '0123456789ABCDEFFEDCBA9876543210';
    expect(desMacAlg4(key, msg, iv, 'iso9797m2').length).toBe(16);
  });

  it('accepts 8-byte key (auto KDM2 derivation)', () => {
    expect(desMacAlg4('0123456789ABCDEF', msg, iv, 'iso9797m2').length).toBe(16);
  });

  it('rejects malformed key (6 bytes)', () => {
    expect(() => desMacAlg4('001122334455', msg, iv, 'iso9797m2')).toThrow();
  });

  it('structural: K=K\' → degenerates to Algorithm 1', () => {
    const k = '0123456789ABCDEF';
    const keyDouble = k + k;
    const alg1 = desMac(k, msg, iv, 8, 'iso9797m2');
    expect(desMacAlg4(keyDouble, msg, iv, 'iso9797m2')).toBe(alg1);
  });

  it('differs from Algorithm 3 when K != K\'', () => {
    const key = '11223344556677880011223344556677';
    const alg3 = desTdesMac(key, msg, iv, 'iso9797m2');
    expect(desMacAlg4(key, msg, iv, 'iso9797m2')).not.toBe(alg3);
  });
});

describe('Algorithm 1, 2, 3, 4 cross-comparison', () => {
  it('all four produce distinct outputs when K != K\'', () => {
    const key = '11223344556677880011223344556677';
    const k1 = key.substring(0, 16);
    const msg = '0001020304050607080910';
    const iv = '0000000000000000';
    const set = new Set([
      desMac(k1, msg, iv, 8, 'iso9797m2'),
      desMacAlg2(key, msg, iv, 'iso9797m2'),
      desTdesMac(key, msg, iv, 'iso9797m2'),
      desMacAlg4(key, msg, iv, 'iso9797m2'),
    ]);
    expect(set.size).toBe(4);
  });
});

// ═══════════════════════════════════════════════════════════════
// HMAC-SHA2 official vectors — NIST CAVS 11.0 (HMAC_SHA2.txt)
// Full HMAC output is truncated to Tlen bytes for comparison.
// ═══════════════════════════════════════════════════════════════

function truncatedHmac(alg: string, key: string, msg: string, tlen: number): string {
  return hmac(alg, key, msg).substring(0, tlen * 2).toUpperCase();
}

describe('HMAC-SHA-1 CAVS [L=20]', () => {
  it('Count=0 Tlen=10', () => {
    expect(truncatedHmac('sha1',
      '82f3b69a1bff4de15c33',
      'fcd6d98bef45ed6850806e96f255fa0c8114b72873abe8f43c10bea7c1df706f10458e6d4e1c9201f057b8492fa10fe4b541d0fc9d41ef839acff1bc76e3fdfebf2235b5bd0347a9a6303e83152f9f8db941b1b94a8a1ce5c273b55dc94d99a171377969234134e7dad1ab4c8e46d18df4dc016764cf95a11ac4b491a2646be1',
      10,
    )).toBe('1BA0E66CF72EFC349207');
  });
  it('Count=1 Tlen=10', () => {
    expect(truncatedHmac('sha1',
      '4766e6fe5dffc98a5c50',
      'd68b828a153f5198c005ee36c0af2ff92e84907517f01d9b7c7993469df5c21078fa356a8c9715ece2414be94e10e547f32cbb8d0582523ed3bb0066046e51722094aa44533d2c876e82db402fbb00a6c2f2cc3487973dfc1674463e81e42a39d9402941f39b5e126bafe864ea1648c0a5be0a912697a87e4f8eabf79cbf130e',
      10,
    )).toBe('007E4504041A12F9E345');
  });
  it('Count=47 Tlen=20 (full output)', () => {
    expect(truncatedHmac('sha1',
      'aa6197d4afd5eef5187a',
      '9f3360cf8f5465c7d24d7cbd7bef00315cd4f4ac29f245f6db714e8853baa14440d1056442e4bbb1502406f557d3eab2239e3314832eb925a8fae340cf5f6ac820f25f19d51570bf9ec867e744c2f3128dc1ab11611e502d2aa452a681a2965f063f77d78f0e0b5b86e2a77a8ce4a5ba62e264890aea91762918a5a1b0acaf70',
      20,
    )).toBe('3745829991354A1EB42277BB9AFF04AB2ABCAA47');
  });
});

describe('HMAC-SHA-256 CAVS [L=32]', () => {
  it('Count=0 Tlen=16', () => {
    expect(truncatedHmac('sha256',
      '6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb5df95febbdd61236f33245',
      '752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0970ef73f918f675945a9aefe26daea27587e8dc909dd56fd0468805f834039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c3720570b58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a2759f82a54c41ccd7b5f592b',
      16,
    )).toBe('05D1243E6465ED9620C9AEC1C351A186');
  });
  it('Count=33 Tlen=32 (full output)', () => {
    expect(truncatedHmac('sha256',
      '5448998f9d8f98534addf0c8ba631c496bf8a8006cbb46ad15fa1fa2f55367120c19348c3afa90c3',
      '1c4396f7b7f9228e832a13692002ba2aff439dcb7fddbfd456c022d133ee8903a2d482562fdaa493ce3916d77a0c51441dab26f6b0340238a36a71f87fc3e179cabca9482b704971ce69f3f20ab64b70413d6c2908532b2a888a9fc224cae1365da410b6f2e298904b63b4a41726321835a4774dd063c211cfc8b5166c2d11a2',
      32,
    )).toBe('7E8CBA9DD9F06EBDD7F92E0F1A67C7F4DF52693C212BDD84F67370B351533C6C');
  });
  it('Count=91 Tlen=16 (64-byte key)', () => {
    expect(truncatedHmac('sha256',
      'eae255d9e083268f896429ce36645502aff9dbeaca7159f93c7d51fdaeefdbfe14c396693a5ce46e9f1157a687e866f94ca165bff5f7b425092236d2a6a004cb',
      'c28f6a09ce076ef270458967fe19d46e6f6b2cbeb6362bdc4fd55684177e984a600cf0814501665c3bcb4353e94681c83a8381ebb0c8fcdbfbd73c0eca738cf2e121edd46b2c0a0292eb6e2c4e46f5107a7780572d0eedb9473847684a4039ac6c56c9caea90432b9e2e72bad422168e5ad093c9d612e7c05c7fde5c40ed89c0',
      16,
    )).toBe('B84003C417A472FD2935341962744330');
  });
  it('Count=120 Tlen=32 (64-byte key)', () => {
    expect(truncatedHmac('sha256',
      '992868504d2564c4fb47bcbd4ae482d8fb0e8e56d7b81864e61986a0e25682daeb5b50177c095edc9e971da95c3210c376e723365ac33d1b4f391817f4c35124',
      'ed4f269a8851eb3154771516b27228155200778049b2dc1963f3ac32ba46ea1387cfbb9c39151a2cc406cdc13c3c9860a27eb0b7fe8a7201ad11552afd041e33f70e53d97c62f17194b66117028fa9071cc0e04bd92de4972cd54f719010a694e414d4977abed7ca6b90ba612df6c3d467cded85032598a48546804f9cf2ecfe',
      32,
    )).toBe('2F8321F416B9BB249F113B13FC12D70E1668DC332839C10DAA5717896CB70DDF');
  });
});

describe('HMAC-SHA-384 CAVS [L=48]', () => {
  it('Count=0 Tlen=24', () => {
    expect(truncatedHmac('sha384',
      'f16ad73790ca39c7f9856c4483202e7f8e0c8283c7d50d6da79cc07d3dc7b76c2ef76100fa3ae2df8083b5a1c5579628f1c8',
      '9870007654ebc3d28f883bb832e0b31700f923d9c9b10168e0605971cfb920e848f1c64c5f240a2cf7f412ea7a73bbbfce432eff84fbb49e52cdcbf4c36679bd2d16e064e4311381adb528a0752c8e4443d4a12b6cfe7cd406b40e3f9e9e71f42e27764649db85d99913a4628bd5d5ae49f6a5e6e9810211e35d4ddac929b093',
      24,
    )).toBe('79E24A203BF42074E72C8B4A0222AFACE3E8CE7B4004CEC2');
  });
  it('Count=18 Tlen=32', () => {
    expect(truncatedHmac('sha384',
      '136933635a4f9252a65ecdb0a266fe7a68e935d597db26f5a6a61e3d78713ca830a2dd6746a158ccdbdfec664918f66effd5',
      '1cd86dbe49225fc2f82758f53dfa3696ef66a7645dd284a93d686177e5776232be15504ef508eb5a73e7823e107cc2c1036dcc4e9d1b8af738cb42ba6a046b037e37c07324a694e0677e659de046b3fb297d120f957f7fb61ea9f0d79fbd2fe84488e7b43ec2ff5bbb35289a1522b24c49e0a431acc60befd94b9256ee6c53e8',
      32,
    )).toBe('3E92717865123DCBC7BE18C72522AAD889C29DD2AFA16D30F0AD68CD9640BC84');
  });
  it('Count=49 Tlen=48 (full output)', () => {
    expect(truncatedHmac('sha384',
      '6c075056122218f595bb28753e87ae6334a0adc24336e85bdb8202545cfce30490ce5e067988108c4e158bf6c0eeb4a4818d',
      '0b9b52ec0e46793a179589513f117a956fcf98717339373f5010a268d8b254cc7b996b6460255925b59bdd28436d320945bc868d7a1bad87799617fc45f3ff852137e6f5a56c403c12a26d8be334eab9a44cc9e607a95e5e35a03cbf6261605fa47cabe805a49645d7b221c247ed0c6e35884ac4436cb38b2c38f9fb5886dd21',
      48,
    )).toBe('58C6F879AA6EE523DC374A01E541F02F4C3DFFB948B071468D2B242BBD358D8614AA7FAD660348E61828CEA1B758B91E');
  });
});

describe('HMAC-SHA-512 CAVS [L=64]', () => {
  it('Count=0 Tlen=32', () => {
    expect(truncatedHmac('sha512',
      '726374c4b8df517510db9159b730f93431e0cd468d4f3821eab0edb93abd0fba46ab4f1ef35d54fec3d85fa89ef72ff3d35f22cf5ab69e205c10afcdf4aaf11338dbb12073474fddb556e60b8ee52f91163ba314303ee0c910e64e87fbf302214edbe3f2',
      'ac939659dc5f668c9969c0530422e3417a462c8b665e8db25a883a625f7aa59b89c5ad0ece5712ca17442d1798c6dea25d82c5db260cb59c75ae650be56569c1bd2d612cc57e71315917f116bbfa65a0aeb8af7840ee83d3e7101c52cf652d2773531b7a6bdd690b846a741816c860819270522a5b0cdfa1d736c501c583d916',
      32,
    )).toBe('BD3D2DF6F9D284B421A43E5F9CB94BC4FF88A88243F1F0133BAD0FB1791F6569');
  });
  it('Count=62 Tlen=64 (full output)', () => {
    expect(truncatedHmac('sha512',
      '662ca8f53b97edd9bbd43b1f9e4ea49f2ac14417faee257aff93608bc49a85abf6913def235a2e76c2241ffa749a5da489595d25c6a8a2026563e12f5e3964e0e518ac9c34e45a938a6f503174a613f34b08737afe5d6fde11a45344e64d23b33ca83c23',
      '0c057a2b56cb7e651c6339e4c91a1a72d51af2a646de9dfd77e9e42c18b8a2b576f526b9fcedd90dfa442090a6e784bb614311793bb5fb39b8418842d586294746f1ea3c02320d6801ecf2ba44b13b60172d2d9693a158bc66947aacd7c5a14a0463905d6e80649db8c4770cac5e858a7f400da4568cfaae08498311265b50e5',
      64,
    )).toBe('C0D6E13C5746369D49BEF107CFC9A465627691320B8203233359E6A49659025AC96A6DB6C4D460224F6AA1CB7A6B8DF311E066F6109BD466CD9AEE3058DBC5F0');
  });
  it('Count=374 Tlen=64 (142-byte key)', () => {
    expect(truncatedHmac('sha512',
      'f78343071f61ee7d9f791bd53132e6d557928bcfe4b214bebf6f3592e46374c7ab148c3c4d6a1443a4675cf4321298c865b440631947b6b05f2c2a337d1cbb9b3661de974b4604eb41cc77c3659e85470e47e16f22a34619db935d59cbf5e1101ed401c020db069eff1035e9d1bff77bd8b3379e05ac0c20bc0e98aad7d7304dedd3bc5ed4136184649b5e0f7e5b',
      'd63b50b54e1536e35d5f3c6e29f1e49a78ca43fa22b31232c71f0300bd56517e4cd29ba11ee9f206f1ad31ee8f118c87004d6c6dfe837b70a9a2fa987c8b5b6680720c5dbf8791c1fcd6d59fa16cc20df9bc0fb39f41598a376476e45b9f06add8e34af01b373a9ce6a3d189484cacb6cbe0d3d5ef34d709d72c1dee43dc79da',
      64,
    )).toBe('086F674D778DB491E73B6FBC5126233C6B6E1F066963356D49EA386D9C0868AD25BF6EDAD0371CDE87CEA94A18C6DBA47535DFCE2E40D2246AB17980495D656C');
  });
});

// ═══════════════════════════════════════════════════════════════
// ISO 9797-1 Annex B official vectors
// K = 0123456789ABCDEF.  KDM2 K' = F1D3B597795B3D1F.
// Note: ISO 9797-1:1999 Annex B has 3 known M2-padding errata (1-bit typos).
// ═══════════════════════════════════════════════════════════════

const ISO_K = '0123456789ABCDEF';
const ISO_string1 = '4E6F77206973207468652074696D6520666F7220616C6C20'; // "Now is the time for all " (24B)
const ISO_string2 = '4E6F77206973207468652074696D6520666F72206974';     // "Now is the time for it"  (22B)

describe('ISO 9797-1 Algorithm 1 — official vectors (4-byte MAC)', () => {
  it('string1 + M1 → 70A30640', () => {
    expect(desMac(ISO_K, ISO_string1, undefined, 4, 'iso9797m1')).toBe('70A30640');
  });
  it('string1 + M2 → 10E1F0F1', () => {
    expect(desMac(ISO_K, ISO_string1, undefined, 4, 'iso9797m2')).toBe('10E1F0F1');
  });
  it('string1 + M3 → 2C58FB8F', () => {
    expect(desMac(ISO_K, ISO_string1, undefined, 4, 'iso9797m3')).toBe('2C58FB8F');
  });
  it('string2 + M1 → E45B3AD2', () => {
    expect(desMac(ISO_K, ISO_string2, undefined, 4, 'iso9797m1')).toBe('E45B3AD2');
  });
  it('string2 + M2 → A924C721', () => {
    expect(desMac(ISO_K, ISO_string2, undefined, 4, 'iso9797m2')).toBe('A924C721');
  });
  it('string2 + M3 → B1ECD6FC', () => {
    expect(desMac(ISO_K, ISO_string2, undefined, 4, 'iso9797m3')).toBe('B1ECD6FC');
  });
});

describe('ISO 9797-1 Algorithm 2 — official vectors (auto KDM2)', () => {
  it('string1 + M1 → 10F9BC67A03CD5D8', () => {
    expect(desMacAlg2(ISO_K, ISO_string1, undefined, 'iso9797m1')).toBe('10F9BC67A03CD5D8');
  });
  it('string1 + M2 → BE7C2AB7D36BF5B7 (spec prints "BEFC..." — 1-bit typo)', () => {
    expect(desMacAlg2(ISO_K, ISO_string1, undefined, 'iso9797m2')).toBe('BE7C2AB7D36BF5B7');
  });
  it('string1 + M3 → 8EFC8BC7C2726E5C', () => {
    expect(desMacAlg2(ISO_K, ISO_string1, undefined, 'iso9797m3')).toBe('8EFC8BC7C2726E5C');
  });
  it('string2 + M1 → 215E9CE6D91BC7FB', () => {
    expect(desMacAlg2(ISO_K, ISO_string2, undefined, 'iso9797m1')).toBe('215E9CE6D91BC7FB');
  });
  it('string2 + M2 → 1736AC1A61630EFB (spec prints "63630EFB" — suspected errata)', () => {
    expect(desMacAlg2(ISO_K, ISO_string2, undefined, 'iso9797m2')).toBe('1736AC1A61630EFB');
  });
  it('string2 + M3 → 05382696274FB4F0', () => {
    expect(desMacAlg2(ISO_K, ISO_string2, undefined, 'iso9797m3')).toBe('05382696274FB4F0');
  });
});

describe('ISO 9797-1 Algorithm 3 (Retail MAC) — official vectors (explicit K\' = FEDCBA9876543210)', () => {
  const kAndKprime = '0123456789ABCDEFFEDCBA9876543210';

  it('string1 + M1 → A1C72E74EA3FA9B6', () => {
    expect(desTdesMac(kAndKprime, ISO_string1, undefined, 'iso9797m1')).toBe('A1C72E74EA3FA9B6');
  });
  it('string1 + M2 → E9086230CA3BE796 (spec prints "...CA3BEF96" — 1-bit typo)', () => {
    expect(desTdesMac(kAndKprime, ISO_string1, undefined, 'iso9797m2')).toBe('E9086230CA3BE796');
  });
  it('string1 + M3 → AB059463D7A7D170', () => {
    expect(desTdesMac(kAndKprime, ISO_string1, undefined, 'iso9797m3')).toBe('AB059463D7A7D170');
  });
  it('string2 + M1 → 2E2B1428CC78254F', () => {
    expect(desTdesMac(kAndKprime, ISO_string2, undefined, 'iso9797m1')).toBe('2E2B1428CC78254F');
  });
  it('string2 + M2 → 5A692CE64F404145', () => {
    expect(desTdesMac(kAndKprime, ISO_string2, undefined, 'iso9797m2')).toBe('5A692CE64F404145');
  });
  it('string2 + M3 → C59F7EED328DDD69', () => {
    expect(desTdesMac(kAndKprime, ISO_string2, undefined, 'iso9797m3')).toBe('C59F7EED328DDD69');
  });
});
