import { describe, it } from 'vitest';
import { desMac, desFullMac, desTdesMac } from '../../src/crypto/mac.ts';
import { iso9797m2 } from '../../src/crypto/padding.ts';

function compare(label: string, key: string, plaintext: string) {
  const iv = '0000000000000000';
  const padded = iso9797m2(plaintext, 8);
  const r1 = desMac(key, plaintext, iv, 8, 'iso9797m2');
  const r2 = desFullMac(key, plaintext, 'iso9797m2');
  const r3 = desTdesMac(key, plaintext, iv, 'iso9797m2');

  console.log(`\n══════ ${label} ══════`);
  console.log(`Key:                ${key}`);
  console.log(`  K1 = ${key.substring(0, 16)}`);
  console.log(`  K2 = ${key.substring(16, 32)}`);
  console.log(`  K1 == K2 ?  ${key.substring(0, 16) === key.substring(16, 32)}`);
  console.log(`Padded (M2):        ${padded}`);
  console.log(`DES MAC:            ${r1}`);
  console.log(`DES Full MAC:       ${r2}`);
  console.log(`DES/TDES MAC:       ${r3}`);
  console.log(`all three equal ?   ${r1 === r2 && r2 === r3}`);
}

describe('MAC comparison — effect of K1==K2 degeneracy', () => {
  it('Case A: K1 == K2 (user input)', () => {
    compare(
      'A — K1 == K2 (3DES degenerates to single DES)',
      '11223344556677881122334455667788',
      '11223344556677881122334455667788112233445566778899',
    );
  });

  it('Case B: K1 != K2 (normal 16B key)', () => {
    compare(
      'B — K1 != K2 (proper 3DES key)',
      '11223344556677880011223344556677',
      '11223344556677881122334455667788112233445566778899',
    );
  });
});
