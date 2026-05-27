import { describe, it, expect } from 'vitest';
import { 
  kemKeygen, kemEncapsulate, kemDecapsulate, dsaKeygen, dsaSign, dsaVerify 
} from '../../src/crypto/pqc.ts';

describe('Phase 7: PQC', () => {
  describe('ML-KEM-768', () => {
    it('should perform keygen, encapsulate, and decapsulate roundtrip', () => {
      const { ek, dk } = kemKeygen(768);
      const { ciphertext, sharedSecret: ss1 } = kemEncapsulate(768, ek);
      const ss2 = kemDecapsulate(768, dk, ciphertext);
      expect(ss1).toBe(ss2);
    });
  });

  describe('ML-DSA-65', () => {
    it('should perform keygen, sign, and verify roundtrip', () => {
      const { publicKey, secretKey } = dsaKeygen(65);
      const msg = '48656c6c6f'; // "Hello"
      const sig = dsaSign(65, secretKey, msg);
      const ok = dsaVerify(65, publicKey, msg, sig);
      expect(ok).toBe(true);
    });

    it('verification should fail with wrong message', () => {
      const { publicKey, secretKey } = dsaKeygen(65);
      const msg = '48656c6c6f';
      const sig = dsaSign(65, secretKey, msg);
      const ok = dsaVerify(65, publicKey, msg + '00', sig);
      expect(ok).toBe(false);
    });
  });
});
