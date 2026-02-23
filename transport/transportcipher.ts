/**
 * Transport layer cipher that combines AES-CTR and HMAC-SHA256.
 * Manages encryption/decryption state, sequence numbers, and MAC verification.
 */
import { encryptAES128CTR, decryptAES128CTR } from "../crypto/cipher";
import { computeHMACSHA256, constantTimeEqual } from "../crypto/mac";
import { buildPacket } from "../protocol/codec";
import { writeUint32, concat } from "../protocol/serialization";
import { HMAC_SHA256_SIZE, AES_BLOCK_SIZE, MAX_PACKET_SIZE } from "../domain/constants";
import { MacVerificationError, ProtocolError } from "../domain/errors";

export interface EncryptResult {
  ciphertext: Uint8Array;
}

export interface DecryptResult {
  payload: Uint8Array;
  consumed: number;
}

export class TransportCipher {
  private ivEnc: Uint8Array;
  private ivDec: Uint8Array;
  private keyEnc: CryptoKey;
  private keyDec: CryptoKey;
  private seqOut: number;
  private seqIn: number;
  private macEtm: boolean;
  private macC: Uint8Array;
  private macS: Uint8Array;

  constructor(
    ivC: Uint8Array,
    keyC: Uint8Array,
    macC: Uint8Array,
    ivS: Uint8Array,
    keyS: Uint8Array,
    macS: Uint8Array,
    initialSeqOut: number,
    initialSeqIn: number,
    macEtm: boolean,
    keyEncCrypto: CryptoKey,
    keyDecCrypto: CryptoKey
  ) {
    this.ivEnc = new Uint8Array(ivC);
    this.ivDec = new Uint8Array(ivS);
    this.keyEnc = keyEncCrypto;
    this.keyDec = keyDecCrypto;
    this.seqOut = initialSeqOut;
    this.seqIn = initialSeqIn;
    this.macEtm = macEtm;
    this.macC = macC;
    this.macS = macS;
  }

  async encrypt(payload: Uint8Array): Promise<EncryptResult> {
    const raw = buildPacket(payload, this.macEtm);
    const seq = this.seqOut++;
    let ciphertext: Uint8Array;
    let macInput: Uint8Array;
    if (this.macEtm) {
      const packetLen = raw.subarray(0, 4);
      const { ciphertext: ct, nextIv } = await encryptAES128CTR(this.keyEnc, this.ivEnc, raw.subarray(4));
      this.ivEnc = nextIv;
      ciphertext = ct;
      macInput = concat(writeUint32(seq), packetLen, ciphertext);
      const mac = await computeHMACSHA256(this.macC, macInput);
      return { ciphertext: concat(packetLen, ciphertext, mac) };
    }
    const { ciphertext: ct, nextIv } = await encryptAES128CTR(this.keyEnc, this.ivEnc, raw);
    this.ivEnc = nextIv;
    ciphertext = ct;
    macInput = concat(writeUint32(seq), raw);
    const mac = await computeHMACSHA256(this.macC, macInput);
    return { ciphertext: concat(ciphertext, mac) };
  }

  async decrypt(data: Uint8Array): Promise<DecryptResult | null> {
    if (this.macEtm) return this.decryptEtm(data);
    return this.decryptStandard(data);
  }

  private async decryptEtm(data: Uint8Array): Promise<DecryptResult | null> {
    if (data.length < 4 + HMAC_SHA256_SIZE) return null;
    const plen = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, false);
    if (plen < 5 || plen > MAX_PACKET_SIZE) return null;
    const totalLen = 4 + plen + HMAC_SHA256_SIZE;
    if (data.length < totalLen) return null;
    const packetLen = data.subarray(0, 4);
    const ciphertext = data.subarray(4, 4 + plen);
    const macReceived = data.subarray(4 + plen, 4 + plen + HMAC_SHA256_SIZE);
    const macInput = concat(writeUint32(this.seqIn), packetLen, ciphertext);
    const macExpected = await computeHMACSHA256(this.macS, macInput);
    if (!constantTimeEqual(macReceived, macExpected)) {
      throw new MacVerificationError("MAC verification failed (EtM mode)");
    }
    const { plaintext: fullRawInner, nextIv } = await decryptAES128CTR(this.keyDec, this.ivDec, ciphertext);
    const padLen = fullRawInner[0];
    if (padLen < 4 || padLen > 255) {
      throw new ProtocolError(`Invalid padding length: ${padLen} (seq=${this.seqIn})`);
    }
    if (padLen > plen - 1) {
      throw new ProtocolError(`Padding exceeds packet length (seq=${this.seqIn})`);
    }
    const payloadLen = plen - 1 - padLen;
    if (payloadLen < 0 || 1 + payloadLen > fullRawInner.length) {
      throw new ProtocolError(`Invalid payload length: ${payloadLen} (seq=${this.seqIn})`);
    }
    this.ivDec = nextIv;
    this.seqIn++;
    const payload = fullRawInner.subarray(1, 1 + payloadLen);
    return { payload, consumed: totalLen };
  }

  private async decryptStandard(data: Uint8Array): Promise<DecryptResult | null> {
    if (data.length < AES_BLOCK_SIZE + HMAC_SHA256_SIZE) return null;
    const firstBlock = data.subarray(0, AES_BLOCK_SIZE);
    const { plaintext: first, nextIv: ivAfterFirst } = await decryptAES128CTR(this.keyDec, this.ivDec, firstBlock);
    const plen = new DataView(first.buffer, first.byteOffset, 4).getUint32(0, false);
    if (plen < 5 || plen > MAX_PACKET_SIZE) return null;
    const totalEnc = 4 + plen;
    if (data.length < totalEnc + HMAC_SHA256_SIZE) return null;
    const macReceived = data.subarray(totalEnc, totalEnc + HMAC_SHA256_SIZE);
    let fullRaw: Uint8Array;
    let ivAfterDecrypt: Uint8Array;
    if (totalEnc <= AES_BLOCK_SIZE) {
      fullRaw = first.subarray(0, totalEnc);
      ivAfterDecrypt = ivAfterFirst;
    } else {
      const { plaintext: raw, nextIv: ivAfterRest } = await decryptAES128CTR(this.keyDec, ivAfterFirst, data.subarray(AES_BLOCK_SIZE, totalEnc));
      ivAfterDecrypt = ivAfterRest;
      fullRaw = concat(first, raw);
    }
    const padLen = fullRaw[4];
    if (padLen < 4 || padLen > 255) {
      throw new ProtocolError(`Invalid padding length: ${padLen} (seq=${this.seqIn})`);
    }
    const payloadLen = plen - 1 - padLen;
    if (payloadLen < 0 || 5 + payloadLen > fullRaw.length) {
      throw new ProtocolError(`Invalid payload length: ${payloadLen} (seq=${this.seqIn})`);
    }
    const macInput = concat(writeUint32(this.seqIn), fullRaw);
    const macExpected = await computeHMACSHA256(this.macS, macInput);
    if (!constantTimeEqual(macReceived, macExpected)) {
      throw new MacVerificationError("MAC verification failed");
    }
    this.seqIn++;
    this.ivDec = ivAfterDecrypt;
    const payload = fullRaw.subarray(5, 5 + payloadLen);
    return { payload, consumed: totalEnc + HMAC_SHA256_SIZE };
  }
}

export async function createTransportCipher(
  ivC: Uint8Array,
  keyC: Uint8Array,
  macC: Uint8Array,
  ivS: Uint8Array,
  keyS: Uint8Array,
  macS: Uint8Array,
  initialSeqOut: number,
  initialSeqIn: number,
  macEtm: boolean
): Promise<TransportCipher> {
  const keyEncCrypto = await crypto.subtle.importKey("raw", keyC as BufferSource, { name: "AES-CTR" }, false, ["encrypt"]);
  const keyDecCrypto = await crypto.subtle.importKey("raw", keyS as BufferSource, { name: "AES-CTR" }, false, ["decrypt"]);
  return new TransportCipher(ivC, keyC, macC, ivS, keyS, macS, initialSeqOut, initialSeqIn, macEtm, keyEncCrypto, keyDecCrypto);
}
