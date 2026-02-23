/**
 * Main SSH connection orchestrator.
 * Entry point that coordinates all layers: domain, crypto, protocol, transport, state machines.
 */

import type { SSHConnection, ConnectSSHOptions } from "./types";
import type { Credentials as SSHCredentials } from "../domain/models";
import { createConnectionState, setFatalError, type ConnectionState } from "./connectionstate";
import { log } from "../debug";
import { parsePacket } from "../protocol/codec";
import { getMessageName } from "../protocol/messages";
import { readString, readBytes, readMpint } from "../protocol/deserialization";
import { writeString, writeBytes, writeUint32, writeBigintMpint, concat } from "../protocol/serialization";
import { computeSHA256 } from "../crypto/digest";
import { generateDHPrivate, computeDHSharedSecret, generateX25519KeyPair, computeX25519SharedSecret } from "../crypto/keyexchange";
import { deriveKeys } from "../crypto/keys";
import { createTransportCipher } from "../transport/transportcipher";
import { buildKexInit } from "../kex/builder";
import { parseCertBase64 } from "../auth/certparser";
import { buildPacket } from "../protocol/codec";
import { writeByteMpint } from "../protocol/serialization";
import { MacVerificationError } from "../domain/errors";
import { parsePemPrivateKey, ed25519Sign } from "../auth/keys";
import {
  SSH_MSG_KEXINIT,
  SSH_MSG_KEX_ECDH_INIT,
  SSH_MSG_KEXDH_INIT,
  SSH_MSG_KEX_ECDH_REPLY,
  SSH_MSG_KEXDH_REPLY,
  SSH_MSG_NEWKEYS,
  SSH_MSG_SERVICE_REQUEST,
  SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_USERAUTH_REQUEST,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_USERAUTH_PK_OK,
  SSH_MSG_USERAUTH_SUCCESS,
  SSH_MSG_CHANNEL_OPEN,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_REQUEST,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_EXTENDED_DATA,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_FAILURE,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_GLOBAL_REQUEST,
  SSH_MSG_REQUEST_SUCCESS,
  SSH_MSG_REQUEST_FAILURE,
  SSH_MSG_EXT_INFO,
  CLIENT_IDENT,
  PREFERRED_KEX,
  PREFERRED_MAC,
  DEFAULT_TERMINAL_COLS,
  DEFAULT_TERMINAL_ROWS,
  DEFAULT_TERMINAL_TYPE,
  DEFAULT_WINDOW_SIZE,
  KEX_TIMEOUT_MS,
} from "../domain/constants";

export async function connectSSH(
  ws: WebSocket,
  creds: SSHCredentials,
  onError?: (err: string) => void,
  options?: ConnectSSHOptions
): Promise<SSHConnection> {
  const privKey = await parsePemPrivateKey(creds.privateKey);
  const certParsed = parseCertBase64(creds.certificate);
  const termCols = options?.cols ?? DEFAULT_TERMINAL_COLS;
  const termRows = options?.rows ?? DEFAULT_TERMINAL_ROWS;
  log("=== SSH Connection Starting ===");
  const conn = new SSHConnectionOrchestrator(
    ws,
    creds,
    privKey,
    certParsed,
    termCols,
    termRows,
    onError,
    options
  );
  await conn.start();
  return conn.getPublicAPI();
}

class SSHConnectionOrchestrator {
  private ws: WebSocket;
  private creds: SSHCredentials;
  private privKey: CryptoKey;
  private certParsed: { keyType: string; certBlob: Uint8Array };
  private termCols: number;
  private termRows: number;
  private onError?: (err: string) => void;
  private options?: ConnectSSHOptions;
  private connState: ConnectionState;
  private dataCallback: ((s: string) => void) | null = null;
  private dataBuffer: number[] = [];
  private encryptedBuf: Uint8Array = new Uint8Array(0);
  private identBuf: Uint8Array = new Uint8Array(0);
  private sendPending: Promise<void> = Promise.resolve();
  private draining = false;
  private useEncrypted = false;
  private kexTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private fatalError = false;
  private channelId = 0;
  private peerChannelId = new Uint8Array(4);
  private shellSent = false;
  private flushCount = 0;
  private kexInitC: Uint8Array | null = null;
  private kexInitS: Uint8Array | null = null;
  private serverKexList: string[] = [];
  private negotiatedMac: string | null = null;
  private ephemeralPriv: CryptoKey | null = null;
  private qc: Uint8Array | null = null;
  private dhX: bigint | null = null;
  private dhE: bigint | null = null;
  private sessionId: Uint8Array | null = null;
  private receivedPKOk = false;

  constructor(
    ws: WebSocket,
    creds: SSHCredentials,
    privKey: CryptoKey,
    certParsed: { keyType: string; certBlob: Uint8Array },
    termCols: number,
    termRows: number,
    onError?: (err: string) => void,
    options?: ConnectSSHOptions
  ) {
    this.ws = ws;
    this.creds = creds;
    this.privKey = privKey;
    this.certParsed = certParsed;
    this.termCols = termCols;
    this.termRows = termRows;
    this.onError = onError;
    this.options = options;
    this.connState = createConnectionState(DEFAULT_WINDOW_SIZE);
    ws.binaryType = "arraybuffer";
    ws.onmessage = (e) => this.handleMessage(e);
    ws.onclose = (e) => this.handleClose(e);
    ws.onerror = () => this.handleWSError();
  }

  async start(): Promise<void> {
    this.send(new TextEncoder().encode(CLIENT_IDENT + "\r\n"));
    log("SEND client ident:", CLIENT_IDENT);
  }

  private send(data: Uint8Array): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(data);
  }

  private setFatal(msg: string): void {
    if (!this.fatalError) {
      this.fatalError = true;
      this.onError?.(msg);
    }
  }

  private async sendEncrypted(payload: Uint8Array): Promise<void> {
    const prev = this.sendPending;
    const doSend = async () => {
      if (!this.connState.cipher) return;
      const { ciphertext } = await this.connState.cipher.encrypt(payload);
      if (this.ws.readyState === WebSocket.OPEN) this.ws.send(ciphertext);
    };
    const ourSend = prev.then(doSend);
    this.sendPending = ourSend;
    await ourSend;
  }

  private flushBuf(): void {
    if (this.dataBuffer.length > 0 && this.dataCallback) {
      const s = new TextDecoder().decode(new Uint8Array(this.dataBuffer));
      this.flushCount++;
      log(">>> PROMPT/DATA TO TERMINAL <<<", this.flushCount, "chars=", this.dataBuffer.length);
      this.dataCallback(s);
      this.dataBuffer.length = 0;
    }
  }

  private handleMessage(e: MessageEvent): void {
    if (e.data instanceof ArrayBuffer) {
      log("ws.onmessage bytes=", e.data.byteLength);
      this.handleRawData(new Uint8Array(e.data)).catch((err) => {
        log("handleRawData error:", err);
        this.setFatal(err instanceof Error ? err.message : String(err));
      });
    }
  }

  private async handleRawData(d: Uint8Array): Promise<void> {
    if (this.fatalError) return;
    if (!this.connState.serverIdent) {
      const result = this.extractServerIdent(d);
      if (!result) return;
      d = result;
    }
    if (!this.useEncrypted) {
      await this.processUnencryptedPackets(d);
    } else {
      this.encryptedBuf = concat(this.encryptedBuf, d);
      await this.processEncryptedPackets();
    }
  }

  private extractServerIdent(d: Uint8Array): Uint8Array | null {
    const combined = concat(this.identBuf, d);
    const sshStart = combined.findIndex((_, i) =>
      i <= combined.length - 4 &&
      combined[i] === 0x53 &&
      combined[i + 1] === 0x53 &&
      combined[i + 2] === 0x48 &&
      combined[i + 3] === 0x2d
    );
    if (sshStart < 0) {
      this.identBuf = combined;
      return null;
    }
    const afterIdent = combined.subarray(sshStart);
    let end = afterIdent.findIndex((_, i) =>
      i < afterIdent.length - 1 && afterIdent[i] === 0x0d && afterIdent[i + 1] === 0x0a
    );
    let termLen = 2;
    if (end < 0) {
      end = afterIdent.findIndex((b) => b === 0x0a);
      termLen = 1;
    }
    if (end < 0) {
      this.identBuf = combined;
      return null;
    }
    this.connState.serverIdent = new TextDecoder().decode(afterIdent.subarray(0, end));
    log("RECV server ident:", this.connState.serverIdent);
    this.identBuf = new Uint8Array(0);
    const restStart = sshStart + end + termLen;
    if (restStart < combined.length) return combined.subarray(restStart);
    return new Uint8Array(0);
  }

  private async processUnencryptedPackets(d: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < d.length) {
      const result = parsePacket(d.subarray(offset));
      if (!result) break;
      offset += result.consumed;
      await this.processPayload(result.payload);
      if (this.useEncrypted) {
        this.encryptedBuf = concat(this.encryptedBuf, d.subarray(offset));
        await this.processEncryptedPackets();
        return;
      }
    }
  }

  private async processEncryptedPackets(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      while (true) {
        if (!this.connState.cipher) break;
        let r: { payload: Uint8Array; consumed: number } | null;
        try {
          r = await this.connState.cipher.decrypt(this.encryptedBuf);
        } catch (err) {
          if (err instanceof MacVerificationError) {
            this.setFatal("SSH MAC verification failed");
          }
          break;
        }
        if (!r) break;
        this.encryptedBuf = this.encryptedBuf.subarray(r.consumed);
        await this.processPayload(r.payload);
      }
    } finally {
      this.draining = false;
    }
  }

  private async processPayload(p: Uint8Array): Promise<void> {
    const msgType = p[0];
    if (msgType === 2) return;
    if (msgType === 1) {
      const reasonCode = p.length >= 5 ? new DataView(p.buffer, p.byteOffset + 1, 4).getUint32(0, false) : 0;
      const desc = readString(p, 5);
      const msg = desc ? desc.value : `reason_code=${reasonCode}`;
      log("DISCONNECT from server:", msg, "reason_code=", reasonCode);
      this.setFatal(`Server disconnected: ${msg}`);
      return;
    }
    if (msgType === 3) {
      const rejectedSeq = p.length >= 5 ? new DataView(p.buffer, p.byteOffset + 1, 4).getUint32(0, false) : 0;
      log("UNIMPLEMENTED: server rejected our packet seq=", rejectedSeq);
      return;
    }
    if (msgType === 4) return;
    if (msgType === SSH_MSG_EXT_INFO) {
      log("EXT_INFO received (ignored)");
      return;
    }
    if (msgType === SSH_MSG_GLOBAL_REQUEST) {
      const reqName = readString(p, 1);
      if (!reqName) return;
      const wantReply = 1 + reqName.consumed < p.length && p[1 + reqName.consumed] !== 0;
      if (wantReply) {
        const ok = reqName.value === "keepalive@openssh.com";
        const reply = new Uint8Array([ok ? SSH_MSG_REQUEST_SUCCESS : SSH_MSG_REQUEST_FAILURE]);
        await this.sendEncrypted(reply);
        log("GLOBAL_REQUEST", reqName.value, "->", ok ? "REQUEST_SUCCESS" : "REQUEST_FAILURE");
      }
      return;
    }
    log("processPayload", getMessageName(msgType), "len=", p.length);
    if (msgType === SSH_MSG_KEXINIT && !this.kexInitS) {
      this.kexInitS = p;
      let o = 1 + 16;
      const serverKex = readString(p, o);
      if (!serverKex) {
        this.setFatal("kex init parse");
        return;
      }
      o += serverKex.consumed;
      this.serverKexList = serverKex.value.split(",").map((s) => s.trim()).filter(Boolean);
      const serverHostKey = readString(p, o);
      if (!serverHostKey) {
        this.setFatal("kex init server_host_key");
        return;
      }
      o += serverHostKey.consumed;
      const cipherCtos = readString(p, o);
      if (!cipherCtos) {
        this.setFatal("kex init cipher_ctos");
        return;
      }
      o += cipherCtos.consumed;
      const cipherStoc = readString(p, o);
      if (!cipherStoc) {
        this.setFatal("kex init cipher_stoc");
        return;
      }
      o += cipherStoc.consumed;
      const macCtos = readString(p, o);
      if (!macCtos) {
        this.setFatal("kex init mac_ctos");
        return;
      }
      o += macCtos.consumed;
      const macStoc = readString(p, o);
      if (!macStoc) {
        this.setFatal("kex init mac_stoc");
        return;
      }
      o += macStoc.consumed;
      const serverMacList = macStoc.value.split(",").map((s) => s.trim()).filter(Boolean);
      const ourMacList = PREFERRED_MAC.split(",").map((s) => s.trim()).filter(Boolean);
      this.negotiatedMac = ourMacList.find((a) => serverMacList.includes(a)) ?? null;
      if (!this.negotiatedMac) {
        this.setFatal(`MAC negotiation failed: server supports ${serverMacList.slice(0, 3).join(",")}... we need hmac-sha2-256 or hmac-sha2-256-etm@openssh.com`);
        return;
      }
      log("MAC negotiated:", this.negotiatedMac);
      const ourKexList = PREFERRED_KEX.split(",").map((s) => s.trim()).filter(Boolean);
      const negotiated = ourKexList.find((a) => this.serverKexList.includes(a));
      const isDH = negotiated === "diffie-hellman-group14-sha256";
      const isCurve = negotiated === "curve25519-sha256" || negotiated === "curve25519-sha256@libssh.org";
      if (!negotiated || (!isDH && !isCurve)) {
        this.setFatal(`KEX negotiation failed: server supports ${this.serverKexList.slice(0, 3).join(",")}... we need curve25519 or diffie-hellman-group14-sha256`);
        return;
      }
      log("KEX negotiated:", negotiated);
      const kexInit = buildKexInit();
      this.kexInitC = kexInit;
      this.send(buildPacket(kexInit));
      log("SEND KEXINIT");
      if (isDH) {
        const { x, e } = await generateDHPrivate();
        this.dhX = x;
        this.dhE = e;
        const initPayload = concat(new Uint8Array([SSH_MSG_KEXDH_INIT]), writeBigintMpint(e));
        this.send(buildPacket(initPayload));
        log("SEND KEXDH_INIT (diffie-hellman-group14-sha256)");
      } else {
        const kp = await generateX25519KeyPair();
        this.ephemeralPriv = kp.privateKey;
        this.qc = kp.publicKey;
        const initPayload = concat(new Uint8Array([SSH_MSG_KEX_ECDH_INIT]), writeBytes(this.qc));
        this.send(buildPacket(initPayload));
        log("SEND KEX_ECDH_INIT");
      }
      this.kexTimeoutId = setTimeout(() => {
        if (!this.sessionId) console.warn("[SSH] No KEX reply after 8s - server may reject KEX or connection hung. Check backend proxy logs.");
      }, KEX_TIMEOUT_MS);
    } else if (msgType === SSH_MSG_KEXDH_REPLY && this.dhX !== null && this.dhE !== null && this.kexInitC && this.kexInitS) {
      if (this.kexTimeoutId) clearTimeout(this.kexTimeoutId);
      this.kexTimeoutId = null;
      let o = 1;
      const ks = readBytes(p, o);
      if (!ks) {
        this.setFatal("kex dh reply parse");
        return;
      }
      o += ks.consumed;
      const serverHostKey = ks.value;
      const fMpint = readMpint(p, o);
      if (!fMpint) {
        this.setFatal("kex dh reply f");
        return;
      }
      o += fMpint.consumed;
      const f = fMpint.value;
      const k = computeDHSharedSecret(f, this.dhX);
      const vc = CLIENT_IDENT;
      const vs = this.connState.serverIdent.replace(/\r?\n$/, "");
      const h = await computeSHA256(
        concat(writeString(vc), writeString(vs), writeBytes(this.kexInitC), writeBytes(this.kexInitS), writeBytes(serverHostKey), writeBigintMpint(this.dhE), writeBigintMpint(f), writeBigintMpint(k))
      );
      this.sessionId = h;
      this.connState.sessionId = h;
      const kEncoded = writeBigintMpint(k);
      const { ivC, keyC, macC, ivS, keyS, macS } = await deriveKeys(kEncoded, h, this.sessionId);
      const macEtm = this.negotiatedMac === "hmac-sha2-256-etm@openssh.com";
      const cipher = await createTransportCipher(ivC, keyC, macC, ivS, keyS, macS, 3, 3, macEtm);
      this.connState.cipher = cipher;
      this.send(buildPacket(concat(new Uint8Array([SSH_MSG_NEWKEYS]))));
      log("SEND NEWKEYS encryption on (DH)");
    } else if (msgType === SSH_MSG_KEX_ECDH_REPLY && this.ephemeralPriv && this.qc && this.kexInitC && this.kexInitS) {
      if (this.kexTimeoutId) clearTimeout(this.kexTimeoutId);
      this.kexTimeoutId = null;
      let o = 1;
      const ks = readBytes(p, o);
      if (!ks) {
        this.setFatal("kex reply parse");
        return;
      }
      o += ks.consumed;
      const serverHostKey = ks.value;
      const qsBytes = readBytes(p, o);
      if (!qsBytes) {
        this.setFatal("kex reply qs");
        return;
      }
      o += qsBytes.consumed;
      const qs = qsBytes.value;
      const k = await computeX25519SharedSecret(this.ephemeralPriv, qs);
      const vc = CLIENT_IDENT;
      const vs = this.connState.serverIdent.replace(/\r?\n$/, "");
      const h = await computeSHA256(
        concat(writeString(vc), writeString(vs), writeBytes(this.kexInitC), writeBytes(this.kexInitS), writeBytes(serverHostKey), writeBytes(this.qc), writeBytes(qs), writeByteMpint(k))
      );
      this.sessionId = h;
      this.connState.sessionId = h;
      const kEncoded = writeByteMpint(k);
      const { ivC, keyC, macC, ivS, keyS, macS } = await deriveKeys(kEncoded, h, this.sessionId);
      const macEtm = this.negotiatedMac === "hmac-sha2-256-etm@openssh.com";
      const cipher = await createTransportCipher(ivC, keyC, macC, ivS, keyS, macS, 3, 3, macEtm);
      this.connState.cipher = cipher;
      this.send(buildPacket(concat(new Uint8Array([SSH_MSG_NEWKEYS]))));
      log("SEND NEWKEYS encryption on (curve)");
    } else if (msgType === SSH_MSG_NEWKEYS) {
      this.useEncrypted = true;
      const serviceReq = concat(
        new Uint8Array([SSH_MSG_SERVICE_REQUEST]),
        writeString("ssh-userauth")
      );
      await this.sendEncrypted(serviceReq);
      log("SEND ssh-userauth");
    } else if (msgType === SSH_MSG_SERVICE_ACCEPT) {
      const signData = concat(
        writeBytes(this.sessionId!),
        new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
        writeString(this.creds.username),
        writeString("ssh-connection"),
        writeString("publickey"),
        new Uint8Array([1]),
        writeString(this.certParsed.keyType),
        writeBytes(this.certParsed.certBlob)
      );
      const sig = await ed25519Sign(this.privKey, signData);
      const sigAlg = this.certParsed.keyType.startsWith("ssh-ed25519") ? "ssh-ed25519" : this.certParsed.keyType;
      const sigBlob = concat(writeString(sigAlg), writeBytes(sig));
      const authReq = concat(
        new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
        writeString(this.creds.username),
        writeString("ssh-connection"),
        writeString("publickey"),
        new Uint8Array([1]),
        writeString(this.certParsed.keyType),
        writeBytes(this.certParsed.certBlob),
        writeBytes(sigBlob)
      );
      await this.sendEncrypted(authReq);
      log("SEND USERAUTH_REQUEST (with sig, no PK_OK round)");
    } else if (msgType === SSH_MSG_USERAUTH_FAILURE) {
      const methods = readString(p, 1);
      const hint = this.receivedPKOk ? "signature verification failed" : "server rejected key/cert";
      const msg = methods ? `Auth failed (${hint}): ${methods.value || "publickey"}` : `Auth failed (${hint})`;
      log("USERAUTH_FAILURE methods=", methods?.value, "afterPKOk=", this.receivedPKOk);
      this.setFatal(msg);
    } else if (msgType === SSH_MSG_USERAUTH_PK_OK) {
      this.receivedPKOk = true;
      const signData = concat(
        writeBytes(this.sessionId!),
        new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
        writeString(this.creds.username),
        writeString("ssh-connection"),
        writeString("publickey"),
        new Uint8Array([1]),
        writeString(this.certParsed.keyType),
        writeBytes(this.certParsed.certBlob)
      );
      const sig = await ed25519Sign(this.privKey, signData);
      const sigAlg = this.certParsed.keyType.startsWith("ssh-ed25519") ? "ssh-ed25519" : this.certParsed.keyType;
      const sigBlob = concat(writeString(sigAlg), writeBytes(sig));
      const authReq2 = concat(
        new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
        writeString(this.creds.username),
        writeString("ssh-connection"),
        writeString("publickey"),
        new Uint8Array([1]),
        writeString(this.certParsed.keyType),
        writeBytes(this.certParsed.certBlob),
        writeBytes(sigBlob)
      );
      await this.sendEncrypted(authReq2);
      log("SEND USERAUTH_REQUEST (with sig)");
    } else if (msgType === SSH_MSG_USERAUTH_SUCCESS) {
      const chOpen = concat(
        new Uint8Array([SSH_MSG_CHANNEL_OPEN]),
        writeString("session"),
        new Uint8Array([0, 0, 0, 1]),
        new Uint8Array([0, 0, 0x80, 0]),
        new Uint8Array([0, 0, 0x20, 0])
      );
      await this.sendEncrypted(chOpen);
      log("SEND CHANNEL_OPEN session");
    } else if (msgType === SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
      this.channelId = new DataView(p.buffer, p.byteOffset + 1, 4).getUint32(0, false);
      this.peerChannelId = p.slice(5, 9);
      const cols = this.options?.cols ?? DEFAULT_TERMINAL_COLS;
      const rows = this.options?.rows ?? DEFAULT_TERMINAL_ROWS;
      const ptyReq = concat(
        new Uint8Array([SSH_MSG_CHANNEL_REQUEST]),
        this.peerChannelId,
        writeString("pty-req"),
        new Uint8Array([1]),
        writeString(DEFAULT_TERMINAL_TYPE),
        writeUint32(cols),
        writeUint32(rows),
        writeUint32(0),
        writeUint32(0),
        writeBytes(new Uint8Array([0]))
      );
      await this.sendEncrypted(ptyReq);
      log("SEND pty-req (want_reply)");
    } else if ((msgType === SSH_MSG_CHANNEL_SUCCESS || msgType === SSH_MSG_CHANNEL_FAILURE) && !this.shellSent) {
      if (msgType === SSH_MSG_CHANNEL_FAILURE) {
        this.onError?.("PTY request denied — shell may have no prompt or echo. Check cert has permit-pty.");
        this.options?.onPtyDenied?.();
      }
      const shellReq = concat(
        new Uint8Array([SSH_MSG_CHANNEL_REQUEST]),
        this.peerChannelId,
        writeString("shell"),
        new Uint8Array([1])
      );
      await this.sendEncrypted(shellReq);
      this.shellSent = true;
      log("SEND shell >>> SESSION READY <<<");
    } else if (msgType === SSH_MSG_CHANNEL_DATA) {
      const data = readBytes(p, 5);
      if (data) {
        log("CHANNEL_DATA received", data.value.length, "bytes");
        for (let i = 0; i < data.value.length; i++) this.dataBuffer.push(data.value[i]);
        this.flushBuf();
        if (data.value.length > 0) {
          const windowAdj = concat(
            new Uint8Array([SSH_MSG_CHANNEL_WINDOW_ADJUST]),
            this.peerChannelId,
            writeUint32(data.value.length)
          );
          void this.sendEncrypted(windowAdj);
        }
      }
    } else if (msgType === SSH_MSG_CHANNEL_EXTENDED_DATA) {
      const data = readBytes(p, 9);
      if (data) {
        log("CHANNEL_EXTENDED_DATA stderr bytes=", data.value.length);
        for (let i = 0; i < data.value.length; i++) this.dataBuffer.push(data.value[i]);
        this.flushBuf();
        if (data.value.length > 0) {
          const windowAdj = concat(
            new Uint8Array([SSH_MSG_CHANNEL_WINDOW_ADJUST]),
            this.peerChannelId,
            writeUint32(data.value.length)
          );
          void this.sendEncrypted(windowAdj);
        }
      }
    } else if (msgType > 0 && msgType < 100) {
      log("UNHANDLED msgType=", msgType, getMessageName(msgType), "len=", p.length);
    }
  }

  private handleClose(e: CloseEvent): void {
    log("ws.onclose code=", e.code, "reason=", e.reason);
    if (!this.fatalError && e.code === 1000 && e.reason === "session ended") {
      this.setFatal("Session ended by server");
    } else if (!this.fatalError && !e.wasClean) {
      this.setFatal(`Connection closed: ${e.reason || `code ${e.code}`}`);
    }
  }

  private handleWSError(): void {
    log("ws.onerror");
  }

  getPublicAPI(): SSHConnection {
    return {
      write: (data: string | Uint8Array) => {
        if (!this.shellSent) return;
        const b = typeof data === "string" ? new TextEncoder().encode(data) : data;
        const payload = new Uint8Array(1 + 4 + 4 + b.length);
        payload[0] = SSH_MSG_CHANNEL_DATA;
        payload.set(this.peerChannelId, 1);
        new DataView(payload.buffer).setUint32(5, b.length, false);
        payload.set(b, 9);
        void this.sendEncrypted(payload);
      },
      onData: (cb: (data: string) => void) => {
        log("onData callback registered");
        this.dataCallback = cb;
        this.flushBuf();
      },
      resize: (cols: number, rows: number) => {
        if (this.channelId === 0) return;
        const winReq = concat(
          new Uint8Array([SSH_MSG_CHANNEL_REQUEST]),
          this.peerChannelId,
          writeString("window-change"),
          new Uint8Array([0]),
          writeUint32(cols),
          writeUint32(rows),
          writeUint32(0),
          writeUint32(0)
        );
        void this.sendEncrypted(winReq);
      },
      close: () => this.ws.close(),
    };
  }
}
