/* tslint:disable */
/* eslint-disable */

export class ClientSession {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The bytes to send as the first WebSocket message.
     */
    clientHelloBytes(): Uint8Array;
    /**
     * Consume the server's `ServerHello`; the session is then `Open` and
     * ready for `encrypt`/`decrypt`.
     *
     * On any failure the session is permanently poisoned (P2-11): all
     * subsequent calls return a clear "session poisoned" error rather
     * than the previous behaviour of getting stuck in `Replacing` and
     * reporting the misleading "session is mid-transition" on every op.
     */
    complete(server_hello: Uint8Array): void;
    /**
     * Decrypt one inbound frame.
     *
     * Returns `DecryptResult { text, endOfTurn }`. **Control frames**
     * (specifically `Control::KeyUpdate`) are handled transparently: the
     * session advances its per-turn DH ratchet in place and the call
     * returns an empty `text` with `endOfTurn=false`, telling the JS host
     * "frame consumed, ask for the next one".
     */
    decrypt(frame: Uint8Array): DecryptResult;
    /**
     * Encrypt a plaintext prompt; the result is one DATA frame ready for the
     * WebSocket.
     */
    encrypt(plaintext: Uint8Array): Uint8Array;
    /**
     * Initialize: verify the bundle, build a `ClientHello`. The returned
     * bytes are sent over the WebSocket as the first message.
     */
    static start(bundle_bytes: Uint8Array, attestation_nonce: Uint8Array, trust_root_bytes: Uint8Array, tee_receipt_pk_bytes: Uint8Array, expected_weight_commit: Uint8Array, now_unix: bigint): ClientSession;
    /**
     * Verify the trailing signed-receipt envelope.
     */
    verifyReceipt(raw: Uint8Array): ReceiptJs;
}

export class DecryptResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly endOfTurn: boolean;
    readonly text: string;
}

export class ReceiptJs {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly epoch: number;
    readonly inputTokens: number;
    readonly issuedAtUnix: bigint;
    readonly model: string;
    readonly outputTokens: number;
    readonly sessionIdHex: string;
}
