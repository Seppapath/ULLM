/* @ts-self-types="./ullm_ts.d.ts" */

class ClientSession {
    static __wrap(ptr) {
        const obj = Object.create(ClientSession.prototype);
        obj.__wbg_ptr = ptr;
        ClientSessionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ClientSessionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_clientsession_free(ptr, 0);
    }
    /**
     * The bytes to send as the first WebSocket message.
     * @returns {Uint8Array}
     */
    clientHelloBytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.clientsession_clientHelloBytes(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Consume the server's `ServerHello`; the session is then `Open` and
     * ready for `encrypt`/`decrypt`.
     *
     * On any failure the session is permanently poisoned (P2-11): all
     * subsequent calls return a clear "session poisoned" error rather
     * than the previous behaviour of getting stuck in `Replacing` and
     * reporting the misleading "session is mid-transition" on every op.
     * @param {Uint8Array} server_hello
     */
    complete(server_hello) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(server_hello, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.clientsession_complete(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Decrypt one inbound frame.
     *
     * Returns `DecryptResult { text, endOfTurn }`. **Control frames**
     * (specifically `Control::KeyUpdate`) are handled transparently: the
     * session advances its per-turn DH ratchet in place and the call
     * returns an empty `text` with `endOfTurn=false`, telling the JS host
     * "frame consumed, ask for the next one".
     * @param {Uint8Array} frame
     * @returns {DecryptResult}
     */
    decrypt(frame) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(frame, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.clientsession_decrypt(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return DecryptResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Encrypt a plaintext prompt; the result is one DATA frame ready for the
     * WebSocket.
     * @param {Uint8Array} plaintext
     * @returns {Uint8Array}
     */
    encrypt(plaintext) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.clientsession_encrypt(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Initialize: verify the bundle, build a `ClientHello`. The returned
     * bytes are sent over the WebSocket as the first message.
     * @param {Uint8Array} bundle_bytes
     * @param {Uint8Array} attestation_nonce
     * @param {Uint8Array} trust_root_bytes
     * @param {Uint8Array} tee_receipt_pk_bytes
     * @param {Uint8Array} expected_weight_commit
     * @param {bigint} now_unix
     * @returns {ClientSession}
     */
    static start(bundle_bytes, attestation_nonce, trust_root_bytes, tee_receipt_pk_bytes, expected_weight_commit, now_unix) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bundle_bytes, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(attestation_nonce, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(trust_root_bytes, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passArray8ToWasm0(tee_receipt_pk_bytes, wasm.__wbindgen_export3);
            const len3 = WASM_VECTOR_LEN;
            const ptr4 = passArray8ToWasm0(expected_weight_commit, wasm.__wbindgen_export3);
            const len4 = WASM_VECTOR_LEN;
            wasm.clientsession_start(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, now_unix);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return ClientSession.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Verify the trailing signed-receipt envelope.
     * @param {Uint8Array} raw
     * @returns {ReceiptJs}
     */
    verifyReceipt(raw) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(raw, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.clientsession_verifyReceipt(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return ReceiptJs.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) ClientSession.prototype[Symbol.dispose] = ClientSession.prototype.free;
exports.ClientSession = ClientSession;

class DecryptResult {
    static __wrap(ptr) {
        const obj = Object.create(DecryptResult.prototype);
        obj.__wbg_ptr = ptr;
        DecryptResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DecryptResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_decryptresult_free(ptr, 0);
    }
    /**
     * @returns {boolean}
     */
    get endOfTurn() {
        const ret = wasm.decryptresult_endOfTurn(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {string}
     */
    get text() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.decryptresult_text(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export2(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) DecryptResult.prototype[Symbol.dispose] = DecryptResult.prototype.free;
exports.DecryptResult = DecryptResult;

class ReceiptJs {
    static __wrap(ptr) {
        const obj = Object.create(ReceiptJs.prototype);
        obj.__wbg_ptr = ptr;
        ReceiptJsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ReceiptJsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_receiptjs_free(ptr, 0);
    }
    /**
     * @returns {number}
     */
    get epoch() {
        const ret = wasm.receiptjs_epoch(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    get inputTokens() {
        const ret = wasm.receiptjs_inputTokens(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {bigint}
     */
    get issuedAtUnix() {
        const ret = wasm.receiptjs_issuedAtUnix(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {string}
     */
    get model() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.receiptjs_model(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export2(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {number}
     */
    get outputTokens() {
        const ret = wasm.receiptjs_outputTokens(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {string}
     */
    get sessionIdHex() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.receiptjs_sessionIdHex(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export2(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) ReceiptJs.prototype[Symbol.dispose] = ReceiptJs.prototype.free;
exports.ReceiptJs = ReceiptJs;
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_bce6d499ff0a4aff: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg___wbindgen_is_function_5cd60d5cf78b4eef: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_b4593df85baada48: function(arg0) {
            const val = getObject(arg0);
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_dde0fd9020db4434: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_35bb9f4c7fd651d5: function(arg0) {
            const ret = getObject(arg0) === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_9c31b086c2b26051: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_dfde26266607c996: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = getObject(arg0).crypto;
            return addHeapObject(ret);
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).getRandomValues(getObject(arg1));
        }, arguments); },
        __wbg_length_56fcd3e2b7e0299d: function(arg0) {
            const ret = getObject(arg0).length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = getObject(arg0).msCrypto;
            return addHeapObject(ret);
        },
        __wbg_new_with_length_99887c91eae4abab: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = getObject(arg0).node;
            return addHeapObject(ret);
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = getObject(arg0).process;
            return addHeapObject(ret);
        },
        __wbg_prototypesetcall_5f9bdc8d75e07276: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), getObject(arg2));
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).randomFillSync(takeObject(arg1));
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return addHeapObject(ret);
        }, arguments); },
        __wbg_static_accessor_GLOBAL_THIS_02344c9b09eb08a9: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_GLOBAL_ac6d4ac874d5cd54: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_SELF_9b2406c23aeb2023: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_WINDOW_b34d2126934e16ba: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_subarray_7c6a0da8f3b4a1ba: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = getObject(arg0).versions;
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_object_clone_ref: function(arg0) {
            const ret = getObject(arg0);
            return addHeapObject(ret);
        },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
    };
    return {
        __proto__: null,
        "./ullm_ts_bg.js": import0,
    };
}

const ClientSessionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_clientsession_free(ptr, 1));
const DecryptResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_decryptresult_free(ptr, 1));
const ReceiptJsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_receiptjs_free(ptr, 1));

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function dropObject(idx) {
    if (idx < 1028) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getObject(idx) { return heap[idx]; }

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_export(addHeapObject(e));
    }
}

let heap = new Array(1024).fill(undefined);
heap.push(undefined, null, true, false);

let heap_next = heap.length;

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
function decodeText(ptr, len) {
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

const wasmPath = `${__dirname}/ullm_ts_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasmInstance = new WebAssembly.Instance(wasmModule, __wbg_get_imports());
let wasm = wasmInstance.exports;
