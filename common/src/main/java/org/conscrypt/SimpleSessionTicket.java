package org.conscrypt;

/*
 * In an ideal world, we would like to fully support SSL_CTX_set_tlsext_ticket_key_cb
 *
 * But as a quicker path, we support the idea of a set of 3 keys: previous, current, next
 * - New session tickets are issued with current
 * - Decryption works with any of the 3. If the previous is used (and it is also not the current or next), then
 *   we will mark it as expired, requiring refresh.
 * The meat of the implementation is in native_crypto.cc.
 * If ANY of the 3 are set to non-null, then our callback will replace the standard OpenSSL session ticket support.
 *   Setting all 3 to null will restore standard OpenSSL session ticket support.
 * Turning on session tickets needs to be an independent action.
 * Note that as we are not JNI-skilled (first time touching JNI), we have kept the Java->native
 *   interface relatively straight forward: a bunch of byte arrays.  This, of course, isn't the cleanest.
 *   We have slightly better encapsulation on the Java side and break out into byte arrays upon passing to native.
 */

// simplesessionticket
public class SimpleSessionTicket {
    public final byte[] keyName;
    public final byte[] aesKey;
    public final byte[] hmacKey;

    public SimpleSessionTicket(byte[] keyName,byte[] aesKey,byte[] hmacKey) {
        if(keyName == null || keyName.length != 16)
            throw new IllegalArgumentException("keyName must be 16 bytes");
        if(aesKey == null || aesKey.length != 16)
            throw new IllegalArgumentException("aesKey must be 16 bytes");
        if(hmacKey == null || hmacKey.length != 32)
            throw new IllegalArgumentException("hmacKey must be 32 bytes");
        this.keyName = keyName;
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
    }
}
