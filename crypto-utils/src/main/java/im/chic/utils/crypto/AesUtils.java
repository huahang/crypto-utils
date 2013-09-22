package im.chic.utils.crypto;

import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.KeyGenerationParameters;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.io.CipherInputStream;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PKCS7Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * AesUtils: Some helpers to do AES encryption and decryption.
 *
 * @author huahang
 */
public class AesUtils {

    /**
     * Generates a 128-bit key (16 bytes) randomly for AES encryption/decryption
     * as the key or iv.
     * <p/>
     * Note that AES 192 or AES 256 is not as secure as AES 128.
     *
     * @return generated key bytes
     */
    public static byte[] generateKey() {
        CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();
        cipherKeyGenerator.init(new KeyGenerationParameters(new SecureRandom(), 128));
        return cipherKeyGenerator.generateKey();
    }

    /**
     * AES/ECB/PKCS5Padding Encryption
     *
     * @param data data to encrypt
     * @param key  valid AES key sizes are 128, 192, or 256 bits (16, 24, or 32 bytes).
     * @return bytes encrypted
     * @throws InvalidCipherTextException thrown if padding is expected and not found
     */
    public static byte[] encrypt(byte[] data, byte[] key) throws InvalidCipherTextException {
        checkNotNull(data);
        checkNotNull(key);
        AESFastEngine aesEngine = new AESFastEngine();
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(aesEngine, new PKCS7Padding());
        cipher.init(true, new KeyParameter(key));
        byte[] outBuf = new byte[cipher.getOutputSize(data.length)];
        int l1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
        int l2 = cipher.doFinal(outBuf, l1);
        byte[] result;
        if (outBuf.length != l1 + l2) {
            result = new byte[l1 + l2];
            System.arraycopy(outBuf, 0, result, 0, result.length);
        } else
            result = outBuf;
        return result;
    }

    /**
     * AES/ECB/PKCS5Padding Encryption
     *
     * @param outputStream output stream to be encrypted
     * @param key          valid AES key sizes are 128, 192, or 256 bits (16, 24, or 32 bytes).
     * @return encrypted output stream
     */
    public static OutputStream encrypt(OutputStream outputStream, byte[] key) {
        checkNotNull(outputStream);
        checkNotNull(key);
        AESFastEngine aesEngine = new AESFastEngine();
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(aesEngine, new PKCS7Padding());
        cipher.init(true, new KeyParameter(key));
        return new CipherOutputStream(outputStream, cipher);
    }

    /**
     * AES/ECB/PKCS5Padding Decryption
     *
     * @param data data to decrypt
     * @param key  valid AES key sizes are 128, 192, or 256 bits (16, 24, or 32 bytes).
     * @return bytes decrypted
     * @throws InvalidCipherTextException thrown if padding is expected and not found
     */
    public static byte[] decrypt(byte[] data, byte[] key) throws InvalidCipherTextException {
        checkNotNull(data);
        checkNotNull(key);
        AESFastEngine aesEngine = new AESFastEngine();
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(aesEngine, new PKCS7Padding());
        cipher.init(false, new KeyParameter(key));
        byte[] outBuf = new byte[cipher.getOutputSize(data.length)];
        int l1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
        int l2 = cipher.doFinal(outBuf, l1);
        byte[] result;
        if (outBuf.length != l1 + l2) {
            result = new byte[l1 + l2];
            System.arraycopy(outBuf, 0, result, 0, result.length);
        } else
            result = outBuf;
        return result;
    }

    /**
     * AES/ECB/PKCS5Padding Decryption
     *
     * @param inputStream input stream to be decrypted
     * @param key         valid AES key sizes are 128, 192, or 256 bits (16, 24, or 32 bytes).
     * @return decrypted input stream
     */
    public static InputStream decrypt(InputStream inputStream, byte[] key) {
        checkNotNull(inputStream);
        checkNotNull(key);
        AESFastEngine aesEngine = new AESFastEngine();
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(aesEngine, new PKCS7Padding());
        cipher.init(false, new KeyParameter(key));
        return new CipherInputStream(inputStream, cipher);
    }

    /**
     * AES/CBC/PKCS5Padding Encryption
     *
     * @param data data to encrypt
     * @param key  valid AES key sizes are 128, 192, or 256 bits (16, 24, or 32 bytes).
     * @param iv   AES initialization vector. Must be the same size as the key.
     * @return bytes encrypted
     * @throws InvalidCipherTextException thrown if padding is expected and not found
     */
    public static byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws InvalidCipherTextException {
        checkNotNull(data);
        checkNotNull(key);
        checkNotNull(iv);
        checkArgument(key.length == iv.length);
        AESFastEngine aesEngine = new AESFastEngine();
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(new CBCBlockCipher(aesEngine), new PKCS7Padding());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] outBuf = new byte[cipher.getOutputSize(data.length)];
        int l1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
        int l2 = cipher.doFinal(outBuf, l1);
        byte[] result;
        if (outBuf.length != l1 + l2) {
            result = new byte[l1 + l2];
            System.arraycopy(outBuf, 0, result, 0, result.length);
        } else
            result = outBuf;
        return result;
    }

    /**
     * AES/CBC/PKCS5Padding Encryption
     *
     * @param outputStream output stream to be encrypted
     * @param key          valid AES key sizes are 128, 192, or 256 bits (16, 24, or 32 bytes).
     * @param iv           AES initialization vector. Must be the same size as the key.
     * @return encrypted output stream
     */
    public static OutputStream encrypt(OutputStream outputStream, byte[] key, byte[] iv) {
        checkNotNull(outputStream);
        checkNotNull(key);
        checkNotNull(iv);
        checkArgument(key.length == iv.length);
        AESFastEngine aesEngine = new AESFastEngine();
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(new CBCBlockCipher(aesEngine), new PKCS7Padding());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        return new CipherOutputStream(outputStream, cipher);
    }

    /**
     * AES/CBC/PKCS5Padding Decryption
     *
     * @param data data to decrypt
     * @param key  valid AES key sizes are 128, 192, or 256 bits (16, 24, or 32 bytes).
     * @param iv   AES initialization vector. Must be the same size as the key.
     * @return bytes decrypted
     * @throws InvalidCipherTextException thrown if padding is expected and not found
     */
    public static byte[] decrypt(byte[] data, byte[] key, byte[] iv) throws InvalidCipherTextException {
        checkNotNull(data);
        checkNotNull(key);
        checkNotNull(iv);
        checkArgument(key.length == iv.length);
        AESFastEngine aesEngine = new AESFastEngine();
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(new CBCBlockCipher(aesEngine), new PKCS7Padding());
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] outBuf = new byte[cipher.getOutputSize(data.length)];
        int l1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
        int l2 = cipher.doFinal(outBuf, l1);
        byte[] result;
        if (outBuf.length != l1 + l2) {
            result = new byte[l1 + l2];
            System.arraycopy(outBuf, 0, result, 0, result.length);
        } else
            result = outBuf;
        return result;
    }

    /**
     * AES/CBC/PKCS5Padding Decryption
     *
     * @param inputStream input stream to be decrypted
     * @param key         valid AES key sizes are 128, 192, or 256 bits (16, 24, or 32 bytes).
     * @param iv          AES initialization vector. Must be the same size as the key.
     * @return decrypted input stream
     */
    public static InputStream decrypt(InputStream inputStream, byte[] key, byte[] iv) {
        checkNotNull(inputStream);
        checkNotNull(key);
        checkNotNull(iv);
        checkArgument(key.length == iv.length);
        AESFastEngine aesEngine = new AESFastEngine();
        PaddedBufferedBlockCipher cipher =
                new PaddedBufferedBlockCipher(new CBCBlockCipher(aesEngine), new PKCS7Padding());
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        return new CipherInputStream(inputStream, cipher);
    }

}
