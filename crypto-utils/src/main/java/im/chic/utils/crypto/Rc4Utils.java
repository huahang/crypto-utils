package im.chic.utils.crypto;

import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.KeyGenerationParameters;
import org.spongycastle.crypto.StreamCipher;
import org.spongycastle.crypto.engines.RC4Engine;
import org.spongycastle.crypto.io.CipherInputStream;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;


/**
 * Rc4Utils: Utils for RC4 encryption/decryption
 *
 * @author huahang
 */
public class Rc4Utils {

    /**
     * Generates a 128-bit key (16 bytes) randomly for RC4 encryption/decryption.
     *
     * @return generated key bytes
     */
    public static byte[] generateKey() {
        CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();
        cipherKeyGenerator.init(new KeyGenerationParameters(new SecureRandom(), 128));
        return cipherKeyGenerator.generateKey();
    }


    /**
     * Encrypt data bytes using RC4
     *
     * @param data data bytes to be encrypted
     * @param key  rc4 key (40..2048 bits)
     * @return encrypted data bytes
     */
    public static byte[] encrypt(byte[] data, byte[] key) {
        checkNotNull(data);
        checkNotNull(key);
        checkArgument(key.length >= 5 && key.length <= 256);
        StreamCipher rc4 = new RC4Engine();
        rc4.init(true, new KeyParameter(key));
        byte[] encrypted = new byte[data.length];
        rc4.processBytes(data, 0, data.length, encrypted, 0);
        return encrypted;
    }

    /**
     * Encrypt output stream using RC4
     *
     * @param outputStream output stream to be encrypted
     * @param key          rc4 key (40..2048 bits)
     * @return encrypted output stream
     */
    public static OutputStream encrypt(OutputStream outputStream, byte[] key) {
        checkNotNull(outputStream);
        checkNotNull(key);
        checkArgument(key.length >= 5 && key.length <= 256);
        StreamCipher rc4 = new RC4Engine();
        rc4.init(true, new KeyParameter(key));
        return new CipherOutputStream(outputStream, rc4);
    }

    /**
     * Decrypt data bytes using RC4
     *
     * @param data data bytes to be decrypted
     * @param key  rc4 key (40..2048 bits)
     * @return decrypted data bytes
     */
    public static byte[] decrypt(byte[] data, byte[] key) {
        checkNotNull(data);
        checkNotNull(key);
        checkArgument(key.length >= 5 && key.length <= 256);
        StreamCipher rc4 = new RC4Engine();
        rc4.init(false, new KeyParameter(key));
        byte[] decrypted = new byte[data.length];
        rc4.processBytes(data, 0, data.length, decrypted, 0);
        return decrypted;
    }


    /**
     * Decrypt input stream using RC4
     *
     * @param inputStream input stream to be decrypted
     * @param key         rc4 key (40..2048 bits)
     * @return decrypted input stream
     */
    public static InputStream decrypt(InputStream inputStream, byte[] key) {
        checkNotNull(inputStream);
        checkNotNull(key);
        checkArgument(key.length >= 5 && key.length <= 256);
        StreamCipher rc4 = new RC4Engine();
        rc4.init(false, new KeyParameter(key));
        return new CipherInputStream(inputStream, rc4);
    }

}
