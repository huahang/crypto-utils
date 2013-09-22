package im.chic.utils.crypto;

import com.google.common.io.BaseEncoding;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;

import java.io.IOException;
import java.io.InputStream;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * DigestUtils: Some helpers to compute message digest.
 *
 * @author huahang
 */
public class DigestUtils {

    /**
     * buffer size 64k *
     */
    private static final int BUFFER_SIZE = 65536;

    /**
     * Calculates the SHA-1 digest and returns the value as a byte[].
     *
     * @param is input stream
     * @return SHA-1 digest as a byte[]
     * @throws IOException On error reading from the stream.
     */
    public static byte[] sha1(InputStream is) throws IOException {
        checkNotNull(is);
        Digest digest = new SHA1Digest();
        int n = 0;
        byte[] buffer = new byte[BUFFER_SIZE];
        while (n >= 0) {
            n = is.read(buffer);
            if (n > 0) {
                digest.update(buffer, 0, n);
            }
        }
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    /**
     * Calculates the SHA-1 digest and returns the value as a hex string.
     *
     * @param is input stream
     * @return SHA-1 digest as a hex string
     * @throws IOException On error reading from the stream
     */
    public static String sha1Hex(InputStream is) throws IOException {
        checkNotNull(is);
        byte[] sha1Bytes = sha1(is);
        return BaseEncoding.base16().encode(sha1Bytes);
    }

    /**
     * Calculates the SHA-1 digest and returns the value as a byte[].
     *
     * @param input input bytes
     * @return SHA-1 digest as a byte[]
     */
    public static byte[] sha1(byte[] input) {
        checkNotNull(input);
        Digest digest = new SHA1Digest();
        digest.update(input, 0, input.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    /**
     * Calculates the SHA-1 digest and returns the value as a hex string.
     *
     * @param input input bytes
     * @return SHA-1 digest as a hex string
     */
    public static String sha1Hex(byte[] input) {
        checkNotNull(input);
        byte[] sha1Bytes = sha1(input);
        return BaseEncoding.base16().encode(sha1Bytes);
    }

}
