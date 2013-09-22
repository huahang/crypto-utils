package im.chic.utils.crypto.benchmarks;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.google.common.base.Preconditions.checkNotNull;

public class DigestUtils_JCE {

    private static final int BUFFER_SIZE = 65536;

    public static byte[] sha1(InputStream is) throws IOException, NoSuchAlgorithmException {
        checkNotNull(is);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
        int n = 0;
        byte[] buffer = new byte[BUFFER_SIZE];
        while (n >= 0) {
            n = is.read(buffer);
            if (n > 0) {
                messageDigest.update(buffer, 0, n);
            }
        }
        return messageDigest.digest();
    }

}
