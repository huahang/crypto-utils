package im.chic.utils.crypto.benchmarks;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkNotNull;

public class Rc4Utils_JCE {

    public static OutputStream encrypt(OutputStream outputStream, byte[] key) throws GeneralSecurityException {
        checkNotNull(outputStream);
        checkNotNull(key);
        final Cipher cipher = Cipher.getInstance("RC4");
        SecretKeySpec keySpec = new SecretKeySpec(key, "RC4");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return new CipherOutputStream(outputStream, cipher);
    }


    public static InputStream decrypt(InputStream inputStream, byte[] key) throws GeneralSecurityException {
        checkNotNull(inputStream);
        checkNotNull(key);
        final Cipher cipher = Cipher.getInstance("RC4");
        SecretKeySpec skeySpec = new SecretKeySpec(key, "RC4");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        return new CipherInputStream(inputStream, cipher);
    }

}
