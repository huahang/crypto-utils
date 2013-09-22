package im.chic.utils.crypto.benchmarks;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkNotNull;

public class AesUtils_JCE {

    public static OutputStream encrypt(OutputStream outputStream, byte[] key) throws GeneralSecurityException {
        checkNotNull(outputStream);
        checkNotNull(key);
        final Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return new CipherOutputStream(outputStream, cipher);
    }


    public static InputStream decrypt(InputStream inputStream, byte[] key) throws GeneralSecurityException {
        checkNotNull(inputStream);
        checkNotNull(key);
        final Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        return new CipherInputStream(inputStream, cipher);
    }

    public static OutputStream encrypt(OutputStream outputStream, byte[] key, byte[] iv) throws GeneralSecurityException {
        checkNotNull(outputStream);
        checkNotNull(key);
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return new CipherOutputStream(outputStream, cipher);
    }

    public static InputStream decrypt(InputStream inputStream, byte[] key, byte[] iv) throws GeneralSecurityException {
        checkNotNull(inputStream);
        checkNotNull(key);
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return new CipherInputStream(inputStream, cipher);
    }

}
