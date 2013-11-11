package im.chic.utils.crypto;

import com.google.common.io.ByteStreams;
import com.google.common.io.Closer;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.spongycastle.crypto.InvalidCipherTextException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.GeneralSecurityException;

@RunWith(JUnit4.class)
public class AesUtilsTest {

    @Test
    public void testAes() throws GeneralSecurityException, InvalidCipherTextException, IOException {
        for (int i = 0; i < 3; ++i) {
            testAesEcbPkcs5(TestUtils.randomBytes(1 * 1024 * 1024, false));
            testAesCbcPkcs5(TestUtils.randomBytes(1 * 1024 * 1024, false));
            testAesEcbPkcs5(TestUtils.randomBytes(0, true));
            testAesCbcPkcs5(TestUtils.randomBytes(0, true));
            testAesEcbPkcs5(TestUtils.randomBytes(1, true));
            testAesCbcPkcs5(TestUtils.randomBytes(1, true));
            testAesEcbPkcs5(TestUtils.randomBytes(2, true));
            testAesCbcPkcs5(TestUtils.randomBytes(2, true));
        }
    }

    @Test
    public void testAes2() throws GeneralSecurityException, InvalidCipherTextException, IOException {
        testAesCbcPkcs5(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 3, 3, 3});
    }

    public void testAesEcbPkcs5(byte[] data) throws GeneralSecurityException, InvalidCipherTextException, IOException {
        // generate key
        byte[] keyBytes = AesUtils.generateKey();
        Assert.assertEquals(16, keyBytes.length);
        // encode with java
        String AES_ALGORITHM = "AES/ECB/PKCS5Padding";
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(data);
        // encode with bouncy castle
        Assert.assertArrayEquals(encryptedBytes, AesUtils.encrypt(data, keyBytes));
        // decode with java
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        Assert.assertArrayEquals(data, cipher.doFinal(encryptedBytes));
        // decode with bouncy castle
        Assert.assertArrayEquals(data, AesUtils.decrypt(encryptedBytes, keyBytes));

        // testing streaming apis
        Closer closer = Closer.create();
        try {
            // encrypt and write
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            closer.register(outputStream);
            OutputStream encryptedOutputStream = AesUtils.encrypt(outputStream, keyBytes);
            closer.register(encryptedOutputStream);
            encryptedOutputStream.write(data);
            encryptedOutputStream.flush();
            // encryptedOutputStream is fully written only if it is closed
            encryptedOutputStream.close();
            // read and decrypt
            ByteArrayInputStream encryptedInputStream = new ByteArrayInputStream(encryptedBytes);
            closer.register(encryptedInputStream);
            InputStream decryptedInputStream = AesUtils.decrypt(encryptedInputStream, keyBytes);
            closer.register(decryptedInputStream);
            // verify data
            Assert.assertArrayEquals(encryptedBytes, outputStream.toByteArray());
            Assert.assertArrayEquals(data, ByteStreams.toByteArray(decryptedInputStream));
        } catch (Throwable t) {
            closer.rethrow(t);
        } finally {
            closer.close();
        }
    }

    public void testAesCbcPkcs5(byte[] data) throws GeneralSecurityException, InvalidCipherTextException, IOException {
        // generate key & iv
        byte[] keyBytes = AesUtils.generateKey();
        byte[] ivBytes = AesUtils.generateKey();
        Assert.assertEquals(16, keyBytes.length);
        Assert.assertEquals(16, ivBytes.length);
        // encode with java
        String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(data);
        // encode with bouncy castle
        Assert.assertArrayEquals(encryptedBytes, AesUtils.encrypt(data, keyBytes, ivBytes));
        // decode with java
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        Assert.assertArrayEquals(data, cipher.doFinal(encryptedBytes));
        // decode with bouncy castle
        Assert.assertArrayEquals(data, AesUtils.decrypt(encryptedBytes, keyBytes, ivBytes));

        // testing streaming apis
        Closer closer = Closer.create();
        try {
            // encrypt and write
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            closer.register(outputStream);
            OutputStream encryptedOutputStream = AesUtils.encrypt(outputStream, keyBytes, ivBytes);
            closer.register(encryptedOutputStream);
            encryptedOutputStream.write(data);
            encryptedOutputStream.flush();
            // encryptedOutputStream is fully written only if it is closed
            encryptedOutputStream.close();
            // read and decrypt
            ByteArrayInputStream encryptedInputStream = new ByteArrayInputStream(encryptedBytes);
            closer.register(encryptedInputStream);
            InputStream decryptedInputStream = AesUtils.decrypt(encryptedInputStream, keyBytes, ivBytes);
            closer.register(decryptedInputStream);
            // verify data
            Assert.assertArrayEquals(encryptedBytes, outputStream.toByteArray());
            Assert.assertArrayEquals(data, ByteStreams.toByteArray(decryptedInputStream));
        } catch (Throwable t) {
            closer.rethrow(t);
        } finally {
            closer.close();
        }
    }

}
