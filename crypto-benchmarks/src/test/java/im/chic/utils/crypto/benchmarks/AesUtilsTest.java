package im.chic.utils.crypto.benchmarks;

import com.google.common.io.ByteStreams;
import im.chic.utils.crypto.AesUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.*;
import java.security.GeneralSecurityException;

public class AesUtilsTest {

    @Test
    public void testAesEcb() throws GeneralSecurityException, IOException {

        testAesEcbImpl1(TestUtils.randomBytes(0, true));
        testAesEcbImpl1(TestUtils.randomBytes(1, true));
        testAesEcbImpl1(TestUtils.randomBytes(2, true));
        testAesEcbImpl1(TestUtils.randomBytes(3, true));

        testAesEcbImpl1(TestUtils.randomBytes(1024 * 1024, false));

        testAesEcbImpl2(TestUtils.randomBytes(0, true));
        testAesEcbImpl2(TestUtils.randomBytes(1, true));
        testAesEcbImpl2(TestUtils.randomBytes(2, true));
        testAesEcbImpl2(TestUtils.randomBytes(3, true));

        testAesEcbImpl2(TestUtils.randomBytes(1024 * 1024, false));

    }

    @Test
    public void testAesCbc() throws GeneralSecurityException, IOException {

        testAesCbcImpl1(TestUtils.randomBytes(0, true));
        testAesCbcImpl1(TestUtils.randomBytes(1, true));
        testAesCbcImpl1(TestUtils.randomBytes(2, true));
        testAesCbcImpl1(TestUtils.randomBytes(3, true));

        testAesCbcImpl1(TestUtils.randomBytes(1024 * 1024, false));

        testAesCbcImpl2(TestUtils.randomBytes(0, true));
        testAesCbcImpl2(TestUtils.randomBytes(1, true));
        testAesCbcImpl2(TestUtils.randomBytes(2, true));
        testAesCbcImpl2(TestUtils.randomBytes(3, true));

        testAesCbcImpl2(TestUtils.randomBytes(1024 * 1024, false));

    }

    public void testAesEcbImpl1(byte[] data) throws GeneralSecurityException, IOException {
        byte[] keyBytes = AesUtils.generateKey();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream = AesUtils_JCE.encrypt(outputStream, keyBytes);
        cipherOutputStream.write(data);
        cipherOutputStream.close();
        byte[] cipherData = outputStream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(cipherData);
        InputStream cipherInputStream = AesUtils.decrypt(inputStream, keyBytes);
        Assert.assertArrayEquals(data, ByteStreams.toByteArray(cipherInputStream));
    }

    public void testAesEcbImpl2(byte[] data) throws GeneralSecurityException, IOException {
        byte[] keyBytes = AesUtils.generateKey();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream = AesUtils.encrypt(outputStream, keyBytes);
        cipherOutputStream.write(data);
        cipherOutputStream.close();
        byte[] cipherData = outputStream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(cipherData);
        InputStream cipherInputStream = AesUtils_JCE.decrypt(inputStream, keyBytes);
        Assert.assertArrayEquals(data, ByteStreams.toByteArray(cipherInputStream));
    }

    public void testAesCbcImpl1(byte[] data) throws GeneralSecurityException, IOException {
        byte[] keyBytes = AesUtils.generateKey();
        byte[] ivBytes = AesUtils.generateKey();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream = AesUtils_JCE.encrypt(outputStream, keyBytes, ivBytes);
        cipherOutputStream.write(data);
        cipherOutputStream.close();
        byte[] cipherData = outputStream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(cipherData);
        InputStream cipherInputStream = AesUtils.decrypt(inputStream, keyBytes, ivBytes);
        Assert.assertArrayEquals(data, ByteStreams.toByteArray(cipherInputStream));
    }

    public void testAesCbcImpl2(byte[] data) throws GeneralSecurityException, IOException {
        byte[] keyBytes = AesUtils.generateKey();
        byte[] ivBytes = AesUtils.generateKey();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream = AesUtils.encrypt(outputStream, keyBytes, ivBytes);
        cipherOutputStream.write(data);
        cipherOutputStream.close();
        byte[] cipherData = outputStream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(cipherData);
        InputStream cipherInputStream = AesUtils_JCE.decrypt(inputStream, keyBytes, ivBytes);
        Assert.assertArrayEquals(data, ByteStreams.toByteArray(cipherInputStream));
    }
}
