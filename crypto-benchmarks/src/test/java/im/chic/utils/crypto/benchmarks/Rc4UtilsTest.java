package im.chic.utils.crypto.benchmarks;

import com.google.common.io.ByteStreams;
import im.chic.utils.crypto.AesUtils;
import im.chic.utils.crypto.Rc4Utils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.*;
import java.security.GeneralSecurityException;


@RunWith(JUnit4.class)
public class Rc4UtilsTest {

    @Test
    public void testRc4() throws GeneralSecurityException, IOException {
        testRc4Impl1(TestUtils.randomBytes(0, true));
        testRc4Impl1(TestUtils.randomBytes(1, true));
        testRc4Impl1(TestUtils.randomBytes(2, true));
        testRc4Impl1(TestUtils.randomBytes(3, true));

        testRc4Impl1(TestUtils.randomBytes(1024 * 1024, false));

        testRc4Impl2(TestUtils.randomBytes(0, true));
        testRc4Impl2(TestUtils.randomBytes(1, true));
        testRc4Impl2(TestUtils.randomBytes(2, true));
        testRc4Impl2(TestUtils.randomBytes(3, true));

        testRc4Impl2(TestUtils.randomBytes(1024 * 1024, false));
    }

    public void testRc4Impl1(byte[] data) throws GeneralSecurityException, IOException {
        byte[] keyBytes = AesUtils.generateKey();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream = Rc4Utils_JCE.encrypt(outputStream, keyBytes);
        cipherOutputStream.write(data);
        cipherOutputStream.close();
        byte[] cipherData = outputStream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(cipherData);
        InputStream cipherInputStream = Rc4Utils.decrypt(inputStream, keyBytes);
        Assert.assertArrayEquals(data, ByteStreams.toByteArray(cipherInputStream));
    }

    public void testRc4Impl2(byte[] data) throws GeneralSecurityException, IOException {
        byte[] keyBytes = AesUtils.generateKey();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream = Rc4Utils.encrypt(outputStream, keyBytes);
        cipherOutputStream.write(data);
        cipherOutputStream.close();
        byte[] cipherData = outputStream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(cipherData);
        InputStream cipherInputStream = Rc4Utils_JCE.decrypt(inputStream, keyBytes);
        Assert.assertArrayEquals(data, ByteStreams.toByteArray(cipherInputStream));
    }

}
