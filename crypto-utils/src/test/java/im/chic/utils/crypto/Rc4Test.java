package im.chic.utils.crypto;

import com.google.common.io.ByteStreams;
import com.google.common.io.Closer;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.*;

@RunWith(JUnit4.class)
public class Rc4Test {

    @Test
    public void testRc4() throws IOException {
        Closer closer = Closer.create();
        try {
            // generate random input data
            byte[] randomData = TestUtils.randomBytes(4 * 1024 * 1024, false);
            InputStream randomInputStream = new ByteArrayInputStream(randomData);
            closer.register(randomInputStream);
            // generate cipher key
            byte[] keyBytes = Rc4Utils.generateKey();
            // encrypt and write
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            closer.register(byteArrayOutputStream);
            OutputStream encryptedOutputStream = Rc4Utils.encrypt(byteArrayOutputStream, keyBytes);
            closer.register(encryptedOutputStream);
            ByteStreams.copy(randomInputStream, encryptedOutputStream);
            byte[] encryptedBytes = byteArrayOutputStream.toByteArray();
            // read and decrypt
            InputStream encryptedInputStream = new ByteArrayInputStream(encryptedBytes);
            closer.register(encryptedInputStream);
            InputStream decryptedInputStream = Rc4Utils.decrypt(encryptedInputStream, keyBytes);
            closer.register(decryptedInputStream);
            byte[] decryptedData = ByteStreams.toByteArray(decryptedInputStream);
            // checking data
            Assert.assertArrayEquals(randomData, decryptedData);
            Assert.assertArrayEquals(Rc4Utils.encrypt(randomData, keyBytes), encryptedBytes);
            Assert.assertArrayEquals(Rc4Utils.decrypt(encryptedBytes, keyBytes), randomData);
        } catch (Throwable t) {
            closer.rethrow(t);
        } finally {
            closer.close();
        }
    }

    @Test
    public void testRc4WithEmptyData() throws IOException {
        Closer closer = Closer.create();
        try {
            // generate random input data
            byte[] randomData = TestUtils.randomBytes(0, true);
            InputStream randomInputStream = new ByteArrayInputStream(randomData);
            closer.register(randomInputStream);
            // generate cipher key
            byte[] keyBytes = Rc4Utils.generateKey();
            // encrypt and write
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            closer.register(byteArrayOutputStream);
            OutputStream encryptedOutputStream = Rc4Utils.encrypt(byteArrayOutputStream, keyBytes);
            closer.register(encryptedOutputStream);
            ByteStreams.copy(randomInputStream, encryptedOutputStream);
            byte[] encryptedBytes = byteArrayOutputStream.toByteArray();
            // read and decrypt
            InputStream encryptedInputStream = new ByteArrayInputStream(encryptedBytes);
            closer.register(encryptedInputStream);
            InputStream decryptedInputStream = Rc4Utils.decrypt(encryptedInputStream, keyBytes);
            closer.register(decryptedInputStream);
            byte[] decryptedData = ByteStreams.toByteArray(decryptedInputStream);
            // checking data
            Assert.assertArrayEquals(randomData, decryptedData);
            Assert.assertArrayEquals(Rc4Utils.encrypt(randomData, keyBytes), encryptedBytes);
            Assert.assertArrayEquals(Rc4Utils.decrypt(encryptedBytes, keyBytes), randomData);
        } catch (Throwable t) {
            closer.rethrow(t);
        } finally {
            closer.close();
        }
    }

}
