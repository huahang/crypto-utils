package im.chic.utils.crypto;

import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.Closer;
import com.google.common.io.Files;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

@RunWith(JUnit4.class)
public class DigestUtilsTest {

    static private void sha1Test(File file, String expectedSha1Hex) throws IOException {
        byte[] expectedSha1Bytes = BaseEncoding.base16().decode(expectedSha1Hex);
        Closer closer = Closer.create();
        try {
            // read bytes
            ByteSource byteSource = Files.asByteSource(file);
            byte[] bytes = byteSource.read();
            // test 1: sha1 bytes of input stream
            InputStream inputStream = new FileInputStream(file);
            closer.register(inputStream);
            byte[] sha1Bytes = DigestUtils.sha1(inputStream);
            Assert.assertArrayEquals(expectedSha1Bytes, sha1Bytes);
            // test 2: sha1 hex of input stream
            inputStream = new FileInputStream(file);
            closer.register(inputStream);
            String sha1Hex = DigestUtils.sha1Hex(inputStream);
            Assert.assertEquals(expectedSha1Hex, sha1Hex);
            // test 3: sha1 bytes of input bytes
            sha1Bytes = DigestUtils.sha1(bytes);
            Assert.assertArrayEquals(expectedSha1Bytes, sha1Bytes);
            // test 4: sha1 hex of input bytes
            sha1Hex = DigestUtils.sha1Hex(bytes);
            Assert.assertEquals(expectedSha1Hex, sha1Hex);
        } catch (Throwable t) {
            closer.rethrow(t);
        } finally {
            closer.close();
        }
    }

    @Test
    public void testLenaSha1() throws IOException {
        URL url = getClass().getResource("/lena_std.tif");
        File file = new File(url.getPath());
        sha1Test(file, "e647d0f6736f82e498de8398eccc48cf0a7d53b9".toUpperCase());
    }

    @Test
    public void testEmptySha1() throws IOException {
        URL url = getClass().getResource("/empty_file");
        File file = new File(url.getPath());
        sha1Test(file, "da39a3ee5e6b4b0d3255bfef95601890afd80709".toUpperCase());
    }

}
