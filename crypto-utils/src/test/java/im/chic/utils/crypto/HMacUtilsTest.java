package im.chic.utils.crypto;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@RunWith(JUnit4.class)
public class HMacUtilsTest {

    @Test
    public void testHmacSHA1() throws NoSuchAlgorithmException, InvalidKeyException {
        // generate key
        KeyGenerator keygen = KeyGenerator.getInstance("HmacSHA1");
        SecretKey key = keygen.generateKey();
        // generate data
        byte[] data = TestUtils.randomBytes(1024 * 1024, false);
        // perform tests
        testHmacSHA1Impl(data, key.getEncoded());
        testHmacSHA1Impl(new byte[0], key.getEncoded());
        testHmacSHA1Impl(data, TestUtils.randomBytes(1024, true));
        testHmacSHA1Impl(new byte[0], TestUtils.randomBytes(1024, true));
        testHmacSHA1Impl(data, TestUtils.randomBytes(1, true));
        testHmacSHA1Impl(new byte[0], TestUtils.randomBytes(1, true));
        testHmacSHA1Impl(data, TestUtils.randomBytes(17, true));
        testHmacSHA1Impl(new byte[0], TestUtils.randomBytes(17, true));
    }

    private void testHmacSHA1Impl(byte[] data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        // generate mac using java
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] bytes = mac.doFinal(data);
        // generate mac using bouncy castle
        Assert.assertArrayEquals(bytes, HMacUtils.hmacSHA1(data, key));
    }
}
