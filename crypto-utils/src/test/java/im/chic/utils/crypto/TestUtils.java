package im.chic.utils.crypto;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Random;

public class TestUtils {

    public static byte[] randomBytes(int maxLength, boolean fixedLength) {
        Random random = new Random();
        int length = fixedLength ? maxLength : Math.abs(random.nextInt()) % maxLength;
        byte[] result = new byte[length];
        random.nextBytes(result);
        return result;
    }

    public static InputStream randomInputStream(int maxLength, boolean fixedLength) {
        byte[] bytes = randomBytes(maxLength, fixedLength);
        return new ByteArrayInputStream(bytes);
    }

}
