package im.chic.utils.crypto.benchmarks;

import im.chic.utils.crypto.DigestUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class DigestBenchmark {
    // 8 Megabytes * 128 Rounds = 1 Gigabyte
    static final int SIZE = 8 * 1024 * 1024;
    static final int ROUND = 128;

    public static String runSha1() throws IOException, GeneralSecurityException {
        String message = "SHA1 SC\n";
        byte[] bytes = TestUtils.randomBytes(SIZE, true);

        int dummy = 0;

        long t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
            byte[] sha1Bytes = DigestUtils.sha1(byteArrayInputStream);
            dummy |= sha1Bytes.length;
        }
        long t1 = System.nanoTime();
        long duration = t1 - t0;
        double sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        double rate = 1024.0f / sec;
        message += String.format("1G data hashed in %f seconds. %f MB/s.\n", sec, rate);

        return message;
    }

    public static String runSha1_JCE() throws IOException, GeneralSecurityException {
        String message = "SHA1 JCE\n";
        byte[] bytes = TestUtils.randomBytes(SIZE, true);

        int dummy = 0;

        long t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
            byte[] sha1Bytes = DigestUtils_JCE.sha1(byteArrayInputStream);
            dummy |= sha1Bytes.length;
        }
        long t1 = System.nanoTime();
        long duration = t1 - t0;
        double sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        double rate = 1024.0f / sec;
        message += String.format("1G data hashed in %f seconds. %f MB/s.\n", sec, rate);

        return message;
    }


}
