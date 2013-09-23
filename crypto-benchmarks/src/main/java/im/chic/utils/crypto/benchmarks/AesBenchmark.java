package im.chic.utils.crypto.benchmarks;

import com.google.common.io.ByteStreams;
import im.chic.utils.crypto.AesUtils;

import java.io.*;
import java.security.GeneralSecurityException;

public class AesBenchmark {

    // 1 Megabytes * 100 Rounds = 100 Megabytes
    static final int SIZE = 1 * 1024 * 1024;
    static final int ROUND = 100;

    public static String runAesEcbPkcs5() throws IOException, GeneralSecurityException {
        String message = "AES/ECB/PKCS5Padding SC\n";
        byte[] key = AesUtils.generateKey();
        byte[] bytes = TestUtils.randomBytes(SIZE, true);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream;
        int dummy = 0;

        long t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            byteArrayOutputStream.reset();
            cipherOutputStream = AesUtils.encrypt(byteArrayOutputStream, key);
            cipherOutputStream.write(bytes);
            cipherOutputStream.close();
            dummy |= cipherOutputStream.hashCode();
            dummy |= byteArrayOutputStream.hashCode();
        }
        long t1 = System.nanoTime();
        long duration = t1 - t0;
        double sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        double rate = 100.0f / sec;
        message += String.format("100M data encrypted in %f seconds. %f MB/s.\n", sec, rate);

        byte[] cipherData = byteArrayOutputStream.toByteArray();
        byte[] buffer = new byte[cipherData.length * 2];
        t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            InputStream inputStream = new ByteArrayInputStream(cipherData);
            InputStream cipherInputStream = AesUtils.decrypt(inputStream, key);
            dummy |= ByteStreams.read(cipherInputStream, buffer, 0, buffer.length);
        }
        t1 = System.nanoTime();
        duration = t1 - t0;
        sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        rate = 100.0f / sec;
        message += String.format("100M data decrypted in %f seconds. %f MB/s.\n", sec, rate);

        return message;
    }

    public static String runAesEcbPkcs5_JCE() throws IOException, GeneralSecurityException {
        String message = "AES/ECB/PKCS5Padding JCE\n";
        byte[] key = AesUtils.generateKey();
        byte[] bytes = TestUtils.randomBytes(SIZE, true);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream;
        int dummy = 0;

        long t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            byteArrayOutputStream.reset();
            cipherOutputStream = AesUtils_JCE.encrypt(byteArrayOutputStream, key);
            cipherOutputStream.write(bytes);
            cipherOutputStream.close();
            dummy |= cipherOutputStream.hashCode();
            dummy |= byteArrayOutputStream.hashCode();
        }
        long t1 = System.nanoTime();
        long duration = t1 - t0;
        double sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        double rate = 100.0f / sec;
        message += String.format("100M data encrypted in %f seconds. %f MB/s.\n", sec, rate);

        byte[] cipherData = byteArrayOutputStream.toByteArray();
        byte[] buffer = new byte[cipherData.length*2];
        t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            InputStream inputStream = new ByteArrayInputStream(cipherData);
            InputStream cipherInputStream = AesUtils_JCE.decrypt(inputStream, key);
            dummy |= ByteStreams.read(cipherInputStream, buffer, 0, buffer.length);
        }
        t1 = System.nanoTime();
        duration = t1 - t0;
        sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        rate = 100.0f / sec;
        message += String.format("100M data decrypted in %f seconds. %f MB/s.\n", sec, rate);

        return message;
    }

    public static String runAesCbcPkcs5() throws IOException, GeneralSecurityException {
        String message = "AES/CBC/PKCS5Padding SC\n";
        byte[] key = AesUtils.generateKey();
        byte[] iv = AesUtils.generateKey();
        byte[] bytes = TestUtils.randomBytes(SIZE, true);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream;
        int dummy = 0;

        long t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            byteArrayOutputStream.reset();
            cipherOutputStream = AesUtils.encrypt(byteArrayOutputStream, key, iv);
            cipherOutputStream.write(bytes);
            cipherOutputStream.close();
            dummy |= cipherOutputStream.hashCode();
            dummy |= byteArrayOutputStream.hashCode();
        }
        long t1 = System.nanoTime();
        long duration = t1 - t0;
        double sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        double rate = 100.0f / sec;
        message += String.format("100M data encrypted in %f seconds. %f MB/s.\n", sec, rate);

        byte[] cipherData = byteArrayOutputStream.toByteArray();
        byte[] buffer = new byte[cipherData.length*2];
        t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            InputStream inputStream = new ByteArrayInputStream(cipherData);
            InputStream cipherInputStream = AesUtils.decrypt(inputStream, key, iv);
            dummy |= ByteStreams.read(cipherInputStream, buffer, 0, buffer.length);
        }
        t1 = System.nanoTime();
        duration = t1 - t0;
        sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        rate = 100.0f / sec;
        message += String.format("100M data decrypted in %f seconds. %f MB/s.\n", sec, rate);

        return message;
    }

    public static String runAesCbcPkcs5_JCE() throws IOException, GeneralSecurityException {
        String message = "AES/CBC/PKCS5Padding JCE\n";
        byte[] key = AesUtils.generateKey();
        byte[] iv = AesUtils.generateKey();
        byte[] bytes = TestUtils.randomBytes(SIZE, true);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        OutputStream cipherOutputStream;
        int dummy = 0;

        long t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            byteArrayOutputStream.reset();
            cipherOutputStream = AesUtils_JCE.encrypt(byteArrayOutputStream, key, iv);
            cipherOutputStream.write(bytes);
            cipherOutputStream.close();
            dummy |= cipherOutputStream.hashCode();
            dummy |= byteArrayOutputStream.hashCode();
        }
        long t1 = System.nanoTime();
        long duration = t1 - t0;
        double sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        double rate = 100.0f / sec;
        message += String.format("100M data encrypted in %f seconds. %f MB/s.\n", sec, rate);

        byte[] cipherData = byteArrayOutputStream.toByteArray();
        byte[] buffer = new byte[cipherData.length*2];
        t0 = System.nanoTime();
        for (int i = 0; i < ROUND; ++i) {
            InputStream inputStream = new ByteArrayInputStream(cipherData);
            InputStream cipherInputStream = AesUtils_JCE.decrypt(inputStream, key, iv);
            dummy |= ByteStreams.read(cipherInputStream, buffer, 0, buffer.length);
        }
        t1 = System.nanoTime();
        duration = t1 - t0;
        sec = (double) duration / 1000.0f / 1000.0f / 1000.0f;
        rate = 100.0f / sec;
        message += String.format("100M data decrypted in %f seconds. %f MB/s.\n", sec, rate);

        return message;
    }

}
