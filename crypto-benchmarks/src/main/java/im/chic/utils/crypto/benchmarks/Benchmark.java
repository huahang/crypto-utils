package im.chic.utils.crypto.benchmarks;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class Benchmark {
    static public void main(String[] args) throws IOException, GeneralSecurityException {
        System.out.println(AesBenchmark.runAesEcbPkcs5_JCE());
        System.out.println(AesBenchmark.runAesEcbPkcs5());
        System.out.println(AesBenchmark.runAesCbcPkcs5_JCE());
        System.out.println(AesBenchmark.runAesCbcPkcs5());
    }
}
