package im.chic.utils.crypto.benchmarks;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class Benchmark {
    static public void main(String[] args) throws IOException, GeneralSecurityException {
        System.out.println(Rc4Benchmark.runRc4_JCE());
        System.out.println(Rc4Benchmark.runRc4());
        System.out.println(DigestBenchmark.runSha1_JCE());
        System.out.println(DigestBenchmark.runSha1());
        System.out.println(AesBenchmark.runAesEcbPkcs5_JCE());
        System.out.println(AesBenchmark.runAesEcbPkcs5());
        System.out.println(AesBenchmark.runAesCbcPkcs5_JCE());
        System.out.println(AesBenchmark.runAesCbcPkcs5());
    }
}
