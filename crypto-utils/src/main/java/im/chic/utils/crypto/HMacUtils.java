package im.chic.utils.crypto;

import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.params.KeyParameter;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * HMacUtils: Some helpers to compute HMAC.
 *
 * @author huahang
 */
public class HMacUtils {
    /**
     * Hash-based message authentication code with SHA1 digest as defined in:
     * <a href="http://www.ietf.org/rfc/rfc2104.txt">RFC 2104</a>.
     *
     * @param data
     * @param key
     * @return
     */
    public static byte[] hmacSHA1(byte[] data, byte[] key) {
        checkNotNull(data);
        checkNotNull(key);
        HMac hMac = new HMac(new SHA1Digest());
        KeyParameter keyParameter = new KeyParameter(key);
        hMac.init(keyParameter);
        hMac.update(data, 0, data.length);
        byte[] result = new byte[hMac.getMacSize()];
        hMac.doFinal(result, 0);
        return result;
    }
}
