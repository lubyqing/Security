package com.arthas.security.messagedigest.hmac;

import com.arthas.security.common.Constant;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Arthas on 16/6/1.
 */
public class SecurityHMAC {

    /**
     * 以指定字段串产生密钥
     * @param keyStr
     * @return
     */
    public static byte[] generateKey(String keyStr) {
        return Hex.decode(keyStr);
    }

    /**
     * JDK 产生密钥
     * @return
     */
    public static byte[] generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(Constant.HMAC_MD5_TYPE);
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Jdk mac md5实现方式
     * @param text
     * @param key
     * @return
     */
    public static String jdkHmacMD5(String text,byte[] key) {
        SecretKey restoreKey = new SecretKeySpec(key, Constant.HMAC_MD5_TYPE);
        try {
            Mac mac = Mac.getInstance(restoreKey.getAlgorithm());
            mac.init(restoreKey);
            byte[] resultBytes = mac.doFinal(text.getBytes());
            return Hex.toHexString(resultBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * bcHamc md5实现
     * @param text
     * @param key
     * @return
     */
    public static String bcHmacMd5(String text,byte[] key){
        HMac hMac = new HMac(new MD5Digest());
        hMac.init(new KeyParameter(key));
        hMac.update(text.getBytes(),0,text.getBytes().length);

        byte[] resultBytes = new byte[hMac.getMacSize()];
        hMac.doFinal(resultBytes,0);

        return Hex.toHexString(resultBytes);
    }
}
