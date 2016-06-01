package com.arthas.security.messagedigest.sha;

import com.arthas.security.common.Constant;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.Security;

/**
 * Created by tanchuanzhi on 2016/5/31.
 */
public class SecuritySHA {

    /**
     * JDK SHA1实现
     *
     * @param text
     * @return
     */
    public static String jdkSHA1(String text) {
        String result = null;
        try {
            MessageDigest
                    messageDigest =
                    MessageDigest.getInstance(Constant.SHA1_TYPE);
            messageDigest.update(text.getBytes());
            result = Hex.encodeHexString(messageDigest.digest());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * JDK SHA-224 实际使用的BC实现
     *
     * @param text
     * @return
     */
    public static String jdkSHA224(String text) {
        String result = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            MessageDigest
                    messageDigest =
                    MessageDigest.getInstance(Constant.SHA224_TYPE);
            messageDigest.update(text.getBytes());
            result = Hex.encodeHexString(messageDigest.digest());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * JDK SHA-256实现
     *
     * @param text
     * @return
     */
    public static String jdkSHA256(String text) {
        String result = null;
        try {
            MessageDigest
                    messageDigest =
                    MessageDigest.getInstance(Constant.SHA256_TYPE);
            messageDigest.update(text.getBytes());
            result = Hex.encodeHexString(messageDigest.digest());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * JDK SHA-384实现
     *
     * @param text
     * @return
     */
    public static String jdkSHA384(String text) {
        String result = null;
        try {
            MessageDigest
                    messageDigest =
                    MessageDigest.getInstance(Constant.SHA384_TYPE);
            messageDigest.update(text.getBytes());
            result = Hex.encodeHexString(messageDigest.digest());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * JDK SHA-512实现
     *
     * @param text
     * @return
     */
    public static String jdkSHA512(String text) {
        String result = null;
        try {
            MessageDigest
                    messageDigest =
                    MessageDigest.getInstance(Constant.SHA512_TYPE);
            messageDigest.update(text.getBytes());
            result = Hex.encodeHexString(messageDigest.digest());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * BC SHA1实现
     *
     * @param text
     * @return
     */
    public static String bcSHA1(String text) {

        Digest digest = new SHA1Digest();
        digest.update(text.getBytes(), 0, text.getBytes().length);
        byte[] resultBytes = new byte[digest.getDigestSize()];
        digest.doFinal(resultBytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(resultBytes);
    }

    /**
     * BC SHA-224实现
     *
     * @param text
     * @return
     */
    public static String bcSHA224(String text) {

        Digest digest = new SHA224Digest();
        digest.update(text.getBytes(), 0, text.getBytes().length);
        byte[] resultBytes = new byte[digest.getDigestSize()];
        digest.doFinal(resultBytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(resultBytes);
    }

    /**
     * CC的实现，基于JDK封装
     * @param text
     * @return
     */
    public static String ccSHA1(String text) {
        return DigestUtils.sha1Hex(text.getBytes());
    }

    public static String ccSHA256(String text) {
        return DigestUtils.sha256Hex(text.getBytes());
    }

    public static String ccSHA384(String text) {
        return DigestUtils.sha384Hex(text.getBytes());
    }

    public static String ccSHA512(String text) {
        return DigestUtils.sha512Hex(text.getBytes());
    }

}
