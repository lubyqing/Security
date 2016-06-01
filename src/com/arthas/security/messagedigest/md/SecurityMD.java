package com.arthas.security.messagedigest.md;

import com.arthas.security.common.Constant;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Created by tanchuanzhi on 2016/5/31.
 */
public class SecurityMD {

    /**
     * jdk md5实现
     * @param text
     * @return
     */
    public static String jdkMD5(String text){
        String result = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(Constant.MD5_TYPE);
            byte[] resultBytes = messageDigest.digest(text.getBytes());
            result =  Hex.encodeHexString(resultBytes);
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * jdk md2实现
     * @param text
     * @return
     */
    public static String jdkMD2(String text){
        String result = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(Constant.MD2_TYPE);
            byte[] resultBytes = messageDigest.digest(text.getBytes());
            result =  Hex.encodeHexString(resultBytes);
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * JDK本身是没有实现MD4,通过动态添加Provider，使用BC的方式实现
     * 与bcMD4方法一样
     * @param text
     * @return
     */
    public static String jdkMD4(String text){
        String result = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            MessageDigest messageDigest = MessageDigest.getInstance("MD4");
            byte[] resultBytes = messageDigest.digest(text.getBytes());
            result =  Hex.encodeHexString(resultBytes);
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * bc MD4实现
     * @param text
     * @return
     */
    public static String bcMD4(String text){
        Digest digest = new MD4Digest();
        digest.update(text.getBytes(),0,text.getBytes().length);
        byte[] resultBytes = new byte[digest.getDigestSize()];
        digest.doFinal(resultBytes,0);

        return org.bouncycastle.util.encoders.Hex.toHexString(resultBytes);
    }

    /**
     * bc MD5实现
     * @param text
     * @return
     */
    public static String bcMD5(String text){
        Digest digest = new MD5Digest();
        digest.update(text.getBytes(),0,text.getBytes().length);
        byte[] resultBytes = new byte[digest.getDigestSize()];
        digest.doFinal(resultBytes,0);

        return org.bouncycastle.util.encoders.Hex.toHexString(resultBytes);
    }

    /**
     * bc MD2实现
     * @param text
     * @return
     */
    public static String bcMD2(String text){
        Digest digest = new MD2Digest();
        digest.update(text.getBytes(),0,text.getBytes().length);
        byte[] resultBytes = new byte[digest.getDigestSize()];
        digest.doFinal(resultBytes,0);

        return org.bouncycastle.util.encoders.Hex.toHexString(resultBytes);
    }

    /**
     * cc MD5实现，只是对jdk实现的进一步封装，所有没有MD4
     * @param text
     * @return
     */
    public static String ccMD5(String text){
        return DigestUtils.md5Hex(text.getBytes());
    }

    /**
     * cc MD2实现，只是对jdk实现的进一步封装，所有没有MD4
     * @param text
     * @return
     */
    public static String ccMD2(String text){
        return DigestUtils.md2Hex(text.getBytes());
    }

}
