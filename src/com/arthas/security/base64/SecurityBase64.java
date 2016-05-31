package com.arthas.security.base64;

import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

/**
 * Created by tanchuanzhi on 2016/5/31.
 * Base64三种实现方式，Jdk自带的不建议使用
 */
public class SecurityBase64 {
    /**
     * jdk实现Base64编码
     * @param text
     * @return
     */
    public static String jdkBase64Encode(String text){
        return new BASE64Encoder().encode(text.getBytes());
    }

    /**
     * jdk实现Base64解码
     * @param text
     * @return
     */
    public static String jdkBase64Decode(String text){
        String result = null;
        try {
            result =  new String(new BASE64Decoder().decodeBuffer(text));
        }
        catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * commons codec编码实现
     * @param text
     * @return
     */
    public static String commonsCodecBase64Encode(String text){
        return new String(Base64.encodeBase64(text.getBytes()));
    }

    /**
     * commons codec解码实现
     * @param text
     * @return
     */
    public static String commonsCodecBase64Decode(String text){
        return new String(Base64.decodeBase64(text.getBytes()));
    }

    /**
     * bouncy castle编码实现
     * @param text
     * @return
     */
    public static String bouncyCastleBase64Encode(String text){
        return new String(org.bouncycastle.util.encoders.Base64.encode(text.getBytes()));
    }

    /**
     * bouncy castle解码实现
     * @param text
     * @return
     */
    public static String bouncyCastleBase64Decode(String text){
        return new String(org.bouncycastle.util.encoders.Base64.decode(text.getBytes()));
    }
    


}
