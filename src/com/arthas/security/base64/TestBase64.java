package com.arthas.security.base64;

/**
 * Created by tanchuanzhi on 2016/5/31.
 */
public class TestBase64 {
    public static void main(String[] args) {
        String text = "This is a input text";

        String jdkEncodeText = SecurityBase64.jdkBase64Encode(text);
        System.out.println("Jdk encode: "+ jdkEncodeText);
        System.out.println("Jdk decode: "+ SecurityBase64.jdkBase64Decode(jdkEncodeText));

        String bcEncodeText = SecurityBase64.bouncyCastleBase64Encode(text);
        System.out.println("BC encode: "+ bcEncodeText);
        System.out.println("BC decode: "+ SecurityBase64.bouncyCastleBase64Decode(bcEncodeText));

        String ccEncodeText = SecurityBase64.commonsCodecBase64Encode(text);
        System.out.println("Jdk encode: "+ ccEncodeText);
        System.out.println("Jdk decode: "+ SecurityBase64.commonsCodecBase64Decode(ccEncodeText));
    }
}
