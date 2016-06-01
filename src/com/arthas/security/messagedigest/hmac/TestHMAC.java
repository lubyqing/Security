package com.arthas.security.messagedigest.hmac;

/**
 * Created by Arthas on 16/6/1.
 */
public class TestHMAC {
    public static void main(String[] args) {
        String text = "This is an input text";

        byte[] jdkKey = SecurityHMAC.generateKey();
        System.out.println("jdk key : " + jdkKey);
        System.out.println("jdk hmac md5 : "+ SecurityHMAC.jdkHmacMD5(text,jdkKey));
        System.out.println("bc hmac md5 :  " + SecurityHMAC.bcHmacMd5(text, jdkKey));

        byte[] defaultKey = SecurityHMAC.generateKey("aaaaaaaa");
        System.out.println("default key :  " + defaultKey);
        System.out.println("jdk hmac md5 : "+ SecurityHMAC.jdkHmacMD5(text,defaultKey));
        System.out.println("bc hmac md5 :  " + SecurityHMAC.bcHmacMd5(text,defaultKey));
    }
}
