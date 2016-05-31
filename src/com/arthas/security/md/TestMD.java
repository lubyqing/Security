package com.arthas.security.md;

/**
 * Created by tanchuanzhi on 2016/5/31.
 */
public class TestMD {
    public static void main(String[] args) {
        String text = "This is a input text";
        System.out.println("JDK MD5 : + "+ SecurityMD.jdkMD5(text));
        System.out.println("BC MD5 : + "+ SecurityMD.bcMD5(text));
        System.out.println("CC MD5 : + "+ SecurityMD.ccMD5(text));

        System.out.println("JDK MD2 : + "+ SecurityMD.jdkMD2(text));
        System.out.println("BC MD2 : + "+ SecurityMD.bcMD2(text));
        System.out.println("CC MD2 : + "+ SecurityMD.ccMD2(text));

        System.out.println("JDK MD4 : + "+ SecurityMD.jdkMD4(text));
        System.out.println("BC MD4 : + "+ SecurityMD.bcMD4(text));
    }
}
