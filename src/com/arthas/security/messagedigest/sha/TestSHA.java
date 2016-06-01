package com.arthas.security.messagedigest.sha;

/**
 * Created by tanchuanzhi on 2016/5/31.
 */
public class TestSHA {
    public static void main(String[] args) {
        String text = "This is an input text";
        System.out.println("jdk sha-1: "+ SecuritySHA.jdkSHA1(text));
        System.out.println("bc sha-1： "+ SecuritySHA.bcSHA1(text) );
        System.out.println("cc sha-1: "+SecuritySHA.ccSHA1(text));

        System.out.println("jdk sha-224: "+ SecuritySHA.jdkSHA224(text));
        System.out.println("bc sha-224: "+ SecuritySHA.bcSHA224(text));

    }
}
