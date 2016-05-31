package com.arthas.security.des;

import java.security.Key;

/**
 * Created by Arthas on 16/5/30.
 */
public class Test3DES {
    public static void main(String[] args) {
        Security3DES jdk3DES = new Security3DES(true);
        Key jdkKey = jdk3DES.generateKey();
        String text = jdk3DES.desOpt("123456", true, jdkKey);
        System.out.println("jdk encode : " + text);
        System.out.println("jdk decode : " + jdk3DES.desOpt(text, false, jdkKey));

        Security3DES bc3DES = new Security3DES(false);
        Key bcKey = bc3DES.generateKey();
        String bcText = bc3DES.desOpt("123456", true, bcKey);
        System.out.println("bc encode : " + bcText);
        System.out.println("bc decode : " + bc3DES.desOpt(bcText,false,bcKey));
    }
}
