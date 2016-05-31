package com.arthas.security.aes;

import com.arthas.security.des.SecurityDES;

import java.security.Key;

/**
 * Created by Arthas on 16/5/30.
 */
public class TestAES {
    public static void main(String[] args) {
        SecurityAES jdkDES = new SecurityAES(true);
        Key jdkKey = jdkDES.generateKey();
        String text = jdkDES.desOpt("123456", true, jdkKey);
        System.out.println("jdk encode : " + text);
        System.out.println("jdk decode : " + jdkDES.desOpt(text, false, jdkKey));

        SecurityAES bcDES = new SecurityAES(false);
        Key bcKey = bcDES.generateKey();
        String bcText = bcDES.desOpt("123456", true, bcKey);
        System.out.println("bc encode : " + bcText);
        System.out.println("bc decode : " + bcDES.desOpt(bcText,false,bcKey));
    }
}
