package com.arthas.security.symmetric.pbe;

/**
 * Created by Arthas on 16/5/30.
 */
public class TestPBE {
    public static void main(String[] args) {
        SecurityPBE jdkDES = new SecurityPBE(true);
        byte[] jdkSalt = jdkDES.generateSalt();
        String text = jdkDES.desOpt("123456", true, jdkSalt);
        System.out.println("jdk encode : " + text);
        System.out.println("jdk decode : " + jdkDES.desOpt(text, false, jdkSalt));

        SecurityPBE bcDES = new SecurityPBE(false);
        byte[] bcSalt = bcDES.generateSalt();
        String bcText = bcDES.desOpt("123456", true, bcSalt);
        System.out.println("bc encode : " + bcText);
        System.out.println("bc decode : " + bcDES.desOpt(bcText,false,bcSalt));
    }
}
