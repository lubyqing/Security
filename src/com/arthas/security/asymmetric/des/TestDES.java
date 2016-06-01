package com.arthas.security.asymmetric.des;


import java.security.Key;

/**
 * Created by Arthas on 16/5/30.
 */
public class TestDES {
    public static void main(String[] args) {
        SecurityDES jdkDES = new SecurityDES(true);
        Key jdkKey = jdkDES.generateKey();
        String text = jdkDES.desOpt("123456", true, jdkKey);
        System.out.println("jdk encode : " + text);
        System.out.println("jdk decode : " + jdkDES.desOpt(text, false, jdkKey));

        SecurityDES bcDES = new SecurityDES(false);
        Key bcKey = bcDES.generateKey();
        String bcText = bcDES.desOpt("123456", true, bcKey);
        System.out.println("bc encode : " + bcText);
        System.out.println("bc decode : " + bcDES.desOpt(bcText,false,bcKey));
    }
}
