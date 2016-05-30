package com.arthas.security.des;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.Key;
import java.security.Security;

/**
 * Created by Arthas on 16/5/30.
 * <p>
 * DES（Data Encryption Standard）:数据加密标准。
 * 1998年后，该加密方式不断被破解，不再具有安全性，基本上已不再使用在实际项目中。
 * 目前只会在以前的老项目或一些案例介绍上可以见到。
 * DES主要有两种实现方式：jdkDES,bcDES
 */
public class SecurityDES {
    private boolean isJdkDES;//是使用jdkDES还是BCDES

    public SecurityDES(boolean isJdkDES) {
        this.isJdkDES = isJdkDES;
    }


    public Key generateKey() {
        Key convertSecretKey = null;
        try {
            //生成Key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            if (!isJdkDES) {
                Security.addProvider(new BouncyCastleProvider());
                keyGenerator = KeyGenerator.getInstance("DES", "BC");
            }

            keyGenerator.init(56);//密钥长度
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();

            //转换Key
            DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            convertSecretKey = factory.generateSecret(desKeySpec);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return convertSecretKey;
    }

    /**
     * jdk DES
     *
     * @param text     需要加密或解密的文本
     * @param isEncode true:加密，false:解密
     * @return 加密或解密的结果
     */
    public String desOpt(String text, boolean isEncode, Key convertSecretKey) {
        try {
            //加密或解密
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");//填充方式
            if (isEncode) {
                cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
                byte[] result = cipher.doFinal(text.getBytes());

                return HexBin.encode(result);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);

                return new String(cipher.doFinal(HexBin.decode(text)));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

}
