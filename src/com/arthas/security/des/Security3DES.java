package com.arthas.security.des;

import com.arthas.security.common.Constant;
import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Created by Arthas on 16/5/30.
 * <p>
 * 三重DES
 * 3DES相比DES，密钥长度增长112，168
 * 迭代次数增加
 * 应用广泛
 */
public class Security3DES {
    private boolean isJdkDES;//是使用jdkDES还是BCDES

    public Security3DES(boolean isJdkDES) {
        this.isJdkDES = isJdkDES;
    }


    /**
     * 生成密钥
     * @return 密钥
     */
    public Key generateKey() {
        Key convertSecretKey = null;
        try {
            //生成Key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(Constant.DESEDE_TYPE);
            if (!isJdkDES) {
                Security.addProvider(new BouncyCastleProvider());
                keyGenerator = KeyGenerator.getInstance(Constant.DESEDE_TYPE, Constant.BC_TYPE);
            }

            //keyGenerator.init(168);//密钥长度
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();

            //转换Key
            DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(Constant.DESEDE_TYPE);
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
            Cipher cipher = Cipher.getInstance(Constant.DESEDE_MODE);//填充方式
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
