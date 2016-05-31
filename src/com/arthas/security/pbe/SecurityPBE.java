package com.arthas.security.pbe;

import com.arthas.security.common.Constant;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Created by Arthas on 16/5/31.
 * <p/>
 * PBE:Password Based Encryption,基于口令加密
 * 对已有算法的包装
 * JDK，BC
 * 盐
 * PBEWithMD5AndDES
 */
public class SecurityPBE {
    private boolean isJdkDES;//是使用jdkDES还是BCDES

    public SecurityPBE(boolean isJdkDES) {
        this.isJdkDES = isJdkDES;
    }

    /**
     * 初始化盐
     * @return
     */
    public byte[] generateSalt() {
        //初始化盐
        SecureRandom random = new SecureRandom();
        byte[] salt = random.generateSeed(8);

        return salt;
    }

    /**
     * 根据口令生成Key,固定，私有
     * @return
     */
    private Key generateKey() {
        Key key = null;
        try {
            //口令与密钥
            PBEKeySpec pbeKeySpec = new PBEKeySpec(Constant.PBE_PASSWORD.toCharArray());
            SecretKeyFactory factory = SecretKeyFactory.getInstance(Constant.PBE_MODE);
            if (!isJdkDES) {
                Security.addProvider(new BouncyCastleProvider());
                factory = SecretKeyFactory.getInstance(Constant.PBE_MODE, "BC");
            }
            key = factory.generateSecret(pbeKeySpec);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return key;
    }

    /**
     * jdk DES
     *
     * @param text     需要加密或解密的文本
     * @param isEncode true:加密，false:解密
     * @param salt 盐
     * @return 加密或解密的结果
     */
    public String desOpt(String text, boolean isEncode, byte[] salt) {
        try {
            //加密或解密
            PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
            Cipher cipher = Cipher.getInstance(Constant.PBE_MODE);//填充方式
            if (isEncode) {
                cipher.init(Cipher.ENCRYPT_MODE, generateKey(),pbeParameterSpec);
                byte[] result = cipher.doFinal(text.getBytes());

                return Hex.encodeHexString(result);
            }
            else {
                cipher.init(Cipher.DECRYPT_MODE, generateKey(),pbeParameterSpec);

                return new String(cipher.doFinal(Hex.decodeHex(text.toCharArray())));
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

}
