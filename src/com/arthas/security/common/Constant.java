package com.arthas.security.common;

/**
 * Created by Arthas on 16/5/30.
 */
public interface Constant {

    /**
     * BC 实现方式
     */
    String BC_TYPE = "BC";

    /**
     * DES 加密类型
     */
    String DES_TYPE = "DES";
    /**
     * DES 加密方式
     */
    String DES_MODE = "DES/ECB/PKCS5Padding";

    /**
     * DESede 加密类型
     */
    String DESEDE_TYPE = "DESede";
    /**
     * DESede 加密方式
     */
    String DESEDE_MODE = "DESede/ECB/PKCS5Padding";

    /**
     * AES 加密类型
     */
    String AES_TYPE = "AES";
    /**
     * AES 加密方式
     */
    String AES_MODE = "AES/ECB/PKCS5Padding";

    /**
     * PBE 加密口令
     */
    String PBE_PASSWORD = "password";
    /**
     * PBE 加密方式
     */
    String PBE_MODE = "PBEWithMD5AndDES";

    /**
     * MD5 加密类型
     */
    String MD5_TYPE = "MD5";
    /**
     * MD2 加密类型
     */
    String MD2_TYPE = "MD2";

    /**
     * SHA-1 加密类型
     */
    String SHA1_TYPE = "SHA";

    /**
     * SHA-224 加密类型
     */
    String SHA224_TYPE = "SHA-224";
    /**
     * SHA-256 加密类型
     */
    String SHA256_TYPE = "SHA-256";
    /**
     * SHA-384 加密类型
     */
    String SHA384_TYPE = "SHA-384";
    /**
     * SHA-1 加密类型
     */
    String SHA512_TYPE = "SHA-512";

    String HMAC_MD5_TYPE = "HmacMD5";

}
