package com.wiley.bir.util;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.wiley.bir.exception.EncryptionException;




public class EncryptionUtil {

	private static final String IV = "WILEYINIVECPARAM";
	private static final String ENCRYPTION_KEY_SALT = "W!l3YsLt";
	private static final String TRANSFORMATION_TYPE = "AES/CBC/PKCS5PADDING";
	private static final String PROVIDER = "SunJCE";
	private static final String ENCODING_TYPE = "UTF-8";
	private final Cipher aesCipherForEncryption;
	private final Cipher aesCipherForDecryption;
	private final AlgorithmParameterSpec ivParameterSpec;
	private final SecretKeySpec secretKey;

	private final Object encryptionLock = new Object();
	private final Object decryptionLock = new Object();


	private boolean minEncryptedKeyLengthCheckEnabled = true;

	private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionUtil.class);


	public EncryptionUtil(final String encryptionKey) throws Exception {
		this.aesCipherForEncryption = Cipher.getInstance(TRANSFORMATION_TYPE, PROVIDER);
		this.aesCipherForDecryption = Cipher.getInstance(TRANSFORMATION_TYPE, PROVIDER);
		this.ivParameterSpec = new IvParameterSpec(IV.getBytes(ENCODING_TYPE));
		this.secretKey = fetchSecretKey(ENCRYPTION_KEY_SALT.concat(encryptionKey));
	}

	public String encrypt(final String inputClearText) throws EncryptionException {
		String encryptedOutput = inputClearText;
		if(StringUtils.isNotBlank(encryptedOutput)){
			try {
				synchronized(this.encryptionLock){
					this.aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, this.secretKey, this.ivParameterSpec);
					final byte[] byteCipherText = this.aesCipherForEncryption.doFinal(inputClearText.getBytes());
					encryptedOutput = Base64.encodeBase64String(byteCipherText);
				}
			} catch (final Exception exception) {
				LOGGER.error("Error while encrypting password: " + inputClearText + ": " + exception);
				throw new EncryptionException("Error while encrypting password: " + exception);
			}
		}
		return encryptedOutput;
	}

	public String decrypt(final String inputEncryptedText) throws EncryptionException {
		String decryptedOutput = inputEncryptedText;
		if(StringUtils.isNotBlank(decryptedOutput)){
			try {
				synchronized(this.decryptionLock){
					this.aesCipherForDecryption.init(Cipher.DECRYPT_MODE, this.secretKey, this.ivParameterSpec);
					final byte[] encryptedDataBytes = inputEncryptedText.getBytes();
					if (isValidEncryptedText(inputEncryptedText, 24) && Base64.isArrayByteBase64(encryptedDataBytes))
					{
						final byte[] byteDataToDecrypt = Base64.decodeBase64(inputEncryptedText);
						final byte[] byteDecryptedText = this.aesCipherForDecryption.doFinal(byteDataToDecrypt);
						decryptedOutput = new String(byteDecryptedText);
					}
				}
			} catch (final Exception exception) {
				LOGGER.error("Error while decrypting password: " + inputEncryptedText + ": " + exception);
				throw new EncryptionException("Error while decrypting password: " + exception);
			}
		}
		return decryptedOutput;
	}

	private SecretKeySpec fetchSecretKey(final String encryptionKey) {
		MessageDigest sha = null;
		SecretKeySpec secretKey = null;
		byte[] key = null;
		try {
			key = encryptionKey.getBytes(ENCODING_TYPE);
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secretKey = new SecretKeySpec(key, "AES");
		} catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
			LOGGER.error("Error while fetching secret key: " + secretKey + ": " + noSuchAlgorithmException);
		} catch (final UnsupportedEncodingException unsupportedEncodingException) {
			LOGGER.error("Error while fetching secret key: " + secretKey + ": " + unsupportedEncodingException);
		}
		return secretKey;
	}

	private boolean isValidEncryptedText(final String input, final int minLength) {
		return this.minEncryptedKeyLengthCheckEnabled ? (input.length() >= minLength) : true;
	}

}