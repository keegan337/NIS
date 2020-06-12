import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class CryptoUtils {
	public static final int SIGNATURE_LENGTH = 512; //SHA256withRSA signature is 512 bits
	public static final int ENCRYPTED_SECRET_KEY_LENGTH = 512; //AES encoded encrypted key length is 512 bits

	public static byte[] signData(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		Signature signer = Signature.getInstance("SHA256withRSA");
		signer.initSign(privateKey);
		signer.update(data);
		byte[] signature = signer.sign();
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(signature.length + data.length);
		outputStream.write(signature);
		outputStream.write(data);
		return outputStream.toByteArray();
	}

	/**
	 * Encrypt the data that is received as a byte array. This involves zipping the data, generating a secret key, encrypting that secret key with the public key, and encrypting the seperate data with the secret key. Both of these encrypted data objects are then concatenated.
	 *
	 * @param data received after data is signed
	 * @param publicKey the public key of the receiver
	 */
	public static byte[] encryptData (byte [] data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {

		//compresses the data passed into the method with a zip algorithm
		byte [] compressedData = compressData(data, 9);

		//Provides the functionality of a cryptographic cipher which we will use for encryption, which in this case is set to use the AES algorithm in CBC mode with PKCS5 padding.
		Cipher symmetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		//Creating a key generator object that generates secret keys for the specified algorithm, AES in this case
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

		//Initializes this key generator for a certain keysize
		keyGenerator.init(256);

		//Generate the secret key
		SecretKey skey = keyGenerator.generateKey();

		//Get the encoded version of the secret key
		byte[] encodedSecretKey = skey.getEncoded();

		//Specifies an initialization vector to use for the symmetric cipher
		byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		//Initializes this cipher with the secret key and the IV.
		symmetricCipher.init(Cipher.ENCRYPT_MODE, skey, ivspec);

		//Encrypting the data
		byte[] encryptedData = symmetricCipher.doFinal(compressedData);

		//Provides the functionality of a cryptographic cipher which we will use for encryption, which in this case is set to use the RSA algorithm in ECB mode with PKCS1 padding.
		Cipher asymmetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		//Initializes this cipher with the public key.
		asymmetricCipher.init(Cipher.ENCRYPT_MODE, publicKey);

		//The bytes in data are processed, and the result is stored in a new buffer.
		asymmetricCipher.update(encodedSecretKey);

		//Encrypting the data
		byte[] encryptedSecretKey = asymmetricCipher.doFinal();

		//Create a new ByteArrayOutputStream in order to combine both byte arrays
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(encryptedSecretKey.length + encryptedData.length);

		outputStream.write(encryptedSecretKey);
		outputStream.write(encryptedData);

		return outputStream.toByteArray();

	}

	public static byte[] decryptData(byte[] encryptedKeyAndData, PrivateKey privateKey) throws Exception {

		//Calculate the portion of the byte [] sent to the method that is the secret key part
		byte[] encryptedSecretKey = Arrays.copyOfRange(encryptedKeyAndData, 0, ENCRYPTED_SECRET_KEY_LENGTH);

		//Calculate the portion of the byte [] sent to the method that is the data part
		byte[] encryptedData = Arrays.copyOfRange(encryptedKeyAndData, ENCRYPTED_SECRET_KEY_LENGTH, encryptedKeyAndData.length);

		//Specifies an initialization vector to use for the symmetric cipher
		byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		//Provides the functionality of a cryptographic cipher which we will use for decryption, which in this case is set to use the RSA algorithm in ECB mode with PKCS1 padding.
		Cipher asymmetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		//Initializes this cipher with the private key.
		asymmetricCipher.init(Cipher.DECRYPT_MODE, privateKey);

		//Decrypts the encrypted secret key into a byte array
		byte[] decryptedSecretKey = asymmetricCipher.doFinal(encryptedSecretKey);

		//Create the secret key from the byte array, using the AES algorithm
		SecretKeySpec secretKeySpec = new SecretKeySpec(decryptedSecretKey, "AES");

		//Provides the functionality of a cryptographic cipher which we will use for decryption, which in this case is set to use the AES algorithm in CBC mode with PKCS5 padding.
		Cipher symmetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		//Initializes this cipher with the secret key and the IV.
		symmetricCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);

		//Decrypt the data part and store in a byte array
		byte[] decryptedData = symmetricCipher.doFinal(encryptedData);

		//Decompress the data into a byte array
		byte [] decompressedData = decompressData(decryptedData);

		return decompressedData;
	}

	public static byte[] verifyAndExtractSignedData(byte[] signedData, PublicKey publicKey) throws Exception {
		byte[] signature = Arrays.copyOfRange(signedData, 0, SIGNATURE_LENGTH);
		byte[] data = Arrays.copyOfRange(signedData, SIGNATURE_LENGTH, signedData.length);

		Signature verifier = Signature.getInstance("SHA256withRSA");
		verifier.initVerify(publicKey);
		verifier.update(data);

		if (verifier.verify(signature)) {
			return data;
		} else {
			throw new InvalidSignatureException();
		}
	}

	public static byte[] compressData(byte[] data, int compressionType) throws IOException {
		Deflater compressor = new Deflater(compressionType);

		compressor.setInput(data);

		compressor.finish();

		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		byte[] readBuffer = new byte[1024];
		int readCount = 0;

		while (!compressor.finished()) {
			readCount = compressor.deflate(readBuffer);
			if (readCount > 0) {
				bao.write(readBuffer, 0, readCount);
			}
		}

		compressor.end();
		return bao.toByteArray();
	}

	public static byte[] decompressData (byte[] input) throws IOException, DataFormatException {
		Inflater decompressor = new Inflater();
		decompressor.setInput(input);
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		byte[] readBuffer = new byte[1024];
		int readCount = 0;

		while (!decompressor.finished()) {
			readCount = decompressor.inflate(readBuffer);
			if (readCount > 0) {
				bao.write(readBuffer, 0, readCount);
			}
		}
		decompressor.end();
		return bao.toByteArray();
	}

	public static class InvalidSignatureException extends Exception {
		public InvalidSignatureException() {
			super("invalid signature");
		}
	}
}

