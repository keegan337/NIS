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


	/**
	 * Signing the hashed message and concatenating that signed hash with the actual message.
	 *
	 * @param data received data that is the byte array conversion of a string sent by a user
	 * @param privateKey the private key of the user
	 */
	public static byte[] signData(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		//Returns a Signature object that implements the specified signature algorithm (SHA256withRSA)
		Signature signer = Signature.getInstance("SHA256withRSA");

		//Initialize this object for signing with the private key of the identity whose signature is going to be generated.
		signer.initSign(privateKey);

		//Updates the data to be signed or verified, using the specified array of bytes, which is the message converted into a byte array in this case.
		signer.update(data);

		//Hashes the data and signs it with the private key of the user
		byte[] signature = signer.sign();

		//Creates a new ByteArrayOutputStream, with a buffer capacity in bytes which is the size of the signature length added to the data length
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

	/**
	 * Decrypt the data that is received as a byte array. This involves first separating the encrypted key portion and the data portion of the byte array. Then, the encrypted secret key is decrypted
	 * with the private key. The secret key is then used to decrypt the data, which is then decompressed. A single initialization vector is used since the secret key changes with every message.
	 * @param encryptedKeyAndData received after encrypted data is sent to the user
	 * @param privateKey the private key of the user
	 */
	public static byte[] decryptData(byte[] encryptedKeyAndData, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, IOException, DataFormatException {

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

	/**
	 * Receives the decrypted signed data that is verified by first separating the data into the encrypted hash of the message and the message itself.
	 * The public key of the connected client is then used to decrypted the encrypted hash of the message, and it is compared to the hash of the separated message. If the hashes are equal, the original message is returned
	 * @param signedData the decompressed signed data that is received as a byte array
	 * @param publicKey the public key of the connected client
	 */
	public static byte[] verifyAndExtractSignedData(byte[] signedData, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidSignatureException {
		//Separate the signed hash of the message
		byte[] signature = Arrays.copyOfRange(signedData, 0, SIGNATURE_LENGTH);

		//Separate the message
		byte[] data = Arrays.copyOfRange(signedData, SIGNATURE_LENGTH, signedData.length);

		//Returns a Signature object that implements the specified signature algorithm (SHA256withRSA)
		Signature verifier = Signature.getInstance("SHA256withRSA");

		//Initializes this object for verification with the public key of the identity whose signature is going to be verified.
		verifier.initVerify(publicKey);

		//Updates the data to be signed or verified, using the data array of bytes
		verifier.update(data);

		//If the signature is verified, return the data, otherwise throw an Invalid Signature Exception Error
		if (verifier.verify(signature)) {
			return data;
		} else {
			throw new InvalidSignatureException();
		}
	}


	/**
	 * Compresses data with a zip algorithm at a specified strength
	 *
	 * @param data the data to be compressed
	 * @param compressionType the strength of compression from 0-9
	 */
	public static byte[] compressData(byte[] data, int compressionType) {
		Deflater zipper = new Deflater(compressionType);

		zipper.setInput(data);

		zipper.finish();

		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		byte[] readBuffer = new byte[1024];
		int readCount = 0;

		while (!zipper.finished()) {

			readCount = zipper.deflate(readBuffer);

			if (readCount > 0) {
				byteArrayOutputStream.write(readBuffer, 0, readCount);
			}
		}

		zipper.end();

		return byteArrayOutputStream.toByteArray();
	}

	/**
	 * Decompresses data with a zip algorithm
	 *
	 *
	 * @param data the data to be decompressed
	 */
	public static byte[] decompressData (byte[] data) throws DataFormatException {
		Inflater unzipper = new Inflater();

		unzipper.setInput(data);

		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

		byte[] readBuffer = new byte[1024];

		int readCount = 0;

		while (!unzipper.finished()) {

			readCount = unzipper.inflate(readBuffer);

			if (readCount > 0) {
				byteArrayOutputStream.write(readBuffer, 0, readCount);
			}
		}

		unzipper.end();

		return byteArrayOutputStream.toByteArray();
	}

	public static class InvalidSignatureException extends Exception {
		public InvalidSignatureException() {
			super("invalid signature");
		}
	}
}

