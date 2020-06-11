import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class CryptoUtils {
	public static final int SIGNATURE_LENGTH = 512; //SHA256withRSA signature is 512 bits

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

	public static byte[] verifyAndExtractSignedData(byte[] signedData, PublicKey publicKey) throws Exception {
		byte[] signature = Arrays.copyOfRange(signedData, 0, SIGNATURE_LENGTH);
		byte[] data = Arrays.copyOfRange(signedData, SIGNATURE_LENGTH, signedData.length);

		Signature verifier = Signature.getInstance("SHA256withRSA");
		verifier.initVerify(publicKey);
		verifier.update(data);

		if (verifier.verify(signature)) {
			return data;
		} else {
			throw new Exception("Invalid Signature");
		}
	}
}
