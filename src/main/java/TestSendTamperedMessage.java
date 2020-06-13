import org.bouncycastle.operator.OperatorCreationException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Scanner;
import java.util.zip.DataFormatException;

/**
 * This is a fake client that simulates an attacker tampering with it's messages before they are encrypted.
 * Tampering with the message after encryption typically results in error's after decryption.
 * This test simulates the worst case: that an attacker manages to manipulate the encrypted message so that it decrypts to a valid format.
 * The signature check should then detect that the message has been tampered with.
 * Please send messages with at least 5 characters to avoid errors.
 * See line 151 for changes made.
 * Use this "fake messenger" to connect to a client that is using the real messenger
 * The real messenger app should detect that the message was tampered with (based on the signature) and reject it.
 */
public class TestSendTamperedMessage {
	private static int SERVER_PORT = 9000;
	private static String MACHINE_NAME = "localhost";
	private static NetworkManager networkManager;

	private static X509Certificate caCertificate; //CA cert
	private static X509Certificate clientCertificate; // MY cert
	private static X509Certificate connectedClientCertificate; // THEIR cert

	private static PrivateKey clientPrivateKey; //MY private key

	private static final Scanner in = new Scanner(System.in);

	/**
	 * @param args leave blank to run as server, otherwise provide ip and port to connect directly (1.2.3.4 1234)
	 */
	public static void main(String[] args) throws Exception {
		System.out.println("Please enter your username and password, if this is the first run enter a username and password of your choice");
		String username = "alice";
		String password = "123";
		System.out.print("Enter Username:");
		String line = in.nextLine();
		if (line.length() > 0) {
			username = line;
		}
		System.out.print("Enter Password:");
		line = in.nextLine();
		if (line.length() > 0) {
			password = line;
		}

		System.out.println("Username = " + username);
		System.out.println("Password = " + password);

		System.out.println();
		ensureCertificateExists(username, password);

		System.out.println();
		System.out.println("Reading client and CA certificates and client private keys from keystore on disk:");
		KeyStore store = CertificateUtils.loadKeyStoreFromPKCS12(username + ".p12", password);
		Certificate[] certChain = store.getCertificateChain(username);
		clientCertificate = (X509Certificate) certChain[0];
		caCertificate = (X509Certificate) certChain[1];
		clientPrivateKey = (PrivateKey) store.getKey(username, password.toCharArray());

		System.out.println("Client Public Key (from certificate):\n" + clientCertificate.getPublicKey());
		System.out.println("\nClient Private Key (from keystore):\n" + clientPrivateKey);
		System.out.println("\nCA Public Key (from certificate):\n" + caCertificate.getPublicKey());

		networkManager = new NetworkManager();

//		Initial connection setup
		if (args.length < 2) {
			if (args.length == 1) {
				SERVER_PORT = Integer.parseInt(args[0]);
			}
			networkManager.listenForConnection(SERVER_PORT);
			System.out.println("Connection setup on " + MACHINE_NAME + ":" + SERVER_PORT);
			System.out.println("Performing initial certificate verification:");
			connectedClientCertificate = receiveCertificate();
			validateCertificate(connectedClientCertificate);
			sendCertificate(clientCertificate);
		} else {
			MACHINE_NAME = args[0];
			SERVER_PORT = Integer.parseInt(args[1]);
			try {
				networkManager.connect(MACHINE_NAME, SERVER_PORT);
			}
			catch (ConnectException e) {
				System.out.println("Could not connect to server");
				System.exit(2);
			}
			System.out.println("Connected to " + MACHINE_NAME + ":" + SERVER_PORT);
			System.out.println("Performing initial certificate verification:");
			sendCertificate(clientCertificate);
			connectedClientCertificate = receiveCertificate();
			validateCertificate(connectedClientCertificate);
		}

		System.out.println("Mutual certificate exchange and validation successful");
		System.out.println("You are talking to: " + connectedClientCertificate.getSubjectX500Principal());


//		Create thread to receive messages asynchronously
		System.out.println();
		System.out.println("Creating threads for sending and receiving of messages...");
		networkManager.startAsyncReceiveThread(bytes -> {
			//Decrypt message
			try {
				bytes = CryptoUtils.decryptData(bytes, clientPrivateKey);
			} catch (NoSuchPaddingException | InvalidAlgorithmParameterException | IOException | DataFormatException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException e) {
				System.out.println("Could not decrypt message");
				e.printStackTrace();
				return;
			}
			System.out.println("Decrypted data in bytes:");
			System.out.println(new String(bytes));

			//Verify signature
			try {
				bytes = CryptoUtils.verifyAndExtractSignedData(bytes, connectedClientCertificate.getPublicKey());
			}
			catch (CryptoUtils.InvalidSignatureException e) {
				System.out.println("INVALID SIGNATURE");
				System.out.println("This message was not signed by " + connectedClientCertificate.getSubjectX500Principal());
				return;
			}
			catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
				e.printStackTrace();
				System.exit(2);
			}

			System.out.println("message received: " + new String(bytes, StandardCharsets.UTF_8));
		});
		System.out.println("Threads created");


		String inputLine = "";

		while (!inputLine.equals("EXIT")) {
			System.out.println("enter a message to send:");
			inputLine = in.nextLine();
			byte[] bytes = inputLine.getBytes();

			//Sign message
			bytes = CryptoUtils.signData(bytes, clientPrivateKey);
			System.out.println("Signed data in bytes:");
			System.out.println(new String(bytes));

			//TESTING: tamper with data in message
			bytes[CryptoUtils.SIGNATURE_LENGTH]     = 'h';
			bytes[CryptoUtils.SIGNATURE_LENGTH + 1] = 'a';
			bytes[CryptoUtils.SIGNATURE_LENGTH + 2] = 'x';
			bytes[CryptoUtils.SIGNATURE_LENGTH + 3] = 'x';
			bytes[CryptoUtils.SIGNATURE_LENGTH + 4] = 'd';


			//Encrypt message
			bytes = CryptoUtils.encryptData(bytes, connectedClientCertificate.getPublicKey());
			System.out.println("Encrypted data in bytes:");
			System.out.println(new String(bytes));

			//Send message
			networkManager.writeByteArray(bytes);
		}

		networkManager.close();
	}

	/**
	 * Checks for a keystore (.p12 file) for the given username, and generates a new client certificate if missing.
	 *
	 * @param username the username of the current user
	 * @param password the password of the current user
	 */
	private static void ensureCertificateExists(String username, String password) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, IOException {
		System.out.println("Checking for keystore for " + username);
		File f = new File(username + ".p12");
		if (!f.exists()) {
			System.out.println("Keystore not found, generating client certificate for new user");
			CertificateUtils.generateClientCert(username, password);
			System.out.println("Keystore generated");
		} else {
			System.out.println("Keystore found");
		}
	}

	/**
	 * Hash the certificate using SHA256 and compare with the CA signed certificate hash. Use local CA PubKey Copy
	 *
	 * @param cert received from connected client
	 */
	private static void validateCertificate(X509Certificate cert) throws IOException, NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException {
		System.out.println("Validating certificate received was signed by the trusted Certificate Authority:");
		try {
			cert.verify(caCertificate.getPublicKey());
			System.out.println("Certificate validated successfully");
			networkManager.writeByte(ProtocolUtils.CERT_ACCEPTED_BYTE);
		}
		catch (SignatureException e) {
			System.out.println("Invalid Certificate, closing connection.");
			networkManager.writeByte(ProtocolUtils.CERT_REJECTED_BYTE);
			networkManager.close();
			System.exit(2);
		}
	}

	/**
	 * Receive the connected client's certificate over the network.
	 *
	 * @return the connected client's certificate
	 */
	private static X509Certificate receiveCertificate() throws IOException, CertificateException {
		System.out.println("Receiving certificate from connected client");

		byte[] certAsBytes = networkManager.readByteArray();
		X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certAsBytes));
		System.out.println("Received certificate from connected client");
		return cert;
	}

	/**
	 * Send clients certificate over the network to the connected client
	 *
	 * @param cert the certificate to be sent.
	 */
	private static void sendCertificate(X509Certificate cert) throws CertificateEncodingException, IOException {
		System.out.println("Sending certificate");

		byte[] bytes = cert.getEncoded();
		System.out.println("Length of encoded certificate (in bytes): " + bytes.length);
		networkManager.writeByteArray(bytes);
		System.out.println("certificate sent");
		byte b = networkManager.readByte();
		switch (b) {
			case ProtocolUtils.CERT_ACCEPTED_BYTE:
				System.out.println("our certificate was accepted");
				break;
			case ProtocolUtils.CERT_REJECTED_BYTE:
				System.out.println("our certificate was rejected");
				networkManager.close();
				System.exit(2);
				break;
		}
	}
}
