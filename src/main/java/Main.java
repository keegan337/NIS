import org.bouncycastle.operator.OperatorCreationException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;


public class Main {
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
	public static void main(String[] args) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, OperatorCreationException, SignatureException, InvalidKeyException {
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


//		Create thread to receive messages asynchronously
		System.out.println();
		System.out.println("Creating threads for sending and receiving of messages...");
		networkManager.startAsyncReceiveThread(bytes -> {
			//Decrypt message
			//TODO: bytes = CryptoUtils.decrypt(bytes, clientPrivateKey);

			//Unzip message
			//TODO: bytes = CryptoUtils.unzip(bytes)

			//Verify signature
			try {
				bytes = CryptoUtils.verifyAndExtractSignedData(bytes, connectedClientCertificate.getPublicKey());
			}
			catch (CryptoUtils.InvalidSignatureException e) {
				System.out.println("WARNING: INVALID SIGNATURE");
				System.out.println("This message was not signed by " + connectedClientCertificate.getSubjectX500Principal().getName());
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

			//Zip message
			//TODO: bytes = CryptoUtils.unzip(bytes)

			//Encrypt message
			//TODO: bytes = CryptoUtils.encrypt(bytes, connectedClientCertificate.getPublicKey());

			//Send message
			networkManager.writeByteArray(bytes);
		}

		networkManager.close();
	}
	
	/**
	 * Checks for a keystore (.p12 file) for the given username, and generates a new client certificate if missing.
	 *
	 * @param username
	 * @param password
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
	 * Hash the certificate using (algorithm) and compare with the CA signed certificate hash. Use local CA PubKey Copy
	 *
	 * @param cert received from connected client
	 */
	private static void validateCertificate(X509Certificate cert) {
		System.out.println("Validating certificate received was signed by the trusted Certificate Authority:");
		try {
			cert.verify(caCertificate.getPublicKey());
			System.out.println("Certificate validated successfully");
			networkManager.writeByte(ProtocolUtils.CERT_VALID_BYTE);
		}
		catch (InvalidKeyException e) {
			System.out.println("Invalid Certificate, closing connection.");
			try {
				networkManager.writeByte(ProtocolUtils.CERT_INVALID_BYTE);
				networkManager.close();
				System.exit(2);
			}
			catch (IOException ioException) {
				ioException.printStackTrace();
			}
		} catch (CertificateException | NoSuchAlgorithmException | SignatureException | NoSuchProviderException | IOException e) {
			e.printStackTrace();
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
	 * @param cert to be sent.
	 */
	private static void sendCertificate(X509Certificate cert) throws CertificateEncodingException, IOException {
		System.out.println("Sending certificate");

		byte[] bytes = cert.getEncoded();
		System.out.println("Length of encoded certificate (in bytes): " + bytes.length);
		networkManager.writeByteArray(bytes);
		System.out.println("certificate sent");
		byte b = networkManager.readByte();
		switch (b) {
			case ProtocolUtils.CERT_VALID_BYTE:
				System.out.println("our certificate was accepted");
				break;
			case ProtocolUtils.CERT_INVALID_BYTE:
				System.out.println("our certificate was rejected");
				networkManager.close();
				System.exit(2);
				break;
		}
	}
}
