import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class GenerateClientCert {
	public static void main(String[] args) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, OperatorCreationException {
		CertificateAuthority ca = new CertificateAuthority();
		X500NameBuilder nameBuilder = new X500NameBuilder();

		Scanner scanner = new Scanner(System.in);

		String username;
		while (true) {
			System.out.print("Enter client username: ");
			username = scanner.next();

			if (new File(username + ".p12").exists()) {
				System.out.println("user already exists");
			} else {
				break;
			}
		}

		System.out.print("Enter client password: ");
		String password = scanner.next();


		nameBuilder.addRDN(BCStyle.NAME, username);

		scanner.close();

		System.out.println("generating key pair");
		KeyPair kp = CertificateUtils.generateKeyPair();

		System.out.println("generating signed certificate");
		X509CertificateHolder certHolder = ca.getSignedClientCertificate(kp.getPublic(), nameBuilder.build());

		System.out.println("saving certificate and keys to file");
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		X509Certificate caCert = converter.getCertificate(ca.getCaCertHolder());
		X509Certificate clientCert = converter.getCertificate(certHolder);
		Certificate[] certChain = new Certificate[]{clientCert, caCert};
		CertificateUtils.saveToPKCS12(kp, certHolder, certChain, username, password, username + ".p12", password);
	}

	/**
	 * Generates a client certificate and saves it as a file
	 * @param username the username of the client
	 * @param password the client's password
	 * @throws UnrecoverableKeyException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws OperatorCreationException
	 */
	public static void generateClientCert(String username, String password) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, OperatorCreationException {
		CertificateAuthority ca = new CertificateAuthority();
		X500NameBuilder nameBuilder = new X500NameBuilder();

		// generate key pair
		KeyPair kp = CertificateUtils.generateKeyPair();

		// generate signed certificate
		X509CertificateHolder certHolder = ca.getSignedClientCertificate(kp.getPublic(), nameBuilder.build());
		System.out.println("\nNew client certificate created for "+username);
		
		// save cert and keys to file
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		X509Certificate caCert = converter.getCertificate(ca.getCaCertHolder());
		X509Certificate clientCert = converter.getCertificate(certHolder);
		Certificate[] certChain = new Certificate[]{clientCert, caCert};
		CertificateUtils.saveToPKCS12(kp, certHolder, certChain, username, password, username + ".p12", password);
	}
}
