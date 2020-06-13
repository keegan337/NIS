import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * A utility class containing methods to create, store and load certificates and related objects as well as get information
 * about certificates
 */
public class CertificateUtils {
	//The length of a month in milliseconds
	public static final long millisecondMonth=1000L*60*60*24*30;

	/**
	 * Creates a keystore from a .p12 file
	 * @param fileName the named of the file to be loaded
	 * @param password the specific clients's password
	 * @return
	 */
	public static KeyStore loadKeyStoreFromPKCS12(String fileName, String password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
		FileInputStream inputStream = new FileInputStream(fileName);
		KeyStore store = KeyStore.getInstance("PKCS12");
		store.load(inputStream, password.toCharArray());
		inputStream.close();
		return store;
	}
	
	/**
	 * Save a given certificate to a file for later use
	 *
	 * @param certHolder certificate holder object for the certificate to be saved
	 * @param fileName   to store certificate as (eg: uct.der for CA)
	 */
	public static void saveCertToDER(X509CertificateHolder certHolder, String fileName) throws IOException {
		FileOutputStream fileOutputStream = new FileOutputStream(fileName);
		fileOutputStream.write(certHolder.getEncoded());
		fileOutputStream.flush();
		fileOutputStream.close();
	}
	
	/**
	 * The private key is saved in a password-protected file called a keystore.
	 * A keystore can contain many keys and each key is protected with its own password.
	 * In this case we are only saving one key into this keystore, Eg: the certificate authority's private key.
	 *
	 * @param kp               KeyPair containing the private key to be stored
	 * @param certHolder       containing the public key for the kp
	 * @param storeKeyAlias    Alias name for key
	 * @param storeKeyPassword to protect the key
	 * @param filename         to save the store as (uct.p12 for CA)
	 * @param storePassword    the password to generate the keystore integrity check
	 */
	public static void saveToPKCS12(KeyPair kp, X509CertificateHolder certHolder, Certificate[] certificateChain, String storeKeyAlias, String storeKeyPassword, String filename, String storePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore store = KeyStore.getInstance("PKCS12");
		store.load(null, null); //create empty keystore
		
		//Here we specify the password for the key
		store.setKeyEntry(storeKeyAlias, kp.getPrivate(), storeKeyPassword.toCharArray(), certificateChain);
		
		FileOutputStream fileOutputStream = new FileOutputStream(filename);
		store.store(fileOutputStream, storePassword.toCharArray()); //Here we specify the password for the keystore
		fileOutputStream.flush();
		fileOutputStream.close();
	}
	
	/**
	 * Generate an X509 certificate given a key pair and x500 name
	 *
	 * @param issuerPrivateKey private key of the certificate issuer
	 * @param subjectPublicKey public key of actual certificate owner
	 * @param issuerName name of certificate issuer
	 * @param subjectName name of actual certificate owner
	 * @return The X509CertificateHolder object for the created certificate
	 */
	public static X509CertificateHolder generateX509CertificateHolder(PrivateKey issuerPrivateKey, PublicKey subjectPublicKey, X500Name issuerName, X500Name subjectName) throws OperatorCreationException {
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
				issuerName,
				BigInteger.valueOf(1),
				new Date(System.currentTimeMillis() - millisecondMonth * 6),
				new Date(System.currentTimeMillis() + millisecondMonth * 6),
				subjectName,
				subjectPublicKey
		);
		
		//Sign the certificate using the issuer's private key (with the SHA1withRSA signing algorithm)
		return certGen.build(new JcaContentSignerBuilder("SHA1withRSA").build(issuerPrivateKey));
	}
	
	/**
	 * Generates an X500 formatted name for use in X509CertificateHolder's
	 *
	 * @param countryCode the country the certificate owner is located in
	 * @param organisation the organisation the certificate owner belongs to
	 * @param organisationalUnit organisational unit within an institutional hierarchy
	 * @param email email address of certificate owner
	 * @return the X500Name for the certificate owner
	 */
	public static X500Name generateX500Name(String countryCode, String organisation, String organisationalUnit, String email) {
		X500NameBuilder nameBuilder = new X500NameBuilder();
		
		nameBuilder.addRDN(BCStyle.C, countryCode);
		nameBuilder.addRDN(BCStyle.O, organisation);
		nameBuilder.addRDN(BCStyle.OU, organisationalUnit);
		nameBuilder.addRDN(BCStyle.EmailAddress, email); //Dont think this is strictly necessary
		
		return nameBuilder.build();
	}
	
	/**
	 * Generate a Public/Private Key Pair using RSA4096
	 *
	 * @return the KeyPair
	 */
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		System.out.println("Generating key pair using RSA4096...");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(4096);
		KeyPair returnable = keyGen.generateKeyPair();
		System.out.println("Key pair generated\nPublic Key:\n" + returnable.getPublic() + "\nPrivate Key:\n" + returnable.getPrivate());
		return returnable;
	}
	
	/**
	 * Generates a client certificate and saves it as a file
	 *
	 * @param username the username of the client
	 * @param password the client's password
	 */
	public static void generateClientCert(String username, String password) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, OperatorCreationException {
		CertificateAuthority ca = new CertificateAuthority();
		X500NameBuilder nameBuilder = new X500NameBuilder();
		
		nameBuilder.addRDN(BCStyle.NAME, username);
		
		// generate key pair
		KeyPair kp = CertificateUtils.generateKeyPair();
		
		// generate signed certificate
		X509CertificateHolder certHolder = ca.getSignedClientCertificate(kp.getPublic(), nameBuilder.build());
		System.out.println("\nNew client certificate created for " + username);
		
		// save cert and keys to file
		System.out.println("saving certificate and keys to file");
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		X509Certificate caCert = converter.getCertificate(ca.getCaCertHolder());
		X509Certificate clientCert = converter.getCertificate(certHolder);
		Certificate[] certChain = new Certificate[]{clientCert, caCert};
		CertificateUtils.saveToPKCS12(kp, certHolder, certChain, username, password, username + ".p12", password);

		System.out.println("saving certificate to file");
		CertificateUtils.saveCertToDER(certHolder, username + ".der");
	}
}
