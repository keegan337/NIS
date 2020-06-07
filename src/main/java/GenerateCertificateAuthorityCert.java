import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Generates keys for the certificate authority.
 * These keys will be used to sign certificates for each user.
 */
public class GenerateCertificateAuthorityCert {
	
	public static final long millisecondMonth = 1000L * 60 * 60 * 24 * 30;
	
	public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, IOException, KeyStoreException, CertificateException {
		KeyPair kp = generateKeyPair();
		
		System.out.println("creating signed certificate");
		X500Name name = getX500Name("ZA", "University of Cape Town", "Department of Computer Science", "dept@cs.uct.ac.za");
		X509CertificateHolder certHolder = getX509CertificateHolder(kp, name);
		
		saveCertToFile(certHolder, "uct.der");
		
		saverPkToFile(kp, certHolder);
	}
	
	/** Default values used by Stuart when initially writing this for the CA class */
	public static void saverPkToFile(KeyPair kp, X509CertificateHolder certHolder) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		saverPkToFile(kp, certHolder, null, null, "uct", "123", "uct.p12", "123");
	}
	
	/**
	 * The private key is saved in a password-protected file called a keystore.
	 * A keystore can contain many keys and each key is protected with its own password.
	 * In this case we are only saving one key into this keystore, Eg: the certificate authority's private key.
	 * @param kp KeyPair containing the private key to be stored
	 * @param certHolder containing the public key for the kp
	 * @param storeStream the input stream from which the keystore is loaded, or null (for CA null)
	 * @param storeLoadPassword Needed a separate one for loading in case of null (as in CA); the password used to check the integrity of the keystore, the password used to unlock the keystore, or null
	 * @param storeKeyAlias Alias name for key
	 * @param storeKeyPassword to protect the key
	 * @param filename to save the store as (uct.p12 for CA)
	 * @param storePassword the password to generate the keystore integrity check
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	public static void saverPkToFile(KeyPair kp, X509CertificateHolder certHolder, InputStream storeStream, char[] storeLoadPassword, String storeKeyAlias, String storeKeyPassword, String filename, String storePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		System.out.println("saving private key to file");

		KeyStore store = KeyStore.getInstance("PKCS12");
		store.load(storeStream, storeLoadPassword); //TODO why is storeLoadPassword passed as null
		
		X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
		Certificate[] certChain = new Certificate[]{cert};
		
		//Here we specify the password for the key
		store.setKeyEntry(storeKeyAlias, kp.getPrivate(), storeKeyPassword.toCharArray(), certChain);
		
		FileOutputStream fileOutputStream = new FileOutputStream(filename);
		store.store(fileOutputStream, storePassword.toCharArray()); //Here we specify the password for the keystore
		fileOutputStream.flush();
		fileOutputStream.close();
	}
	
	/**
	 * Save a given certificate to a file for later use
	 * @param certHolder certificate
	 * @param fileName to store certificate as (eg: uct.der for CA)
	 * @throws IOException
	 */
	public static void saveCertToFile(X509CertificateHolder certHolder, String fileName) throws IOException {
		System.out.println("saving certificate to file");
		//Write certificate to file
		FileOutputStream fileOutputStream = new FileOutputStream(fileName);
		fileOutputStream.write(certHolder.getEncoded());
		fileOutputStream.flush();
		fileOutputStream.close();
	}
	
	/**
	 * Generate an X509 certificate given a key pair and x500 name
	 * @param kp keyPair
	 * @param name
	 * @return The X509Certificate Holder
	 * @throws OperatorCreationException
	 */
	public static X509CertificateHolder getX509CertificateHolder(KeyPair kp, X500Name name) throws OperatorCreationException {
		//issuer and subject names are the same because it is self-signed
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
				name,
				BigInteger.valueOf(1),
				new Date(System.currentTimeMillis() - millisecondMonth),
				new Date(System.currentTimeMillis() + millisecondMonth),
				name,
				kp.getPublic()
		);
		
		//Sign the certificate using the private key (with the SHA1withRSA signing algorithm)
		return certGen.build(new JcaContentSignerBuilder("SHA1withRSA").build(kp.getPrivate()));
	}
	
	/**
	 * Generates an X500 formatted name for use in X509CertificateHolder's
	 * @param countryCode
	 * @param organisation
	 * @param organisationalUnit
	 * @param email
	 * @return the X500Name
	 */
	public static X500Name getX500Name(String countryCode, String organisation, String organisationalUnit, String email) {
		X500NameBuilder nameBuilder = new X500NameBuilder();
		
		nameBuilder.addRDN(BCStyle.C, countryCode);
		nameBuilder.addRDN(BCStyle.O, organisation);
		nameBuilder.addRDN(BCStyle.OU, organisationalUnit);
		nameBuilder.addRDN(BCStyle.EmailAddress, email); //Dont think this is strictly necessary
		
		return nameBuilder.build();
	}
	
	/**
	 * Generate a Public/Private Key Pair using RSA4096
	 * @return the KeyPair
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		System.out.println("generating key pair");
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(4096);
		return keyGen.generateKeyPair();
	}
}
