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
public class GenerateRootCert {
	public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, IOException, KeyStoreException, CertificateException {
		System.out.println("generating key pair");

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(4096);
		KeyPair kp = keyGen.generateKeyPair();

		System.out.println("creating signed certificate");

		X500NameBuilder nameBuilder = new X500NameBuilder();

		nameBuilder.addRDN(BCStyle.C, "ZA");
		nameBuilder.addRDN(BCStyle.O, "University of Cape Town");
		nameBuilder.addRDN(BCStyle.OU, "Department of Computer Science");
		nameBuilder.addRDN(BCStyle.EmailAddress, "dept@cs.uct.ac.za");

		X500Name name = nameBuilder.build();

		//issuer and subject names are the same because it is self-signed
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
				name,
				BigInteger.valueOf(1),
				new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
				new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
				name,
				kp.getPublic()
		);

		//Sign the certificate using the private key (with the SHA1withRSA signing algorithm)
		X509CertificateHolder certHolder = certGen.build(new JcaContentSignerBuilder("SHA1withRSA").build(kp.getPrivate()));

		System.out.println("saving certificate to file");

		//Write certificate to file
		FileOutputStream fileOutputStream = new FileOutputStream("uct.der");
		fileOutputStream.write(certHolder.getEncoded());
		fileOutputStream.flush();
		fileOutputStream.close();

		System.out.println("saving private key to file");

		//Write private key to file

		/*
		 * The private key is saved in a password-protected file called a keystore.
		 * A keystore can contain many keys and each key is protected with its own password.
		 * In this case we are only saving one key into this keystore: the certificate authority's private key.
		 */
		KeyStore store = KeyStore.getInstance("PKCS12");
		store.load(null, null);

		X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
		Certificate[] chain = new Certificate[]{cert};

		//Here we specify the password for the key
		store.setKeyEntry("uct", kp.getPrivate(), "123".toCharArray(), chain);

		fileOutputStream = new FileOutputStream("uct.p12");
		store.store(fileOutputStream, "123".toCharArray()); //Here we specify the password for the keystore
		fileOutputStream.flush();
		fileOutputStream.close();
	}
}
