import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
/**
 * Creates a Certificate Authority (CA) object that loads the keystore that is used to get the CA private key
 * and create a holding object for the X.509 certificate for the CA.
 * Has get method for the CA holding object.
 * Signs certificates for client
 */
public class CertificateAuthority {

	private X509CertificateHolder caCertHolder;
	private PrivateKey caPrivateKey;

	/**
	 * Constructor method that creates a CertificateAuthority object that creates and holds a keystore and a certificate holder.
	 * Also stores the private key for the CA.
	 */
	public CertificateAuthority() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, OperatorCreationException {
		//Load keystore from PKCS12 file
		KeyStore store = CertificateUtils.loadKeyStoreFromPKCS12("uct.p12", "123");

		//Get private key from keystore
		caPrivateKey = (PrivateKey) store.getKey("uct", "123".toCharArray());

		//Get CA certificate from keystore
		Certificate[] chain = store.getCertificateChain("uct");
		caCertHolder = new JcaX509CertificateHolder((X509Certificate) chain[0]);
	}

	/**
	 * A get method used to access the certificate holding object for the CA's X.509 certificate
 	 * @return the certificate holding object for the CA
	 */
	public X509CertificateHolder getCaCertHolder() {
		return caCertHolder;
	}

	/**
	 * Fulfils a certificate signing request from a client.
	 * @param subjectPublicKey the certificate owner's public key
	 * @param subjectName the certificate owner's name
	 * @return the X.509CertificateHolder object for the particular client specified
	 */
	public X509CertificateHolder getSignedClientCertificate(PublicKey subjectPublicKey, X500Name subjectName) throws OperatorCreationException {
		return CertificateUtils.generateX509CertificateHolder(caPrivateKey, subjectPublicKey, caCertHolder.getSubject(), subjectName);
	}
}
