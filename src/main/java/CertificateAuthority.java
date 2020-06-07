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

public class CertificateAuthority {

	private X509CertificateHolder caCertHolder;
	private PrivateKey caPrivateKey;

	public CertificateAuthority() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
		//Load keystore from PKCS12 file
		KeyStore store = CertificateUtils.loadKeyStoreFromPKCS12("uct.p12", "123");

		//Get private key from keystore
		caPrivateKey = (PrivateKey) store.getKey("uct", "123".toCharArray());

		//Get CA certificate from keystore
		Certificate[] chain = store.getCertificateChain("uct");
		caCertHolder = new JcaX509CertificateHolder((X509Certificate) chain[0]);
	}

	public X509CertificateHolder getCaCertHolder() {
		return caCertHolder;
	}

	public X509CertificateHolder getSignedClientCertificate(PublicKey subjectPublicKey, X500Name subjectName) throws OperatorCreationException {
		return CertificateUtils.getX509CertificateHolder(caPrivateKey, subjectPublicKey, caCertHolder.getSubject(), subjectName);
	}
}
