import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Generates keys for the certificate authority.
 * These keys will be used to sign certificates for each user.
 */
public class GenerateCertificateAuthorityCert {
	
	public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, IOException, KeyStoreException, CertificateException {
		System.out.println("generating key pair");
		KeyPair kp = CertificateUtils.generateKeyPair();
		
		System.out.println("creating signed certificate");
		X500Name name = CertificateUtils.getX500Name("ZA", "University of Cape Town", "Department of Computer Science", "dept@cs.uct.ac.za");
		X509CertificateHolder certHolder = CertificateUtils.getX509CertificateHolder(kp.getPrivate(), kp.getPublic(), name, name);

		System.out.println("saving certificate to file");
		CertificateUtils.saveCertToDER(certHolder, "uct.der");

		System.out.println("saving private key to file");
		X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
		Certificate[] certChain = new Certificate[]{cert};
		CertificateUtils.saveToPKCS12(kp, certHolder, certChain, "uct", "123", "uct.p12", "123");
	}
}
