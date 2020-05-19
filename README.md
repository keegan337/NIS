# NIS Assignment

## Notes

### Libraries
JDK14 version of [Bouncy Castle](https://www.bouncycastle.org/) 1.51

### Certificate Format
X509 v3 certificates

Using der encoding when saving certificates to files.
See [here](https://support.ssl.com/Knowledgebase/Article/View/19/0/der-vs-crt-vs-cer-vs-pem-certificates-and-how-to-convert-them) for an explanation.
The contents of a der encoded certificate can be viewed using:
```bash
openssl x509 -in uct.der -inform der -text -noout
```

### Private key storage
Private keys are stored in [PKCS12](https://en.wikipedia.org/wiki/PKCS_12) files.
