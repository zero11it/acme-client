/**
 * Copyright (C) 2015 Zero11 S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package it.zero11.acme.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class X509Utils {
	public static final String DEFAULT_ALGHORITM = "RSA";

	public static PKCS10CertificationRequest generateCSR(String commonName, KeyPair pair) throws OperatorCreationException {
		X500NameBuilder namebuilder = new X500NameBuilder(X500Name.getDefaultStyle());
		namebuilder.addRDN(BCStyle.CN, commonName);
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(namebuilder.build(), pair.getPublic());
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer = csBuilder.build(pair.getPrivate());
		PKCS10CertificationRequest request = p10Builder.build(signer);
		return request;
	}

	public static KeyPair generateKeyPair(int size) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DEFAULT_ALGHORITM);
		keyGen.initialize(size);
		return keyGen.generateKeyPair();
	}

	public static KeyPair loadPEMKeyPair(InputStream privateKeyInputStream) throws IOException {
		try(PEMParser pemParser = new PEMParser(new InputStreamReader(privateKeyInputStream))){
			PEMKeyPair keyPair = (PEMKeyPair) pemParser.readObject();
			return new JcaPEMKeyConverter().getKeyPair(keyPair);
		}
	}

	public static void savePEM(OutputStream outputStream, Object object) throws IOException {
		try(JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(outputStream))){
			writer.writeObject(object);
		}
	}

	public static String getCACertificateURL(X509Certificate certificate) throws IOException {
		byte[] bOctets = ((ASN1OctetString) ASN1Primitive.fromByteArray(certificate.getExtensionValue(Extension.authorityInfoAccess.getId()))).getOctets();
		AuthorityInformationAccess access = AuthorityInformationAccess.getInstance(ASN1Sequence.fromByteArray(bOctets));
		for (AccessDescription ad:access.getAccessDescriptions()){
			if (ad.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)){
				return ad.getAccessLocation().getName().toString();
			}
		}
		return null;
	}
}
