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

package it.zero11.acme.storage.impl;

import it.zero11.acme.storage.CertificateStorage;
import it.zero11.acme.storage.CertificateStorageException;
import it.zero11.acme.utils.X509Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.x509.util.StreamParsingException;

public class DefaultCertificateStorage implements CertificateStorage {
	private static final int USER_KEY_SIZE = 4096;
	private static final int WEBSITE_KEY_SIZE = 2048;
	private final boolean saveCAIntermediateCertificate;
	//TODO: handle certificate / csr history and private key renewal as needed

	public DefaultCertificateStorage(){
		this(false);
	}

	public DefaultCertificateStorage(boolean saveCAIntermediateCertificate){
		this.saveCAIntermediateCertificate = saveCAIntermediateCertificate;
	}

	@Override
	public KeyPair getDomainKeyPair(String[] domains) {
		try {
			KeyPair pair = getKeyPair(new File(domains[0] + ".key"), WEBSITE_KEY_SIZE);
			if (domains.length > 1){
				for (String domain:domains){
					overrideKeyPairIfDifferent(new File(domain + ".key"), pair);
				}
			}
			return pair;
		} catch (NoSuchAlgorithmException|IOException e) {
			throw new CertificateStorageException(e);
		}
	}

	@Override
	public KeyPair getUserKeyPair() {
		try {
			return getKeyPair(new File("user.key"), USER_KEY_SIZE);
		} catch (NoSuchAlgorithmException|IOException e) {
			throw new CertificateStorageException(e);
		}
	}

	private void overrideKeyPairIfDifferent(File filePrivateKey, KeyPair pair) throws IOException {
		if (filePrivateKey.exists()){
			KeyPair existing;
			try(InputStream privateKeyInputStream = new FileInputStream(filePrivateKey)){
				existing = X509Utils.loadPEMKeyPair(privateKeyInputStream);
			}
			if (!existing.equals(pair)){
				try(OutputStream outputStream = new FileOutputStream(filePrivateKey)){
					X509Utils.savePEM(outputStream, pair);
				}
			}
		}else{
			try(OutputStream outputStream = new FileOutputStream(filePrivateKey)){
				X509Utils.savePEM(outputStream, pair);
			}
		}
	}
	
	private KeyPair getKeyPair(File filePrivateKey, int size) throws IOException, NoSuchAlgorithmException {
		if (filePrivateKey.exists()){
			try(InputStream privateKeyInputStream = new FileInputStream(filePrivateKey)){
				return X509Utils.loadPEMKeyPair(privateKeyInputStream);
			}
		}else{
			KeyPair newPair = X509Utils.generateKeyPair(size); 
			try(OutputStream outputStream = new FileOutputStream(filePrivateKey)){
				X509Utils.savePEM(outputStream, newPair);
			}
			return newPair;
		}
	}

	@Override
	public void saveCertificate(String[] domains, X509Certificate certificate) {
		for (String domain:domains){
			try(OutputStream outputStream = new FileOutputStream(domain + ".crt")) {
				X509Utils.savePEM(outputStream, certificate);
			} catch (IOException e) {
				throw new CertificateStorageException(e);
			}
		}
		if (saveCAIntermediateCertificate){
			try{
				String caIntermediateCertificateURL = X509Utils.getCACertificateURL(certificate);
				if (caIntermediateCertificateURL != null){
					X509CertificateObject caIntermediateCertificate;
					try(InputStream is = new URL(caIntermediateCertificateURL).openStream()){
						X509CertParser certParser = new X509CertParser();
						certParser.engineInit(is);
						caIntermediateCertificate =  (X509CertificateObject) certParser.engineRead();
					}
					for (String domain:domains){
						try(OutputStream outputStream = new FileOutputStream(domain + ".chain.crt")) {
							X509Utils.savePEM(outputStream, caIntermediateCertificate);
						}
					}
				}
			}catch (IOException|StreamParsingException e) {
				throw new CertificateStorageException(e);
			}
		}
	}

	@Override
	public void saveCSR(String[] domains, PKCS10CertificationRequest csr) {
		for (String domain:domains){
			try(OutputStream outputStream = new FileOutputStream(domain + ".csr")) {
				X509Utils.savePEM(outputStream, csr);
			} catch (IOException e) {
				throw new CertificateStorageException(e);
			}
		}
	}
}
