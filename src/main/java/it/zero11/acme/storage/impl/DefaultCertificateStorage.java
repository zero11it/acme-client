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
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class DefaultCertificateStorage implements CertificateStorage {
	private static final int USER_KEY_SIZE = 4096;
	private static final int WEBSITE_KEY_SIZE = 2048;
	
	//TODO: handle certificate / csr history and private key renewal as needed
	
	@Override
	public KeyPair getDomainKeyPair(String domain) {
		try {
			return getKeyPair(new File(domain + ".key"), WEBSITE_KEY_SIZE);
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
	public void saveCertificate(String domain, X509Certificate certificate) {
		try(OutputStream outputStream = new FileOutputStream(domain + ".crt")) {
			X509Utils.savePEM(outputStream, certificate);
		} catch (IOException e) {
			throw new CertificateStorageException(e);
		}
	}

	@Override
	public void saveCSR(String domain, PKCS10CertificationRequest csr) {
		try(OutputStream outputStream = new FileOutputStream(domain + ".csr")) {
			X509Utils.savePEM(outputStream, csr);
		} catch (IOException e) {
			throw new CertificateStorageException(e);
		}
	}
}
