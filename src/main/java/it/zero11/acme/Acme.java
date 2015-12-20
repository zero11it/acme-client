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

package it.zero11.acme;

import it.zero11.acme.storage.CertificateStorage;
import it.zero11.acme.utils.JWKUtils;
import it.zero11.acme.utils.X509Utils;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.TreeMap;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.x509.util.StreamParsingException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;

public class Acme {
	private static final String AGREEMENT_KEY = "agreement";
	private static final String CHALLENGE_STATUS_KEY = "status";
	private static final String CHALLENGE_STATUS_PENDING = "pending";
	private static final String CHALLENGE_STATUS_VALID = "valid";
	private static final String CHALLENGE_TLS_KEY = "tls";
	private static final String CHALLENGE_TOKEN_KEY = "token";
	private static final String CHALLENGE_KEY_AUTHORIZATION_KEY = "keyAuthorization";
	private static final String CHALLENGE_TYPE_KEY = "type";
	private static final String CHALLENGE_TYPE_HTTP_01 = "http-01";
	private static final String CHALLENGE_URI_KEY = "uri";
	private static final String CHALLENGES_KEY = "challenges";
	private static final String CONTACT_KEY = "contact";
	private static final String CSR_KEY = "csr";
	private static final String HEADER_REPLAY_NONCE = "replay-nonce";
	private static final String IDENTIFIER_KEY = "identifier";
	private static final String IDENTIFIER_TYPE_DNS = "dns";
	private static final String IDENTIFIER_TYPE_KEY = "type";
	private static final String IDENTIFIER_VALUE_KEY = "value";
	private static final String NONCE_KEY = "nonce";
	private static final String RESOURCE_CHALLENGE = "challenge";
	private static final String RESOURCE_KEY = "resource";
	private static final String RESOURCE_NEW_AUTHZ = "new-authz";
	private static final String RESOURCE_NEW_CERT = "new-cert";
	private static final String RESOURCE_NEW_REG = "new-reg";
	private static final String RESOURCE_UPDATE_REGISTRATION = "reg";

	private static SSLContext getTrustAllCertificateSSLContext() throws NoSuchAlgorithmException, KeyManagementException{
		TrustManager[] trustAllCerts = new TrustManager[] { 
				new X509TrustManager() {     
					@Override
					public void checkClientTrusted(X509Certificate[] certs, String authType) {
					} 
					@Override
					public void checkServerTrusted(X509Certificate[] certs, String authType) {
					}
					@Override
					public X509Certificate[] getAcceptedIssuers() {
						return new X509Certificate[0];
					}
				} 
		}; 

		SSLContext sc = SSLContext.getInstance("SSL"); 
		sc.init(null, trustAllCerts, new SecureRandom()); 
		return sc;
	}

	private final CertificateStorage certificateStorage; 
	private final String certificationAuthorityURI;
	private final boolean trustAllCertificate;
	private final boolean debugHttpRequests;

	public Acme(String certificationAuthorityURI, CertificateStorage certificateStorage){
		this(certificationAuthorityURI, certificateStorage, false, false);
	}

	public Acme(String certificationAuthorityURI, CertificateStorage certificateStorage, boolean trustAllCertificate) {
		this(certificationAuthorityURI, certificateStorage, trustAllCertificate, false);
	}
	
	public Acme(String certificationAuthorityURI, CertificateStorage certificateStorage, boolean trustAllCertificate, boolean debugHttpRequests){
		this.certificationAuthorityURI = certificationAuthorityURI;
		this.certificateStorage = certificateStorage;
		this.trustAllCertificate = trustAllCertificate;
		this.debugHttpRequests = debugHttpRequests;
	}

	@SuppressWarnings("serial")
	protected String getAuthorizationRequest(final KeyPair userKey, final String nextNonce, final String domain) {
		return Jwts.builder()
				.setHeaderParam(NONCE_KEY, nextNonce)
				.setHeaderParam(JwsHeader.JSON_WEB_KEY, JWKUtils.getWebKey(userKey.getPublic()))
				.setClaims(new TreeMap<String, Object>(){{
					put(RESOURCE_KEY, RESOURCE_NEW_AUTHZ);
					put(IDENTIFIER_KEY, new TreeMap<String, Object>(){{
						put(IDENTIFIER_TYPE_KEY, IDENTIFIER_TYPE_DNS);
						put(IDENTIFIER_VALUE_KEY, domain);
					}});
				}})
				.signWith(getJWSSignatureAlgorithm(), userKey.getPrivate())
				.compact();
	}

	public X509Certificate getCertificate(final String[] domains, final String agreement, final String[] contacts, AcmeChallengeListener challengeListener) throws IOException, InterruptedException, OperatorCreationException, StreamParsingException{
		KeyPair userKey = certificateStorage.getUserKeyPair();

		/**
		 * Step 1: Get initial Nonce
		 */
		String nextNonce;
		{
			Response initialNonceResponse = getRestClient()
					.target(certificationAuthorityURI)
					.path(RESOURCE_NEW_REG)
					.request()
					.head();
			nextNonce = initialNonceResponse.getHeaderString(HEADER_REPLAY_NONCE);
		}
		
		Thread.sleep(1000L);
		
		/**
		 * Step 2: Register a new account with CA
		 */
		String registrationURI;
		{
			Response registrationResponse = getRestClient()
					.target(certificationAuthorityURI)
					.path(RESOURCE_NEW_REG)
					.request()
					.accept(MediaType.APPLICATION_JSON)
					.post(Entity.entity(getRegistrationRequest(userKey, nextNonce, agreement, contacts), MediaType.APPLICATION_JSON));

			nextNonce = registrationResponse.getHeaderString(HEADER_REPLAY_NONCE);

			if (registrationResponse.getStatus() != Status.CREATED.getStatusCode() &&
					registrationResponse.getStatus() != Status.CONFLICT.getStatusCode()){
				throw new AcmeException("Registration failed.", registrationResponse);
			}

			registrationURI = registrationResponse.getHeaderString(HttpHeaders.LOCATION);
		}
		
		Thread.sleep(1000L);
		
		for (String domain:domains){
			/**
			 * Step 3: Ask CA a challenge for our domain
			 */
			String challengeURI = null;
			String challengeToken = null;
			{
				Response authorizationResponse = getRestClient()
						.target(certificationAuthorityURI)
						.path(RESOURCE_NEW_AUTHZ)
						.request()
						.accept(MediaType.APPLICATION_JSON)
						.post(Entity.entity(getAuthorizationRequest(userKey, nextNonce, domain), MediaType.APPLICATION_JSON));
	
				nextNonce = authorizationResponse.getHeaderString(HEADER_REPLAY_NONCE);
	
				if (authorizationResponse.getStatus() == Status.FORBIDDEN.getStatusCode()){
					if (agreement != null){
						/**
						 * Step 3b: sign new agreement
						 */
						Response updateRegistrationResponse = getRestClient()
								.target(registrationURI)
								.request()
								.accept(MediaType.APPLICATION_JSON)
								.post(Entity.entity(getUpdateRegistrationRequest(userKey, nextNonce, agreement, contacts), MediaType.APPLICATION_JSON));
	
						nextNonce = updateRegistrationResponse.getHeaderString(HEADER_REPLAY_NONCE);
	
						if (updateRegistrationResponse.getStatus() != Status.ACCEPTED.getStatusCode()){
							throw new AcmeException("Registration failed.", updateRegistrationResponse);
						}
	
						/**
						 * Step 3c: Ask CA a challenge for our domain after agreement update
						 */
						authorizationResponse = getRestClient()
								.target(certificationAuthorityURI)
								.path(RESOURCE_NEW_AUTHZ)
								.request()
								.accept(MediaType.APPLICATION_JSON)
								.post(Entity.entity(getAuthorizationRequest(userKey, nextNonce, domain), MediaType.APPLICATION_JSON));
	
						nextNonce = authorizationResponse.getHeaderString(HEADER_REPLAY_NONCE);
	
						if (authorizationResponse.getStatus() != Status.CREATED.getStatusCode()){
							throw new AcmeException("Client unautorized. May need to accept new terms.", authorizationResponse);
						}
					}else{
						throw new AcmeException("Client unautorized. May need to accept new terms.", authorizationResponse);
					}
				}else if (authorizationResponse.getStatus() != Status.CREATED.getStatusCode()){
					throw new AcmeException("Failed to create new authorization request.", authorizationResponse);
				}
	
				JsonNode authorizationResponseJson = new ObjectMapper().readTree((InputStream)authorizationResponse.getEntity());
	
				for (JsonNode challange:authorizationResponseJson.get(CHALLENGES_KEY)){
					String challengeType = challange.get(CHALLENGE_TYPE_KEY).asText();
					String token = challange.get(CHALLENGE_TOKEN_KEY).asText();
					String uri = challange.get(CHALLENGE_URI_KEY).asText();
	
					if (handleChallenge(userKey, domain, challengeListener, challengeType, token, uri)){
						challengeURI = uri;
						challengeToken = token;
						break;
					}
				}
				if (challengeURI == null){
					throw new AcmeException("No challenge completed.");
				}
			}
	
			Thread.sleep(1000L);
			
			/**
			 * Step 4: Ask CA to verify challenge
			 */
			{
				Response answerToChallengeResponse = getRestClient()
						.target(challengeURI)
						.request()
						.accept(MediaType.APPLICATION_JSON)
						.post(Entity.entity(getHTTP01ChallengeRequest(userKey, challengeToken, nextNonce), MediaType.APPLICATION_JSON));
	
				nextNonce = answerToChallengeResponse.getHeaderString(HEADER_REPLAY_NONCE);
	
				if (answerToChallengeResponse.getStatus() != Status.ACCEPTED.getStatusCode()){
					throw new AcmeException("Failed to post challenge.", answerToChallengeResponse);
				}
			}
			
			Thread.sleep(1000L);
			
			/**
			 * Step 5: Waiting for challenge verification
			 */
			{
				int validateChallengeRetryCount = 20;
				while (--validateChallengeRetryCount > 0){
					Thread.sleep(5000L);
	
					Response validateChallengeResponse = getRestClient()
							.target(challengeURI)
							.request()
							.accept(MediaType.APPLICATION_JSON)
							.get();
					if (validateChallengeResponse.getStatus() == Status.ACCEPTED.getStatusCode()){
						JsonNode validateChallengeJson = new ObjectMapper().readTree((InputStream)validateChallengeResponse.getEntity());
						String status = validateChallengeJson.get(CHALLENGE_STATUS_KEY).asText();
						if (status.equals(CHALLENGE_STATUS_VALID)){
							validateChallengeRetryCount = -1;
						}else if(!status.equals(CHALLENGE_STATUS_PENDING)){
							challengeListener.challengeFailed(domain);
							throw new AcmeException("Failed verify challenge. Status: " + status, validateChallengeResponse);
						}
					}else{
						challengeListener.challengeFailed(domain);
						throw new AcmeException("Failed verify challenge.", validateChallengeResponse);
					}
				}
				if (validateChallengeRetryCount == 0){
					challengeListener.challengeFailed(domain);
					throw new AcmeException("Failed verify challenge. Timeout.");
				}
	
				challengeListener.challengeCompleted(domain);
			}
			
			Thread.sleep(1000L);
		}
		
		/**
		 * Step 6: Generate CSR
		 */
		KeyPair domainKey = certificateStorage.getDomainKeyPair(domains);
		final PKCS10CertificationRequest csr = X509Utils.generateCSR(domains, domainKey);
		certificateStorage.saveCSR(domains, csr);
		
		Thread.sleep(1000L);
		
		/**
		 * Step 7: Ask for new certificate
		 */
		String certificateURL;
		{
			Response newCertificateResponse = getRestClient()
					.target(certificationAuthorityURI)
					.path(RESOURCE_NEW_CERT)
					.request()
					.accept(MediaType.APPLICATION_JSON)
					.post(Entity.entity(getNewCertificateRequest(userKey, nextNonce, csr), MediaType.APPLICATION_JSON));

			if (newCertificateResponse.getStatus() == Status.CREATED.getStatusCode()){
				certificateURL = newCertificateResponse.getHeaderString(HttpHeaders.LOCATION);
				if (newCertificateResponse.getLength() > 0){
					return extractCertificate(domains, (InputStream) newCertificateResponse.getEntity());
				}
			}else if (newCertificateResponse.getStatus() == 429){
				throw new AcmeException("You are rate limited.", newCertificateResponse);
			}else{
				throw new AcmeException("Failed to download certificate.", newCertificateResponse);
			}
		}
		
		Thread.sleep(1000L);
		
		/**
		 * Step 8: Fetch new certificate (if not already returned)
		 */
		{
			int downloadRetryCount = 20;
			while(downloadRetryCount-- > 0){
				Thread.sleep(5000L);
				Response certificateResponse = getRestClient()
						.target(certificateURL)
						.request()
						.get();
				if (certificateResponse.getStatus() == Status.CREATED.getStatusCode()){
					if (certificateResponse.getLength() > 0){
						return extractCertificate(domains, (InputStream) certificateResponse.getEntity());
					}
				}else{
					throw new AcmeException("Failed to download certificate.", certificateResponse);
				}
			}

			throw new AcmeException("Failed to download certificate. Timeout.");
		}
	}

	private X509Certificate extractCertificate(final String[] domains, InputStream inputStream)
			throws StreamParsingException {
		X509CertParser certParser = new X509CertParser();
		certParser.engineInit(inputStream);
		X509Certificate certificate = (X509Certificate) certParser.engineRead();
		certificateStorage.saveCertificate(domains, certificate);
		return certificate;
	}

	protected SignatureAlgorithm getJWSSignatureAlgorithm() {
		return SignatureAlgorithm.RS256;
	}

	@SuppressWarnings("serial")
	protected String getNewCertificateRequest(final KeyPair userKey, final String nonce, final PKCS10CertificationRequest csr) throws IOException {
		return Jwts.builder()
				.setHeaderParam(NONCE_KEY, nonce)
				.setHeaderParam(JwsHeader.JSON_WEB_KEY, JWKUtils.getWebKey(userKey.getPublic()))
				.setClaims(new TreeMap<String, Object>(){{
					put(RESOURCE_KEY, RESOURCE_NEW_CERT);
					put(CSR_KEY, TextCodec.BASE64URL.encode(csr.getEncoded()));
				}})
				.signWith(getJWSSignatureAlgorithm(), userKey.getPrivate())
				.compact();
	}

	@SuppressWarnings("serial")
	protected String getRegistrationRequest(final KeyPair userKey, final String nonce, final String agreement, final String[] contacts) {
		return Jwts.builder()
				.setHeaderParam(NONCE_KEY, nonce)
				.setHeaderParam(JwsHeader.JSON_WEB_KEY, JWKUtils.getWebKey(userKey.getPublic()))
				.setClaims(new TreeMap<String, Object>(){{
					put(RESOURCE_KEY, RESOURCE_NEW_REG);
					if (contacts != null && contacts.length > 0){
						put(CONTACT_KEY, contacts);
					}
					if (agreement != null){
						put(AGREEMENT_KEY, agreement);
					}
				}})
				.signWith(getJWSSignatureAlgorithm(), userKey.getPrivate())
				.compact();
	}

	protected Client getRestClient(){
		try{
			Client client = ClientBuilder.newBuilder().sslContext((trustAllCertificate) ? getTrustAllCertificateSSLContext() : SSLContext.getDefault()).build();
			
			if (debugHttpRequests){
				try{
					Class<?> clazz = Class.forName("org.glassfish.jersey.filter.LoggingFilter");
					Constructor<?> contructor = clazz.getConstructor(Logger.class, boolean.class);
					client.register(contructor.newInstance(Logger.getLogger("it.zero11.acme"), true));
				}catch(Exception e){
					
				}
			}
			
			return client;
		}catch(NoSuchAlgorithmException | KeyManagementException e){
			throw new AcmeException(e);
		}
	}

	protected String getHTTP01ChallengeContent(final KeyPair userKey, final String token) {
		return token + "." + JWKUtils.getWebKeyThumbprintSHA256(userKey.getPublic());
	}

	@SuppressWarnings("serial")
	protected String getHTTP01ChallengeRequest(final KeyPair userKey, final String token, final String nonce) {
		return Jwts.builder()
				.setHeaderParam(NONCE_KEY, nonce)
				.setHeaderParam(JwsHeader.JSON_WEB_KEY, JWKUtils.getWebKey(userKey.getPublic()))
				.setClaims(new TreeMap<String, Object>(){{
					put(RESOURCE_KEY, RESOURCE_CHALLENGE);
					put(CHALLENGE_TYPE_KEY, CHALLENGE_TYPE_HTTP_01);
					put(CHALLENGE_TLS_KEY, true);
					put(CHALLENGE_KEY_AUTHORIZATION_KEY, getHTTP01ChallengeContent(userKey, token));
					put(CHALLENGE_TOKEN_KEY, token);
				}})
				.signWith(getJWSSignatureAlgorithm(), userKey.getPrivate())
				.compact();
	}

	@SuppressWarnings("serial")
	protected String getUpdateRegistrationRequest(final KeyPair userKey, final String nonce, final String agreement, final String[] contacts) {
		return Jwts.builder()
				.setHeaderParam(NONCE_KEY, nonce)
				.setHeaderParam(JwsHeader.JSON_WEB_KEY, JWKUtils.getWebKey(userKey.getPublic()))
				.setClaims(new TreeMap<String, Object>(){{
					put(RESOURCE_KEY, RESOURCE_UPDATE_REGISTRATION);
					if (contacts != null && contacts.length > 0){
						put(CONTACT_KEY, contacts);
					}
					put(AGREEMENT_KEY, agreement);
				}})
				.signWith(getJWSSignatureAlgorithm(), userKey.getPrivate())
				.compact();
	}

	private boolean handleChallenge(KeyPair userKey, String domain, AcmeChallengeListener challengeListener, String challengeType, String token, String challengeURI) {
		switch(challengeType){
		case CHALLENGE_TYPE_HTTP_01:
			return challengeListener.challengeHTTP01(domain, token, challengeURI, getHTTP01ChallengeContent(userKey, token));
		default:
			return false;
		}
	}
}
