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

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.TreeMap;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.impl.TextCodec;

public class JWKUtils {
	
	// Copied from Apache Commons Codec 1.10
	private static byte[] toIntegerBytes(final BigInteger bigInt) {
        int bitlen = bigInt.bitLength();
        // round bitlen
        bitlen = ((bitlen + 7) >> 3) << 3;
        final byte[] bigBytes = bigInt.toByteArray();

        if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
            return bigBytes;
        }
        // set up params for copying everything but sign bit
        int startSrc = 0;
        int len = bigBytes.length;

        // if bigInt is exactly byte-aligned, just skip signbit in copy
        if ((bigInt.bitLength() % 8) == 0) {
            startSrc = 1;
            len--;
        }
        final int startDst = bitlen / 8 - len; // to pad w/ nulls as per spec
        final byte[] resizedBytes = new byte[bitlen / 8];
        System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
        return resizedBytes;
    }

	public static TreeMap<String, Object> getWebKey(PublicKey publicKey) {
		TreeMap<String, Object> key = new TreeMap<>();
		if (publicKey instanceof RSAPublicKey){
			key.put("kty","RSA");
			key.put("e", TextCodec.BASE64URL.encode(toIntegerBytes(((RSAPublicKey) publicKey).getPublicExponent())));
			key.put("n", TextCodec.BASE64URL.encode(toIntegerBytes(((RSAPublicKey) publicKey).getModulus())));
			return key;
		}else{
			throw new IllegalArgumentException();
		}
	}
	
	public static String getWebKeyThumbprintSHA256(PublicKey publicKey){
		try {
			TreeMap<String, Object> webKey = JWKUtils.getWebKey(publicKey);
			String webKeyJson = new ObjectMapper().writeValueAsString(webKey);
			return TextCodec.BASE64URL.encode(SHA256(webKeyJson));
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}

	private static byte[] SHA256(String text){
		try {
			MessageDigest md;
			md = MessageDigest.getInstance("SHA-256");
			md.update(text.getBytes("UTF-8"), 0, text.length());
			return md.digest();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

}
