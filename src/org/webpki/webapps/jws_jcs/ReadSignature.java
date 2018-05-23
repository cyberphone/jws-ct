/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.webapps.jws_jcs;

import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;

import java.util.regex.Pattern;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONTypes;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;

/**
 * Simple signature verify program
 */
public class ReadSignature {
    
    static final Pattern DETACHED_JWS_PATTERN  = Pattern.compile("^[0-9a-zA-Z\\-_]+\\.\\.[0-9a-zA-Z\\-_]+$");

    private StringBuilder result = new StringBuilder();
    
    JSONObjectReader jwsHeader;

    byte[] canonicalizedData;

    private String cryptoBinary(BigInteger value, KeyAlgorithms key_alg)
            throws IOException {
        byte[] crypto_binary = value.toByteArray();
        boolean modify = true;
        if (key_alg.isECKey()) {
            if (crypto_binary.length > (key_alg.getPublicKeySizeInBits() + 7) / 8) {
                if (crypto_binary[0] != 0) {
                    throw new IOException("Unexpected EC value");
                }
            } else {
                modify = false;
            }
        }
        if (modify && crypto_binary[0] == 0x00) {
            byte[] wo_zero = new byte[crypto_binary.length - 1];
            System.arraycopy(crypto_binary, 1, wo_zero, 0, wo_zero.length);
            crypto_binary = wo_zero;
        }
        String pre = "";
        StringBuilder result = new StringBuilder();
        int i = 0;
        for (char c : DebugFormatter.getHexString(crypto_binary).toCharArray()) {
            if (++i % 80 == 0) {
                result.append('\n');
                pre = "\n";
            }
            result.append(c);
        }
        return pre + result.toString();
    }
    
    void processOneSignature(JSONObjectReader signedObject) throws IOException, GeneralSecurityException {
        String jwsSignature = signedObject.getString(JSONCryptoHelper.SIGNATURE_JSON);
        if (!DETACHED_JWS_PATTERN.matcher(jwsSignature).matches()) {
            throw new IOException("Malformed JWS string");
        }
        signedObject = signedObject.clone();  // Non-destructive validation
        signedObject.removeProperty(JSONCryptoHelper.SIGNATURE_JSON);
        canonicalizedData = signedObject.serializeToBytes(JSONOutputFormats.CANONICALIZED);
        int dot = jwsSignature.indexOf('.');
        byte[] signedData = (jwsSignature.substring(0, dot + 1) + 
                             Base64URL.encode(canonicalizedData)).getBytes("utf-8");
        jwsHeader = JSONParser.parse(Base64URL.decode(jwsSignature.substring(0, dot)));
        byte[] signatureValue = Base64URL.decode(jwsSignature.substring(dot + 2));
        String algorithm = jwsHeader.getString(JSONCryptoHelper.ALG_JSON);
        StringBuilder debug = new StringBuilder();
        if (algorithm.startsWith("HS")) {
            if (!ArrayUtil.compare(signatureValue,
                MACAlgorithms.getAlgorithmFromId(algorithm, 
                                                 AlgorithmPreferences.JOSE)
                    .digest(GenerateSignature.SYMMETRIC_KEY, signedData))) {
                throw new IOException("HMAC signature did not validate");
            }
            debug.append("HMAC signature validated for Key ID: ")
                 .append(jwsHeader.getString(JSONCryptoHelper.KID_JSON))
                 .append("\nValue=")
                 .append(DebugFormatter.getHexString(GenerateSignature.SYMMETRIC_KEY));
            
        } else {
            AsymSignatureAlgorithms asymAlg = 
                AsymSignatureAlgorithms.getAlgorithmFromId(algorithm, AlgorithmPreferences.JOSE);
            PublicKey publicKey;
            if (jwsHeader.hasProperty(JSONCryptoHelper.X5C_JSON)) {
                X509Certificate[] cert_path = jwsHeader.getCertificatePath();
                debug.append("X509 signature validated for:\n")
                     .append(new CertificateInfo(cert_path[0]).toString());
                publicKey = cert_path[0].getPublicKey();
            } else {
                publicKey = jwsHeader.getPublicKey();
                KeyAlgorithms key_alg = KeyAlgorithms.getKeyAlgorithm(publicKey);
                debug.append("Asymmetric key signature validated for:\n")
                     .append(key_alg.isECKey() ? "EC" : "RSA")
                     .append(" Public Key (")
                     .append(key_alg.getPublicKeySizeInBits())
                     .append(" bits)");
                if (key_alg.isECKey()) {
                    debug.append(", Curve=").append(key_alg.getJceName());
                    ECPoint ec_point = ((ECPublicKey) publicKey).getW();
                    debug.append("\nX: ")
                         .append(cryptoBinary(ec_point.getAffineX(), key_alg))
                         .append("\nY: ")
                         .append(cryptoBinary(ec_point.getAffineY(), key_alg));
                } else {
                    debug.append("\nModulus: ")
                         .append(cryptoBinary(((RSAPublicKey) publicKey).getModulus(), key_alg))
                         .append("\nExponent: ")
                         .append(cryptoBinary(((RSAPublicKey) publicKey).getPublicExponent(), key_alg));
                }
            }
            if (!new SignatureWrapper(asymAlg, publicKey)
                .update(signedData)
                .verify(signatureValue)) {
                throw new IOException("Signature validation failed for:\n" + publicKey.toString());
            }
        }
        debugOutput(debug.toString());
    }

    void recurseObject(JSONObjectReader rd) throws IOException, GeneralSecurityException {
        for (String property : rd.getProperties()) {
            if (property.equals(JSONCryptoHelper.SIGNATURE_JSON)) {
                processOneSignature(rd);
            } else {
                switch (rd.getPropertyType(property)) {
                case OBJECT:
                    recurseObject(rd.getObject(property));
                    break;
    
                case ARRAY:
                    recurseArray(rd.getArray(property));
                    break;
    
                default:
                    rd.scanAway(property);
                }
            }
        }
    }

    void recurseArray(JSONArrayReader array) throws IOException, GeneralSecurityException {
        while (array.hasMore()) {
            if (array.getElementType() == JSONTypes.OBJECT) {
                recurseObject(array.getObject());
            } else if (array.getElementType() == JSONTypes.ARRAY) {
                recurseArray(array.getArray());
            } else {
                array.scanAway();
            }
        }
    }

    void debugOutput(String string) {
        result.append('\n').append(string).append('\n');
    }

    String getResult() throws IOException {
        if (result.length() == 0) {
            throw new IOException("No Signatures found!");
        }
        return result.toString();
    }
}
