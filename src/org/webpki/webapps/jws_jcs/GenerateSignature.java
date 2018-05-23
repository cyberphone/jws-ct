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

import java.security.KeyStore;
import java.security.PublicKey;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;
import org.webpki.crypto.SymKeyVerifierInterface;

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

/**
 * Simple signature test generator
 */
public class GenerateSignature {

    static enum ACTION {
         SYM  ("HS256"),
         EC   ("ES256"), 
         RSA  ("RS256"), 
         X509 ("RS256");
         
         String algorithm;
         
         ACTION (String algorithm) {
             this.algorithm = algorithm;
         }
    }

    static final String KEY_NAME = "mykey";

    static final byte[] SYMMETRIC_KEY = 
          { (byte) 0xF4, (byte) 0xC7, (byte) 0x4F, (byte) 0x33,
            (byte) 0x98, (byte) 0xC4, (byte) 0x9C, (byte) 0xF4,
            (byte) 0x6D, (byte) 0x93, (byte) 0xEC, (byte) 0x98,
            (byte) 0x18, (byte) 0x83, (byte) 0x26, (byte) 0x61,
            (byte) 0xA4, (byte) 0x0B, (byte) 0xAE, (byte) 0x4D,
            (byte) 0x20, (byte) 0x4D, (byte) 0x75, (byte) 0x50,
            (byte) 0x36, (byte) 0x14, (byte) 0x10, (byte) 0x20,
            (byte) 0x74, (byte) 0x34, (byte) 0x69, (byte) 0x09 };

    ACTION action;

    GenerateSignature(ACTION action) {
        this.action = action;
    }

    static class AsymSignatureHelper extends KeyStoreSigner implements
            AsymKeySignerInterface {
        AsymSignatureHelper(KeyStore signer_keystore) throws IOException {
            super(signer_keystore, null);
            setKey(KEY_NAME, JWSService.key_password);
        }

        @Override
        public PublicKey getPublicKey() throws IOException {
            return getCertificatePath()[0].getPublicKey();
        }
    }

    static class SymmetricOperations implements SymKeySignerInterface, SymKeyVerifierInterface {
        @Override
        public byte[] signData(byte[] data, MACAlgorithms algorithm) throws IOException {
            return algorithm.digest(SYMMETRIC_KEY, data);
        }

        @Override
        public MACAlgorithms getMacAlgorithm() throws IOException {
            return MACAlgorithms.HMAC_SHA256;
        }

        @Override
        public boolean verifyData(byte[] data, byte[] digest, MACAlgorithms algorithm, String keyId) throws IOException {
            if (KEY_NAME.equals(keyId)) {
                return ArrayUtil.compare(digest,
                        algorithm.digest(SYMMETRIC_KEY, data));
            }
            throw new IOException("Unknown key id: " + keyId);
        }
    }

    byte[] sign(JSONObjectWriter wr) throws IOException {
        AsymSignatureHelper ash = null;
        JSONObjectWriter jwsHeader = new JSONObjectWriter();
        jwsHeader.setString(JSONCryptoHelper.ALG_JSON, action.algorithm);
        if (action == ACTION.SYM) {
            jwsHeader.setString(JSONCryptoHelper.KID_JSON, KEY_NAME);
        } else if (action == ACTION.X509) {
            jwsHeader.setCertificatePath(((ash = new AsymSignatureHelper(
                    JWSService.clientkey_rsa)).getCertificatePath()));
        } else {
            jwsHeader.setPublicKey((ash = new AsymSignatureHelper(
                    action == ACTION.RSA ? JWSService.clientkey_rsa
                            : JWSService.clientkey_ec)).getPublicKey());
        }
        String jwsHeaderB64 = Base64URL.encode(jwsHeader.serializeToBytes(JSONOutputFormats.NORMALIZED));
        String payloadB64 = Base64URL.encode(wr.serializeToBytes(JSONOutputFormats.CANONICALIZED));
        String toBeSigned = jwsHeaderB64 + "." + payloadB64;
        byte[] toBeSignedBin = toBeSigned.getBytes("utf-8");
        byte[] signatureValue;
        if (action == ACTION.SYM) {
            signatureValue = 
                MACAlgorithms.getAlgorithmFromId(action.algorithm, AlgorithmPreferences.JOSE)
                    .digest(SYMMETRIC_KEY, toBeSignedBin);
        } else {
            ash.setECDSASignatureEncoding(false);
            signatureValue = ash.signData(toBeSignedBin, 
                AsymSignatureAlgorithms
                    .getAlgorithmFromId(action.algorithm, AlgorithmPreferences.JOSE));
        }
        wr.setString(JSONCryptoHelper.SIGNATURE_JSON,
                     jwsHeaderB64 + ".." + Base64URL.encode(signatureValue));
        System.out.println(jwsHeaderB64 + "." + payloadB64 + "." + Base64URL.encode(signatureValue));
        return wr.serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
    }
}
