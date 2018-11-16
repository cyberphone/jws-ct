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

import java.net.URLEncoder;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.RSAPrivateCrtKey;

import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.util.Vector;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;

public class CreateServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(CreateServlet.class.getName());

    private static final long serialVersionUID = 1L;

    // HTML form arguments
    static final String PRM_JSON_DATA    = "json";
    
    static final String PRM_JWS_EXTRA    = "xtra";

    static final String PRM_SECRET_KEY   = "sec";

    static final String PRM_PRIVATE_KEY  = "priv";

    static final String PRM_CERT_PATH    = "cert";

    static final String PRM_ALGORITHM    = "alg";
    static final String FLG_CERT_PATH    = "cerflg";
    static final String FLG_JAVASCRIPT   = "jsflg";
    static final String FLG_JWK_INLINE   = "jwkflg";
    
    static final String DEFAULT_ALG      = "ES256";
    
    class SelectAlg {

        String preSelected;
        StringBuilder html = new StringBuilder("<select name=\"" +
                PRM_ALGORITHM + "\" id=\"" +
                PRM_ALGORITHM + "\" onchange=\"algChange(this.value)\">");
        
        SelectAlg(String preSelected) {
            this.preSelected = preSelected;
        }

        SelectAlg add(SignatureAlgorithms algorithm) throws IOException {
            String algId = algorithm.getAlgorithmId(AlgorithmPreferences.JOSE);
            html.append("<option value=\"")
                .append(algId)
                .append("\"")
                .append(algId.equals(preSelected) ? " selected>" : ">")
                .append(algId)
                .append("</option>");
            return this;
        }

        @Override
        public String toString() {
            return html.append("</select>").toString();
        }
    }
    
    StringBuilder checkBox(String idName, String text, boolean checked, String onchange) {
        StringBuilder html = new StringBuilder("<div style=\"display:flex;align-items:center\"><input type=\"checkbox\" id=\"")
            .append(idName)
            .append("\" name=\"")
            .append(idName)
            .append("\"");
        if (checked) {
            html.append(" checked");
        }
        if (onchange != null) {
            html.append(" onchange=\"")
                .append(onchange)
                .append("\"");
        }
        html.append("><div style=\"display:inline-block\">")
            .append(text)
            .append("</div></div>");
        return html;
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String selected = "ES256";
        StringBuilder js = new StringBuilder("\"use strict\";\n")
            .append(JWSService.keyDeclarations);
        StringBuilder html = new StringBuilder(
                "<form name=\"shoot\" method=\"POST\" action=\"create\">" +
                "<div class=\"header\">JSON Signature Creation</div>" +
                HTML.fancyText(
                        true,
                        PRM_JSON_DATA,
                        10,
                        "",
                        "Paste an unsigned JSON object in the text box or try with the default") +
                 "<div style=\"display:flex;justify-content:center;margin-top:20pt\">" +
                 "<div class=\"sigparmbox\">" +
                 "<div style=\"display:flex;justify-content:center\">" +
                   "<div class=\"sigparmhead\">Signature Parameters</div>" +
                 "</div><div style=\"display:flex;align-items:center\">")
            .append(new SelectAlg(selected)
                 .add(MACAlgorithms.HMAC_SHA256)
                 .add(MACAlgorithms.HMAC_SHA384)
                 .add(MACAlgorithms.HMAC_SHA512)
                 .add(AsymSignatureAlgorithms.ECDSA_SHA256)
                 .add(AsymSignatureAlgorithms.ECDSA_SHA384)
                 .add(AsymSignatureAlgorithms.ECDSA_SHA512)
                 .add(AsymSignatureAlgorithms.RSA_SHA256)
                 .add(AsymSignatureAlgorithms.RSA_SHA384)
                 .add(AsymSignatureAlgorithms.RSA_SHA512)
                 .toString())
            .append(
                "<div style=\"display:inline-block;padding:0 10pt 0 5pt\">Algorithm</div>" +
                "<div class=\"defbtn\" onclick=\"restoreDefaults()\">Restore&nbsp;defaults</div></div>")
            .append(checkBox(FLG_JWK_INLINE, "Automagically insert public key (JWK)", false, "jwkFlagChange(this.checked)"))
            .append(checkBox(FLG_CERT_PATH, "Include provided certificate path (X5C)", false, "certFlagChange(this.checked)"))
            .append(checkBox(FLG_JAVASCRIPT, "Serialize as JavaScript (but do not verify)", false, null))
            .append(
                "</div>" +
                "</div>" +
                "<div style=\"display:flex;justify-content:center\">" +
                "<div class=\"stdbtn\" onclick=\"document.forms.shoot.submit()\">" +
                "Create JSON Signature" +
                "</div>" +
                "</div>")
            .append(
                HTML.fancyText(true,
                          PRM_JWS_EXTRA,
                          4,
                          "",
                          "Additional JWS header parameters (here expressed as properties of a JSON object)"))
            .append(
                HTML.fancyText(false,
                          PRM_SECRET_KEY,
                          1,
                          "",
                          "Secret key in hexadecimal format"))
            .append(
                HTML.fancyText(false,
                          PRM_PRIVATE_KEY,
                          4,
                          "",
                          "Private key in PEM/PKCS #8 or &quot;plain&quot; JWK format"))
            .append(
                HTML.fancyText(false,
                          PRM_CERT_PATH,
                          4,
                          "",
                          "Certificate path in PEM format"))
            .append(
                "</form>" +
                "<div>&nbsp;</div>");
        js.append(
            "function fill(id, alg, keyHolder, unconditionally) {\n" +
            "  let element = document.getElementById(id).children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = keyHolder[alg];\n" +
            "}\n" +
            "function disableAndClearCheckBox(id) {\n" +
            "  let checkBox = document.getElementById(id);\n" +
            "  checkBox.checked = false;\n" +
            "  checkBox.disabled = true;\n" +
            "}\n" +
            "function enableCheckBox(id) {\n" +
            "  document.getElementById(id).disabled = false;\n" +
            "}\n" +
            "function setParameters(alg, unconditionally) {\n" +
            "  if (alg.startsWith('HS')) {\n" +
            "    showCert(false);\n" +
            "    showPriv(false);\n" +
            "    disableAndClearCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    disableAndClearCheckBox('" + FLG_JWK_INLINE + "');\n" +
            "    fill('" + PRM_SECRET_KEY + "', alg, " + 
                 JWSService.KeyDeclaration.SECRET_KEYS + ", unconditionally);\n" +
            "    showSec(true)\n" +
            "  } else {\n" +
            "    showSec(false)\n" +
            "    enableCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    enableCheckBox('" + FLG_JWK_INLINE + "');\n" +
            "    fill('" + PRM_PRIVATE_KEY + "', alg, " + 
            JWSService.KeyDeclaration.PRIVATE_KEYS + ", unconditionally);\n" +
            "    showPriv(true);\n" +
            "    fill('" + PRM_CERT_PATH + "', alg, " + 
            JWSService.KeyDeclaration.CERTIFICATES + ", unconditionally);\n" +
            "    showCert(document.getElementById('" + FLG_CERT_PATH + "').checked);\n" +
            "  }\n" +
            "  let element = document.getElementById('" + PRM_JSON_DATA + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '{\\n" +
            "  \"statement\": \"Hello signed world!\",\\n" +
            "  \"otherProperties\": [2e+3, true]\\n}';\n" +
            "  element = document.getElementById('" + PRM_JWS_EXTRA + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '{\\n}';\n" +
            "}\n" +
            "function jwkFlagChange(flag) {\n" +
            "  if (flag) {\n" +
            "    document.getElementById('" + FLG_CERT_PATH + "').checked = false;\n" +
            "    showCert(false);\n" +
            "  }\n" +
            "}\n" +
            "function certFlagChange(flag) {\n" +
            "  showCert(flag);\n" +
            "  if (flag) {\n" +
            "    document.getElementById('" + FLG_JWK_INLINE + "').checked = false;\n" +
            "  }\n" +
            "}\n" +
            "function restoreDefaults() {\n" +
            "  let s = document.getElementById('" + PRM_ALGORITHM + "');\n" +
            "  for (let i = 0; i < s.options.length; i++) {\n" +
            "    if (s.options[i].text == '" + DEFAULT_ALG + "') {\n" +
            "      s.options[i].selected = true;\n" +
            "      break;\n" +
            "    }\n" +
            "  }\n" +
            "  setParameters('" + DEFAULT_ALG + "', true);\n" +
            "  document.getElementById('" + FLG_CERT_PATH + "').checked = false;\n" +
            "  document.getElementById('" + FLG_JAVASCRIPT + "').checked = false;\n" +
            "  document.getElementById('" + FLG_JWK_INLINE + "').checked = false;\n" +
            "}\n" +
            "function algChange(alg) {\n" +
            "console.log('alg=' + alg);\n" +
            "  setParameters(alg, true);\n" +
            "}\n" +
            "function showCert(show) {\n" +
            "  document.getElementById('" + PRM_CERT_PATH + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function showPriv(show) {\n" +
            "  document.getElementById('" + PRM_PRIVATE_KEY + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function showSec(show) {\n" +
            "  document.getElementById('" + PRM_SECRET_KEY + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "window.addEventListener('load', function(event) {\n" +
            "  setParameters(document.getElementById('" + PRM_ALGORITHM + "').value, false);\n" +
            "});\n");
        HTML.standardPage(response, 
                         js.toString(),
                         html);
    }
    
    static String getParameter(HttpServletRequest request, String parameter) throws IOException {
        String string = request.getParameter(parameter);
        if (string == null) {
            throw new IOException("Missing data for: "+ parameter);
        }
        return string.trim();
    }

    static String getTextArea(HttpServletRequest request, String name)
            throws IOException {
        String string = getParameter(request, name);
        StringBuilder s = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c != '\r') {
                s.append(c);
            }
        }
        return s.toString();
    }


    static Vector<byte[]> getPemBlobs(String pemData,
                                      String type) throws IOException {
        Vector<byte[]> blobs = new Vector<byte[]>();
        do {
            if (!pemData.startsWith("-----BEGIN " + type + "-----")) {
                if (pemData.startsWith("-----BEGIN RSA") || pemData.startsWith("-----BEGIN EC")) {
                    throw new IOException("This application only supports PEM formatted private keys compliant with PKCS #8 (consult OpenSSL)");
                }
                throw new IOException("PEM BEGIN error in: " + type);
            }
            int i = pemData.indexOf("-----END " + type + "-----");
            if (i < 0) {
                throw new IOException("PEM END error in: " + type);
            }
            try {
                byte[] blob = new Base64()
                    .getBinaryFromBase64String(pemData.substring(16 + type.length(), i));
                blobs.add(blob);
            } catch (IOException e) {
                throw new IOException("PEM data error in: " + type + 
                                      " reason: " + e.getMessage());
            }
            pemData = pemData.substring(i + type.length() + 14).trim();
        } while (pemData.length() != 0);
        return blobs;
    }
    
    static byte[] getPemBlob(String pemData,
                             String type) throws IOException {
        Vector<byte[]> blobs = getPemBlobs(pemData, type);
        if (blobs.size() != 1) throw new IOException("Only one element is allowed for: " + type);
        return blobs.firstElement();
    }
    

    PublicKey ecPublicKeyFromPKCS8(byte[] privateKeyBlob) throws IOException, GeneralSecurityException {
        ASN1Sequence seq = ParseUtil.sequence(DerDecoder.decode(privateKeyBlob), 3);
        String oid = ParseUtil.oid(ParseUtil.sequence(seq.get(1), 2).get(1)).oid();
        seq = ParseUtil.sequence(DerDecoder.decode(ParseUtil.octet(seq.get(2))));
        byte[] publicKey = ParseUtil.bitstring(ParseUtil.singleContext(seq.get(seq.size() -1), 1));
        int length = (publicKey.length - 1) / 2;
        byte[] parm = new byte[length];
        System.arraycopy(publicKey, 1, parm, 0, length);
        BigInteger x = new BigInteger(1, parm);
        System.arraycopy(publicKey, 1 + length, parm, 0, length);
        BigInteger y = new BigInteger(1, parm);
        for (KeyAlgorithms ka : KeyAlgorithms.values()) {
            if (oid.equals(ka.getECDomainOID())) {
                if (oid.equals(ka.getECDomainOID())) {
                    ECPoint w = new ECPoint(x, y);
                    return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, ka.getECParameterSpec()));
                }
            }
        }
        throw new IOException("Failed creating EC public key from private key");
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
         try {
            request.setCharacterEncoding("utf-8");
            String jsonData = getTextArea(request, PRM_JSON_DATA);
            JSONObjectReader reader = JSONParser.parse(jsonData);
            if (reader.getJSONArrayReader() != null) {
                throw new IOException("The demo does not support signed arrays");
            }
            JSONObjectReader additionalHeaderData = JSONParser.parse(getParameter(request, PRM_JWS_EXTRA));
            boolean jsFlag = request.getParameter(FLG_JAVASCRIPT) != null;
            boolean keyInlining = request.getParameter(FLG_JWK_INLINE) != null;
            boolean certOption = request.getParameter(FLG_CERT_PATH) != null;
            String algorithm = getParameter(request, PRM_ALGORITHM);
            JSONObjectWriter jwsHeader = new JSONObjectWriter();

            // Create the minimal JWS header
            jwsHeader.setString(JSONCryptoHelper.ALG_JSON, algorithm);

            // Add any optional (by the user specified) arguments
            for (String key : additionalHeaderData.getProperties()) {
                jwsHeader.copyElement(key, key, additionalHeaderData);
            }
            
            // Get the signature key
            PrivateKey privateKey = null;
            byte[] secretKey = null;
            String validationKey;
            
            // Symmetric or asymmetric?
            if (algorithm.startsWith("HS")) {
                validationKey = getParameter(request, PRM_SECRET_KEY);
                secretKey = DebugFormatter.getByteArrayFromHex(validationKey);
            } else {
                // To simplify UI we require PKCS #8 with the public key embedded
                // but we also support JWK which also has the public key
                PublicKey publicKey;
                String privateKeyString = getParameter(request, PRM_PRIVATE_KEY);
                if (privateKeyString.startsWith("{")) {
                    KeyPair keyPair = JSONParser.parse(privateKeyString).getKeyPair();
                    publicKey = keyPair.getPublic();
                    privateKey = keyPair.getPrivate();
                } else {
                    byte[] privateKeyBlob = getPemBlob(privateKeyString, "PRIVATE KEY");
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBlob);
                    if (algorithm.startsWith("ES")) {
                        privateKey = KeyFactory.getInstance("EC").generatePrivate(keySpec);
                        publicKey = ecPublicKeyFromPKCS8(privateKeyBlob);
                    } else {
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        privateKey = keyFactory.generatePrivate(keySpec);
                        RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privateKey;
                        RSAPublicKeySpec publicKeySpec = 
                                new RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());
                        publicKey = keyFactory.generatePublic(publicKeySpec);
                    }
                }
                privateKeyString = null;  // Nullify it after use
                validationKey = "-----BEGIN PUBLIC KEY-----\n" +
                                new Base64().getBase64StringFromBinary(publicKey.getEncoded()) +
                                "\n-----END PUBLIC KEY-----";

                // Add other JWS header data that the demo program fixes 
                if (certOption) {
                    X509Certificate[] certificatePath =
                        CertificateUtil
                            .makeCertificatePath(getPemBlobs(getParameter(request, PRM_CERT_PATH),
                                                             "CERTIFICATE"));
                    jwsHeader.setCertificatePath(certificatePath);
                } else if (keyInlining) {
                    jwsHeader.setPublicKey(publicKey);
                }
            }

            // Creating JWS data to be signed
            String jwsHeaderB64 = Base64URL.encode(jwsHeader.serializeToBytes(JSONOutputFormats.NORMALIZED));
            String payloadB64 = Base64URL.encode(reader.serializeToBytes(JSONOutputFormats.CANONICALIZED));
            byte[] dataToBeSigned = (jwsHeaderB64 + "." + payloadB64).getBytes("utf-8");

            // Sign it using the provided algorithm and key
            String signatureB64 = Base64URL.encode(secretKey == null ?
                new SignatureWrapper(
                    AsymSignatureAlgorithms.getAlgorithmFromId(algorithm, AlgorithmPreferences.JOSE),
                    privateKey)
                        .update(dataToBeSigned).sign()
                                                                     :
                MACAlgorithms.getAlgorithmFromId(algorithm, AlgorithmPreferences.JOSE)
                        .digest(secretKey, dataToBeSigned));
            privateKey = null;  // Nullify it after use

            // Create the completed object
            String signedJsonObject = new JSONObjectWriter(reader)
                .setString(JSONCryptoHelper.SIGNATURE_JSON,
                           jwsHeaderB64 + ".." + signatureB64)
                .serializeToString(JSONOutputFormats.NORMALIZED);

            // How things should appear in a "regular" JWS
            if (JWSService.logging) {
                logger.info(jwsHeaderB64 + '.' + payloadB64 + '.' + signatureB64);
            }

            // The following is just for the demo.  That is, we want to preserve
            // the original ("untouched") JSON data for educational purposes.
            int i = signedJsonObject.lastIndexOf("\"sig");
            if (signedJsonObject.charAt(i - 1) == ',') {
                i--;
            }
            int j = jsonData.lastIndexOf("}");
            signedJsonObject = jsonData.substring(0, j) + 
                    signedJsonObject.substring(i, signedJsonObject.length() - 1) +
                    jsonData.substring(j);

            // We terminate by verifying the signature as well
            request.getRequestDispatcher((jsFlag ? "jssignature?" : "request?") +
                RequestServlet.JWS_OBJECT + 
                "=" +
                URLEncoder.encode(signedJsonObject, "utf-8") +
                "&" +
                RequestServlet.JWS_VALIDATION_KEY + 
                "=" +
                URLEncoder.encode(validationKey, "utf-8"))
                    .forward(request, response);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
