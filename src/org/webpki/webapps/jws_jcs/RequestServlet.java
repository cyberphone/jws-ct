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

import java.security.KeyFactory;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import java.security.spec.X509EncodedKeySpec;

import java.util.Vector;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;

public class RequestServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(RequestServlet.class.getName());

    // HTML form arguments
    static final String JWS_OBJECT         = "jws";

    static final String JWS_VALIDATION_KEY = "vkey";
    

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }
            logger.info("JSON Signature Verification Entered");
            // Get the two input data items
            String signedJsonObject = CreateServlet.getParameter(request, JWS_OBJECT);
            String validationKey = CreateServlet.getParameter(request, JWS_VALIDATION_KEY);

            // Parse the JSON data
            JSONObjectReader parsedObject = JSONParser.parse(signedJsonObject);
            
            // Create a pretty-printed JSON object without canonicalization
            String prettySignature = parsedObject.serializeToString(JSONOutputFormats.PRETTY_HTML);
            Vector<String> tokens = new JSONTokenExtractor().getTokens(signedJsonObject);
            int fromIndex = 0;
            for (String token : tokens) {
                int start = prettySignature.indexOf("<span ", fromIndex);
                int stop = prettySignature.indexOf("</span>", start);
                // <span style="color:#C00000">
                prettySignature = prettySignature.substring(0, start + 28) + token + prettySignature.substring(stop);
                fromIndex = start + 1;
            }
            
            // Now begin the real work...

            // Get the embedded (detached) JWS signature
            String jwsString = parsedObject.getString(JSONCryptoHelper.SIGNATURE_JSON);
            
            // Get the actual JSON data bytes and remove the signature
            byte[] jsonData = parsedObject.removeProperty(JSONCryptoHelper.SIGNATURE_JSON)
                    .serializeToBytes(JSONOutputFormats.CANONICALIZED);
            String jsonDataB64 = Base64URL.encode(jsonData);

            // Extract the JWS header
            int endOfHeader = jwsString.indexOf('.');
            int startOfSignature = jwsString.lastIndexOf('.');
            if (endOfHeader < 10 || 
                endOfHeader != startOfSignature - 1 || 
                startOfSignature > jwsString.length() - 10) {
                throw new IOException("JWS syntax error");
            }
            
            // Parse it after the sanity test
            String jwsHeaderB64 = jwsString.substring(0, endOfHeader);
            JSONObjectReader jwsHeader = JSONParser.parse(Base64URL.decode(jwsHeaderB64));
            byte[] signedData = (jwsHeaderB64 + "." + jsonDataB64).getBytes("utf-8");
            
            // Get the other component, the signature
            byte[] signature = Base64URL.decode(jwsString.substring(startOfSignature + 1));
            
            // Start decoding the JWS header.  Algorithm is the minimum
            String algorithm = jwsHeader.getString(JSONCryptoHelper.ALG_JSON);

            // We don't bother about any other header data than possible public key
            // elements modulo JKU and X5U
            boolean macFlag = algorithm.startsWith("HS");
            PublicKey jwsSuppliedPublicKey = null;
            X509Certificate[] certificatePath = null;
            if (jwsHeader.hasProperty(JSONCryptoHelper.JWK_JSON)) {
                jwsSuppliedPublicKey = jwsHeader.getPublicKey();
            }
            StringBuilder certificateData = null;
            if (jwsHeader.hasProperty(JSONCryptoHelper.X5C_JSON)) {
                if (jwsSuppliedPublicKey != null) {
                    throw new IOException("Both X5C and JWK?");
                }
                certificatePath = jwsHeader.getCertificatePath();
                jwsSuppliedPublicKey = certificatePath[0].getPublicKey();
                for (X509Certificate certificate : certificatePath) {
                    if (certificateData == null) {
                        certificateData = new StringBuilder();
                    } else {
                        certificateData.append("<br>&nbsp;<br>");
                    }
                    certificateData.append(
                        HTML.encode(new CertificateInfo(certificate).toString())
                            .replace("\n", "<br>").replace("  ", ""));
                }
            }
            
            // Recreate the validation key and validate the signature
            boolean jwkValidationKey = validationKey.startsWith("{");
            if (macFlag) {
                if (jwsSuppliedPublicKey != null) {
                    throw new IOException("Public key header elements in a HMAC signature?");
                }
                if (!ArrayUtil.compare(MACAlgorithms.getAlgorithmFromId(algorithm, AlgorithmPreferences.JOSE)
                        .digest(DebugFormatter.getByteArrayFromHex(validationKey), signedData), signature)) {
                    throw new IOException("HMAC signature validation error");
                }
            } else {
                PublicKey externalPublicKey =  jwkValidationKey ? 
                    JSONParser.parse(validationKey).getCorePublicKey(AlgorithmPreferences.JOSE)
                                                                :
                    KeyFactory.getInstance(algorithm.startsWith("ES") ? "EC" : "RSA")
                        .generatePublic(new X509EncodedKeySpec(CreateServlet.getPemBlob(validationKey,
                                                                                        "PUBLIC KEY")));
                AsymSignatureAlgorithms signatureAlgorithm = 
                        AsymSignatureAlgorithms.getAlgorithmFromId(algorithm,
                                                                   AlgorithmPreferences.JOSE);
                if (externalPublicKey instanceof ECPublicKey && 
                    KeyAlgorithms.getKeyAlgorithm(externalPublicKey)
                        .getRecommendedSignatureAlgorithm() != signatureAlgorithm) {
                    throw new IOException("EC key and algorithm does not match the JWS spec");
                }
                if (!new SignatureWrapper(signatureAlgorithm, externalPublicKey)
                            .update(signedData)
                            .verify(signature)) {
                    throw new IOException("Asymmetric key signature validation error");
                }
                if (jwsSuppliedPublicKey != null && !jwsSuppliedPublicKey.equals(externalPublicKey)) {
                    throw new IOException("Supplied public key differs from the one derived from the JWS header");
                }
            }
            StringBuilder html = new StringBuilder(
                    "<div class=\"header\"> Signature Successfully Validated</div>")
                .append(HTML.fancyBox("signed", prettySignature, "JSON object signed by an embedded JWS element"))           
                .append(HTML.fancyBox("header", 
                                      jwsHeader.serializeToString(JSONOutputFormats.PRETTY_HTML),
                                      "Decoded JWS header"))
                .append(HTML.fancyBox("vkey",
                                      jwkValidationKey ? 
                                          JSONParser.parse(validationKey)
                                              .serializeToString(JSONOutputFormats.PRETTY_HTML)
                                                       :
                                      HTML.encode(validationKey).replace("\n", "<br>"),
                                      "Signature validation " + (macFlag ? 
                                             "secret key in hexadecimal" :
                                             "public key in " + 
                                             (jwkValidationKey ? "JWK" : "PEM") +
                                             " format")))
                .append(HTML.fancyBox("canonical", 
                                      HTML.encode(new String(jsonData, "utf-8")),
                                      "Canonical version of the JSON data (with possible line breaks " +
                                      "for display purposes only)"));
            if (certificateData != null) {
                html.append(HTML.fancyBox("certpath", 
                                          certificateData.toString(),
                                          "Core certificate data"));
            }
            html.append(HTML.fancyBox("original", 
                                      jwsHeaderB64 + '.' + jsonDataB64 + jwsString.substring(startOfSignature),
                                      "Finally (as a reference only...), the same object expressed as a standard JWS"));

            // Finally, print it out
            HTML.standardPage(response, null, html.append("<div style=\"padding:10pt\"></div>"));
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
