/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.jws_ct;

import java.io.IOException;

import java.security.KeyPair;
import java.security.PublicKey;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.jose.JoseKeyWords;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.tools.KeyStore2JWKConverter;
import org.webpki.tools.KeyStore2PEMConverter;

import org.webpki.util.PEMDecoder;

public class KeyConvertServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(KeyConvertServlet.class.getName());

    // HTML form arguments
    static final String KEY_DATA        = "key";

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }

            // Get the input key
            KeyPair keyPair = null;
            PublicKey publicKey = null;
            String keyData = CreateServlet.getParameter(request, KEY_DATA);
            boolean jwkFound = false;
            if (keyData.startsWith("{")) {
                jwkFound = true;
                JSONObjectReader parsedJson = JSONParser.parse(keyData);
                if (parsedJson.hasProperty(JoseKeyWords.KID_JSON)) {
                    parsedJson.removeProperty(JoseKeyWords.KID_JSON);
                }
                try {
                    keyPair = parsedJson.getKeyPair();
                } catch (Exception e) {
                    publicKey = parsedJson.getCorePublicKey(AlgorithmPreferences.JOSE);
                }
            } else {
                byte[] keyDataBin = keyData.getBytes("utf-8");
                try {
                    keyPair = PEMDecoder.getKeyPair(keyDataBin);
                } catch (Exception e) {
                    if (keyData.contains("PRIVATE KEY")) {
                        throw e;
                    }
                    publicKey = PEMDecoder.getPublicKey(keyDataBin);
                }
            }
            KeyStore2PEMConverter pemConverter = new KeyStore2PEMConverter();
            if (keyPair == null) {
                pemConverter.writePublicKey(publicKey);
            } else {
                pemConverter.writePrivateKey(keyPair.getPrivate(), keyPair.getPublic());
            }
            String pem = new String(pemConverter.getData(), "utf-8");
            KeyStore2JWKConverter jwkConverter = new KeyStore2JWKConverter();
            String jwk = keyPair == null ?
                        jwkConverter.writePublicKey(publicKey)
                                         :
                        jwkConverter.writePrivateKey(keyPair.getPrivate(), keyPair.getPublic());
            if (jwkFound) {
                jwk = keyData;
            } else {
                pem = keyData;
            }
            StringBuilder html = new StringBuilder(
                    "<div class='header'>Key Successfully Converted</div>")
                .append(HTML.fancyBox("jwk", 
                                      JSONParser.parse(jwk).serializeToString(
                                              JSONOutputFormats.PRETTY_HTML), 
                                      "\"Pretty-printed\" JWK"))           
                 .append(HTML.fancyCode("pem", 
                                        pem,
                                        "Key in PEM format"));

            // Finally, print it out
            HTML.standardPage(response, null, html.append("<div style='padding:10pt'></div>"));
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
                "<form name='shoot' method='POST' action='keyconv'>" +
                "<div class='header'>Convert JWK &lt;-&gt; PEM</div>")
            .append(HTML.fancyText(true,
                                   KEY_DATA,
                                   10, 
                                   JwsCtService.sampleKeyConversionKey,
                     "Paste public or private key in JWK or PEM format or try with the default"))
            .append(
                "<div style='margin-top:1em'>Limitations:" +
                  "<ul>" +
                    "<li>JWK keys may only contain the core key data plus an <i>optional</i> \"kid\"</li>" +
                    "<li>PEM keys <b>must not</b> have external algorithm identifiers like \"RSA\"</li>" +
                    "<li>PEM private keys <b>must not</b> be encrypted" +
                    "<li>PEM private keys <b>must</b> be supplied as PKCS #8 with a <i>defined public key attribute</i>" +
                  "</ul>" +
                "</div>" +
                "<div style='display:flex;justify-content:center'>" +
                "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
                "Convert Key" +
                "</div>" +
                "</div>" +
                "</form>" +
                "<div>&nbsp;</div>"));
    }
}
