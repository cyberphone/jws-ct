/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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

import java.net.URLEncoder;

import java.security.KeyPair;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.jose.jws.JwsAsymKeySigner;
import org.webpki.jose.jws.JwsHmacSigner;
import org.webpki.jose.jws.JwsSigner;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;
import org.webpki.util.PEMDecoder;

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
    static final String PRM_SIG_LABEL    = "siglbl";

    static final String FLG_CERT_PATH    = "cerflg";
    static final String FLG_JAVASCRIPT   = "jsflg";
    static final String FLG_JWK_INLINE   = "jwkflg";
    
    static final String DEFAULT_ALG      = "ES256";
    static final String DEFAULT_SIG_LBL  = "signature";
    
    class SelectAlg {

        String preSelected;
        StringBuilder html = new StringBuilder("<select name='" +
                PRM_ALGORITHM + "' id='" +
                PRM_ALGORITHM + "' onchange=\"algChange(this.value)\">");
        
        SelectAlg(String preSelected) {
            this.preSelected = preSelected;
        }

        SelectAlg add(SignatureAlgorithms algorithm) throws IOException {
            String algId = algorithm.getAlgorithmId(AlgorithmPreferences.JOSE);
            html.append("<option value='")
                .append(algId)
                .append("'")
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
        StringBuilder html = new StringBuilder(
                "<div style='display:flex;align-items:center'><input type='checkbox' id='")
            .append(idName)
            .append("' name='")
            .append(idName)
            .append("'");
        if (checked) {
            html.append(" checked");
        }
        if (onchange != null) {
            html.append(" onchange=\"")
                .append(onchange)
                .append("\"");
        }
        html.append("><div style='display:inline-block'>")
            .append(text)
            .append("</div></div>");
        return html;
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String selected = "ES256";
        StringBuilder js = new StringBuilder("'use strict';\n")
            .append(JWSJCSService.keyDeclarations);
        StringBuilder html = new StringBuilder(
                "<form name='shoot' method='POST' action='create'>" +
                "<div class='header'>JSON Signature Creation</div>" +
                HTML.fancyText(
                        true,
                        PRM_JSON_DATA,
                        10,
                        "",
                        "Paste an unsigned JSON object in the text box or try with the default") +
                 "<div style='display:flex;justify-content:center;margin-top:20pt'>" +
                 "<div class='sigparmbox'>" +
                 "<div style='display:flex;justify-content:center'>" +
                   "<div class='sigparmhead'>Signature Parameters</div>" +
                 "</div><div style='display:flex;align-items:center'>")
            .append(new SelectAlg(selected)
                 .add(MACAlgorithms.HMAC_SHA256)
                 .add(MACAlgorithms.HMAC_SHA384)
                 .add(MACAlgorithms.HMAC_SHA512)
                 .add(AsymSignatureAlgorithms.ED25519)
                 .add(AsymSignatureAlgorithms.ED448)
                 .add(AsymSignatureAlgorithms.ECDSA_SHA256)
                 .add(AsymSignatureAlgorithms.ECDSA_SHA384)
                 .add(AsymSignatureAlgorithms.ECDSA_SHA512)
                 .add(AsymSignatureAlgorithms.RSA_SHA256)
                 .add(AsymSignatureAlgorithms.RSA_SHA384)
                 .add(AsymSignatureAlgorithms.RSA_SHA512)
                 .toString())
            .append(
                "<div style='display:inline-block;padding:0 10pt 0 5pt'>Algorithm</div>" +
                "<div class='defbtn' onclick=\"restoreDefaults()\">Restore&nbsp;defaults</div></div>")
            .append(checkBox(FLG_JWK_INLINE, "Automagically insert public key (JWK)",
                             false, "jwkFlagChange(this.checked)"))
            .append(checkBox(FLG_CERT_PATH, "Include provided certificate path (X5C)", 
                             false, "certFlagChange(this.checked)"))
            .append(checkBox(FLG_JAVASCRIPT, "Serialize as JavaScript (but do not verify)",
                             false, null))
            .append(
                "<div style='display:flex;align-items:center'>" +
                "<input type='text' name='" + PRM_SIG_LABEL + "' id='" + PRM_SIG_LABEL + "' " +
                "style='padding:0 3pt;width:7em;font-family:monospace' " +
                "maxlength='100' value='" + DEFAULT_SIG_LBL + "'>" +
                "<div style='display:inline-block'>&nbsp;Signature label</div></div>" +
                "</div>" +
                "</div>" +
                "<div style='display:flex;justify-content:center'>" +
                "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
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
            "function setUserData(unconditionally) {\n" +
            "  let element = document.getElementById('" + PRM_JSON_DATA + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '{\\n" +
            "  \"statement\": \"Hello signed world!\",\\n" +
            "  \"otherProperties\": [2e+3, true]\\n}';\n" +
            "  element = document.getElementById('" + PRM_JWS_EXTRA + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '{\\n}';\n" +
            "}\n" +
            "function setParameters(alg, unconditionally) {\n" +
            "  if (alg.startsWith('HS')) {\n" +
            "    showCert(false);\n" +
            "    showPriv(false);\n" +
            "    disableAndClearCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    disableAndClearCheckBox('" + FLG_JWK_INLINE + "');\n" +
            "    fill('" + PRM_SECRET_KEY + "', alg, " + 
                 JWSJCSService.KeyDeclaration.SECRET_KEYS + ", unconditionally);\n" +
            "    showSec(true)\n" +
            "  } else {\n" +
            "    showSec(false)\n" +
            "    enableCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    enableCheckBox('" + FLG_JWK_INLINE + "');\n" +
            "    fill('" + PRM_PRIVATE_KEY + "', alg, " + 
            JWSJCSService.KeyDeclaration.PRIVATE_KEYS + ", unconditionally);\n" +
            "    showPriv(true);\n" +
            "    fill('" + PRM_CERT_PATH + "', alg, " + 
            JWSJCSService.KeyDeclaration.CERTIFICATES + ", unconditionally);\n" +
            "    showCert(document.getElementById('" + FLG_CERT_PATH + "').checked);\n" +
            "  }\n" +
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
            "  document.getElementById('" + PRM_SIG_LABEL + "').value = '" + DEFAULT_SIG_LBL + "';\n" +
            "  showCert(false);\n" +
            "  setUserData(true);\n" +
            "}\n" +
            "function algChange(alg) {\n" +
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
            "  setUserData(false);\n" +
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
    
    static byte[] getBinaryParameter(HttpServletRequest request, String parameter) throws IOException {
        return getParameter(request, parameter).getBytes("utf-8");
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

   
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
         try {
            request.setCharacterEncoding("utf-8");
            String jsonData = getTextArea(request, PRM_JSON_DATA);
            String signatureLabel = getParameter(request, PRM_SIG_LABEL);
            JSONObjectReader reader = JSONParser.parse(jsonData);
            if (reader.getJSONArrayReader() != null) {
                throw new IOException("The demo does not support signed arrays");
            }
            JSONObjectReader additionalHeaderData = 
                    JSONParser.parse(getParameter(request, PRM_JWS_EXTRA));
            boolean jsFlag = request.getParameter(FLG_JAVASCRIPT) != null;
            boolean keyInlining = request.getParameter(FLG_JWK_INLINE) != null;
            boolean certOption = request.getParameter(FLG_CERT_PATH) != null;

            // Get wanted signature algorithm
            String algorithmParam = getParameter(request, PRM_ALGORITHM);
            SignatureAlgorithms signatureAlgorithm = algorithmParam.startsWith("HS") ?
                    MACAlgorithms.getAlgorithmFromId(algorithmParam, 
                                                     AlgorithmPreferences.JOSE)
                                                                            :
                    AsymSignatureAlgorithms.getAlgorithmFromId(algorithmParam, 
                                                               AlgorithmPreferences.JOSE);

            // Get the signature key
            JwsSigner jwsSigner;
            String validationKey;
            
            // Symmetric or asymmetric?
            if (signatureAlgorithm.isSymmetric()) {
                validationKey = getParameter(request, PRM_SECRET_KEY);
                jwsSigner = new JwsHmacSigner(DebugFormatter.getByteArrayFromHex(validationKey),
                                              (MACAlgorithms)signatureAlgorithm);
            } else {
                // To simplify UI we require PKCS #8 with the public key embedded
                // but we also support JWK which also has the public key
                byte[] privateKeyBlob = getBinaryParameter(request, PRM_PRIVATE_KEY);
                KeyPair keyPair;
                if (privateKeyBlob[0] == '{') {
                    keyPair = JSONParser.parse(privateKeyBlob).getKeyPair();
                    validationKey = 
                            JSONObjectWriter.createCorePublicKey(
                                    keyPair.getPublic(),
                                    AlgorithmPreferences.JOSE).toString();
                 } else {
                    keyPair = PEMDecoder.getKeyPair(privateKeyBlob);
                    validationKey = "-----BEGIN PUBLIC KEY-----\n" +
                            new Base64().getBase64StringFromBinary(
                                    keyPair.getPublic().getEncoded()) +
                            "\n-----END PUBLIC KEY-----";
                }
                privateKeyBlob = null;  // Nullify it after use
                jwsSigner = new JwsAsymKeySigner(keyPair.getPrivate(),
                                                 (AsymSignatureAlgorithms)signatureAlgorithm);

                // Add other JWS header data that the demo program fixes 
                if (certOption) {
                    ((JwsAsymKeySigner)jwsSigner).setCertificatePath(
                            PEMDecoder.getCertificatePath(getBinaryParameter(request,
                                                                             PRM_CERT_PATH)));
                } else if (keyInlining) {
                    ((JwsAsymKeySigner)jwsSigner).setPublicKey(keyPair.getPublic());
                }
            }
            
            // Add any optional (by the user specified) arguments
            jwsSigner.addHeaderItems(additionalHeaderData);

            // Create the detached JWS data to be signed. Of course using RFC 8785 :)
            byte[] jwsPayload = reader.serializeToBytes(JSONOutputFormats.CANONICALIZED);

            // Sign it using the provided algorithm and key
            String jwsString = jwsSigner.createSignature(jwsPayload, true);

            // Create the completed object
            String signedJsonObject = new JSONObjectWriter(reader)
                .setString(signatureLabel, jwsString)
                .serializeToString(JSONOutputFormats.NORMALIZED);
            
            // How things should appear in a "regular" JWS
            if (JWSJCSService.logging) {
                logger.info(jwsString.substring(0, jwsString.lastIndexOf('.')) +
                            Base64URL.encode(jwsPayload) +
                            jwsString.substring(jwsString.lastIndexOf('.')));
            }

            // The following is just for the demo.  That is, we want to preserve
            // the original ("untouched") JSON data for educational purposes.
            int i = signedJsonObject.lastIndexOf("\"" + signatureLabel);
            if (signedJsonObject.charAt(i - 1) == ',') {
                i--;
            }
            int j = jsonData.lastIndexOf("}");
            signedJsonObject = jsonData.substring(0, j) + 
                    signedJsonObject.substring(i, signedJsonObject.length() - 1) +
                    jsonData.substring(j);

            // We terminate by validating the signature as well
            request.getRequestDispatcher((jsFlag ? "jssignature?" : "validate?") +
                ValidateServlet.JWS_OBJECT + 
                "=" +
                URLEncoder.encode(signedJsonObject, "utf-8") +
                "&" +
                ValidateServlet.JWS_VALIDATION_KEY + 
                "=" +
                URLEncoder.encode(validationKey, "utf-8") +
                "&" +
                ValidateServlet.JWS_SIGN_LABL + 
                "=" +
                URLEncoder.encode(signatureLabel, "utf-8"))
                    .forward(request, response);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
