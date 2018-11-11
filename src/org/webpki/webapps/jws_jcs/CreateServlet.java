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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Vector;
import java.util.logging.Logger;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;
import org.webpki.util.Base64;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;

public class CreateServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(RequestServlet.class.getName());

    private static final long serialVersionUID = 1L;

    static final String PRM_JSON_DATA    = "json";
    
    static final String PRM_JWS_EXTRA    = "extra";

    static final String PRM_SECRET_KEY   = "sec";

    static final String PRM_PRIVATE_KEY  = "PEMPRIV";

    static final String PRM_CERT_PATH    = "PEMCERT";

    static final String PRM_ALGORITHM    = "alg";
    static final String FLG_CERT_PATH    = "cflg";
    static final String FLG_JAVASCRIPT   = "js";
    static final String FLG_JWK_INLINE   = "jwk";
    
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
                        "{\n" +
                        "  &quot;statement&quot;: &quot;Hello signed world!&quot;,\n" +
                        "  &quot;otherProperties&quot;: [2e+3, true]\n" +
                        "}",
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
                "<div class=\"defbtn\" onclick=\"restoreDefaults()\">Defaults</div></div>")
            .append(checkBox(FLG_JWK_INLINE, "Inlined public key (JWK)", false, "jwkFlagChange(this.checked)"))
            .append(checkBox(FLG_CERT_PATH, "Certificate path", false, "certFlagChange(this.checked)"))
            .append(checkBox(FLG_JAVASCRIPT, "Serialize as JavaScript (but do not verify)", false, null))
            .append(
                "</div>" +
                "</div>" +
                "<div style=\"display:flex;justify-content:center\">" +
                "<div class=\"stdbtn\" onclick=\"document.forms.shoot.submit()\">" +
                "Create JSON Signature!" +
                "</div>" +
                "</div>")
            .append(
                HTML.fancyText(true,
                          PRM_JWS_EXTRA,
                          4,
                          "{\n" +
                          "}",
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
                          "Private key in PEM/PKCS #8 format"))
            .append(
                HTML.fancyText(false,
                          PRM_CERT_PATH,
                          4,
                          "",
                          "Certificate path in PEM format"))
            .append(
                "</form>" +
                "<div style=\"padding:15pt\">Note: No data is stored on the server, it only passes it!</div>");
        js.append(
            "function fill(element, alg, keyHolder, unconditional) {\n" +
            "  let textarea = document.getElementById(element).children[1];\n" +
            "  if (unconditional || textarea.innerHTML == '') {\n" +
            "    textarea.innerHTML = keyHolder[alg];\n" +
            "  }\n" +
            "}\n" +
            "function disableAndClearCheckBox(id) {\n" +
            "  let checkBox = document.getElementById(id);\n" +
            "  checkBox.checked = false;\n" +
            "  checkBox.disabled = true;\n" +
            "}\n" +
            "function enableCheckBox(id) {\n" +
            "  document.getElementById(id).disabled = false;\n" +
            "}\n" +
            "function setParameters(alg, unconditional) {\n" +
            "  if (alg.startsWith('HS')) {\n" +
            "    showCert(false);\n" +
            "    showPriv(false);\n" +
            "    disableAndClearCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    disableAndClearCheckBox('" + FLG_JWK_INLINE + "');\n" +
            "    fill('" + PRM_SECRET_KEY + "', alg, " + 
                 JWSService.KeyDeclaration.SECRET_KEYS + ", unconditional);\n" +
            "    showSec(true)\n" +
            "  } else {\n" +
            "    showSec(false)\n" +
            "    enableCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    enableCheckBox('" + FLG_JWK_INLINE + "');\n" +
            "    fill('" + PRM_PRIVATE_KEY + "', alg, " + 
            JWSService.KeyDeclaration.PRIVATE_KEYS + ", unconditional);\n" +
            "    showPriv(true);\n" +
            "    fill('" + PRM_CERT_PATH + "', alg, " + 
            JWSService.KeyDeclaration.CERTIFICATES + ", unconditional);\n" +
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
            "  let alg = document.getElementById('" + PRM_ALGORITHM  + "').value;\n" +
            "  console.log('alg=' + alg);\n" +
            "  setParameters(alg, false);\n" +
            "});\n");
        HTML.requestPage(response, 
                         js.toString(),
                         html);
    }
    
    static String getParameter(HttpServletRequest request, String parameter) throws IOException {
        String string = request.getParameter(parameter);
        if (string == null) {
            throw new IOException("Missing data for: "+ parameter);
        }
        return string;
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


    static Vector<byte[]> getPemBlobs(HttpServletRequest request, 
                                      String name,
                                      String type) throws IOException {
        Vector<byte[]> blobs = new Vector<byte[]>();
        String pemData = getParameter(request, name).trim();
        do {
            if (!pemData.startsWith("-----BEGIN " + type + "-----")) {
                throw new IOException("PEM BEGIN error in: " + name);
            }
            int i = pemData.indexOf("-----END " + type + "-----");
            if (i < 0) {
                throw new IOException("PEM END error in: " + name);
            }
            try {
                byte[] blob = new Base64().getBinaryFromBase64String(pemData.substring(16 + type.length(), i));
                blobs.add(blob);
            } catch (IOException e) {
                throw new IOException("PEM data error in: " + name + " reason: " + e.getMessage());
            }
            pemData = pemData.substring(i + type.length() + 14).trim();
        } while (pemData.length() != 0);
        return blobs;
    }
    
    static byte[] getPemBlob(HttpServletRequest request, 
                             String name,
                             String type) throws IOException {
        Vector<byte[]> blobs = getPemBlobs(request, name, type);
        if (blobs.size() != 1) throw new IOException("Only one element is allowed for: " + type);
        return blobs.firstElement();
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("UTF-8");
        try {
            String json_object = getTextArea(request, PRM_JSON_DATA);
            JSONObjectReader reader = JSONParser.parse(json_object);
            if (reader.getJSONArrayReader() != null) {
                throw new IOException("The demo does not support signed arrays");
            }
            JSONObjectReader additionalHeaderData = JSONParser.parse(getParameter(request, PRM_JWS_EXTRA));
            boolean jsFlag = request.getParameter(FLG_JAVASCRIPT) != null;
            boolean keyInlining = request.getParameter(FLG_JWK_INLINE) != null;
            boolean certOption = request.getParameter(FLG_CERT_PATH) != null;
            String algorithm = getParameter(request, PRM_ALGORITHM);
            JSONObjectWriter jwsHeader = new JSONObjectWriter();
            jwsHeader.setString(JSONCryptoHelper.ALG_JSON, algorithm);
            JSONObjectWriter writer = new JSONObjectWriter(reader);
            for (String key : additionalHeaderData.getProperties()) {
                jwsHeader.copyElement(key, key, additionalHeaderData);
            }
            PublicKey publicKey = null;
            PrivateKey privateKey = null;
            if (algorithm.startsWith("HS")) {
                
            } else {
                byte[] privateKeyBlob = getPemBlob(request, PRM_PRIVATE_KEY, "PRIVATE KEY");
                if (algorithm.startsWith("RS")) {
                    
                } else {
                    
                }
                if (certOption) {
                    X509Certificate[] certificatePath =
                        CertificateUtil
                            .makeCertificatePath(getPemBlobs(request, PRM_CERT_PATH, "CERTIFICATE"));
                    jwsHeader.setCertificatePath(certificatePath);
                }
            }
            logger.info(jwsHeader.toString());
/*          
            switch (action) {
                case SYM:
                    byte[] secretKey = 
                        DebugFormatter.getByteArrayFromHex(getParameter(request,
                                                                        RequestServlet.JWS_SECRET_KEY));
                    MACAlgorithms symAlg = MACAlgorithms.getAlgorithmFromId(algorithm, 
                                                                            AlgorithmPreferences.JOSE);
                    break;
                default:
                    throw new IOException("Not impl");
            }

            KeyPair keyPair = null;
            if (action == RadioButton.SYM) {
            } else if (action == RadioButton.CERT) {
                jwsHeader.setCertificatePath(JWSService.clientkey_rsa.certificatePath);
                keyPair = JWSService.clientkey_rsa.keyPair;
            } else {
                keyPair = (action == RadioButton.PRIV ? JWSService.clientkey_rsa : JWSService.clientkey_ec).keyPair;
                if (keyInlining) {
                    jwsHeader.setPublicKey(keyPair.getPublic());
                }
            }
            String signed_json = new String(new GenerateSignature(jwsHeader, keyPair)
                    .sign(writer), "utf-8");
            int i = signed_json.lastIndexOf("\"sig");
            if (signed_json.charAt(i - 1) == ',') {
                i--;
            }
            int j = json_object.lastIndexOf("}");
            signed_json = json_object.substring(0, j) + 
                    signed_json.substring(i, signed_json.length() - 1) +
                    json_object.substring(j);
            RequestDispatcher rd = request
                    .getRequestDispatcher((jsFlag ? "jssignature?" : "request?")
                            + RequestServlet.JWS_CORE
                            + "="
                            + Base64URL.encode(signed_json.getBytes("utf-8")));
            rd.forward(request, response);
            */
        } catch (Exception e) {
            HTML.errorPage(response, e.getMessage());
        }
    }

}
