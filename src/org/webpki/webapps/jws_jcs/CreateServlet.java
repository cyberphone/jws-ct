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

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;

public class CreateServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    static final String KEY_TYPE     = "keytype";
    static final String JS_FLAG      = "js";
    static final String KEY_INLINING = "keyinlining";
    
    static final String JS_SYM_KEY   = "symKeyHex";
    static final String JS_EC_KEY    = "ecPEM";
    static final String JS_RSA_KEY   = "rsaPEM";
    static final String JS_CERT_PATH = "certPEM";
    
    class SelectAlg {
        StringBuilder js;
        String preSelected;
        StringBuilder html = new StringBuilder("<select name=\"" +
                RequestServlet.JWS_ALGORITHM + "\" id=\"" +
                RequestServlet.JWS_ALGORITHM + "\" onchange=\"algChange(this.value)\">");
        
        SelectAlg(StringBuilder js, String preSelected) {
            this.js = js;
            this.preSelected = preSelected;
        }

        SelectAlg add(SignatureAlgorithms algorithm, String executor) throws IOException {
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
                        RequestServlet.JWS_CORE,
                        10,
                        "{\n" +
                        "  &quot;statement&quot;: &quot;Hello signed world!&quot;,\n" +
                        "  &quot;otherProperties&quot;: [2e+3, true]\n" +
                        "}",
                        "Paste an unsigned JSON object in the text box or try with the default") +
                "<div style=\"display:flex;justify-content:center;padding-top:15pt\">" +
                "<table class=\"keytable\">" +
                "<tr><td valign=\"middle\" rowspan=\"5\">Signing parameters:&nbsp;</td>" +
                "<td colspan=\"4\"><div style=\"display:inline-block\">")
            .append(new SelectAlg(js, selected)
                 .add(MACAlgorithms.HMAC_SHA256,            "symKey()")
                 .add(MACAlgorithms.HMAC_SHA384,            "symKey()")
                 .add(MACAlgorithms.HMAC_SHA512,            "symKey()")
                 .add(AsymSignatureAlgorithms.ECDSA_SHA256, "ecKey()")
                 .add(AsymSignatureAlgorithms.ECDSA_SHA384, "ecKey()")
                 .add(AsymSignatureAlgorithms.ECDSA_SHA512, "ecKey()")
                 .add(AsymSignatureAlgorithms.RSA_SHA256,   "rsaKey()")
                 .add(AsymSignatureAlgorithms.RSA_SHA384,   "rsaKey()")
                 .add(AsymSignatureAlgorithms.RSA_SHA512,   "rsaKey()")
                 .toString())
            .append(
                "</div><div style=\"display:inline-block;padding-left:5pt\">Algorithm</div></td></tr>" +
                "<tr><td style=\"padding-left:1px\">")
            .append(radioButton(false,
                    GenerateSignature.ACTION.SYM,
                    "symKey()"))
            .append(
                "</td><td colspan=\"3\">Symmetric key</td></tr>" +
                "<tr><td style=\"border-width:1px 0 1px 1px\">")
            .append(radioButton(true, 
                    GenerateSignature.ACTION.EC,
                    "privKey()"))
            .append(
                "</td><td style=\"border-width:1px 0 1px 0\">Private Key</td>" +
                "<td style=\"border-width:1px 0 1px 0\">" +
                "<input type=\"checkbox\" name=\"" +
                CreateServlet.KEY_INLINING +
                "\" value=\"false\"></td>" +
                "<td style=\"border-width:1px 1px 1px 0\">Inlined public key (JWK)&nbsp;</td></tr>" +
                "<tr><td align=\"center\" style=\"padding-left:1px\">")
            .append(radioButton(false,
                    GenerateSignature.ACTION.X509,
                    "certPath()"))
            .append(
                "</td><td colspan=\"3\">X.509 Certificate/Private key</td></tr>" +
                "<tr><td style=\"padding-left:1px\"><input type=\"checkbox\" name=\"" +
                CreateServlet.JS_FLAG +
                "\" value=\"true\"></td><td colspan=\"3\">Serialize as JavaScript (but do not verify)</td></tr>" +
                "</table></div>" +
                "<div style=\"display:flex;justify-content:center\">" +
                "<div class=\"stdbtn\" onclick=\"document.forms.shoot.submit()\">" +
                "Create JSON Signature!" +
                "</div>" +
                "</div>")
            .append(
                HTML.fancyText(true,
                          RequestServlet.JWS_ADDITIONAL,
                          4,
                          "{\n" +
                          "}",
                          "Additional JWS header parameters (here expressed as properties of a JSON object)"))
            .append(
                HTML.fancyText(false,
                          RequestServlet.JWS_SECRET_KEY,
                          1,
                          "",
                          "Secret key in hexadecimal format"))
            .append(
                HTML.fancyText(false,
                          RequestServlet.JWS_PRIVATE_KEY,
                          4,
                          "",
                          "Private key in PEM/PKCS #8 format"))
            .append(
                HTML.fancyText(false,
                          RequestServlet.JWS_CERT_PATH,
                          4,
                          "",
                          "Certificate path in PEM format"))
            .append(
                "</form>" +
                "<div style=\"padding:15pt\">Note: No data is stored on the server, it only passes it!</div>");
        js.append(
            "function fill(element, keyHolder) {\n" +
            "  let alg = document.shoot." + RequestServlet.JWS_ALGORITHM + ".value;\n" +
            "  document.getElementById(element).children[1].innerHTML = keyHolder[alg];\n" +
            "}\n" +
            "function optionalFill(element, alg, keyHolder) {\n" +
            "  let textarea = document.getElementById(element).children[1];\n" +
            "console.log('txt=' + textarea.innerHTML + '=');\n" +
            "  if (textarea.innerHTML == '') {\n" +
            "    textarea.innerHTML = keyHolder[alg];\n" +
            "  }\n" +
            "}\n" +
            "function algChange(alg) {\n" +
            "console.log('alg=' + alg);\n" +
            "  if (alg.startsWith('HS')) {\n" +
            "    document.shoot." + CreateServlet.KEY_TYPE + "[0].checked = true;\n" +
            "    symKey();\n" +
            "  } else {\n" +
            "    document.shoot." + CreateServlet.KEY_TYPE + "[1].checked = true;\n" +
            "    privKey();\n" +
            "  }\n" +
            "}\n" +
            "function algCheck(symmetric) {\n" +
            "  let s = document.shoot." + RequestServlet.JWS_ALGORITHM + ";\n" +
            "  if (s.value.startsWith('HS') != symmetric) {\n" +
            "    let v = symmetric ? 'HS256' : 'ES256';\n" +
            "    for (let i = 0; i < s.options.length; i++) {\n" +
            "      if (s.options[i].text == v) {\n" +
            "        s.options[i].selected = true;\n" +
            "        return;\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
            "function showCert(show) {\n" +
            "  document.getElementById('" + RequestServlet.JWS_CERT_PATH + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function showPriv(show) {\n" +
            "  document.getElementById('" + RequestServlet.JWS_PRIVATE_KEY + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function showSym(show) {\n" +
            "  document.getElementById('" + RequestServlet.JWS_SECRET_KEY + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function symKey() {\n" +
            "  algCheck(true);\n" +
            "  showCert(false);\n" +
            "  showPriv(false);\n" +
            "  fill('" + RequestServlet.JWS_SECRET_KEY + "', symmetricKeys);\n" +
            "  showSym(true);\n" +
            "}\n" +
            "function privKey() {\n" +
            "  algCheck(false);\n" +
            "  showCert(false);\n" +
            "  showSym(false);\n" +
            "  fill('" + RequestServlet.JWS_PRIVATE_KEY + "', privateKeys);\n" +
            "  showPriv(true);\n" +
            "}\n" +
            "function certPath() {\n" +
            "  algCheck(false);\n" +
            "  showSym(false);\n" +
            "  fill('" + RequestServlet.JWS_PRIVATE_KEY + "', privateKeys);\n" +
            "  showPriv(true);\n" +
            "  fill('" + RequestServlet.JWS_CERT_PATH + "', certificates);\n" +
            "  showCert(true);\n" +
            "}\n" +
            "window.addEventListener('load', function(event) {\n" +
            "  let alg = document.getElementById('" + RequestServlet.JWS_ALGORITHM  + "').value;\n" +
            "  console.log('alg=' + alg);\n" +
            "  if (alg.startsWith('HS')) {\n" +
            "  } else {\n" +
            "  console.log('ES/RS=' + alg);\n" +
            "    optionalFill('" + RequestServlet.JWS_PRIVATE_KEY + "', alg, privateKeys);\n" +
            "    showPriv(true);\n" +
            "  }\n" +
            "});\n");
        HTML.requestPage(response, 
                         js.toString(),
                         html);
    }
    
    private String radioButton(boolean checked, 
                               GenerateSignature.ACTION action,
                               String onClick) {
        return "<input type=\"radio\" name=\"" +
                CreateServlet.KEY_TYPE +
                "\"" +
                (checked ? " checked" : "") +
                " onclick=\"" +
                onClick +
                "\" value=\"" +
                action.toString() +
                "\">";
    }

    public static String getParameter(HttpServletRequest request, String parameter) throws IOException {
        String string = request.getParameter(parameter);
        if (string == null) {
            throw new IOException("Missing data for: "+ parameter);
        }
        return string;
    }

    static public String getTextArea(HttpServletRequest request)
            throws IOException {
        String string = getParameter(request, RequestServlet.JWS_CORE);
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
        request.setCharacterEncoding("UTF-8");
        String json_object = getTextArea(request);
        JSONObjectReader additionalHeaderData = JSONParser.parse(getParameter(request, RequestServlet.JWS_ADDITIONAL));
        GenerateSignature.ACTION action = GenerateSignature.ACTION.EC;
        boolean jsFlag = request.getParameter(JS_FLAG) != null;
        boolean keyInlining = request.getParameter(KEY_INLINING) != null;
        String key_type = request.getParameter(KEY_TYPE);
        for (GenerateSignature.ACTION a : GenerateSignature.ACTION.values()) {
            if (a.toString().equals(key_type)) {
                action = a;
                break;
            }
        }
        try {
            JSONObjectReader reader = JSONParser.parse(json_object);
            if (reader.getJSONArrayReader() != null) {
                throw new IOException("The demo does not support signed arrays");
            }
            JSONObjectWriter writer = new JSONObjectWriter(reader);
            JSONObjectWriter jwsHeader = new JSONObjectWriter();
            jwsHeader.setString(JSONCryptoHelper.ALG_JSON, action.algorithm);
            for (String key : additionalHeaderData.getProperties()) {
                jwsHeader.copyElement(key, key, additionalHeaderData);
            }
            KeyPair keyPair = null;
            if (action == GenerateSignature.ACTION.SYM) {
            } else if (action == GenerateSignature.ACTION.X509) {
                jwsHeader.setCertificatePath(JWSService.clientkey_rsa.certificatePath);
                keyPair = JWSService.clientkey_rsa.keyPair;
            } else {
                keyPair = (action == GenerateSignature.ACTION.RSA ? JWSService.clientkey_rsa : JWSService.clientkey_ec).keyPair;
                if (keyInlining) {
                    jwsHeader.setPublicKey(keyPair.getPublic());
                }
            }
            String signed_json = new String(new GenerateSignature(action, jwsHeader, keyPair)
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
        } catch (IOException | GeneralSecurityException e) {
            HTML.errorPage(response, e.getMessage());
        }
    }
}
