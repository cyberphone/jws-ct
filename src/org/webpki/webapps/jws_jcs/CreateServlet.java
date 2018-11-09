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

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;
import org.webpki.util.Base64URL;

public class CreateServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    static final String KEY_TYPE     = "keytype";
    static final String JS_FLAG      = "js";
    static final String KEY_INLINING = "keyinlining";
    
    static final String JS_EC_KEY    = "ecPEM";
    static final String JS_RSA_KEY   = "rsaPEM";
    static final String JS_CERT_PATH = "certPEM";

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
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
                "<tr><td valign=\"middle\" rowspan=\"5\">Signing parameters:&nbsp;</td><td align=\"left\" style=\"padding-left:2px\"><input type=\"radio\" name=\"" +
                CreateServlet.KEY_TYPE +
                "\" value=\"" +
                GenerateSignature.ACTION.SYM +
                "\"></td><td colspan=\"3\">Symmetric key</td></tr>" +
                "<tr><td align=\"center\" style=\"border-width:1px 0 0 1px\">")
            .append(radioButton(true, 
                    GenerateSignature.ACTION.EC,
                    "ecKey()"))
            .append(
                "</td><td style=\"border-width:1px 0 0 0\">EC Key (P-256)</td>" +
                "<td rowspan=\"2\" align=\"right\" style=\"border-width:1px 0 1px 0\"><input type=\"checkbox\" name=\"" +
                CreateServlet.KEY_INLINING +
                "\" value=\"false\"></td><td rowspan=\"2\" style=\"border-width:1px 1px 1px 0\">Inlined public key (JWK)&nbsp;</td></tr>" +
                "<tr><td align=\"center\" style=\"border-width:0 0 1px 1px\">")
            .append(radioButton(false, 
                    GenerateSignature.ACTION.RSA,
                    "rsaKey()"))
            .append(
                "</td><td style=\"border-width:0 0 1px 0\">RSA Key (2048)</td></tr>" +
                "<tr><td align=\"center\" style=\"padding-left:2px\">")
            .append(radioButton(false,
                    GenerateSignature.ACTION.X509,
                    "certPath()"))
            .append(
                "</td><td colspan=\"3\">X.509 Certificate/Private key</td></tr>" +
                "<tr><td align=\"center\" style=\"padding-left:2px\"><input type=\"checkbox\" name=\"" +
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
                          RequestServlet.JWS_PRIVATE_KEY,
                          4,
                          "{\n" +
                          "}",
                          "Private key in PEM/PKCS #8 format"))
            .append(
                HTML.fancyText(false,
                          RequestServlet.JWS_CERT_PATH,
                          4,
                          "{\n" +
                          "}",
                          "Certificate path in PEM format"))
            .append("</form>");
        StringBuilder js = new StringBuilder();
        createPEMJS(js, JS_EC_KEY, JWSService.clientkey_ec.getPrivateKeyPEM());
        createPEMJS(js, JS_RSA_KEY, JWSService.clientkey_rsa.getPrivateKeyPEM());
        createPEMJS(js, JS_CERT_PATH, JWSService.clientkey_rsa.getCertificatePathPEM());
        js.append(
            "function fill(element, data) {\n" +
            "  document.getElementById(element).children[1].innerHTML = data;\n" +
            "}\n" +
            "function showCert(show) {\n" +
            "  document.getElementById('" + RequestServlet.JWS_CERT_PATH + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function showPriv(show) {\n" +
            "  document.getElementById('" + RequestServlet.JWS_PRIVATE_KEY + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function ecKey() {\n" +
            "  showCert(false);\n" +
            "  fill('" + RequestServlet.JWS_PRIVATE_KEY + "', " + JS_EC_KEY + ");\n" +
            "  showPriv(true);\n" +
            "}\n" +
            "function rsaKey() {\n" +
            "  showCert(false);\n" +
            "  fill('" + RequestServlet.JWS_PRIVATE_KEY + "', " + JS_RSA_KEY + ");\n" +
            "  showPriv(true);\n" +
            "}\n" +
            "function certPath() {\n" +
            "  showPriv(true);\n" +
            "  fill('" + RequestServlet.JWS_PRIVATE_KEY + "', " + JS_RSA_KEY + ");\n" +
            "  fill('" + RequestServlet.JWS_CERT_PATH + "', " + JS_CERT_PATH + ");\n" +
            "  showCert(true);\n" +
            "}\n");
        HTML.requestPage(response, 
                         js.toString(),
                         html);
    }
    
    private void createPEMJS(StringBuilder js, String name, StringBuilder pem) {
        js.append("var ")
          .append(name)
          .append(" = '")
          .append(HTML.javaScript(pem.toString()))
          .append("';\n");
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
