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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONCryptoHelper;

public class HTML {
    static final String SIGNUP_BGND_COLOR = "#F4FFF1";
    static final String SIGNUP_EDIT_COLOR = "#FFFA91";
    static final String SIGNUP_BAD_COLOR = "#F78181";
    static final String BOX_SHADDOW = "box-shadow:5px 5px 5px #C0C0C0";
    static final String KG2_DEVID_BASE = "Field";

    static final String STATIC_BOX = "background:#F8F8F8;";
    static final String COMMON_BOX = "box-sizing:border-box;width:100%;word-break:break-all;border-width:1px;border-style:solid;border-color:grey;padding:10pt;box-shadow:3pt 3pt 3pt #D0D0D0";

    static final String TEXT_BOX = "background:#FFFFD0;";

    static final String SAMPLE_DATA = "{\n"
        + "  &quot;statement&quot;: &quot;Hello signed world!&quot;,\n"
        + "  &quot;otherProperties&quot;: [2000, true]\n" + "}";

    static final String HTML_INIT = "<!DOCTYPE html>" +
        "<html><head><link rel=\"icon\" href=\"webpkiorg.png\" sizes=\"192x192\">" + 
        "<meta name=\"viewport\" content=\"initial-scale=1.0\"/>" + 
        "<title>JSON Signature Demo</title>" + 
        "<link rel=\"stylesheet\" type=\"text/css\" href=\"style.css\">";

    static String encode(String val) {
        if (val != null) {
            StringBuilder buf = new StringBuilder(val.length() + 8);
            char c;

            for (int i = 0; i < val.length(); i++) {
                c = val.charAt(i);
                switch (c) {
                case '<':
                    buf.append("&lt;");
                    break;
                case '>':
                    buf.append("&gt;");
                    break;
                case '&':
                    buf.append("&amp;");
                    break;
                case '\"':
                    buf.append("&#034;");
                    break;
                case '\'':
                    buf.append("&#039;");
                    break;
                default:
                    buf.append(c);
                    break;
                }
            }
            return buf.toString();
        } else {
            return new String("");
        }
    }

    static String newLines2HTML(String text_with_newlines) {
        StringBuilder result = new StringBuilder();
        for (char c : text_with_newlines.toCharArray()) {
            if (c == '\n') {
                result.append("<br>");
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    static String getHTML(String javascript, String box) {
        StringBuilder s = new StringBuilder(HTML_INIT);
        if (javascript != null) {
            s.append("<script type=\"text/javascript\">").append(javascript)
                    .append("</script>");
        }
        s.append("</head><body>" +
        "<div style=\"margin:10pt 0 20pt 10pt;cursor:pointer;padding:2pt 0 0 0;width:100pt;"
        + "height:47pt;border-width:1px;border-style:solid;border-color:black;box-shadow:3pt 3pt 3pt #D0D0D0\""
        + " onclick=\"document.location.href='home'\" title=\"Home sweet home...\">")
                .append(JWSService.logotype)
                .append("</div>")
                .append(box).append("</body></html>");
        return s.toString();
    }

    static void output(HttpServletResponse response, String html)
            throws IOException, ServletException {
        response.setContentType("text/html; charset=utf-8");
        response.setHeader("Pragma", "No-Cache");
        response.setDateHeader("EXPIRES", 0);
        response.getOutputStream().write(html.getBytes("UTF-8"));
    }

    static String getConditionalParameter(HttpServletRequest request,
            String name) {
        String value = request.getParameter(name);
        if (value == null) {
            return "";
        }
        return value;
    }
    
    public static String boxHeader(String id, String text, boolean visible) {
        return new StringBuilder("<div id=\"")
            .append(id)
            .append("\" style=\"padding:10pt 10pt 0 10pt")
            .append(visible ? "" : ";display:none")
            .append("\">" +
               "<div style=\"padding-bottom:3pt\">" + text + ":</div>").toString();
    }

    public static String fancyBox(String id, String content, String header) {
        return boxHeader(id, header, true)
            + "<div id=\"" + id + "\" style=\"" + STATIC_BOX + COMMON_BOX
            + "\">" + content + "</div></div>";
    }

    public static String fancyText(boolean visible, String id, int rows, String content, String header) {
        return boxHeader(id, header, visible) +
            "<textarea style=\"" + TEXT_BOX + COMMON_BOX +
            "\" rows=\"" + rows + "\" maxlength=\"100000\" name=\"" +
            id + "\">" + content + "</textarea></div>";
    }
    
    static void requestPage(HttpServletResponse response, 
                            String javaScript,
                            StringBuilder html) throws IOException, ServletException {
        HTML.output(response, HTML.getHTML(javaScript, html.toString()));
    }

    public static void homePage(HttpServletResponse response, String baseurl)
            throws IOException, ServletException {
        HTML.output(
                response,
                HTML.getHTML(
                        null,
          "<table style=\"max-width=\"300px\">"
        + "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">JSON Clear Text Signature<br>&nbsp;</td></tr>"
        + "<tr><td align=\"left\"><a href=\""
        + baseurl
        + "/verify\">Verify a JWS-JCS on the server</a></td></tr>"
        + "<tr><td>&nbsp;</td></tr>"
        + "<tr><td align=\"left\"><a href=\""
        + baseurl
        + "/create\">Create a JWS-JCS on the server</a></td></tr>"
        + "<tr><td>&nbsp;</td></tr>"
        + "<tr><td align=\"left\"><a href=\""
        + baseurl
        + "/webcrypto\">Create a JWS-JCS using WebCrypto</a></td></tr>"
        + "<tr><td>&nbsp;</td></tr>"
        + "<tr><td align=\"left\"><a target=\"_blank\" href=\"https://github.com/cyberphone/jws-jcs#combining-detached-jws-with-jcs-json-canonicalization-scheme\">JWS-JCS Documentation</a></td></tr>"
        + "</table>"));
    }

    public static void verifyPage(HttpServletResponse response,
                                  HttpServletRequest request,
                                  String signature) throws IOException, ServletException {
        HTML.output(
                response,
                HTML.getHTML(
                        null,
          "<form method=\"POST\" action=\"" +
          request.getRequestURL().toString() +
          "\">" +
          "<div class=\"header\">Testing JSON Signatures</div>" +
          fancyText(true,
                    RequestServlet.JWS_CORE,
                    20, 
                    encode(signature),
                    "Paste a signed JSON object in the text box or try with the default") +
          "<input type=\"submit\" value=\"Verify JSON Signature!\" name=\"sumbit\">" +
          "</form>"));
    }

    public static void noWebCryptoPage(HttpServletResponse response)
            throws IOException, ServletException {
        HTML.output(
                response,
                HTML.getHTML(
                        null,
                        "Your Browser Doesn't Support WebCrypto :-("));
    }

    private static String javaScript(String string) {
        StringBuilder s = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c == '\n') {
                s.append("\\n");
            } else {
                s.append(c);
            }
        }
        return s.toString();
    }

    public static void webCryptoPage(HttpServletResponse response)
            throws IOException, ServletException {
        StringBuilder html = new StringBuilder(
                "<!DOCTYPE html>\n<html><head><title>WebCrypto/JWS-JCS Demo</title><link rel=\"icon\" href=\"webpkiorg.png\" sizes=\"192x192\"><style> "
        + "a {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none} "
        + "</style></head>\n"
        + "<body style=\"padding:10pt;font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white\""
        + ">\n"
        + "<h3>WebCrypto / JWS-JCS Demo</h3>\n\n"
        + "This demo only relies on ES6 and WebCrypto features and does not refer to any external libraries either."
        + "<p><input type=\"button\" value=\"Create Key\" onClick=\"createKey ()\"/></p>\n\n"
        + "<div id=\"pub.key\"></div>\n\n"
        + "<script>\n\n  // This code is supposed to be compliant with the WebCrypto draft...\n\n"
        +

        "var pubKey;\n"
        + "var privKey;\n"
        + "var jsonObject;\n"
        + "var publicKeyInJWKFormat; // The bridge between JWS-JCS and WebCrypto\n\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "// Utility methods                                                      //\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "var BASE64URL_ENCODE = ["
        + "'A','B','C','D','E','F','G','H',"
        + "'I','J','K','L','M','N','O','P',"
        + "'Q','R','S','T','U','V','W','X',"
        + "'Y','Z','a','b','c','d','e','f',"
        + "'g','h','i','j','k','l','m','n',"
        + "'o','p','q','r','s','t','u','v',"
        + "'w','x','y','z','0','1','2','3',"
        + "'4','5','6','7','8','9','-','_'];\n"
        + "function convertToBase64URL(binarray) {\n"
        + "    var encoded = new String ();\n"
        + "    var i = 0;\n"
        + "    var modulo3 = binarray.length % 3;\n"
        + "    while (i < binarray.length - modulo3) {\n"
        + "        encoded += BASE64URL_ENCODE[(binarray[i] >>> 2) & 0x3F];\n"
        + "        encoded += BASE64URL_ENCODE[((binarray[i++] << 4) & 0x30) | ((binarray[i] >>> 4) & 0x0F)];\n"
        + "        encoded += BASE64URL_ENCODE[((binarray[i++] << 2) & 0x3C) | ((binarray[i] >>> 6) & 0x03)];\n"
        + "        encoded += BASE64URL_ENCODE[binarray[i++] & 0x3F];\n"
        + "    }\n"
        + "    if (modulo3 == 1) {\n"
        + "        encoded += BASE64URL_ENCODE[(binarray[i] >>> 2) & 0x3F];\n"
        + "        encoded += BASE64URL_ENCODE[(binarray[i] << 4) & 0x30];\n"
        + "    }\n"
        + "    else if (modulo3 == 2) {\n"
        + "        encoded += BASE64URL_ENCODE[(binarray[i] >>> 2) & 0x3F];\n"
        + "        encoded += BASE64URL_ENCODE[((binarray[i++] << 4) & 0x30) | ((binarray[i] >>> 4) & 0x0F)];\n"
        + "        encoded += BASE64URL_ENCODE[(binarray[i] << 2) & 0x3C];\n"
        + "    }\n"
        + "    return encoded;\n"
        + "}\n\n" +
        "function convertToUTF8(string) {\n"
        + " var buffer = [];\n"
        + " for (var i = 0; i < string.length; i++) {\n"
        + "   var c = string.charCodeAt(i);\n"
        + "   if (c < 128) {\n"
        + "     buffer.push(c);\n"
        + "   } else if ((c > 127) && (c < 2048)) {\n"
        + "     buffer.push((c >> 6) | 0xC0);\n"
        + "     buffer.push((c & 0x3F) | 0x80);\n"
        + "   } else {\n"
        + "     buffer.push((c >> 12) | 0xE0);\n"
        + "     buffer.push(((c >> 6) & 0x3F) | 0x80);\n"
        + "     buffer.push((c & 0x3F) | 0x80);\n"
        + "   }\n"
        + " }\n"
        + " return new Uint8Array(buffer);\n"
        + "}\n\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "// Nice-looking text-boxes                                              //\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "function fancyJSONBox(header, json) {\n"
        + "  return header + ':<br><div style=\"margin-top:3pt;background:#F8F8F8;border-width:1px;border-style:solid;border-color:grey;"
        + "max-width:800pt;padding:10pt;word-break:break-all;box-shadow:3pt 3pt 3pt #D0D0D0\">' + JSON.stringify(json, null, '  ').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\\n/g,'<br>').replace(/  /g,'&nbsp;&nbsp;&nbsp;&nbsp;') + '</div>';\n"
        + "}\n\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "// Error message helper                                                 //\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "function bad(id, message) {\n"
        + " document.getElementById (id).innerHTML = '<b style=\"color:red\">' + message + '</b>';\n"
        + "}\n\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "// Create key event handler                                             //\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "function createKey() {\n"
        + "  if (window.crypto === undefined || window.crypto.subtle == undefined) {\n"
        + "    document.location.href = 'nowebcrypto';\n"
        + "    return;\n"
        + "  }\n"
        + "  console.log('Begin creating key...');\n"
        + "  document.getElementById('pub.key').innerHTML = '<i>Working...</i>';\n"
        + "  crypto.subtle.generateKey({name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}, modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01])},\n"
        + "                            false, ['sign', 'verify']).then(function(key) {\n"
        + "    pubKey = key.publicKey;\n"
        + "    privKey = key.privateKey;\n\n"
        +

        "    crypto.subtle.exportKey('jwk', pubKey).then(function(key) {\n"
        + "      publicKeyInJWKFormat = key;\n"
        + "      console.log('generateKey() RSASSA-PKCS1-v1_5: PASS');\n"
        + "      document.getElementById('pub.key').innerHTML = fancyJSONBox('Generated public key in JWK format', publicKeyInJWKFormat) + "
        + "'<br>&nbsp;<br>Editable sample data in JSON Format:<br>"
        + "<textarea style=\"margin-top:3pt;margin-left:0pt;padding:10px;background:#FFFFD0;min-width:805pt;border-width:1px;border-style:solid;border-color:grey;box-shadow:3pt 3pt 3pt #D0D0D0\" "
        + "rows=\"5\" maxlength=\"1000\" id=\"json.text\">"
        + javaScript(SAMPLE_DATA)
        + "</textarea>"
        + "<p><input type=\"button\" value=\"Sign Sample Data\" onClick=\"signSampleData()\"/></p><p id=\"sign.res\"><p>';\n"
        + "    });\n"
        + "  }).then(undefined, function() {\n"
        + "    bad('pub.key', 'WebCrypto failed for unknown reasons');\n"
        + "  });"
        + "\n}\n\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "// Canonicalizer                                                        //\n"
        + "//////////////////////////////////////////////////////////////////////////\n" +
        "var canonicalize = function(object) {\n" +
        "\n" +
        "    var buffer = '';\n" +
        "    serialize(object);\n" +
        "    return buffer;\n" +
        "\n" +
        "    function serialize(object) {\n" +
        "        if (object !== null && typeof object === 'object') {\n" +
        "            if (Array.isArray(object)) {\n" +
        "                buffer += '[';\n" +
        "                let next = false;\n" +
        "                // Array - Maintain element order\n" +
        "                object.forEach((element) => {\n" +
        "                    if (next) {\n" +
        "                        buffer += ',';\n" +
        "                    }\n" +
        "                    next = true;\n" +
        "                    // Recursive call\n" +
        "                    serialize(element);\n" +
        "                });\n" +
        "                buffer += ']';\n" +
        "            } else {\n" +
        "                buffer += '{';\n" +
        "                let next = false;\n" +
        "                // Object - Sort properties before serializing\n" +
        "                Object.keys(object).sort().forEach((property) => {\n" +
        "                    if (next) {\n" +
        "                        buffer += ',';\n" +
        "                    }\n" +
        "                    next = true;\n" +
        "                    // Properties are just strings - Use ES6\n" +
        "                    buffer += JSON.stringify(property);\n" +
        "                    buffer += ':';\n" +
        "                    // Recursive call\n" +
        "                    serialize(object[property]);\n" +
        "                });\n" +
        "                buffer += '}';\n" +
        "            }\n" +
        "        } else {\n" +
        "            // Primitive data type - Use ES6\n" +
        "            buffer += JSON.stringify(object);\n" +
        "        }\n" +
        "    }\n" +
        "};\n\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "// Sign event handler                                                   //\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "function signSampleData() {\n"
        + "  try {\n"
        + "    document.getElementById('sign.res').innerHTML = '';\n"
        + "    jsonObject = JSON.parse(document.getElementById('json.text').value);\n"
        + "    if (typeof jsonObject !== 'object' || Array.isArray(jsonObject)) {\n"
        + "      bad('sign.res', 'Only JSON objects can be signed');\n"
        + "      return;\n"
        + "    }\n"
        + "    if (jsonObject."
        + JSONCryptoHelper.SIGNATURE_JSON
        + ") {\n"
        + "      bad('sign.res', 'Object is already signed');\n"
        + "      return;\n"
        + "    }\n"
        + "    var jwsHeader = {};\n"
        + "    jwsHeader."
        + JSONCryptoHelper.ALG_JSON
        + " = '"
        + AsymSignatureAlgorithms.RSA_SHA256
                .getAlgorithmId(AlgorithmPreferences.JOSE)
        + "';\n"
        + "    var publicKeyObject = jwsHeader."
        + JSONCryptoHelper.JWK_JSON
        + " = {};\n"
        + "    publicKeyObject."
        + JSONCryptoHelper.KTY_JSON
        + " = '"
        + JSONCryptoHelper.RSA_PUBLIC_KEY
        + "';\n"
        + "    publicKeyObject."
        + JSONCryptoHelper.N_JSON
        + " = publicKeyInJWKFormat."
        + JSONCryptoHelper.N_JSON
        + ";\n"
        + "    publicKeyObject."
        + JSONCryptoHelper.E_JSON
        + " = publicKeyInJWKFormat."
        + JSONCryptoHelper.E_JSON
        + ";\n"
        + "  } catch (err) {\n"
        + "    bad('sign.res', 'JSON error: ' + err.toString());\n"
        + "    return;\n"
        + "  }\n"
        + "  var jwsHeaderB64 = convertToBase64URL(convertToUTF8(JSON.stringify(jwsHeader)));\n"
        + "  var payloadB64 = convertToBase64URL(convertToUTF8(canonicalize(jsonObject)));\n"
        + "  crypto.subtle.sign({name: 'RSASSA-PKCS1-v1_5'}, privKey,\n"
        + "                     convertToUTF8(jwsHeaderB64 + '.' + payloadB64" +
        ")).then(function(signature) {\n"
        + "    console.log('Sign with RSASSA-PKCS1-v1_5 - SHA-256: PASS');\n"
        + "    jsonObject."
        + JSONCryptoHelper.SIGNATURE_JSON
        + " = jwsHeaderB64 + '..' + convertToBase64URL(new Uint8Array(signature));\n"
        + "    document.getElementById('sign.res').innerHTML = fancyJSONBox('Signed data in JWS-JCS format', jsonObject) + "
        + "'<p><input type=\"button\" value=\"Verify Signature (on the server)\" onClick=\"verifySignatureOnServer()\"></p>';\n"
        + "  }).then(undefined, function() {\n"
        + "    bad('sign.res', 'WebCrypto failed for unknown reasons');\n"
        + "  });\n"
        + "}\n\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "// Optional validation is in this demo/test happening on the server     //\n"
        + "//////////////////////////////////////////////////////////////////////////\n"
        + "function verifySignatureOnServer() {\n"
        + "  document.location.href = 'request?"
        + RequestServlet.JWS_CORE
        + "="
        + "' + "
        + "convertToBase64URL(convertToUTF8(JSON.stringify(jsonObject)));\n"
        + "}\n");

        HTML.output(response, html.append("</script></body></html>").toString());
    }

    public static void errorPage(HttpServletResponse response, String error)
            throws IOException, ServletException {
        HTML.output(
                response,
                HTML.getHTML(
                        null,
         "<table style=\"max-width=\"300px\">"
        + "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana;color:red\">Something went wrong...<br>&nbsp;</td></tr>"
        + "<tr><td align=\"left\">"
        + newLines2HTML(encode(error)) + "</td></tr>"
        + "</table>"));
    }

    public static void printResultPage(HttpServletResponse response,
            String message) throws IOException, ServletException {
        HTML.output(response, HTML.getHTML(null, message));
    }
}
