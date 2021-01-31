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

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

public class HashServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(HashServlet.class.getName());

    // HTML form arguments
    static final String JSON_DATA        = "json";

    static final String HASH_ALGORITHM     = "alg";
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }

            // Get the input data items
            JSONObjectReader parsedJson = JSONParser.parse(
                    CreateServlet.getParameter(request, JSON_DATA));
            HashAlgorithms hashAlgorithm = HashAlgorithms.getAlgorithmFromId(
                    CreateServlet.getParameter(request, HASH_ALGORITHM), 
                    AlgorithmPreferences.JOSE);

            // Create a pretty-printed JSON object without canonicalization
            String prettyJson = parsedJson.serializeToString(JSONOutputFormats.PRETTY_HTML);
            
            // Create a canonicalized (RFC 8785) version of the JSON data
            String canonicalJson = parsedJson.serializeToString(JSONOutputFormats.CANONICALIZED);
            byte[] canonicalJsonBinary = canonicalJson.getBytes("utf-8");
            
            // Hash the UTF-8
            byte[] hashedJson = hashAlgorithm.digest(canonicalJsonBinary);
            
            StringBuilder html = new StringBuilder(
                    "<div class='header'>JSON Data Successfully Hashed</div>")
                .append(HTML.fancyBox("pretty", 
                                      prettyJson, 
                                      "\"Pretty-printed\" JSON data"))           
                .append(HTML.fancyCode("canonical", 
                                       canonicalJson,
                                       "Canonical (RFC 8785) version of the JSON data"))
                .append(HTML.fancyBox("canonicalhex", 
                                  ArrayUtil.toHexString(canonicalJsonBinary, 0, -1, false, ' '),
                                      "Canonical data in hexadecimal"))
                .append(HTML.fancyBox("algorithm", 
                                       hashAlgorithm.getJoseAlgorithmId(),
                                       "Hash algorithm in JOSE-like notation"))
                 .append(HTML.fancyBox("hex",
                                       ArrayUtil.toHexString(hashedJson, 0, -1, false, ' '),
                                       "Hash in hexadecimal"))
                 .append(HTML.fancyBox("b64u",
                                       Base64URL.encode(hashedJson),
                                       "Hash in Base64Url"));

            // Finally, print it out
            HTML.standardPage(response, null, html.append("<div style='padding:10pt'></div>"));
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
    
    StringBuilder algorithmSelector() throws IOException {
        StringBuilder html = new StringBuilder(
                "<div style='display:flex;justify-content:center;margin-top:1.5em'>" + 
                "<table><tr><td>Selected hash algoritm:</td></tr>" +
                "<tr><td><select name='" + HASH_ALGORITHM + "'>");
        
        for (HashAlgorithms algorithm : HashAlgorithms.values()) {
            if (algorithm == HashAlgorithms.SHA1) {
                continue; // Deprecated these days...
            }
            String algId = algorithm.getAlgorithmId(AlgorithmPreferences.JOSE);
            html.append("<option value='")
                .append(algId)
                .append("'")
                .append(algorithm == HashAlgorithms.SHA256 ? " selected>" : ">")
                .append(algId)
                .append(" - ")
                .append(algorithm.toString())
                .append("</option>");
        }
        return html.append("</select></td></tr></table></div>");
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
                "<form name='shoot' method='POST' action='hash'>" +
                "<div class='header'>Canonicalize and Hash JSON Data</div>")
            .append(HTML.fancyText(true,
                                   JSON_DATA,
                                   10, 
                                   JwsCtService.sampleJsonForHashing,
                     "Paste JSON data in the text box or try with the default"))
            .append(algorithmSelector())
            .append(
                "<div style='display:flex;justify-content:center'>" +
                "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
                "Hash JSON Data" +
                "</div>" +
                "</div>" +
                "</form>" +
                "<div>&nbsp;</div>"));
    }
}
