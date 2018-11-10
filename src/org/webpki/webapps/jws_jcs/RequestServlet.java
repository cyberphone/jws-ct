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
import java.util.Vector;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.util.Base64URL;
import org.webpki.webutil.ServletUtil;

public class RequestServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(RequestServlet.class.getName());

    static final String JWS_CORE        = "JWS";
    static final String JWS_ADDITIONAL  = "additional";
    static final String JWS_PRIVATE_KEY = "private";
    static final String JWS_CERT_PATH   = "certpath";
    static final String JWS_SECRET_KEY  = "secret";
    static final String JWS_ALGORITHM    = "alg";

    static void error(HttpServletResponse response, String error_message)
            throws IOException, ServletException {
        HTML.errorPage(response, error_message);
    }

    void verifySignature(HttpServletRequest request,
            HttpServletResponse response, byte[] signed_json)
            throws IOException, ServletException, GeneralSecurityException {
        logger.info("JSON Signature Verification Entered");
        ReadSignature doc = new ReadSignature();
        JSONObjectReader parsed_json = JSONParser.parse(signed_json);
        doc.recurseObject(parsed_json);
        String prettySignature = parsed_json.serializeToString(JSONOutputFormats.PRETTY_HTML);
        Vector<String> tokens = new JSONTokenExtractor().getTokens(new String(signed_json, "utf-8"));
        int fromIndex = 0;
        for (String token : tokens) {
            int start = prettySignature.indexOf("<span ", fromIndex);
            int stop = prettySignature.indexOf("</span>", start);
            // <span style="color:#C00000">
            prettySignature = prettySignature.substring(0, start + 28) + token + prettySignature.substring(stop);
            fromIndex = start + 1;
        }
        HTML.printResultPage(
                response,
            "<div class=\"header\"> Signature Successfully Validated</div>" +
            "<div style=\"margin-left:5%\">" +
              HTML.newLines2HTML(doc.getResult()) +
            "</div>" + 
            HTML.fancyBox("verify", prettySignature, "Signed JSON Object") +
            HTML.fancyBox("header", 
                          doc.jwsHeader.serializeToString(JSONOutputFormats.PRETTY_HTML),
                          "Decoded JWS Header") +
            HTML.fancyBox("canonicalized",
                          HTML.encode(new String(doc.canonicalizedData, "UTF-8")),
                          "Canonicalized JSON Data (with possible line breaks for display purposes only)"));
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        byte[] data = null;
        if (request.getContentType().startsWith(
                "application/x-www-form-urlencoded")) {
            data = Base64URL.decode(request.getParameter(JWS_CORE));
        } else {
            if (!request.getContentType().startsWith("application/json")) {
                error(response, "Request didn't have the proper mime-type: "
                        + request.getContentType());
                return;
            }
            data = ServletUtil.getData(request);
        }
        try {
            verifySignature(request, response, data);
        } catch (Exception e) {
            HTML.errorPage(response, e.getMessage());
            return;
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String json = request.getParameter(JWS_CORE);
        if (json == null) {
            error(response, "Request didn't contain a \"" + JWS_CORE
                    + "\" argment");
            return;
        }
        try {
            verifySignature(request, response, Base64URL.decode(json));
        } catch (IOException | GeneralSecurityException e) {
            HTML.errorPage(response, e.getMessage());
            return;
        }
    }
}
