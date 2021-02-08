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

import org.webpki.asn1.DerDecoder;

import org.webpki.util.Base64;

public class DumpASN1Servlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(DumpASN1Servlet.class.getName());

    // HTML form arguments
    static final String PEM_OBJECT        = "pem";

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }

            String pem = CreateServlet.getParameter(request, PEM_OBJECT);
            int i = pem.indexOf("-----BEGIN ");
            if (i != 0) {
                badPem();
            }
            i += 11;
            int j = pem.indexOf("-----", 8);
            if (j < 0) {
                badPem();
            }
            String objectType = pem.substring(i, j);
            int l = objectType.length();
            if (l > 20) {
                badPem();
            }
            i = pem.lastIndexOf("-----END " + objectType + "-----");
            if (i < 0) {
                badPem();
            }
            if (i != pem.length() - l - 14) {
                badPem();
            }
            byte[] asn1 = new Base64().getBinaryFromBase64String(
                    pem.substring(l + 17, pem.length() - 14 - l));
            StringBuilder html = new StringBuilder(
                    "<div class='header'>PEM Successfully Decoded</div>")
                .append(HTML.fancyCode("pem", 
                                        pem,
                                        "PEM object"))
                .append(HTML.fancyBox("asn.1", 
                                      "<code>" + 
                                        HTML.encode(DerDecoder.decode(asn1).toString(true, true), 
                                                    true).replace(" ", "&nbsp;") +
                                        "</code>", 
                                      "ASN.1 dump"));
            // Finally, print it out
            HTML.standardPage(response, null, html.append("<div style='padding:10pt'></div>"));
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
    
    private void badPem() throws IOException {
        throw new IOException("Unrecognized PEM");
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
                "<form name='shoot' method='POST' action='dumpasn1'>" +
                "<div class='header'>Dump PEM as ASN.1</div>")
            .append(HTML.fancyText(true,
                                   PEM_OBJECT,
                                   10, 
                                   JwsCtService.sampleKeyConversionKey,
                     "Paste a <i>single</i> PEM object or try with the default"))
            .append(
                "<div style='display:flex;justify-content:center'>" +
                "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
                "Dump PEM Object" +
                "</div>" +
                "</div>" +
                "</form>" +
                "<div>&nbsp;</div>"));
    }
}
