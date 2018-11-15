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

import java.net.URLEncoder;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VerifyServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    static final String VFY_SIGNED_DATA    = "vsign";
    static final String VFY_VALIDATION_KEY = "vkey";

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
                "<form name=\"shoot\" method=\"POST\" action=\"verify\">" +
                "<div class=\"header\">Testing JSON Signatures</div>")
            .append(HTML.fancyText(true,
                VFY_SIGNED_DATA,
                10, 
                HTML.encode(JWSService.sampleSignature),
                "Paste a signed JSON object in the text box or try with the default"))
            .append(HTML.fancyText(true,
                VFY_VALIDATION_KEY,
                4, 
                HTML.encode(JWSService.sampleKey),
                "Validation key (secret key in hexadecimal or public key in PEM or &quot;plain&quot; JWK format)"))
            .append(
                "<div style=\"display:flex;justify-content:center\">" +
                "<div class=\"stdbtn\" onclick=\"document.forms.shoot.submit()\">" +
                "Verify JSON Signature" +
                "</div>" +
                "</div>" +
                "</form>" +
                "<div>&nbsp;</div>"));
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        request.getRequestDispatcher("request?" +
            RequestServlet.JWS_OBJECT +
            "=" +
            URLEncoder.encode(CreateServlet.getTextArea(request, VFY_SIGNED_DATA), "utf-8") + 
            "&" +
            RequestServlet.JWS_VALIDATION_KEY +
            "=" +
            URLEncoder.encode(CreateServlet.getTextArea(request, VFY_VALIDATION_KEY), "utf-8"))
                .forward(request, response);
    }
}
