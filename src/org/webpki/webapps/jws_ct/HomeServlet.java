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
package org.webpki.webapps.jws_ct;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HomeServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
            "<div class='header'>JSON Clear Text Signature</div>" +
            "<div style='padding-top:15pt'>This site permits testing and debugging " +
            "a scheme for \"Clear&nbsp;Text\" JSON signatures tentatively targeted for " +
            "publication as an <a href='" +
            "https://www.ietf.org/archive/id/draft-jordan-jws-ct-02.html" +
            "' target='_blank'>IETF RFC</a>. " +
            "For detailed technical information and " +
            "open source code, click on the JWS/CT logotype.</div>" +
            "<div style='display:flex;justify-content:center'><table>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='create'\" " +
            "title='Create JSON signatures'>" +
            "Create JSON Signatures" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='validate'\" " +
            "title='Validate JSON signatures'>" +
            "Validate JSON Signatures" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='webcrypto'\" " +
            "title='&quot;Experimental&quot; - WebCrypto'>" +
            "&quot;Experimental&quot; - WebCrypto" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='hash'\" " +
            "title='Canonicalize and Hash JSON'>" +
            "Canonicalize and Hash JSON" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='keyconv'\" " +
            "title='Convert JWK &lt;-&gt; PEM keys'>" +
            "Convert JWK &lt;-&gt; PEM Keys" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='dumpasn1'\" " +
            "title='Dump PEM as ASN.1'>" +
            "Dump PEM as ASN.1" +
            "</div></td></tr>" +   
            "</table></div>" +
            "<div class='sitefooter'>Privacy/security notice: No user provided data is " +
            "ever stored or logged on the server; it only processes the data and returns the " +
            "result.</div>"));
    }
}
