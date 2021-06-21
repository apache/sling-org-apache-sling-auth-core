/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.core.impl;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.request.ResponseUtil;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.propertytypes.ServiceDescription;
import org.osgi.service.component.propertytypes.ServiceVendor;

@SuppressWarnings("serial")
@Component(service = Servlet.class,
    configurationPid = SlingAuthenticator.PID,
    property = {
            "felix.webconsole.label=" + AuthenticatorWebConsolePlugin.LABEL,
            "felix.webconsole.title=" + AuthenticatorWebConsolePlugin.TITLE,
            "felix.webconsole.category=Sling"
    })
@ServiceDescription("Apache Sling Request Authenticator WebConsole Plugin")
@ServiceVendor("The Apache Software Foundation")
public class AuthenticatorWebConsolePlugin extends HttpServlet {

    /** The label for the web console */
    public static final String LABEL = "slingauth";
    /** The title for the web console */
    public static final String TITLE = "Authenticator";

    @Reference(service = AuthenticationRequirementsManager.class)
    private PathBasedHolderCache<AuthenticationRequirementHolder> authenticationRequirementsManager; // NOSONAR

    @Reference
    private AuthenticationHandlersManager authenticationHoldersManager; // NOSONAR

    private final SlingAuthenticator.Config config;

    @Activate
    public AuthenticatorWebConsolePlugin(final SlingAuthenticator.Config config) {
        this.config = config;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        // only handle GET requests, ensure no error message for other requests
        if ("GET".equals(req.getMethod()) || "HEAD".equals(req.getMethod())) {
            super.service(req, resp);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        try {
            PrintWriter pw = resp.getWriter();

            pw.println("<table class='content' width='100%' cellspacing='0' cellpadding='0'>");

            printAuthenticationHandler(pw);

            pw.println("<tr><td colspan='2'>&nbsp;</td></tr>");

            printAuthenticationRequirements(pw);

            pw.println("<tr><td colspan='2'>&nbsp;</td></tr>");

            printAuthenticationConfiguration(pw);

            pw.println("</table>");
        } catch (IOException ioe) {
            log("Unexpected exception caught", ioe);
            try {
                resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            } catch (IOException ioe2) {
                log("Unexpected exception caught while sending the error", ioe2);
            }
        }
    }

    private void printAuthenticationHandler(final PrintWriter pw) {
        tr(pw);
        pw.println("<th class='content container' colspan='3'>Registered Authentication Handler</td>");
        endTr(pw);
        tr(pw);
        pw.println("<th class='content'>Path</td>");
        pw.println("<th class='content' colspan='2'>Handler</td>");
        endTr(pw);

        final Map<String, List<String>> handlerMap = authenticationHoldersManager.getAuthenticationHandlerMap();
        for (final Map.Entry<String, List<String>> handler : handlerMap.entrySet()) {
            final String path = handler.getKey();
            for (final String name : handler.getValue()) {
                pw.println("<tr class='content'>");
                td(pw, path);
                td(pw, name, 2);
                endTr(pw);
            }
        }
    }

    private void printAuthenticationRequirements(final PrintWriter pw) {
        tr(pw);
        pw.println("<th class='content container' colspan='3'>Authentication Requirement Configuration</td>");
        endTr(pw);
        tr(pw);
        pw.println("<th class='content'>Path</td>");
        pw.println("<th class='content'>Authentication Required</td>");
        pw.println("<th class='content'>Defining Service (Description or ID)</td>");
        endTr(pw);

        final List<AuthenticationRequirementHolder> holderList = authenticationRequirementsManager.getHolders();
        for (final AuthenticationRequirementHolder req : holderList) {

            pw.println("<tr class='content'>");
            td(pw, req.fullPath);
            td(pw, (req.requiresAuthentication() ? "Yes" : "No"));
            td(pw, req.getProvider());
            endTr(pw);

        }
    }

    private void printAuthenticationConfiguration(final PrintWriter pw) {
        final String anonUser = (this.config.sling_auth_anonymous_user() != null && this.config.sling_auth_anonymous_user().isEmpty()) ? this.config.sling_auth_anonymous_user() : "(default)";
        final String sudoCookie = this.config.auth_sudo_cookie();
        final String sudoParam = this.config.auth_sudo_parameter();

        tr(pw);
        pw.println("<th class='content container' colspan='3'>Miscellaneous Configuration</td>");
        endTr(pw);
        endTr(pw);
        tr(pw);
        pw.println("<td class='content'>Impersonation Cookie</td>");
        td(pw, sudoCookie, 2);
        endTr(pw);
        tr(pw);
        pw.println("<td class='content'>Impersonation Parameter</td>");
        td(pw, sudoParam, 2);
        endTr(pw);
        tr(pw);
        pw.println("<td class='content'>Anonymous User Name</td>");
        td(pw, anonUser, 2);
        endTr(pw);
    }

    private void td(final PrintWriter pw, String content) {
        td(pw, content, -1);
    }
    private void td(final PrintWriter pw, String content, int colspan) {
        if (colspan > 1) {
            pw.printf("<td class='content' colspan='%d'>%s</td>%n", colspan, ResponseUtil.escapeXml(content));
        } else {
            pw.printf("<td class='content'>%s</td>%n", ResponseUtil.escapeXml(content));
        }
    }

    private void tr(final PrintWriter pw) {
        pw.println("<tr>");
    }

    private void endTr(final PrintWriter pw) {
        pw.println("</tr>");
    }

}
