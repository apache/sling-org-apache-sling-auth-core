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
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.auth.core.AuthUtil;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.JakartaAuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.JakartaAuthenticationHandler;
import org.osgi.framework.ServiceReference;
import org.osgi.util.converter.Converters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The <code>AuthenticationHandlerHolder</code> class represents an
 * authentication handler service in the internal data structure of the
 * {@link SlingAuthenticator}.
 */
final class AuthenticationHandlerHolder extends AbstractAuthenticationHandlerHolder {

    // the actual authentication handler
    private final JakartaAuthenticationHandler handler;

    // the supported authentication type of the handler
    private final String authType;

    // whether requestCredentials only for browsers
    private final boolean browserOnlyRequestCredentials;

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    AuthenticationHandlerHolder(
            final String fullPath,
            final JakartaAuthenticationHandler handler,
            final ServiceReference<?> serviceReference) {
        super(fullPath, serviceReference);

        final String browserOnly = Converters.standardConverter()
                .convert(serviceReference.getProperty(AuthConstants.AUTH_HANDLER_BROWSER_ONLY))
                .to(String.class);

        // assign the fields
        this.handler = handler;
        this.authType = Converters.standardConverter()
                .convert(serviceReference.getProperty(JakartaAuthenticationHandler.TYPE_PROPERTY))
                .to(String.class);
        this.browserOnlyRequestCredentials =
                "true".equalsIgnoreCase(browserOnly) || "yes".equalsIgnoreCase(browserOnly);
    }

    AuthenticationHandlerHolder(
            final String fullPath,
            @SuppressWarnings("deprecation") final org.apache.sling.auth.core.spi.AuthenticationHandler handler,
            final ServiceReference<?> serviceReference) {
        this(fullPath, AuthenticationHandlerWrapper.wrap(handler), serviceReference);
    }

    @Override
    protected JakartaAuthenticationFeedbackHandler getFeedbackHandler() {
        if (handler instanceof JakartaAuthenticationFeedbackHandler) {
            return (JakartaAuthenticationFeedbackHandler) handler;
        }
        return null;
    }

    @Override
    public AuthenticationInfo doExtractCredentials(HttpServletRequest request, HttpServletResponse response) {
        this.logDebugMessage("doExtractCredentials", request);
        return handler.extractCredentials(request, response);
    }

    @Override
    public boolean doRequestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {

        // call handler if ok by its authentication type
        if (doesRequestCredentials(request)) {
            this.logDebugMessage("doRequestCredentials", request);
            return handler.requestCredentials(request, response);
        }

        // no credentials have been requested
        return false;
    }

    @Override
    public void doDropCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        this.logDebugMessage("doDropCredentials", request);
        handler.dropCredentials(request, response);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Objects.hash(authType, browserOnlyRequestCredentials, handler);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!super.equals(obj)) return false;
        if (getClass() != obj.getClass()) return false;
        AuthenticationHandlerHolder other = (AuthenticationHandlerHolder) obj;
        return Objects.equals(authType, other.authType)
                && browserOnlyRequestCredentials == other.browserOnlyRequestCredentials
                && Objects.equals(handler, other.handler);
    }

    @Override
    public String toString() {
        return handler.toString();
    }

    /**
     * Returns <code>true</code> if the <code>requestCredentials</code> method
     * of the held authentication handler should be called or not:
     * <ul>
     * <li>If the handler handles all clients or the request is assumed to be
     * coming from a browser</li>
     * <li>If the authentication handler is registered without an authentication
     * type</li>
     * <li>If the <code>sling:authRequestLogin</code> request parameter or
     * attribute is not set</li>
     * <li>If the <code>sling:authRequestLogin</code> is set to the same value
     * as the authentication type of the held authentication handler.</li>
     * <ul>
     * <p>
     * Otherwise <code>false</code> is returned and the
     * <code>requestCredentials</code> method is not called.
     *
     * @param request The request object providing the <code>
     *            sling:authRequestLogin</code> parameter
     * @return <code>true</code> if the <code>requestCredentials</code> method
     *         should be called.
     */
    private boolean doesRequestCredentials(final HttpServletRequest request) {

        if (browserOnlyRequestCredentials && !AuthUtil.isBrowserRequest(request)) {
            return false;
        }

        if (authType == null) {
            return true;
        }

        final String requestLogin = AuthUtil.getAttributeOrParameter(request, REQUEST_LOGIN_PARAMETER, null);
        return requestLogin == null || authType.equals(requestLogin);
    }

    private void logDebugMessage(String functionName, HttpServletRequest request) {
        if (logger.isDebugEnabled()) {
            String message =
                    functionName + ": Using AuthenticationHandler class {} to request credentials for request {} {}";
            logger.debug(message, handler, request.getMethod(), request.getRequestURL());
        }
    }
}
