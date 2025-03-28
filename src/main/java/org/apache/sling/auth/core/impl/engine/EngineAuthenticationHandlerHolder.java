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
package org.apache.sling.auth.core.impl.engine;

import java.io.IOException;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.sling.api.wrappers.JakartaToJavaxRequestWrapper;
import org.apache.sling.api.wrappers.JakartaToJavaxResponseWrapper;
import org.apache.sling.auth.core.impl.AbstractAuthenticationHandlerHolder;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.JakartaAuthenticationFeedbackHandler;
import org.apache.sling.engine.auth.AuthenticationHandler;
import org.osgi.framework.ServiceReference;

/**
 * The <code>EngineAuthenticationHandlerHolder</code> class represents an
 * old-style Sling {@link AuthenticationHandler} service in the internal data
 * structure of the
 * {@link org.apache.sling.auth.core.impl.SlingAuthenticator}.
 */
@SuppressWarnings("deprecation")
public final class EngineAuthenticationHandlerHolder extends AbstractAuthenticationHandlerHolder {

    // the actual authentication handler
    private final AuthenticationHandler handler;

    public EngineAuthenticationHandlerHolder(
            final String fullPath, final AuthenticationHandler handler, final ServiceReference<?> serviceReference) {
        super(fullPath, serviceReference);
        this.handler = handler;
    }

    @Override
    protected JakartaAuthenticationFeedbackHandler getFeedbackHandler() {
        if (handler instanceof AuthenticationFeedbackHandler) {
            return new JakartaAuthenticationFeedbackHandler() {

                @Override
                public void authenticationFailed(
                        HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
                    ((AuthenticationFeedbackHandler) handler)
                            .authenticationFailed(
                                    JakartaToJavaxRequestWrapper.toJavaxRequest(request),
                                    JakartaToJavaxResponseWrapper.toJavaxResponse(response),
                                    authInfo);
                }

                @Override
                public boolean authenticationSucceeded(
                        HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
                    return ((AuthenticationFeedbackHandler) handler)
                            .authenticationSucceeded(
                                    JakartaToJavaxRequestWrapper.toJavaxRequest(request),
                                    JakartaToJavaxResponseWrapper.toJavaxResponse(response),
                                    authInfo);
                }
            };
        }
        return null;
    }

    public AuthenticationInfo doExtractCredentials(HttpServletRequest request, HttpServletResponse response) {

        org.apache.sling.engine.auth.AuthenticationInfo engineAuthInfo = handler.authenticate(
                JakartaToJavaxRequestWrapper.toJavaxRequest(request),
                JakartaToJavaxResponseWrapper.toJavaxResponse(response));
        if (engineAuthInfo == null) {
            return null;
        } else if (engineAuthInfo == org.apache.sling.engine.auth.AuthenticationInfo.DOING_AUTH) {
            return AuthenticationInfo.DOING_AUTH;
        }

        // backwards compatibility support for JCR credentials and workspace
        // name now encapsulated in the JCR Resource bundle
        AuthenticationInfo info = new AuthenticationInfo(engineAuthInfo.getAuthType());
        info.put("user.jcr.credentials", engineAuthInfo.getCredentials());
        info.put("user.jcr.workspace", engineAuthInfo.getWorkspaceName());

        return info;
    }

    public boolean doRequestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        return handler.requestAuthentication(
                JakartaToJavaxRequestWrapper.toJavaxRequest(request),
                JakartaToJavaxResponseWrapper.toJavaxResponse(response));
    }

    public void doDropCredentials(HttpServletRequest request, HttpServletResponse response) {
        // Engine AuthenticationHandler does not have this method
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Objects.hash(handler);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!super.equals(obj)) return false;
        if (getClass() != obj.getClass()) return false;
        EngineAuthenticationHandlerHolder other = (EngineAuthenticationHandlerHolder) obj;
        return Objects.equals(handler, other.handler);
    }

    @Override
    public String toString() {
        return handler.toString() + " (Legacy API Handler)";
    }
}
