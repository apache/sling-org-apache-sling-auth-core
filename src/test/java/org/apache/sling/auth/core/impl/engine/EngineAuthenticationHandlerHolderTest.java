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

import javax.jcr.Credentials;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import junitx.util.PrivateAccessor;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.JakartaAuthenticationFeedbackHandler;
import org.apache.sling.engine.auth.AuthenticationHandler;
import org.junit.Test;
import org.osgi.framework.ServiceReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("deprecation")
public class EngineAuthenticationHandlerHolderTest {

    private static final String PATH = "/content";

    private interface FeedbackEngineHandler extends AuthenticationHandler, AuthenticationFeedbackHandler {}

    @Test
    public void extractCredentialsReturnsNullWhenEngineHandlerReturnsNull() {
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);
        final EngineAuthenticationHandlerHolder holder = holder(handler);

        assertNull(holder.doExtractCredentials(mock(HttpServletRequest.class), mock(HttpServletResponse.class)));
    }

    @Test
    public void extractCredentialsConvertsDoingAuthSingleton() {
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);
        final EngineAuthenticationHandlerHolder holder = holder(handler);
        when(handler.authenticate(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class)))
                .thenReturn(org.apache.sling.engine.auth.AuthenticationInfo.DOING_AUTH);

        assertSame(
                AuthenticationInfo.DOING_AUTH,
                holder.doExtractCredentials(mock(HttpServletRequest.class), mock(HttpServletResponse.class)));
    }

    @Test
    public void extractCredentialsConvertsLegacyAuthenticationInfo() {
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);
        final EngineAuthenticationHandlerHolder holder = holder(handler);
        final Credentials credentials = mock(Credentials.class);
        final org.apache.sling.engine.auth.AuthenticationInfo engineInfo =
                new org.apache.sling.engine.auth.AuthenticationInfo("engine", credentials, "workspace");
        when(handler.authenticate(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class)))
                .thenReturn(engineInfo);

        final AuthenticationInfo info =
                holder.doExtractCredentials(mock(HttpServletRequest.class), mock(HttpServletResponse.class));

        assertEquals("engine", info.getAuthType());
        assertSame(credentials, info.get("user.jcr.credentials"));
        assertEquals("workspace", info.get("user.jcr.workspace"));
    }

    @Test
    public void requestCredentialsDelegatesToLegacyHandler() throws IOException {
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);
        final EngineAuthenticationHandlerHolder holder = holder(handler);
        when(handler.requestAuthentication(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class)))
                .thenReturn(true);

        assertTrue(holder.doRequestCredentials(mock(HttpServletRequest.class), mock(HttpServletResponse.class)));

        verify(handler)
                .requestAuthentication(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class));
    }

    @Test
    public void dropCredentialsDoesNotCallLegacyHandler() throws Throwable {
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);

        holder(handler).doDropCredentials(mock(HttpServletRequest.class), mock(HttpServletResponse.class));

        verify(handler, never())
                .authenticate(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class));
        verify(handler, never())
                .requestAuthentication(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class));
    }

    @Test
    public void getFeedbackHandlerReturnsNullForPlainEngineHandler() throws Throwable {
        assertNull(getFeedbackHandler(holder(mock(AuthenticationHandler.class))));
    }

    @Test
    public void feedbackHandlerAdaptsJakartaCallsToLegacyFeedbackHandler() throws Throwable {
        final FeedbackEngineHandler handler = mock(FeedbackEngineHandler.class);
        final JakartaAuthenticationFeedbackHandler feedbackHandler = getFeedbackHandler(holder(handler));
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final AuthenticationInfo authInfo = new AuthenticationInfo("engine");
        when(handler.authenticationSucceeded(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class),
                        same(authInfo)))
                .thenReturn(true);

        assertNotNull(feedbackHandler);
        feedbackHandler.authenticationFailed(request, response, authInfo);
        assertTrue(feedbackHandler.authenticationSucceeded(request, response, authInfo));

        verify(handler)
                .authenticationFailed(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class),
                        same(authInfo));
        verify(handler)
                .authenticationSucceeded(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class),
                        same(authInfo));
    }

    @Test
    public void finalMethodsSetAndResetPathAroundEngineDelegation() {
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);
        final EngineAuthenticationHandlerHolder holder = holder(handler);
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getAttribute(org.apache.sling.auth.core.spi.JakartaAuthenticationHandler.PATH_PROPERTY))
                .thenReturn("oldPath");

        holder.extractCredentials(request, response);

        verify(request).setAttribute(org.apache.sling.auth.core.spi.JakartaAuthenticationHandler.PATH_PROPERTY, PATH);
        verify(request)
                .setAttribute(org.apache.sling.auth.core.spi.JakartaAuthenticationHandler.PATH_PROPERTY, "oldPath");
    }

    @Test
    public void equalsHashCodeCompareToAndToStringIncludeEngineHandler() {
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);
        when(handler.toString()).thenReturn("engineHandler");
        final ServiceReference<?> reference = mock(ServiceReference.class);
        final EngineAuthenticationHandlerHolder holder =
                new EngineAuthenticationHandlerHolder(PATH, handler, reference);
        final EngineAuthenticationHandlerHolder same = new EngineAuthenticationHandlerHolder(PATH, handler, reference);
        final EngineAuthenticationHandlerHolder differentHandler =
                new EngineAuthenticationHandlerHolder(PATH, mock(AuthenticationHandler.class), reference);

        assertEquals(holder, holder);
        assertEquals(holder, same);
        assertEquals(holder.hashCode(), same.hashCode());
        assertEquals(0, holder.compareTo(same));
        assertNotEquals(holder, null);
        assertNotEquals(holder, differentHandler);
        assertFalse(holder.equals(new Object()));
        assertEquals("engineHandler (Legacy API Handler)", holder.toString());
    }

    private EngineAuthenticationHandlerHolder holder(final AuthenticationHandler handler) {
        return new EngineAuthenticationHandlerHolder(PATH, handler, mock(ServiceReference.class));
    }

    private JakartaAuthenticationFeedbackHandler getFeedbackHandler(final EngineAuthenticationHandlerHolder holder)
            throws Throwable {
        return (JakartaAuthenticationFeedbackHandler)
                PrivateAccessor.invoke(holder, "getFeedbackHandler", new Class[0], new Object[0]);
    }
}
