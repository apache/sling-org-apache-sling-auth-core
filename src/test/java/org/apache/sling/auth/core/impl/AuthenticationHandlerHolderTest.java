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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.JakartaAuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.JakartaAuthenticationHandler;
import org.junit.Test;
import org.mockito.InOrder;
import org.osgi.framework.ServiceReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthenticationHandlerHolderTest {

    private static final String PATH = "/content";

    private interface FeedbackHandler extends JakartaAuthenticationHandler, JakartaAuthenticationFeedbackHandler {}

    @SuppressWarnings("deprecation")
    private interface LegacyFeedbackHandler
            extends org.apache.sling.auth.core.spi.AuthenticationHandler,
                    org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler {}

    @Test
    public void extractCredentialsSetsAndRestoresExistingPath() {
        final JakartaAuthenticationHandler handler = mock(JakartaAuthenticationHandler.class);
        final AuthenticationHandlerHolder holder = holder(handler, "form", null);
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final AuthenticationInfo authInfo = new AuthenticationInfo("form");
        when(request.getAttribute(JakartaAuthenticationHandler.PATH_PROPERTY)).thenReturn("oldPath");
        when(handler.extractCredentials(request, response)).thenReturn(authInfo);

        assertSame(authInfo, holder.extractCredentials(request, response));

        final InOrder order = inOrder(request, handler);
        order.verify(request).getAttribute(JakartaAuthenticationHandler.PATH_PROPERTY);
        order.verify(request).setAttribute(JakartaAuthenticationHandler.PATH_PROPERTY, PATH);
        order.verify(handler).extractCredentials(request, response);
        order.verify(request).setAttribute(JakartaAuthenticationHandler.PATH_PROPERTY, "oldPath");
    }

    @Test
    public void dropCredentialsRemovesPathWhenNoPreviousPathExists() throws IOException {
        final JakartaAuthenticationHandler handler = mock(JakartaAuthenticationHandler.class);
        final AuthenticationHandlerHolder holder = holder(handler, "form", null);
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);

        holder.dropCredentials(request, response);

        final InOrder order = inOrder(request, handler);
        order.verify(request).setAttribute(JakartaAuthenticationHandler.PATH_PROPERTY, PATH);
        order.verify(handler).dropCredentials(request, response);
        order.verify(request).removeAttribute(JakartaAuthenticationHandler.PATH_PROPERTY);
    }

    @Test
    public void requestCredentialsDelegatesWhenRequestedLoginMatchesAuthType() throws IOException {
        final JakartaAuthenticationHandler handler = mock(JakartaAuthenticationHandler.class);
        final AuthenticationHandlerHolder holder = holder(handler, "form", null);
        final HttpServletRequest request = requestWithLogin(null, "form");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(handler.requestCredentials(request, response)).thenReturn(true);

        assertTrue(holder.requestCredentials(request, response));

        verify(handler).requestCredentials(request, response);
        verify(request).removeAttribute(JakartaAuthenticationHandler.PATH_PROPERTY);
    }

    @Test
    public void requestCredentialsSkipsWhenRequestedLoginDoesNotMatchAuthType() throws IOException {
        final JakartaAuthenticationHandler handler = mock(JakartaAuthenticationHandler.class);
        final AuthenticationHandlerHolder holder = holder(handler, "form", null);
        final HttpServletRequest request = requestWithLogin(null, "basic");

        assertFalse(holder.requestCredentials(request, mock(HttpServletResponse.class)));

        verify(handler, never()).requestCredentials(any(HttpServletRequest.class), any(HttpServletResponse.class));
        verify(request).removeAttribute(JakartaAuthenticationHandler.PATH_PROPERTY);
    }

    @Test
    public void requestCredentialsUsesLoginAttributeBeforeParameter() throws IOException {
        final JakartaAuthenticationHandler handler = mock(JakartaAuthenticationHandler.class);
        final AuthenticationHandlerHolder holder = holder(handler, "form", null);
        final HttpServletRequest request = requestWithLogin("form", "basic");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(handler.requestCredentials(request, response)).thenReturn(true);

        assertTrue(holder.requestCredentials(request, response));

        verify(handler).requestCredentials(request, response);
    }

    @Test
    public void requestCredentialsWithoutAuthTypeIgnoresRequestedLogin() throws IOException {
        final JakartaAuthenticationHandler handler = mock(JakartaAuthenticationHandler.class);
        final AuthenticationHandlerHolder holder = holder(handler, null, null);
        final HttpServletRequest request = requestWithLogin(null, "basic");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(handler.requestCredentials(request, response)).thenReturn(true);

        assertTrue(holder.requestCredentials(request, response));

        verify(handler).requestCredentials(request, response);
    }

    @Test
    public void browserOnlyRequestCredentialsSkipsNonBrowserRequests() throws IOException {
        final JakartaAuthenticationHandler handler = mock(JakartaAuthenticationHandler.class);
        final AuthenticationHandlerHolder holder = holder(handler, "form", "true");
        final HttpServletRequest request = requestWithLogin(null, null);
        when(request.getHeader("User-Agent")).thenReturn("curl/8.0");

        assertFalse(holder.requestCredentials(request, mock(HttpServletResponse.class)));

        verify(handler, never()).requestCredentials(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void browserOnlyRequestCredentialsAllowsBrowserRequestsForYesValue() throws IOException {
        final JakartaAuthenticationHandler handler = mock(JakartaAuthenticationHandler.class);
        final AuthenticationHandlerHolder holder = holder(handler, "form", "yes");
        final HttpServletRequest request = requestWithLogin(null, null);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        when(handler.requestCredentials(request, response)).thenReturn(true);

        assertTrue(holder.requestCredentials(request, response));

        verify(handler).requestCredentials(request, response);
    }

    @Test
    public void getFeedbackHandlerReturnsJakartaFeedbackHandlerOnlyWhenImplemented() {
        final FeedbackHandler feedbackHandler = mock(FeedbackHandler.class);
        assertSame(feedbackHandler, holder(feedbackHandler, "form", null).getFeedbackHandler());
        assertNull(
                holder(mock(JakartaAuthenticationHandler.class), "form", null).getFeedbackHandler());
    }

    @Test
    @SuppressWarnings("deprecation")
    public void legacyConstructorWrapsDeprecatedAuthenticationHandler() {
        final org.apache.sling.auth.core.spi.AuthenticationHandler handler = mock(LegacyFeedbackHandler.class);
        final AuthenticationHandlerHolder holder =
                new AuthenticationHandlerHolder(PATH, handler, serviceReference("legacy", null));
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final AuthenticationInfo authInfo = new AuthenticationInfo("legacy");
        when(handler.extractCredentials(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class)))
                .thenReturn(authInfo);

        assertSame(authInfo, holder.extractCredentials(request, response));
    }

    @Test
    public void equalsHashCodeCompareToAndToStringIncludeHolderState() {
        final JakartaAuthenticationHandler handler = mock(JakartaAuthenticationHandler.class);
        when(handler.toString()).thenReturn("handlerString");
        final ServiceReference<?> serviceReference = serviceReference("form", null);
        final AuthenticationHandlerHolder holder = new AuthenticationHandlerHolder(PATH, handler, serviceReference);
        final AuthenticationHandlerHolder same = new AuthenticationHandlerHolder(PATH, handler, serviceReference);
        final AuthenticationHandlerHolder differentHandler =
                new AuthenticationHandlerHolder(PATH, mock(JakartaAuthenticationHandler.class), serviceReference);
        final AuthenticationHandlerHolder differentType =
                new AuthenticationHandlerHolder(PATH, handler, serviceReference("basic", null));
        final AuthenticationHandlerHolder differentBrowserOnly =
                new AuthenticationHandlerHolder(PATH, handler, serviceReference("form", "true"));

        assertEquals(holder, holder);
        assertEquals(holder, same);
        assertEquals(holder.hashCode(), same.hashCode());
        assertEquals(0, holder.compareTo(same));
        assertNotEquals(holder, null);
        assertNotEquals(holder, differentHandler);
        assertNotEquals(holder, differentType);
        assertNotEquals(holder, differentBrowserOnly);
        assertEquals("handlerString", holder.toString());
        assertTrue(holder.isPathRequiresHandler("/content/page"));
    }

    private AuthenticationHandlerHolder holder(
            final JakartaAuthenticationHandler handler, final String authType, final String browserOnly) {
        return new AuthenticationHandlerHolder(PATH, handler, serviceReference(authType, browserOnly));
    }

    private HttpServletRequest requestWithLogin(final String attributeValue, final String parameterValue) {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getAttribute(JakartaAuthenticationHandler.REQUEST_LOGIN_PARAMETER))
                .thenReturn(attributeValue);
        when(request.getParameter(JakartaAuthenticationHandler.REQUEST_LOGIN_PARAMETER))
                .thenReturn(parameterValue);
        return request;
    }

    private ServiceReference<?> serviceReference(final String authType, final String browserOnly) {
        final ServiceReference<?> serviceReference = mock(ServiceReference.class);
        when(serviceReference.getProperty(JakartaAuthenticationHandler.TYPE_PROPERTY))
                .thenReturn(authType);
        when(serviceReference.getProperty(AuthConstants.AUTH_HANDLER_BROWSER_ONLY))
                .thenReturn(browserOnly);
        return serviceReference;
    }
}
