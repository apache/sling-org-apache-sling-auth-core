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
import java.io.UnsupportedEncodingException;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestEvent;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import junitx.util.PrivateAccessor;
import org.apache.sling.api.SlingJakartaHttpServletRequest;
import org.apache.sling.api.SlingJakartaHttpServletResponse;
import org.apache.sling.api.auth.NoAuthenticationHandlerException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.JakartaAuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.JakartaAuthenticationHandler;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SlingAuthenticatorTest {

    /**
     * Helper method to create a default configuration
     */
    public static SlingAuthenticator.Config createDefaultConfig() {
        final SlingAuthenticator.Config config = mock(SlingAuthenticator.Config.class);

        when(config.auth_sudo_cookie()).thenReturn("sling.sudo");
        when(config.auth_sudo_parameter()).thenReturn("sudo");
        when(config.auth_annonymous()).thenReturn(true);
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_PREEMPTIVE);
        when(config.auth_http_realm()).thenReturn("Sling (Development)");
        when(config.auth_uri_suffix()).thenReturn(new String[] {SlingAuthenticator.DEFAULT_AUTH_URI_SUFFIX});

        return config;
    }

    private SlingAuthenticator createSlingAuthenticator() {
        return createSlingAuthenticator(createDefaultConfig());
    }

    public SlingAuthenticator createSlingAuthenticator(final String... typeAndPathPairs) {
        return createSlingAuthenticator(createDefaultConfig(), typeAndPathPairs);
    }

    private static final long BUNDLE_ID = 732;

    private BundleContext createBundleContext() {
        final BundleContext context = mock(BundleContext.class);
        final Bundle bundle = mock(Bundle.class);
        when(bundle.getBundleId()).thenReturn(BUNDLE_ID);
        when(context.getBundle()).thenReturn(bundle);
        return context;
    }

    private SlingAuthenticator createSlingAuthenticator(
            final SlingAuthenticator.Config config, final String... typeAndPathPairs) {
        final AuthenticationRequirementsManager requirements =
                new AuthenticationRequirementsManager(createBundleContext(), null, config, Runnable::run);
        final AuthenticationHandlersManager handlers = new AuthenticationHandlersManager(config);
        if (typeAndPathPairs != null) {
            int i = 0;
            while (i < typeAndPathPairs.length) {
                handlers.addHolder(buildAuthHolderForAuthTypeAndPath(typeAndPathPairs[i], typeAndPathPairs[i + 1]));
                i += 2;
            }
        }
        return new SlingAuthenticator(requirements, handlers, null, mock(BundleContext.class), config);
    }

    @Test
    public void test_quoteCookieValue() throws UnsupportedEncodingException {

        try {
            SlingAuthenticator.quoteCookieValue(null);
            Assert.fail("Expected IllegalArgumentExcepion on null value");
        } catch (IllegalArgumentException iae) {
            // expected
        }

        checkQuote("\"", "\"\\\"\"");
        checkQuote("simplevalue", "\"simplevalue\"");
        checkQuote("simple value", "\"simple+value\"");
        checkQuote("email@address.com", "\"email@address.com\"");

        checkQuote("string\ttab", "\"string%09tab\"");
        checkQuote("test中文", "\"test%E4%B8%AD%E6%96%87\"");

        try {
            SlingAuthenticator.quoteCookieValue("string\rCR");
            Assert.fail("Expected IllegalArgumentExcepion on value containing CR");
        } catch (IllegalArgumentException iae) {
            // expected
        }
    }

    @Test
    public void test_unquoteCookieValue() {

        Assert.assertNull(SlingAuthenticator.unquoteCookieValue(null));
        Assert.assertEquals("", SlingAuthenticator.unquoteCookieValue(""));

        checkUnQuote("unquoted", "unquoted");
        checkUnQuote("unquoted\"", "unquoted\"");
        checkUnQuote("un\"quoted", "un\"quoted");

        checkUnQuote("\"\\\"\"", "\"");
        checkUnQuote("\"simplevalue\"", "simplevalue");
        checkUnQuote("\"simple value\"", "simple value");
        checkUnQuote("\"email@address.com\"", "email@address.com");

        checkUnQuote("\"string\ttab\"", "string\ttab");
    }

    // SLING-4864
    @Test
    public void test_isAnonAllowed() throws Throwable {
        // anon is allowed by default
        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator();

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(80);
        when(request.getScheme()).thenReturn("http");

        Assert.assertTrue(slingAuthenticator.isAnonAllowed(request));
    }

    @Test
    public void test_isAnonNotAllowed() throws Throwable {
        // anon is allowed by default
        final SlingAuthenticator.Config config = createDefaultConfig();
        when(config.auth_annonymous()).thenReturn(false);

        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator(config);

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(80);
        when(request.getScheme()).thenReturn("http");

        Assert.assertFalse(slingAuthenticator.isAnonAllowed(request));
    }

    private void assertAuthInfo(String protectedPath, String requestChildNode) throws Throwable {
        final String authType = "AUTH_TYPE_TEST";
        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator(authType, protectedPath);

        final HttpServletRequest request = mock(HttpServletRequest.class);
        buildExpectationsForRequest(request, requestChildNode);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(
                slingAuthenticator,
                "getAuthenticationInfo",
                new Class[] {HttpServletRequest.class, HttpServletResponse.class},
                new Object[] {request, mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined above should be used for the path /test and his children: eg /test/childnode.
         */
        Assert.assertEquals(authType, authInfo.getAuthType());
    }

    /**
     * Test is OK for child node;
     * @throws Throwable
     */
    @Test
    public void test_childNodeShouldHaveAuthenticationInfo() throws Throwable {
        assertAuthInfo("/content/en/test", "/content/en/test/childnodetest");
    }

    /**
     * Test is OK for same node;
     * @throws Throwable
     */
    @Test
    public void test_childNodeShouldHaveAuthenticationInfo2() throws Throwable {
        assertAuthInfo("/content/en/test", "/content/en/test");
    }

    /**
     * Test is OK for same node with ending slash;
     * @throws Throwable
     */
    @Test
    public void test_childNodeShouldHaveAuthenticationInfo3() throws Throwable {
        assertAuthInfo("/content/en/test", "/content/en/test/");
    }

    /**
     * Test is OK for same node with extension
     * @throws Throwable
     */
    @Test
    public void test_childNodeShouldHaveAuthenticationInfo4() throws Throwable {
        assertAuthInfo("/content/en/test", "/content/en/test.html");
    }

    @Test
    public void test_childNodeShouldHaveAuthenticationInfoRoot() throws Throwable {
        assertAuthInfo("/", "/content/en/test");
    }

    @Test
    public void test_childNodeShouldHaveAuthenticationInfoLonger() throws Throwable {
        final String AUTH_TYPE = "AUTH_TYPE_TEST";
        final String AUTH_TYPE_LONGER = "AUTH_TYPE_LONGER_TEST";
        final String PROTECTED_PATH = "/resource1";
        final String PROTECTED_PATH_LONGER = "/resource1.test2";
        final String REQUEST_CHILD_NODE = "/resource1.test2";

        final SlingAuthenticator slingAuthenticator =
                this.createSlingAuthenticator(AUTH_TYPE, PROTECTED_PATH, AUTH_TYPE_LONGER, PROTECTED_PATH_LONGER);

        final HttpServletRequest request = mock(HttpServletRequest.class);
        buildExpectationsForRequest(request, REQUEST_CHILD_NODE);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(
                slingAuthenticator,
                "getAuthenticationInfo",
                new Class[] {HttpServletRequest.class, HttpServletResponse.class},
                new Object[] {request, mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined aboved should  be used for the path /test and his children: eg /test/childnode.
         */
        Assert.assertEquals(AUTH_TYPE_LONGER, authInfo.getAuthType());
    }

    /**
     * JIRA: SLING-6053
     * Issue can be reproduced with the following steps:
     *
     * Create node "/page"
     * Create sibling node "/page1"
     * Define an auth handler for node: "/page"
     *
     * Expected: "/page" has AuthenticationInfo
     *           "/page1" does not have AuthenticationInfo (has anonymous)
     *
     * Actual:  "/page" & "page1" are both having AuthenticationInfo
     *
     *
     * @throws Throwable
     */
    @Test
    public void test_siblingNodeShouldNotHaveAuthenticationInfo() throws Throwable {
        final String AUTH_TYPE = "AUTH_TYPE_TEST";
        final String PROTECTED_PATH = "/content/en/test";
        final String REQUEST_NOT_PROTECTED_PATH = "/content/en/test2";

        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator(AUTH_TYPE, PROTECTED_PATH);

        final HttpServletRequest request = mock(HttpServletRequest.class);
        buildExpectationsForRequest(request, REQUEST_NOT_PROTECTED_PATH);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(
                slingAuthenticator,
                "getAuthenticationInfo",
                new Class[] {HttpServletRequest.class, HttpServletResponse.class},
                new Object[] {request, mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined aboved should not be used for the path /test2.
         */
        Assert.assertNotEquals(AUTH_TYPE, authInfo.getAuthType());
    }

    @Test
    public void testServletRequestListener() {
        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator();
        final ServletRequestEvent event = mock(ServletRequestEvent.class);
        final ServletRequest request = mock(ServletRequest.class);
        when(event.getServletRequest()).thenReturn(request);

        slingAuthenticator.requestInitialized(event);

        final ResourceResolver resolver = mock(ResourceResolver.class);
        when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);

        slingAuthenticator.requestDestroyed(event);
        // verify resolver close, attribute removed
        verify(resolver).close();
        verify(request).removeAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER);
    }

    @Test
    public void testSetSudoCookieNoSudoBeforeNoSudoAfter() {
        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator();
        final AuthenticationInfo info = new AuthenticationInfo("basic");

        final SlingJakartaHttpServletRequest req = mock(SlingJakartaHttpServletRequest.class);
        final SlingJakartaHttpServletResponse res = mock(SlingJakartaHttpServletResponse.class);

        assertFalse(slingAuthenticator.setSudoCookie(req, res, info));
        verify(res, never()).addCookie(any());
    }

    @Test
    public void testSetSudoCookieNoSudoBeforeSudoAfter() {
        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator();
        final AuthenticationInfo info = new AuthenticationInfo("basic");
        info.put(ResourceResolverFactory.USER_IMPERSONATION, "newsudo");

        final SlingJakartaHttpServletRequest req = mock(SlingJakartaHttpServletRequest.class);
        final SlingJakartaHttpServletResponse res = mock(SlingJakartaHttpServletResponse.class);

        assertTrue(slingAuthenticator.setSudoCookie(req, res, info));
        ArgumentCaptor<Cookie> argument = ArgumentCaptor.forClass(Cookie.class);
        verify(res).addCookie(argument.capture());
        assertEquals("\"newsudo\"", argument.getValue().getValue());
    }

    @Test
    public void testSetSudoCookieSudoBeforeSameSudoAfter() {
        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator();
        final AuthenticationInfo info = new AuthenticationInfo("basic");
        info.put(ResourceResolverFactory.USER_IMPERSONATION, "oldsudo");

        final SlingJakartaHttpServletRequest req = mock(SlingJakartaHttpServletRequest.class);
        final Cookie cookie = new Cookie("sling.sudo", "\"oldsudo\"");
        when(req.getCookies()).thenReturn(new Cookie[] {cookie});
        final SlingJakartaHttpServletResponse res = mock(SlingJakartaHttpServletResponse.class);

        assertFalse(slingAuthenticator.setSudoCookie(req, res, info));
        verify(res, never()).addCookie(any());
    }

    @Test
    public void testSetSudoCookieSudoBeforeNewSudoAfter() {
        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator();
        final AuthenticationInfo info = new AuthenticationInfo("basic");
        info.put(ResourceResolverFactory.USER_IMPERSONATION, "newsudo");

        final SlingJakartaHttpServletRequest req = mock(SlingJakartaHttpServletRequest.class);
        final Cookie cookie = new Cookie("sling.sudo", "\"oldsudo\"");
        when(req.getCookies()).thenReturn(new Cookie[] {cookie});
        final SlingJakartaHttpServletResponse res = mock(SlingJakartaHttpServletResponse.class);

        assertTrue(slingAuthenticator.setSudoCookie(req, res, info));
        ArgumentCaptor<Cookie> argument = ArgumentCaptor.forClass(Cookie.class);
        verify(res).addCookie(argument.capture());
        assertEquals("\"newsudo\"", argument.getValue().getValue());
    }

    @Test
    public void testSetSudoCookieSudoBeforeNoSudoAfter() {
        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator();
        final AuthenticationInfo info = new AuthenticationInfo("basic");

        final SlingJakartaHttpServletRequest req = mock(SlingJakartaHttpServletRequest.class);
        final Cookie cookie = new Cookie("sling.sudo", "\"oldsudo\"");
        when(req.getCookies()).thenReturn(new Cookie[] {cookie});
        final SlingJakartaHttpServletResponse res = mock(SlingJakartaHttpServletResponse.class);

        assertTrue(slingAuthenticator.setSudoCookie(req, res, info));
        ArgumentCaptor<Cookie> argument = ArgumentCaptor.forClass(Cookie.class);
        verify(res).addCookie(argument.capture());
        assertEquals("\"\"", argument.getValue().getValue());
    }

    @Test
    public void testSudoCookieFlags() {
        final SlingAuthenticator slingAuthenticator = this.createSlingAuthenticator();
        final AuthenticationInfo info = new AuthenticationInfo("basic");
        info.put(ResourceResolverFactory.USER_IMPERSONATION, "newsudo");

        final SlingJakartaHttpServletRequest req = mock(SlingJakartaHttpServletRequest.class);
        when(req.isSecure()).thenReturn(true);
        SlingJakartaHttpServletResponse res = mock(SlingJakartaHttpServletResponse.class);

        assertTrue(slingAuthenticator.setSudoCookie(req, res, info));
        ArgumentCaptor<Cookie> argument1 = ArgumentCaptor.forClass(Cookie.class);
        verify(res).addCookie(argument1.capture());
        assertTrue(argument1.getValue().isHttpOnly());
        assertTrue(argument1.getValue().getSecure());

        res = mock(SlingJakartaHttpServletResponse.class);
        when(req.isSecure()).thenReturn(false);
        assertTrue(slingAuthenticator.setSudoCookie(req, res, info));
        ArgumentCaptor<Cookie> argument2 = ArgumentCaptor.forClass(Cookie.class);
        verify(res).addCookie(argument2.capture());
        assertTrue(argument2.getValue().isHttpOnly());
        assertFalse(argument2.getValue().getSecure());
    }

    // ---------------------------- PRIVATE METHODS -----------------------------

    /**
     * Mocks the request to accept method calls on path;
     *
     * @param request http request
     * @param requestPath request path
     */
    private void buildExpectationsForRequest(final HttpServletRequest request, final String requestPath) {
        {
            when(request.getServletPath()).thenReturn(requestPath);
            when(request.getServerName()).thenReturn("localhost");
            when(request.getServerPort()).thenReturn(80);
            when(request.getScheme()).thenReturn("http");
        }
    }

    /**
     * Builds an auth handler for a specific path;
     * @param authType             name of the auth for this path
     * @param authProtectedPath    path protected by the auth handler
     * @return AbstractAuthenticationHandlerHolder with only an AuthenticationInfo
     */
    private AbstractAuthenticationHandlerHolder buildAuthHolderForAuthTypeAndPath(
            final String authType, final String authProtectedPath) {
        return new AbstractAuthenticationHandlerHolder(authProtectedPath, null) {

            @Override
            protected JakartaAuthenticationFeedbackHandler getFeedbackHandler() {
                return null;
            }

            @Override
            protected AuthenticationInfo doExtractCredentials(
                    HttpServletRequest request, HttpServletResponse response) {
                return new AuthenticationInfo(authType);
            }

            @Override
            protected boolean doRequestCredentials(HttpServletRequest request, HttpServletResponse response)
                    throws IOException {
                return false;
            }

            @Override
            protected void doDropCredentials(HttpServletRequest request, HttpServletResponse response)
                    throws IOException {
                // Intentionally empty: this test stub never needs to drop credentials.
            }
        };
    }

    private void checkQuote(final String value, final String expected) throws UnsupportedEncodingException {
        final String actual = SlingAuthenticator.quoteCookieValue(value);
        Assert.assertEquals(expected, actual);
    }

    private void checkUnQuote(final String value, final String expected) {
        final String actual = SlingAuthenticator.unquoteCookieValue(value);
        Assert.assertEquals(expected, actual);
    }

    class SimpleAuthHandler implements JakartaAuthenticationHandler {

        @Override
        public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
            throw new UnsupportedOperationException("Unimplemented method 'extractCredentials'");
        }

        @Override
        public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
            throw new UnsupportedOperationException("Unimplemented method 'requestCredentials'");
        }

        @Override
        public void dropCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
            throw new UnsupportedOperationException("Unimplemented method 'dropCredentials'");
        }
    }

    private SlingAuthenticator createAuthenticator(AbstractAuthenticationHandlerHolder... holders) {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        final AuthenticationRequirementsManager requirements =
                new AuthenticationRequirementsManager(createBundleContext(), null, config, Runnable::run);
        final AuthenticationHandlersManager handlers = new AuthenticationHandlersManager(config);
        for (AbstractAuthenticationHandlerHolder h : holders) {
            handlers.addHolder(h);
        }
        return new SlingAuthenticator(requirements, handlers, null, mock(BundleContext.class), config);
    }

    private SlingAuthenticator createAuthenticator(
            final ResourceResolverFactory rrf, final AbstractAuthenticationHandlerHolder... holders) {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        final AuthenticationRequirementsManager requirements =
                new AuthenticationRequirementsManager(createBundleContext(), null, config, Runnable::run);
        final AuthenticationHandlersManager handlers = new AuthenticationHandlersManager(config);
        for (AbstractAuthenticationHandlerHolder h : holders) {
            handlers.addHolder(h);
        }
        return new SlingAuthenticator(requirements, handlers, rrf, mock(BundleContext.class), config);
    }

    private AbstractAuthenticationHandlerHolder infoHolder(final String path, final AuthenticationInfo info) {
        return new AbstractAuthenticationHandlerHolder(path, null) {
            @Override
            protected JakartaAuthenticationFeedbackHandler getFeedbackHandler() {
                return null;
            }

            @Override
            protected AuthenticationInfo doExtractCredentials(
                    HttpServletRequest request, HttpServletResponse response) {
                return info;
            }

            @Override
            protected boolean doRequestCredentials(HttpServletRequest request, HttpServletResponse response)
                    throws IOException {
                return true;
            }

            @Override
            protected void doDropCredentials(HttpServletRequest request, HttpServletResponse response)
                    throws IOException {
                // Intentionally empty: this test stub never needs to drop credentials.
            }
        };
    }

    private AbstractAuthenticationHandlerHolder holder(
            final String path, final boolean requestResult, final boolean throwOnRequest) {
        return new AbstractAuthenticationHandlerHolder(path, null) {
            @Override
            protected JakartaAuthenticationFeedbackHandler getFeedbackHandler() {
                return null;
            }

            @Override
            protected AuthenticationInfo doExtractCredentials(
                    HttpServletRequest request, HttpServletResponse response) {
                return null;
            }

            @Override
            protected boolean doRequestCredentials(HttpServletRequest request, HttpServletResponse response)
                    throws IOException {
                if (throwOnRequest) {
                    throw new IOException("boom");
                }
                return requestResult;
            }

            @Override
            protected void doDropCredentials(HttpServletRequest request, HttpServletResponse response)
                    throws IOException {
                // Intentionally empty: this test stub never needs to drop credentials.
            }
        };
    }

    private HttpServletRequest requestFor(String path) {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn(path);
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(80);
        when(request.getScheme()).thenReturn("http");
        when(request.getContextPath()).thenReturn("");
        when(request.getRequestURI()).thenReturn(path);
        return request;
    }

    @Test
    public void test_login_success() {
        final SlingAuthenticator auth = createAuthenticator(holder("/", true, false));
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        auth.login(request, response);
        // login checks the commit state before delegating to a handler
        verify(response).isCommitted();
    }

    @Test
    public void test_login_handler_throws_is_treated_as_done() {
        final SlingAuthenticator auth = createAuthenticator(holder("/", false, true));
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        auth.login(request, response);
        // an IOException from the handler is treated as "done", so no exception escapes
        verify(response).isCommitted();
    }

    @Test(expected = NoAuthenticationHandlerException.class)
    public void test_login_no_handler() {
        final SlingAuthenticator auth = createAuthenticator(holder("/", false, false));
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        auth.login(request, response);
    }

    @Test(expected = IllegalStateException.class)
    public void test_login_response_committed() {
        final SlingAuthenticator auth = createAuthenticator(holder("/", true, false));
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.isCommitted()).thenReturn(true);
        auth.login(request, response);
    }

    @Test
    public void test_logout_success() {
        final SlingAuthenticator auth = createAuthenticator(holder("/", true, false));
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        auth.logout(request, response);
        // logout checks the commit state before dropping credentials
        verify(response, atLeastOnce()).isCommitted();
    }

    @Test(expected = IllegalStateException.class)
    public void test_logout_response_committed() {
        final SlingAuthenticator auth = createAuthenticator(holder("/", true, false));
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.isCommitted()).thenReturn(true);
        auth.logout(request, response);
    }

    @Test
    public void test_javax_login_wrapper() {
        final SlingAuthenticator auth = createAuthenticator(holder("/", true, false));
        final javax.servlet.http.HttpServletRequest request = mock(javax.servlet.http.HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("/content");
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(80);
        when(request.getScheme()).thenReturn("http");
        when(request.getContextPath()).thenReturn("");
        final javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        auth.login(request, response);
        // the javax wrapper delegates to the jakarta login, which checks the commit state
        verify(response).isCommitted();
    }

    @Test
    public void test_javax_logout_wrapper() {
        final SlingAuthenticator auth = createAuthenticator(holder("/", true, false));
        final javax.servlet.http.HttpServletRequest request = mock(javax.servlet.http.HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("/content");
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(80);
        when(request.getScheme()).thenReturn("http");
        when(request.getContextPath()).thenReturn("");
        final javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        auth.logout(request, response);
        // the javax wrapper delegates to the jakarta logout, which checks the commit state
        verify(response, atLeastOnce()).isCommitted();
    }

    @Test
    public void test_handleSecurity_already_authenticated() {
        final SlingAuthenticator auth = createAuthenticator();
        final HttpServletRequest request = requestFor("/content");
        final ResourceResolver resolver = mock(ResourceResolver.class);
        when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        Assert.assertTrue(auth.handleSecurity(request, response));
    }

    @Test
    public void test_handleSecurity_valid_credentials() throws Exception {
        final ResourceResolverFactory rrf = mock(ResourceResolverFactory.class);
        final ResourceResolver resolver = mock(ResourceResolver.class);
        when(rrf.getResourceResolver(any(java.util.Map.class))).thenReturn(resolver);

        final AuthenticationInfo info = new AuthenticationInfo("basic", "user", "pwd".toCharArray());
        final SlingAuthenticator auth = createAuthenticator(rrf, infoHolder("/", info));

        final HttpServletRequest request = requestFor("/content");
        // a non-resolver attribute should be overwritten
        when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn("not-a-resolver");
        final HttpServletResponse response = mock(HttpServletResponse.class);

        auth.handleSecurity(request, response);
        verify(request, atLeastOnce()).setAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER, resolver);
    }

    @Test
    public void test_handleSecurity_valid_credentials_with_redirect() throws Exception {
        final ResourceResolverFactory rrf = mock(ResourceResolverFactory.class);
        final ResourceResolver resolver = mock(ResourceResolver.class);
        when(rrf.getResourceResolver(any(java.util.Map.class))).thenReturn(resolver);

        final AuthenticationInfo info = new AuthenticationInfo("basic", "user", "pwd".toCharArray());
        final SlingAuthenticator auth = createAuthenticator(rrf, infoHolder("/", info));

        final HttpServletRequest request = requestFor("/content");
        when(request.getParameter(AuthenticationSupport.REDIRECT_PARAMETER)).thenReturn("/content/redirect");
        final HttpServletResponse response = mock(HttpServletResponse.class);

        // redirect requested -> request considered done, resolver closed
        Assert.assertFalse(auth.handleSecurity(request, response));
        verify(resolver).close();
    }

    @Test
    public void test_handleSecurity_doing_auth() {
        final SlingAuthenticator auth = createAuthenticator(infoHolder("/", AuthenticationInfo.DOING_AUTH));
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        Assert.assertFalse(auth.handleSecurity(request, response));
    }

    @Test
    public void test_handleSecurity_fail_auth_triggers_login() {
        final SlingAuthenticator auth = createAuthenticator(infoHolder("/", AuthenticationInfo.FAIL_AUTH));
        final HttpServletRequest request = requestFor("/content");
        when(request.getRequestURI()).thenReturn("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        Assert.assertFalse(auth.handleSecurity(request, response));
    }

    @Test
    public void test_finishSecurity_closes_resolver() {
        final SlingAuthenticator auth = createAuthenticator();
        final HttpServletRequest request = requestFor("/content");
        final ResourceResolver resolver = mock(ResourceResolver.class);
        when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        auth.finishSecurity(request, response);
        verify(resolver).close();
        verify(request).removeAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER);
    }

    @Test
    public void test_finishSecurity_no_resolver() {
        final SlingAuthenticator auth = createAuthenticator();
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        auth.finishSecurity(request, response);
        // with no resolver attribute present, nothing is closed or removed
        verify(request).getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER);
        verify(request, never()).removeAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER);
    }

    @Test
    public void test_javax_handleSecurity_wrapper() {
        final ResourceResolverFactory rrf = mock(ResourceResolverFactory.class);
        final ResourceResolver resolver = mock(ResourceResolver.class);
        try {
            when(rrf.getResourceResolver(any(java.util.Map.class))).thenReturn(resolver);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        final AuthenticationInfo info = new AuthenticationInfo("basic", "user", "pwd".toCharArray());
        final SlingAuthenticator auth = createAuthenticator(rrf, infoHolder("/", info));

        final javax.servlet.http.HttpServletRequest request = mock(javax.servlet.http.HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("/content");
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(80);
        when(request.getScheme()).thenReturn("http");
        when(request.getContextPath()).thenReturn("");
        when(request.getRequestURI()).thenReturn("/content");
        final javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        // valid credentials are supplied, so the javax wrapper authenticates successfully
        Assert.assertTrue(auth.handleSecurity(request, response));
    }

    @Test
    public void test_logout_dropCredentials_ioexception() {
        final AbstractAuthenticationHandlerHolder dropThrows = new AbstractAuthenticationHandlerHolder("/", null) {
            @Override
            protected JakartaAuthenticationFeedbackHandler getFeedbackHandler() {
                return null;
            }

            @Override
            protected AuthenticationInfo doExtractCredentials(
                    HttpServletRequest request, HttpServletResponse response) {
                return null;
            }

            @Override
            protected boolean doRequestCredentials(HttpServletRequest request, HttpServletResponse response)
                    throws IOException {
                return false;
            }

            @Override
            protected void doDropCredentials(HttpServletRequest request, HttpServletResponse response)
                    throws IOException {
                throw new IOException("boom");
            }
        };
        final SlingAuthenticator auth = createAuthenticator(dropThrows);
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        auth.logout(request, response);
        // an IOException while dropping credentials is caught, so logout still completes
        verify(response, atLeastOnce()).isCommitted();
    }

    private Object invokeHandleLoginFailure(
            SlingAuthenticator auth,
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationInfo info,
            Exception reason)
            throws Throwable {
        return junitx.util.PrivateAccessor.invoke(
                auth,
                "handleLoginFailure",
                new Class[] {
                    HttpServletRequest.class, HttpServletResponse.class, AuthenticationInfo.class, Exception.class
                },
                new Object[] {request, response, info, reason});
    }

    @Test
    public void test_handleLoginFailure_loginException_doLogin() throws Throwable {
        final SlingAuthenticator auth = createAuthenticator(holder("/", true, false));
        final HttpServletRequest request = requestFor("/content");
        when(request.getParameter(org.apache.sling.auth.core.AuthConstants.PAR_J_VALIDATE))
                .thenReturn("true");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final AuthenticationInfo info = new AuthenticationInfo("basic", "user");
        final Object result = invokeHandleLoginFailure(
                auth, request, response, info, new org.apache.sling.api.resource.LoginException("bad"));
        Assert.assertEquals(Boolean.FALSE, result);
    }

    @Test
    public void test_handleLoginFailure_tooManySessions() throws Throwable {
        final SlingAuthenticator auth = createAuthenticator();
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final AuthenticationInfo info = new AuthenticationInfo("basic", "user");
        invokeHandleLoginFailure(auth, request, response, info, new TooManySessionsException("too many"));
        verify(response).sendError(eq(503), anyString());
    }

    @Test
    public void test_handleLoginFailure_genericError() throws Throwable {
        final SlingAuthenticator auth = createAuthenticator();
        final HttpServletRequest request = requestFor("/content");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final AuthenticationInfo info = new AuthenticationInfo("basic", "user");
        invokeHandleLoginFailure(auth, request, response, info, new RuntimeException("kaboom"));
        verify(response).sendError(eq(500), anyString());
    }

    static class TooManySessionsException extends RuntimeException {
        TooManySessionsException(String msg) {
            super(msg);
        }
    }
}
