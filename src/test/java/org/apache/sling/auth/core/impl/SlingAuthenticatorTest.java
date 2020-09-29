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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.resource.mapping.PathToUriMappingService;
import org.apache.sling.api.resource.mapping.PathToUriMappingService.Result;
import org.apache.sling.api.uri.SlingUriBuilder;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import junitx.util.PrivateAccessor;

@RunWith(MockitoJUnitRunner.class)
public class SlingAuthenticatorTest {

    @InjectMocks
    SlingAuthenticator slingAuthenticator = new SlingAuthenticator();

    @Mock
    PathToUriMappingService pathToUriMappingService;

    @Mock
    HttpServletRequest request;

    @Mock
    PathToUriMappingService.Result resolveResult;

    @Before
    public void setup() {
        when(pathToUriMappingService.resolve(request, null)).thenReturn(resolveResult);
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

    //SLING-4864
    @Test
    public void  test_isAnonAllowed() throws Throwable {

        when(resolveResult.getUri()).thenReturn(SlingUriBuilder.parse("/", null).build());

        PathBasedHolderCache<AuthenticationRequirementHolder> authRequiredCache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        authRequiredCache.addHolder(new AuthenticationRequirementHolder("/", false, null));

        PrivateAccessor.setField(slingAuthenticator, "authRequiredCache", authRequiredCache);
        Mockito.when(request.getServerName()).thenReturn("localhost");
        Mockito.when(request.getServerPort()).thenReturn(80);
        Mockito.when(request.getScheme()).thenReturn("http");

        Boolean allowed = (Boolean) PrivateAccessor.invoke(slingAuthenticator,"isAnonAllowed",  new Class[]{HttpServletRequest.class},new Object[]{request});
        Assert.assertTrue(allowed);
    }


    /**
     * Test is OK for child node;
     * @throws Throwable
     */
    @Test
    public void test_childNodeShouldHaveAuthenticationInfo() throws Throwable {
        final String AUTH_TYPE = "AUTH_TYPE_TEST";
        final String PROTECTED_PATH = "/content/en/test";
        final String REQUEST_CHILD_NODE = "/content/en/test/childnodetest";

        PathBasedHolderCache<AbstractAuthenticationHandlerHolder> authRequiredCache = new PathBasedHolderCache<AbstractAuthenticationHandlerHolder>();
        authRequiredCache.addHolder(buildAuthHolderForAuthTypeAndPath(AUTH_TYPE, PROTECTED_PATH));

        PrivateAccessor.setField(slingAuthenticator, "authHandlerCache", authRequiredCache);
        buildExpectationsForRequest(request, REQUEST_CHILD_NODE);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(slingAuthenticator, "getAuthenticationInfo",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class}, new Object[]{request, Mockito.mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined aboved should  be used for the path /test and his children: eg /test/childnode.
         */
        Assert.assertTrue(AUTH_TYPE.equals(authInfo.getAuthType()));
    }

    /**
     * Test is OK for same node;
     * @throws Throwable
     */
    @Test
    public void test_childNodeShouldHaveAuthenticationInfo2() throws Throwable {
        final String AUTH_TYPE = "AUTH_TYPE_TEST";
        final String PROTECTED_PATH = "/content/en/test";
        final String REQUEST_CHILD_NODE = "/content/en/test";

        PathBasedHolderCache<AbstractAuthenticationHandlerHolder> authRequiredCache = new PathBasedHolderCache<AbstractAuthenticationHandlerHolder>();
        authRequiredCache.addHolder(buildAuthHolderForAuthTypeAndPath(AUTH_TYPE, PROTECTED_PATH));

        PrivateAccessor.setField(slingAuthenticator, "authHandlerCache", authRequiredCache);
        buildExpectationsForRequest(request, REQUEST_CHILD_NODE);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(slingAuthenticator, "getAuthenticationInfo",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class}, new Object[]{request, Mockito.mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined aboved should  be used for the path /test and his children: eg /test/childnode.
         */
        Assert.assertTrue(AUTH_TYPE.equals(authInfo.getAuthType()));
    }

    /**
     * Test is OK for same node with ending slash;
     * @throws Throwable
     */
    @Test
    public void test_childNodeShouldHaveAuthenticationInfo3() throws Throwable {
        final String AUTH_TYPE = "AUTH_TYPE_TEST";
        final String PROTECTED_PATH = "/content/en/test";
        final String REQUEST_CHILD_NODE = "/content/en/test/";

        PathBasedHolderCache<AbstractAuthenticationHandlerHolder> authRequiredCache = new PathBasedHolderCache<AbstractAuthenticationHandlerHolder>();
        authRequiredCache.addHolder(buildAuthHolderForAuthTypeAndPath(AUTH_TYPE, PROTECTED_PATH));

        PrivateAccessor.setField(slingAuthenticator, "authHandlerCache", authRequiredCache);
        buildExpectationsForRequest(request, REQUEST_CHILD_NODE);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(slingAuthenticator, "getAuthenticationInfo",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class}, new Object[]{request, Mockito.mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined aboved should  be used for the path /test and his children: eg /test/childnode.
         */
        Assert.assertTrue(AUTH_TYPE.equals(authInfo.getAuthType()));
    }

    /**
     * Test is OK for same node with extension
     * @throws Throwable
     */
    @Test
    public void test_childNodeShouldHaveAuthenticationInfo4() throws Throwable {
        final String AUTH_TYPE = "AUTH_TYPE_TEST";
        final String PROTECTED_PATH = "/content/en/test";
        final String REQUEST_CHILD_NODE = "/content/en/test.html";

        PathBasedHolderCache<AbstractAuthenticationHandlerHolder> authRequiredCache = new PathBasedHolderCache<AbstractAuthenticationHandlerHolder>();
        authRequiredCache.addHolder(buildAuthHolderForAuthTypeAndPath(AUTH_TYPE, PROTECTED_PATH));

        PrivateAccessor.setField(slingAuthenticator, "authHandlerCache", authRequiredCache);
        buildExpectationsForRequest(request, REQUEST_CHILD_NODE);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(slingAuthenticator, "getAuthenticationInfo",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class}, new Object[]{request, Mockito.mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined aboved should  be used for the path /test and his children: eg /test/childnode.
         */
        Assert.assertTrue(AUTH_TYPE.equals(authInfo.getAuthType()));
    }

    @Test
    public void test_childNodeShouldHaveAuthenticationInfoRoot() throws Throwable {
        final String AUTH_TYPE = "AUTH_TYPE_TEST";
        final String PROTECTED_PATH = "/";
        final String REQUEST_CHILD_NODE = "/content/en/test";

        PathBasedHolderCache<AbstractAuthenticationHandlerHolder> authRequiredCache = new PathBasedHolderCache<AbstractAuthenticationHandlerHolder>();
        authRequiredCache.addHolder(buildAuthHolderForAuthTypeAndPath(AUTH_TYPE, PROTECTED_PATH));

        PrivateAccessor.setField(slingAuthenticator, "authHandlerCache", authRequiredCache);
        buildExpectationsForRequest(request, REQUEST_CHILD_NODE);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(slingAuthenticator, "getAuthenticationInfo",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class}, new Object[]{request, Mockito.mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined aboved should  be used for the path /test and his children: eg /test/childnode.
         */
        Assert.assertTrue(AUTH_TYPE.equals(authInfo.getAuthType()));
    }

    @Test
    public void test_childNodeShouldHaveAuthenticationInfoLonger() throws Throwable {
        final String AUTH_TYPE = "AUTH_TYPE_TEST";
        final String AUTH_TYPE_LONGER = "AUTH_TYPE_LONGER_TEST";
        final String PROTECTED_PATH = "/resource1";
        final String PROTECTED_PATH_LONGER = "/resource1.test2";
        final String REQUEST_CHILD_NODE = "/resource1.test2";

        PathBasedHolderCache<AbstractAuthenticationHandlerHolder> authRequiredCache = new PathBasedHolderCache<AbstractAuthenticationHandlerHolder>();
        authRequiredCache.addHolder(buildAuthHolderForAuthTypeAndPath(AUTH_TYPE, PROTECTED_PATH));
        authRequiredCache.addHolder(buildAuthHolderForAuthTypeAndPath(AUTH_TYPE_LONGER, PROTECTED_PATH_LONGER));

        PrivateAccessor.setField(slingAuthenticator, "authHandlerCache", authRequiredCache);
        buildExpectationsForRequest(request, REQUEST_CHILD_NODE);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(slingAuthenticator, "getAuthenticationInfo",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class}, new Object[]{request, Mockito.mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined aboved should  be used for the path /test and his children: eg /test/childnode.
         */
        Assert.assertTrue(AUTH_TYPE_LONGER.equals(authInfo.getAuthType()));
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

        PathBasedHolderCache<AbstractAuthenticationHandlerHolder> authRequiredCache = new PathBasedHolderCache<AbstractAuthenticationHandlerHolder>();
        authRequiredCache.addHolder(buildAuthHolderForAuthTypeAndPath(AUTH_TYPE, PROTECTED_PATH));

        PrivateAccessor.setField(slingAuthenticator, "authHandlerCache", authRequiredCache);
        buildExpectationsForRequest(request, REQUEST_NOT_PROTECTED_PATH);

        AuthenticationInfo authInfo = (AuthenticationInfo) PrivateAccessor.invoke(slingAuthenticator, "getAuthenticationInfo",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class}, new Object[]{request, Mockito.mock(HttpServletResponse.class)});
        /**
         * The AUTH TYPE defined above should not be used for the path /test2.
         */
        Assert.assertFalse(AUTH_TYPE.equals(authInfo.getAuthType()));
    }

    @Test
    public void test_childNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test/test2";
        final String handlerPath = "/content/test";

        Assert.assertTrue( (boolean)PrivateAccessor.invoke(slingAuthenticator, "isNodeRequiresAuthHandler", new Class[] {String.class, String.class}, new Object[] {requestPath, handlerPath}));
    }

    @Test
    public void test_siblingNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test2.html/en/2016/09/19/test.html";
        final String handlerPath = "/content/test";

        Assert.assertFalse( (boolean)PrivateAccessor.invoke(slingAuthenticator, "isNodeRequiresAuthHandler", new Class[] {String.class, String.class}, new Object[] {requestPath, handlerPath}));
    }

    @Test
    public void test_actualNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test";
        final String handlerPath = "/content/test";

        Assert.assertTrue( (boolean)PrivateAccessor.invoke(slingAuthenticator, "isNodeRequiresAuthHandler", new Class[] {String.class, String.class}, new Object[] {requestPath, handlerPath}));
    }

    @Test
    public void test_rootNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test";
        final String handlerPath = "/";

        Assert.assertTrue( (boolean)PrivateAccessor.invoke(slingAuthenticator, "isNodeRequiresAuthHandler", new Class[] {String.class, String.class}, new Object[] {requestPath, handlerPath}));
    }

    @Test
    public void test_requestPathSelectorsAreTakenInConsideration() throws Throwable {
        final String requestPath = "/content/test.selector1.selector2.html/en/2016/test.html";
        final String handlerPath = "/content/test";

        Assert.assertTrue( (boolean)PrivateAccessor.invoke(slingAuthenticator, "isNodeRequiresAuthHandler", new Class[] {String.class, String.class}, new Object[] {requestPath, handlerPath}));
    }

    @Test
    public void test_requestPathSelectorsSiblingAreTakenInConsideration() throws Throwable {
        final String requestPath = "/content/test.selector1.selector2.html/en/2016/09/19/test.html";
        final String handlerPath = "/content/test2";

        Assert.assertFalse( (boolean)PrivateAccessor.invoke(slingAuthenticator, "isNodeRequiresAuthHandler", new Class[] {String.class, String.class}, new Object[] {requestPath, handlerPath}));
    }

    @Test
    public void test_requestPathBackSlash() throws Throwable {
        final String requestPath = "/page1\\somesubepage";
        final String handlerPath = "/page";

        Assert.assertFalse( (boolean)PrivateAccessor.invoke(slingAuthenticator, "isNodeRequiresAuthHandler", new Class[] {String.class, String.class}, new Object[] {requestPath, handlerPath}));
    }

    @Test
    public void test_emptyNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test";
        final String handlerPath = "";

        Assert.assertTrue( (boolean)PrivateAccessor.invoke(slingAuthenticator, "isNodeRequiresAuthHandler", new Class[] {String.class, String.class}, new Object[] {requestPath, handlerPath}));
    }
    @Test public void testIsAnonAllowedWithMapping() {
        final HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        when(req.getScheme()).thenReturn("http");
        when(req.getServerPort()).thenReturn(80);
     
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = this.slingAuthenticator.authRequiredCache;
        cache.addHolder(AuthenticationRequirementHolder.fromConfig("-/path1", null));
        cache.addHolder(AuthenticationRequirementHolder.fromConfig("-/path2", null));

        final Result r = Mockito.mock(Result.class);
        when(this.pathToUriMappingService.resolve(req, null)).thenReturn(r);
        when(r.getUri()).thenReturn(SlingUriBuilder.create().setPath("/path").build());
        assertFalse(this.slingAuthenticator.isAnonAllowed(req));
        when(r.getUri()).thenReturn(SlingUriBuilder.create().setPath("/path1").build());
        assertTrue(this.slingAuthenticator.isAnonAllowed(req));
        when(r.getUri()).thenReturn(SlingUriBuilder.create().setPath("/path2").build());
        assertTrue(this.slingAuthenticator.isAnonAllowed(req));
    }
    //---------------------------- PRIVATE METHODS -----------------------------

    /**
     * Mocks the request to accept method calls on path;
     *
     * @param request http request
     * @param requestPath request path
     */
    private void buildExpectationsForRequest(final HttpServletRequest request, final String requestPath) {
        // path is not taken directly from request but from PathToUriMappingService
        when(resolveResult.getUri()).thenReturn(SlingUriBuilder.parse(requestPath, null).build());
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(80);
        when(request.getScheme()).thenReturn("http");
    }

    /**
     * Builds an auth handler for a specific path;
     * @param authType             name of the auth for this path
     * @param authProtectedPath    path protected by the auth handler
     * @return AbstractAuthenticationHandlerHolder with only an AuthenticationInfo
     */
    private AbstractAuthenticationHandlerHolder buildAuthHolderForAuthTypeAndPath(final String authType, final String authProtectedPath) {
        return new AbstractAuthenticationHandlerHolder(authProtectedPath, null) {

            @Override
            protected AuthenticationFeedbackHandler getFeedbackHandler() {
                return null;
            }

            @Override
            protected AuthenticationInfo doExtractCredentials(HttpServletRequest request, HttpServletResponse response) {
                return new AuthenticationInfo(authType);
            }

            @Override
            protected boolean doRequestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
                return false;
            }

            @Override
            protected void doDropCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {

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
}
