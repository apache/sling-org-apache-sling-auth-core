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
package org.apache.sling.auth.core;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.api.resource.NonExistingResource;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.SyntheticResource;
import org.apache.sling.auth.core.spi.JakartaAuthenticationHandler;
import org.junit.Assert;
import org.junit.Test;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.startsWith;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("deprecation")
public class AuthUtilTest {

    final ResourceResolver resolver = mock(ResourceResolver.class);

    final HttpServletRequest request = mock(HttpServletRequest.class);

    @Test
    public void test_isRedirectValid_null_empty() {
        Assert.assertFalse(AuthUtil.isRedirectValid((HttpServletRequest) null, null));
        Assert.assertFalse(AuthUtil.isRedirectValid((HttpServletRequest) null, ""));
    }

    @Test
    public void test_isRedirectValid_url() {
        Assert.assertFalse(AuthUtil.isRedirectValid((HttpServletRequest) null, "http://www.google.com"));
    }

    @Test
    public void test_isRedirectValid_no_request() {
        Assert.assertFalse(AuthUtil.isRedirectValid((HttpServletRequest) null, "relative/path"));
        Assert.assertTrue(AuthUtil.isRedirectValid((HttpServletRequest) null, "/absolute/path"));
    }

    @Test
    public void test_isRedirectValid_normalized() {
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/unnormalized//double/slash"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/unnormalized/double/slash//"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/unnormalized/./dot"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/unnormalized/../dot"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/unnormalized/dot/."));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/unnormalized/dot/.."));
    }

    @Test
    public void test_isRedirectValid_invalid_characters() {
        when(request.getContextPath()).thenReturn("");

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/</x"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/>/x"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/'/x"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/\"/x"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/\n"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/\r"));
    }

    @Test
    public void test_isRedirectValid_no_resource_resolver_root_context() {
        when(request.getContextPath()).thenReturn("");

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "relative/path"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/absolute/path"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/"));
    }

    @Test
    public void test_isRedirectValid_no_resource_resolver_non_root_context() {
        when(request.getContextPath()).thenReturn("/ctx");

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "relative/path"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/absolute/path"));

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "ctx/relative/path"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/ctx/absolute/path"));

        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/ctx/"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/ctx"));
    }

    @Test
    public void test_isRedirectValid_resource_resolver_root_context() {
        when(request.getContextPath()).thenReturn("");
        when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);

        when(resolver.resolve((HttpServletRequest) any(), eq("/absolute/path")))
                .thenReturn(new SyntheticResource(resolver, "/absolute/path", "test"));
        when(resolver.resolve((HttpServletRequest) any(), eq("relative/path")))
                .thenReturn(new NonExistingResource(resolver, "relative/path"));
        when(resolver.resolve((HttpServletRequest) any(), any()))
                .thenReturn(new NonExistingResource(resolver, "/absolute/missing"));

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "relative/path"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/absolute/path"));

        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/absolute/missing"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/absolute/missing/valid"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/absolute/missing/invalid/<"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/absolute/missing/invalid/>"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/absolute/missing/invalid/'"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/absolute/missing/invalid/\""));
    }

    @Test
    public void test_isRedirectValid_resource_resolver_non_root_context() {
        when(request.getContextPath()).thenReturn("/ctx");
        when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);

        when(resolver.resolve((HttpServletRequest) any(), eq("/absolute/path")))
                .thenReturn(new SyntheticResource(resolver, "/absolute/path", "test"));
        when(resolver.resolve((HttpServletRequest) any(), eq("relative/path")))
                .thenReturn(new NonExistingResource(resolver, "relative/path"));
        when(resolver.resolve((HttpServletRequest) any(), any()))
                .thenReturn(new NonExistingResource(resolver, "/absolute/missing"));

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "relative/path"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/absolute/path"));

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "ctx/relative/path"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/ctx/absolute/path"));

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/ctxrelative/path"));
    }

    @Test
    public void test_isBrowserRequest_null() {
        Assert.assertFalse(AuthUtil.isBrowserRequest(request));
    }

    @Test
    public void test_isBrowserRequest_Mozilla() {
        when(request.getHeader("User-Agent")).thenReturn("This is firefox (Mozilla)");
        Assert.assertTrue(AuthUtil.isBrowserRequest(request));
    }

    @Test
    public void test_isBrowserRequest_Opera() {
        when(request.getHeader("User-Agent")).thenReturn("This is opera (Opera)");
        Assert.assertTrue(AuthUtil.isBrowserRequest(request));
    }

    @Test
    public void test_isBrowserRequest_WebDAV() {
        when(request.getHeader("User-Agent")).thenReturn("WebDAV Client");
        Assert.assertFalse(AuthUtil.isBrowserRequest(request));
    }

    // ---- Jakarta variants ----

    @Test
    public void test_getAttributeOrParameter_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(req.getAttribute("a")).thenReturn("attrValue");
        Assert.assertEquals("attrValue", AuthUtil.getAttributeOrParameter(req, "a", "def"));

        when(req.getAttribute("b")).thenReturn(null);
        when(req.getParameter("b")).thenReturn("paramValue");
        Assert.assertEquals("paramValue", AuthUtil.getAttributeOrParameter(req, "b", "def"));

        when(req.getAttribute("c")).thenReturn("");
        when(req.getParameter("c")).thenReturn("");
        Assert.assertEquals("def", AuthUtil.getAttributeOrParameter(req, "c", "def"));

        // non-string attribute is ignored
        when(req.getAttribute("d")).thenReturn(Integer.valueOf(1));
        when(req.getParameter("d")).thenReturn(null);
        Assert.assertEquals("def", AuthUtil.getAttributeOrParameter(req, "d", "def"));
    }

    @Test
    public void test_getLoginResource_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(req.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/res");
        Assert.assertEquals("/res", AuthUtil.getLoginResource(req, "/def"));

        jakarta.servlet.http.HttpServletRequest request2 = mock(jakarta.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/def", AuthUtil.getLoginResource(request2, "/def"));
    }

    @Test
    public void test_getMappedLoginResourcePath_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        ResourceResolver resolver = mock(ResourceResolver.class);
        when(req.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER)).thenReturn(resolver);
        when(req.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/res");
        when(resolver.map(req, "/res")).thenReturn("/mapped/res");
        Assert.assertEquals("/mapped/res", AuthUtil.getMappedLoginResourcePath(req, "/def"));
    }

    @Test
    public void test_getMappedLoginResourcePath_null_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        // no resolver -> getResourceResolver returns null -> NPE guarded by null path only
        // here defaultLoginResource is null and no param -> resourcePath null -> returns null
        Assert.assertNull(AuthUtil.getMappedLoginResourcePath(req, null));
    }

    @Test
    public void test_setLoginResourceAttribute_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        // attribute already set
        when(req.getAttribute(Authenticator.LOGIN_RESOURCE)).thenReturn("/existing");
        Assert.assertEquals("/existing", AuthUtil.setLoginResourceAttribute(req, "/def"));

        // parameter set
        jakarta.servlet.http.HttpServletRequest request2 = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(request2.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/param");
        Assert.assertEquals("/param", AuthUtil.setLoginResourceAttribute(request2, "/def"));

        // default used
        jakarta.servlet.http.HttpServletRequest request3 = mock(jakarta.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/def", AuthUtil.setLoginResourceAttribute(request3, "/def"));

        // fallback to "/"
        jakarta.servlet.http.HttpServletRequest request4 = mock(jakarta.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/", AuthUtil.setLoginResourceAttribute(request4, null));
    }

    @Test
    public void test_sendRedirect_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/current");
        when(req.getQueryString()).thenReturn("x=1");

        Map<String, String> params = new HashMap<>();
        params.put("k", "v v");
        AuthUtil.sendRedirect(req, response, "/valid/target", params);

        verify(response).sendRedirect(contains("/valid/target?"));
    }

    @Test
    public void test_sendRedirect_invalidTarget_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        when(req.getContextPath()).thenReturn("/ctx");
        when(req.getRequestURI()).thenReturn("/current");

        AuthUtil.sendRedirect(req, response, "relative", null);
        verify(response).sendRedirect(startsWith("/ctx?"));
    }

    @Test
    public void test_sendRedirect_invalidTarget_rootContext_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/current");

        AuthUtil.sendRedirect(req, response, "relative", null);
        verify(response).sendRedirect(startsWith("/?"));
    }

    @Test(expected = IllegalStateException.class)
    public void test_sendRedirect_committed_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        when(response.isCommitted()).thenReturn(true);
        AuthUtil.sendRedirect(req, response, "/target", null);
    }

    @Test
    public void test_isValidateRequest_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(req.getParameter(AuthConstants.PAR_J_VALIDATE)).thenReturn("TRUE");
        Assert.assertTrue(AuthUtil.isValidateRequest(req));
        when(req.getParameter(AuthConstants.PAR_J_VALIDATE)).thenReturn("no");
        Assert.assertFalse(AuthUtil.isValidateRequest(req));
    }

    @Test
    public void test_sendValid_jakarta() {
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        AuthUtil.sendValid(response);
        verify(response).setStatus(jakarta.servlet.http.HttpServletResponse.SC_OK);
        verify(response).setContentLength(0);
    }

    @Test
    public void test_sendInvalid_withReason_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        when(req.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON)).thenReturn("bad");
        when(req.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON_CODE)).thenReturn("code1");
        StringWriter sw = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(sw));

        AuthUtil.sendInvalid(req, response);
        verify(response).setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN);
        verify(response).setHeader(AuthConstants.X_REASON, "bad");
        verify(response).setHeader(AuthConstants.X_REASON_CODE, "code1");
        Assert.assertTrue(sw.toString().contains("bad"));
    }

    @Test
    public void test_sendInvalid_noReason_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        AuthUtil.sendInvalid(req, response);
        verify(response).setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void test_checkReferer_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        // not a POST -> true
        when(req.getMethod()).thenReturn("GET");
        Assert.assertTrue(AuthUtil.checkReferer(req, "/login"));

        // POST with no referer -> true
        when(req.getMethod()).thenReturn("POST");
        Assert.assertTrue(AuthUtil.checkReferer(req, "/login"));

        // POST with matching referer -> true
        when(req.getContextPath()).thenReturn("");
        when(req.getHeader("Referer")).thenReturn("http://host/login");
        Assert.assertTrue(AuthUtil.checkReferer(req, "/login"));

        // POST with non-matching referer -> false
        when(req.getHeader("Referer")).thenReturn("http://host/other");
        Assert.assertFalse(AuthUtil.checkReferer(req, "/login"));

        // POST with malformed referer -> true (parse fails, falls through)
        when(req.getHeader("Referer")).thenReturn("::not a url::");
        Assert.assertTrue(AuthUtil.checkReferer(req, "/login"));
    }

    @Test
    public void test_isAjaxRequest_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(req.getHeader("X-Requested-With")).thenReturn("XMLHttpRequest");
        Assert.assertTrue(AuthUtil.isAjaxRequest(req));
        when(req.getHeader("X-Requested-With")).thenReturn("other");
        Assert.assertFalse(AuthUtil.isAjaxRequest(req));
    }

    @Test
    public void test_isRedirectValid_url_jakarta() {
        Assert.assertFalse(
                AuthUtil.isRedirectValid((jakarta.servlet.http.HttpServletRequest) null, "http://www.google.com"));
    }

    @Test
    public void test_isBrowserRequest_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(req.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        Assert.assertTrue(AuthUtil.isBrowserRequest(req));
        when(req.getHeader("User-Agent")).thenReturn("curl");
        Assert.assertFalse(AuthUtil.isBrowserRequest(req));
    }

    // ---- Deprecated javax variants ----

    @SuppressWarnings("deprecation")
    @Test
    public void test_getAttributeOrParameter_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getAttribute("a")).thenReturn("attrValue");
        Assert.assertEquals("attrValue", AuthUtil.getAttributeOrParameter(req, "a", "def"));

        when(req.getAttribute("b")).thenReturn(null);
        when(req.getParameter("b")).thenReturn("paramValue");
        Assert.assertEquals("paramValue", AuthUtil.getAttributeOrParameter(req, "b", "def"));

        when(req.getAttribute("c")).thenReturn(null);
        when(req.getParameter("c")).thenReturn(null);
        Assert.assertEquals("def", AuthUtil.getAttributeOrParameter(req, "c", "def"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_getLoginResource_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/res");
        Assert.assertEquals("/res", AuthUtil.getLoginResource(req, "/def"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_getMappedLoginResourcePath_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        ResourceResolver resolver = mock(ResourceResolver.class);
        when(req.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER)).thenReturn(resolver);
        when(req.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/res");
        when(resolver.map(req, "/res")).thenReturn("/mapped/res");
        Assert.assertEquals("/mapped/res", AuthUtil.getMappedLoginResourcePath(req, "/def"));

        javax.servlet.http.HttpServletRequest request2 = mock(javax.servlet.http.HttpServletRequest.class);
        Assert.assertNull(AuthUtil.getMappedLoginResourcePath(request2, null));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_setLoginResourceAttribute_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getAttribute(Authenticator.LOGIN_RESOURCE)).thenReturn("/existing");
        Assert.assertEquals("/existing", AuthUtil.setLoginResourceAttribute(req, "/def"));

        javax.servlet.http.HttpServletRequest request2 = mock(javax.servlet.http.HttpServletRequest.class);
        when(request2.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/param");
        Assert.assertEquals("/param", AuthUtil.setLoginResourceAttribute(request2, "/def"));

        javax.servlet.http.HttpServletRequest request3 = mock(javax.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/def", AuthUtil.setLoginResourceAttribute(request3, "/def"));

        javax.servlet.http.HttpServletRequest request4 = mock(javax.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/", AuthUtil.setLoginResourceAttribute(request4, null));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_sendRedirect_javax() throws Exception {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/current");
        when(req.getQueryString()).thenReturn(null);

        Map<String, String> params = new HashMap<>();
        params.put("k", "v");
        AuthUtil.sendRedirect(req, response, "/valid/target", params);
        verify(response).sendRedirect(contains("/valid/target?"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_isValidateRequest_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getParameter(AuthConstants.PAR_J_VALIDATE)).thenReturn("true");
        Assert.assertTrue(AuthUtil.isValidateRequest(req));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_sendValid_javax() {
        javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        AuthUtil.sendValid(response);
        verify(response).setStatus(javax.servlet.http.HttpServletResponse.SC_OK);
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_sendInvalid_javax() throws Exception {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        when(req.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON)).thenReturn("bad");
        StringWriter sw = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(sw));
        AuthUtil.sendInvalid(req, response);
        verify(response).setStatus(javax.servlet.http.HttpServletResponse.SC_FORBIDDEN);
        Assert.assertTrue(sw.toString().contains("bad"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_checkReferer_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getContextPath()).thenReturn("");
        when(req.getHeader("Referer")).thenReturn("http://host/login");
        Assert.assertTrue(AuthUtil.checkReferer(req, "/login"));
        when(req.getHeader("Referer")).thenReturn("http://host/other");
        Assert.assertFalse(AuthUtil.checkReferer(req, "/login"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_isAjaxRequest_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getHeader("X-Requested-With")).thenReturn("XMLHttpRequest");
        Assert.assertTrue(AuthUtil.isAjaxRequest(req));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_isBrowserRequest_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getHeader("User-Agent")).thenReturn("Opera/9");
        Assert.assertTrue(AuthUtil.isBrowserRequest(req));
        when(req.getHeader("User-Agent")).thenReturn(null);
        Assert.assertFalse(AuthUtil.isBrowserRequest(req));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_isRedirectValid_javax() {
        Assert.assertFalse(AuthUtil.isRedirectValid((javax.servlet.http.HttpServletRequest) null, "http://host"));
        Assert.assertTrue(AuthUtil.isRedirectValid((javax.servlet.http.HttpServletRequest) null, "/absolute/path"));
        Assert.assertFalse(AuthUtil.isRedirectValid((javax.servlet.http.HttpServletRequest) null, "/unnormalized//x"));
    }

    // ---- jakarta isRedirectValid, resolver resolves the target ----

    @Test
    public void test_isRedirectValid_resolvesToResource_jakarta() {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(req.getContextPath()).thenReturn("");
        final ResourceResolver resolver = mock(ResourceResolver.class);
        final Resource resource = mock(Resource.class);
        when(resource.getResourceType()).thenReturn("some/type");
        when(resolver.resolve(eq(req), anyString())).thenReturn(resource);
        when(req.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER)).thenReturn(resolver);

        Assert.assertTrue(AuthUtil.isRedirectValid(req, "/valid/path"));
    }

    // ---- javax isRedirectValid full branch coverage ----

    @Test
    public void test_isRedirectValid_empty_javax() {
        Assert.assertFalse(AuthUtil.isRedirectValid((javax.servlet.http.HttpServletRequest) null, ""));
        Assert.assertFalse(AuthUtil.isRedirectValid((javax.servlet.http.HttpServletRequest) null, null));
    }

    @Test
    public void test_isRedirectValid_illegalCharacters_javax() {
        // a space triggers a URISyntaxException
        Assert.assertFalse(AuthUtil.isRedirectValid((javax.servlet.http.HttpServletRequest) null, "/a b"));
    }

    @Test
    public void test_isRedirectValid_url_javax() {
        Assert.assertFalse(AuthUtil.isRedirectValid((javax.servlet.http.HttpServletRequest) null, "http://host/x"));
    }

    @Test
    public void test_isRedirectValid_notNormalized_javax() {
        Assert.assertFalse(AuthUtil.isRedirectValid((javax.servlet.http.HttpServletRequest) null, "/a//b"));
    }

    @Test
    public void test_isRedirectValid_contextPathMismatch_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getContextPath()).thenReturn("/ctx");
        Assert.assertFalse(AuthUtil.isRedirectValid(req, "/other/path"));
    }

    @Test
    public void test_isRedirectValid_contextRoot_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getContextPath()).thenReturn("/ctx");
        Assert.assertTrue(AuthUtil.isRedirectValid(req, "/ctx"));
    }

    @Test
    public void test_isRedirectValid_notAbsoluteAfterContext_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getContextPath()).thenReturn("/ctx");
        Assert.assertFalse(AuthUtil.isRedirectValid(req, "/ctxrelative"));
    }

    @Test
    public void test_isRedirectValid_illegalChars_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getContextPath()).thenReturn("");
        Assert.assertFalse(AuthUtil.isRedirectValid(req, "/path'quote"));
    }

    @Test
    public void test_isRedirectValid_resolvesToResource_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getContextPath()).thenReturn("");
        final ResourceResolver resolver = mock(ResourceResolver.class);
        final Resource resource = mock(Resource.class);
        when(resource.getResourceType()).thenReturn("some/type");
        when(resolver.resolve(eq(req), anyString())).thenReturn(resource);
        when(req.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER)).thenReturn(resolver);

        Assert.assertTrue(AuthUtil.isRedirectValid(req, "/valid/path"));
    }

    // ---- javax sendRedirect branch coverage ----

    @Test
    public void test_sendRedirect_invalidTarget_rootContext_javax() throws Exception {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/current");
        AuthUtil.sendRedirect(req, response, "relative", null);
        verify(response).sendRedirect(startsWith("/?"));
    }

    @Test
    public void test_sendRedirect_invalidTarget_withContext_javax() throws Exception {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        when(req.getContextPath()).thenReturn("/ctx");
        when(req.getRequestURI()).thenReturn("/ctx/current");
        when(req.getQueryString()).thenReturn("a=b");
        final Map<String, String> params = new HashMap<>();
        AuthUtil.sendRedirect(req, response, "relative", params);
        verify(response).sendRedirect(startsWith("/ctx?"));
    }

    // ---- jakarta sendInvalid with reason code ----

    @Test
    public void test_sendInvalid_withReasonCode_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        when(req.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON)).thenReturn("bad");
        when(req.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON_CODE)).thenReturn("code42");
        when(response.getWriter()).thenReturn(new java.io.PrintWriter(new java.io.StringWriter()));
        AuthUtil.sendInvalid(req, response);
        verify(response).setHeader(AuthConstants.X_REASON_CODE, "code42");
    }

    // ---- IOException error paths ----

    @Test
    public void test_sendValid_ioexception_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        doThrow(new IOException("boom")).when(response).flushBuffer();
        AuthUtil.sendValid(response);
        // IOException from flushBuffer is caught internally; the OK response is still prepared.
        verify(response).setStatus(jakarta.servlet.http.HttpServletResponse.SC_OK);
        verify(response).flushBuffer();
    }

    @Test
    public void test_sendValid_ioexception_javax() throws Exception {
        javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        doThrow(new IOException("boom")).when(response).flushBuffer();
        AuthUtil.sendValid(response);
        // IOException from flushBuffer is caught internally; the OK response is still prepared.
        verify(response).setStatus(javax.servlet.http.HttpServletResponse.SC_OK);
        verify(response).flushBuffer();
    }

    @Test
    public void test_sendInvalid_ioexception_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest req = mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response = mock(jakarta.servlet.http.HttpServletResponse.class);
        doThrow(new IOException("boom")).when(response).flushBuffer();
        AuthUtil.sendInvalid(req, response);
        // IOException from flushBuffer is caught internally; the FORBIDDEN response is still prepared.
        verify(response).setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN);
        verify(response).flushBuffer();
    }

    @Test
    public void test_sendInvalid_ioexception_javax() throws Exception {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = mock(javax.servlet.http.HttpServletResponse.class);
        doThrow(new IOException("boom")).when(response).flushBuffer();
        AuthUtil.sendInvalid(req, response);
        // IOException from flushBuffer is caught internally; the FORBIDDEN response is still prepared.
        verify(response).setStatus(javax.servlet.http.HttpServletResponse.SC_FORBIDDEN);
        verify(response).flushBuffer();
    }

    // ---- javax checkReferer malformed URL ----

    @Test
    public void test_checkReferer_malformedUrl_javax() {
        javax.servlet.http.HttpServletRequest req = mock(javax.servlet.http.HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getContextPath()).thenReturn("");
        when(req.getHeader("Referer")).thenReturn("::: not a url :::");
        Assert.assertTrue(AuthUtil.checkReferer(req, "/login"));
    }
}
