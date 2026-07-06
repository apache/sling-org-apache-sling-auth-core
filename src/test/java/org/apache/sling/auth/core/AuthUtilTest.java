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
import org.mockito.Mockito;

@SuppressWarnings("deprecation")
public class AuthUtilTest {

    final ResourceResolver resolver = Mockito.mock(ResourceResolver.class);

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

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
        Mockito.when(request.getContextPath()).thenReturn("");

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/</x"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/>/x"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/'/x"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/\"/x"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/\n"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/illegal/\r"));
    }

    @Test
    public void test_isRedirectValid_no_resource_resolver_root_context() {
        Mockito.when(request.getContextPath()).thenReturn("");

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "relative/path"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/absolute/path"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/"));
    }

    @Test
    public void test_isRedirectValid_no_resource_resolver_non_root_context() {
        Mockito.when(request.getContextPath()).thenReturn("/ctx");

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "relative/path"));
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/absolute/path"));

        Assert.assertFalse(AuthUtil.isRedirectValid(request, "ctx/relative/path"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/ctx/absolute/path"));

        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/ctx/"));
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/ctx"));
    }

    @Test
    public void test_isRedirectValid_resource_resolver_root_context() {
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);

        Mockito.when(resolver.resolve((HttpServletRequest) Mockito.any(), Mockito.eq("/absolute/path")))
                .thenReturn(new SyntheticResource(resolver, "/absolute/path", "test"));
        Mockito.when(resolver.resolve((HttpServletRequest) Mockito.any(), Mockito.eq("relative/path")))
                .thenReturn(new NonExistingResource(resolver, "relative/path"));
        Mockito.when(resolver.resolve((HttpServletRequest) Mockito.any(), Mockito.any()))
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
        Mockito.when(request.getContextPath()).thenReturn("/ctx");
        Mockito.when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);

        Mockito.when(resolver.resolve((HttpServletRequest) Mockito.any(), Mockito.eq("/absolute/path")))
                .thenReturn(new SyntheticResource(resolver, "/absolute/path", "test"));
        Mockito.when(resolver.resolve((HttpServletRequest) Mockito.any(), Mockito.eq("relative/path")))
                .thenReturn(new NonExistingResource(resolver, "relative/path"));
        Mockito.when(resolver.resolve((HttpServletRequest) Mockito.any(), Mockito.any()))
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
        Mockito.when(request.getHeader("User-Agent")).thenReturn("This is firefox (Mozilla)");
        Assert.assertTrue(AuthUtil.isBrowserRequest(request));
    }

    @Test
    public void test_isBrowserRequest_Opera() {
        Mockito.when(request.getHeader("User-Agent")).thenReturn("This is opera (Opera)");
        Assert.assertTrue(AuthUtil.isBrowserRequest(request));
    }

    @Test
    public void test_isBrowserRequest_WebDAV() {
        Mockito.when(request.getHeader("User-Agent")).thenReturn("WebDAV Client");
        Assert.assertFalse(AuthUtil.isBrowserRequest(request));
    }

    // ---- Jakarta variants ----

    @Test
    public void test_getAttributeOrParameter_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getAttribute("a")).thenReturn("attrValue");
        Assert.assertEquals("attrValue", AuthUtil.getAttributeOrParameter(request, "a", "def"));

        Mockito.when(request.getAttribute("b")).thenReturn(null);
        Mockito.when(request.getParameter("b")).thenReturn("paramValue");
        Assert.assertEquals("paramValue", AuthUtil.getAttributeOrParameter(request, "b", "def"));

        Mockito.when(request.getAttribute("c")).thenReturn("");
        Mockito.when(request.getParameter("c")).thenReturn("");
        Assert.assertEquals("def", AuthUtil.getAttributeOrParameter(request, "c", "def"));

        // non-string attribute is ignored
        Mockito.when(request.getAttribute("d")).thenReturn(Integer.valueOf(1));
        Mockito.when(request.getParameter("d")).thenReturn(null);
        Assert.assertEquals("def", AuthUtil.getAttributeOrParameter(request, "d", "def"));
    }

    @Test
    public void test_getLoginResource_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/res");
        Assert.assertEquals("/res", AuthUtil.getLoginResource(request, "/def"));

        jakarta.servlet.http.HttpServletRequest request2 = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/def", AuthUtil.getLoginResource(request2, "/def"));
    }

    @Test
    public void test_getMappedLoginResourcePath_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        ResourceResolver resolver = Mockito.mock(ResourceResolver.class);
        Mockito.when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);
        Mockito.when(request.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/res");
        Mockito.when(resolver.map(request, "/res")).thenReturn("/mapped/res");
        Assert.assertEquals("/mapped/res", AuthUtil.getMappedLoginResourcePath(request, "/def"));
    }

    @Test
    public void test_getMappedLoginResourcePath_null_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        // no resolver -> getResourceResolver returns null -> NPE guarded by null path only
        // here defaultLoginResource is null and no param -> resourcePath null -> returns null
        Assert.assertNull(AuthUtil.getMappedLoginResourcePath(request, null));
    }

    @Test
    public void test_setLoginResourceAttribute_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        // attribute already set
        Mockito.when(request.getAttribute(Authenticator.LOGIN_RESOURCE)).thenReturn("/existing");
        Assert.assertEquals("/existing", AuthUtil.setLoginResourceAttribute(request, "/def"));

        // parameter set
        jakarta.servlet.http.HttpServletRequest request2 = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Mockito.when(request2.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/param");
        Assert.assertEquals("/param", AuthUtil.setLoginResourceAttribute(request2, "/def"));

        // default used
        jakarta.servlet.http.HttpServletRequest request3 = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/def", AuthUtil.setLoginResourceAttribute(request3, "/def"));

        // fallback to "/"
        jakarta.servlet.http.HttpServletRequest request4 = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/", AuthUtil.setLoginResourceAttribute(request4, null));
    }

    @Test
    public void test_sendRedirect_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getRequestURI()).thenReturn("/current");
        Mockito.when(request.getQueryString()).thenReturn("x=1");

        Map<String, String> params = new HashMap<>();
        params.put("k", "v v");
        AuthUtil.sendRedirect(request, response, "/valid/target", params);

        Mockito.verify(response).sendRedirect(Mockito.contains("/valid/target?"));
    }

    @Test
    public void test_sendRedirect_invalidTarget_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        Mockito.when(request.getContextPath()).thenReturn("/ctx");
        Mockito.when(request.getRequestURI()).thenReturn("/current");

        AuthUtil.sendRedirect(request, response, "relative", null);
        Mockito.verify(response).sendRedirect(Mockito.startsWith("/ctx?"));
    }

    @Test
    public void test_sendRedirect_invalidTarget_rootContext_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getRequestURI()).thenReturn("/current");

        AuthUtil.sendRedirect(request, response, "relative", null);
        Mockito.verify(response).sendRedirect(Mockito.startsWith("/?"));
    }

    @Test(expected = IllegalStateException.class)
    public void test_sendRedirect_committed_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        Mockito.when(response.isCommitted()).thenReturn(true);
        AuthUtil.sendRedirect(request, response, "/target", null);
    }

    @Test
    public void test_isValidateRequest_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getParameter(AuthConstants.PAR_J_VALIDATE)).thenReturn("TRUE");
        Assert.assertTrue(AuthUtil.isValidateRequest(request));
        Mockito.when(request.getParameter(AuthConstants.PAR_J_VALIDATE)).thenReturn("no");
        Assert.assertFalse(AuthUtil.isValidateRequest(request));
    }

    @Test
    public void test_sendValid_jakarta() {
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        AuthUtil.sendValid(response);
        Mockito.verify(response).setStatus(jakarta.servlet.http.HttpServletResponse.SC_OK);
        Mockito.verify(response).setContentLength(0);
    }

    @Test
    public void test_sendInvalid_withReason_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        Mockito.when(request.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON))
                .thenReturn("bad");
        Mockito.when(request.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON_CODE))
                .thenReturn("code1");
        StringWriter sw = new StringWriter();
        Mockito.when(response.getWriter()).thenReturn(new PrintWriter(sw));

        AuthUtil.sendInvalid(request, response);
        Mockito.verify(response).setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN);
        Mockito.verify(response).setHeader(AuthConstants.X_REASON, "bad");
        Mockito.verify(response).setHeader(AuthConstants.X_REASON_CODE, "code1");
        Assert.assertTrue(sw.toString().contains("bad"));
    }

    @Test
    public void test_sendInvalid_noReason_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        AuthUtil.sendInvalid(request, response);
        Mockito.verify(response).setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void test_checkReferer_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        // not a POST -> true
        Mockito.when(request.getMethod()).thenReturn("GET");
        Assert.assertTrue(AuthUtil.checkReferer(request, "/login"));

        // POST with no referer -> true
        Mockito.when(request.getMethod()).thenReturn("POST");
        Assert.assertTrue(AuthUtil.checkReferer(request, "/login"));

        // POST with matching referer -> true
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getHeader("Referer")).thenReturn("http://host/login");
        Assert.assertTrue(AuthUtil.checkReferer(request, "/login"));

        // POST with non-matching referer -> false
        Mockito.when(request.getHeader("Referer")).thenReturn("http://host/other");
        Assert.assertFalse(AuthUtil.checkReferer(request, "/login"));

        // POST with malformed referer -> true (parse fails, falls through)
        Mockito.when(request.getHeader("Referer")).thenReturn("::not a url::");
        Assert.assertTrue(AuthUtil.checkReferer(request, "/login"));
    }

    @Test
    public void test_isAjaxRequest_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getHeader("X-Requested-With")).thenReturn("XMLHttpRequest");
        Assert.assertTrue(AuthUtil.isAjaxRequest(request));
        Mockito.when(request.getHeader("X-Requested-With")).thenReturn("other");
        Assert.assertFalse(AuthUtil.isAjaxRequest(request));
    }

    @Test
    public void test_isRedirectValid_url_jakarta() {
        Assert.assertFalse(
                AuthUtil.isRedirectValid((jakarta.servlet.http.HttpServletRequest) null, "http://www.google.com"));
    }

    @Test
    public void test_isBrowserRequest_jakarta() {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        Assert.assertTrue(AuthUtil.isBrowserRequest(request));
        Mockito.when(request.getHeader("User-Agent")).thenReturn("curl");
        Assert.assertFalse(AuthUtil.isBrowserRequest(request));
    }

    // ---- Deprecated javax variants ----

    @SuppressWarnings("deprecation")
    @Test
    public void test_getAttributeOrParameter_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getAttribute("a")).thenReturn("attrValue");
        Assert.assertEquals("attrValue", AuthUtil.getAttributeOrParameter(request, "a", "def"));

        Mockito.when(request.getAttribute("b")).thenReturn(null);
        Mockito.when(request.getParameter("b")).thenReturn("paramValue");
        Assert.assertEquals("paramValue", AuthUtil.getAttributeOrParameter(request, "b", "def"));

        Mockito.when(request.getAttribute("c")).thenReturn(null);
        Mockito.when(request.getParameter("c")).thenReturn(null);
        Assert.assertEquals("def", AuthUtil.getAttributeOrParameter(request, "c", "def"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_getLoginResource_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/res");
        Assert.assertEquals("/res", AuthUtil.getLoginResource(request, "/def"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_getMappedLoginResourcePath_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        ResourceResolver resolver = Mockito.mock(ResourceResolver.class);
        Mockito.when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);
        Mockito.when(request.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/res");
        Mockito.when(resolver.map(request, "/res")).thenReturn("/mapped/res");
        Assert.assertEquals("/mapped/res", AuthUtil.getMappedLoginResourcePath(request, "/def"));

        javax.servlet.http.HttpServletRequest request2 = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Assert.assertNull(AuthUtil.getMappedLoginResourcePath(request2, null));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_setLoginResourceAttribute_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getAttribute(Authenticator.LOGIN_RESOURCE)).thenReturn("/existing");
        Assert.assertEquals("/existing", AuthUtil.setLoginResourceAttribute(request, "/def"));

        javax.servlet.http.HttpServletRequest request2 = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request2.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/param");
        Assert.assertEquals("/param", AuthUtil.setLoginResourceAttribute(request2, "/def"));

        javax.servlet.http.HttpServletRequest request3 = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/def", AuthUtil.setLoginResourceAttribute(request3, "/def"));

        javax.servlet.http.HttpServletRequest request4 = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Assert.assertEquals("/", AuthUtil.setLoginResourceAttribute(request4, null));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_sendRedirect_javax() throws Exception {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = Mockito.mock(javax.servlet.http.HttpServletResponse.class);
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getRequestURI()).thenReturn("/current");
        Mockito.when(request.getQueryString()).thenReturn(null);

        Map<String, String> params = new HashMap<>();
        params.put("k", "v");
        AuthUtil.sendRedirect(request, response, "/valid/target", params);
        Mockito.verify(response).sendRedirect(Mockito.contains("/valid/target?"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_isValidateRequest_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getParameter(AuthConstants.PAR_J_VALIDATE)).thenReturn("true");
        Assert.assertTrue(AuthUtil.isValidateRequest(request));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_sendValid_javax() {
        javax.servlet.http.HttpServletResponse response = Mockito.mock(javax.servlet.http.HttpServletResponse.class);
        AuthUtil.sendValid(response);
        Mockito.verify(response).setStatus(javax.servlet.http.HttpServletResponse.SC_OK);
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_sendInvalid_javax() throws Exception {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = Mockito.mock(javax.servlet.http.HttpServletResponse.class);
        Mockito.when(request.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON))
                .thenReturn("bad");
        StringWriter sw = new StringWriter();
        Mockito.when(response.getWriter()).thenReturn(new PrintWriter(sw));
        AuthUtil.sendInvalid(request, response);
        Mockito.verify(response).setStatus(javax.servlet.http.HttpServletResponse.SC_FORBIDDEN);
        Assert.assertTrue(sw.toString().contains("bad"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_checkReferer_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getMethod()).thenReturn("POST");
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getHeader("Referer")).thenReturn("http://host/login");
        Assert.assertTrue(AuthUtil.checkReferer(request, "/login"));
        Mockito.when(request.getHeader("Referer")).thenReturn("http://host/other");
        Assert.assertFalse(AuthUtil.checkReferer(request, "/login"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_isAjaxRequest_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getHeader("X-Requested-With")).thenReturn("XMLHttpRequest");
        Assert.assertTrue(AuthUtil.isAjaxRequest(request));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void test_isBrowserRequest_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getHeader("User-Agent")).thenReturn("Opera/9");
        Assert.assertTrue(AuthUtil.isBrowserRequest(request));
        Mockito.when(request.getHeader("User-Agent")).thenReturn(null);
        Assert.assertFalse(AuthUtil.isBrowserRequest(request));
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
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("");
        final ResourceResolver resolver = Mockito.mock(ResourceResolver.class);
        final Resource resource = Mockito.mock(Resource.class);
        Mockito.when(resource.getResourceType()).thenReturn("some/type");
        Mockito.when(resolver.resolve(Mockito.eq(request), Mockito.anyString())).thenReturn(resource);
        Mockito.when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);

        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/valid/path"));
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
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("/ctx");
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/other/path"));
    }

    @Test
    public void test_isRedirectValid_contextRoot_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("/ctx");
        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/ctx"));
    }

    @Test
    public void test_isRedirectValid_notAbsoluteAfterContext_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("/ctx");
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/ctxrelative"));
    }

    @Test
    public void test_isRedirectValid_illegalChars_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("");
        Assert.assertFalse(AuthUtil.isRedirectValid(request, "/path'quote"));
    }

    @Test
    public void test_isRedirectValid_resolvesToResource_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("");
        final ResourceResolver resolver = Mockito.mock(ResourceResolver.class);
        final Resource resource = Mockito.mock(Resource.class);
        Mockito.when(resource.getResourceType()).thenReturn("some/type");
        Mockito.when(resolver.resolve(Mockito.eq(request), Mockito.anyString())).thenReturn(resource);
        Mockito.when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER))
                .thenReturn(resolver);

        Assert.assertTrue(AuthUtil.isRedirectValid(request, "/valid/path"));
    }

    // ---- javax sendRedirect branch coverage ----

    @Test
    public void test_sendRedirect_invalidTarget_rootContext_javax() throws Exception {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = Mockito.mock(javax.servlet.http.HttpServletResponse.class);
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getRequestURI()).thenReturn("/current");
        AuthUtil.sendRedirect(request, response, "relative", null);
        Mockito.verify(response).sendRedirect(Mockito.startsWith("/?"));
    }

    @Test
    public void test_sendRedirect_invalidTarget_withContext_javax() throws Exception {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = Mockito.mock(javax.servlet.http.HttpServletResponse.class);
        Mockito.when(request.getContextPath()).thenReturn("/ctx");
        Mockito.when(request.getRequestURI()).thenReturn("/ctx/current");
        Mockito.when(request.getQueryString()).thenReturn("a=b");
        final Map<String, String> params = new HashMap<>();
        AuthUtil.sendRedirect(request, response, "relative", params);
        Mockito.verify(response).sendRedirect(Mockito.startsWith("/ctx?"));
    }

    // ---- jakarta sendInvalid with reason code ----

    @Test
    public void test_sendInvalid_withReasonCode_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        Mockito.when(request.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON))
                .thenReturn("bad");
        Mockito.when(request.getAttribute(JakartaAuthenticationHandler.FAILURE_REASON_CODE))
                .thenReturn("code42");
        Mockito.when(response.getWriter()).thenReturn(new java.io.PrintWriter(new java.io.StringWriter()));
        AuthUtil.sendInvalid(request, response);
        Mockito.verify(response).setHeader(AuthConstants.X_REASON_CODE, "code42");
    }

    // ---- IOException error paths ----

    @Test
    public void test_sendValid_ioexception_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        Mockito.doThrow(new IOException("boom")).when(response).flushBuffer();
        AuthUtil.sendValid(response);
    }

    @Test
    public void test_sendValid_ioexception_javax() throws Exception {
        javax.servlet.http.HttpServletResponse response = Mockito.mock(javax.servlet.http.HttpServletResponse.class);
        Mockito.doThrow(new IOException("boom")).when(response).flushBuffer();
        AuthUtil.sendValid(response);
    }

    @Test
    public void test_sendInvalid_ioexception_jakarta() throws Exception {
        jakarta.servlet.http.HttpServletRequest request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        jakarta.servlet.http.HttpServletResponse response =
                Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        Mockito.doThrow(new IOException("boom")).when(response).flushBuffer();
        AuthUtil.sendInvalid(request, response);
    }

    @Test
    public void test_sendInvalid_ioexception_javax() throws Exception {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpServletResponse response = Mockito.mock(javax.servlet.http.HttpServletResponse.class);
        Mockito.doThrow(new IOException("boom")).when(response).flushBuffer();
        AuthUtil.sendInvalid(request, response);
    }

    // ---- javax checkReferer malformed URL ----

    @Test
    public void test_checkReferer_malformedUrl_javax() {
        javax.servlet.http.HttpServletRequest request = Mockito.mock(javax.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getMethod()).thenReturn("POST");
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getHeader("Referer")).thenReturn("::: not a url :::");
        Assert.assertTrue(AuthUtil.checkReferer(request, "/login"));
    }
}
