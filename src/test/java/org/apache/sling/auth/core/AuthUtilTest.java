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

import jakarta.servlet.http.HttpServletRequest;
import org.apache.sling.api.resource.NonExistingResource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.SyntheticResource;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

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
}
