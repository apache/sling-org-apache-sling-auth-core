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
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.JakartaAuthenticationHandler;
import org.junit.Assert;
import org.junit.Test;

import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class HttpBasicAuthenticationHandlerTest {

    private HttpServletRequest request = mock(HttpServletRequest.class);
    private HttpServletResponse response = mock(HttpServletResponse.class);

    private static String basic(String user, String pass) {
        String raw = user + ":" + pass;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.ISO_8859_1));
    }

    @Test
    public void test_extractCredentials_valid() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        when(request.getHeader("Authorization")).thenReturn(basic("admin", "secret"));
        AuthenticationInfo info = handler.extractCredentials(request, response);
        Assert.assertNotNull(info);
        Assert.assertEquals("admin", info.getUser());
        Assert.assertArrayEquals("secret".toCharArray(), info.getPassword());
    }

    @Test
    public void test_extractCredentials_no_colon() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        String header = "Basic " + Base64.getEncoder().encodeToString("justuser".getBytes(StandardCharsets.ISO_8859_1));
        when(request.getHeader("Authorization")).thenReturn(header);
        AuthenticationInfo info = handler.extractCredentials(request);
        Assert.assertNotNull(info);
        Assert.assertEquals("justuser", info.getUser());
        Assert.assertEquals(0, info.getPassword().length);
    }

    @Test
    public void test_extractCredentials_no_header() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        Assert.assertNull(handler.extractCredentials(request));
        when(request.getHeader("Authorization")).thenReturn("");
        Assert.assertNull(handler.extractCredentials(request));
    }

    @Test
    public void test_extractCredentials_no_blank() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        when(request.getHeader("Authorization")).thenReturn("Basic");
        Assert.assertNull(handler.extractCredentials(request));
    }

    @Test
    public void test_extractCredentials_wrong_scheme() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        when(request.getHeader("Authorization")).thenReturn("Digest abc");
        Assert.assertNull(handler.extractCredentials(request));
    }

    @Test
    public void test_extractCredentials_login_requested() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        when(request.getHeader("Authorization")).thenReturn(null);
        when(request.getParameter(JakartaAuthenticationHandler.REQUEST_LOGIN_PARAMETER))
                .thenReturn("BASIC");
        AuthenticationInfo info = handler.extractCredentials(request, response);
        Assert.assertSame(AuthenticationInfo.DOING_AUTH, info);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void test_extractCredentials_no_login_requested() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        when(request.getHeader("Authorization")).thenReturn(null);
        Assert.assertNull(handler.extractCredentials(request, response));
    }

    @Test
    public void test_requestCredentials_fullSupport() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        Assert.assertTrue(handler.requestCredentials(request, response));
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void test_requestCredentials_preemptive() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", false);
        Assert.assertFalse(handler.requestCredentials(request, response));
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    public void test_dropCredentials_fullSupport_withHeader() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        when(request.getHeader("Authorization")).thenReturn("Basic xyz");
        handler.dropCredentials(request, response);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void test_dropCredentials_noHeader() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        when(request.getHeader("Authorization")).thenReturn(null);
        handler.dropCredentials(request, response);
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    public void test_authenticationFailed_notValidate() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        handler.authenticationFailed(request, response, new AuthenticationInfo("BASIC"));
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void test_authenticationFailed_validate() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        when(request.getParameter("j_validate")).thenReturn("true");
        handler.authenticationFailed(request, response, new AuthenticationInfo("BASIC"));
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    public void test_sendUnauthorized_committed() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        when(response.isCommitted()).thenReturn(true);
        Assert.assertFalse(handler.sendUnauthorized(response));
    }

    @Test
    public void test_sendUnauthorized_ok() {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        Assert.assertTrue(handler.sendUnauthorized(response));
        verify(response).setHeader("WWW-Authenticate", "Basic realm=\"realm\"");
    }

    @Test
    public void test_sendUnauthorized_ioexception() throws IOException {
        HttpBasicAuthenticationHandler handler = new HttpBasicAuthenticationHandler("realm", true);
        doThrow(new IOException("boom")).when(response).flushBuffer();
        Assert.assertFalse(handler.sendUnauthorized(response));
    }

    @Test
    public void test_toString() {
        Assert.assertTrue(
                new HttpBasicAuthenticationHandler("r", true).toString().contains("enabled"));
        Assert.assertTrue(
                new HttpBasicAuthenticationHandler("r", false).toString().contains("preemptive"));
    }
}
