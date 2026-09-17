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
package org.apache.sling.auth.core.spi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.junit.Assert;
import org.junit.Test;

import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class DefaultJakartaAuthenticationFeedbackHandlerTest {

    @Test
    public void test_no_redirect() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        // no redirect parameter and no login resource -> false
        Assert.assertFalse(DefaultJakartaAuthenticationFeedbackHandler.handleRedirect(request, response));
    }

    @Test
    public void test_redirect_true_uses_requestUri() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(AuthenticationSupport.REDIRECT_PARAMETER)).thenReturn("true");
        when(request.getRequestURI()).thenReturn("/same/uri");
        Assert.assertTrue(DefaultJakartaAuthenticationFeedbackHandler.handleRedirect(request, response));
        verify(response).sendRedirect("/same/uri");
    }

    @Test
    public void test_redirect_empty_uses_requestUri() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(AuthenticationSupport.REDIRECT_PARAMETER)).thenReturn("");
        when(request.getRequestURI()).thenReturn("/same/uri");
        Assert.assertTrue(DefaultJakartaAuthenticationFeedbackHandler.handleRedirect(request, response));
        verify(response).sendRedirect("/same/uri");
    }

    @Test
    public void test_redirect_absolute_valid() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(AuthenticationSupport.REDIRECT_PARAMETER)).thenReturn("/valid/path");
        when(request.getContextPath()).thenReturn("");
        Assert.assertTrue(DefaultJakartaAuthenticationFeedbackHandler.handleRedirect(request, response));
        verify(response).sendRedirect("/valid/path");
    }

    @Test
    public void test_redirect_relative_made_absolute() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(AuthenticationSupport.REDIRECT_PARAMETER)).thenReturn("rel");
        when(request.getRequestURI()).thenReturn("/base/page");
        when(request.getContextPath()).thenReturn("");
        Assert.assertTrue(DefaultJakartaAuthenticationFeedbackHandler.handleRedirect(request, response));
        verify(response).sendRedirect("/base/rel");
    }

    @Test
    public void test_redirect_invalid_falls_back_to_root() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(AuthenticationSupport.REDIRECT_PARAMETER)).thenReturn("/invalid//path");
        when(request.getContextPath()).thenReturn("");
        Assert.assertTrue(DefaultJakartaAuthenticationFeedbackHandler.handleRedirect(request, response));
        verify(response).sendRedirect("/");
    }

    @Test
    public void test_redirect_send_failure_is_swallowed() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter(AuthenticationSupport.REDIRECT_PARAMETER)).thenReturn("/valid");
        when(request.getContextPath()).thenReturn("");
        doThrow(new java.io.IOException("boom")).when(response).sendRedirect(anyString());
        Assert.assertTrue(DefaultJakartaAuthenticationFeedbackHandler.handleRedirect(request, response));
    }

    @Test
    public void test_authenticationFailed_noop() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        DefaultJakartaAuthenticationFeedbackHandler handler = new DefaultJakartaAuthenticationFeedbackHandler();
        handler.authenticationFailed(request, response, new AuthenticationInfo("test"));
        verifyNoInteractions(response);
    }

    @Test
    public void test_authenticationSucceeded_delegates() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        DefaultJakartaAuthenticationFeedbackHandler handler = new DefaultJakartaAuthenticationFeedbackHandler();
        Assert.assertFalse(handler.authenticationSucceeded(request, response, new AuthenticationInfo("test")));
    }
}
