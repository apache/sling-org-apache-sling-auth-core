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
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.JakartaAuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.JakartaAuthenticationHandler;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("deprecation")
public class AuthenticationHandlerWrapperTest {

    private interface FeedbackHandler extends AuthenticationHandler, AuthenticationFeedbackHandler {}

    @Test
    public void plainWrapperDelegatesAuthenticationHandlerMethods() throws IOException {
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);
        final JakartaAuthenticationHandler wrapper = AuthenticationHandlerWrapper.wrap(handler);
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final AuthenticationInfo authInfo = new AuthenticationInfo("legacy");
        when(handler.extractCredentials(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class)))
                .thenReturn(authInfo);
        when(handler.requestCredentials(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class)))
                .thenReturn(true);

        assertFalse(wrapper instanceof JakartaAuthenticationFeedbackHandler);
        assertSame(authInfo, wrapper.extractCredentials(request, response));
        assertTrue(wrapper.requestCredentials(request, response));
        wrapper.dropCredentials(request, response);

        final ArgumentCaptor<javax.servlet.http.HttpServletRequest> requestCaptor =
                ArgumentCaptor.forClass(javax.servlet.http.HttpServletRequest.class);
        final ArgumentCaptor<javax.servlet.http.HttpServletResponse> responseCaptor =
                ArgumentCaptor.forClass(javax.servlet.http.HttpServletResponse.class);
        verify(handler).extractCredentials(requestCaptor.capture(), responseCaptor.capture());
        verify(handler)
                .requestCredentials(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class));
        verify(handler)
                .dropCredentials(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class));
        assertNotNull(requestCaptor.getValue());
        assertNotNull(responseCaptor.getValue());
    }

    @Test
    public void feedbackWrapperDelegatesFeedbackMethods() {
        final FeedbackHandler handler = mock(FeedbackHandler.class);
        final JakartaAuthenticationHandler wrapper = AuthenticationHandlerWrapper.wrap(handler);
        final JakartaAuthenticationFeedbackHandler feedbackWrapper = (JakartaAuthenticationFeedbackHandler) wrapper;
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final AuthenticationInfo authInfo = new AuthenticationInfo("legacy");
        when(handler.authenticationSucceeded(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class),
                        any(AuthenticationInfo.class)))
                .thenReturn(true);

        feedbackWrapper.authenticationFailed(request, response, authInfo);
        assertTrue(feedbackWrapper.authenticationSucceeded(request, response, authInfo));

        verify(handler)
                .authenticationFailed(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class),
                        org.mockito.ArgumentMatchers.same(authInfo));
        verify(handler)
                .authenticationSucceeded(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class),
                        org.mockito.ArgumentMatchers.same(authInfo));
    }
}
