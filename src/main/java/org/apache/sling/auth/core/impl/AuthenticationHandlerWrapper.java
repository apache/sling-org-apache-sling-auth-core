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

import org.apache.sling.api.wrappers.JakartaToJavaxRequestWrapper;
import org.apache.sling.api.wrappers.JakartaToJavaxResponseWrapper;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.JakartaAuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.JakartaAuthenticationHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@SuppressWarnings("deprecation")
public class AuthenticationHandlerWrapper {

    public static JakartaAuthenticationHandler wrap(final AuthenticationHandler handler) {
        if (handler instanceof AuthenticationFeedbackHandler) {
            return new FeedbackHandlerWrapper(handler);

        }
        return new HandlerWrapper(handler);
    }

    private static class HandlerWrapper implements JakartaAuthenticationHandler {

        private final AuthenticationHandler handler;

        HandlerWrapper(final AuthenticationHandler handler) {
            this.handler = handler;
        }

        @Override
        public void dropCredentials(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
            handler.dropCredentials(
                JakartaToJavaxRequestWrapper.toJavaxRequest(request),
                JakartaToJavaxResponseWrapper.toJavaxResponse(response));
        }

        @Override
        public AuthenticationInfo extractCredentials(final HttpServletRequest request, final HttpServletResponse response) {
            return handler.extractCredentials(
            JakartaToJavaxRequestWrapper.toJavaxRequest(request),
            JakartaToJavaxResponseWrapper.toJavaxResponse(response));
        }

        @Override
        public boolean requestCredentials(final HttpServletRequest request, final HttpServletResponse response)
                throws IOException {
            return handler.requestCredentials(
                JakartaToJavaxRequestWrapper.toJavaxRequest(request),
                JakartaToJavaxResponseWrapper.toJavaxResponse(response));
        }
    }

    private static class FeedbackHandlerWrapper extends HandlerWrapper implements JakartaAuthenticationFeedbackHandler {

        private final AuthenticationFeedbackHandler handler;

        FeedbackHandlerWrapper(final AuthenticationHandler handler) {
            super(handler);
            this.handler = (AuthenticationFeedbackHandler)handler;
        }


        @Override
        public void authenticationFailed(final HttpServletRequest request, final HttpServletResponse response,
                final AuthenticationInfo authInfo) {
            handler.authenticationFailed(JakartaToJavaxRequestWrapper.toJavaxRequest(request),
                JakartaToJavaxResponseWrapper.toJavaxResponse(response), authInfo);
        }


        @Override
        public boolean authenticationSucceeded(final HttpServletRequest request, final HttpServletResponse response,
                final AuthenticationInfo authInfo) {
            return handler.authenticationSucceeded(JakartaToJavaxRequestWrapper.toJavaxRequest(request),
                JakartaToJavaxResponseWrapper.toJavaxResponse(response), authInfo);
        }
    }
}
