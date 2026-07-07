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

import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.auth.core.impl.hc.SetField;
import org.junit.Test;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class LogoutServletTest {

    private SlingHttpServletRequest request = mock(SlingHttpServletRequest.class);
    private SlingHttpServletResponse response = mock(SlingHttpServletResponse.class);

    @Test
    public void test_logout_success() throws Exception {
        LogoutServlet servlet = new LogoutServlet();
        Authenticator authenticator = mock(Authenticator.class);
        SetField.set(servlet, "authenticator", authenticator);

        servlet.service(request, response);
        verify(authenticator)
                .logout((javax.servlet.http.HttpServletRequest) request, (javax.servlet.http.HttpServletResponse)
                        response);
    }

    @Test
    public void test_logout_no_authenticator() throws Exception {
        LogoutServlet servlet = new LogoutServlet();
        servlet.service(request, response);
        verify(response).setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @Test
    public void test_logout_response_committed() throws Exception {
        LogoutServlet servlet = new LogoutServlet();
        Authenticator authenticator = mock(Authenticator.class);
        SetField.set(servlet, "authenticator", authenticator);
        doThrow(new IllegalStateException("committed"))
                .when(authenticator)
                .logout(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class));

        servlet.service(request, response);
        verify(response, never()).setStatus(anyInt());
    }
}
