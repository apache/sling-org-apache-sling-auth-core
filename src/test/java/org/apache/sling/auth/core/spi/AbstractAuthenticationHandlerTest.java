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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.HashMap;
import java.util.Map;

import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.auth.core.AuthConstants;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

/**
 * Verifies that the deprecated {@link AbstractAuthenticationHandler} helper
 * methods delegate to {@link org.apache.sling.auth.core.AuthUtil}.
 */
@SuppressWarnings("deprecation")
public class AbstractAuthenticationHandlerTest {

    private HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    private HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    @Test
    public void test_getAttributeOrParameter() {
        Mockito.when(request.getParameter("p")).thenReturn("v");
        Assert.assertEquals("v", AbstractAuthenticationHandler.getAttributeOrParameter(request, "p", "def"));
    }

    @Test
    public void test_getLoginResource() {
        Mockito.when(request.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/res");
        Assert.assertEquals("/res", AbstractAuthenticationHandler.getLoginResource(request, "/def"));
    }

    @Test
    public void test_setLoginResourceAttribute() {
        Assert.assertEquals("/def", AbstractAuthenticationHandler.setLoginResourceAttribute(request, "/def"));
    }

    @Test
    public void test_sendRedirect() throws Exception {
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getRequestURI()).thenReturn("/current");
        Map<String, String> params = new HashMap<>();
        AbstractAuthenticationHandler.sendRedirect(request, response, "/target", params);
        Mockito.verify(response).sendRedirect(Mockito.contains("/target?"));
    }

    @Test
    public void test_isRedirectValid() {
        Assert.assertTrue(AbstractAuthenticationHandler.isRedirectValid(null, "/absolute/path"));
        Assert.assertFalse(AbstractAuthenticationHandler.isRedirectValid(null, "http://host"));
    }

    @Test
    public void test_isValidateRequest() {
        Mockito.when(request.getParameter(AuthConstants.PAR_J_VALIDATE)).thenReturn("true");
        Assert.assertTrue(AbstractAuthenticationHandler.isValidateRequest(request));
    }

    @Test
    public void test_sendValid() {
        AbstractAuthenticationHandler.sendValid(response);
        Mockito.verify(response).setStatus(HttpServletResponse.SC_OK);
    }

    @Test
    public void test_sendInvalid() {
        AbstractAuthenticationHandler.sendInvalid(request, response);
        Mockito.verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
