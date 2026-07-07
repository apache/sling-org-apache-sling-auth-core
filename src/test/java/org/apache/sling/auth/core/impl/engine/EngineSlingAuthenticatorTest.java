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
package org.apache.sling.auth.core.impl.engine;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.auth.core.impl.hc.SetField;
import org.apache.sling.engine.auth.NoAuthenticationHandlerException;
import org.junit.Assert;
import org.junit.Test;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("deprecation")
public class EngineSlingAuthenticatorTest {

    private HttpServletRequest request = mock(HttpServletRequest.class);
    private HttpServletResponse response = mock(HttpServletResponse.class);

    @Test
    public void test_login_delegates() throws Exception {
        EngineSlingAuthenticator bridge = new EngineSlingAuthenticator();
        org.apache.sling.api.auth.Authenticator delegate = mock(org.apache.sling.api.auth.Authenticator.class);
        SetField.set(bridge, "slingAuthenticator", delegate);

        bridge.login(request, response);
        verify(delegate).login((javax.servlet.http.HttpServletRequest) request, (javax.servlet.http.HttpServletResponse)
                response);
    }

    @Test
    public void test_login_wraps_exception() throws Exception {
        EngineSlingAuthenticator bridge = new EngineSlingAuthenticator();
        org.apache.sling.api.auth.Authenticator delegate = mock(org.apache.sling.api.auth.Authenticator.class);
        SetField.set(bridge, "slingAuthenticator", delegate);
        doThrow(new org.apache.sling.api.auth.NoAuthenticationHandlerException())
                .when(delegate)
                .login(
                        any(javax.servlet.http.HttpServletRequest.class),
                        any(javax.servlet.http.HttpServletResponse.class));

        try {
            bridge.login(request, response);
            Assert.fail("Expected NoAuthenticationHandlerException");
        } catch (NoAuthenticationHandlerException expected) {
            Assert.assertNotNull(expected.getCause());
        }
    }

    @Test
    public void test_logout_delegates() throws Exception {
        EngineSlingAuthenticator bridge = new EngineSlingAuthenticator();
        org.apache.sling.api.auth.Authenticator delegate = mock(org.apache.sling.api.auth.Authenticator.class);
        SetField.set(bridge, "slingAuthenticator", delegate);

        bridge.logout(request, response);
        verify(delegate)
                .logout((javax.servlet.http.HttpServletRequest) request, (javax.servlet.http.HttpServletResponse)
                        response);
    }
}
