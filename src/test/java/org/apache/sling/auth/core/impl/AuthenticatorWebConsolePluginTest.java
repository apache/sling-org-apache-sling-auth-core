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
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.sling.auth.core.impl.hc.SetField;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthenticatorWebConsolePluginTest {

    private SlingAuthenticator.Config config;
    private AuthenticationHandlersManager handlersManager;

    @SuppressWarnings("unchecked")
    private PathBasedHolderCache<AuthenticationRequirementHolder> requirementsManager =
            mock(PathBasedHolderCache.class);

    private HttpServletRequest request = mock(HttpServletRequest.class);
    private HttpServletResponse response = mock(HttpServletResponse.class);

    @Before
    public void setup() throws Exception {
        config = mock(SlingAuthenticator.Config.class);
        when(config.sling_auth_anonymous_user()).thenReturn("");
        when(config.auth_sudo_cookie()).thenReturn("sling.sudo");
        when(config.auth_sudo_parameter()).thenReturn("sudo");

        handlersManager = mock(AuthenticationHandlersManager.class);
        Map<String, List<String>> handlerMap = new LinkedHashMap<>();
        handlerMap.put("/path/a", Arrays.asList("HandlerA", "HandlerB"));
        when(handlersManager.getAuthenticationHandlerMap()).thenReturn(handlerMap);

        when(requirementsManager.getHolders())
                .thenReturn(Arrays.asList(
                        new AuthenticationRequirementHolder("/secure", true, null),
                        new AuthenticationRequirementHolder("/public", false, null)));
    }

    private AuthenticatorWebConsolePlugin newPlugin() throws Exception {
        AuthenticatorWebConsolePlugin plugin = new AuthenticatorWebConsolePlugin(config);
        SetField.set(plugin, "authenticationHoldersManager", handlersManager);
        SetField.set(plugin, "authenticationRequirementsManager", requirementsManager);
        return plugin;
    }

    @Test
    public void test_doGet_rendersAllSections() throws Exception {
        AuthenticatorWebConsolePlugin plugin = newPlugin();
        StringWriter sw = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(sw));

        plugin.doGet(request, response);

        String out = sw.toString();
        Assert.assertTrue(out.contains("Registered Authentication Handler"));
        Assert.assertTrue(out.contains("/path/a"));
        Assert.assertTrue(out.contains("HandlerA"));
        Assert.assertTrue(out.contains("Authentication Requirement Configuration"));
        Assert.assertTrue(out.contains("/secure"));
        Assert.assertTrue(out.contains("Yes"));
        Assert.assertTrue(out.contains("/public"));
        Assert.assertTrue(out.contains("No"));
        Assert.assertTrue(out.contains("Miscellaneous Configuration"));
        Assert.assertTrue(out.contains("sling.sudo"));
        Assert.assertTrue(out.contains("sudo"));
    }

    @Test
    public void test_config_default_anonymous_user() throws Exception {
        when(config.sling_auth_anonymous_user()).thenReturn(null);
        AuthenticatorWebConsolePlugin plugin = newPlugin();
        StringWriter sw = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(sw));

        plugin.doGet(request, response);
        Assert.assertTrue(sw.toString().contains("(default)"));
    }

    @Test
    public void test_service_get_dispatches() throws Exception {
        AuthenticatorWebConsolePlugin plugin = newPlugin();
        StringWriter sw = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(sw));
        when(request.getMethod()).thenReturn("GET");
        when(request.getProtocol()).thenReturn("HTTP/1.1");

        plugin.service(request, response);
        Assert.assertTrue(sw.toString().contains("Registered Authentication Handler"));
    }

    @Test
    public void test_service_post_ignored() throws Exception {
        AuthenticatorWebConsolePlugin plugin = newPlugin();
        when(request.getMethod()).thenReturn("POST");

        plugin.service(request, response);
        verify(response, never()).getWriter();
    }

    @Test
    public void test_doGet_ioexception_sends_error() throws Exception {
        AuthenticatorWebConsolePlugin plugin = newPlugin();
        jakarta.servlet.ServletConfig scfg = mock(jakarta.servlet.ServletConfig.class);
        when(scfg.getServletContext()).thenReturn(mock(jakarta.servlet.ServletContext.class));
        plugin.init(scfg);
        when(response.getWriter()).thenThrow(new IOException("no writer"));

        plugin.doGet(request, response);
        verify(response).sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }

    @Test
    public void test_modified_updates_config() throws Exception {
        AuthenticatorWebConsolePlugin plugin = newPlugin();
        SlingAuthenticator.Config newConfig = mock(SlingAuthenticator.Config.class);
        when(newConfig.sling_auth_anonymous_user()).thenReturn(null);
        when(newConfig.auth_sudo_cookie()).thenReturn("c2");
        when(newConfig.auth_sudo_parameter()).thenReturn("p2");
        plugin.modified(newConfig);

        StringWriter sw = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(sw));
        plugin.doGet(request, response);
        Assert.assertTrue(sw.toString().contains("c2"));
        Assert.assertTrue(sw.toString().contains("p2"));
    }
}
