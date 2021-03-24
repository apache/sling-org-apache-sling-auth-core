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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.Test;

public class AuthenticationHandlersTest {

    @Test public void testDefaultConfiguration() {
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(SlingAuthenticatorTest.createDefaultConfig());

        final Map<String, List<String>> map = manager.getAuthenticationHandlerMap();
        assertEquals(1, map.size());
        final List<String> list = map.get("/");
        assertNotNull(list);
        assertEquals(1, list.size());
        assertEquals("HTTP Basic Authentication Handler (preemptive)", list.get(0));
    }

    @Test public void testDefaultConfigurationDisabled() {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_DISABLED);
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(config);

        final Map<String, List<String>> map = manager.getAuthenticationHandlerMap();
        assertTrue(map.isEmpty());
    }

    @Test public void testDefaultConfigurationEnabled() {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_ENABLED);
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(config);

        final Map<String, List<String>> map = manager.getAuthenticationHandlerMap();
        assertEquals(1, map.size());
        final List<String> list = map.get("/");
        assertNotNull(list);
        assertEquals(1, list.size());
        assertEquals("HTTP Basic Authentication Handler (enabled)", list.get(0));
    }
}
