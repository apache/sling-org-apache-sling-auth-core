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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import junitx.util.PrivateAccessor;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.junit.Test;
import org.osgi.framework.ServiceReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthenticationHandlersManagerTest {

    @Test
    public void testDefaultConfiguration() {
        final AuthenticationHandlersManager manager =
                new AuthenticationHandlersManager(SlingAuthenticatorTest.createDefaultConfig());

        final Map<String, List<String>> map = manager.getAuthenticationHandlerMap();
        assertEquals(1, map.size());
        final List<String> list = map.get("/");
        assertNotNull(list);
        assertEquals(1, list.size());
        assertEquals("HTTP Basic Authentication Handler (preemptive)", list.get(0));
    }

    @Test
    public void testDefaultConfigurationDisabled() {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_DISABLED);
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(config);

        final Map<String, List<String>> map = manager.getAuthenticationHandlerMap();
        assertTrue(map.isEmpty());
    }

    @Test
    public void testDefaultConfigurationEnabled() {
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

    private void assertPaths(
            final PathBasedHolderCache<AbstractAuthenticationHandlerHolder> cache,
            final String[] paths,
            final ServiceReference<?>[] refs) {
        assertEquals("Wrong input to assert paths", paths.length, refs.length);

        for (final AbstractAuthenticationHandlerHolder h : cache.getHolders()) {
            int index = 0;
            boolean found = false;
            while (!found && index < paths.length) {
                if (paths[index].equals(h.path) && refs[index].equals(h.serviceReference)) {
                    found = true;

                } else {
                    index++;
                }
            }
            assertTrue(Arrays.toString(paths) + " should contain " + h.path, found);
        }
    }

    private long serviceId = 1;

    private final List<ServiceReference<?>> refs = new ArrayList<>();

    @SuppressWarnings("deprecation")
    private ServiceReference<?> createServiceReference(final String[] paths) {
        final ServiceReference<?> ref = mock(ServiceReference.class);
        when(ref.getProperty(org.apache.sling.engine.auth.AuthenticationHandler.PATH_PROPERTY))
                .thenReturn(paths);
        when(ref.getProperty(AuthenticationHandler.PATH_PROPERTY)).thenReturn(paths);
        when(ref.getProperty(org.osgi.framework.Constants.SERVICE_ID)).thenReturn(serviceId);
        serviceId++;

        for (final ServiceReference<?> r : refs) {
            when(ref.compareTo(r)).thenReturn(1);
            when(r.compareTo(ref)).thenReturn(-1);
        }
        when(ref.compareTo(ref)).thenReturn(0);

        refs.add(ref);
        return ref;
    }

    @Test
    public void testAddRemoveRegistration() throws Throwable {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_DISABLED);
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(config);

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);

        PrivateAccessor.invoke(
                manager,
                "bindAuthHandler",
                new Class[] {AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref});

        assertPaths(manager, new String[] {"/path1"}, new ServiceReference<?>[] {ref});

        PrivateAccessor.invoke(manager, "unbindAuthHandler", new Class[] {ServiceReference.class}, new Object[] {ref});

        assertTrue(manager.getHolders().isEmpty());
    }

    @Test
    public void testAddUpdateRemoveRegistration() throws Throwable {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_DISABLED);
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(config);

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1", "/path2"});
        final AuthenticationHandler handler = mock(AuthenticationHandler.class);

        // add
        PrivateAccessor.invoke(
                manager,
                "bindAuthHandler",
                new Class[] {AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref});

        assertPaths(manager, new String[] {"/path1", "/path2"}, new ServiceReference<?>[] {ref, ref});

        // update
        when(ref.getProperty(AuthenticationHandler.PATH_PROPERTY)).thenReturn(new String[] {"/path2", "/path3"});
        PrivateAccessor.invoke(
                manager,
                "updatedAuthHandler",
                new Class[] {AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref});

        assertPaths(manager, new String[] {"/path2", "/path3"}, new ServiceReference<?>[] {ref, ref});

        // remmove
        PrivateAccessor.invoke(manager, "unbindAuthHandler", new Class[] {ServiceReference.class}, new Object[] {ref});

        assertTrue(manager.getHolders().isEmpty());
    }

    @Test
    public void testDuplicateRegistration() throws Throwable {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_DISABLED);
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(config);

        final AuthenticationHandler handler = mock(AuthenticationHandler.class);

        // add
        final ServiceReference<?> ref1 = createServiceReference(new String[] {"/path1", "/path1", "/path2"});
        // add
        PrivateAccessor.invoke(
                manager,
                "bindAuthHandler",
                new Class[] {AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref1});

        final ServiceReference<?> ref2 = createServiceReference(new String[] {"/path2", "/path3"});
        // add
        PrivateAccessor.invoke(
                manager,
                "bindAuthHandler",
                new Class[] {AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref2});
        assertPaths(manager, new String[] {"/path1", "/path2", "/path2", "/path3"}, new ServiceReference<?>[] {
            ref1, ref1, ref2, ref2
        });

        PrivateAccessor.invoke(manager, "unbindAuthHandler", new Class[] {ServiceReference.class}, new Object[] {ref2});

        assertPaths(manager, new String[] {"/path1", "/path2"}, new ServiceReference<?>[] {ref1, ref1});

        PrivateAccessor.invoke(manager, "unbindAuthHandler", new Class[] {ServiceReference.class}, new Object[] {ref1});
        assertTrue(manager.getHolders().isEmpty());
    }

    @Deprecated
    @Test
    public void testAddRemoveRegistrationLegacy() throws Throwable {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_DISABLED);
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(config);

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});
        final org.apache.sling.engine.auth.AuthenticationHandler handler =
                mock(org.apache.sling.engine.auth.AuthenticationHandler.class);

        PrivateAccessor.invoke(
                manager,
                "bindEngineAuthHandler",
                new Class[] {org.apache.sling.engine.auth.AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref});

        assertPaths(manager, new String[] {"/path1"}, new ServiceReference<?>[] {ref});

        PrivateAccessor.invoke(
                manager, "unbindEngineAuthHandler", new Class[] {ServiceReference.class}, new Object[] {ref});

        assertTrue(manager.getHolders().isEmpty());
    }

    @Deprecated
    @Test
    public void testAddUpdateRemoveRegistrationLegacy() throws Throwable {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_DISABLED);
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(config);

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1", "/path2"});
        final org.apache.sling.engine.auth.AuthenticationHandler handler =
                mock(org.apache.sling.engine.auth.AuthenticationHandler.class);

        // add
        PrivateAccessor.invoke(
                manager,
                "bindEngineAuthHandler",
                new Class[] {org.apache.sling.engine.auth.AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref});

        assertPaths(manager, new String[] {"/path1", "/path2"}, new ServiceReference<?>[] {ref, ref});

        // update
        when(ref.getProperty(AuthenticationHandler.PATH_PROPERTY)).thenReturn(new String[] {"/path2", "/path3"});
        PrivateAccessor.invoke(
                manager,
                "updatedEngineAuthHandler",
                new Class[] {org.apache.sling.engine.auth.AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref});

        assertPaths(manager, new String[] {"/path2", "/path3"}, new ServiceReference<?>[] {ref, ref});

        // remmove
        PrivateAccessor.invoke(
                manager, "unbindEngineAuthHandler", new Class[] {ServiceReference.class}, new Object[] {ref});

        assertTrue(manager.getHolders().isEmpty());
    }

    @Deprecated
    @Test
    public void testDuplicateRegistrationLegacy() throws Throwable {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.auth_http()).thenReturn(SlingAuthenticator.HTTP_AUTH_DISABLED);
        final AuthenticationHandlersManager manager = new AuthenticationHandlersManager(config);

        final org.apache.sling.engine.auth.AuthenticationHandler handler =
                mock(org.apache.sling.engine.auth.AuthenticationHandler.class);

        // add
        final ServiceReference<?> ref1 = createServiceReference(new String[] {"/path1", "/path1", "/path2"});
        // add
        PrivateAccessor.invoke(
                manager,
                "bindEngineAuthHandler",
                new Class[] {org.apache.sling.engine.auth.AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref1});

        final ServiceReference<?> ref2 = createServiceReference(new String[] {"/path2", "/path3"});
        // add
        PrivateAccessor.invoke(
                manager,
                "bindEngineAuthHandler",
                new Class[] {org.apache.sling.engine.auth.AuthenticationHandler.class, ServiceReference.class},
                new Object[] {handler, ref2});
        assertPaths(manager, new String[] {"/path1", "/path2", "/path2", "/path3"}, new ServiceReference<?>[] {
            ref1, ref1, ref2, ref2
        });

        PrivateAccessor.invoke(
                manager, "unbindEngineAuthHandler", new Class[] {ServiceReference.class}, new Object[] {ref2});

        assertPaths(manager, new String[] {"/path1", "/path2"}, new ServiceReference<?>[] {ref1, ref1});

        PrivateAccessor.invoke(
                manager, "unbindEngineAuthHandler", new Class[] {ServiceReference.class}, new Object[] {ref1});
        assertTrue(manager.getHolders().isEmpty());
    }
}
