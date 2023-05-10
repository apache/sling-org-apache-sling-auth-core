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
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.resource.mapping.ResourceMapper;
import org.apache.sling.auth.core.AuthConstants;
import org.junit.Test;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceReference;

public class AuthenticationRequirementsManagerTest {

    private void assertPaths(final PathBasedHolderCache<AuthenticationRequirementHolder> cache,
            final String[] paths,
            final ServiceReference<?>[] refs) {
        assertPaths(cache, paths, refs, null);
    }

    private void assertPaths(final PathBasedHolderCache<AuthenticationRequirementHolder> cache,
            final String[] paths,
            final ServiceReference<?>[] refs,
            final boolean[] requireAuth) {
        assertEquals("Wrong input to assert paths", paths.length, refs.length);
        if ( requireAuth != null ) {
            assertEquals("Wrong input to assert paths", paths.length, requireAuth.length);
        }

        // there are three default entries
        assertEquals(3 + paths.length, cache.getHolders().size());
        for(final AuthenticationRequirementHolder h : cache.getHolders()) {
            boolean found = Arrays.asList(LoginServlet.SERVLET_PATH, LogoutServlet.SERVLET_PATH, "/").contains(h.path);
            if ( !found ) {
                int index = 0 ;
                while ( !found && index < paths.length ) {
                    if (paths[index].equals(h.path) && ((refs[index] == null && h.serviceReference == null) || refs[index].equals(h.serviceReference)) ) {
                        found = true;
    
                        if ( requireAuth != null ) {
                            assertEquals(requireAuth[index], h.requiresAuthentication());
                        }
                    } else {
                        index++;
                    }
                }
            }
            assertTrue(Arrays.toString(paths) + " should contain " + h.path, found);    
        }
    }

    private long serviceId = 1;

    private final List<ServiceReference<?>> refs = new ArrayList<>();

    private ServiceReference<?> createServiceReference(final String[] paths) {
        final ServiceReference<?> ref = mock(ServiceReference.class);
        when(ref.getProperty(AuthConstants.AUTH_REQUIREMENTS)).thenReturn(paths);
        when(ref.getProperty(Constants.SERVICE_ID)).thenReturn(serviceId);
        serviceId++;

        for(final ServiceReference<?> r : refs) {
            when(ref.compareTo(r)).thenReturn(1);
            when(r.compareTo(ref)).thenReturn(-1);
        }
        when(ref.compareTo(ref)).thenReturn(0);

        final Bundle bundle = mock(Bundle.class);
        when(bundle.getBundleId()).thenReturn(1L);
        when(ref.getBundle()).thenReturn(bundle);
        
        refs.add(ref);
        return ref;
    }

    private ResourceResolverFactory createFactoryForMapper(final ResourceMapper mapper) throws LoginException {
        final ResourceResolverFactory factory = mock(ResourceResolverFactory.class);

        final ResourceResolver resolver = mock(ResourceResolver.class);

        when(factory.getServiceResourceResolver(null)).thenReturn(resolver);

        when(resolver.adaptTo(ResourceMapper.class)).thenReturn(mapper);

        return factory;
    }

    private static final long BUNDLE_ID = 732;

    private BundleContext createBundleContext() {
        final BundleContext context = mock(BundleContext.class);
        final Bundle bundle = mock(Bundle.class);
        when(bundle.getBundleId()).thenReturn(BUNDLE_ID);
        when(context.getBundle()).thenReturn(bundle);
        return context;
    }
    
    @Test public void testAddRemoveRegistration() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(mapper), 
            SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        assertEquals(3, manager.getHolders().size());

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(manager, new String[] {"/path1"},
                           new ServiceReference<?>[] {ref});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertEquals(3, manager.getHolders().size());
    }

    @Test public void testAddUpdateRemoveRegistration() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path1a"));
        when(mapper.getAllMappings("/path2")).thenReturn(Arrays.asList("/path2", "/path2a"));
        when(mapper.getAllMappings("/path3")).thenReturn(Arrays.asList("/path3", "/path3a"));

        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(mapper), 
                SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        // add
        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1", "/path2"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(manager, new String[] {"/path1", "/path1a", "/path2", "/path2a"},
                           new ServiceReference<?>[] {ref, ref, ref, ref},
                           new boolean[] {true, true, true, true});

        // update
        when(ref.getProperty(AuthConstants.AUTH_REQUIREMENTS)).thenReturn(new String[] {"/path2", "/path3"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.MODIFIED, ref));

        assertPaths(manager, new String[] {"/path2", "/path2a", "/path3", "/path3a"},
                new ServiceReference<?>[] {ref, ref, ref, ref},
                new boolean[] {true, true, true, true});

        // remmove
        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertEquals(3, manager.getHolders().size());
    }

    @Test public void testDuplicateRegistration() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        when(mapper.getAllMappings("/path2")).thenReturn(Collections.singleton("/path2"));
        when(mapper.getAllMappings("/path3")).thenReturn(Collections.singleton("/path3"));
        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(mapper), 
                 SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        final ServiceReference<?> ref1 = createServiceReference(new String[] {"/path1", "/path1", "/path2"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref1));

        final ServiceReference<?> ref2 = createServiceReference(new String[] {"/path2", "/path3"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref2));
        assertPaths(manager, new String[] {"/path1", "/path2", "/path2", "/path3"},
                           new ServiceReference<?>[] {ref1, ref1, ref2, ref2});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref2));

        assertPaths(manager, new String[] {"/path1", "/path2"},
                           new ServiceReference<?>[] {ref1, ref1});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref1));
        assertEquals(3, manager.getHolders().size());
    }

    @Test public void testAddRemoveRegistrations() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        when(mapper.getAllMappings("/path2")).thenReturn(Collections.singleton("/path2"));
        when(mapper.getAllMappings("/path3")).thenReturn(Collections.singleton("/path3"));
        when(mapper.getAllMappings("/path4")).thenReturn(Collections.singleton("/path4"));
        when(mapper.getAllMappings("/path5")).thenReturn(Collections.singleton("/path5"));
        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(mapper),
                  SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        final ServiceReference<?> ref1 = createServiceReference(new String[] {"/path1"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref1));

        final ServiceReference<?> ref2 = createServiceReference(new String[] {"/path2", "/path3"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref2));

        final ServiceReference<?> ref3 = createServiceReference(new String[] {"/path4", "/path5"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref3));

        assertPaths(manager, new String[] { "/path1", "/path2", "/path3", "/path4", "/path5"},
                           new ServiceReference<?>[] {ref1, ref2, ref2, ref3, ref3});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref2));

        assertPaths(manager, new String[] { "/path1", "/path4", "/path5"},
                new ServiceReference<?>[] {ref1, ref3, ref3});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref1));
        assertPaths(manager, new String[] { "/path4", "/path5"},
                new ServiceReference<?>[] {ref3, ref3});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref3));
        assertEquals(3, manager.getHolders().size());
    }

    @Test public void testModifyRegistration() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        when(mapper.getAllMappings("/path2")).thenReturn(Collections.singleton("/path2"));
        when(mapper.getAllMappings("/path3")).thenReturn(Collections.singleton("/path3"));
        when(mapper.getAllMappings("/path4")).thenReturn(Collections.singleton("/path4"));
        when(mapper.getAllMappings("/path5")).thenReturn(Collections.singleton("/path5"));
        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(mapper),
                 SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        final ServiceReference<?> ref1 = createServiceReference(new String[] {"/path1", "/path2", "/path3"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref1));
        assertPaths(manager, new String[] { "/path1", "/path2", "/path3"},
                new ServiceReference<?>[] {ref1, ref1, ref1});

        when(ref1.getProperty(AuthConstants.AUTH_REQUIREMENTS)).thenReturn(new String[] {"/path1", "/path4", "/path5"});
        assertPaths(manager, new String[] { "/path1", "/path2", "/path3"},
                new ServiceReference<?>[] {ref1, ref1, ref1});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.MODIFIED, ref1));
        assertPaths(manager, new String[] { "/path1", "/path4", "/path5"},
                new ServiceReference<?>[] {ref1, ref1, ref1});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.MODIFIED_ENDMATCH, ref1));
        assertEquals(3, manager.getHolders().size());
    }

    @Test public void testRegistrationWithMapping() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path2", "/path3"));
        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(mapper),
                SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(manager, new String[] {"/path1", "/path2", "/path3"},
                           new ServiceReference<?>[] {ref, ref, ref});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertEquals(3, manager.getHolders().size());
    }

    @Test public void testRegistrationAndUpdatingMapping() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path2", "/path3"));
        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(mapper),
                SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(manager, new String[] {"/path1", "/path2", "/path3"},
                           new ServiceReference<?>[] {ref, ref, ref});

        // update mapper
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path5"));
        manager.handleEvent(null);

        assertPaths(manager, new String[] {"/path1", "/path5"},
                new ServiceReference<?>[] {ref, ref});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertEquals(3, manager.getHolders().size());
    }

    // see SLING-11867
    @Test public void testRegistrationWithEmptyMapping() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);

        // Resourcemapper returns empty mapping
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", ""));

        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(mapper),
                SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        // register
        final ServiceReference<?> ref = createServiceReference(new String[] {"+/path1"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        // Allow anonymous enable/disable also add an entry for "/"
        // As config for test has anonymous enabled ("-/" -> false)
        // We can check if empty mapping has added "+/"
        assertPaths(manager, new String[] {"/path1", "/"},
                new ServiceReference<?>[] {ref, ref},
                new boolean[] {true, true});
    }

    @Test public void testAllowDeny() throws LoginException {
        final BundleContext context = createBundleContext();

        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(null),
            SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        final ServiceReference<?> ref = createServiceReference(new String[] {"-/path1", "+/path2", "/path3"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(manager, new String[] {"/path1", "/path2", "/path3"},
                           new ServiceReference<?>[] {ref, ref, ref},
                           new boolean[] {false, true, true});
    }

    @Test public void testAllowDenyWithMapping() throws LoginException {
        final BundleContext context = createBundleContext();

        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path1a", "/path1b"));
        when(mapper.getAllMappings("/path2")).thenReturn(Arrays.asList("/path2", "/path2a", "/path2b"));
        when(mapper.getAllMappings("/path3")).thenReturn(Arrays.asList("/path3", "/path3a", "/path3b"));
        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context, createFactoryForMapper(mapper),
            SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        final ServiceReference<?> ref = createServiceReference(new String[] {"-/path1", "+/path2", "/path3"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(manager, new String[] {"/path1", "/path2", "/path3", "/path1a", "/path2a", "/path3a", "/path1b", "/path2b", "/path3b"},
                           new ServiceReference<?>[] {ref, ref, ref, ref, ref, ref, ref, ref, ref},
                           new boolean[] {false, true, true, false, true, true, false, true, true});

        // update mapping
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path1c"));
        when(mapper.getAllMappings("/path2")).thenReturn(Arrays.asList("/path2", "/path2c"));
        when(mapper.getAllMappings("/path3")).thenReturn(Arrays.asList("/path3", "/path3c"));
        manager.handleEvent(null);

        assertPaths(manager, new String[] {"/path1", "/path2", "/path3", "/path1c", "/path2c", "/path3c"},
                new ServiceReference<?>[] {ref, ref, ref, ref, ref, ref},
                new boolean[] {false, true, true, false, true, true});
    }

    @Test public void testSwitchAllowDeny() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path1a"));
        when(mapper.getAllMappings("/path2")).thenReturn(Arrays.asList("/path2", "/path2a"));

        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context,  createFactoryForMapper(mapper),
            SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        // add
        final ServiceReference<?> ref = createServiceReference(new String[] {"+/path1", "-/path2"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(manager, new String[] {"/path1", "/path1a", "/path2", "/path2a"},
                           new ServiceReference<?>[] {ref, ref, ref, ref},
                           new boolean[] {true, true, false, false});

        // update
        when(ref.getProperty(AuthConstants.AUTH_REQUIREMENTS)).thenReturn(new String[] {"-/path1", "/path2"});
        manager.serviceChanged(new ServiceEvent(ServiceEvent.MODIFIED, ref));

        assertPaths(manager, new String[] {"/path1", "/path1a", "/path2", "/path2a"},
                new ServiceReference<?>[] {ref, ref, ref, ref},
                new boolean[] {false, false, true, true});

        // remmove
        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertEquals(3, manager.getHolders().size());
    }

    @Test public void testIgnoreRegistrationFromAuthCoreBundle() throws LoginException {
        final BundleContext context = createBundleContext();
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context, createFactoryForMapper(mapper), 
            SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        assertEquals(3, manager.getHolders().size());

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});
        when(ref.getBundle().getBundleId()).thenReturn(BUNDLE_ID);
        manager.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertEquals(3, manager.getHolders().size());

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertEquals(3, manager.getHolders().size());
    }

    @Test public void testInitialServices() throws Exception {
        final BundleContext context = createBundleContext();

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});

        when(context.getAllServiceReferences(null, "(".concat(AuthConstants.AUTH_REQUIREMENTS).concat("=*)")))
            .thenReturn(new ServiceReference[] {ref});

        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context, createFactoryForMapper(mapper), 
            SlingAuthenticatorTest.createDefaultConfig(), callable -> callable.run());

        assertPaths(manager, new String[] {"/path1"},
                           new ServiceReference<?>[] {ref});

        manager.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertEquals(3, manager.getHolders().size());
    }

    @Test public void testInitialConfiguration() throws Exception {
        final BundleContext context = createBundleContext();

        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        when(config.sling_auth_requirements()).thenReturn(new String[] {"/path1", "-/path2"});

        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        when(mapper.getAllMappings("/path2")).thenReturn(Collections.singleton("/path2"));

        final AuthenticationRequirementsManager manager = new AuthenticationRequirementsManager(context, createFactoryForMapper(mapper), 
                config, callable -> callable.run());

        assertPaths(manager, new String[] {"/path1", "/path2"},
                           new ServiceReference<?>[] {null, null},
                           new boolean[] {true, false});

    }
}
