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
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceReference;

public class SlingAuthenticatorServiceListenerTest {

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

        assertEquals(paths.length, cache.getHolders().size());
        for(final AuthenticationRequirementHolder h : cache.getHolders()) {
            boolean found = false;
            int index = 0;
            while ( !found && index < paths.length ) {
                if (paths[index].equals(h.path) && refs[index].equals(h.serviceReference) ) {
                    found = true;

                    if ( requireAuth != null ) {
                        assertEquals(requireAuth[index], h.requiresAuthentication());
                    }
                } else {
                    index++;
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

    @Test public void testAddRemoveRegistration() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(mapper), cache);

        assertTrue(cache.getHolders().isEmpty());

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(cache, new String[] {"/path1"},
                           new ServiceReference<?>[] {ref});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertTrue(cache.getHolders().isEmpty());
    }

    @Test public void testAddUpdateRemoveRegistration() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path1a"));
        when(mapper.getAllMappings("/path2")).thenReturn(Arrays.asList("/path2", "/path2a"));
        when(mapper.getAllMappings("/path3")).thenReturn(Arrays.asList("/path3", "/path3a"));

        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(mapper), cache);

        // add
        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1", "/path2"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(cache, new String[] {"/path1", "/path1a", "/path2", "/path2a"},
                           new ServiceReference<?>[] {ref, ref, ref, ref},
                           new boolean[] {true, true, true, true});

        // update
        when(ref.getProperty(AuthConstants.AUTH_REQUIREMENTS)).thenReturn(new String[] {"/path2", "/path3"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.MODIFIED, ref));

        assertPaths(cache, new String[] {"/path2", "/path2a", "/path3", "/path3a"},
                new ServiceReference<?>[] {ref, ref, ref, ref},
                new boolean[] {true, true, true, true});

        // remmove
        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertTrue(cache.getHolders().isEmpty());
    }

    @Test public void testDuplicateRegistration() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        when(mapper.getAllMappings("/path2")).thenReturn(Collections.singleton("/path2"));
        when(mapper.getAllMappings("/path3")).thenReturn(Collections.singleton("/path3"));
        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(mapper), cache);

        final ServiceReference<?> ref1 = createServiceReference(new String[] {"/path1", "/path1", "/path2"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref1));

        final ServiceReference<?> ref2 = createServiceReference(new String[] {"/path2", "/path3"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref2));
        assertPaths(cache, new String[] {"/path1", "/path2", "/path2", "/path3"},
                           new ServiceReference<?>[] {ref1, ref1, ref2, ref2});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref2));

        assertPaths(cache, new String[] {"/path1", "/path2"},
                           new ServiceReference<?>[] {ref1, ref1});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref1));
        assertTrue(cache.getHolders().isEmpty());
    }

    @Test public void testAddRemoveRegistrations() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        when(mapper.getAllMappings("/path2")).thenReturn(Collections.singleton("/path2"));
        when(mapper.getAllMappings("/path3")).thenReturn(Collections.singleton("/path3"));
        when(mapper.getAllMappings("/path4")).thenReturn(Collections.singleton("/path4"));
        when(mapper.getAllMappings("/path5")).thenReturn(Collections.singleton("/path5"));
        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(mapper), cache);

        final ServiceReference<?> ref1 = createServiceReference(new String[] {"/path1"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref1));

        final ServiceReference<?> ref2 = createServiceReference(new String[] {"/path2", "/path3"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref2));

        final ServiceReference<?> ref3 = createServiceReference(new String[] {"/path4", "/path5"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref3));

        assertPaths(cache, new String[] { "/path1", "/path2", "/path3", "/path4", "/path5"},
                           new ServiceReference<?>[] {ref1, ref2, ref2, ref3, ref3});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref2));

        assertPaths(cache, new String[] { "/path1", "/path4", "/path5"},
                new ServiceReference<?>[] {ref1, ref3, ref3});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref1));
        assertPaths(cache, new String[] { "/path4", "/path5"},
                new ServiceReference<?>[] {ref3, ref3});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref3));
        assertTrue(cache.getHolders().isEmpty());
    }

    @Test public void testModifyRegistration() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Collections.singleton("/path1"));
        when(mapper.getAllMappings("/path2")).thenReturn(Collections.singleton("/path2"));
        when(mapper.getAllMappings("/path3")).thenReturn(Collections.singleton("/path3"));
        when(mapper.getAllMappings("/path4")).thenReturn(Collections.singleton("/path4"));
        when(mapper.getAllMappings("/path5")).thenReturn(Collections.singleton("/path5"));
        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(mapper), cache);

        final ServiceReference<?> ref1 = createServiceReference(new String[] {"/path1", "/path2", "/path3"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref1));
        assertPaths(cache, new String[] { "/path1", "/path2", "/path3"},
                new ServiceReference<?>[] {ref1, ref1, ref1});

        when(ref1.getProperty(AuthConstants.AUTH_REQUIREMENTS)).thenReturn(new String[] {"/path1", "/path4", "/path5"});
        assertPaths(cache, new String[] { "/path1", "/path2", "/path3"},
                new ServiceReference<?>[] {ref1, ref1, ref1});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.MODIFIED, ref1));
        assertPaths(cache, new String[] { "/path1", "/path4", "/path5"},
                new ServiceReference<?>[] {ref1, ref1, ref1});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.MODIFIED_ENDMATCH, ref1));
        assertTrue(cache.getHolders().isEmpty());

    }

    @Test public void testRegistrationWithMapping() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path2", "/path3"));
        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(mapper), cache);

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(cache, new String[] {"/path1", "/path2", "/path3"},
                           new ServiceReference<?>[] {ref, ref, ref});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertTrue(cache.getHolders().isEmpty());
    }

    @Test public void testRegistrationAndUpdatingMapping() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path2", "/path3"));
        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(mapper), cache);

        final ServiceReference<?> ref = createServiceReference(new String[] {"/path1"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(cache, new String[] {"/path1", "/path2", "/path3"},
                           new ServiceReference<?>[] {ref, ref, ref});

        // update mapper
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path5"));
        listener.handleEvent(null);

        assertPaths(cache, new String[] {"/path1", "/path5"},
                new ServiceReference<?>[] {ref, ref});

        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertTrue(cache.getHolders().isEmpty());
    }

    @Test public void testAllowDeny() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);

        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(null), cache);

        final ServiceReference<?> ref = createServiceReference(new String[] {"-/path1", "+/path2", "/path3"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(cache, new String[] {"/path1", "/path2", "/path3"},
                           new ServiceReference<?>[] {ref, ref, ref},
                           new boolean[] {false, true, true});
    }

    @Test public void testAllowDenyWithMapping() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);

        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path1a", "/path1b"));
        when(mapper.getAllMappings("/path2")).thenReturn(Arrays.asList("/path2", "/path2a", "/path2b"));
        when(mapper.getAllMappings("/path3")).thenReturn(Arrays.asList("/path3", "/path3a", "/path3b"));
        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(mapper), cache);

        final ServiceReference<?> ref = createServiceReference(new String[] {"-/path1", "+/path2", "/path3"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(cache, new String[] {"/path1", "/path2", "/path3", "/path1a", "/path2a", "/path3a", "/path1b", "/path2b", "/path3b"},
                           new ServiceReference<?>[] {ref, ref, ref, ref, ref, ref, ref, ref, ref},
                           new boolean[] {false, true, true, false, true, true, false, true, true});

        // update mapping
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path1c"));
        when(mapper.getAllMappings("/path2")).thenReturn(Arrays.asList("/path2", "/path2c"));
        when(mapper.getAllMappings("/path3")).thenReturn(Arrays.asList("/path3", "/path3c"));
        listener.handleEvent(null);

        assertPaths(cache, new String[] {"/path1", "/path2", "/path3", "/path1c", "/path2c", "/path3c"},
                new ServiceReference<?>[] {ref, ref, ref, ref, ref, ref},
                new boolean[] {false, true, true, false, true, true});
    }

    @Test public void testSwitchAllowDeny() throws LoginException {
        final PathBasedHolderCache<AuthenticationRequirementHolder> cache = new PathBasedHolderCache<AuthenticationRequirementHolder>();
        final BundleContext context = mock(BundleContext.class);
        final ResourceMapper mapper = mock(ResourceMapper.class);
        when(mapper.getAllMappings("/path1")).thenReturn(Arrays.asList("/path1", "/path1a"));
        when(mapper.getAllMappings("/path2")).thenReturn(Arrays.asList("/path2", "/path2a"));

        final SlingAuthenticatorServiceListener listener = SlingAuthenticatorServiceListener.createListener(context, callable -> callable.run(), createFactoryForMapper(mapper), cache);

        // add
        final ServiceReference<?> ref = createServiceReference(new String[] {"+/path1", "-/path2"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, ref));

        assertPaths(cache, new String[] {"/path1", "/path1a", "/path2", "/path2a"},
                           new ServiceReference<?>[] {ref, ref, ref, ref},
                           new boolean[] {true, true, false, false});

        // update
        when(ref.getProperty(AuthConstants.AUTH_REQUIREMENTS)).thenReturn(new String[] {"-/path1", "/path2"});
        listener.serviceChanged(new ServiceEvent(ServiceEvent.MODIFIED, ref));

        assertPaths(cache, new String[] {"/path1", "/path1a", "/path2", "/path2a"},
                new ServiceReference<?>[] {ref, ref, ref, ref},
                new boolean[] {false, false, true, true});

        // remmove
        listener.serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, ref));

        assertTrue(cache.getHolders().isEmpty());
    }
}
