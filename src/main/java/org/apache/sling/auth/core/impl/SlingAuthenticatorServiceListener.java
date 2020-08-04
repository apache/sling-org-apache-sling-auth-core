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
import java.util.Collection;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sling.api.SlingConstants;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.resource.mapping.ResourceMapper;
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.osgi.framework.AllServiceListener;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.event.Event;
import org.osgi.service.event.EventConstants;
import org.osgi.service.event.EventHandler;

/**
 * Service listener keeping track of all auth requirements registered in
 * the service registry.
 *
 */
public class SlingAuthenticatorServiceListener implements AllServiceListener, EventHandler {

    private static String FILTER_EXPR = "(".concat(AuthConstants.AUTH_REQUIREMENTS).concat("=*)");

    private static final Long UPDATE = 0L;

    private static final Long CLEAR = -1L;

    private final ResourceResolverFactory resolverFactory;

    private final PathBasedHolderCache<AuthenticationRequirementHolder> authRequiredCache;

    private final Map<Long, Set<String>> regProps = new ConcurrentHashMap<>();

    private final Map<Long, List<AuthenticationRequirementHolder>> props = new ConcurrentHashMap<>();

    private ServiceRegistration<EventHandler> serviceRegistration;

    private final Map<Long, Action> processingQueue = new LinkedHashMap<>();

    private final Executor executor;

    private final AtomicBoolean backgroundJobRunning = new AtomicBoolean(false);

    static SlingAuthenticatorServiceListener createListener(
        final BundleContext context,
        final Executor executor,
        final ResourceResolverFactory factory,
        final PathBasedHolderCache<AuthenticationRequirementHolder> authRequiredCache) {

        final SlingAuthenticatorServiceListener listener = new SlingAuthenticatorServiceListener(authRequiredCache,
                executor,
                factory);
        try {
            context.addServiceListener(listener, FILTER_EXPR);
            final Dictionary<String, Object> props = new Hashtable<>();
            props.put(EventConstants.EVENT_TOPIC, SlingConstants.TOPIC_RESOURCE_RESOLVER_MAPPING_CHANGED);
            listener.setServiceRegistration(context.registerService(EventHandler.class, listener, props));
            ServiceReference<?>[] refs = context.getAllServiceReferences(null, FILTER_EXPR);
            if (refs != null) {
                for (final ServiceReference<?> ref : refs) {
                    final Long id = (Long)ref.getProperty(Constants.SERVICE_ID);
                    listener.queue(id, new Action(ActionType.ADDED, ref));
                }
            }

            listener.schedule();

            return listener;
        } catch (InvalidSyntaxException ise) {
        }
        return null;
    }

    private SlingAuthenticatorServiceListener(final PathBasedHolderCache<AuthenticationRequirementHolder> authRequiredCache,
            final Executor executor,
            final ResourceResolverFactory factory) {
        this.authRequiredCache = authRequiredCache;
        this.executor = executor;
        this.resolverFactory = factory;
    }

    void setServiceRegistration(final ServiceRegistration<EventHandler> reg) {
        this.serviceRegistration = reg;
    }

    public void stop(final BundleContext bundleContext) {
        bundleContext.removeServiceListener(this);
        if ( this.serviceRegistration != null ) {
            this.serviceRegistration.unregister();
            this.serviceRegistration = null;
        }
        queue(CLEAR, null);
        backgroundJobRunning.set(false);
    }

    private void schedule() {
        if ( this.backgroundJobRunning.compareAndSet(false, true) ) {
            this.executor.execute(() -> { processQueue(); });
        }
    }

    @Override
    public void serviceChanged(final ServiceEvent event) {
        // modification of service properties, unregistration of the
        // service or service properties does not contain requirements
        // property any longer (new event with type 8 added in OSGi Core
        // 4.2)
        final Long id = (Long)event.getServiceReference().getProperty(Constants.SERVICE_ID);
        if ((event.getType() & (ServiceEvent.UNREGISTERING | ServiceEvent.MODIFIED_ENDMATCH)) != 0) {
            queue(id, new Action(ActionType.REMOVED, event.getServiceReference()));
        }

        if ((event.getType() & ServiceEvent.MODIFIED ) != 0) {
            queue(id, new Action(ActionType.MODIFIED, event.getServiceReference()));
        }

        // add requirements for newly registered services and for
        // updated services
        if ((event.getType() & ServiceEvent.REGISTERED ) != 0) {
            queue(id, new Action(ActionType.ADDED, event.getServiceReference()));
        }
        schedule();
    }

    @Override
    public void handleEvent(final Event event) {
        queue(UPDATE, null);
        schedule();
    }

    /**
     * Queue a new action
     * @param id The id of the service
     * @param action The action to take
     */
    private void queue(final Long id, final Action action) {
        synchronized ( this.processingQueue ) {
            if ( id == CLEAR ) {
                this.processingQueue.clear();
            } else if ( id == UPDATE ) {
                for(final Long updateId: this.props.keySet()) {
                    this.processingQueue.putIfAbsent(updateId, new Action(ActionType.UPDATE, null));
                }
            } else {
                this.processingQueue.remove(id);
                this.processingQueue.put(id, action);
            }
        }
    }

    private void processQueue() {
        ResourceResolver resolver = null;
        ResourceMapper mapper = null;
        try {
            while ( this.backgroundJobRunning.get() ) {
                Map.Entry<Long, Action> entry = null;
                synchronized ( this.processingQueue ) {
                    final Iterator<Map.Entry<Long, Action> > iter = this.processingQueue.entrySet().iterator();
                    if ( iter.hasNext() ) {
                        entry = iter.next();
                        iter.remove();
                    }
                }
                if ( entry == null ) {
                    synchronized ( this.processingQueue ) {
                        this.backgroundJobRunning.compareAndSet(true, !this.processingQueue.isEmpty());
                    }
                } else {
                    if ( entry.getValue().type != ActionType.REMOVED ) {
                        if ( mapper == null ) {
                            try {
                                resolver = this.resolverFactory.getServiceResourceResolver(null);
                                mapper = resolver.adaptTo(ResourceMapper.class);
                            } catch ( final org.apache.sling.api.resource.LoginException le) {
                                // ignore
                            }
                        }
                    }
                    process(mapper, entry.getKey(), entry.getValue());
                }
            }

        } finally {
            if ( resolver != null ) {
                resolver.close();
            }
        }
    }

    private void process(final ResourceMapper mapper, final Long id, final Action action) {
        switch ( action.type ) {
            case ADDED : this.addService(mapper, action.reference); break;
            case REMOVED : this.removeService((Long)action.reference.getProperty(Constants.SERVICE_ID)); break;
            case MODIFIED : this.modifiedService(mapper, action.reference); break;
            case UPDATE: final List<AuthenticationRequirementHolder> list = props.get(id);
                         if (!list.isEmpty() ) {
                             this.modifiedService(mapper, list.get(0).serviceReference, regProps.get(id));
                         }
        }
    }

    /**
     * Register all known services.
     */
    void registerAllServices() {
        for(final List<AuthenticationRequirementHolder> authReqs : props.values()) {
            registerService(authReqs);
        }
    }

    /**
     * Register all authentication requirement holders.
     * @param authReqs The auth requirement holders
     */
    private void registerService(final List<AuthenticationRequirementHolder> authReqs) {
        for (AuthenticationRequirementHolder authReq : authReqs) {
            authRequiredCache.addHolder(authReq);
        }
    }

    private Set<String> buildPathsSet(final ResourceMapper mapper, final Collection<String> authReqPaths) {
        final Set<String> paths = new HashSet<>();
        for(final String authReq : authReqPaths) {
            if (authReq != null && authReq.length() > 0) {
                paths.add(authReq);

                if ( mapper != null ) {
                    for(final String mappedPath : mapper.getAllMappings(authReq)) {
                        paths.add(mappedPath);
                    }
                }
            }
        }
        return paths;
    }

    /**
     * Process a new service with auth requirements
     * @param ref The service reference
     */
    private void addService(final ResourceMapper mapper, final ServiceReference<?> ref) {
        final String[] authReqPaths = PropertiesUtil.toStringArray(ref.getProperty(AuthConstants.AUTH_REQUIREMENTS));
        if ( authReqPaths != null ) {
            final Long id = (Long)ref.getProperty(Constants.SERVICE_ID);
            final Set<String> paths = buildPathsSet(mapper, Arrays.asList(authReqPaths));

            if ( !paths.isEmpty() ) {
                final List<AuthenticationRequirementHolder> authReqList = new ArrayList<AuthenticationRequirementHolder>();
                for (final String authReq : paths) {
                    authReqList.add(AuthenticationRequirementHolder.fromConfig(authReq, ref));
                }

                // keep original set for modified
                regProps.put(id, paths);
                registerService(authReqList);
                props.put(id, authReqList);
            }
        }
    }

    /**
     * Process a modified service with auth requirements
     * @param ref The service reference
     */
    private void modifiedService(final ResourceMapper mapper, final ServiceReference<?> ref) {
        final String[] authReqPaths = PropertiesUtil.toStringArray(ref.getProperty(AuthConstants.AUTH_REQUIREMENTS));

        modifiedService(mapper, ref, Arrays.asList(authReqPaths));
    }


    private void modifiedService(final ResourceMapper mapper, final ServiceReference<?> ref, final Collection<String> authReqPaths) {
        final Long id = (Long)ref.getProperty(Constants.SERVICE_ID);
        if ( authReqPaths != null ) {
            final Set<String> oldPaths = regProps.get(id);
            if ( oldPaths == null ) {
                addService(mapper, ref);
            } else {
                final Set<String> paths = buildPathsSet(mapper, authReqPaths);
                if ( paths.isEmpty() ) {
                    removeService(id);
                } else {
                    final List<AuthenticationRequirementHolder> authReqs = props.get(id);
                    // compare sets
                    for(final String oldPath : oldPaths) {
                        if ( !paths.contains(oldPath) ) {
                            // remove
                            final AuthenticationRequirementHolder holder = AuthenticationRequirementHolder.fromConfig(oldPath, ref);
                            authReqs.remove(holder);
                            authRequiredCache.removeHolder(holder);
                        }
                    }
                    for(final String path : paths) {
                        if ( !oldPaths.contains(path) ) {
                            // add
                            final AuthenticationRequirementHolder holder = AuthenticationRequirementHolder.fromConfig(path, ref);
                            authReqs.add(holder);
                            authRequiredCache.addHolder(holder);
                        }
                    }
                    regProps.put(id, paths);
                }
            }
        } else {
            removeService(id);
        }
    }

    /**
     * Process a removed service with auth requirements
     * @param ref The service reference
     */
    private void removeService(final Long id) {
        final List<AuthenticationRequirementHolder> authReqs = props.remove(id);
        if (authReqs != null) {
            for (final AuthenticationRequirementHolder authReq : authReqs) {
                authRequiredCache.removeHolder(authReq);
            }
        }
        regProps.remove(id);
    }

    public enum ActionType {
        ADDED, MODIFIED, REMOVED, UPDATE
    }

    public static final class Action {

        public final ActionType type;

        public final ServiceReference<?> reference;

        public Action(final ActionType type, final ServiceReference<?> ref) {
            this.type = type;
            this.reference = ref;
        }
    }
}
