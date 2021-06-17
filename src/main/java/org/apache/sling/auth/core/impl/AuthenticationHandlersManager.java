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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import org.apache.sling.auth.core.impl.engine.EngineAuthenticationHandlerHolder;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.util.converter.Converters;

@Component(service = {AuthenticationHandlersManager.class},
     configurationPid = SlingAuthenticator.PID)
public class AuthenticationHandlersManager extends PathBasedHolderCache<AbstractAuthenticationHandlerHolder> {

    /** Handler map for authentication handlers */
    private final Map<String, List<AbstractAuthenticationHandlerHolder>> handlerMap = new ConcurrentHashMap<>();
    
    private final Boolean httpSupport;

    @Activate
    public AuthenticationHandlersManager(final SlingAuthenticator.Config config) {
        final String http = SlingAuthenticator.getHttpAuth(config);
        if (SlingAuthenticator.HTTP_AUTH_DISABLED.equals(http)) {
            this.httpSupport = null;
        } else {
            this.httpSupport = SlingAuthenticator.HTTP_AUTH_ENABLED.equals(http);
        }
    }

    /**
     * Returns the list of registered authentication handlers as a map for the web console
     */
    Map<String, List<String>> getAuthenticationHandlerMap() {
        final List<AbstractAuthenticationHandlerHolder> registeredHolders = this.getHolders();
        final LinkedHashMap<String, List<String>> ahMap = new LinkedHashMap<>();
        for (final AbstractAuthenticationHandlerHolder holder : registeredHolders) {
            final List<String> provider = ahMap.computeIfAbsent(holder.fullPath, key -> new ArrayList<>());
            provider.add(holder.getProvider());
        }
        if (httpSupport != null) {
            final List<String> provider = ahMap.computeIfAbsent("/", key -> new ArrayList<>());
            provider.add("HTTP Basic Authentication Handler ("
                + (Boolean.TRUE.equals(httpSupport) ? "enabled" : "preemptive") + ")");
        }
        return ahMap;
    }

    /**
     * Bind authentication handler
     * @param ref Service reference
     * @param handler The handler
     */
    @Reference(cardinality = ReferenceCardinality.MULTIPLE, policy = ReferencePolicy.DYNAMIC)
    private void bindAuthHandler(final AuthenticationHandler handler, final ServiceReference<Object> ref) {
        final String id = "A".concat(ref.getProperty(Constants.SERVICE_ID).toString());
        final String[] paths = Converters.standardConverter().convert(ref.getProperty(AuthenticationHandler.PATH_PROPERTY)).to(String[].class);
        internalBindAuthHandler(paths, id, path -> new AuthenticationHandlerHolder(path,
                handler,
                ref));
    }

    /**
     * Update authentication handler
     * @param ref Service reference
     * @param handler The handler
     */
    @SuppressWarnings("unused")
    private void updatedAuthHandler(final AuthenticationHandler handler, final ServiceReference<Object> ref) {
        unbindAuthHandler(ref);
        bindAuthHandler(handler, ref);
    }

    /**
     * Unbind authentication handler
     * @param ref Service Reference
     */
    private void unbindAuthHandler(final ServiceReference<Object> ref) {
        final String id = "A".concat(ref.getProperty(Constants.SERVICE_ID).toString());
        internalUnbindAuthHandler(id);
    }

    /**
     * Bind old engine authentication handler
     * @param ref Service reference
     * @param handler The handler
     * @deprecated use {@link #bindAuthHandler(AuthenticationHandler, ServiceReference)} instead
     */
    @Deprecated
    @Reference(cardinality = ReferenceCardinality.MULTIPLE, policy = ReferencePolicy.DYNAMIC)
    private void bindEngineAuthHandler(final org.apache.sling.engine.auth.AuthenticationHandler handler, final ServiceReference<Object> ref) {
        final String id = "E".concat(ref.getProperty(Constants.SERVICE_ID).toString());
        final String[] paths = Converters.standardConverter().convert(ref.getProperty(AuthenticationHandler.PATH_PROPERTY)).to(String[].class);
        internalBindAuthHandler(paths, id, path -> new EngineAuthenticationHandlerHolder(path,
                handler,
                ref));
    }

    /**
     * Update old engine authentication handler
     * @param ref Service reference
     * @param handler The handler
     * @deprecated use {@link #updatedAuthHandler(AuthenticationHandler, ServiceReference)} instead
     */
    @SuppressWarnings("unused")
    @Deprecated
    private void updatedEngineAuthHandler(final org.apache.sling.engine.auth.AuthenticationHandler handler, final ServiceReference<Object> ref) {
        unbindEngineAuthHandler(ref);
        bindEngineAuthHandler(handler, ref);
    }

    /**
     * Unbind old engine authentication handler
     * @param ref Service Reference
     */
    private void unbindEngineAuthHandler(final ServiceReference<Object> ref) {
        final String id = "E".concat(ref.getProperty(Constants.SERVICE_ID).toString());
        internalUnbindAuthHandler(id);
    }

    /**
     * Bind an authentication handler
     * @param paths The paths
     * @param id Unique id
     * @param createFunction Creation callback
     */
    private void internalBindAuthHandler(final String[] paths, final String id, final Function<String, AbstractAuthenticationHandlerHolder> createFunction) {
        if (paths != null && paths.length > 0) {

            // generate the holders
            ArrayList<AbstractAuthenticationHandlerHolder> holderList = new ArrayList<>();
            for (String path : paths) {
                if (path != null && path.length() > 0) {
                    holderList.add(createFunction.apply(path));
                }
            }
            // register the holders
            if ( !holderList.isEmpty() ) {
                for(final AbstractAuthenticationHandlerHolder holder : holderList) {
                    this.addHolder(holder);
                }

                // keep a copy of them for unregistration later
                handlerMap.put(id, holderList);
            }
        }
    }

    /**
     * Unbind authentication handler
     * @param id Unqiue id
     */
    private void internalUnbindAuthHandler(final String id) {
        final List<AbstractAuthenticationHandlerHolder> holders = handlerMap.remove(id);

        if (holders != null) {
            for (AbstractAuthenticationHandlerHolder holder : holders) {
                this.removeHolder(holder);
            }
        }
    }
}
