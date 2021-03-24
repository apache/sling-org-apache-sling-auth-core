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
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpServletRequest;

public class PathBasedHolderCache<Type extends PathBasedHolder> {

    /**
     * The cache is a concurrent map of concurrent maps.
     * As the final value, the sorted set is replaced on each change, reading of the
     * cache does not need to be synchronized. Updating of the cache is synchronized.
     */
    private final Map<String, Map<String, SortedSet<Type>>> cache = new ConcurrentHashMap<>();

    protected void clear() {
        cache.clear();
    }

    public synchronized void addHolder(final Type holder) {
        final Map<String, SortedSet<Type>> byHostMap = cache.computeIfAbsent(holder.protocol, protocol -> new ConcurrentHashMap<>());

        // preset with current list
        final SortedSet<Type> currentPathSet = byHostMap.get(holder.host);
        final SortedSet<Type> byPathSet = new TreeSet<Type>();
        if (currentPathSet != null) {
            byPathSet.addAll(currentPathSet);
        }

        // add the new holder
        byPathSet.add(holder);

        // replace old set with new set
        byHostMap.put(holder.host, byPathSet);
    }

    public synchronized void removeHolder(final Type holder) {
        final Map<String, SortedSet<Type>> byHostMap = cache.get(holder.protocol);
        if (byHostMap != null) {
            final SortedSet<Type> byPathSet = byHostMap.get(holder.host);
            if (byPathSet != null) {

                // create a new set without the removed holder
                final SortedSet<Type> set = new TreeSet<Type>();
                set.addAll(byPathSet);
                set.remove(holder);

                // replace the old set with the new one (or remove if empty)
                if (set.isEmpty()) {
                    byHostMap.remove(holder.host);
                } else {
                    byHostMap.put(holder.host, set);
                }
            }
        }
    }

    public Collection<Type>[] findApplicableHolders(final HttpServletRequest request) {
        final String hostname;
        if ( request.getServerPort() != 80 && request.getServerPort() != 443 ) {
            hostname = request.getServerName().concat(":").concat(String.valueOf(request.getServerPort()));
        } else {
            hostname = request.getServerName();
        }

        @SuppressWarnings("unchecked")
        final SortedSet<Type>[] result = new SortedSet[4];

        final Map<String, SortedSet<Type>> byHostMap = cache.get(request.getScheme());
        if ( byHostMap != null ) {
            result[0] = byHostMap.get(hostname);
            result[1] = byHostMap.get("");
        }
        final Map<String, SortedSet<Type>> defaultByHostMap = cache.get("");
        if ( defaultByHostMap != null ) {
            result[2] = defaultByHostMap.get(hostname);
            result[3] = defaultByHostMap.get("");
        }
        return result;
    }

    public List<Type> getHolders() {
        final List<Type> result = new ArrayList<Type>();
        for (Map<String, SortedSet<Type>> byHostEntry : cache.values()) {
            for (SortedSet<Type> holderSet : byHostEntry.values()) {
                result.addAll(holderSet);
            }
        }
        return result;
    }
}
