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

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.apache.sling.api.resource.ResourceResolverFactory;

/**
 * The <code>AuthenticationInfo</code> conveys any authentication credentials
 * and/or details extracted by the
 * {@link JakartaAuthenticationHandler#extractCredentials(jakarta.servlet.http.HttpServletRequest, jakarta.servlet.http.HttpServletResponse)}
 * method from the request.
 * <p>
 * {@link JakartaAuthenticationHandler} implementations must return instances of this
 * class which may be constructed through any of the provided public
 * constructors.
 * <p>
 * Internally all values are stored in the map where some property names have
 * special semantics and the data type of the properties are ensured by the
 * {@link #put(String, Object)} method implementation.
 */
@SuppressWarnings("serial")
public class AuthenticationInfo extends HashMap<String, Object> {

    /**
     * A special instance of this class which may be returned from the
     * {@link JakartaAuthenticationHandler#extractCredentials(jakarta.servlet.http.HttpServletRequest, jakarta.servlet.http.HttpServletResponse)}
     * method to inform the caller, that a response has been sent to the client
     * to request for credentials.
     * <p>
     * If this value is returned, the request should be considered finished and
     * no further actions should be taken on this request.
     */
    public static final AuthenticationInfo DOING_AUTH = new ReadOnlyAuthenticationInfo( // NOSONAR
        "DOING_AUTH");

    /**
     * A special instance of this class which may be returned from the
     * {@link JakartaAuthenticationHandler#extractCredentials(jakarta.servlet.http.HttpServletRequest, jakarta.servlet.http.HttpServletResponse)}
     * method to inform the caller that credential extraction failed for some
     * reason.
     * <p>
     * If this value is returned, the handler signals that credentials would be
     * present in the request but the credentials are not valid for use (for
     * example OpenID identify failed to validate or some authentication cookie
     * expired).
     */
    public static final AuthenticationInfo FAIL_AUTH = new ReadOnlyAuthenticationInfo( // NOSONAR
        "FAIL_AUTH");

    /**
     * The name of the special property providing the authentication type
     * provided by the {@link JakartaAuthenticationHandler}. This value must be
     * supplied to one of the constructors and is ultimately used as the value
     * of the <code>HttpServletRequest.getAuthType</code> method.
     * <p>
     * This property is always present (and cannot be removed) in this map and
     * is of <code>String</code> type.
     */
    public static final String AUTH_TYPE = "sling.authType";

    /**
     * Creates an instance of this class with just the authentication type. To
     * effectively use this instance the user Id with optional password and/or
     * the credentials should be set.
     *
     * @param authType The authentication type, must not be <code>null</code>.
     */
    public AuthenticationInfo(final String authType) {
        this(authType, null, null);
    }

    /**
     * Creates an instance of this class authenticating with the given type and
     * userid.
     *
     * @param authType The authentication type, must not be <code>null</code>.
     * @param userId The name of the user to authenticate as. This may be
     *            <code>null</code> for the constructor and later be set.
     * @throws NullPointerException if <code>authType</code> is
     *             <code>null</code>.
     */
    public AuthenticationInfo(final String authType, final String userId) {
        this(authType, userId, null);
    }

    /**
     * Creates an instance of this class authenticating with the given type and
     * userid/password connecting.
     *
     * @param authType The authentication type, must not be <code>null</code>.
     * @param userId The name of the user to authenticate as. This may be
     *            <code>null</code> for the constructor and later be set.
     * @param password The password to authenticate with or <code>null</code> if
     *            no password can be supplied.
     * @throws NullPointerException if <code>authType</code> is
     *             <code>null</code>.
     */
    public AuthenticationInfo(final String authType, final String userId,
            final char[] password) {
        super.put(AUTH_TYPE, authType);
        putIfNotNull(ResourceResolverFactory.USER, userId);
        putIfNotNull(ResourceResolverFactory.PASSWORD, password);
    }

    /**
     * @param authType The authentication type to set. If this is
     *            <code>null</code> the current authentication type is not
     *            replaced.
     */
    public final void setAuthType(String authType) {
        putIfNotNull(AUTH_TYPE, authType);
    }

    /**
     * Returns the authentication type as stored in the {@link #AUTH_TYPE} property
     * in this map. This value is expected to never be <code>null</code>.
     * <p>
     * If authentication is taking place through one of the standard ways, such
     * as Basic or Digest, the return value is one of the predefined constants
     * of the <code>HttpServletRequest</code> interface. Otherwise the value may
     * be specific to the {@link JakartaAuthenticationHandler} implementation.
     * @return The authentication type as stored in the {@link #AUTH_TYPE} property.
     */
    public final String getAuthType() {
        return (String) get(AUTH_TYPE);
    }

    /**
     * @param user The name of the user to authenticate as. If this is
     *            <code>null</code> the current user name is not replaced.
     */
    public final void setUser(String user) {
        putIfNotNull(ResourceResolverFactory.USER, user);
    }

    /**
     * Returns the user name stored as the {@link ResourceResolverFactory#USER} property or
     * <code>null</code> if the user is not set in this map.
     * @return The user name as stored in the {@link ResourceResolverFactory#USER} property.
     */
    public final String getUser() {
        return (String) get(ResourceResolverFactory.USER);
    }

    /**
     * @param password The password to authenticate with. If this is
     *            <code>null</code> the current password is not replaced.
     */
    public final void setPassword(char[] password) {
        putIfNotNull(ResourceResolverFactory.PASSWORD, password);
    }

    /**
     * Returns the password stored as the {@link ResourceResolverFactory#PASSWORD} property or
     * <code>null</code> if the password is not set in this map.
     * @return the password as stored in the {@link ResourceResolverFactory#PASSWORD} property
     */
    public final char[] getPassword() {
        return (char[]) get(ResourceResolverFactory.PASSWORD);
    }

    /**
     * Sets or resets a property with the given <code>key</code> to a new
     * <code>value</code>. Some keys have special meanings and their values are
     * required to have predefined as listed in the following table:
     * <table>
     * <caption>Predefined Keys</caption>
     * <tr>
     * <td>{@link #AUTH_TYPE}</td>
     * <td><code>String</code></td>
     * </tr>
     * <tr>
     * <td>{@link ResourceResolverFactory#USER}</td>
     * <td><code>String</code></td>
     * </tr>
     * <tr>
     * <td>{@link ResourceResolverFactory#PASSWORD}</td>
     * <td><code>char[]</code></td>
     * </tr>
     * </table>
     * <p>
     * If the value for the special key does not match the required type an
     * <code>IllegalArgumentException</code> is thrown.
     *
     * @param key The name of the property to set
     * @param value The value of the property which must be of a special type if
     *            the <code>key</code> designates one of the predefined
     *            properties.
     * @return The value previously set for the given <code>key</code>.
     * @throws IllegalArgumentException if <code>key</code> designates one of
     *             the special properties and the <code>value</code> does not
     *             have the correct type for the respective key.
     */
    @Override
    public Object put(final String key, final Object value) {

        if (AUTH_TYPE.equals(key) && !(value instanceof String)) {
            throw new IllegalArgumentException(AUTH_TYPE
                + " property must be a String");
        }

        if (ResourceResolverFactory.USER.equals(key)
            && !(value instanceof String)) {
            throw new IllegalArgumentException(ResourceResolverFactory.USER
                + " property must be a String");
        }

        if (ResourceResolverFactory.PASSWORD.equals(key)
            && !(value instanceof char[])) {
            throw new IllegalArgumentException(ResourceResolverFactory.PASSWORD
                + " property must be a char[]");
        }

        return super.put(key, value);
    }

    /**
     * Removes the entry with the given <code>key</code> and returns its former
     * value (if existing). If the <code>key</code> is {@link #AUTH_TYPE} the
     * value is not actually removed and <code>null</code> is always returned.
     *
     * @param key Removes the value associated with this key.
     * @return The former value associated with the key.
     */
    @Override
    public Object remove(Object key) {

        // don't remove the auth type from the map
        if (AUTH_TYPE.equals(key)) {
            return null;
        }

        return super.remove(key);
    }

    /**
     * Clears all properties from the map with the exception of the
     * {@link #AUTH_TYPE} property.
     */
    @Override
    public void clear() {
        final String authType = getAuthType();
        super.clear();
        setAuthType(authType);
    }

    /**
     * Calls {@link #put(String, Object)} only if the <code>value</code> is not
     * <code>null</code>, otherwise does nothing.
     *
     * @param key The key of the property to set
     * @param value The value to set for the property. This may be
     *            <code>null</code> in which case this method does nothing.
     */
    private void putIfNotNull(final String key, final Object value) {
        if (value != null) {
            put(key, value);
        }
    }

    /**
     * The <code>ReadOnlyAuthenticationInfo</code> extends the
     * {@link AuthenticationInfo} class overwriting all of the
     * methods that may change the state.
     * This acts like kind of a read-only immutable wrapper.
     */
    private static final class ReadOnlyAuthenticationInfo extends
            AuthenticationInfo {

        private final transient Map<String, Object> unmodifiableMap;  // NOSONAR

        // used to guard against stack overflow
        private final transient ThreadLocal<Boolean> stackGuard = new ThreadLocal<>();

        /**
         * Creates an instance of this read-only class with the given
         * authentication type.
         *
         * @param authType The authentication type to set
         */
        ReadOnlyAuthenticationInfo(final String authType) {
            super(authType);
            // create an unmodifiable wrapper in order to delegate
            //  all the public api calls that may change the state
            unmodifiableMap = Collections.unmodifiableMap(this);
        }

        @Override
        public Object put(String key, Object value) {
            return unmodifiableMap.put(key, value);
        }

        @Override
        public void putAll(Map<? extends String, ? extends Object> m) {
            unmodifiableMap.putAll(m);
        }

        @Override
        public Object remove(Object key) {
            return unmodifiableMap.remove(key);
        }

        @Override
        public void clear() {
            unmodifiableMap.clear();
        }

        @Override
        public Set<String> keySet() {
            if (Boolean.TRUE.equals(stackGuard.get())) {
                return super.keySet();
            } else {
                try {
                    stackGuard.set(Boolean.TRUE);
                    return unmodifiableMap.keySet();
                } finally {
                    stackGuard.remove();
                }
            }
        }

        @Override
        public Collection<Object> values() {
            if (Boolean.TRUE.equals(stackGuard.get())) {
                return super.values();
            } else {
                try {
                    stackGuard.set(Boolean.TRUE);
                    return unmodifiableMap.values();
                } finally {
                    stackGuard.remove();
                }
            }
        }

        @Override
        public Set<Entry<String, Object>> entrySet() {
            if (Boolean.TRUE.equals(stackGuard.get())) {
                return super.entrySet();
            } else {
                try {
                    stackGuard.set(Boolean.TRUE);
                    return unmodifiableMap.entrySet();
                } finally {
                    stackGuard.remove();
                }
            }
        }

        @Override
        public Object putIfAbsent(String key, Object value) {
            return unmodifiableMap.putIfAbsent(key, value);
        }

        @Override
        public boolean remove(Object key, Object value) {
            return unmodifiableMap.remove(key, value);
        }

        @Override
        public boolean replace(String key, Object oldValue, Object newValue) {
            return unmodifiableMap.replace(key, oldValue, newValue);
        }

        @Override
        public Object replace(String key, Object value) {
            return unmodifiableMap.replace(key, value);
        }

        @Override
        public Object computeIfAbsent(String key, Function<? super String, ? extends Object> mappingFunction) {
            return unmodifiableMap.computeIfAbsent(key, mappingFunction);
        }

        @Override
        public Object computeIfPresent(String key,
                BiFunction<? super String, ? super Object, ? extends Object> remappingFunction) {
            return unmodifiableMap.computeIfPresent(key, remappingFunction);
        }

        @Override
        public Object compute(String key,
                BiFunction<? super String, ? super Object, ? extends Object> remappingFunction) {
            return unmodifiableMap.compute(key, remappingFunction);
        }

        @Override
        public Object merge(String key, Object value,
                BiFunction<? super Object, ? super Object, ? extends Object> remappingFunction) {
            return unmodifiableMap.merge(key, value, remappingFunction);
        }

        @Override
        public void replaceAll(BiFunction<? super String, ? super Object, ? extends Object> function) {
            unmodifiableMap.replaceAll(function);
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = super.hashCode();
            result = prime * result;
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (!super.equals(obj))
                return false;
            return getClass() == obj.getClass();
        }

    }
}
