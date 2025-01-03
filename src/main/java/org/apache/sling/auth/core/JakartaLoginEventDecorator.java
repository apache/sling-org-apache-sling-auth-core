/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sling.auth.core;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.jetbrains.annotations.NotNull;
import org.osgi.annotation.versioning.ConsumerType;

/**
 * Components should implement this interface to customize properties
 * in the Login and/or LoginFailed event
 * @since 1.6.0
 */
@ConsumerType
public interface JakartaLoginEventDecorator {

    /**
     * Called to allow the component to modify the login event properties
     *
     * @param request the current request
     * @param authInfo the current authInfo
     * @param eventProperties the event properties to decorate
     */
    @NotNull default void decorateLoginEvent(final @NotNull HttpServletRequest request,
            final @NotNull AuthenticationInfo authInfo,
            final @NotNull Map<String, Object> eventProperties) {
        //no-op
    }

    /**
     * Called to allow the component to modify the login failed event properties
     *
     * @param request the current request
     * @param authInfo the current authInfo
     * @param eventProperties the event properties to decorate
     */
    @NotNull default void decorateLoginFailedEvent(final @NotNull HttpServletRequest request,
            final @NotNull AuthenticationInfo authInfo,
            final @NotNull Map<String, Object> eventProperties) {
        //no-op
    }

}
