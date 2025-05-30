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
package org.apache.sling.auth.core;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The <code>AuthConstants</code> provides a collection of constants used to
 * configure and customize the Sling authentication infrastructure.
 * <p>
 * This class can neither be extended from nor can it be instantiated.
 *
 * @since 1.1 (bundle version 1.0.8)
 */
public final class AuthConstants {

    /**
     * The name of the request parameter indicating that the submitted username
     * and password should just be checked and a status code be set for success
     * (200/OK) or failure (403/FORBIDDEN).
     *
     * @see AuthUtil#isValidateRequest(HttpServletRequest)
     * @see AuthUtil#sendValid(HttpServletResponse)
     * @see AuthUtil#sendInvalid(HttpServletRequest, HttpServletResponse)
     */
    public static final String PAR_J_VALIDATE = "j_validate";

    /**
     * The name of the request header set by the
     * {@link AuthUtil#sendInvalid(HttpServletRequest, HttpServletResponse)} method if the provided
     * credentials cannot be used for login.
     * <p>
     * This header may be inspected by clients for a reason why the request
     * failed.
     *
     * @see AuthUtil#sendInvalid(HttpServletRequest, HttpServletResponse)
     */
    public static final String X_REASON = "X-Reason";

    /**
     * The name of the request header set by the
     * {@link AuthUtil#sendInvalid(HttpServletRequest, HttpServletResponse)} method if the provided
     * credentials cannot be used for login.
     * <p>
     * This header may be inspected by clients for a a detailed reason code why the request
     * failed.
     *
     * @see AuthUtil#sendInvalid(HttpServletRequest, HttpServletResponse)
     */
    public static final String X_REASON_CODE = "X-Reason-Code";

    /**
     * Service Registration property which may be set by an
     * {@link org.apache.sling.auth.core.spi.JakartaAuthenticationHandler} service to
     * indicate whether its
     * {@link org.apache.sling.auth.core.spi.JakartaAuthenticationHandler#requestCredentials(HttpServletRequest, HttpServletResponse)}
     * method supports non-browser requests (according to
     * {@link AuthUtil#isBrowserRequest(HttpServletRequest)}
     * or not.
     * <p>
     * For backwards compatibility with existing
     * {@link org.apache.sling.auth.core.spi.JakartaAuthenticationHandler} services the
     * default assumption in the absence of this property is that all requests
     * are supported.
     * <p>
     * If this property is set to <code>true</code> or <code>yes</code>
     * (case-insensitive check) the handler is not called for requests assumed
     * to be sent from non-browser clients. Any other value of this property
     * indicates support for non-browser requests by the handler.
     * <p>
     * Note that this property only influences whether the
     * <code>requestCredentials</code> method is called or not. The
     * <code>extractCredentials</code> and <code>dropCredentials</code> are
     * called regardless of this property.
     */
    public static final String AUTH_HANDLER_BROWSER_ONLY = "sling.auth.browser-only";

    /**
     * Marker property in the
     * {@link org.apache.sling.auth.core.spi.AuthenticationInfo} object returned
     * by the
     * {@link org.apache.sling.auth.core.spi.JakartaAuthenticationHandler#extractCredentials(HttpServletRequest, HttpServletResponse)}
     * method indicating a first authentication considered to be a login.
     * <p>
     * By setting this property to any non-<code>null</code> value an
     * {@link org.apache.sling.auth.core.spi.JakartaAuthenticationHandler} indicates,
     * that the {@link #TOPIC_LOGIN} event should be fired after successfully
     * acquiring the <code>ResourceResolver</code>.
     */
    public static final String AUTH_INFO_LOGIN = "$$auth.info.login$$";

    /**
     * The topic for the OSGi event which is sent when a user has logged in successfully.
     * The event contains at least the {@link org.apache.sling.api.SlingConstants#PROPERTY_USERID}
     * and the {@link org.apache.sling.auth.core.spi.AuthenticationInfo#AUTH_TYPE}
     * properties.
     */
    public static final String TOPIC_LOGIN = "org/apache/sling/auth/core/Authenticator/LOGIN";

    /**
     * The topic for the OSGi event which is sent when a user has failed to login successfully.
     * The event contains at least the {@link org.apache.sling.api.SlingConstants#PROPERTY_USERID}
     * and the {@link org.apache.sling.auth.core.spi.AuthenticationInfo#AUTH_TYPE}
     * properties.
     */
    public static final String TOPIC_LOGIN_FAILED = "org/apache/sling/auth/core/Authenticator/LOGIN_FAILED";

    /**
     * Any OSGi service may provide a {@code sling.auth.requirements} registration property which is used
     * to dynamically extend the authentication requirements for the {@code AuthenticationSupport}.
     * This may for example be set by AuthenticationHandler implementations providing
     * a login form to ensure access to the login form does not require authentication. The value
     * of this property is a single string, an array of strings or a Collection of strings.
     * Each string can be an absolute path (such as /content) or and absolute URI (such as
     * http://thehost/content). Optionally each entry may be prefixed by a plus (+) or minus (-) sign
     * indicating that authentication is required (plus) or not required (minus).
     */
    public static final String AUTH_REQUIREMENTS = "sling.auth.requirements";

    /**
     * The name of the request attribute containing the list of
     * request URI suffixes handled by the default authenticator
     * <code>org.apache.sling.auth.core.impl.SlingAuthenticator</code>.
     * The authenticator will populate this attribute so that login JSPs
     * can post j_username and j_password to the correct URI.
     *
     * @since 1.3.2 (bundle version 1.4.0)
     */
    public static final String ATTR_REQUEST_AUTH_URI_SUFFIX = "org.apache.sling.api.include.auth_uri_suffix";

    private AuthConstants() {}
}
