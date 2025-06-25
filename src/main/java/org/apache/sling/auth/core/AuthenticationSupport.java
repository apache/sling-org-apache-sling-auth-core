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
import org.osgi.annotation.versioning.ProviderType;

/**
 * The {@code AuthenticationSupport} provides the service API used to
 * implement the {@code ServletContextHelper.handleSecurity} method as defined in
 * the OSGi Whiteboard Specification for Jakarta Servlet.
 * <p>
 * Bundles registering servlets and/or resources with custom
 * {@code ServletContextHelper} implementations may implement the
 * {@code handleSecurity} method using this service. The
 * {@link #handleSecurity(HttpServletRequest, HttpServletResponse)} method
 * implemented by this service exactly implements the specification of the
 * {@code ServletContextHelper.handleSecurity} method.
 * Similarly, the
 * {@link #finishSecurity(HttpServletRequest, HttpServletResponse)} method
 * implemented by this service exactly implements the specification of the
 * {@code ServletContextHelper.finishSecurity} method.
 * <p>
 * A simple implementation of the {@code ServletContextHelper} interface based on
 * this could be (using SCR JavaDoc tags of the Maven SCR Plugin) :
 *
 * <pre>
 * &#47;** &#64;scr.component *&#47;
 * public class MyHttpContext extends ServletContextHelper {
 *     &#47;** &#64;scr.reference *&#47;
 *     private AuthenticationSupport authSupport;
 *
 *     &#47;** &#64;scr.reference *&#47;
 *     private MimeTypeService mimeTypes;
 *
 *     public boolean handleSecurity(HttpServletRequest request,
 *             HttpServletResponse response) {
 *         return authSupport.handleSecurity(request, response);
 *     }
 *
 *     public void finishSecurity(HttpServletRequest request,
 *             HttpServletResponse response) {
 *         return authSupport.finishSecurity(request, response);
 *     }
 * }
 * </pre>
 * <p>
 * This interface is implemented by this bundle and is not intended to be
 * implemented by client bundles.
 */
@ProviderType
public interface AuthenticationSupport {

    /**
     * The name under which this service is registered.
     */
    static final String SERVICE_NAME = "org.apache.sling.auth.core.AuthenticationSupport";

    /**
     * The name of the request attribute set by the
     * {@link #handleSecurity(HttpServletRequest, HttpServletResponse)} method
     * if authentication succeeds and {@code true} is returned.
     * <p>
     * The request attribute is set to a Sling {@code ResourceResolver}
     * attached to resource providers, e.g. a JCR repository, using the credentials
     * provided by the request.
     */
    static final String REQUEST_ATTRIBUTE_RESOLVER = "org.apache.sling.auth.core.ResourceResolver";

    /**
     * The name of the request parameter indicating where to redirect to after
     * successful authentication (and optional impersonation). This parameter is
     * respected if either anonymous authentication or regular authentication
     * succeed.
     * <p>
     * If authentication fails, either because the credentials are wrong or
     * because anonymous authentication fails or because anonymous
     * authentication is not allowed for the request, the parameter is ignored
     * and the
     * {@link org.apache.sling.auth.core.spi.JakartaAuthenticationHandler#requestCredentials(HttpServletRequest, HttpServletResponse)}
     * method is called to request authentication.
     */
    static final String REDIRECT_PARAMETER = "sling.auth.redirect";

    /**
     * Handles security on behalf of a custom OSGi
     * {@code ServletContextHelper} instance extracting credentials from the request
     * using any registered
     * {@link org.apache.sling.auth.core.spi.AuthenticationHandler} services.
     * If the credentials can be extracted and used to log into the resource
     * resolver this method sets the request attributes required by the OSGi
     * Whiteboard Specification for Jakarta Service plus the {@link #REQUEST_ATTRIBUTE_RESOLVER}
     * attribute.
     *
     * @param request The HTTP request to be authenticated
     * @param response The HTTP response to send any response to in case of
     *            problems.
     * @return {@code true} if authentication succeeded and the request
     *         attributes are set. {@code false} is returned no request attributes are set.
     * @since 1.6.0
     */
    boolean handleSecurity(HttpServletRequest request, HttpServletResponse response);

    /**
     * Handles security on behalf of a custom OSGi {@code ServletContextHelper}
     * instance, finishing the authentication context established
     * by {@link #handleSecurity(HttpServletRequest, HttpServletResponse)}.
     * If the request contains an attribute {@link #REQUEST_ATTRIBUTE_RESOLVER}
     * and the value is a {@code ResourceResolver}, this method will close it.
     *
     * @param request The HTTP request
     * @param response The HTTP response
     * @since 1.6.0
     */
    void finishSecurity(HttpServletRequest request, HttpServletResponse response);

    /**
     * Handles security on behalf of a custom OSGi Http Service
     * <code>HttpContext</code> instance extracting credentials from the request
     * using any registered
     * {@link org.apache.sling.auth.core.spi.AuthenticationHandler} services.
     * If the credentials can be extracted and used to log into the JCR
     * repository this method sets the request attributes required by the OSGi
     * Http Service specification plus the {@link #REQUEST_ATTRIBUTE_RESOLVER}
     * attribute.
     *
     * @param request The HTTP request to be authenticated
     * @param response The HTTP response to send any response to in case of
     *            problems.
     * @return <code>true</code> if authentication succeeded and the request
     *         attributes are set. If <code>false</code> is returned the request
     *         is immediately terminated and no request attributes are set.
     * @deprecated Use {@link #handleSecurity(HttpServletRequest, HttpServletResponse)}
     */
    @Deprecated
    boolean handleSecurity(
            javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response);
}
