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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import junitx.util.PrivateAccessor;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;

/**
 * Reproduces the unbounded {@code handleLoginFailure -> getAnonymousResolver} recursion in
 * {@link org.apache.sling.auth.core.impl.SlingAuthenticator} that occurs when acquiring the
 * anonymous {@code ResourceResolver} keeps failing with a {@code LoginException} (for example
 * when the underlying repository is unavailable or a required segment is missing). Without the
 * re-entrancy guard the two methods call each other until a {@code StackOverflowError} is thrown,
 * and every failed request logs the full repeating stack trace - the mechanism that filled the
 * disk on the affected AEM author instance.
 */
public class SlingAuthenticatorAnonymousRecursionTest {

    private static final long BUNDLE_ID = 732;

    private BundleContext createBundleContext() {
        final BundleContext context = Mockito.mock(BundleContext.class);
        final Bundle bundle = Mockito.mock(Bundle.class);
        Mockito.when(bundle.getBundleId()).thenReturn(BUNDLE_ID);
        Mockito.when(context.getBundle()).thenReturn(bundle);
        return context;
    }

    private SlingAuthenticator createAuthenticator(final ResourceResolverFactory resourceResolverFactory) {
        final SlingAuthenticator.Config config = SlingAuthenticatorTest.createDefaultConfig();
        final AuthenticationRequirementsManager requirements =
                new AuthenticationRequirementsManager(createBundleContext(), null, config, callable -> callable.run());
        final AuthenticationHandlersManager handlers = new AuthenticationHandlersManager(config);
        return new SlingAuthenticator(
                requirements, handlers, resourceResolverFactory, Mockito.mock(BundleContext.class), config);
    }

    /**
     * A plain browser request to an anonymously accessible resource (not a login/validate request).
     */
    private HttpServletRequest anonymousBrowserRequest() {
        final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getServletPath()).thenReturn("/content/page.html");
        Mockito.when(request.getServerName()).thenReturn("localhost");
        Mockito.when(request.getServerPort()).thenReturn(80);
        Mockito.when(request.getScheme()).thenReturn("http");
        Mockito.when(request.getRequestURI()).thenReturn("/content/page.html");

        // a real servlet request stores attributes; model that so the re-entrancy guard round-trips
        final Map<String, Object> attributes = new HashMap<>();
        Mockito.when(request.getAttribute(Mockito.anyString()))
                .thenAnswer(invocation -> attributes.get(invocation.<String>getArgument(0)));
        Mockito.doAnswer(invocation -> {
                    attributes.put(invocation.getArgument(0), invocation.getArgument(1));
                    return null;
                })
                .when(request)
                .setAttribute(Mockito.anyString(), Mockito.any());
        return request;
    }

    /**
     * When the anonymous login fails repeatedly, the authenticator must attempt it once and then
     * terminate the request - it must not recurse into itself. Before the fix this test fails with
     * a {@code StackOverflowError}; after the fix the anonymous login is attempted exactly once.
     */
    @Test
    public void anonymousLoginFailureIsNotRetriedInALoop() throws Throwable {
        final AtomicInteger loginAttempts = new AtomicInteger();
        final ResourceResolverFactory resourceResolverFactory = Mockito.mock(ResourceResolverFactory.class);
        Mockito.when(resourceResolverFactory.getResourceResolver(Mockito.anyMap()))
                .thenAnswer(invocation -> {
                    loginAttempts.incrementAndGet();
                    throw new LoginException("repository unavailable (simulated SegmentNotFoundException)");
                });

        final SlingAuthenticator authenticator = createAuthenticator(resourceResolverFactory);
        final HttpServletRequest request = anonymousBrowserRequest();
        final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        final boolean processRequest;
        try {
            processRequest = (Boolean) PrivateAccessor.invoke(
                    authenticator,
                    "getAnonymousResolver",
                    new Class[] {HttpServletRequest.class, HttpServletResponse.class, AuthenticationInfo.class},
                    new Object[] {request, response, new AuthenticationInfo(null)});
        } catch (Throwable t) {
            if (isStackOverflow(t)) {
                Assert.fail("anonymous login failure caused unbounded recursion (StackOverflowError); "
                        + "getResourceResolver was called " + loginAttempts.get() + " times");
            }
            throw t;
        }

        Assert.assertFalse("a failed anonymous resolution must terminate the request", processRequest);
        Assert.assertEquals(
                "anonymous login must be attempted exactly once, never retried in a recursive loop",
                1,
                loginAttempts.get());
    }

    private static boolean isStackOverflow(Throwable t) {
        for (Throwable current = t; current != null; current = current.getCause()) {
            if (current instanceof StackOverflowError) {
                return true;
            }
        }
        return false;
    }
}
