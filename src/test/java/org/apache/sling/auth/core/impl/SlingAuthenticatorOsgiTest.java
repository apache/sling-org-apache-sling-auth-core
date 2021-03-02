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
package org.apache.sling.auth.core.impl;

import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.commons.metrics.Meter;
import org.apache.sling.commons.metrics.MetricsService;
import org.apache.sling.commons.metrics.Timer;
import org.apache.sling.testing.mock.osgi.junit.OsgiContext;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class SlingAuthenticatorOsgiTest {

    @Rule
    public final OsgiContext context = new OsgiContext();

    private Meter meter = mock(Meter.class);
    private Timer.Context ctx = mock(Timer.Context.class);
    private Timer timer = mock(Timer.class);
    private final MetricsService metricsService = mock(MetricsService.class);

    private final SlingAuthenticator authenticator = new SlingAuthenticator();

    @Before
    public void before() throws Exception {
        ResourceResolver rr = mock(ResourceResolver.class);
        ResourceResolverFactory resourceResolverFactory = mock(ResourceResolverFactory.class);
        when(resourceResolverFactory.getResourceResolver(any(AuthenticationInfo.class))).thenReturn(rr);

        when(timer.time()).thenReturn(ctx);
        when(metricsService.meter(anyString())).thenReturn(meter);
        when(metricsService.timer(anyString())).thenReturn(timer);

        context.registerService(ResourceResolverFactory.class, resourceResolverFactory);
        context.registerService(MetricsService.class, metricsService);
        context.registerInjectActivateService(authenticator);
    }

    @Test
    public void testHandleSecurity() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getServletPath()).thenReturn("/");
        when(req.getServerName()).thenReturn("localhost");
        when(req.getServerPort()).thenReturn(80);
        when(req.getScheme()).thenReturn("http");
        when(req.getRequestURI()).thenReturn("http://localhost:80/");

        HttpServletResponse resp = mock(HttpServletResponse.class);
        authenticator.handleSecurity(req, resp);

        verify(timer).time();
        verify(ctx).stop();
        verify(meter).mark();
        verifyNoMoreInteractions(timer, meter, ctx);
    }

}