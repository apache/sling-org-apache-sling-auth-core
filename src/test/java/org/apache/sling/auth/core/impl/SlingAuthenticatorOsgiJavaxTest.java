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

import static org.apache.sling.auth.core.impl.SlingAuthenticationMetrics.AUTHENTICATE_FAILED_METER_NAME;
import static org.apache.sling.auth.core.impl.SlingAuthenticationMetrics.AUTHENTICATE_SUCCESS_METER_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.auth.core.LoginEventDecorator;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.commons.metrics.Meter;
import org.apache.sling.commons.metrics.MetricsService;
import org.apache.sling.commons.metrics.Timer;
import org.apache.sling.testing.mock.osgi.junit.OsgiContext;
import org.awaitility.Awaitility;
import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mockito;
import org.osgi.service.event.Event;
import org.osgi.service.event.EventHandler;

public class SlingAuthenticatorOsgiJavaxTest {

    @Rule
    public final OsgiContext context = new OsgiContext();

    private Meter successMeter = mock(Meter.class);
    private Meter failedMeter = mock(Meter.class);
    private Timer.Context ctx = mock(Timer.Context.class);
    private Timer timer = mock(Timer.class);
    private final MetricsService metricsService = mock(MetricsService.class);
    private final AuthenticationHandler testAuthHandler = mock(AuthenticationHandler.class);
    private final TestEventHandler testEventHandler = new TestEventHandler();
    private final ResourceResolverFactory resourceResolverFactory = mock(ResourceResolverFactory.class);

    private SlingAuthenticator authenticator;

    @Before
    public void before() throws Exception {
        ResourceResolver rr = mock(ResourceResolver.class);

        when(resourceResolverFactory.getResourceResolver(any(AuthenticationInfo.class))).thenReturn(rr);

        when(timer.time()).thenReturn(ctx);
        when(metricsService.meter(AUTHENTICATE_SUCCESS_METER_NAME)).thenReturn(successMeter);
        when(metricsService.meter(AUTHENTICATE_FAILED_METER_NAME)).thenReturn(failedMeter);
        when(metricsService.timer(anyString())).thenReturn(timer);

        context.registerService(ResourceResolverFactory.class, resourceResolverFactory);
        context.registerService(MetricsService.class, metricsService);
        context.registerInjectActivateService(SlingAuthenticationMetrics.class);
        context.registerInjectActivateService(AuthenticationRequirementsManager.class);

        //register a test auth handler
        context.registerService(AuthenticationHandler.class, testAuthHandler, Collections.singletonMap(AuthenticationHandler.PATH_PROPERTY, new String[] {"/"}));
        context.registerService(EventHandler.class, testEventHandler);
        context.registerService(LoginEventDecorator.class, new TestLoginEventDecorator());

        context.registerInjectActivateService(AuthenticationHandlersManager.class);
        authenticator = context.registerInjectActivateService(SlingAuthenticator.class);
    }

    /**
     * Verify decoration of a login event
     */
    @Test
    public void testLoginEventDecoration() {
        assertLoginEvent(
                (req, resp) -> {
                    // provide test authInfo
                    AuthenticationInfo authInfo = new AuthenticationInfo("testing", "admin", "admin".toCharArray());
                    authInfo.put(AuthConstants.AUTH_INFO_LOGIN, Boolean.TRUE);
                    when(req.getRequestURL()).thenReturn(new StringBuffer("/test"));
                    when(testAuthHandler.extractCredentials(Mockito.any(), Mockito.any())).thenReturn(authInfo);
                },
                () -> testEventHandler.collectedEvents(AuthConstants.TOPIC_LOGIN),
                event -> assertEquals("test1Value", event.getProperty("test1"))
            );
    }

    /**
     * Verify decoration of a login failed event
     */
    @Test
    public void testLoginFailedEventDecoration() {
        assertLoginEvent(
                (req, resp) -> {
                    // provide invalid test authInfo
                    AuthenticationInfo authInfo = new AuthenticationInfo("testing", "invalid", "invalid".toCharArray());
                    when(req.getRequestURL()).thenReturn(new StringBuffer("/testing"));
                    when(testAuthHandler.extractCredentials(Mockito.any(), Mockito.any())).thenReturn(authInfo);
                    // throw exception to trigger FailedLogin event
                    try {
                        when(resourceResolverFactory.getResourceResolver(authInfo)).thenThrow(new LoginException("Test LoginFailed"));
                    } catch (LoginException e) {
                        // should never get here as the LoginException should be caught by the SlingAuthenticator
                        fail("Unexpected exception caught: " + e.getMessage());
                    }
                },
                () -> testEventHandler.collectedEvents(AuthConstants.TOPIC_LOGIN_FAILED),
                event -> assertEquals("test2Value", event.getProperty("test2"))
            );
    }

    /**
     * The common parts for verifying the LoginEvent properties to avoid
     * code duplication in the similar tests
     *
     * @param prepareAuthInfo to do the work of mocking the authInfo
     * @param collectEvents to do the work of collecting the delivered events
     * @param verifyEvent to do the work to assert that the event has the expected state
     */
    protected void assertLoginEvent(BiConsumer<HttpServletRequest, HttpServletResponse> prepareAuthInfo,
            Supplier<List<Event>> collectEvents,
            Consumer<Event> verifyEvent) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getServletPath()).thenReturn("/");
        when(req.getServerName()).thenReturn("localhost");
        when(req.getServerPort()).thenReturn(80);
        when(req.getScheme()).thenReturn("http");
        when(req.getRequestURI()).thenReturn("http://localhost:80/");

        HttpServletResponse resp = mock(HttpServletResponse.class);

        // prepare the auth mocks
        prepareAuthInfo.accept(req, resp);

        testEventHandler.clear();
        authenticator.handleSecurity(req, resp);

        // wait for the login event to arrive
        Awaitility.await("eventDelivery")
            .atMost(Duration.ofSeconds(5))
            .pollInterval(Duration.ofMillis(100))
            .until(() -> {
                List<Event> events = collectEvents.get();
                return !events.isEmpty();
            });
        List<Event> events = collectEvents.get();
        assertEquals(1, events.size());
        // make sure the event has the state that we expect
        verifyEvent.accept(events.get(0));
    }

    /**
     * EventHandler that collects the events that were delivered for inspection
     */
    static class TestEventHandler implements EventHandler {
        private Map<String, List<Event>> collectedEvents = new HashMap<>();

        public void clear() {
            collectedEvents.clear();
        }

        public @NotNull List<Event> collectedEvents(String topic) {
            List<Event> list = collectedEvents.get(topic);
            return list == null ? Collections.emptyList() : new ArrayList<>(list);
        }

        @Override
        public void handleEvent(Event event) {
            String topic = event.getTopic();
            // collect the event if it is one of the topics we are interested in
            if (AuthConstants.TOPIC_LOGIN_FAILED.equals(topic) ||
                    AuthConstants.TOPIC_LOGIN.equals(topic)) {
                List<Event> list = collectedEvents.computeIfAbsent(topic, t -> new ArrayList<>());
                list.add(event);
            }
        }

    }

    /**
     * Test login event decorator that adds a test value to the event properties
     */
    static class TestLoginEventDecorator implements LoginEventDecorator {

        @Override
        public @NotNull void decorateLoginEvent(@NotNull javax.servlet.http.HttpServletRequest request,
                @NotNull AuthenticationInfo authInfo, @NotNull Map<String, Object> eventProperties) {
            eventProperties.put("test1", "test1Value");
        }

        @Override
        public @NotNull void decorateLoginFailedEvent(@NotNull javax.servlet.http.HttpServletRequest request,
                @NotNull AuthenticationInfo authInfo, @NotNull Map<String, Object> eventProperties) {
            eventProperties.put("test2", "test2Value");
        }

    }

}