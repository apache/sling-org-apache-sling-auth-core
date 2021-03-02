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

import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.commons.metrics.Meter;
import org.apache.sling.commons.metrics.MetricsService;
import org.apache.sling.commons.metrics.Timer;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class SlingAuthenticationMetricsTest {

    private Meter meter = mock(Meter.class);
    private Timer.Context ctx = mock(Timer.Context.class);
    private Timer timer = mock(Timer.class);
    private final MetricsService metricsService = mock(MetricsService.class);

    private SlingAuthenticationMetrics metrics;

    @Before
    public void before() {
        when(timer.time()).thenReturn(ctx);
        when(metricsService.meter(anyString())).thenReturn(meter);
        when(metricsService.timer(anyString())).thenReturn(timer);

        metrics = new SlingAuthenticationMetrics(metricsService);

        verify(metricsService).timer(anyString());
        verify(metricsService, times(2)).meter(anyString());
    }

    @Test
    public void testAuthenticationCompleted() {
        metrics.authenticateCompleted(true);
        metrics.authenticateCompleted(false);
        verify(meter, times(2)).mark();
        verifyNoMoreInteractions(meter);
        verifyNoInteractions(timer, ctx);
    }

    @Test
    public void testAuthenticationTimerContext() {
        Timer.Context timerContext = metrics.authenticationTimerContext();
        timerContext.stop();

        verify(timer).time();
        verify(ctx).stop();
        verifyNoMoreInteractions(timer, ctx);
        verifyNoInteractions(meter);
    }
}