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

import java.io.Closeable;
import java.io.IOException;

import org.apache.sling.commons.metrics.Meter;
import org.apache.sling.commons.metrics.MetricsService;
import org.apache.sling.commons.metrics.Timer;
import org.junit.Before;
import org.junit.Test;

import static org.apache.sling.auth.core.impl.SlingAuthenticationMetrics.AUTHENTICATE_FAILED_METER_NAME;
import static org.apache.sling.auth.core.impl.SlingAuthenticationMetrics.AUTHENTICATE_SUCCESS_METER_NAME;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class SlingAuthenticationMetricsTest {

    private Meter successMeter = mock(Meter.class);
    private Meter failedMeter = mock(Meter.class);
    private Timer.Context ctx = mock(Timer.Context.class);
    private Timer timer = mock(Timer.class);
    private final MetricsService metricsService = mock(MetricsService.class);

    private SlingAuthenticationMetrics metrics;

    @Before
    public void before() {
        when(timer.time()).thenReturn(ctx);
        when(metricsService.meter(AUTHENTICATE_SUCCESS_METER_NAME)).thenReturn(successMeter);
        when(metricsService.meter(AUTHENTICATE_FAILED_METER_NAME)).thenReturn(failedMeter);
        when(metricsService.timer(anyString())).thenReturn(timer);

        metrics = new SlingAuthenticationMetrics(metricsService);

        verify(metricsService).timer(anyString());
        verify(metricsService, times(2)).meter(anyString());
    }

    @Test
    public void testAuthenticationCompletedSuccess() {
        metrics.authenticateCompleted(true);
        verify(successMeter, times(1)).mark();
        verify(failedMeter, never()).mark();
        verifyNoMoreInteractions(successMeter, failedMeter);
        verifyNoInteractions(timer, ctx);
    }

    @Test
    public void testAuthenticationCompletedFailed() {
        metrics.authenticateCompleted(false);
        verify(failedMeter, times(1)).mark();
        verify(successMeter, never()).mark();
        verifyNoMoreInteractions(successMeter, failedMeter);
        verifyNoInteractions(timer, ctx);
    }

    @Test
    public void testAuthenticationTimerContext() throws IOException {
        Closeable timerContext = metrics.authenticationTimerContext();
        timerContext.close();

        verify(timer).time();
        verify(ctx).close();
        verifyNoMoreInteractions(timer, ctx);
        verifyNoInteractions(successMeter, failedMeter);
    }
}
