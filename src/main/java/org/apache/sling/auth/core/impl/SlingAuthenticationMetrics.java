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

import org.apache.sling.commons.metrics.Meter;
import org.apache.sling.commons.metrics.MetricsService;
import org.apache.sling.commons.metrics.Timer;
import org.jetbrains.annotations.NotNull;

class SlingAuthenticationMetrics {

    static final String AUTHENTICATE_TIMER_NAME = "sling.auth.core.authenticate.timer";
    static final String AUTHENTICATE_SUCCESS_METER_NAME = "sling.auth.core.authenticate.success";
    static final String AUTHENTICATE_FAILED_METER_NAME = "sling.auth.core.authenticate.failed";

    private final Timer authenticateTimer;
    private final Meter authenticateSuccess;
    private final Meter authenticateFailed;

    SlingAuthenticationMetrics(@NotNull MetricsService metricsService) {
        authenticateTimer = metricsService.timer(AUTHENTICATE_TIMER_NAME);
        authenticateSuccess = metricsService.meter(AUTHENTICATE_SUCCESS_METER_NAME);
        authenticateFailed = metricsService.meter(AUTHENTICATE_FAILED_METER_NAME);
    }

    @NotNull
    Timer.Context authenticationTimerContext() {
        return authenticateTimer.time();
    }

    void authenticateCompleted(boolean success) {
        if (success) {
            authenticateSuccess.mark();
        } else {
            authenticateFailed.mark();
        }
    }
}