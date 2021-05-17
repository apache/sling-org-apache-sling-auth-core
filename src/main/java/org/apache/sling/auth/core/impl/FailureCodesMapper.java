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

import javax.jcr.SimpleCredentials;
import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.CredentialExpiredException;

import org.apache.sling.api.resource.LoginException;
import org.apache.sling.auth.core.spi.AuthenticationHandler.FAILURE_REASON_CODES;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.jetbrains.annotations.NotNull;

public final class FailureCodesMapper {

    /**
     * Determine the failure reason from the thrown exception
     *
     * @param authInfo The authentication info
     * @param reason The exception
     *
     * @return The failure code, possibly <tt>unknown</tt> if no mapping could be found
     */
    public static @NotNull FAILURE_REASON_CODES getFailureReason(final AuthenticationInfo authInfo, Exception reason) {

        FAILURE_REASON_CODES code = FAILURE_REASON_CODES.UNKNOWN;
        if (reason instanceof LoginException) {
            if (reason.getCause() instanceof CredentialExpiredException) {
                // force failure attribute to be set so handlers can
                // react to this special circumstance
                Object creds = authInfo.get("user.jcr.credentials");
                if (creds instanceof SimpleCredentials && ((SimpleCredentials) creds).getAttribute("PasswordHistoryException") != null) {
                    code = FAILURE_REASON_CODES.PASSWORD_EXPIRED_AND_NEW_PASSWORD_IN_HISTORY;
                } else {
                    code = FAILURE_REASON_CODES.PASSWORD_EXPIRED;
                }
            } else if (reason.getCause() instanceof AccountLockedException) {
                code = FAILURE_REASON_CODES.ACCOUNT_LOCKED;
            } else if (reason.getCause() instanceof AccountNotFoundException) {
                code = FAILURE_REASON_CODES.ACCOUNT_NOT_FOUND;
            } else if (isTokenCredentialsExpiredException(reason)) {
                code = FAILURE_REASON_CODES.EXPIRED_TOKEN;
            } else {
                // default to invalid login as the reason
                code = FAILURE_REASON_CODES.INVALID_LOGIN;
            }
        }

        return code;
    }

    private static boolean isTokenCredentialsExpiredException(Exception reason) {
        // we don't want to strongly bind to Oak class names, so we use the String form here
        // requires Oak 1.40+ ( https://issues.apache.org/jira/browse/OAK-9433 )
        return reason.getCause() != null
                && reason.getCause().getClass().getSimpleName().equals("TokenCredentialsExpiredException"); // NOSONAR
    }

    private FailureCodesMapper() {
        // prevent instantiation
    }
}
