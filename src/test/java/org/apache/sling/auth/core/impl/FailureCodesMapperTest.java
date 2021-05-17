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

import static org.apache.sling.auth.core.impl.FailureCodesMapper.getFailureReason;

import javax.jcr.SimpleCredentials;
import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.CredentialExpiredException;

import org.apache.sling.api.resource.LoginException;
import org.apache.sling.auth.core.spi.AuthenticationHandler.FAILURE_REASON_CODES;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Test;

public class FailureCodesMapperTest {

    private final AuthenticationInfo dummyAuthInfo = new AuthenticationInfo("dummy");

    @Test
    public void unknown() {
        MatcherAssert.assertThat(
            getFailureReason(dummyAuthInfo, new RuntimeException()),
            CoreMatchers.equalTo(FAILURE_REASON_CODES.UNKNOWN));
    }

    @Test
    public void loginExceptionWithNoCause() {
        MatcherAssert.assertThat(
            getFailureReason(dummyAuthInfo, new LoginException("Something went wrong")),
            CoreMatchers.equalTo(FAILURE_REASON_CODES.INVALID_LOGIN));
    }

    @Test
    public void passwordExpired() {
        MatcherAssert.assertThat(
            getFailureReason(dummyAuthInfo, new LoginException(new CredentialExpiredException())),
            CoreMatchers.equalTo(FAILURE_REASON_CODES.PASSWORD_EXPIRED));
    }

    @Test
    public void accountLocked() {
        MatcherAssert.assertThat(
            getFailureReason(dummyAuthInfo, new LoginException(new AccountLockedException())),
            CoreMatchers.equalTo(FAILURE_REASON_CODES.ACCOUNT_LOCKED));
    }

    @Test
    public void accountNotFound() {
        MatcherAssert.assertThat(
            getFailureReason(dummyAuthInfo, new LoginException(new AccountNotFoundException())),
            CoreMatchers.equalTo(FAILURE_REASON_CODES.ACCOUNT_NOT_FOUND));
    }

    @Test
    public void expiredToken() {
        MatcherAssert.assertThat(
            getFailureReason(dummyAuthInfo, new LoginException(new TokenCredentialsExpiredException())),
            CoreMatchers.equalTo(FAILURE_REASON_CODES.EXPIRED_TOKEN));
    }

    @Test
    public void passwordExpiredAndNewPasswordInHistory() {

        AuthenticationInfo info = new AuthenticationInfo("dummy");
        SimpleCredentials credentials = new SimpleCredentials("ignored", "ignored".toCharArray());
        credentials.setAttribute("PasswordHistoryException", new Object()); // value is not checked
        info.put("user.jcr.credentials", credentials);

        MatcherAssert.assertThat(
            getFailureReason(info, new LoginException(new CredentialExpiredException())),
            CoreMatchers.equalTo(FAILURE_REASON_CODES.PASSWORD_EXPIRED_AND_NEW_PASSWORD_IN_HISTORY));
    }

    // doubles for an Oak class
    static class TokenCredentialsExpiredException extends Exception {

        private static final long serialVersionUID = 1L;

    }

}
