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
package org.apache.sling.auth.core.impl.hc;

import javax.jcr.Credentials;
import javax.jcr.LoginException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;

import java.util.Arrays;

import org.apache.felix.hc.api.Result;
import org.apache.sling.jcr.api.SlingRepository;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DefaultLoginsHealthCheckTest {

    private Result getTestResult(String login) throws Exception {
        final DefaultLoginsHealthCheck c = new DefaultLoginsHealthCheck();
        if (login == null) {
            SetField.set(c, "logins", Arrays.asList(new String[0]));
        } else {
            SetField.set(c, "logins", Arrays.asList(new String[] {login}));
        }

        final SlingRepository repo = Mockito.mock(SlingRepository.class);
        SetField.set(c, "repository", repo);
        final Session s = Mockito.mock(Session.class);
        Mockito.when(repo.login(ArgumentMatchers.any(Credentials.class))).thenAnswer(new Answer<Session>() {
            @Override
            public Session answer(InvocationOnMock invocation) throws LoginException {
                final SimpleCredentials c = (SimpleCredentials) invocation.getArguments()[0];
                if ("admin".equals(c.getUserID())) {
                    return s;
                } else if ("throw".equals(c.getUserID())) {
                    throw new LoginException("Login Failed");
                }
                return null;
            }
        });

        return c.execute();
    }

    @Test
    public void testHealthCheckFails() throws Exception {
        assertFalse("Expecting failed check", getTestResult("admin:admin").isOk());
    }

    @Test
    public void testHealthCheckSucceeds() throws Exception {
        assertTrue("Expecting successful check", getTestResult("FOO:bar").isOk());
    }

    @Test
    public void testHealthCheckInvalidLogins() throws Exception {
        Result testResult = getTestResult("FOO");
        assertFalse("Expecting successful check", testResult.isOk());
        assertTrue(
                "Expected warning in the ResultLog",
                testResult.toString().contains("WARN Expected login in the form username:password, got [FOO]"));
    }

    @Test
    public void testHealthCheckEmptyLogins() throws Exception {
        Result testResult = getTestResult(null);
        assertFalse("Expecting failed check", testResult.isOk());
        assertTrue(
                "Expected warning in the ResultLog",
                testResult.toString().contains("WARN Did not check any logins, configured logins=[]"));
    }

    @Test
    public void testHealthCheckSucceedsWithLoginException() throws Exception {
        Result testResult = getTestResult("throw:loginexception");
        assertTrue("Expecting successful check", testResult.isOk());
        assertTrue(
                "Expected debug in the ResultLog",
                testResult.toString().contains("DEBUG Login as [throw] failed, as expected"));
    }
}
