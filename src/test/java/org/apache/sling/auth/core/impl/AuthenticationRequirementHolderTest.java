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

import org.junit.Assert;
import org.junit.Test;

public class AuthenticationRequirementHolderTest {

    @Test
    public void test_fromConfig_plus() {
        AuthenticationRequirementHolder h = AuthenticationRequirementHolder.fromConfig("+/secure", null);
        Assert.assertTrue(h.requiresAuthentication());
        Assert.assertEquals("/secure", h.fullPath);
    }

    @Test
    public void test_fromConfig_minus() {
        AuthenticationRequirementHolder h = AuthenticationRequirementHolder.fromConfig("-/open", null);
        Assert.assertFalse(h.requiresAuthentication());
        Assert.assertEquals("/open", h.fullPath);
    }

    @Test
    public void test_fromConfig_plain() {
        AuthenticationRequirementHolder h = AuthenticationRequirementHolder.fromConfig("/plain", null);
        Assert.assertTrue(h.requiresAuthentication());
        Assert.assertEquals("/plain", h.fullPath);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_fromConfig_null() {
        AuthenticationRequirementHolder.fromConfig(null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_fromConfig_empty() {
        AuthenticationRequirementHolder.fromConfig("", null);
    }

    @Test
    public void test_hashCode_equals() {
        AuthenticationRequirementHolder a = new AuthenticationRequirementHolder("/p", true, null);
        AuthenticationRequirementHolder b = new AuthenticationRequirementHolder("/p", true, null);
        AuthenticationRequirementHolder c = new AuthenticationRequirementHolder("/p", false, null);

        Assert.assertEquals(a, b);
        Assert.assertEquals(a.hashCode(), b.hashCode());
        Assert.assertNotEquals(a, c);
        Assert.assertNotEquals(a.hashCode(), c.hashCode());
        Assert.assertEquals(a, a);
        Assert.assertNotEquals(a, null);
        Assert.assertNotEquals(a, "not a holder");
    }
}
