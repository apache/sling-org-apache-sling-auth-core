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
package org.apache.sling.auth.core.spi;

import java.util.Collection;
import java.util.Collections;
import java.util.Map.Entry;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

/**
 * Verify that ReadOnlyAuthenticationInfo instances are immutable
 */
public class ReadOnlyAuthenticationInfoTest {
    private AuthenticationInfo authInfo;

    @Before
    public void before() {
        // create a clone so each test starts with a fresh object
        authInfo = (AuthenticationInfo) AuthenticationInfo.FAIL_AUTH.clone();
    }

    @Test
    public void testGetAuthType() {
        assertEquals("FAIL_AUTH", authInfo.getAuthType());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testSetAuthType() {
        authInfo.setAuthType("newValue");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testSetUser() {
        authInfo.setUser("newUser");
    }

    @Test
    public void testGetUser() {
        assertNull(authInfo.getUser());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testSetPassword() {
        authInfo.setPassword("newPwd".toCharArray());
    }

    @Test
    public void testGetPassword() {
        assertNull(authInfo.getPassword());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testPut() {
        authInfo.put("hello", "world");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testPutAll() {
        authInfo.putAll(Collections.singletonMap("hello", "world"));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testRemove() {
        authInfo.remove(AuthenticationInfo.AUTH_TYPE);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testClear() {
        authInfo.clear();
    }

    @Test
    public void testKeySet() {
        Set<String> keySet = authInfo.keySet();
        assertNotNull(keySet);
        assertThrows(UnsupportedOperationException.class, keySet::clear);
    }

    @Test
    public void testValues() {
        Collection<Object> values = authInfo.values();
        assertNotNull(values);
        assertThrows(UnsupportedOperationException.class, values::clear);
    }

    @Test
    public void testEntrySet() {
        Set<Entry<String, Object>> entrySet = authInfo.entrySet();
        assertNotNull(entrySet);
        assertThrows(UnsupportedOperationException.class, entrySet::clear);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testPutIfAbsent() {
        authInfo.putIfAbsent("hello", "world");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testRemoveExpectedValue() {
        authInfo.remove(AuthenticationInfo.AUTH_TYPE, "FAIL_AUTH");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testReplaceOldEntry() {
        authInfo.replace(AuthenticationInfo.AUTH_TYPE, "FAIL_AUTH", "newValue");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testReplace() {
        authInfo.replace(AuthenticationInfo.AUTH_TYPE, "FAIL_AUTH");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testComputeIfAbsent() {
        authInfo.computeIfAbsent("key", k -> "hello");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testComputeIfPresent() {
        authInfo.computeIfPresent("key", (k, v) -> "hello");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testCompute() {
        authInfo.compute("key", (k, v) -> "hello");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testMerge() {
        authInfo.merge("hello", "world", (v1, v2) -> "newValue");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testReplaceAll() {
        authInfo.replaceAll((k, v1) -> "newValue");
    }

    @Test
    public void testHashCode() {
        int failAuthHashCode = authInfo.hashCode();
        int failAuthHashCode2 = authInfo.hashCode();
        assertEquals(failAuthHashCode, failAuthHashCode2);

        int doingAuthHashCode = AuthenticationInfo.DOING_AUTH.hashCode();
        assertNotEquals(failAuthHashCode, doingAuthHashCode);
    }

    @Test
    public void testEquals() {
        assertEquals(authInfo, authInfo);
        assertNotEquals(authInfo, AuthenticationInfo.DOING_AUTH);
    }

    @Test
    public void testClone() {
        Object clone = authInfo.clone();
        assertEquals(authInfo, clone);
        assertNotSame(authInfo, clone);
    }
}
