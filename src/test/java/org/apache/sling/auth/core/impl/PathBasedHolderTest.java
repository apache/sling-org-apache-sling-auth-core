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
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PathBasedHolderTest {

    private static PathBasedHolder holder(String url, ServiceReference<?> ref) {
        return new PathBasedHolder(url, ref) {};
    }

    @Test
    public void TestIsPathRequiresHandlerRoot() {
        final PathBasedHolder holder = new PathBasedHolder("/", null) {};

        assertTrue(holder.isPathRequiresHandler("/"));
        assertTrue(holder.isPathRequiresHandler("/a"));
        assertTrue(holder.isPathRequiresHandler("/a/b"));
        assertTrue(holder.isPathRequiresHandler("/a/b/c"));
        assertTrue(holder.isPathRequiresHandler("/a.html"));
        assertTrue(holder.isPathRequiresHandler("/a/b.html"));
        assertTrue(holder.isPathRequiresHandler("/a/b/c.html"));
    }

    @Test
    public void TestIsPathRequiresHandlerPrefix() {
        final PathBasedHolder holder = new PathBasedHolder("/a/b", null) {};

        assertFalse(holder.isPathRequiresHandler("/"));
        assertFalse(holder.isPathRequiresHandler("/a"));
        assertTrue(holder.isPathRequiresHandler("/a/b"));
        assertTrue(holder.isPathRequiresHandler("/a/b/c"));
        assertFalse(holder.isPathRequiresHandler("/a.html"));
        assertTrue(holder.isPathRequiresHandler("/a/b.html"));
        assertTrue(holder.isPathRequiresHandler("/a/b/c.html"));

        assertFalse(holder.isPathRequiresHandler("/a/c"));
    }

    @Test
    public void test_childNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test/test2";
        final String handlerPath = "/content/test";
        final PathBasedHolder holder = new PathBasedHolder(handlerPath, null) {};

        assertTrue(holder.isPathRequiresHandler(requestPath));
    }

    private void assertPathRequiresHandler(boolean expected, String requestPath, String handlerPath) {
        final PathBasedHolder holder = new PathBasedHolder(handlerPath, null) {};
        assertEquals(expected, holder.isPathRequiresHandler(requestPath));
    }

    @Test
    public void test_siblingNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test2.html/en/2016/09/19/test.html";
        final String handlerPath = "/content/test";
        assertPathRequiresHandler(false, requestPath, handlerPath);
    }

    @Test
    public void test_actualNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test";
        final String handlerPath = "/content/test";
        assertPathRequiresHandler(true, requestPath, handlerPath);
    }

    @Test
    public void test_rootNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test";
        final String handlerPath = "/";
        assertPathRequiresHandler(true, requestPath, handlerPath);
    }

    @Test
    public void test_requestPathSelectorsAreTakenInConsideration() throws Throwable {
        final String requestPath = "/content/test.selector1.selector2.html/en/2016/test.html";
        final String handlerPath = "/content/test";
        assertPathRequiresHandler(true, requestPath, handlerPath);
    }

    @Test
    public void test_requestPathSelectorsSiblingAreTakenInConsideration() throws Throwable {
        final String requestPath = "/content/test.selector1.selector2.html/en/2016/09/19/test.html";
        final String handlerPath = "/content/test2";
        assertPathRequiresHandler(false, requestPath, handlerPath);
    }

    @Test
    public void test_requestPathBackSlash() throws Throwable {
        final String requestPath = "/page1\\somesubepage";
        final String handlerPath = "/page";
        assertPathRequiresHandler(false, requestPath, handlerPath);
    }

    @Test
    public void test_emptyNodeAuthenticationHandlerPath() throws Throwable {
        final String requestPath = "/content/test";
        final String handlerPath = "";
        assertPathRequiresHandler(true, requestPath, handlerPath);
    }

    @Test
    public void test_getProvider_noReference() {
        assertEquals("Apache Sling Request Authenticator", holder("/x", null).getProvider());
    }

    @Test
    public void test_getProvider_description() {
        ServiceReference<?> ref = mock(ServiceReference.class);
        when(ref.getProperty(Constants.SERVICE_DESCRIPTION)).thenReturn("My Service");
        assertEquals("My Service", holder("/x", ref).getProvider());
    }

    @Test
    public void test_getProvider_serviceId() {
        ServiceReference<?> ref = mock(ServiceReference.class);
        when(ref.getProperty(Constants.SERVICE_DESCRIPTION)).thenReturn(null);
        when(ref.getProperty(Constants.SERVICE_ID)).thenReturn(42L);
        assertEquals("Service 42", holder("/x", ref).getProvider());
    }

    @Test
    public void test_protocol_and_host_parsing() {
        PathBasedHolder h = holder("http://example.com/some/path", null);
        assertTrue(h.isPathRequiresHandler("/some/path"));

        // host only with trailing content
        PathBasedHolder h2 = holder("//example.com/foo", null);
        assertTrue(h2.isPathRequiresHandler("/foo"));

        // host only, no path
        PathBasedHolder h3 = holder("//example.com", null);
        assertTrue(h3.isPathRequiresHandler("/anything"));

        // just double slash
        PathBasedHolder h4 = holder("//", null);
        assertTrue(h4.isPathRequiresHandler("/anything"));
    }

    @Test
    public void test_hashCode_and_equals() {
        PathBasedHolder a = holder("/x", null);
        PathBasedHolder b = holder("/x", null);
        assertEquals(a.hashCode(), b.hashCode());
        assertEquals(a, b);
        Assert.assertNotEquals(a, holder("/y", null));
        Assert.assertNotEquals(a, null);
        Assert.assertNotEquals(a, "not a holder");
        assertEquals(a, a);
    }

    @Test
    public void test_equals_differentServiceReference() {
        ServiceReference<?> ref = mock(ServiceReference.class);
        Assert.assertNotEquals(holder("/x", ref), holder("/x", null));
        assertEquals(holder("/x", ref), holder("/x", ref));
    }

    @Test
    public void test_compareTo_byPath() {
        PathBasedHolder a = holder("/a", null);
        PathBasedHolder b = holder("/b", null);
        assertTrue(a.compareTo(b) > 0);
        assertTrue(b.compareTo(a) < 0);
    }

    @Test
    public void test_compareTo_nullServiceReferences() {
        PathBasedHolder a = holder("/same", null);
        PathBasedHolder b = holder("/same", null);
        // both null service references -> compared by class name (same class) -> 0
        assertEquals(0, a.compareTo(b));
    }

    @Test
    public void test_compareTo_oneNullServiceReference() {
        ServiceReference<?> ref = mock(ServiceReference.class);
        PathBasedHolder withRef = holder("/same", ref);
        PathBasedHolder withoutRef = holder("/same", null);
        assertEquals(-1, withoutRef.compareTo(withRef));
        assertEquals(1, withRef.compareTo(withoutRef));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    public void test_compareTo_byServiceReference() {
        ServiceReference refA = mock(ServiceReference.class);
        ServiceReference refB = mock(ServiceReference.class);
        when(refB.compareTo(refA)).thenReturn(5);
        PathBasedHolder a = holder("/same", refA);
        PathBasedHolder b = holder("/same", refB);
        assertEquals(5, a.compareTo(b));
    }
}
