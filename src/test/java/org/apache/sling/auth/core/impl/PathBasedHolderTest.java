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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class PathBasedHolderTest {

    @Test public void TestIsPathRequiresHandlerRoot() {
        final PathBasedHolder holder = new PathBasedHolder("/", null){};

        assertTrue(holder.isPathRequiresHandler("/"));
        assertTrue(holder.isPathRequiresHandler("/a"));
        assertTrue(holder.isPathRequiresHandler("/a/b"));
        assertTrue(holder.isPathRequiresHandler("/a/b/c"));
        assertTrue(holder.isPathRequiresHandler("/a.html"));
        assertTrue(holder.isPathRequiresHandler("/a/b.html"));
        assertTrue(holder.isPathRequiresHandler("/a/b/c.html"));
    }

    @Test public void TestIsPathRequiresHandlerPrefix() {
        final PathBasedHolder holder = new PathBasedHolder("/a/b", null){};

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
        final PathBasedHolder holder = new PathBasedHolder(handlerPath, null){};

        assertTrue(holder.isPathRequiresHandler(requestPath));
    }

    private void assertPathRequiresHandler(boolean expected, String requestPath, String handlerPath) {
        final PathBasedHolder holder = new PathBasedHolder(handlerPath, null){};
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
}
