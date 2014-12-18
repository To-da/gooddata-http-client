/*
 * Copyright (C) 2007-2014, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class TokenUtilsTest {
    @Test
    public void extractTokenFromBody_validSst() throws IOException {
        String tt = TokenUtils.extractTokenFromBody("{" +
                "\"userLogin\" : {" +
                "   \"profile\" : \"/gdc/account/profile/1\"," +
                "   \"token\" : \"nbWW7peskrKbSMYj\"," +
                "   \"state\" : \"/gdc/account/login/1\"" +
                "}" +
                "}", "userLogin");
        assertEquals("nbWW7peskrKbSMYj", tt);
    }

    @Test
    public void extractTokenFromBody_validTt() throws IOException {
        String tt = TokenUtils.extractTokenFromBody("{" +
                "\"userToken\" : {" +
                "   \"token\" : \"nbWW7peskrKbSMYj\"" +
                "}" +
                "}", "userToken");
        assertEquals("nbWW7peskrKbSMYj", tt);
    }
}
