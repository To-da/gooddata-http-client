/*
 * Copyright (C) 2007-2014, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.http.HttpResponse;
import org.apache.http.entity.StringEntity;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TokenUtilsTest {
    @Test
    public void extractTokenFromBody_validSst() throws Exception {
        String tt = TokenUtils.extractSST(response("{" +
                "\"userLogin\" : {" +
                "   \"profile\" : \"/gdc/account/profile/1\"," +
                "   \"token\" : \"nbWW7peskrKbSMYj\"," +
                "   \"state\" : \"/gdc/account/login/1\"" +
                "}" +
                "}"));
        assertEquals("nbWW7peskrKbSMYj", tt);
    }

    @Test
    public void extractTokenFromBody_validTt() throws Exception {
        String tt = TokenUtils.extractTT(response("{" +
                "\"userToken\" : {" +
                "   \"token\" : \"nbWW7peskrKbSMYj\"" +
                "}" +
                "}"));
        assertEquals("nbWW7peskrKbSMYj", tt);
    }

    private static HttpResponse response(final String body) throws UnsupportedEncodingException {
        final HttpResponse response = mock(HttpResponse.class);
        when(response.getEntity()).thenReturn(new StringEntity(body));
        return response;
    }
}
