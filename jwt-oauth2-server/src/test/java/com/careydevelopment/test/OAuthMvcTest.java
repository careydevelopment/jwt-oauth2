package com.careydevelopment.test;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import com.careydevelopment.oauth2.server.AuthorizationServerApplication;


@RunWith(SpringRunner.class)
@WebAppConfiguration
@SpringBootTest(classes = AuthorizationServerApplication.class)
@ActiveProfiles("mvc")
public class OAuthMvcTest {

	@Autowired
	private BCryptPasswordEncoder encoder;
	
    @Autowired
    private WebApplicationContext wac;
    
    @Autowired
    private FilterChainProxy springSecurityFilterChain;

    private MockMvc mockMvc;

    private static final String CLIENT_ID = "fooClientIdPassword";
    private static final String CLIENT_SECRET = "secret";

    private static final String CONTENT_TYPE = "application/json;charset=UTF-8";

    private static final String EMAIL = "jim@yahoo.com";
    private static final String NAME = "Jim";

    private enum GrantType {
    	IMPLICIT, AUTHORIZATION_CODE, PASSWORD;
    }
    
    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac)
        		.addFilter(springSecurityFilterChain)
        		.apply(SecurityMockMvcConfigurers.springSecurity())
        		.build();
    }

    
    private String obtainAccessTokenWithPassword(String username, String password) throws Exception {
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", "fooClientIdPassword");
        params.add("username", username);
        params.add("password", password);

        // @formatter:off

        ResultActions result = mockMvc.perform(post("/oauth/token")
                               .params(params)
                               .with(httpBasic("fooClientIdPassword","secret"))
                               .accept(CONTENT_TYPE))
                               .andExpect(status().isOk())
                               .andExpect(content().contentType(CONTENT_TYPE));
        
        // @formatter:on

        String resultString = result.andReturn().getResponse().getContentAsString();

        JacksonJsonParser jsonParser = new JacksonJsonParser();
        return jsonParser.parseMap(resultString).get("access_token").toString();
    }

    @Test
    @WithMockUser(username = "john", password = "123", roles = "USER")    
    public void givenAuthorizationCode_whenGetToken_thenOk() {
    	String code = getAuthorizationCode();
    	String token = getTokenWithAuthorizationCode(code);
    	Assert.assertNotNull(token);
    	System.err.println(token);
    }

    
    @Test
    public void givenNoLogin_whenGetAuthorizationCode_thenRedirect() {
        try {
            final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("response_type", "code");
            params.add("client_id", "fooClientIdPassword");
            params.add("redirect_uri", "http://localhost:8080/login/oauth2/code/custom");

            // @formatter:off            
	        ResultActions result = mockMvc.perform(post("/oauth/authorize")
	                               .params(params)
	                               .accept(CONTENT_TYPE))
	                               .andExpect(status().is3xxRedirection());
	        // @formatter:on

	        String forwardUrl = result.andReturn().getResponse().getRedirectedUrl();
	        
	        Assert.assertNotNull(forwardUrl);
	        Assert.assertTrue(forwardUrl.indexOf("/login") > -1);
	    } catch (Exception e) {
        	e.printStackTrace();
        	Assert.fail();
        }
    }
    
    private String getTokenWithAuthorizationCode(String code) {
        String token = null;
        
    	try {
	        final MultiValueMap<String, String> tokenParams = new LinkedMultiValueMap<>();
	        tokenParams.add("grant_type", "authorization_code");
	        tokenParams.add("client_id", "fooClientIdPassword");
	        tokenParams.add("code", code);
	        tokenParams.add("redirect_uri", "http://localhost:8080/login/oauth2/code/custom");

	        // @formatter:off
	        ResultActions tokenResult = mockMvc.perform(post("/oauth/token")
	                               .params(tokenParams)
	                               .with(httpBasic("fooClientIdPassword","secret"))
	                               .accept(CONTENT_TYPE))
	                               .andExpect(status().isOk())
	                               .andExpect(content().contentType(CONTENT_TYPE));
	        
	        //System.err.println("tokenResult is " + tokenResult.andReturn().getResponse().getContentAsString());
	        // @formatter:on

	        String resultString = tokenResult.andReturn().getResponse().getContentAsString();

	        JacksonJsonParser jsonParser = new JacksonJsonParser();
	        token = jsonParser.parseMap(resultString).get("access_token").toString();
        } catch (Exception e) {
        	e.printStackTrace();
        	Assert.fail();
        }
    	
    	return token;
    }

    
    private String getAuthorizationCode() {
    	String code = null;
    	
        try {
            final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("response_type", "code");
            params.add("client_id", "fooClientIdPassword");
            params.add("redirect_uri", "http://localhost:8080/login/oauth2/code/custom");

            // @formatter:off            
	        ResultActions result = mockMvc.perform(post("/oauth/authorize")
	                               .params(params)
	                               .accept(CONTENT_TYPE))
	                               .andExpect(status().is3xxRedirection());
	        // @formatter:on

	        String forwardUrl = result.andReturn().getResponse().getRedirectedUrl();
	        Assert.assertNotNull(forwardUrl);
	        
	        MultiValueMap<String, String> parameters = UriComponentsBuilder.fromUriString(forwardUrl).build().getQueryParams();
	        List<String> codes = parameters.get("code");
	        Assert.assertNotNull(codes);
	        Assert.assertEquals(1, codes.size());
	        
	        code = codes.get(0);
	        Assert.assertNotNull(code);
	    } catch (Exception e) {
        	e.printStackTrace();
        	Assert.fail();
        }
        
        return code;
    }

    
//    @Test
//    public void givenNoToken_whenGetSecureRequest_thenUnauthorized() throws Exception {
//        mockMvc.perform(get("/employee").param("email", EMAIL)).andExpect(status().isUnauthorized());
//    }
//
//    @Test
//    public void givenInvalidRole_whenGetSecureRequest_thenForbidden() throws Exception {
//        final String accessToken = obtainAccessTokenWithPassword("user1", "pass");
//        System.out.println("token:" + accessToken);
//        mockMvc.perform(get("/employee").header("Authorization", "Bearer " + accessToken).param("email", EMAIL)).andExpect(status().isForbidden());
//    }


    private String obtainAccessTokenImplicit() throws Exception {
    	//http://localhost:8081/spring-security-oauth-server/oauth/authorize?response_type=id_token%20token&client_id=sampleClientId&state=whSBGywzbk3gNsq2wfVpRzMcCLXWE05qtqTR3hLB&redirect_uri=http%3A%2F%2Flocalhost%3A4200%2F&scope=openid%20read%20write%20foo%20bar&nonce=whSBGywzbk3gNsq2wfVpRzMcCLXWE05qtqTR3hLB
    	
    	String token = null;
    	
        try {
            final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("response_type", "token");
            params.add("client_id", "sampleClientId");
            params.add("redirect_uri", "http://localhost:8083/");
            params.add("scope", "read");

            // @formatter:off            
	        ResultActions result = mockMvc.perform(post("/oauth/authorize")
	                               .params(params)
	                               .accept(CONTENT_TYPE))
	                               .andExpect(status().is3xxRedirection());
	        // @formatter:on

	        MockHttpServletResponse response = result.andReturn().getResponse();
	        String forwardUrl = response.getRedirectedUrl();
	        System.err.println(forwardUrl);
	        Assert.assertNotNull(forwardUrl);

	        String queryFragment = new URI(forwardUrl).getFragment();
	        Assert.assertNotNull(queryFragment);
	        
	        Map<String,List<String>> map = parseRequestParams(queryFragment);

	        List<String> tokens = map.get("access_token");
	        Assert.assertNotNull(tokens);
	        Assert.assertEquals(1, tokens.size());
	        
	        token = tokens.get(0);
	        Assert.assertNotNull(token);
	    } catch (Exception e) {
        	e.printStackTrace();
        	Assert.fail();
        }
        
        return token;
    }

    private Map<String, List<String>> parseRequestParams(final String query) {
        return Arrays.asList(query.split("&"))
        		.stream()
        		.map(p -> p.split("="))
        			.collect(Collectors.toMap(s -> decode(index(s, 0)), s -> Arrays.asList(decode(index(s, 1))), this::mergeLists));
    }

    private <T> List<T> mergeLists(final List<T> l1, final List<T> l2) {
        List<T> list = new ArrayList<>();
        list.addAll(l1);
        list.addAll(l2);
        return list;
    }

    private <T> T index(final T[] array, final int index) {
        return index >= array.length ? null : array[index];
    }

    private String decode(final String encoded) {
        try {
            return encoded == null ? null : URLDecoder.decode(encoded, "UTF-8");
        } catch(final UnsupportedEncodingException e) {
            throw new RuntimeException("Impossible: UTF-8 is a required encoding", e);
        }
    }    
    
    @Test
    public void givenToken_whenPostGetSecureRequest_thenOk() throws Exception {
        final String accessToken = obtainAccessTokenWithPassword("john", "123");
        Assert.assertNotNull(accessToken);
        System.err.println(accessToken);
    }
    
    @Test
    @WithMockUser(username = "john", password = "123", roles = "USER")    
    public void givenToken_whenPostImplicitRequest_thenOk() throws Exception {
        final String accessToken = obtainAccessTokenImplicit();
        Assert.assertNotNull(accessToken);
        System.err.println(accessToken);
    }

}