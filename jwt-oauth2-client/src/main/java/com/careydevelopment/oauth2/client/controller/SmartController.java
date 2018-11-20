package com.careydevelopment.oauth2.client.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.careydevelopment.oauth2.client.model.Foo;

@RestController
public class SmartController {

	@Autowired
	OAuth2RestTemplate restTemplate;
	
    @RequestMapping(method = RequestMethod.GET, value = "/wamp")
    public String wamp() {
    	try {
	    	//ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:8082/spring-security-oauth-resource/foos/23", String.class);
	    	Foo foo = restTemplate.getForObject("http://localhost:8082/spring-security-oauth-resource/foos/23", Foo.class);
	    	System.err.println("it is " + foo.getId() + " " + foo.getName());
//	    	System.err.println("response is " + response.getBody());
//	    	ObjectMapper mapper = new ObjectMapper();
//	    	JsonNode root = mapper.readTree(response.getBody());
	    	//System.err.println("root is " + root.asText());
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	
        return "wamp";
    }
}
