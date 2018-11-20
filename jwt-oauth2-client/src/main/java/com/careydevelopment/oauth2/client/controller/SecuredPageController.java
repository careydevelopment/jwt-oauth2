package com.careydevelopment.oauth2.client.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class SecuredPageController {

    @RequestMapping(method = RequestMethod.GET, value = "/securedPage")
    public String index(Model model) {
    	Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    	System.err.println("principal here is " + principal);
    	model.addAttribute("name", principal.toString());
        return "securedPage";
    }
}
