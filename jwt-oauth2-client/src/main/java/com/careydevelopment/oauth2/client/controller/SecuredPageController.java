package com.careydevelopment.oauth2.client.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class SecuredPageController {

    @RequestMapping(method = RequestMethod.GET, value = "/securedPage")
    public String index(Model model) {
        return "securedPage";
    }
}
