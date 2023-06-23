package com.siukatech.poc.oauthclient.web.controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class WebController {

    @GetMapping(path = "/")
    public String index() {
        return "external";
    }

    @GetMapping(path = "/authorized")
    public String authorized(Principal principal, Model model) {
        //addCustomers();
        //model.addAttribute("customers", customerDAO.findAll());
        model.addAttribute("username", principal.getName());
        return principal.getName();
    }

}
