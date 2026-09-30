package com.example;

import java.io.File;
import java.io.ObjectInputStream;
import java.net.URL;
import java.security.MessageDigest;
import javax.xml.parsers.DocumentBuilderFactory;

public class LegacyServlet {
    private static final String API_KEY = "abcd1234efgh";

    public void doGet(Object request) throws Exception {
        String path = request.getParameter("path");
        File file = new File(path);
        Runtime.getRuntime().exec(request.getParameter("cmd"));
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        in.readObject();
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        new URL(request.getParameter("url"));
        MessageDigest.getInstance("MD5");
        new java.util.Random().nextInt();
    }
}
