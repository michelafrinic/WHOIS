package net.apnic.db.whois.common.rpsl.impl;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import net.ripe.db.whois.common.rpsl.impl.*;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;
import java.util.List;

/**
 * Created by michel on 7/15/14.
 */
public class ApnicObjectTypeFactoryTest {

    private IObjectTypeFactory apnicObjectTypeFactory;

    @Before
    public void init() {
        apnicObjectTypeFactory = new ApnicObjectTypeFactory();
    }

    @Test
    public void testApnicValues() {
        Collection<IObjectType> values = apnicObjectTypeFactory.values();
        Assert.assertEquals(4, values.size());

        Assert.assertNotNull(apnicObjectTypeFactory.get("inetnum"));
        Assert.assertNotNull(apnicObjectTypeFactory.get("person"));
        Assert.assertNotNull(apnicObjectTypeFactory.get("role"));
        Assert.assertNotNull(apnicObjectTypeFactory.get("organisation"));

        Assert.assertNull(apnicObjectTypeFactory.get("inet6num"));
        Assert.assertNull(apnicObjectTypeFactory.get((String) null));
    }

    @Test
    public void testGetById() {
        Assert.assertEquals(apnicObjectTypeFactory.get(1), apnicObjectTypeFactory.get("inetnum"));
        Assert.assertEquals(apnicObjectTypeFactory.get(3), apnicObjectTypeFactory.get("person"));
        Assert.assertEquals(apnicObjectTypeFactory.get(6), apnicObjectTypeFactory.get("role"));
        Assert.assertEquals(apnicObjectTypeFactory.get(2), apnicObjectTypeFactory.get("organisation"));

        Assert.assertNull(apnicObjectTypeFactory.get(7));
    }
}